//! Restoring pane grids from a `SNAPSHOT` (`restore_snapshot_grid` in the
//! old `tmate-daemon-decoder.c`). Each cell comes as a packed word
//! `flags << 24 | attr << 16 | bg << 8 | fg` with tmux 2.2's `GRID_ATTR_*`
//! and `GRID_FLAG_*` bits; the lines are replayed into a fresh parser so
//! history, screen and cursor end up as the host had them.

use crate::proto::{PaneSnapshot, SnapshotGrid};
use crate::render::{Attrs, Color};

const GRID_ATTR_BRIGHT: u32 = 0x1;
const GRID_ATTR_DIM: u32 = 0x2;
const GRID_ATTR_UNDERSCORE: u32 = 0x4;
const GRID_ATTR_REVERSE: u32 = 0x10;
const GRID_ATTR_ITALICS: u32 = 0x40;
const GRID_FLAG_FG256: u32 = 0x1;
const GRID_FLAG_BG256: u32 = 0x2;
const GRID_FLAG_PADDING: u32 = 0x4;
/// `MODE_CURSOR` in the screen mode word.
const MODE_CURSOR: i64 = 0x1;

/// tmux's colour byte: 8 is the default, 0-7 the base colours, 90-97 the
/// bright ones, and anything with the 256 flag an index.
fn colour(value: u32, is256: bool) -> Color {
    let v = value as u8;
    if is256 {
        return Color::Idx(v);
    }
    match v {
        0..=7 => Color::Idx(v),
        90..=97 => Color::Idx(v - 90 + 8),
        _ => Color::Default,
    }
}

/// Decodes one packed cell word into attributes and whether the cell is
/// the padding after a wide character.
pub fn decode_cell(packed: u32) -> (Attrs, bool) {
    let flags = packed >> 24;
    let attr = (packed >> 16) & 0xff;
    let bg = (packed >> 8) & 0xff;
    let fg = packed & 0xff;
    let attrs = Attrs {
        fg: colour(fg, flags & GRID_FLAG_FG256 != 0),
        bg: colour(bg, flags & GRID_FLAG_BG256 != 0),
        bold: attr & GRID_ATTR_BRIGHT != 0,
        dim: attr & GRID_ATTR_DIM != 0,
        italic: attr & GRID_ATTR_ITALICS != 0,
        underline: attr & GRID_ATTR_UNDERSCORE != 0,
        inverse: attr & GRID_ATTR_REVERSE != 0,
    };
    (attrs, flags & GRID_FLAG_PADDING != 0)
}

/// Replays a grid into the parser: history lines scroll off the top as
/// tmux's `grid_scroll_history` did, then the cursor is placed.
fn replay(parser: &mut vt100::Parser, grid: &SnapshotGrid) {
    let mut out = Vec::new();
    let mut attrs: Option<Attrs> = None;
    for (i, line) in grid.lines.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(b"\r\n");
        }
        let mut chars = line.text.chars();
        for packed in &line.cells {
            let (a, padding) = decode_cell(*packed);
            if padding {
                continue;
            }
            let ch = chars.next().unwrap_or(' ');
            if attrs != Some(a) {
                out.extend_from_slice(a.sgr().as_bytes());
                attrs = Some(a);
            }
            let mut buf = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
    }
    out.extend_from_slice(b"\x1b[0m");
    out.extend_from_slice(
        format!("\x1b[{};{}H", grid.cy.max(0) + 1, grid.cx.max(0) + 1).as_bytes(),
    );
    parser.process(&out);
}

/// A parser of the pane's current size holding the snapshot's contents.
/// With a saved grid the pane is on its alternate screen: the saved grid
/// becomes the main screen and the live grid the alternate one.
pub fn restore(snap: &PaneSnapshot, rows: u16, cols: u16, scrollback: usize) -> vt100::Parser {
    let mut parser = vt100::Parser::new(rows, cols, scrollback);
    if let Some(saved) = &snap.saved {
        replay(&mut parser, saved);
        parser.process(b"\x1b[?1049h");
    }
    replay(&mut parser, &snap.grid);
    if snap.mode & MODE_CURSOR == 0 {
        parser.process(b"\x1b[?25l");
    }
    parser
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::SnapshotLine;
    use crate::render::Cell;

    fn pack(flags: u32, attr: u32, bg: u32, fg: u32) -> u32 {
        flags << 24 | attr << 16 | bg << 8 | fg
    }

    fn line(text: &str, cells: Vec<u32>) -> SnapshotLine {
        SnapshotLine {
            text: text.into(),
            cells,
        }
    }

    #[test]
    fn cell_words_decode() {
        let (a, pad) = decode_cell(pack(0, 0, 8, 8));
        assert_eq!(a, Attrs::default());
        assert!(!pad);
        let (a, _) = decode_cell(pack(0, GRID_ATTR_BRIGHT | GRID_ATTR_UNDERSCORE, 8, 1));
        assert!(a.bold && a.underline && !a.inverse);
        assert_eq!(a.fg, Color::Idx(1));
        let (a, _) = decode_cell(pack(
            GRID_FLAG_FG256 | GRID_FLAG_BG256,
            GRID_ATTR_REVERSE | GRID_ATTR_ITALICS,
            236,
            33,
        ));
        assert_eq!((a.fg, a.bg), (Color::Idx(33), Color::Idx(236)));
        assert!(a.inverse && a.italic);
        let (a, _) = decode_cell(pack(0, GRID_ATTR_DIM, 94, 97));
        assert_eq!((a.fg, a.bg), (Color::Idx(15), Color::Idx(12)));
        assert!(a.dim);
        assert!(decode_cell(pack(GRID_FLAG_PADDING, 0, 8, 8)).1);
    }

    #[test]
    fn grid_restores_history_screen_and_cursor() {
        let d = pack(0, 0, 8, 8);
        let red = pack(0, GRID_ATTR_BRIGHT, 8, 1);
        let snap = PaneSnapshot {
            id: 0,
            mode: MODE_CURSOR,
            grid: SnapshotGrid {
                cx: 2,
                cy: 1,
                lines: vec![
                    line("old1", vec![d; 4]),
                    line("old2", vec![d; 4]),
                    line("ab", vec![red, d]),
                    line("日x", vec![d, pack(GRID_FLAG_PADDING, 0, 8, 8), d]),
                    line("", vec![]),
                ],
            },
            saved: None,
        };
        let mut p = restore(&snap, 3, 10, 100);
        assert_eq!(p.screen().contents(), "ab\n日x");
        assert_eq!(p.screen().cursor_position(), (1, 2));
        let cell = Cell::from_vt(p.screen().cell(0, 0).unwrap());
        assert!(cell.attrs.bold);
        assert_eq!(cell.attrs.fg, Color::Idx(1));
        assert_eq!(
            Cell::from_vt(p.screen().cell(0, 1).unwrap()).attrs,
            Attrs::default()
        );
        assert!(p.screen().cell(1, 0).unwrap().is_wide());
        assert_eq!(p.screen().cell(1, 2).unwrap().contents(), "x");
        assert_eq!(crate::copymode::history_len(&mut p), 2);
        p.screen_mut().set_scrollback(2);
        assert_eq!(p.screen().contents(), "old1\nold2\nab");
        assert!(!p.screen().hide_cursor());
    }

    #[test]
    fn alternate_screen_and_hidden_cursor() {
        let d = pack(0, 0, 8, 8);
        let snap = PaneSnapshot {
            id: 0,
            mode: 0,
            grid: SnapshotGrid {
                cx: 0,
                cy: 0,
                lines: vec![line("alt", vec![d; 3])],
            },
            saved: Some(SnapshotGrid {
                cx: 4,
                cy: 0,
                lines: vec![line("main", vec![d; 4])],
            }),
        };
        let mut p = restore(&snap, 2, 10, 10);
        assert!(p.screen().alternate_screen());
        assert_eq!(p.screen().contents(), "alt");
        assert!(p.screen().hide_cursor());
        p.process(b"\x1b[?1049l");
        assert_eq!(p.screen().contents(), "main");
        assert_eq!(p.screen().cursor_position(), (0, 4));
    }
}
