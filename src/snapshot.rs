//! Pane grids in the packed form the old server used: restoring them from
//! a host's `SNAPSHOT` (`restore_snapshot_grid` in `tmate-daemon-decoder.c`)
//! and producing them for the backend (`do_snapshot` in
//! `tmate-websocket.c`). Each cell is a word
//! `flags << 24 | attr << 16 | bg << 8 | fg` with tmux 2.2's `GRID_ATTR_*`
//! and `GRID_FLAG_*` bits; restoring replays the lines into a fresh parser
//! so history, screen and cursor end up as the host had them.

use crate::backend;
use crate::grid;
use crate::proto::{PaneSnapshot, SnapshotGrid};
use crate::render::{Attrs, Cell, Color};

const GRID_ATTR_BRIGHT: u32 = 0x1;
const GRID_ATTR_DIM: u32 = 0x2;
const GRID_ATTR_UNDERSCORE: u32 = 0x4;
const GRID_ATTR_REVERSE: u32 = 0x10;
const GRID_ATTR_ITALICS: u32 = 0x40;
const GRID_FLAG_FG256: u32 = 0x1;
const GRID_FLAG_BG256: u32 = 0x2;
const GRID_FLAG_PADDING: u32 = 0x4;
/// tmux 2.2 `MODE_*` bits of a screen.
const MODE_CURSOR: i64 = 0x1;
const MODE_KCURSOR: u32 = 0x4;
const MODE_KKEYPAD: u32 = 0x8;
const MODE_WRAP: u32 = 0x10;
const MODE_MOUSE_STANDARD: u32 = 0x20;
const MODE_MOUSE_BUTTON: u32 = 0x40;
const MODE_MOUSE_UTF8: u32 = 0x100;
const MODE_MOUSE_SGR: u32 = 0x200;
const MODE_BRACKETPASTE: u32 = 0x400;

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

/// tmux's colour byte for a `vt100` colour, with the 256 flag when the
/// value is an index rather than a base colour. True colour, which tmux
/// 2.2's packed word cannot carry, becomes the nearest of the 256.
fn colour_byte(c: Color) -> (u32, bool) {
    match c {
        Color::Default => (8, false),
        Color::Idx(n) if n < 8 => (u32::from(n), false),
        Color::Idx(n) if n < 16 => (u32::from(n) - 8 + 90, false),
        Color::Idx(n) => (u32::from(n), true),
        Color::Rgb(r, g, b) => (u32::from(nearest_256(r, g, b)), true),
    }
}

/// The xterm 256-colour index closest to an RGB value (the 6x6x6 cube or
/// the grey ramp).
fn nearest_256(r: u8, g: u8, b: u8) -> u8 {
    let level = |v: u8| -> u8 {
        if v < 48 {
            0
        } else if v < 115 {
            1
        } else {
            ((u16::from(v) - 35) / 40) as u8
        }
    };
    let cube = 16 + 36 * level(r) + 6 * level(g) + level(b);
    let cube_rgb = |i: u8| -> u8 { if i == 0 { 0 } else { 55 + 40 * i } };
    let (cr, cg, cb) = (cube_rgb(level(r)), cube_rgb(level(g)), cube_rgb(level(b)));
    let avg = (u16::from(r) + u16::from(g) + u16::from(b)) / 3;
    let grey_idx = if avg > 238 {
        23
    } else {
        ((avg.saturating_sub(3)) / 10) as u8
    };
    let grey = 8 + 10 * u16::from(grey_idx);
    let dist = |x: u8, y: u8, z: u8| -> u32 {
        let d = |a: u8, b: u8| (i32::from(a) - i32::from(b)).pow(2) as u32;
        d(r, x) + d(g, y) + d(b, z)
    };
    let grey_v = grey as u8;
    if dist(grey_v, grey_v, grey_v) < dist(cr, cg, cb) {
        232 + grey_idx
    } else {
        cube
    }
}

/// The packed word for a cell: the inverse of `decode_cell`.
pub fn encode_cell(attrs: &Attrs, padding: bool) -> u32 {
    let (fg, fg256) = colour_byte(attrs.fg);
    let (bg, bg256) = colour_byte(attrs.bg);
    let mut flags = 0;
    if fg256 {
        flags |= GRID_FLAG_FG256;
    }
    if bg256 {
        flags |= GRID_FLAG_BG256;
    }
    if padding {
        flags |= GRID_FLAG_PADDING;
    }
    let mut attr = 0;
    if attrs.bold {
        attr |= GRID_ATTR_BRIGHT;
    }
    if attrs.dim {
        attr |= GRID_ATTR_DIM;
    }
    if attrs.underline {
        attr |= GRID_ATTR_UNDERSCORE;
    }
    if attrs.inverse {
        attr |= GRID_ATTR_REVERSE;
    }
    if attrs.italic {
        attr |= GRID_ATTR_ITALICS;
    }
    flags << 24 | attr << 16 | bg << 8 | fg
}

/// One line as `do_snapshot` packs it: the text of every written cell
/// (padding after a wide character contributes no text) and the cell
/// words, trailing unwritten cells left out.
fn encode_line(cells: &[Cell]) -> backend::SnapshotLine {
    let mut text = String::new();
    let mut words = Vec::with_capacity(cells.len());
    for c in cells {
        let padding = c.width == 0;
        if !padding {
            text.push(c.ch);
        }
        words.push(encode_cell(&c.attrs, padding));
    }
    backend::SnapshotLine { text, cells: words }
}

/// The screen mode word for the backend, from what `vt100` tracks.
fn mode_of(screen: &vt100::Screen) -> u32 {
    use vt100::{MouseProtocolEncoding, MouseProtocolMode};
    let mut mode = MODE_WRAP;
    if !screen.hide_cursor() {
        mode |= MODE_CURSOR as u32;
    }
    if screen.application_cursor() {
        mode |= MODE_KCURSOR;
    }
    if screen.application_keypad() {
        mode |= MODE_KKEYPAD;
    }
    if screen.bracketed_paste() {
        mode |= MODE_BRACKETPASTE;
    }
    match screen.mouse_protocol_mode() {
        MouseProtocolMode::None => {}
        MouseProtocolMode::Press | MouseProtocolMode::PressRelease => {
            mode |= MODE_MOUSE_STANDARD;
        }
        MouseProtocolMode::ButtonMotion | MouseProtocolMode::AnyMotion => {
            mode |= MODE_MOUSE_BUTTON;
        }
    }
    match screen.mouse_protocol_encoding() {
        MouseProtocolEncoding::Default => {}
        MouseProtocolEncoding::Utf8 => mode |= MODE_MOUSE_UTF8,
        MouseProtocolEncoding::Sgr => mode |= MODE_MOUSE_SGR,
    }
    mode
}

/// A pane for the backend's `CTL_SNAPSHOT`: the last `max_history_lines`
/// of history plus the screen, with the cursor and mode, as `do_snapshot`
/// packed them. On the alternate screen only that screen is sent, since
/// its grid has no history.
pub fn capture(
    parser: &mut vt100::Parser,
    id: i64,
    max_history_lines: usize,
) -> backend::PaneSnapshot {
    let (rows, _) = parser.screen().size();
    let mut lines = grid::lines_of(parser);
    let max_lines = max_history_lines.saturating_add(usize::from(rows));
    if lines.len() > max_lines {
        lines.drain(..lines.len() - max_lines);
    }
    let screen = parser.screen();
    let (cy, cx) = screen.cursor_position();
    backend::PaneSnapshot {
        id,
        cx: i64::from(cx),
        cy: i64::from(cy),
        mode: mode_of(screen),
        lines: lines.iter().map(|l| encode_line(l)).collect(),
    }
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
    fn cell_words_roundtrip_through_the_encoder() {
        for word in [
            pack(0, 0, 8, 8),
            pack(0, GRID_ATTR_BRIGHT | GRID_ATTR_UNDERSCORE, 8, 1),
            pack(
                GRID_FLAG_FG256 | GRID_FLAG_BG256,
                GRID_ATTR_REVERSE | GRID_ATTR_ITALICS,
                236,
                33,
            ),
            pack(0, GRID_ATTR_DIM, 94, 97),
            pack(GRID_FLAG_PADDING, 0, 8, 8),
        ] {
            let (attrs, padding) = decode_cell(word);
            assert_eq!(encode_cell(&attrs, padding), word, "{word:#x}");
        }
        // True colour has no packed form; the nearest index is used.
        let a = Attrs {
            fg: Color::Rgb(255, 0, 0),
            bg: Color::Rgb(128, 128, 128),
            ..Attrs::default()
        };
        let (back, _) = decode_cell(encode_cell(&a, false));
        assert_eq!(back.fg, Color::Idx(196));
        assert_eq!(back.bg, Color::Idx(244));
        assert_eq!(nearest_256(0, 0, 0), 16);
        assert_eq!(nearest_256(255, 255, 255), 231);
    }

    #[test]
    fn capture_packs_history_screen_cursor_and_mode() {
        let mut p = vt100::Parser::new(2, 10, 100);
        p.process(b"one\r\ntwo\r\n\x1b[1;31mth\xe6\x97\xa5\x1b[0mx\r\nfour");
        let snap = capture(&mut p, 5, 300);
        assert_eq!(snap.id, 5);
        let texts: Vec<&str> = snap.lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts, ["one", "two", "th日x", "four"]);
        assert_eq!((snap.cx, snap.cy), (4, 1));
        assert_eq!(snap.mode, MODE_WRAP | MODE_CURSOR as u32);
        let wide = &snap.lines[2];
        // t h 日 pad x: five cells, four characters.
        assert_eq!(wide.cells.len(), 5);
        assert_eq!(wide.cells[0], pack(0, GRID_ATTR_BRIGHT, 8, 1));
        assert!(decode_cell(wide.cells[3]).1, "padding after the wide char");
        assert_eq!(wide.cells[4], pack(0, 0, 8, 8));
        // The backend's limit cuts the oldest history first.
        let snap = capture(&mut p, 5, 1);
        let texts: Vec<&str> = snap.lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts, ["two", "th日x", "four"]);
        // What we send, we can restore.
        let restored = PaneSnapshot {
            id: 5,
            mode: i64::from(snap.mode),
            grid: SnapshotGrid {
                cx: snap.cx,
                cy: snap.cy,
                lines: snap
                    .lines
                    .iter()
                    .map(|l| line(&l.text, l.cells.clone()))
                    .collect(),
            },
            saved: None,
        };
        let mut back = restore(&restored, 2, 10, 100);
        assert_eq!(back.screen().contents(), "th日x\nfour");
        assert_eq!(back.screen().cursor_position(), (1, 4));
        assert_eq!(crate::copymode::history_len(&mut back), 1);
        p.process(b"\x1b[?25l\x1b[?1h\x1b[?2004h\x1b[?1000h\x1b[?1006h");
        let mode = capture(&mut p, 5, 0).mode;
        assert_eq!(
            mode,
            MODE_WRAP | MODE_KCURSOR | MODE_BRACKETPASTE | MODE_MOUSE_STANDARD | MODE_MOUSE_SGR
        );
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
