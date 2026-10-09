//! Rebuilding a pane's `vt100` parser from its own lines: tmux 2.2's
//! resize semantics (`screen_resize_y`: a shrinking pane pushes the lines
//! above the cursor into history, a growing one pulls them back) and
//! `CSI 3 J` clearing the history, neither of which `vt100` does itself.
//! Widths change without reflow, as in tmux 2.2 without `reflow` support
//! for lines that were never wrapped: lines are simply cut at the new
//! width.

use crate::render::{Attrs, Cell};

/// Number of scrollback lines a parser holds.
pub fn history_len(parser: &mut vt100::Parser) -> usize {
    let before = parser.screen().scrollback();
    parser.screen_mut().set_scrollback(usize::MAX);
    let len = parser.screen().scrollback();
    parser.screen_mut().set_scrollback(before);
    len
}

/// Whether a screen row has any written cell, matching tmux's
/// `cellsize != 0`: a cell holds content once something — a glyph or even a
/// space — has been written to it, and `\033[K` (erase) empties it again.
/// This is what `grid_view_clear_history` scans for, so a blank-but-written
/// line (e.g. spaces left by a prompt redraw) still scrolls into history,
/// unlike a never-touched line. `vt100`'s `has_contents` keeps this
/// distinction that `Cell::default()` (a plain space) would lose.
fn row_used(screen: &vt100::Screen, row: u16, cols: u16) -> bool {
    (0..cols).any(|c| screen.cell(row, c).is_some_and(vt100::Cell::has_contents))
}

fn row_cells(screen: &vt100::Screen, row: u16, cols: u16) -> Vec<Cell> {
    let mut cells: Vec<Cell> = (0..cols)
        .map(|c| screen.cell(row, c).map(Cell::from_vt).unwrap_or_default())
        .collect();
    while cells.last() == Some(&Cell::default()) {
        cells.pop();
    }
    cells
}

/// Every line of the pane, history first, trailing blanks trimmed.
pub fn lines_of(parser: &mut vt100::Parser) -> Vec<Vec<Cell>> {
    let (rows, cols) = parser.screen().size();
    let hsize = history_len(parser);
    let mut lines = Vec::with_capacity(hsize + usize::from(rows));
    for i in 0..hsize {
        parser.screen_mut().set_scrollback(hsize - i);
        lines.push(row_cells(parser.screen(), 0, cols));
    }
    parser.screen_mut().set_scrollback(0);
    let screen = parser.screen();
    for r in 0..rows {
        lines.push(row_cells(screen, r, cols));
    }
    lines
}

/// Appends a line's cells (cut at `cols`) with the SGR changes they need.
pub fn write_line(out: &mut Vec<u8>, line: &[Cell], cols: u16, attrs: &mut Attrs) {
    let mut col = 0u16;
    for cell in line {
        if cell.width == 0 {
            continue;
        }
        if col + u16::from(cell.width) > cols {
            break;
        }
        if cell.attrs != *attrs {
            out.extend_from_slice(cell.attrs.sgr().as_bytes());
            *attrs = cell.attrs;
        }
        let mut buf = [0u8; 4];
        out.extend_from_slice(cell.ch.encode_utf8(&mut buf).as_bytes());
        col += u16::from(cell.width);
    }
}

/// A new parser showing `lines` (the last `rows` of them on screen, the
/// rest as history) with the cursor at `(row, col)`, carrying over the
/// old parser's input modes, attributes and cursor visibility.
pub fn rebuild(
    old: &vt100::Parser,
    lines: &[Vec<Cell>],
    rows: u16,
    cols: u16,
    scrollback: usize,
    cursor: (u16, u16),
) -> vt100::Parser {
    let mut out = Vec::new();
    let mut attrs = Attrs::default();
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(b"\r\n");
        }
        write_line(&mut out, line, cols, &mut attrs);
    }
    out.extend_from_slice(b"\x1b[0m");
    out.extend_from_slice(&old.screen().attributes_formatted());
    out.extend_from_slice(&old.screen().input_mode_formatted());
    if old.screen().hide_cursor() {
        out.extend_from_slice(b"\x1b[?25l");
    }
    out.extend_from_slice(format!("\x1b[{};{}H", cursor.0 + 1, cursor.1 + 1).as_bytes());
    let mut parser = vt100::Parser::new(rows, cols, scrollback);
    parser.process(&out);
    parser
}

/// `screen_resize_y`/`screen_resize_x`: the pane at a new size.
pub fn resize(
    parser: &mut vt100::Parser,
    rows: u16,
    cols: u16,
    scrollback: usize,
) -> vt100::Parser {
    let (old_rows, _) = parser.screen().size();
    let (cy, cx) = parser.screen().cursor_position();
    let mut lines = lines_of(parser);
    let mut hsize = lines.len() - usize::from(old_rows);
    let mut cy = usize::from(cy);
    let (rows_u, old_u) = (usize::from(rows), usize::from(old_rows));
    if rows_u < old_u {
        let mut needed = old_u - rows_u;
        // Lines below the cursor go first, then lines above it into history.
        let available = (old_u - 1 - cy).min(needed);
        lines.truncate(lines.len() - available);
        needed -= available;
        hsize += needed;
        cy -= needed;
    } else if rows_u > old_u {
        let mut needed = rows_u - old_u;
        let pull = hsize.min(needed);
        hsize -= pull;
        cy += pull;
        needed -= pull;
        lines.extend(std::iter::repeat_n(Vec::new(), needed));
    }
    debug_assert_eq!(lines.len(), hsize + rows_u);
    rebuild(
        parser,
        &lines,
        rows,
        cols,
        scrollback,
        (cy as u16, cx.min(cols.saturating_sub(1))),
    )
}

/// `screen_write_clearhistory`: the screen without its history.
pub fn clear_history(parser: &mut vt100::Parser, scrollback: usize) -> vt100::Parser {
    let (rows, cols) = parser.screen().size();
    let cursor = parser.screen().cursor_position();
    let lines = lines_of(parser);
    let screen_lines = &lines[lines.len() - usize::from(rows)..];
    rebuild(parser, screen_lines, rows, cols, scrollback, cursor)
}

/// `screen_write_clearscreen` with history on: the screen's lines up to
/// the last used one are scrolled into the history, and the cursor stays.
pub fn clear_screen_into_history(parser: &mut vt100::Parser, scrollback: usize) -> vt100::Parser {
    let (rows, cols) = parser.screen().size();
    let cursor = parser.screen().cursor_position();
    let mut lines = lines_of(parser);
    let first_screen = lines.len() - usize::from(rows);
    // tmux's `grid_view_clear_history` scrolls lines up to the last one with
    // `cellsize != 0` into the history, counting written-but-blank lines, not
    // just lines with visible glyphs. `lines_of` restores scrollback to 0, so
    // the live screen is what we scan here.
    let screen = parser.screen();
    let last_used = (0..rows)
        .rev()
        .find(|&r| row_used(screen, r, cols))
        .map_or(0, |r| usize::from(r) + 1);
    lines.truncate(first_screen + last_used);
    lines.extend(std::iter::repeat_n(Vec::new(), usize::from(rows)));
    rebuild(parser, &lines, rows, cols, scrollback, cursor)
}

/// An erase-display (`CSI Ps J`) sequence found in pane output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erase {
    /// `CSI J` / `CSI 0 J`: to the end of the screen.
    ToEnd,
    /// `CSI 2 J`: the whole screen.
    Screen,
    /// `CSI 3 J`: the history.
    History,
}

/// Finds the next erase-display sequence: `(offset, length, kind)`.
pub fn find_erase(data: &[u8]) -> Option<(usize, usize, Erase)> {
    let mut i = 0;
    while let Some(rel) = data[i..].windows(2).position(|w| w == b"\x1b[") {
        let start = i + rel;
        let rest = &data[start + 2..];
        let found = match rest {
            [b'J', ..] => Some((3, Erase::ToEnd)),
            [b'0', b'J', ..] => Some((4, Erase::ToEnd)),
            [b'2', b'J', ..] => Some((4, Erase::Screen)),
            [b'3', b'J', ..] => Some((4, Erase::History)),
            _ => None,
        };
        if let Some((len, kind)) = found {
            return Some((start, len, kind));
        }
        i = start + 2;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parser_with(rows: u16, lines: &[&str]) -> vt100::Parser {
        let mut p = vt100::Parser::new(rows, 20, 100);
        for (i, l) in lines.iter().enumerate() {
            if i > 0 {
                p.process(b"\r\n");
            }
            p.process(l.as_bytes());
        }
        p
    }

    fn contents(p: &mut vt100::Parser) -> (Vec<String>, usize) {
        let (_, cols) = p.screen().size();
        let rows: Vec<String> = p
            .screen()
            .rows(0, cols)
            .map(|r| r.trim_end().to_string())
            .collect();
        (rows, history_len(p))
    }

    #[test]
    fn shrinking_moves_lines_into_history_like_tmux() {
        // 5 rows, 3 lines written, cursor on row 2: two blank rows below.
        let mut p = parser_with(5, &["one", "two", "three"]);
        let mut small = resize(&mut p, 2, 20, 100);
        assert_eq!(
            contents(&mut small),
            (vec!["two".into(), "three".into()], 1)
        );
        assert_eq!(small.screen().cursor_position(), (1, 5));
        // Then shrinking to 1: one more line into history.
        let mut tiny = resize(&mut small, 1, 20, 100);
        assert_eq!(contents(&mut tiny), (vec!["three".into()], 2));
        // Growing pulls history back first, then blanks.
        let mut big = resize(&mut tiny, 4, 20, 100);
        assert_eq!(
            contents(&mut big),
            (
                vec!["one".into(), "two".into(), "three".into(), "".into()],
                0
            )
        );
        assert_eq!(big.screen().cursor_position(), (2, 5));
    }

    #[test]
    fn full_screen_shrink_keeps_the_cursor_lines() {
        let mut p = parser_with(
            23,
            &(1..=42)
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        p.process(b"\r\n$ ");
        assert_eq!(history_len(&mut p), 20);
        let mut r = resize(&mut p, 23, 80, 2000);
        let (rows, h) = contents(&mut r);
        assert_eq!(h, 20, "same height: unchanged");
        assert_eq!(rows[0], "21");
        let mut r = resize(&mut r, 10, 80, 2000);
        let (rows, h) = contents(&mut r);
        assert_eq!(h, 33);
        assert_eq!(rows[9], "$");
        assert_eq!(rows[0], "34");
        assert_eq!(r.screen().cursor_position(), (9, 2));
    }

    #[test]
    fn width_changes_cut_lines_and_keep_attributes_and_modes() {
        let mut p = vt100::Parser::new(3, 20, 10);
        p.process(b"\x1b[1;31mred\x1b[0m-and-more-text\r\n\x1b[?1h\x1b[?2004h\x1b[?25l\x1b[4m");
        let mut r = resize(&mut p, 3, 6, 10);
        let (rows, _) = contents(&mut r);
        assert_eq!(rows[0], "red-an");
        assert!(Cell::from_vt(r.screen().cell(0, 0).unwrap()).attrs.bold);
        assert!(
            r.screen().application_cursor()
                && r.screen().bracketed_paste()
                && r.screen().hide_cursor()
        );
        assert!(r.screen().underline(), "pending attributes carry over");
        r.process(b"x");
        assert!(
            Cell::from_vt(r.screen().cell(1, 0).unwrap())
                .attrs
                .underline
        );
    }

    #[test]
    fn clear_screen_scrolls_used_lines_into_history() {
        let mut p = parser_with(5, &["a", "b", "", "c"]);
        p.process(b"\x1b[H");
        let mut c = clear_screen_into_history(&mut p, 100);
        assert_eq!(
            contents(&mut c),
            (vec!["".into(); 5], 4),
            "lines up to the last used one, blanks included"
        );
        assert_eq!(c.screen().cursor_position(), (0, 0));
        c.screen_mut().set_scrollback(4);
        assert_eq!(
            c.screen().rows(0, 20).take(4).collect::<Vec<_>>(),
            ["a", "b", "", "c"]
        );
        // An empty screen adds nothing.
        let mut c2 = clear_screen_into_history(&mut c, 100);
        assert_eq!(history_len(&mut c2), 4);
    }

    #[test]
    fn clear_counts_blank_but_written_lines() {
        // Row 0 has a glyph; row 2 holds only spaces that were written to it
        // (as a prompt redraw might leave); row 1 was never touched. tmux's
        // `grid_view_clear_history` scans by `cellsize`, so the last *written*
        // line is row 2 and three lines scroll into the history — the blank
        // written line included, unlike a trailing never-touched line.
        let mut p = vt100::Parser::new(5, 20, 100);
        p.process(b"a\r\n\r\n   ");
        p.process(b"\x1b[H");
        let mut c = clear_screen_into_history(&mut p, 100);
        assert_eq!(history_len(&mut c), 3);
        // A screen whose only written line is blank still scrolls one line.
        let mut p = vt100::Parser::new(5, 20, 100);
        p.process(b"   \x1b[H");
        let mut c = clear_screen_into_history(&mut p, 100);
        assert_eq!(history_len(&mut c), 1);
        // `\033[K` empties a line again (cellsize back to 0): nothing scrolls.
        let mut p = vt100::Parser::new(5, 20, 100);
        p.process(b"   \r\x1b[K\x1b[H");
        let mut c = clear_screen_into_history(&mut p, 100);
        assert_eq!(history_len(&mut c), 0);
    }

    #[test]
    fn erase_sequences_are_found() {
        assert_eq!(find_erase(b"abc\x1b[H\x1b[J"), Some((6, 3, Erase::ToEnd)));
        assert_eq!(find_erase(b"\x1b[0Jx"), Some((0, 4, Erase::ToEnd)));
        assert_eq!(
            find_erase(b"\x1b[3J\x1b[H\x1b[2J"),
            Some((0, 4, Erase::History))
        );
        assert_eq!(find_erase(b"\x1b[H\x1b[2J"), Some((3, 4, Erase::Screen)));
        assert_eq!(find_erase(b"\x1b[1J\x1b[K"), None);
    }

    #[test]
    fn clearing_history() {
        let mut p = parser_with(2, &["a", "b", "c"]);
        assert_eq!(history_len(&mut p), 1);
        let mut c = clear_history(&mut p, 100);
        assert_eq!(contents(&mut c), (vec!["b".into(), "c".into()], 0));
        assert_eq!(c.screen().cursor_position(), (1, 1));
    }
}
