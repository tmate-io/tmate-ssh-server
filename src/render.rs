//! Draws what a viewer sees: a canvas of cells the size of the viewer's
//! terminal, composed from pane screens, borders, overlays and the status
//! line, then turned into terminal bytes either from scratch or as a diff
//! against what the viewer's terminal already shows.

use std::fmt::Write as _;

pub use vt100::Color;

/// Terminal size of a viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
    pub cols: u16,
    pub rows: u16,
}

/// Cell attributes as both `vt100` and tmux 2.2 represent them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Attrs {
    pub fg: Color,
    pub bg: Color,
    pub bold: bool,
    pub dim: bool,
    pub italic: bool,
    pub underline: bool,
    pub inverse: bool,
}

impl Attrs {
    pub const fn colours(fg: Color, bg: Color) -> Attrs {
        Attrs {
            fg,
            bg,
            bold: false,
            dim: false,
            italic: false,
            underline: false,
            inverse: false,
        }
    }

    /// `status-style`: bg=green,fg=black.
    pub const STATUS: Attrs = Attrs::colours(Color::Idx(0), Color::Idx(2));
    /// `mode-style` and `message-style`: bg=yellow,fg=black.
    pub const MODE: Attrs = Attrs::colours(Color::Idx(0), Color::Idx(3));
    /// `pane-active-border-style`: fg=green.
    pub const ACTIVE_BORDER: Attrs = Attrs::colours(Color::Idx(2), Color::Default);

    pub fn from_vt(c: &vt100::Cell) -> Attrs {
        Attrs {
            fg: c.fgcolor(),
            bg: c.bgcolor(),
            bold: c.bold(),
            dim: c.dim(),
            italic: c.italic(),
            underline: c.underline(),
            inverse: c.inverse(),
        }
    }

    /// The SGR sequence that sets exactly these attributes from any state.
    pub fn sgr(&self) -> String {
        let mut s = String::from("\x1b[0");
        if self.bold {
            s.push_str(";1");
        }
        if self.dim {
            s.push_str(";2");
        }
        if self.italic {
            s.push_str(";3");
        }
        if self.underline {
            s.push_str(";4");
        }
        if self.inverse {
            s.push_str(";7");
        }
        colour_param(&mut s, self.fg, 30);
        colour_param(&mut s, self.bg, 40);
        s.push('m');
        s
    }
}

fn colour_param(s: &mut String, c: Color, base: u8) {
    match c {
        Color::Default => {}
        Color::Idx(n) if n < 8 => {
            let _ = write!(s, ";{}", base + n);
        }
        Color::Idx(n) if n < 16 => {
            let _ = write!(s, ";{}", base + 60 + n - 8);
        }
        Color::Idx(n) => {
            let _ = write!(s, ";{};5;{n}", base + 8);
        }
        Color::Rgb(r, g, b) => {
            let _ = write!(s, ";{};2;{r};{g};{b}", base + 8);
        }
    }
}

/// One terminal cell. `width` is 2 for a wide character, 0 for the cell
/// after it, 1 otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    pub ch: char,
    pub width: u8,
    pub attrs: Attrs,
}

impl Default for Cell {
    fn default() -> Self {
        Cell {
            ch: ' ',
            width: 1,
            attrs: Attrs::default(),
        }
    }
}

impl Cell {
    pub fn new(ch: char, attrs: Attrs) -> Cell {
        Cell {
            ch,
            width: char_width(ch),
            attrs,
        }
    }

    pub const fn continuation(attrs: Attrs) -> Cell {
        Cell {
            ch: ' ',
            width: 0,
            attrs,
        }
    }

    pub fn blank(attrs: Attrs) -> Cell {
        Cell::new(' ', attrs)
    }

    pub fn from_vt(c: &vt100::Cell) -> Cell {
        let attrs = Attrs::from_vt(c);
        if c.is_wide_continuation() {
            return Cell::continuation(attrs);
        }
        let ch = c.contents().chars().next().unwrap_or(' ');
        Cell {
            ch,
            width: if c.is_wide() { 2 } else { 1 },
            attrs,
        }
    }
}

/// Column width of a character: 2 for East Asian wide and fullwidth
/// ranges and emoji, 0 for combining marks and controls, else 1. Enough
/// for status text and prompts; pane contents carry `vt100`'s own widths.
pub fn char_width(c: char) -> u8 {
    let u = c as u32;
    if u < 0x20 || (0x7f..0xa0).contains(&u) {
        return 0;
    }
    if (0x300..0x370).contains(&u) || (0x200b..0x2010).contains(&u) || u == 0xfe0f {
        return 0;
    }
    let wide = matches!(u,
        0x1100..=0x115f
        | 0x2e80..=0x303e
        | 0x3041..=0x33ff
        | 0x3400..=0x4dbf
        | 0x4e00..=0x9fff
        | 0xa000..=0xa4cf
        | 0xac00..=0xd7a3
        | 0xf900..=0xfaff
        | 0xfe30..=0xfe4f
        | 0xff00..=0xff60
        | 0xffe0..=0xffe6
        | 0x1f300..=0x1f64f
        | 0x1f900..=0x1f9ff
        | 0x20000..=0x3fffd);
    if wide { 2 } else { 1 }
}

/// Cells for a string, with continuation cells after wide characters.
pub fn cells_of(text: &str, attrs: Attrs) -> Vec<Cell> {
    let mut out = Vec::with_capacity(text.len());
    for ch in text.chars() {
        let w = char_width(ch);
        if w == 0 {
            continue;
        }
        out.push(Cell {
            ch,
            width: w,
            attrs,
        });
        if w == 2 {
            out.push(Cell::continuation(attrs));
        }
    }
    out
}

/// Takes the first `max` cells, never ending on half a wide character.
pub fn clip_cells(mut cells: Vec<Cell>, max: usize) -> Vec<Cell> {
    cells.truncate(max);
    if cells.last().is_some_and(|c| c.width == 2) {
        cells.pop();
    }
    cells
}

/// The viewer's whole terminal, drawn from scratch each time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canvas {
    cols: u16,
    rows: u16,
    cells: Vec<Cell>,
    /// `(row, col)`; `None` hides the cursor.
    pub cursor: Option<(u16, u16)>,
}

impl Canvas {
    pub fn new(size: Size) -> Canvas {
        Canvas {
            cols: size.cols,
            rows: size.rows,
            cells: vec![Cell::default(); usize::from(size.cols) * usize::from(size.rows)],
            cursor: None,
        }
    }

    pub fn size(&self) -> Size {
        Size {
            cols: self.cols,
            rows: self.rows,
        }
    }

    fn index(&self, row: u16, col: u16) -> Option<usize> {
        (row < self.rows && col < self.cols)
            .then(|| usize::from(row) * usize::from(self.cols) + usize::from(col))
    }

    #[cfg(test)]
    pub fn get(&self, row: u16, col: u16) -> Option<&Cell> {
        self.index(row, col).map(|i| &self.cells[i])
    }

    /// Sets a cell; positions off the canvas are ignored. Overwriting half
    /// of a wide character blanks the other half.
    pub fn set(&mut self, row: u16, col: u16, cell: Cell) {
        let Some(i) = self.index(row, col) else {
            return;
        };
        let old = self.cells[i];
        if old.width == 2 && cell.width != 2 && col + 1 < self.cols {
            self.cells[i + 1] = Cell::blank(old.attrs);
        }
        if old.width == 0 && cell.width != 0 && col > 0 {
            self.cells[i - 1] = Cell::blank(old.attrs);
        }
        self.cells[i] = cell;
    }

    pub fn put_cells(&mut self, row: u16, col: u16, cells: &[Cell]) {
        for (i, cell) in cells.iter().enumerate() {
            let Ok(c) = u16::try_from(usize::from(col) + i) else {
                break;
            };
            self.set(row, c, *cell);
        }
    }

    pub fn put_str(&mut self, row: u16, col: u16, text: &str, attrs: Attrs) {
        self.put_cells(row, col, &cells_of(text, attrs));
    }

    /// The text of a row with trailing blanks removed.
    #[cfg(test)]
    pub fn row_text(&self, row: u16) -> String {
        let mut s = String::new();
        for col in 0..self.cols {
            if let Some(c) = self.get(row, col)
                && c.width != 0
            {
                s.push(c.ch);
            }
        }
        s.trim_end().to_string()
    }

    #[cfg(test)]
    pub fn rows_text(&self) -> Vec<String> {
        (0..self.rows).map(|r| self.row_text(r)).collect()
    }

    /// Everything needed to draw the viewer's terminal from scratch.
    pub fn render_full(&self) -> Vec<u8> {
        let mut out = b"\x1b[?25l\x1b[0m\x1b[H\x1b[2J".to_vec();
        let blank = Canvas::new(self.size());
        self.write_diff(&mut out, &blank);
        self.write_cursor(&mut out);
        out
    }

    /// Only what changed since `prev` was drawn; empty when nothing did.
    /// `prev` must have the same size.
    pub fn render_diff(&self, prev: &Canvas) -> Vec<u8> {
        if self == prev {
            return Vec::new();
        }
        let mut out = b"\x1b[?25l".to_vec();
        self.write_diff(&mut out, prev);
        self.write_cursor(&mut out);
        out
    }

    fn write_diff(&self, out: &mut Vec<u8>, prev: &Canvas) {
        let cols = usize::from(self.cols);
        let mut attrs = Attrs::default();
        let mut changed = vec![false; cols];
        for row in 0..self.rows {
            let start = usize::from(row) * cols;
            let line = &self.cells[start..start + cols];
            let old = &prev.cells[start..start + cols];
            let mut any = false;
            for col in 0..cols {
                changed[col] = line[col] != old[col];
                any |= changed[col];
            }
            if !any {
                continue;
            }
            // Wide characters are redrawn whole.
            for col in 0..cols {
                if !changed[col] {
                    continue;
                }
                if (line[col].width == 2 || old[col].width == 2) && col + 1 < cols {
                    changed[col + 1] = true;
                }
                if (line[col].width == 0 || old[col].width == 0) && col > 0 {
                    changed[col - 1] = true;
                }
            }
            let mut col = 0;
            while col < cols {
                if !changed[col] {
                    col += 1;
                    continue;
                }
                let _ = write!(ByteWriter(out), "\x1b[{};{}H", row + 1, col + 1);
                while col < cols && changed[col] {
                    let cell = &line[col];
                    if cell.width == 0 {
                        col += 1;
                        continue;
                    }
                    if cell.attrs != attrs {
                        out.extend_from_slice(cell.attrs.sgr().as_bytes());
                        attrs = cell.attrs;
                    }
                    if cell.width == 2 && col + 1 >= cols {
                        out.push(b' ');
                    } else {
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(cell.ch.encode_utf8(&mut buf).as_bytes());
                    }
                    col += usize::from(cell.width);
                }
            }
        }
        if attrs != Attrs::default() {
            out.extend_from_slice(b"\x1b[0m");
        }
    }

    fn write_cursor(&self, out: &mut Vec<u8>) {
        match self.cursor {
            Some((row, col)) => {
                let _ = write!(ByteWriter(out), "\x1b[{};{}H\x1b[?25h", row + 1, col + 1);
            }
            None => {
                let _ = write!(ByteWriter(out), "\x1b[{};1H", self.rows.max(1));
            }
        }
    }
}

struct ByteWriter<'a>(&'a mut Vec<u8>);

impl std::fmt::Write for ByteWriter<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// One window in the status line's list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowEntry {
    pub idx: i64,
    pub name: String,
    pub current: bool,
    pub last: bool,
}

/// Status line as tmux 2.2's `status_redraw` draws it with tmate's host
/// supplied left/right texts: left (clipped to `status-left-length`), the
/// window list `idx:name` with `*` for the current and `-` for the last
/// window, scrolled with `<`/`>` when it does not fit, then right.
pub struct StatusLine<'a> {
    pub left: &'a str,
    pub right: &'a str,
    pub windows: &'a [WindowEntry],
    pub left_length: usize,
    pub right_length: usize,
}

impl StatusLine<'_> {
    pub fn render(&self, cols: usize) -> Vec<Cell> {
        let attrs = Attrs::STATUS;
        let mut line = vec![Cell::blank(attrs); cols];
        if cols == 0 {
            return line;
        }
        let left = clip_cells(cells_of(self.left, attrs), self.left_length);
        let right = clip_cells(cells_of(self.right, attrs), self.right_length);
        let (llen, rlen) = (left.len(), right.len());
        let needed = llen + rlen;
        if cols <= needed {
            return line;
        }
        let mut wlavailable = cols - needed;

        let mut list: Vec<Cell> = Vec::new();
        let (mut wloffset, mut wlsize) = (0, 0);
        for w in self.windows {
            let flag = if w.current {
                "*"
            } else if w.last {
                "-"
            } else {
                " "
            };
            let cells = cells_of(&format!("{}:{}{flag}", w.idx, w.name), attrs);
            if w.current {
                wloffset = list.len();
                wlsize = cells.len();
            }
            list.extend(cells);
            list.push(Cell::blank(attrs)); // window-status-separator
        }
        let mut wlwidth = list.len();
        let mut wlstart = 0;
        let (mut larrow, mut rarrow) = (false, false);
        if wlwidth > wlavailable {
            if wloffset + wlsize < wlavailable {
                if wlavailable > 0 {
                    rarrow = true;
                    wlavailable -= 1;
                }
                wlwidth = wlavailable;
            } else {
                if wlavailable > 0 {
                    larrow = true;
                    wlavailable -= 1;
                }
                wlstart = wloffset + wlsize - wlavailable;
                if wlavailable > 0 && wlwidth > wlstart + wlavailable + 1 {
                    rarrow = true;
                    wlstart += 1;
                    wlavailable -= 1;
                }
                wlwidth = wlavailable;
            }
            if wlwidth == 0 || wlavailable == 0 {
                return line;
            }
        }

        line[..llen].copy_from_slice(&left);
        if larrow {
            line[llen] = Cell::new('<', attrs);
        }
        if rarrow {
            line[cols - rlen - 1] = Cell::new('>', attrs);
        }
        line[cols - rlen..].copy_from_slice(&right);
        let offset = llen + usize::from(larrow);
        for i in 0..wlwidth {
            let Some(cell) = list.get(wlstart + i) else {
                break;
            };
            let mut cell = *cell;
            if cell.width == 0 && i == 0 {
                cell = Cell::blank(attrs);
            }
            if offset + i < line.len() {
                line[offset + i] = cell;
            }
        }
        line
    }
}

/// A status message (`status_message_redraw`): the text in `message-style`,
/// padded to the width.
pub fn message_row(text: &str, cols: usize) -> Vec<Cell> {
    let mut line = clip_cells(cells_of(text, Attrs::MODE), cols);
    line.resize(cols, Cell::blank(Attrs::MODE));
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    fn windows(spec: &[(i64, &str, char)]) -> Vec<WindowEntry> {
        spec.iter()
            .map(|(idx, name, flag)| WindowEntry {
                idx: *idx,
                name: name.to_string(),
                current: *flag == '*',
                last: *flag == '-',
            })
            .collect()
    }

    fn text(cells: &[Cell]) -> String {
        cells
            .iter()
            .filter(|c| c.width != 0)
            .map(|c| c.ch)
            .collect()
    }

    fn status<'a>(left: &'a str, right: &'a str, w: &'a [WindowEntry]) -> StatusLine<'a> {
        StatusLine {
            left,
            right,
            windows: w,
            left_length: 10,
            right_length: 40,
        }
    }

    #[test]
    fn window_list_formatting() {
        let w = windows(&[(0, "bash", '-'), (1, "vim", '*'), (2, "top", ' ')]);
        let line = text(&status("[default] ", " 21:43 08-Oct-26", &w).render(50));
        assert_eq!(line, "[default] 0:bash- 1:vim* 2:top     21:43 08-Oct-26");
        assert_eq!(line.len(), 50);
        // No left text: list starts at column 0, as in the parity capture.
        let w = windows(&[(0, "bash", '-'), (1, "bash", '*')]);
        assert_eq!(
            text(&status("", "", &w).render(80)).trim_end(),
            "0:bash- 1:bash*"
        );
        // Left is clipped to status-left-length, right to status-right-length.
        let line = text(&status("[a-very-long-session-name] ", "", &w).render(80));
        assert!(line.starts_with("[a-very-lo0:bash- 1:bash*"), "{line}");
        let long_right: String = "r".repeat(60);
        let line = text(&status("", &long_right, &w).render(80));
        assert_eq!(line.matches('r').count(), 40);
        // Too narrow for left + right: blank.
        assert_eq!(
            text(&status("[default] ", "0123456789", &w).render(20)).trim(),
            ""
        );
        assert_eq!(status("x", "", &w).render(0).len(), 0);
    }

    #[test]
    fn window_list_scrolls_with_arrows() {
        let w: Vec<WindowEntry> = (0..8)
            .map(|i| WindowEntry {
                idx: i,
                name: "window".into(),
                current: i == 6,
                last: i == 5,
            })
            .collect();
        let line = text(&status("[s] ", "", &w).render(30));
        assert_eq!(line.len(), 30);
        assert!(line.starts_with("[s] <"), "{line}");
        assert!(line.contains("6:window*"), "{line}");
        assert!(line.ends_with('>'), "{line}");
        // Current window near the start: only a right arrow.
        let w: Vec<WindowEntry> = (0..8)
            .map(|i| WindowEntry {
                idx: i,
                name: "window".into(),
                current: i == 0,
                last: false,
            })
            .collect();
        let line = text(&status("", "", &w).render(30));
        assert!(line.starts_with("0:window* 1:window "), "{line}");
        assert!(line.ends_with('>'), "{line}");
    }

    #[test]
    fn status_cells_use_status_style() {
        let w = windows(&[(0, "sh", '*')]);
        let cells = status("[x] ", "", &w).render(10);
        assert!(cells.iter().all(|c| c.attrs == Attrs::STATUS));
        let msg = message_row("Unknown command: x", 10);
        assert_eq!(text(&msg), "Unknown co");
        assert!(msg.iter().all(|c| c.attrs == Attrs::MODE));
    }

    #[test]
    fn full_frame_and_diff() {
        let mut c = Canvas::new(Size { cols: 10, rows: 3 });
        c.put_str(0, 0, "hello", Attrs::default());
        c.put_str(2, 0, "[x] 0:sh*", Attrs::STATUS);
        c.cursor = Some((0, 5));
        let out = String::from_utf8(c.render_full()).unwrap();
        assert!(
            out.starts_with("\x1b[?25l\x1b[0m\x1b[H\x1b[2J\x1b[1;1Hhello"),
            "{out:?}"
        );
        assert!(
            out.contains("\x1b[3;1H\x1b[0;30;42m[x] 0:sh*\x1b[0m"),
            "{out:?}"
        );
        assert!(out.ends_with("\x1b[1;6H\x1b[?25h"), "{out:?}");

        let mut next = c.clone();
        assert!(
            next.render_diff(&c).is_empty(),
            "identical canvases produce nothing"
        );
        next.put_str(0, 6, "world", Attrs::default());
        let diff = String::from_utf8(next.render_diff(&c)).unwrap();
        assert_eq!(diff, "\x1b[?25l\x1b[1;7Hworl\x1b[1;6H\x1b[?25h");
        // Cursor hidden: no ?25h.
        next.cursor = None;
        let diff = String::from_utf8(next.render_diff(&c)).unwrap();
        assert!(!diff.contains("?25h"));
    }

    #[test]
    fn wide_characters_are_redrawn_whole() {
        let mut c = Canvas::new(Size { cols: 6, rows: 1 });
        c.put_str(0, 0, "日本", Attrs::default());
        assert_eq!(c.get(0, 1).unwrap().width, 0);
        assert_eq!(c.row_text(0), "日本");
        let full = String::from_utf8(c.render_full()).unwrap();
        assert!(full.contains("\x1b[1;1H日本"), "{full:?}");
        let mut next = c.clone();
        next.put_str(0, 2, "a", Attrs::default());
        // Overwriting the first half of 本 redraws the cell pair.
        let diff = String::from_utf8(next.render_diff(&c)).unwrap();
        assert!(diff.contains("\x1b[1;3Ha "), "{diff:?}");
        // A wide char that would spill past the edge is drawn as a space.
        let mut c = Canvas::new(Size { cols: 1, rows: 1 });
        c.put_str(0, 0, "日", Attrs::default());
        assert!(
            String::from_utf8(c.render_full())
                .unwrap()
                .contains("\x1b[1;1H ")
        );
    }

    #[test]
    fn sgr_sequences() {
        assert_eq!(Attrs::default().sgr(), "\x1b[0m");
        assert_eq!(Attrs::STATUS.sgr(), "\x1b[0;30;42m");
        let a = Attrs {
            fg: Color::Idx(33),
            bg: Color::Rgb(1, 2, 3),
            bold: true,
            underline: true,
            ..Attrs::default()
        };
        assert_eq!(a.sgr(), "\x1b[0;1;4;38;5;33;48;2;1;2;3m");
        assert_eq!(
            Attrs::colours(Color::Idx(9), Color::Default).sgr(),
            "\x1b[0;91m"
        );
        // Attributes carry over from vt100 cells.
        let mut p = vt100::Parser::new(1, 5, 0);
        p.process(b"\x1b[1;31;7mX");
        let cell = Cell::from_vt(p.screen().cell(0, 0).unwrap());
        assert_eq!(cell.ch, 'X');
        assert!(cell.attrs.bold && cell.attrs.inverse);
        assert_eq!(cell.attrs.fg, Color::Idx(1));
    }
}
