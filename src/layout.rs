//! Pane geometry on a viewer's screen: tmux 2.2's border drawing
//! (`screen-redraw.c`), the "(size WxH from a smaller client)" note and
//! the big pane numbers of `display-panes`.
//!
//! Coordinates are the window's: pane offsets and sizes come straight from
//! `SYNC_LAYOUT`. The status line is below the window area and is not
//! this module's business.

use crate::render::{Attrs, Canvas, Cell, Color};

/// A pane's place in its window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaneRect {
    pub xoff: u16,
    pub yoff: u16,
    pub sx: u16,
    pub sy: u16,
}

impl PaneRect {
    fn contains(&self, px: u16, py: u16) -> bool {
        px >= self.xoff && px < self.xoff + self.sx && py >= self.yoff && py < self.yoff + self.sy
    }

    /// `screen_redraw_cell_border1`: 0 inside, 1 on this pane's border,
    /// -1 elsewhere.
    fn border1(&self, px: u16, py: u16) -> i8 {
        if self.contains(px, py) {
            return 0;
        }
        if (self.yoff == 0 || py + 1 >= self.yoff) && py <= self.yoff + self.sy {
            if self.xoff != 0 && px + 1 == self.xoff {
                return 1;
            }
            if px == self.xoff + self.sx {
                return 1;
            }
        }
        if (self.xoff == 0 || px + 1 >= self.xoff) && px <= self.xoff + self.sx {
            if self.yoff != 0 && py + 1 == self.yoff {
                return 1;
            }
            if py == self.yoff + self.sy {
                return 1;
            }
        }
        -1
    }

    /// The pane plus its one-cell border ring.
    fn in_bbox(&self, px: u16, py: u16) -> bool {
        !((self.xoff != 0 && px + 1 < self.xoff)
            || px > self.xoff + self.sx
            || (self.yoff != 0 && py + 1 < self.yoff)
            || py > self.yoff + self.sy)
    }
}

/// Border glyphs by cell type (`CELL_BORDERS` through the ACS table).
pub const BORDERS: [char; 13] = [
    ' ', '│', '─', '┌', '┐', '└', '┘', '┬', '┴', '├', '┤', '┼', '·',
];
const CELL_OUTSIDE: u8 = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellKind {
    Inside(usize),
    Outside,
    /// Index into `BORDERS`.
    Border(u8),
}

/// A window's panes with the border map precomputed, so classifying a
/// cell costs O(1) whatever the pane count.
pub struct Window<'a> {
    pub sx: u16,
    pub sy: u16,
    pub panes: &'a [PaneRect],
    pub active: usize,
    width: usize,
    height: usize,
    /// 0 undecided, 1 inside a pane, 2 border.
    border: Vec<u8>,
    /// First pane whose bbox covers the cell.
    owner: Vec<Option<u16>>,
}

impl<'a> Window<'a> {
    pub fn new(sx: u16, sy: u16, panes: &'a [PaneRect], active: usize) -> Window<'a> {
        // Cells up to (sx, sy) are classified and their neighbours looked at.
        let width = usize::from(sx) + 2;
        let height = usize::from(sy) + 2;
        let mut border = vec![0u8; width * height];
        let mut owner = vec![None; width * height];
        for (i, pane) in panes.iter().enumerate() {
            let x0 = pane.xoff.saturating_sub(1);
            let y0 = pane.yoff.saturating_sub(1);
            let x1 = (usize::from(pane.xoff) + usize::from(pane.sx)).min(width - 1);
            let y1 = (usize::from(pane.yoff) + usize::from(pane.sy)).min(height - 1);
            for py in usize::from(y0)..=y1 {
                for px in usize::from(x0)..=x1 {
                    let idx = py * width + px;
                    let (px16, py16) = (px as u16, py as u16);
                    if owner[idx].is_none() && pane.in_bbox(px16, py16) {
                        owner[idx] = Some(i as u16);
                    }
                    if border[idx] == 0 {
                        border[idx] = match pane.border1(px16, py16) {
                            0 => 1,
                            1 => 2,
                            _ => 0,
                        };
                    }
                }
            }
        }
        Window {
            sx,
            sy,
            panes,
            active,
            width,
            height,
            border,
            owner,
        }
    }

    /// `screen_redraw_cell_border`.
    fn is_border(&self, px: usize, py: usize) -> bool {
        px < self.width && py < self.height && self.border[py * self.width + px] == 2
    }

    /// `screen_redraw_check_cell`.
    pub fn classify(&self, px: u16, py: u16) -> CellKind {
        if px > self.sx || py > self.sy {
            return CellKind::Outside;
        }
        let (x, y) = (usize::from(px), usize::from(py));
        let Some(owner) = self.owner[y * self.width + x] else {
            return CellKind::Outside;
        };
        if !self.is_border(x, y) {
            return CellKind::Inside(usize::from(owner));
        }
        let mut bits = 0;
        if x == 0 || self.is_border(x - 1, y) {
            bits |= 8;
        }
        if self.is_border(x + 1, y) {
            bits |= 4;
        }
        if y == 0 || self.is_border(x, y - 1) {
            bits |= 2;
        }
        if self.is_border(x, y + 1) {
            bits |= 1;
        }
        let kind = match bits {
            15 => 11, // join
            14 => 8,  // bottom join
            13 => 7,  // top join
            12 => 2,  // top/bottom
            11 => 10, // right join
            10 => 6,  // bottom right
            9 => 4,   // top right
            7 => 9,   // left join
            6 => 5,   // bottom left
            5 => 3,   // top left
            3 => 1,   // left/right
            _ => return CellKind::Outside,
        };
        CellKind::Border(kind)
    }

    /// `screen_redraw_check_is` for the active pane: whether a border cell
    /// is drawn in the active colour. With exactly two panes only the half
    /// of the shared border nearest the active pane is.
    pub fn active_border(&self, px: u16, py: u16, kind: CellKind) -> bool {
        let Some(active) = self.panes.get(self.active) else {
            return false;
        };
        if active.border1(px, py) != 1 {
            return false;
        }
        if self.panes.len() != 2 {
            return true;
        }
        let owner = self.owner[usize::from(py) * self.width + usize::from(px)];
        let (Some(owner), CellKind::Border(_)) = (owner, kind) else {
            return true;
        };
        let wp = &self.panes[usize::from(owner)];
        let is_active = usize::from(owner) == self.active;
        if wp.xoff == 0 && wp.sx == self.sx {
            if wp.yoff == 0 {
                return if is_active {
                    px <= wp.sx / 2
                } else {
                    px > wp.sx / 2
                };
            }
            return false;
        }
        if wp.yoff == 0 && wp.sy == self.sy {
            if wp.xoff == 0 {
                return if is_active {
                    py <= wp.sy / 2
                } else {
                    py > wp.sy / 2
                };
            }
            return false;
        }
        true
    }
}

/// Draws borders and the outside filler over `rows` rows of the canvas
/// (`screen_redraw_draw_borders`), then the note a larger viewer gets.
pub fn draw_borders(canvas: &mut Canvas, rows: u16, window: &Window<'_>) {
    let cols = canvas.size().cols;
    for py in 0..rows {
        for px in 0..cols {
            let kind = window.classify(px, py);
            let idx = match kind {
                CellKind::Inside(_) => continue,
                CellKind::Outside => CELL_OUTSIDE,
                CellKind::Border(k) => k,
            };
            let attrs = if window.active_border(px, py, kind) {
                Attrs::ACTIVE_BORDER
            } else {
                Attrs::default()
            };
            canvas.set(py, px, Cell::new(BORDERS[usize::from(idx)], attrs));
        }
    }
    draw_small_note(canvas, rows, window);
}

/// "(size WxH from a smaller client)" at the bottom right when the viewer
/// is bigger than the window.
fn draw_small_note(canvas: &mut Canvas, rows: u16, window: &Window<'_>) {
    let cols = canvas.size().cols;
    if !(rows > window.sy || cols > window.sx) || rows == 0 {
        return;
    }
    let msg = format!("(size {}x{} from a smaller client)", window.sx, window.sy);
    let len = msg.len() as u16;
    let fits = (rows - 1 > window.sy && cols >= len) || cols.saturating_sub(window.sx) > len;
    if !fits {
        return;
    }
    canvas.put_str(rows - 1, cols - len, &msg, Attrs::default());
}

/// `window_clock_table` digits, 5x5 each.
const DIGITS: [[u8; 5]; 10] = [
    [0b11111, 0b10001, 0b10001, 0b10001, 0b11111],
    [0b00001, 0b00001, 0b00001, 0b00001, 0b00001],
    [0b11111, 0b00001, 0b11111, 0b10000, 0b11111],
    [0b11111, 0b00001, 0b11111, 0b00001, 0b11111],
    [0b10001, 0b10001, 0b11111, 0b00001, 0b00001],
    [0b11111, 0b10000, 0b11111, 0b00001, 0b11111],
    [0b11111, 0b10000, 0b11111, 0b10001, 0b11111],
    [0b11111, 0b00001, 0b00001, 0b00001, 0b00001],
    [0b11111, 0b10001, 0b11111, 0b10001, 0b11111],
    [0b11111, 0b10001, 0b11111, 0b00001, 0b11111],
];

/// `screen_redraw_draw_number` for `display-panes`: the pane's index in
/// big digits (`display-panes-colour` blue, `-active-colour` red) with its
/// size at the top right, or just the index when the pane is small.
pub fn draw_pane_number(canvas: &mut Canvas, pane: &PaneRect, index: usize, active: bool) {
    let colour = if active { Color::Idx(1) } else { Color::Idx(4) };
    let text = index.to_string();
    let len = text.len() as u16;
    if pane.sx < len {
        return;
    }
    let (mut px, mut py) = (pane.sx / 2, pane.sy / 2);
    let fg = Attrs::colours(colour, Color::Default);
    if pane.sx < len * 6 || pane.sy < 5 {
        canvas.put_str(pane.yoff + py, pane.xoff + px - len / 2, &text, fg);
        return;
    }
    px -= len * 3;
    py -= 2;
    let bg = Attrs::colours(Color::Default, colour);
    for ch in text.chars() {
        let Some(d) = ch.to_digit(10) else {
            continue;
        };
        for (j, bits) in DIGITS[d as usize].iter().enumerate() {
            for i in 0..5u16 {
                if bits & (1 << (4 - i)) != 0 {
                    canvas.set(
                        pane.yoff + py + j as u16,
                        pane.xoff + px + i,
                        Cell::blank(bg),
                    );
                }
            }
        }
        px += 6;
    }
    let size = format!("{}x{}", pane.sx, pane.sy);
    let slen = size.len() as u16;
    if pane.sx < slen || pane.sy < 6 {
        return;
    }
    canvas.put_str(pane.yoff, pane.xoff + pane.sx - slen, &size, fg);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::Size;

    fn canvas(cols: u16, rows: u16, window: &Window<'_>) -> Canvas {
        let mut c = Canvas::new(Size { cols, rows });
        draw_borders(&mut c, rows, window);
        c
    }

    fn rect(xoff: u16, yoff: u16, sx: u16, sy: u16) -> PaneRect {
        PaneRect { xoff, yoff, sx, sy }
    }

    #[test]
    fn single_pane_has_no_borders() {
        let panes = [rect(0, 0, 80, 23)];
        let w = Window::new(80, 23, &panes, 0);
        let c = canvas(80, 23, &w);
        assert!(c.rows_text().iter().all(String::is_empty));
        assert_eq!(w.classify(0, 0), CellKind::Inside(0));
        assert_eq!(w.classify(79, 22), CellKind::Inside(0));
    }

    #[test]
    fn two_panes_side_by_side() {
        // split-window -h on 80x23: left 0-39, border at 40, right 41-79.
        let panes = [rect(0, 0, 40, 23), rect(41, 0, 39, 23)];
        let w = Window::new(80, 23, &panes, 1);
        let c = canvas(80, 23, &w);
        for row in 0..23 {
            assert_eq!(c.row_text(row), format!("{}│", " ".repeat(40)), "row {row}");
        }
        // The active (right) pane owns the lower half of the shared border.
        assert_eq!(c.get(0, 40).unwrap().attrs, Attrs::default());
        assert_eq!(c.get(11, 40).unwrap().attrs, Attrs::default());
        assert_eq!(c.get(12, 40).unwrap().attrs, Attrs::ACTIVE_BORDER);
        assert_eq!(c.get(22, 40).unwrap().attrs, Attrs::ACTIVE_BORDER);
        let w = Window::new(80, 23, &panes, 0);
        let c = canvas(80, 23, &w);
        assert_eq!(c.get(11, 40).unwrap().attrs, Attrs::ACTIVE_BORDER);
        assert_eq!(c.get(12, 40).unwrap().attrs, Attrs::default());
    }

    #[test]
    fn two_panes_stacked() {
        let panes = [rect(0, 0, 80, 11), rect(0, 12, 80, 11)];
        let w = Window::new(80, 23, &panes, 0);
        let c = canvas(80, 23, &w);
        assert_eq!(c.row_text(11), "─".repeat(80));
        assert!(c.row_text(0).is_empty() && c.row_text(22).is_empty());
        assert_eq!(c.get(11, 40).unwrap().attrs, Attrs::ACTIVE_BORDER);
        assert_eq!(c.get(11, 41).unwrap().attrs, Attrs::default());
    }

    #[test]
    fn four_panes_tiled() {
        // tiled layout on 80x23: two rows of two panes.
        let panes = [
            rect(0, 0, 40, 11),
            rect(41, 0, 39, 11),
            rect(0, 12, 40, 11),
            rect(41, 12, 39, 11),
        ];
        let w = Window::new(80, 23, &panes, 3);
        let c = canvas(80, 23, &w);
        let middle = c.row_text(11);
        assert_eq!(middle, format!("{}┼{}", "─".repeat(40), "─".repeat(39)));
        assert_eq!(c.row_text(0), format!("{}│", " ".repeat(40)));
        assert_eq!(c.row_text(22), format!("{}│", " ".repeat(40)));
        // With more than two panes the whole active border is green.
        assert_eq!(c.get(11, 41).unwrap().attrs, Attrs::ACTIVE_BORDER);
        assert_eq!(
            c.get(11, 40).unwrap().attrs,
            Attrs::ACTIVE_BORDER,
            "the junction touches the active pane"
        );
        assert_eq!(c.get(11, 0).unwrap().attrs, Attrs::default());
        assert_eq!(c.get(15, 40).unwrap().attrs, Attrs::ACTIVE_BORDER);
        assert_eq!(c.get(5, 40).unwrap().attrs, Attrs::default());
    }

    #[test]
    fn bigger_viewer_gets_border_dots_and_note() {
        // Viewer 100x30 (29 rows of window area), window 60x19.
        let panes = [rect(0, 0, 60, 19)];
        let w = Window::new(60, 19, &panes, 0);
        let c = canvas(100, 29, &w);
        assert_eq!(
            c.row_text(0),
            format!("{}│{}", " ".repeat(60), "·".repeat(39))
        );
        assert_eq!(
            c.row_text(19),
            format!("{}┘{}", "─".repeat(60), "·".repeat(39))
        );
        assert_eq!(c.row_text(20), "·".repeat(100));
        assert_eq!(
            c.row_text(28),
            format!("{}(size 60x19 from a smaller client)", "·".repeat(66))
        );
        // Same size: nothing drawn.
        let c = canvas(60, 19, &w);
        assert!(c.rows_text().iter().all(String::is_empty));
        // Only wider: the note needs room to the right of the window.
        let c = canvas(70, 19, &w);
        assert_eq!(
            c.row_text(18),
            format!("{}│{}", " ".repeat(60), "·".repeat(9))
        );
        let c = canvas(100, 19, &w);
        assert!(
            c.row_text(18)
                .ends_with("(size 60x19 from a smaller client)")
        );
    }

    #[test]
    fn pane_numbers() {
        let pane = rect(0, 0, 40, 11);
        let mut c = Canvas::new(Size { cols: 80, rows: 23 });
        draw_pane_number(&mut c, &pane, 1, true);
        // Digit 1 is the right column of a 5x5 block starting at (20-3, 5-2).
        let red_bg = Attrs::colours(Color::Default, Color::Idx(1));
        for j in 0..5 {
            assert_eq!(c.get(3 + j, 21).unwrap().attrs, red_bg, "row {j}");
            assert_eq!(c.get(3 + j, 17).unwrap().attrs, Attrs::default());
        }
        assert_eq!(c.row_text(0), format!("{}40x11", " ".repeat(35)));
        assert_eq!(
            c.get(0, 35).unwrap().attrs,
            Attrs::colours(Color::Idx(1), Color::Default)
        );
        // A small pane just gets the digit.
        let small = rect(50, 0, 5, 3);
        draw_pane_number(&mut c, &small, 2, false);
        assert_eq!(c.get(1, 52).unwrap().ch, '2');
        assert_eq!(
            c.get(1, 52).unwrap().attrs,
            Attrs::colours(Color::Idx(4), Color::Default)
        );
    }
}
