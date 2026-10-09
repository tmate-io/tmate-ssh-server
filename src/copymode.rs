//! Copy mode as the host shows it (`window-copy.c` drawing, driven by
//! `SYNC_COPY_MODE` and `WRITE_COPY_MODE`). The host runs copy mode and
//! tells us the scroll offset, cursor, selection and prompt; we draw the
//! pane's history accordingly. Keys still go to the host.

use crate::proto;
use crate::render::{Attrs, Cell};

/// History kept for the output buffer `show-messages`/`list-keys` write
/// into (tmux uses an unbounded screen).
pub const OUTPUT_HISTORY: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub x: u16,
    /// As the client packs it: lines from the bottom of history + screen.
    pub y_from_bottom: i64,
    pub rect: bool,
}

pub struct CopyState {
    /// Whether the pane's own screen is shown (`copy-mode`) rather than
    /// the output buffer (`show-messages`).
    pub backing_pane: bool,
    output: Option<vt100::Parser>,
    output_written: bool,
    pub oy: usize,
    pub cx: u16,
    pub cy: u16,
    pub selection: Option<Selection>,
    /// `(prompt, input)` of the search/goto prompt on the last line.
    pub input: Option<(String, String)>,
}

pub use crate::grid::history_len;

impl CopyState {
    pub fn new(backing_pane: bool) -> CopyState {
        CopyState {
            backing_pane,
            output: None,
            output_written: false,
            oy: 0,
            cx: 0,
            cy: 0,
            selection: None,
            input: None,
        }
    }

    /// Applies a non-empty `SYNC_COPY_MODE`.
    pub fn sync(&mut self, m: &proto::CopyMode) {
        self.backing_pane = m.backing;
        self.oy = usize::try_from(m.oy).unwrap_or(0);
        self.cx = u16::try_from(m.cx).unwrap_or(u16::MAX);
        self.cy = u16::try_from(m.cy).unwrap_or(u16::MAX);
        self.selection = m.selection.as_ref().map(|s| Selection {
            x: u16::try_from(s.x).unwrap_or(u16::MAX),
            y_from_bottom: s.y_from_bottom,
            rect: s.rect,
        });
        self.input = m
            .input
            .as_ref()
            .map(|i| (i.prompt.clone(), i.input.clone()));
    }

    /// `window_copy_add`: a line of host output into the output buffer,
    /// which the pane shows once the host also syncs copy mode for it.
    pub fn add_output(&mut self, text: &str, rows: u16, cols: u16) {
        if self.backing_pane {
            return;
        }
        let written = std::mem::replace(&mut self.output_written, true);
        let out = self
            .output
            .get_or_insert_with(|| vt100::Parser::new(rows, cols, OUTPUT_HISTORY));
        let before = history_len(out);
        let mut bytes = Vec::with_capacity(text.len() + 2);
        if written {
            bytes.extend_from_slice(b"\r\n");
        }
        // `screen_write_vnputs` drops control characters.
        bytes.extend(
            text.chars()
                .filter(|c| !c.is_control())
                .collect::<String>()
                .into_bytes(),
        );
        out.process(&bytes);
        self.oy += history_len(out) - before;
    }

    pub fn resize(&mut self, rows: u16, cols: u16) {
        if let Some(out) = &mut self.output {
            out.screen_mut().set_size(rows, cols);
        }
    }

    /// Draws the mode screen for a pane of the given size: the backing
    /// screen scrolled by `oy`, the `[oy/history]` indicator, the
    /// selection in `mode-style` and the prompt line. Returns the rows and
    /// the cursor position.
    pub fn draw(&mut self, pane: &mut vt100::Parser) -> (Vec<Vec<Cell>>, (u16, u16)) {
        let (rows, cols) = pane.screen().size();
        let backing = if self.backing_pane {
            pane
        } else {
            self.output
                .get_or_insert_with(|| vt100::Parser::new(rows, cols, OUTPUT_HISTORY))
        };
        let hsize = history_len(backing);
        backing.screen_mut().set_scrollback(self.oy);
        let screen = backing.screen();
        let mut grid: Vec<Vec<Cell>> = (0..rows)
            .map(|r| {
                (0..cols)
                    .map(|c| screen.cell(r, c).map(Cell::from_vt).unwrap_or_default())
                    .collect()
            })
            .collect();
        backing.screen_mut().set_scrollback(0);

        if let Some(sel) = &self.selection {
            let ty = hsize as i64 - self.oy.min(hsize) as i64;
            let sely = hsize as i64 + i64::from(rows) - 1 - sel.y_from_bottom;
            let (mut sx, sy): (u16, u16) = if sely < ty {
                (if sel.rect { sel.x } else { 0 }, 0)
            } else if sely > ty + i64::from(rows) - 1 {
                (
                    if sel.rect {
                        sel.x
                    } else {
                        cols.saturating_sub(1)
                    },
                    rows.saturating_sub(1),
                )
            } else {
                (sel.x, (sely - ty) as u16)
            };
            sx = sx.min(cols.saturating_sub(1));
            let (ex, ey) = (self.cx, self.cy);
            for (py, row) in grid.iter_mut().enumerate() {
                for (px, cell) in row.iter_mut().enumerate() {
                    if check_selection(sx, sy, ex, ey, sel.rect, px as u16, py as u16) {
                        cell.attrs = Attrs::MODE;
                    }
                }
            }
        }

        if rows > 0 {
            let hdr = format!("[{}/{}]", self.oy, hsize);
            let cells = crate::render::clip_cells(
                crate::render::cells_of(&hdr, Attrs::MODE),
                usize::from(cols),
            );
            let start = usize::from(cols) - cells.len();
            grid[0][start..].copy_from_slice(&cells);
            if let Some((prompt, input)) = &self.input {
                let text = format!("{prompt}: {input}");
                let cells = crate::render::clip_cells(
                    crate::render::cells_of(&text, Attrs::MODE),
                    usize::from(cols),
                );
                let last = usize::from(rows) - 1;
                grid[last][..cells.len()].copy_from_slice(&cells);
            }
        }

        let (cx, cy) = (self.cx.min(cols), self.cy.min(rows.saturating_sub(1)));
        if cx == cols && cols > 0 {
            grid[usize::from(cy)][usize::from(cols) - 1] = Cell::new('$', Attrs::default());
        }
        (grid, (cy, cx.min(cols.saturating_sub(1))))
    }
}

/// `screen_check_selection` with emacs mode keys.
fn check_selection(sx: u16, sy: u16, ex: u16, ey: u16, rect: bool, px: u16, py: u16) -> bool {
    if rect {
        if sy < ey {
            if py < sy || py > ey {
                return false;
            }
        } else if sy > ey {
            if py > sy || py < ey {
                return false;
            }
        } else if py != sy {
            return false;
        }
        if ex < sx {
            px >= ex && px <= sx
        } else {
            px >= sx && px <= ex
        }
    } else if sy < ey {
        if py < sy || py > ey {
            return false;
        }
        if py == sy && px < sx {
            return false;
        }
        !(py == ey && px > ex)
    } else if sy > ey {
        if py > sy || py < ey {
            return false;
        }
        if py == ey && px < ex {
            return false;
        }
        let xx = sx.saturating_sub(1);
        !(py == sy && px > xx)
    } else {
        if py != sy {
            return false;
        }
        if ex < sx {
            let xx = sx.saturating_sub(1);
            !(px > xx || px < ex)
        } else {
            !(px < sx || px > ex)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(row: &[Cell]) -> String {
        row.iter()
            .filter(|c| c.width != 0)
            .map(|c| c.ch)
            .collect::<String>()
            .trim_end()
            .to_string()
    }

    fn pane_with_lines(n: usize) -> vt100::Parser {
        let mut p = vt100::Parser::new(5, 20, 100);
        for i in 1..=n {
            p.process(format!("line{i}\r\n").as_bytes());
        }
        p
    }

    fn mode(oy: i64, cx: i64, cy: i64, sel: Option<(i64, i64, bool)>) -> proto::CopyMode {
        proto::CopyMode {
            backing: true,
            oy,
            cx,
            cy,
            selection: sel.map(|(x, y, rect)| proto::Selection {
                x,
                y_from_bottom: y,
                rect,
            }),
            input: None,
        }
    }

    #[test]
    fn scrolled_view_with_indicator() {
        let mut pane = pane_with_lines(10);
        // Screen shows line7..line10 + prompt line; 6 lines of history.
        let mut cs = CopyState::new(true);
        cs.sync(&mode(0, 0, 4, None));
        let (grid, cursor) = cs.draw(&mut pane);
        assert_eq!(text(&grid[0]), "line7          [0/6]");
        assert_eq!(cursor, (4, 0));
        assert_eq!(grid[0][15].attrs, Attrs::MODE);
        cs.sync(&mode(6, 3, 0, None));
        let (grid, cursor) = cs.draw(&mut pane);
        assert_eq!(text(&grid[0]), "line1          [6/6]");
        assert_eq!(text(&grid[4]), "line5");
        assert_eq!(cursor, (0, 3));
        assert_eq!(
            pane.screen().scrollback(),
            0,
            "the live view is restored after drawing"
        );
    }

    #[test]
    fn selection_is_highlighted() {
        let mut pane = pane_with_lines(10);
        let mut cs = CopyState::new(true);
        // Selection started at x=1 on the second screen row (line8: 3 from the bottom),
        // cursor at (3, 2): rows 1..=2 selected from col 1 to col 3.
        cs.sync(&mode(0, 3, 2, Some((1, 3, false))));
        let (grid, _) = cs.draw(&mut pane);
        let selected: Vec<(usize, usize)> = grid
            .iter()
            .enumerate()
            .flat_map(|(r, row)| {
                row.iter()
                    .enumerate()
                    .filter(|(_, c)| c.attrs == Attrs::MODE)
                    .map(move |(c, _)| (r, c))
            })
            .filter(|(r, c)| !(*r == 0 && *c >= 14))
            .collect();
        assert_eq!(selected.first(), Some(&(1, 1)));
        assert_eq!(selected.last(), Some(&(2, 3)));
        assert_eq!(selected.len(), 19 + 4);
        // Rectangle selection.
        cs.sync(&mode(0, 3, 2, Some((1, 3, true))));
        let (grid, _) = cs.draw(&mut pane);
        assert_eq!(grid[1][0].attrs, Attrs::default());
        assert_eq!(grid[1][1].attrs, Attrs::MODE);
        assert_eq!(grid[1][3].attrs, Attrs::MODE);
        assert_eq!(grid[1][4].attrs, Attrs::default());
        assert_eq!(grid[2][2].attrs, Attrs::MODE);
    }

    #[test]
    fn prompt_line_and_output_buffer() {
        let mut pane = pane_with_lines(2);
        let mut cs = CopyState::new(true);
        let mut m = mode(0, 0, 0, None);
        m.input = Some(proto::CopyModeInput {
            kind: 3,
            prompt: "Search Up".into(),
            input: "foo".into(),
        });
        cs.sync(&m);
        let (grid, _) = cs.draw(&mut pane);
        assert_eq!(text(&grid[4]), "Search Up: foo");
        assert_eq!(grid[4][0].attrs, Attrs::MODE);

        let mut cs = CopyState::new(false);
        cs.add_output("first message", 5, 20);
        cs.add_output("second message", 5, 20);
        cs.add_output("\x01ctrl\x07 stripped", 5, 20);
        let (grid, _) = cs.draw(&mut pane);
        assert_eq!(text(&grid[0]), "first message  [0/0]");
        assert_eq!(text(&grid[1]), "second message");
        assert_eq!(text(&grid[2]), "ctrl stripped");
        for _ in 0..5 {
            cs.add_output("more", 5, 20);
        }
        assert_eq!(cs.oy, 3, "the view stays at the top as history grows");
        let (grid, _) = cs.draw(&mut pane);
        assert_eq!(text(&grid[0]), "first message  [3/3]");
    }

    #[test]
    fn cursor_past_the_edge_shows_a_dollar() {
        let mut pane = pane_with_lines(1);
        let mut cs = CopyState::new(true);
        cs.sync(&mode(0, 20, 0, None));
        let (grid, cursor) = cs.draw(&mut pane);
        assert_eq!(grid[0][19].ch, '$');
        assert_eq!(cursor, (0, 19));
    }
}
