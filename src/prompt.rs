//! The status-line prompt (`status.c`): `command-prompt` and
//! `confirm-before` run on the server, edited with `status-keys emacs`.

use crate::cmdline::{self, Args};
use crate::keys::{KEYC_ESCAPE, Special};
use crate::render::{Attrs, Cell, cells_of, clip_cells};

enum Kind {
    Command {
        template: String,
        /// Remaining prompts and their initial inputs, in order.
        prompts: Vec<String>,
        inputs: Vec<String>,
        idx: u32,
    },
    Confirm {
        cmd: String,
    },
}

pub struct Prompt {
    pub text: String,
    buffer: Vec<char>,
    index: usize,
    kind: Kind,
    /// `PROMPT_SINGLE`: the first character answers the prompt.
    single: bool,
}

/// What pressing a key did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Still editing (the row may need redrawing).
    Editing,
    /// The prompt is finished and this command string should run.
    Run(String),
    /// Cancelled, or answered negatively.
    Cancelled,
}

/// `mode_key_emacs_edit` commands. Tab completion, history and paste need
/// state tmux has and we do not; they do nothing.
enum Edit {
    Start,
    Left,
    Cancel,
    Delete,
    End,
    Right,
    Backspace,
    DeleteToEnd,
    Transpose,
    DeleteLine,
    DeleteWord,
    PreviousWord,
    NextWordEnd,
    Enter,
    Insert(char),
    Nothing,
}

impl Edit {
    fn for_key(key: u64) -> Edit {
        match key {
            0x01 => Edit::Start,
            0x02 => Edit::Left,
            0x03 | 0x1b => Edit::Cancel,
            0x04 => Edit::Delete,
            0x05 => Edit::End,
            0x06 => Edit::Right,
            0x08 => Edit::Backspace,
            0x0b => Edit::DeleteToEnd,
            0x14 => Edit::Transpose,
            0x15 => Edit::DeleteLine,
            0x17 => Edit::DeleteWord,
            0x0a | 0x0d => Edit::Enter,
            k if k == Special::Home.code() || k == b'm' as u64 | KEYC_ESCAPE => Edit::Start,
            k if k == Special::End.code() => Edit::End,
            k if k == Special::Left.code() => Edit::Left,
            k if k == Special::Right.code() => Edit::Right,
            k if k == Special::BSpace.code() => Edit::Backspace,
            k if k == Special::DC.code() => Edit::Delete,
            k if k == b'b' as u64 | KEYC_ESCAPE => Edit::PreviousWord,
            k if k == b'f' as u64 | KEYC_ESCAPE => Edit::NextWordEnd,
            k if (0x20..0x7f).contains(&k) => Edit::Insert(char::from(k as u8)),
            _ => Edit::Nothing,
        }
    }
}

impl Prompt {
    /// `command-prompt [-I inputs] [-p prompts] [template]`; `expand`
    /// handles tmux formats (`#W`, `#S`) in prompts and inputs.
    pub fn command_prompt(args: &Args, expand: &dyn Fn(&str) -> String) -> Prompt {
        let template = args
            .positional
            .first()
            .cloned()
            .unwrap_or_else(|| "%1".into());
        let mut prompts: Vec<String> = match args.get('p') {
            Some(p) => p.split(',').map(|s| format!("{s} ")).collect(),
            None if !args.positional.is_empty() => {
                let n = template.find([' ', ',']).unwrap_or(template.len());
                vec![format!("({}) ", &template[..n])]
            }
            None => vec![":".into()],
        };
        let mut inputs: Vec<String> = args
            .get('I')
            .map(|i| i.split(',').map(str::to_string).collect())
            .unwrap_or_default();
        let text = expand(&prompts.remove(0));
        let input = if inputs.is_empty() {
            String::new()
        } else {
            expand(&inputs.remove(0))
        };
        Prompt {
            text,
            buffer: input.chars().collect(),
            index: input.chars().count(),
            kind: Kind::Command {
                template,
                prompts,
                inputs,
                idx: 1,
            },
            single: false,
        }
    }

    /// `confirm-before [-p prompt] command`.
    pub fn confirm_before(args: &Args, expand: &dyn Fn(&str) -> String) -> Option<Prompt> {
        let cmd = args.positional.first()?.clone();
        let text = match args.get('p') {
            Some(p) => format!("{p} "),
            None => format!(
                "Confirm '{}'? (y/n) ",
                cmd.split([' ', '\t']).next().unwrap_or("")
            ),
        };
        Some(Prompt {
            text: expand(&text),
            buffer: Vec::new(),
            index: 0,
            kind: Kind::Confirm { cmd },
            single: true,
        })
    }

    pub fn buffer(&self) -> String {
        self.buffer.iter().collect()
    }

    #[cfg(test)]
    pub fn index(&self) -> usize {
        self.index
    }

    /// `status_prompt_key` with the emacs edit table.
    pub fn key(&mut self, key: u64) -> Outcome {
        let size = self.buffer.len();
        let wsep = |c: char| " -_@".contains(c);
        match Edit::for_key(key) {
            Edit::Start => self.index = 0,
            Edit::Left => self.index = self.index.saturating_sub(1),
            Edit::Cancel => return Outcome::Cancelled,
            Edit::Delete => {
                if self.index < size {
                    self.buffer.remove(self.index);
                }
            }
            Edit::End => self.index = size,
            Edit::Right => self.index = (self.index + 1).min(size),
            Edit::Backspace => {
                if self.index > 0 {
                    self.index -= 1;
                    self.buffer.remove(self.index);
                }
            }
            Edit::DeleteToEnd => self.buffer.truncate(self.index),
            Edit::Transpose => {
                let mut idx = self.index;
                if idx < size {
                    idx += 1;
                }
                if idx >= 2 {
                    self.buffer.swap(idx - 2, idx - 1);
                    self.index = idx;
                }
            }
            Edit::DeleteLine => {
                self.buffer.clear();
                self.index = 0;
            }
            Edit::DeleteWord => {
                let mut idx = self.index;
                while idx > 0 {
                    idx -= 1;
                    if !wsep(self.buffer[idx]) {
                        break;
                    }
                }
                while idx > 0 {
                    idx -= 1;
                    if wsep(self.buffer[idx]) {
                        idx += 1;
                        break;
                    }
                }
                self.buffer.drain(idx..self.index);
                self.index = idx;
            }
            Edit::PreviousWord => {
                while self.index > 0 {
                    self.index -= 1;
                    if !wsep(self.buffer[self.index]) {
                        break;
                    }
                }
                while self.index > 0 {
                    self.index -= 1;
                    if wsep(self.buffer[self.index]) {
                        self.index += 1;
                        break;
                    }
                }
            }
            Edit::NextWordEnd => {
                while self.index < size {
                    self.index += 1;
                    if self.index < size && !wsep(self.buffer[self.index]) {
                        break;
                    }
                }
                while self.index < size {
                    self.index += 1;
                    if self.index < size && wsep(self.buffer[self.index]) {
                        break;
                    }
                }
            }
            Edit::Enter => return self.submit(),
            Edit::Insert(c) => {
                self.buffer.insert(self.index, c);
                self.index += 1;
                if self.single {
                    return self.submit();
                }
            }
            Edit::Nothing => {}
        }
        Outcome::Editing
    }

    fn submit(&mut self) -> Outcome {
        let answer = self.buffer();
        match &mut self.kind {
            Kind::Command {
                template,
                prompts,
                inputs,
                idx,
            } => {
                *template = cmdline::template_replace(template, &answer, *idx);
                if !prompts.is_empty() {
                    self.text = prompts.remove(0);
                    let input = if inputs.is_empty() {
                        String::new()
                    } else {
                        inputs.remove(0)
                    };
                    self.buffer = input.chars().collect();
                    self.index = self.buffer.len();
                    *idx += 1;
                    return Outcome::Editing;
                }
                Outcome::Run(template.clone())
            }
            Kind::Confirm { cmd } => {
                if answer.eq_ignore_ascii_case("y") {
                    Outcome::Run(cmd.clone())
                } else {
                    Outcome::Cancelled
                }
            }
        }
    }

    /// `status_prompt_redraw`: prompt text, the buffer scrolled so the
    /// cursor is visible, and a reverse-video fake cursor.
    pub fn render(&self, cols: usize) -> Vec<Cell> {
        let attrs = Attrs::MODE;
        let mut line = vec![Cell::blank(attrs); cols];
        if cols == 0 {
            return line;
        }
        let prompt = clip_cells(cells_of(&self.text, attrs), cols);
        let len = prompt.len();
        line[..len].copy_from_slice(&prompt);
        let left = cols - len;
        let mut off = 0;
        if left != 0 {
            let buffer: String = self.buffer.iter().collect();
            let mut size = self.buffer.len();
            let mut left = left;
            if self.index >= left {
                off = self.index - left + 1;
                if self.index == size {
                    left -= 1;
                }
                size = left;
            }
            let shown: String = buffer.chars().skip(off).collect();
            let shown = clip_cells(cells_of(&shown, attrs), left);
            line[len..len + shown.len()].copy_from_slice(&shown);
            let _ = size;
        }
        let cursor = len + self.index - off;
        if let Some(cell) = line.get_mut(cursor) {
            cell.attrs.inverse = !cell.attrs.inverse;
        }
        line
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn no_expand(s: &str) -> String {
        s.to_string()
    }

    fn type_keys(p: &mut Prompt, s: &str) -> Outcome {
        let mut last = Outcome::Editing;
        for c in s.chars() {
            last = p.key(c as u64);
        }
        last
    }

    fn text(cells: &[Cell]) -> String {
        cells
            .iter()
            .map(|c| c.ch)
            .collect::<String>()
            .trim_end()
            .to_string()
    }

    #[test]
    fn plain_prompt_edits_and_submits() {
        let args = Args::parse("I:p:t:", &argv(&[])).unwrap();
        let mut p = Prompt::command_prompt(&args, &no_expand);
        assert_eq!(p.text, ":");
        assert_eq!(type_keys(&mut p, "renam-window x"), Outcome::Editing);
        // Fix the typo with cursor movement: C-a, 5x Right, insert 'e'.
        p.key(0x01);
        for _ in 0..5 {
            p.key(Special::Right.code());
        }
        p.key(b'e' as u64);
        assert_eq!(p.buffer(), "rename-window x");
        // C-e, BSpace, C-h, then type.
        p.key(0x05);
        p.key(Special::BSpace.code());
        p.key(0x08);
        type_keys(&mut p, " y");
        assert_eq!(p.buffer(), "rename-window y");
        // C-k from after "rename".
        p.key(0x01);
        for _ in 0..6 {
            p.key(0x06);
        }
        p.key(0x0b);
        assert_eq!(p.buffer(), "rename");
        p.key(0x15);
        assert_eq!(p.buffer(), "");
        type_keys(&mut p, "new-window -n test");
        p.key(0x17);
        assert_eq!(p.buffer(), "new-window -n ", "C-w deletes a word");
        p.key(Special::Left.code());
        p.key(0x04);
        assert_eq!(p.buffer(), "new-window -n");
        p.key(Special::Home.code());
        p.key(Special::Right.code());
        p.key(0x14);
        assert_eq!(p.buffer(), "enw-window -n", "C-t transposes");
        p.key(0x01);
        p.key(0x04);
        p.key(0x04);
        p.key(0x04);
        assert_eq!(p.key(b'\r' as u64), Outcome::Run("-window -n".into()));
    }

    #[test]
    fn cancel_and_templates() {
        let args = Args::parse("I:p:t:", &argv(&[])).unwrap();
        let mut p = Prompt::command_prompt(&args, &no_expand);
        type_keys(&mut p, "abc");
        assert_eq!(p.key(0x1b), Outcome::Cancelled);
        let mut p = Prompt::command_prompt(&args, &no_expand);
        assert_eq!(p.key(0x03), Outcome::Cancelled);
        assert_eq!(
            Prompt::command_prompt(&args, &no_expand).key(b'\r' as u64),
            Outcome::Run("".into())
        );

        // bind , : command-prompt -I'#W' "rename-window '%%'"
        let args = Args::parse("I:p:t:", &argv(&["-I#W", "rename-window '%%'"])).unwrap();
        let expand = |s: &str| s.replace("#W", "bash");
        let mut p = Prompt::command_prompt(&args, &expand);
        assert_eq!(p.text, "(rename-window) ");
        assert_eq!(p.buffer(), "bash");
        assert_eq!(p.index(), 4);
        type_keys(&mut p, "-2");
        assert_eq!(
            p.key(b'\r' as u64),
            Outcome::Run("rename-window 'bash-2'".into())
        );

        // bind ' : command-prompt -pindex "select-window -t ':%%'"
        let args = Args::parse("I:p:t:", &argv(&["-pindex", "select-window -t ':%%'"])).unwrap();
        let mut p = Prompt::command_prompt(&args, &no_expand);
        assert_eq!(p.text, "index ");
        assert_eq!(
            type_keys(&mut p, "3\r"),
            Outcome::Run("select-window -t ':3'".into())
        );

        // Several prompts fill %1, %2 in turn.
        let args = Args::parse(
            "I:p:t:",
            &argv(&["-pfrom,to", "-Ia", "swap-window -s %1 -t %2"]),
        )
        .unwrap();
        let mut p = Prompt::command_prompt(&args, &no_expand);
        assert_eq!((p.text.as_str(), p.buffer()), ("from ", "a".into()));
        assert_eq!(p.key(b'\r' as u64), Outcome::Editing);
        assert_eq!((p.text.as_str(), p.buffer()), ("to ", "".into()));
        assert_eq!(
            type_keys(&mut p, "b\r"),
            Outcome::Run("swap-window -s a -t b".into())
        );
    }

    #[test]
    fn confirm_before_takes_one_key() {
        let args = Args::parse("p:t:", &argv(&["-pkill-window #W? (y/n)", "kill-window"])).unwrap();
        let expand = |s: &str| s.replace("#W", "vim");
        let mut p = Prompt::confirm_before(&args, &expand).unwrap();
        assert_eq!(p.text, "kill-window vim? (y/n) ");
        assert_eq!(p.key(b'y' as u64), Outcome::Run("kill-window".into()));
        let mut p = Prompt::confirm_before(&args, &expand).unwrap();
        assert_eq!(p.key(b'n' as u64), Outcome::Cancelled);
        let mut p = Prompt::confirm_before(&args, &expand).unwrap();
        assert_eq!(p.key(b'Y' as u64), Outcome::Run("kill-window".into()));
        let mut p = Prompt::confirm_before(&args, &expand).unwrap();
        assert_eq!(
            p.key(b'\r' as u64),
            Outcome::Cancelled,
            "an empty answer is no"
        );
        let args = Args::parse("p:t:", &argv(&["kill-pane -a"])).unwrap();
        let p = Prompt::confirm_before(&args, &no_expand).unwrap();
        assert_eq!(p.text, "Confirm 'kill-pane'? (y/n) ");
        assert!(
            Prompt::confirm_before(&Args::parse("p:t:", &argv(&[])).unwrap(), &no_expand).is_none()
        );
    }

    #[test]
    fn rendering_with_fake_cursor_and_scrolling() {
        let args = Args::parse("I:p:t:", &argv(&[])).unwrap();
        let mut p = Prompt::command_prompt(&args, &no_expand);
        type_keys(&mut p, "abc");
        let cells = p.render(10);
        assert_eq!(text(&cells), ":abc");
        assert!(cells[4].attrs.inverse, "cursor after the text");
        assert!(!cells[3].attrs.inverse);
        assert!(
            cells
                .iter()
                .all(|c| c.attrs.fg == Attrs::MODE.fg && c.attrs.bg == Attrs::MODE.bg)
        );
        p.key(Special::Left.code());
        let cells = p.render(10);
        assert!(cells[3].attrs.inverse && !cells[4].attrs.inverse);
        // Long input scrolls so the cursor stays visible.
        let mut p = Prompt::command_prompt(&args, &no_expand);
        type_keys(&mut p, "0123456789abcdef");
        let cells = p.render(10);
        assert_eq!(text(&cells), ":89abcdef");
        assert!(cells[9].attrs.inverse);
        p.key(0x01);
        assert_eq!(text(&p.render(10)), ":012345678");
    }
}
