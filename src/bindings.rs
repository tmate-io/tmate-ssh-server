//! Key tables and bindings as tmux 2.2 keeps them (`key-bindings.c`,
//! `key-string.c`) and the per-client prefix/repeat state machine of
//! `server-client.c:server_client_handle_key`.
//!
//! The server starts with tmux's default bindings because the host only
//! replicates the `bind-key`/`unbind-key` commands a user ran on top.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::cmdline::{self, Args};
use crate::keys::{KEYC_BASE, KEYC_CTRL, KEYC_ESCAPE, KEYC_SHIFT, Special};

/// Default bindings from `key_bindings_init`.
const DEFAULTS: &[&str] = &[
    "bind C-b send-prefix",
    "bind C-o rotate-window",
    "bind C-z suspend-client",
    "bind Space next-layout",
    "bind ! break-pane",
    "bind '\"' split-window",
    "bind '#' list-buffers",
    "bind '$' command-prompt -I'#S' \"rename-session '%%'\"",
    "bind % split-window -h",
    "bind & confirm-before -p\"kill-window #W? (y/n)\" kill-window",
    "bind \"'\" command-prompt -pindex \"select-window -t ':%%'\"",
    "bind ( switch-client -p",
    "bind ) switch-client -n",
    "bind , command-prompt -I'#W' \"rename-window '%%'\"",
    "bind - delete-buffer",
    "bind . command-prompt \"move-window -t '%%'\"",
    "bind 0 select-window -t:=0",
    "bind 1 select-window -t:=1",
    "bind 2 select-window -t:=2",
    "bind 3 select-window -t:=3",
    "bind 4 select-window -t:=4",
    "bind 5 select-window -t:=5",
    "bind 6 select-window -t:=6",
    "bind 7 select-window -t:=7",
    "bind 8 select-window -t:=8",
    "bind 9 select-window -t:=9",
    "bind : command-prompt",
    "bind \\; last-pane",
    "bind = choose-buffer",
    "bind ? list-keys",
    "bind D choose-client",
    "bind L switch-client -l",
    "bind M select-pane -M",
    "bind [ copy-mode",
    "bind ] paste-buffer",
    "bind c new-window",
    "bind d detach-client",
    "bind f command-prompt \"find-window '%%'\"",
    "bind i display-message",
    "bind l last-window",
    "bind m select-pane -m",
    "bind n next-window",
    "bind o select-pane -t:.+",
    "bind p previous-window",
    "bind q display-panes",
    "bind r refresh-client",
    "bind s choose-tree",
    "bind t clock-mode",
    "bind w choose-window",
    "bind x confirm-before -p\"kill-pane #P? (y/n)\" kill-pane",
    "bind z resize-pane -Z",
    "bind { swap-pane -U",
    "bind } swap-pane -D",
    "bind '~' show-messages",
    "bind PPage copy-mode -u",
    "bind -r Up select-pane -U",
    "bind -r Down select-pane -D",
    "bind -r Left select-pane -L",
    "bind -r Right select-pane -R",
    "bind M-1 select-layout even-horizontal",
    "bind M-2 select-layout even-vertical",
    "bind M-3 select-layout main-horizontal",
    "bind M-4 select-layout main-vertical",
    "bind M-5 select-layout tiled",
    "bind M-n next-window -a",
    "bind M-o rotate-window -D",
    "bind M-p previous-window -a",
    "bind -r M-Up resize-pane -U 5",
    "bind -r M-Down resize-pane -D 5",
    "bind -r M-Left resize-pane -L 5",
    "bind -r M-Right resize-pane -R 5",
    "bind -r C-Up resize-pane -U",
    "bind -r C-Down resize-pane -D",
    "bind -r C-Left resize-pane -L",
    "bind -r C-Right resize-pane -R",
    "bind -n MouseDown1Pane select-pane -t=\\; send-keys -M",
    "bind -n MouseDrag1Border resize-pane -M",
    "bind -n MouseDown1Status select-window -t=",
    "bind -n WheelDownStatus next-window",
    "bind -n WheelUpStatus previous-window",
    "bind -n MouseDrag1Pane if -Ft= '#{mouse_any_flag}' 'if -Ft= \"#{pane_in_mode}\" \"copy-mode -M\" \"send-keys -M\"' 'copy-mode -M'",
    "bind -n MouseDown3Pane if-shell -Ft= '#{mouse_any_flag}' 'select-pane -t=; send-keys -M' 'select-pane -mt='",
    "bind -n WheelUpPane if-shell -Ft= '#{mouse_any_flag}' 'send-keys -M' 'if -Ft= \"#{pane_in_mode}\" \"send-keys -M\" \"copy-mode -et=\"'",
];

/// Named keys from `key_string_table`, with their `KEYC_BASE` offsets.
const NAMED: &[(&str, u64)] = &[
    ("F1", Special::F1 as u64),
    ("F2", Special::F2 as u64),
    ("F3", Special::F3 as u64),
    ("F4", Special::F4 as u64),
    ("F5", Special::F5 as u64),
    ("F6", Special::F6 as u64),
    ("F7", Special::F7 as u64),
    ("F8", Special::F8 as u64),
    ("F9", Special::F9 as u64),
    ("F10", Special::F10 as u64),
    ("F11", Special::F11 as u64),
    ("F12", Special::F12 as u64),
    ("IC", Special::IC as u64),
    ("DC", Special::DC as u64),
    ("Home", Special::Home as u64),
    ("End", Special::End as u64),
    ("NPage", Special::NPage as u64),
    ("PageDown", Special::NPage as u64),
    ("PgDn", Special::NPage as u64),
    ("PPage", Special::PPage as u64),
    ("PageUp", Special::PPage as u64),
    ("PgUp", Special::PPage as u64),
    ("BTab", Special::BTab as u64),
    ("BSpace", Special::BSpace as u64),
    ("Up", Special::Up as u64),
    ("Down", Special::Down as u64),
    ("Left", Special::Left as u64),
    ("Right", Special::Right as u64),
    ("KP/", Special::KpSlash as u64),
    ("KP*", Special::KpStar as u64),
    ("KP-", Special::KpMinus as u64),
    ("KP7", Special::KpSeven as u64),
    ("KP8", Special::KpEight as u64),
    ("KP9", Special::KpNine as u64),
    ("KP+", Special::KpPlus as u64),
    ("KP4", Special::KpFour as u64),
    ("KP5", Special::KpFive as u64),
    ("KP6", Special::KpSix as u64),
    ("KP1", Special::KpOne as u64),
    ("KP2", Special::KpTwo as u64),
    ("KP3", Special::KpThree as u64),
    ("KPEnter", Special::KpEnter as u64),
    ("KP0", Special::KpZero as u64),
    ("KP.", Special::KpPeriod as u64),
];

/// Plain keys with names.
const NAMED_PLAIN: &[(&str, u64)] = &[("Tab", 9), ("Space", 32), ("Enter", 13), ("Escape", 27)];

/// Mouse key names: `KEYC_MOUSE` is offset 2, then three entries
/// (Pane, Status, Border) per button event in enum order.
const MOUSE: &[&str] = &[
    "MouseDown1",
    "MouseDown2",
    "MouseDown3",
    "MouseUp1",
    "MouseUp2",
    "MouseUp3",
    "MouseDrag1",
    "MouseDrag2",
    "MouseDrag3",
    "MouseDragEnd1",
    "MouseDragEnd2",
    "MouseDragEnd3",
    "WheelUp",
    "WheelDown",
];

fn search_table(s: &str) -> Option<u64> {
    for (name, off) in NAMED {
        if name.eq_ignore_ascii_case(s) {
            return Some(KEYC_BASE + off);
        }
    }
    for (name, key) in NAMED_PLAIN {
        if name.eq_ignore_ascii_case(s) {
            return Some(*key);
        }
    }
    for (i, name) in MOUSE.iter().enumerate() {
        for (j, suffix) in ["Pane", "Status", "Border"].iter().enumerate() {
            if format!("{name}{suffix}").eq_ignore_ascii_case(s) {
                return Some(KEYC_BASE + 3 + (i * 3 + j) as u64);
            }
        }
    }
    None
}

/// `key_string_lookup_string`: a key name to a `key_code`, or `None` for
/// `None`/unknown names.
pub fn parse_key(s: &str) -> Option<u64> {
    if s.eq_ignore_ascii_case("None") {
        return None;
    }
    if let Some(hex) = s.strip_prefix("0x") {
        let digits: String = hex.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        if digits.is_empty() || digits.len() > 4 {
            return None;
        }
        return u64::from_str_radix(&digits, 16).ok();
    }
    let mut modifiers = 0;
    let mut rest = s;
    if let Some(after) = rest.strip_prefix('^')
        && !after.is_empty()
    {
        modifiers |= KEYC_CTRL;
        rest = after;
    }
    // Any letter followed by `-` is consumed as a modifier; unknown ones
    // are ignored, as in `key_string_get_modifiers`.
    loop {
        let mut chars = rest.chars();
        match (chars.next(), chars.next()) {
            (Some(m), Some('-')) => {
                match m {
                    'C' | 'c' => modifiers |= KEYC_CTRL,
                    'M' | 'm' => modifiers |= KEYC_ESCAPE,
                    'S' | 's' => modifiers |= KEYC_SHIFT,
                    _ => {}
                }
                rest = &rest[m.len_utf8() + 1..];
            }
            _ => break,
        }
    }
    let mut chars = rest.chars();
    let first = chars.next()?;
    let single = chars.next().is_none();
    let key = if single && first.is_ascii() {
        let key = first as u64;
        if key < 32 || key == 127 {
            return None;
        }
        key
    } else if !first.is_ascii() {
        // A single UTF-8 key is its code point, modifiers kept as given;
        // anything longer is not a key name.
        return single.then_some(first as u64 | modifiers);
    } else {
        search_table(rest)?
    };
    // `C-a` is 0x01, `C-Space` is 0, `C-?` is BSpace; `C-` on the
    // punctuation in `other` keeps the modifier bit.
    const OTHER: &str = "!#()+,-.0123456789:;<=>?'\r\t";
    if key < KEYC_BASE && modifiers & KEYC_CTRL != 0 && !OTHER.contains(char::from_u32(key as u32)?)
    {
        let converted = match key {
            97..=122 => key - 96,
            64..=95 => key - 64,
            32 => 0,
            _ => return None,
        };
        return Some(converted | (modifiers & !KEYC_CTRL));
    }
    if key == 63 && modifiers & KEYC_CTRL != 0 {
        return Some(Special::BSpace.code() | (modifiers & !KEYC_CTRL));
    }
    Some(key | modifiers)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub repeat: bool,
    /// The bound command list, one canonical argv per command.
    pub cmds: Vec<Vec<String>>,
}

/// All key tables; `root` and `prefix` always exist.
#[derive(Debug, Clone)]
pub struct KeyTables {
    tables: BTreeMap<String, BTreeMap<u64, Binding>>,
}

impl Default for KeyTables {
    fn default() -> Self {
        Self::tmux_defaults()
    }
}

impl KeyTables {
    pub fn empty() -> Self {
        let mut tables = BTreeMap::new();
        tables.insert("root".to_string(), BTreeMap::new());
        tables.insert("prefix".to_string(), BTreeMap::new());
        KeyTables { tables }
    }

    /// tmux 2.2's default bindings.
    pub fn tmux_defaults() -> Self {
        let mut t = Self::empty();
        for line in DEFAULTS {
            // Each line is a command list of one `bind-key`, so `\;` has
            // already become `;` by the time bind-key reads its arguments.
            for argv in cmdline::parse(line).expect("default binding parses") {
                t.apply(&argv).expect("default binding is valid");
            }
        }
        t
    }

    pub fn lookup(&self, table: &str, key: u64) -> Option<&Binding> {
        self.tables.get(table)?.get(&key)
    }

    /// Applies a `bind-key` or `unbind-key` argv (canonical or alias
    /// name first). Errors carry tmux's wording.
    pub fn apply(&mut self, argv: &[String]) -> Result<(), String> {
        let Some((name, rest)) = argv.split_first() else {
            return Err("no command".into());
        };
        match name.as_str() {
            "bind-key" | "bind" => self.bind(rest),
            "unbind-key" | "unbind" => self.unbind(rest),
            other => Err(format!("not a key binding command: {other}")),
        }
    }

    fn bind(&mut self, argv: &[String]) -> Result<(), String> {
        let args = Args::parse("cnrt:T:", argv).ok_or(
            "usage: bind-key [-cnr] [-t mode-table] [-T key-table] key command [arguments]",
        )?;
        if args.positional.len() < 2 {
            return Err("not enough arguments".into());
        }
        let key = parse_key(&args.positional[0])
            .ok_or_else(|| format!("unknown key: {}", args.positional[0]))?;
        if args.has('t') {
            // Mode key tables (vi/emacs copy mode) live on the host.
            return Ok(());
        }
        let table = args.get('T').map(str::to_string).unwrap_or_else(|| {
            if args.has('n') {
                "root".into()
            } else {
                "prefix".into()
            }
        });
        let cmds = cmdline::parse_list(&args.positional[1..])?;
        self.tables.entry(table).or_default().insert(
            key,
            Binding {
                repeat: args.has('r'),
                cmds,
            },
        );
        Ok(())
    }

    fn unbind(&mut self, argv: &[String]) -> Result<(), String> {
        let args = Args::parse("acnt:T:", argv)
            .ok_or("usage: unbind-key [-acn] [-t mode-table] [-T key-table] key")?;
        if args.has('t') {
            return Ok(());
        }
        if args.has('a') {
            if !args.positional.is_empty() {
                return Err("key given with -a".into());
            }
            match args.get('T') {
                None => {
                    self.tables.insert("root".into(), BTreeMap::new());
                    self.tables.insert("prefix".into(), BTreeMap::new());
                }
                Some(t) => {
                    if !self.tables.contains_key(t) {
                        return Err(format!("table {t} doesn't exist"));
                    }
                    self.tables.insert(t.to_string(), BTreeMap::new());
                }
            }
            return Ok(());
        }
        let Some(name) = args.positional.first() else {
            return Err("missing key".into());
        };
        let key = parse_key(name).ok_or_else(|| format!("unknown key: {name}"))?;
        let table = match args.get('T') {
            Some(t) => {
                if !self.tables.contains_key(t) {
                    return Err(format!("table {t} doesn't exist"));
                }
                t.to_string()
            }
            None if args.has('n') => "root".into(),
            None => "prefix".into(),
        };
        if let Some(t) = self.tables.get_mut(&table) {
            t.remove(&key);
        }
        Ok(())
    }
}

/// Session options that shape key handling, with tmux 2.2 defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub prefix: Option<u64>,
    pub prefix2: Option<u64>,
    pub repeat_time: Duration,
    pub assume_paste_time: Duration,
    pub display_time: Duration,
    pub display_panes_time: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            prefix: Some(2),
            prefix2: None,
            repeat_time: Duration::from_millis(500),
            assume_paste_time: Duration::from_millis(1),
            display_time: Duration::from_millis(750),
            display_panes_time: Duration::from_millis(1000),
        }
    }
}

impl Options {
    /// Applies a `set-option`/`set-window-option` `(name, value)`; other
    /// options are ignored. Returns whether the name was recognised.
    pub fn set(&mut self, name: &str, value: &str) -> bool {
        let millis = |v: &str| v.parse::<u64>().ok().map(Duration::from_millis);
        match name {
            "prefix" => self.prefix = parse_key(value),
            "prefix2" => self.prefix2 = parse_key(value),
            "repeat-time" => {
                if let Some(d) = millis(value) {
                    self.repeat_time = d;
                }
            }
            "assume-paste-time" => {
                if let Some(d) = millis(value) {
                    self.assume_paste_time = d;
                }
            }
            "display-time" => {
                if let Some(d) = millis(value) {
                    self.display_time = d;
                }
            }
            "display-panes-time" => {
                if let Some(d) = millis(value) {
                    self.display_panes_time = d;
                }
            }
            _ => return false,
        }
        true
    }
}

/// What a key turned into after the tables were consulted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send the key to the host's active pane.
    Forward(u64),
    /// Run the bound command list.
    Run(Vec<Vec<String>>),
    /// Swallowed: the prefix itself, or an unbound key after it.
    Ignore,
}

/// `server_client_handle_key` state for one viewer.
#[derive(Debug, Clone)]
pub struct KeyState {
    table: String,
    /// Set after a `-r` binding; the table stays until `repeat_until`.
    repeat_until: Option<Instant>,
    last_key: Option<Instant>,
    pasting: bool,
}

impl Default for KeyState {
    fn default() -> Self {
        KeyState {
            table: "root".into(),
            repeat_until: None,
            last_key: None,
            pasting: false,
        }
    }
}

impl KeyState {
    #[cfg(test)]
    pub fn table(&self) -> &str {
        &self.table
    }

    fn reset(&mut self) {
        self.table = "root".into();
        self.repeat_until = None;
    }

    /// Marks the start of a fresh input packet (one SSH read). A genuine
    /// paste arrives inside a single packet, so paste mode is never carried
    /// across packets: this keeps a prefix key that begins a new packet
    /// from being mistaken for pasted text when two packets happen to
    /// arrive within `assume-paste-time` of each other (as they can over a
    /// local connection), which would otherwise drop the binding.
    pub fn begin_packet(&mut self) {
        self.pasting = false;
    }

    /// `server_client_assume_paste`: keys arriving faster than
    /// `assume-paste-time` apart are pasted text, not commands. The
    /// activity timer and the `pasting` flag are updated on every key so
    /// the timing stays accurate, but the caller only acts on the result
    /// while in the root table (see `handle`).
    fn assume_paste(&mut self, options: &Options, now: Instant) -> bool {
        let last = self.last_key.replace(now);
        if options.assume_paste_time.is_zero() {
            self.pasting = false;
            return false;
        }
        let quick =
            last.is_some_and(|l| now.saturating_duration_since(l) < options.assume_paste_time);
        if quick {
            if self.pasting {
                return true;
            }
            self.pasting = true;
            return false;
        }
        self.pasting = false;
        false
    }

    pub fn handle(
        &mut self,
        key: u64,
        tables: &KeyTables,
        options: &Options,
        now: Instant,
    ) -> Action {
        // Paste detection governs only the root table. A key that follows
        // a real (non-pasted) prefix is a command, so it must reach the
        // key-table lookup below: were it force-forwarded as "paste", the
        // binding would be silently dropped. During an actual paste the
        // prefix key is itself forwarded in the root table, so we never
        // reach a non-root table with pasting set.
        let pasting = self.assume_paste(options, now);
        if pasting && self.table == "root" {
            return Action::Forward(key);
        }
        // The repeat timer fired while nobody was typing.
        if self.repeat_until.is_some_and(|until| now >= until) {
            self.reset();
        }
        loop {
            if let Some(binding) = tables.lookup(&self.table, key) {
                if self.repeat_until.is_some() && !binding.repeat {
                    self.reset();
                    continue;
                }
                let cmds = binding.cmds.clone();
                if !options.repeat_time.is_zero() && binding.repeat {
                    self.repeat_until = Some(now + options.repeat_time);
                } else {
                    self.reset();
                }
                return Action::Run(cmds);
            }
            if self.repeat_until.is_some() {
                self.reset();
                continue;
            }
            break;
        }
        if self.table != "root" {
            self.reset();
            return Action::Ignore;
        }
        if Some(key) == options.prefix || Some(key) == options.prefix2 {
            self.table = "prefix".into();
            return Action::Ignore;
        }
        Action::Forward(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn key_names() {
        assert_eq!(parse_key("C-a"), Some(1));
        assert_eq!(parse_key("c-A"), Some(1));
        assert_eq!(parse_key("C-b"), Some(2));
        assert_eq!(parse_key("^?"), Some(Special::BSpace.code()));
        assert_eq!(parse_key("C-?"), Some(Special::BSpace.code()));
        assert_eq!(parse_key("C-Space"), Some(0));
        assert_eq!(parse_key("C-@"), Some(0));
        assert_eq!(parse_key("M-x"), Some(b'x' as u64 | KEYC_ESCAPE));
        assert_eq!(parse_key("M-Up"), Some(Special::Up.code() | KEYC_ESCAPE));
        assert_eq!(parse_key("C-M-a"), Some(1 | KEYC_ESCAPE));
        assert_eq!(parse_key("PPage"), Some(Special::PPage.code()));
        assert_eq!(parse_key("pageup"), Some(Special::PPage.code()));
        assert_eq!(parse_key("0x41"), Some(b'A' as u64));
        assert_eq!(parse_key("0x1"), Some(1));
        assert_eq!(parse_key("0x12345"), None);
        assert_eq!(parse_key("S-F1"), Some(Special::F1.code() | KEYC_SHIFT));
        assert_eq!(parse_key("C-Up"), Some(Special::Up.code() | KEYC_CTRL));
        assert_eq!(parse_key("Space"), Some(32));
        assert_eq!(parse_key("Enter"), Some(13));
        assert_eq!(parse_key("Tab"), Some(9));
        assert_eq!(parse_key("Escape"), Some(27));
        assert_eq!(parse_key("BSpace"), Some(Special::BSpace.code()));
        assert_eq!(parse_key("\\;"), None, "two-character junk is unknown");
        assert_eq!(parse_key(";"), Some(b';' as u64));
        assert_eq!(
            parse_key("C-;"),
            Some(b';' as u64 | KEYC_CTRL),
            "punctuation keeps the modifier bit"
        );
        assert_eq!(parse_key("C-1"), Some(b'1' as u64 | KEYC_CTRL));
        assert_eq!(parse_key("é"), Some(0xe9));
        assert_eq!(parse_key("M-é"), Some(0xe9 | KEYC_ESCAPE));
        assert_eq!(parse_key("None"), None);
        assert_eq!(parse_key(""), None);
        assert_eq!(parse_key("Bogus"), None);
        assert_eq!(parse_key("MouseDown1Pane"), Some(KEYC_BASE + 3));
        assert_eq!(parse_key("WheelDownBorder"), Some(KEYC_BASE + 44));
        assert_eq!(
            parse_key("C-"),
            None,
            "the dash is consumed with the modifier"
        );
        assert_eq!(parse_key("C--"), Some(b'-' as u64 | KEYC_CTRL));
        assert_eq!(parse_key("éé"), None);
    }

    #[test]
    fn defaults_load() {
        let t = KeyTables::tmux_defaults();
        let b = t.lookup("prefix", b'c' as u64).unwrap();
        assert_eq!(b.cmds, vec![vec!["new-window"]]);
        assert!(!b.repeat);
        assert!(t.lookup("prefix", Special::Up.code()).unwrap().repeat);
        assert_eq!(
            t.lookup("prefix", b';' as u64).unwrap().cmds,
            vec![vec!["last-pane"]]
        );
        assert_eq!(
            t.lookup("prefix", b'$' as u64).unwrap().cmds,
            vec![vec!["command-prompt", "-I#S", "rename-session '%%'"]]
        );
        assert_eq!(
            t.lookup("root", KEYC_BASE + 3).unwrap().cmds,
            vec![vec!["select-pane", "-t="], vec!["send-keys", "-M"]],
            "the escaped semicolon splits once bind-key parses its own arguments"
        );
        assert_eq!(
            t.lookup("prefix", 2).unwrap().cmds,
            vec![vec!["send-prefix"]]
        );
        assert!(t.lookup("root", b'c' as u64).is_none());
    }

    #[test]
    fn bind_and_unbind() {
        let mut t = KeyTables::tmux_defaults();
        t.apply(&argv(&["bind-key", "-n", "C-t", "new-window"]))
            .unwrap();
        assert_eq!(t.lookup("root", 20).unwrap().cmds, vec![vec!["new-window"]]);
        t.apply(&argv(&[
            "bind",
            "-r",
            "-T",
            "mine",
            "h",
            "select-pane",
            "-L",
        ]))
        .unwrap();
        assert!(t.lookup("mine", b'h' as u64).unwrap().repeat);
        t.apply(&argv(&[
            "bind-key",
            "x",
            "kill-pane",
            ";",
            "display",
            "gone",
        ]))
        .unwrap();
        assert_eq!(
            t.lookup("prefix", b'x' as u64).unwrap().cmds,
            vec![vec!["kill-pane"], vec!["display-message", "gone"]]
        );
        assert_eq!(
            t.apply(&argv(&["bind-key", "Bogus", "x"])),
            Err("unknown key: Bogus".into())
        );
        assert_eq!(
            t.apply(&argv(&["bind-key", "y"])),
            Err("not enough arguments".into())
        );
        assert_eq!(
            t.apply(&argv(&["bind-key", "y", "nonsense-cmd"])),
            Err("unknown command: nonsense-cmd".into())
        );
        t.apply(&argv(&[
            "bind-key",
            "-t",
            "vi-copy",
            "v",
            "begin-selection",
        ]))
        .unwrap();

        t.apply(&argv(&["unbind-key", "c"])).unwrap();
        assert!(t.lookup("prefix", b'c' as u64).is_none());
        t.apply(&argv(&["unbind", "-n", "C-t"])).unwrap();
        assert!(t.lookup("root", 20).is_none());
        assert_eq!(
            t.apply(&argv(&["unbind", "-T", "nope", "x"])),
            Err("table nope doesn't exist".into())
        );
        t.apply(&argv(&["unbind", "-a"])).unwrap();
        assert!(t.lookup("prefix", b'n' as u64).is_none());
        assert!(
            t.lookup("mine", b'h' as u64).is_some(),
            "-a without -T clears root and prefix only"
        );
    }

    #[test]
    fn options_parse() {
        let mut o = Options::default();
        assert_eq!(o.prefix, Some(2));
        assert!(o.set("prefix", "C-a"));
        assert_eq!(o.prefix, Some(1));
        assert!(o.set("prefix2", "None"));
        assert_eq!(o.prefix2, None);
        assert!(o.set("repeat-time", "0"));
        assert!(o.repeat_time.is_zero());
        assert!(!o.set("status-left", "x"));
    }

    #[test]
    fn prefix_then_key_runs_binding() {
        let t = KeyTables::tmux_defaults();
        let o = Options::default();
        let mut s = KeyState::default();
        let mut now = Instant::now();
        let mut step = |s: &mut KeyState, key: u64| {
            now += Duration::from_millis(100);
            s.handle(key, &t, &o, now)
        };
        assert_eq!(step(&mut s, b'a' as u64), Action::Forward(b'a' as u64));
        assert_eq!(step(&mut s, 2), Action::Ignore);
        assert_eq!(s.table(), "prefix");
        assert_eq!(
            step(&mut s, b'c' as u64),
            Action::Run(vec![vec!["new-window".into()]])
        );
        assert_eq!(s.table(), "root");
        // Unbound key after the prefix is swallowed.
        assert_eq!(step(&mut s, 2), Action::Ignore);
        assert_eq!(step(&mut s, b'Z' as u64 | KEYC_ESCAPE), Action::Ignore);
        assert_eq!(s.table(), "root");
        assert_eq!(step(&mut s, b'Z' as u64), Action::Forward(b'Z' as u64));
        // send-prefix is an ordinary binding.
        assert_eq!(step(&mut s, 2), Action::Ignore);
        assert_eq!(
            step(&mut s, 2),
            Action::Run(vec![vec!["send-prefix".into()]])
        );
        // detach-client is a binding like any other at this level.
        assert_eq!(step(&mut s, 2), Action::Ignore);
        assert_eq!(
            step(&mut s, b'd' as u64),
            Action::Run(vec![vec!["detach-client".into()]])
        );
    }

    #[test]
    fn repeat_keeps_the_prefix_table_for_repeat_time() {
        let t = KeyTables::tmux_defaults();
        let o = Options::default();
        let mut s = KeyState::default();
        let t0 = Instant::now();
        let up = Special::Up.code();
        assert_eq!(s.handle(2, &t, &o, t0), Action::Ignore);
        assert_eq!(
            s.handle(up, &t, &o, t0 + Duration::from_millis(10)),
            Action::Run(vec![vec!["select-pane".into(), "-U".into()]])
        );
        assert_eq!(
            s.table(),
            "prefix",
            "stays in the prefix table while repeating"
        );
        assert_eq!(
            s.handle(up, &t, &o, t0 + Duration::from_millis(300)),
            Action::Run(vec![vec!["select-pane".into(), "-U".into()]])
        );
        // A non-repeating binding while repeating is looked up in root: not bound, so forwarded.
        assert_eq!(
            s.handle(b'c' as u64, &t, &o, t0 + Duration::from_millis(400)),
            Action::Forward(b'c' as u64)
        );
        assert_eq!(s.table(), "root");
        // After repeat-time the table is back to root.
        assert_eq!(
            s.handle(2, &t, &o, t0 + Duration::from_secs(2)),
            Action::Ignore
        );
        assert_eq!(
            s.handle(up, &t, &o, t0 + Duration::from_millis(2010)),
            Action::Run(vec![vec!["select-pane".into(), "-U".into()]])
        );
        assert_eq!(
            s.handle(up, &t, &o, t0 + Duration::from_secs(3)),
            Action::Forward(up)
        );
    }

    #[test]
    fn root_bindings_and_custom_prefix() {
        let mut t = KeyTables::tmux_defaults();
        t.apply(&argv(&["bind", "-n", "F5", "next-window"]))
            .unwrap();
        let mut o = Options::default();
        o.set("prefix", "C-a");
        let mut s = KeyState::default();
        let mut now = Instant::now();
        let mut step = |s: &mut KeyState, key: u64| {
            now += Duration::from_millis(100);
            s.handle(key, &t, &o, now)
        };
        assert_eq!(
            step(&mut s, Special::F5.code()),
            Action::Run(vec![vec!["next-window".into()]])
        );
        assert_eq!(
            step(&mut s, 2),
            Action::Forward(2),
            "C-b is a plain key with another prefix"
        );
        assert_eq!(step(&mut s, 1), Action::Ignore);
        assert_eq!(
            step(&mut s, b'n' as u64),
            Action::Run(vec![vec!["next-window".into()]])
        );
    }

    #[test]
    fn pasted_text_bypasses_bindings() {
        let t = KeyTables::tmux_defaults();
        let o = Options::default();
        let mut s = KeyState::default();
        let t0 = Instant::now();
        let us = Duration::from_micros;
        // First quick key sets the pasting flag, second is treated as pasted.
        assert_eq!(
            s.handle(b'x' as u64, &t, &o, t0),
            Action::Forward(b'x' as u64)
        );
        assert_eq!(
            s.handle(b'y' as u64, &t, &o, t0 + us(100)),
            Action::Forward(b'y' as u64)
        );
        assert_eq!(
            s.handle(2, &t, &o, t0 + us(200)),
            Action::Forward(2),
            "pasted prefix is forwarded"
        );
        assert_eq!(
            s.handle(b'c' as u64, &t, &o, t0 + us(300)),
            Action::Forward(b'c' as u64)
        );
        // Typing speed again: bindings apply.
        assert_eq!(
            s.handle(2, &t, &o, t0 + Duration::from_millis(50)),
            Action::Ignore
        );
        assert_eq!(
            s.handle(b'c' as u64, &t, &o, t0 + Duration::from_millis(100)),
            Action::Run(vec![vec!["new-window".into()]])
        );
    }
}
