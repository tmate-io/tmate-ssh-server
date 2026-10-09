//! Viewer keyboard input -> tmux 2.x key codes.
//!
//! The host runs tmux 2.x (tmate 2.4.0) and expects the `key_code` values
//! from its `tmux.h`: plain keys are the Unicode code point, special keys
//! are `KEYC_BASE + n` in enum order, and modifiers are high bits. The
//! sequences recognised here are tmux's built-in raw table plus the xterm
//! terminfo keys, which covers the terminals viewers actually use.

pub const KEYC_BASE: u64 = 0x1000_0000_0000;
pub const KEYC_ESCAPE: u64 = 0x2000_0000_0000;
pub const KEYC_CTRL: u64 = 0x4000_0000_0000;
pub const KEYC_SHIFT: u64 = 0x8000_0000_0000;

/// Offsets into tmux 2.x's special-key enum. Mouse keys occupy 3..=44 and
/// are never sent (the old server dropped them too).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum Special {
    BSpace = 45,
    F1 = 46,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
    IC,
    DC,
    Home,
    End,
    NPage,
    PPage,
    BTab,
    Up,
    Down,
    Left,
    Right,
    KpSlash,
    KpStar,
    KpMinus,
    KpSeven,
    KpEight,
    KpNine,
    KpPlus,
    KpFour,
    KpFive,
    KpSix,
    KpOne,
    KpTwo,
    KpThree,
    KpEnter,
    KpZero,
    KpPeriod,
}

impl Special {
    pub const fn code(self) -> u64 {
        KEYC_BASE + self as u64
    }
}

use Special::*;

/// Escape sequences after the leading ESC, longest match first.
const SEQUENCES: &[(&[u8], u64)] = &[
    // xterm F1-F4 and application-mode cursor keys.
    (b"OP", F1.code()),
    (b"OQ", F2.code()),
    (b"OR", F3.code()),
    (b"OS", F4.code()),
    (b"OA", Up.code()),
    (b"OB", Down.code()),
    (b"OC", Right.code()),
    (b"OD", Left.code()),
    (b"OH", Home.code()),
    (b"OF", End.code()),
    (b"[A", Up.code()),
    (b"[B", Down.code()),
    (b"[C", Right.code()),
    (b"[D", Left.code()),
    (b"[H", Home.code()),
    (b"[F", End.code()),
    (b"[Z", BTab.code()),
    // vt220-style editing keys.
    (b"[1~", Home.code()),
    (b"[2~", IC.code()),
    (b"[3~", DC.code()),
    (b"[4~", End.code()),
    (b"[5~", PPage.code()),
    (b"[6~", NPage.code()),
    (b"[7~", Home.code()),
    (b"[8~", End.code()),
    (b"[11~", F1.code()),
    (b"[12~", F2.code()),
    (b"[13~", F3.code()),
    (b"[14~", F4.code()),
    (b"[15~", F5.code()),
    (b"[17~", F6.code()),
    (b"[18~", F7.code()),
    (b"[19~", F8.code()),
    (b"[20~", F9.code()),
    (b"[21~", F10.code()),
    (b"[23~", F11.code()),
    (b"[24~", F12.code()),
    // rxvt-style modified arrows.
    (b"Oa", Up.code() | KEYC_CTRL),
    (b"Ob", Down.code() | KEYC_CTRL),
    (b"Oc", Right.code() | KEYC_CTRL),
    (b"Od", Left.code() | KEYC_CTRL),
    (b"[a", Up.code() | KEYC_SHIFT),
    (b"[b", Down.code() | KEYC_SHIFT),
    (b"[c", Right.code() | KEYC_SHIFT),
    (b"[d", Left.code() | KEYC_SHIFT),
    // Numeric keypad in application mode.
    (b"Oo", KpSlash.code()),
    (b"Oj", KpStar.code()),
    (b"Om", KpMinus.code()),
    (b"Ow", KpSeven.code()),
    (b"Ox", KpEight.code()),
    (b"Oy", KpNine.code()),
    (b"Ok", KpPlus.code()),
    (b"Ot", KpFour.code()),
    (b"Ou", KpFive.code()),
    (b"Ov", KpSix.code()),
    (b"Oq", KpOne.code()),
    (b"Or", KpTwo.code()),
    (b"Os", KpThree.code()),
    (b"OM", KpEnter.code()),
    (b"Op", KpZero.code()),
    (b"On", KpPeriod.code()),
];

/// xterm modifier parameter (the `;5` in `ESC [ 1 ; 5 A`) to tmux bits.
fn xterm_modifiers(param: u8) -> Option<u64> {
    let bits = param.checked_sub(1)?;
    let mut m = 0;
    if bits & 1 != 0 {
        m |= KEYC_SHIFT;
    }
    if bits & 2 != 0 {
        m |= KEYC_ESCAPE;
    }
    if bits & 4 != 0 {
        m |= KEYC_CTRL;
    }
    Some(m)
}

/// Result of looking at the bytes after an ESC.
enum Match {
    Key(u64, usize),
    /// Could be a prefix of a longer sequence; wait for more bytes.
    Partial,
    None,
}

fn match_sequence(rest: &[u8]) -> Match {
    let mut partial = false;
    for (seq, key) in SEQUENCES {
        if rest.starts_with(seq) {
            return Match::Key(*key, seq.len());
        }
        if seq.starts_with(rest) {
            partial = true;
        }
    }
    if let Some(m) = match_xterm_modified(rest) {
        return m;
    }
    if partial { Match::Partial } else { Match::None }
}

/// `ESC [ 1 ; m X` (cursor/F1-F4 style) and `ESC [ n ; m ~` (vt220 style).
fn match_xterm_modified(rest: &[u8]) -> Option<Match> {
    if rest.first() != Some(&b'[') {
        return None;
    }
    // Collect "digits ; digits" then a final byte.
    let mut i = 1;
    let num = |i: &mut usize| -> Option<u8> {
        let start = *i;
        while *i < rest.len() && rest[*i].is_ascii_digit() && *i - start < 3 {
            *i += 1;
        }
        if *i == start {
            return None;
        }
        std::str::from_utf8(&rest[start..*i]).ok()?.parse().ok()
    };
    let Some(n) = num(&mut i) else {
        return (rest.len() <= 1).then_some(Match::Partial);
    };
    if i >= rest.len() {
        return Some(Match::Partial);
    }
    if rest[i] != b';' {
        return None;
    }
    i += 1;
    let Some(m) = num(&mut i) else {
        return (i >= rest.len()).then_some(Match::Partial);
    };
    if i >= rest.len() {
        return Some(Match::Partial);
    }
    let modifiers = xterm_modifiers(m)?;
    let key = match (n, rest[i]) {
        (1, b'A') => Up.code(),
        (1, b'B') => Down.code(),
        (1, b'C') => Right.code(),
        (1, b'D') => Left.code(),
        (1, b'H') | (7, b'~') | (1, b'~') => Home.code(),
        (1, b'F') | (8, b'~') | (4, b'~') => End.code(),
        (1, b'P') | (11, b'~') => F1.code(),
        (1, b'Q') | (12, b'~') => F2.code(),
        (1, b'R') | (13, b'~') => F3.code(),
        (1, b'S') | (14, b'~') => F4.code(),
        (15, b'~') => F5.code(),
        (17, b'~') => F6.code(),
        (18, b'~') => F7.code(),
        (19, b'~') => F8.code(),
        (20, b'~') => F9.code(),
        (21, b'~') => F10.code(),
        (23, b'~') => F11.code(),
        (24, b'~') => F12.code(),
        (2, b'~') => IC.code(),
        (3, b'~') => DC.code(),
        (5, b'~') => PPage.code(),
        (6, b'~') => NPage.code(),
        _ => return None,
    };
    Some(Match::Key(key | modifiers, i + 1))
}

/// Mouse reports (`ESC [ M ...` and `ESC [ < ... M/m`) are swallowed.
fn skip_mouse(rest: &[u8]) -> Option<usize> {
    if rest.starts_with(b"[M") {
        return (rest.len() >= 5).then_some(5);
    }
    if rest.starts_with(b"[<") {
        let end = rest.iter().position(|b| *b == b'M' || *b == b'm')?;
        return Some(end + 1);
    }
    None
}

/// Incremental key decoder for one viewer.
#[derive(Default)]
pub struct KeyParser {
    pending: Vec<u8>,
}

impl KeyParser {
    /// Feeds raw terminal input and returns the decoded keys. A trailing
    /// ESC that might start a sequence is held until the next call; call
    /// `flush` after an idle period to release it as a plain Escape.
    pub fn feed(&mut self, data: &[u8]) -> Vec<u64> {
        self.pending.extend_from_slice(data);
        let mut keys = Vec::new();
        let mut pos = 0;
        while pos < self.pending.len() {
            let buf = &self.pending[pos..];
            match decode_one(buf) {
                Step::Key(k, n) => {
                    keys.push(k);
                    pos += n;
                }
                Step::Skip(n) => pos += n,
                Step::NeedMore => break,
            }
        }
        self.pending.drain(..pos);
        keys
    }

    /// True while bytes are being held for a possible longer sequence; the
    /// caller decides when waiting has gone on long enough to `flush`.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Releases a held ESC (or any undecodable tail) as plain keys.
    pub fn flush(&mut self) -> Vec<u64> {
        let tail = std::mem::take(&mut self.pending);
        let mut keys = Vec::new();
        for b in tail {
            keys.push(u64::from(b));
        }
        keys
    }
}

enum Step {
    Key(u64, usize),
    Skip(usize),
    NeedMore,
}

fn decode_one(buf: &[u8]) -> Step {
    let b = buf[0];
    if b == 0x1b {
        let rest = &buf[1..];
        if rest.is_empty() {
            return Step::NeedMore;
        }
        if let Some(n) = skip_mouse(rest) {
            return Step::Skip(n + 1);
        }
        match match_sequence(rest) {
            Match::Key(k, n) => return Step::Key(k, n + 1),
            Match::Partial => return Step::NeedMore,
            Match::None => {}
        }
        // ESC followed by a key: Meta-key. ESC ESC is a plain Escape.
        if rest[0] == 0x1b {
            return Step::Key(0x1b, 1);
        }
        return match decode_one(rest) {
            Step::Key(k, n) => Step::Key(k | KEYC_ESCAPE, n + 1),
            Step::Skip(n) => Step::Skip(n + 1),
            Step::NeedMore => Step::NeedMore,
        };
    }
    if b == 0x7f {
        return Step::Key(BSpace.code(), 1);
    }
    if b < 0x80 {
        return Step::Key(u64::from(b), 1);
    }
    // UTF-8: the key is the code point.
    let len = match b {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return Step::Skip(1),
    };
    if buf.len() < len {
        return Step::NeedMore;
    }
    match std::str::from_utf8(&buf[..len]) {
        Ok(s) => Step::Key(u64::from(s.chars().next().unwrap()), len),
        Err(_) => Step::Skip(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(data: &[u8]) -> Vec<u64> {
        KeyParser::default().feed(data)
    }

    #[test]
    fn enum_offsets_match_tmux_h() {
        // From tmux.h: FOCUS_IN, FOCUS_OUT, MOUSE, 14 mouse keys x 3, then BSPACE.
        assert_eq!(BSpace as u64, 3 + 14 * 3);
        assert_eq!(F12 as u64, F1 as u64 + 11);
        assert_eq!(Up as u64, BTab as u64 + 1);
        assert_eq!(KpPeriod as u64, 84);
    }

    #[test]
    fn plain_and_control() {
        assert_eq!(keys(b"a\x01\r"), vec![b'a' as u64, 1, b'\r' as u64]);
        assert_eq!(keys(b"\x7f"), vec![BSpace.code()]);
        assert_eq!(keys("é".as_bytes()), vec![0xe9]);
    }

    #[test]
    fn sequences() {
        assert_eq!(keys(b"\x1b[A"), vec![Up.code()]);
        assert_eq!(keys(b"\x1bOP\x1b[24~"), vec![F1.code(), F12.code()]);
        assert_eq!(keys(b"\x1b[1;5C"), vec![Right.code() | KEYC_CTRL]);
        assert_eq!(keys(b"\x1b[3;2~"), vec![DC.code() | KEYC_SHIFT]);
        assert_eq!(keys(b"\x1bx"), vec![b'x' as u64 | KEYC_ESCAPE]);
        assert_eq!(keys(b"\x1b\x1b"), vec![0x1b]);
    }

    #[test]
    fn split_sequences_and_flush() {
        let mut p = KeyParser::default();
        assert_eq!(p.feed(b"\x1b["), vec![]);
        assert_eq!(p.feed(b"B"), vec![Down.code()]);
        assert_eq!(p.feed(b"\x1b"), vec![]);
        assert_eq!(p.flush(), vec![0x1b]);
    }

    #[test]
    fn mouse_is_dropped() {
        assert_eq!(keys(b"\x1b[<0;10;5Mz"), vec![b'z' as u64]);
        assert_eq!(keys(b"\x1b[M !!q"), vec![b'q' as u64]);
    }
}
