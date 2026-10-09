//! tmux 2.2 command strings: `cmd-string.c` splitting into words and
//! `cmd-list.c` splitting of words into commands at `;`.
//!
//! Only the parts that matter for key bindings and the command prompt are
//! ported: single and double quotes, backslash escapes inside double
//! quotes, `#` comments and `;` / `\;` separators. `$VAR` and `~` expansion
//! read the server's environment in tmux; here they expand to nothing and
//! stay literal respectively, since a viewer must not learn about the
//! server's environment.

use crate::commands;

/// Splits a command line into words as `cmd_string_parse` does.
/// `Err` carries tmux's wording for an unterminated quote.
pub fn split(s: &str) -> Result<Vec<String>, String> {
    let chars: Vec<char> = s.chars().collect();
    let mut argv = Vec::new();
    let mut buf: Option<String> = None;
    let mut i = 0;
    loop {
        let ch = chars.get(i).copied();
        i += 1;
        match ch {
            Some('\'') => {
                let t = quoted(&chars, &mut i, '\'', false).ok_or_else(|| invalid(s))?;
                buf.get_or_insert_with(String::new).push_str(&t);
            }
            Some('"') => {
                let t = quoted(&chars, &mut i, '"', true).ok_or_else(|| invalid(s))?;
                buf.get_or_insert_with(String::new).push_str(&t);
            }
            Some('$') => {
                let t = variable(&chars, &mut i).ok_or_else(|| invalid(s))?;
                buf.get_or_insert_with(String::new).push_str(&t);
            }
            Some('#') | None | Some(' ') | Some('\t') => {
                if let Some(word) = buf.take() {
                    argv.push(word);
                }
                if ch == Some('#') {
                    // Comment: the rest of the line is discarded.
                    return Ok(argv);
                }
                if ch.is_none() {
                    return Ok(argv);
                }
            }
            Some(c) => buf.get_or_insert_with(String::new).push(c),
        }
    }
}

fn invalid(s: &str) -> String {
    format!("invalid or unknown command: {s}")
}

/// `cmd_string_string`: reads up to the closing quote. Backslash escapes
/// and `$` expansion only apply inside double quotes.
fn quoted(chars: &[char], i: &mut usize, end: char, esc: bool) -> Option<String> {
    let mut out = String::new();
    loop {
        let mut ch = *chars.get(*i)?;
        *i += 1;
        if ch == end {
            return Some(out);
        }
        if esc && ch == '\\' {
            ch = *chars.get(*i)?;
            *i += 1;
            ch = match ch {
                'e' => '\x1b',
                'r' => '\r',
                'n' => '\n',
                't' => '\t',
                other => other,
            };
        } else if esc && ch == '$' {
            out.push_str(&variable(chars, i)?);
            continue;
        }
        out.push(ch);
    }
}

/// `cmd_string_variable`: consumes `$NAME` or `${NAME}`. The value is
/// always empty here (see the module note); a `$` not followed by a name
/// character stays literal in tmux, which is reproduced.
fn variable(chars: &[char], i: &mut usize) -> Option<String> {
    let first = |c: char| c == '_' || c.is_ascii_alphabetic();
    let other = |c: char| c == '_' || c.is_ascii_alphanumeric();
    let mut ch = *chars.get(*i)?;
    *i += 1;
    let braced = ch == '{';
    if braced {
        ch = *chars.get(*i)?;
        *i += 1;
        if !first(ch) {
            return None;
        }
    } else if !first(ch) {
        return Some(format!("${ch}"));
    }
    loop {
        match chars.get(*i) {
            Some(&c) if other(c) => *i += 1,
            Some(&c) => {
                if braced {
                    if c != '}' {
                        return None;
                    }
                    *i += 1;
                }
                return Some(String::new());
            }
            None => return if braced { None } else { Some(String::new()) },
        }
    }
}

/// `cmd_list_parse`: splits words into commands at words ending in `;`
/// (a lone `;` is dropped, `\;` is a literal semicolon) and resolves each
/// command name as `cmd_parse` does, returning its canonical name.
pub fn parse_list(argv: &[String]) -> Result<Vec<Vec<String>>, String> {
    let mut words: Vec<String> = argv.to_vec();
    let mut cmds = Vec::new();
    let mut last_split = 0;
    for i in 0..words.len() {
        let Some(stripped) = words[i].strip_suffix(';') else {
            continue;
        };
        if let Some(escaped) = stripped.strip_suffix('\\') {
            words[i] = format!("{escaped};");
            continue;
        }
        words[i] = stripped.to_string();
        let end = if words[i].is_empty() { i } else { i + 1 };
        cmds.push(parse_one(&words[last_split..end])?);
        last_split = i + 1;
    }
    if last_split != words.len() {
        cmds.push(parse_one(&words[last_split..])?);
    }
    Ok(cmds)
}

fn parse_one(argv: &[String]) -> Result<Vec<String>, String> {
    let Some((name, rest)) = argv.split_first() else {
        return Err("no command".into());
    };
    let canonical = commands::resolve(name)?;
    let mut out = Vec::with_capacity(argv.len());
    out.push(canonical.to_string());
    out.extend(rest.iter().cloned());
    Ok(out)
}

/// `split` then `parse_list`: a command string to canonical argv lists.
pub fn parse(s: &str) -> Result<Vec<Vec<String>>, String> {
    let words = split(s)?;
    if words.is_empty() {
        return Ok(Vec::new());
    }
    parse_list(&words)
}

/// `cmd_template_replace`: substitutes `%N` (for the given index) and the
/// first `%%` with `s`.
pub fn template_replace(template: &str, s: &str, idx: u32) -> String {
    if !template.contains('%') {
        return template.to_string();
    }
    let chars: Vec<char> = template.chars().collect();
    let mut out = String::new();
    let mut replaced = false;
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        i += 1;
        if ch == '%' {
            let next = chars.get(i).copied();
            let numbered = next
                .and_then(|c| c.to_digit(10))
                .is_some_and(|d| (1..=9).contains(&d) && d == idx);
            if !numbered {
                if next != Some('%') || replaced {
                    out.push('%');
                    continue;
                }
                replaced = true;
            }
            i += 1;
            out.push_str(s);
            continue;
        }
        out.push(ch);
    }
    out
}

/// Minimal getopt in the style of tmux's `args_parse`: `template` lists
/// flag letters, each followed by `:` when it takes a value. Parsing stops
/// at the first word that is not a flag (BSD getopt), `--` ends flags.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Args {
    pub flags: Vec<(char, Option<String>)>,
    pub positional: Vec<String>,
}

impl Args {
    pub fn parse(template: &str, argv: &[String]) -> Option<Args> {
        let takes_value = |c: char| {
            let t: Vec<char> = template.chars().collect();
            t.iter()
                .position(|&x| x == c)
                .map(|p| t.get(p + 1) == Some(&':'))
        };
        let mut args = Args::default();
        let mut i = 0;
        while i < argv.len() {
            let word = &argv[i];
            i += 1;
            if word == "--" {
                break;
            }
            let Some(body) = word.strip_prefix('-') else {
                i -= 1;
                break;
            };
            if body.is_empty() {
                i -= 1;
                break;
            }
            let letters: Vec<char> = body.chars().collect();
            let mut j = 0;
            while j < letters.len() {
                let c = letters[j];
                j += 1;
                let needs_value = takes_value(c)?;
                if needs_value {
                    let value = if j < letters.len() {
                        letters[j..].iter().collect::<String>()
                    } else {
                        i += 1;
                        argv.get(i - 1)?.clone()
                    };
                    args.flags.push((c, Some(value)));
                    break;
                }
                args.flags.push((c, None));
            }
        }
        args.positional
            .extend(argv[i.min(argv.len())..].iter().cloned());
        Some(args)
    }

    pub fn has(&self, c: char) -> bool {
        self.flags.iter().any(|(f, _)| *f == c)
    }

    pub fn get(&self, c: char) -> Option<&str> {
        self.flags
            .iter()
            .rev()
            .find(|(f, _)| *f == c)
            .and_then(|(_, v)| v.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(s: &str) -> Vec<String> {
        split(s).unwrap()
    }

    #[test]
    fn splitting_follows_cmd_string_rules() {
        assert_eq!(
            words("bind-key C-a send-prefix"),
            ["bind-key", "C-a", "send-prefix"]
        );
        assert_eq!(
            words("  new-window\t-n 'my win'  "),
            ["new-window", "-n", "my win"]
        );
        assert_eq!(
            words(r#"confirm-before -p"kill-window #W? (y/n)" kill-window"#),
            ["confirm-before", "-pkill-window #W? (y/n)", "kill-window"]
        );
        assert_eq!(
            words(r#"bind '"' split-window"#),
            ["bind", "\"", "split-window"]
        );
        assert_eq!(words(r#"bind "'" x"#), ["bind", "'", "x"]);
        assert_eq!(words(r#"a "b\"c\n" d"#), ["a", "b\"c\n", "d"]);
        assert_eq!(words(r"a 'b\n' d"), ["a", "b\\n", "d"]);
        assert_eq!(
            words("rename-window foo # trailing comment"),
            ["rename-window", "foo"]
        );
        assert_eq!(
            words("x $HOME y"),
            ["x", "", "y"],
            "variables expand to nothing"
        );
        assert_eq!(words("x $1"), ["x", "$1"]);
        assert_eq!(words(r"bind \; last-pane"), ["bind", "\\;", "last-pane"]);
        assert!(words("").is_empty());
        assert!(split("echo 'unterminated").is_err());
        assert!(split("echo \"unterminated").is_err());
    }

    #[test]
    fn lists_split_at_semicolons() {
        let list = parse("select-pane -t=\\; send-keys -M").unwrap();
        assert_eq!(list, vec![vec!["select-pane", "-t=;", "send-keys", "-M"]]);
        let list = parse("new-window ; rename-window x; display").unwrap();
        assert_eq!(
            list,
            vec![
                vec!["new-window"],
                vec!["rename-window", "x"],
                vec!["display-message"]
            ]
        );
        assert_eq!(parse("").unwrap(), Vec::<Vec<String>>::new());
        assert_eq!(
            parse("no-such-command").unwrap_err(),
            "unknown command: no-such-command"
        );
        assert_eq!(parse("neww").unwrap(), vec![vec!["new-window"]]);
        assert_eq!(
            parse("sel").unwrap_err(),
            "ambiguous command: sel, could be: select-layout, select-pane, select-window"
        );
    }

    #[test]
    fn templates() {
        assert_eq!(
            template_replace("rename-session '%%'", "x", 1),
            "rename-session 'x'"
        );
        assert_eq!(template_replace("%1 and %2", "a", 1), "a and %2");
        assert_eq!(template_replace("%1 and %2", "b", 2), "%1 and b");
        assert_eq!(template_replace("%% %%", "z", 1), "z %%");
        assert_eq!(template_replace("plain", "z", 1), "plain");
        assert_eq!(template_replace("50%", "z", 1), "50%");
    }

    #[test]
    fn args() {
        let argv = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let a = Args::parse("cnrt:T:", &argv(&["-nr", "-T", "copy", "x", "cmd", "-r"])).unwrap();
        assert!(a.has('n') && a.has('r') && !a.has('c'));
        assert_eq!(a.get('T'), Some("copy"));
        assert_eq!(a.positional, ["x", "cmd", "-r"]);
        let a = Args::parse("I:p:t:", &argv(&["-I#S", "-pindex", "tmpl"])).unwrap();
        assert_eq!(a.get('I'), Some("#S"));
        assert_eq!(a.get('p'), Some("index"));
        assert_eq!(a.positional, ["tmpl"]);
        assert!(
            Args::parse("ab", &argv(&["-z"])).is_none(),
            "unknown flags are errors"
        );
        assert!(
            Args::parse("a:", &argv(&["-a"])).is_none(),
            "missing values are errors"
        );
    }
}
