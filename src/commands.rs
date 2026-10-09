//! The tmux 2.2 command table (`cmd.c`), used to resolve the names and
//! aliases viewers type the way `cmd_parse` does, so that the messages for
//! unknown or ambiguous commands match the old server's.

/// `(name, alias)` in `cmd_table` order; the order matters for prefix
/// matching.
pub const COMMANDS: &[(&str, Option<&str>)] = &[
    ("attach-session", Some("attach")),
    ("bind-key", Some("bind")),
    ("break-pane", Some("breakp")),
    ("capture-pane", Some("capturep")),
    ("choose-buffer", None),
    ("choose-client", None),
    ("choose-session", None),
    ("choose-tree", None),
    ("choose-window", None),
    ("clear-history", Some("clearhist")),
    ("clock-mode", None),
    ("command-prompt", None),
    ("confirm-before", Some("confirm")),
    ("copy-mode", None),
    ("delete-buffer", Some("deleteb")),
    ("detach-client", Some("detach")),
    ("display-message", Some("display")),
    ("display-panes", Some("displayp")),
    ("find-window", Some("findw")),
    ("has-session", Some("has")),
    ("if-shell", Some("if")),
    ("join-pane", Some("joinp")),
    ("kill-pane", Some("killp")),
    ("kill-server", None),
    ("kill-session", None),
    ("kill-window", Some("killw")),
    ("last-pane", Some("lastp")),
    ("last-window", Some("last")),
    ("link-window", Some("linkw")),
    ("list-buffers", Some("lsb")),
    ("list-clients", Some("lsc")),
    ("list-commands", Some("lscm")),
    ("list-keys", Some("lsk")),
    ("list-panes", Some("lsp")),
    ("list-sessions", Some("ls")),
    ("list-windows", Some("lsw")),
    ("load-buffer", Some("loadb")),
    ("lock-client", Some("lockc")),
    ("lock-server", Some("lock")),
    ("lock-session", Some("locks")),
    ("move-pane", Some("movep")),
    ("move-window", Some("movew")),
    ("new-session", Some("new")),
    ("new-window", Some("neww")),
    ("next-layout", Some("nextl")),
    ("next-window", Some("next")),
    ("paste-buffer", Some("pasteb")),
    ("pipe-pane", Some("pipep")),
    ("previous-layout", Some("prevl")),
    ("previous-window", Some("prev")),
    ("refresh-client", Some("refresh")),
    ("rename-session", Some("rename")),
    ("rename-window", Some("renamew")),
    ("resize-pane", Some("resizep")),
    ("respawn-pane", Some("respawnp")),
    ("respawn-window", Some("respawnw")),
    ("rotate-window", Some("rotatew")),
    ("run-shell", Some("run")),
    ("save-buffer", Some("saveb")),
    ("select-layout", Some("selectl")),
    ("select-pane", Some("selectp")),
    ("select-window", Some("selectw")),
    ("send-keys", Some("send")),
    ("send-prefix", None),
    ("server-info", Some("info")),
    ("set-buffer", Some("setb")),
    ("set-environment", Some("setenv")),
    ("set-hook", None),
    ("set-option", Some("set")),
    ("set-window-option", Some("setw")),
    ("show-buffer", Some("showb")),
    ("show-environment", Some("showenv")),
    ("show-hooks", None),
    ("show-messages", Some("showmsgs")),
    ("show-options", Some("show")),
    ("show-window-options", Some("showw")),
    ("source-file", Some("source")),
    ("split-window", Some("splitw")),
    ("start-server", Some("start")),
    ("suspend-client", Some("suspendc")),
    ("swap-pane", Some("swapp")),
    ("swap-window", Some("swapw")),
    ("switch-client", Some("switchc")),
    ("unbind-key", Some("unbind")),
    ("unlink-window", Some("unlinkw")),
    ("wait-for", Some("wait")),
];

/// Resolves a typed command name to its canonical name with `cmd_parse`'s
/// rules: an alias wins outright, otherwise a unique prefix of a name.
pub fn resolve(typed: &str) -> Result<&'static str, String> {
    let mut found: Option<&'static str> = None;
    let mut ambiguous = false;
    for (name, alias) in COMMANDS {
        if *alias == Some(typed) {
            return Ok(name);
        }
        if !name.starts_with(typed) {
            continue;
        }
        if found.is_some() {
            ambiguous = true;
        }
        found = Some(name);
        if *name == typed {
            ambiguous = false;
            break;
        }
    }
    if ambiguous {
        let names: Vec<&str> = COMMANDS
            .iter()
            .map(|(n, _)| *n)
            .filter(|n| n.starts_with(typed))
            .collect();
        return Err(format!(
            "ambiguous command: {typed}, could be: {}",
            names.join(", ")
        ));
    }
    found.ok_or_else(|| format!("unknown command: {typed}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolution_like_cmd_parse() {
        assert_eq!(
            resolve("set"),
            Ok("set-option"),
            "alias beats earlier prefix matches"
        );
        assert_eq!(resolve("set-option"), Ok("set-option"));
        assert_eq!(resolve("setw"), Ok("set-window-option"));
        assert_eq!(resolve("split"), Ok("split-window"));
        assert_eq!(resolve("ls"), Ok("list-sessions"));
        assert_eq!(resolve("list-k"), Ok("list-keys"));
        assert_eq!(resolve("detach"), Ok("detach-client"));
        assert_eq!(resolve("show").unwrap(), "show-options");
        assert_eq!(
            resolve("li").unwrap_err().split(':').next(),
            Some("ambiguous command")
        );
        assert_eq!(resolve("zzz"), Err("unknown command: zzz".into()));
        assert_eq!(resolve(""), Err("ambiguous command: , could be: attach-session, bind-key, break-pane, capture-pane, choose-buffer, choose-client, choose-session, choose-tree, choose-window, clear-history, clock-mode, command-prompt, confirm-before, copy-mode, delete-buffer, detach-client, display-message, display-panes, find-window, has-session, if-shell, join-pane, kill-pane, kill-server, kill-session, kill-window, last-pane, last-window, link-window, list-buffers, list-clients, list-commands, list-keys, list-panes, list-sessions, list-windows, load-buffer, lock-client, lock-server, lock-session, move-pane, move-window, new-session, new-window, next-layout, next-window, paste-buffer, pipe-pane, previous-layout, previous-window, refresh-client, rename-session, rename-window, resize-pane, respawn-pane, respawn-window, rotate-window, run-shell, save-buffer, select-layout, select-pane, select-window, send-keys, send-prefix, server-info, set-buffer, set-environment, set-hook, set-option, set-window-option, show-buffer, show-environment, show-hooks, show-messages, show-options, show-window-options, source-file, split-window, start-server, suspend-client, swap-pane, swap-window, switch-client, unbind-key, unlink-window, wait-for".into()));
    }
}
