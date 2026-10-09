# tmate-server-rs

A Rust replacement for `tmate-ssh-server`, wire-compatible with unmodified
tmate 2.4.0 clients (protocol 6). Viewers keep joining with plain `ssh`.

## Status (2026-10-08)

| Milestone | State |
|---|---|
| M0 handshake | **Passed** with Homebrew tmate 2.4.0 and the static Linux 2.4.0 binary (libssh 0.9.0, what action-tmate downloads). `tmate wait tmate-ready` returns; `display -p '#{tmate_ssh}'` gives a link. zlib and the libssh kex negotiate with russh 0.64.1. |
| M1 single-pane viewing | **Done**: live viewers, typing, read-only, size rule, join/leave notices, `-a` keys, session end. 9 live tests, parity with the old server on handshake, viewing and rendering. |
| M2 viewer experience | **Done**: connection parity (PROXY v1, grace period, exec reply, old CLI flags); layout with borders and several panes/windows, tmux 2.2 key tables and prefix bindings, command prompt and confirm-before, status messages, copy mode mirroring, snapshot restore and host reconnect. Parity suite: 8/8 scenarios match the old server screen for screen. |
| M3 sandboxing/ops | Dockerfile (non-root) and Fly template done. Per-session sandbox **done** on Linux: one worker process per session (`src/worker.rs`, `src/sandbox.rs`, `src/wire.rs`, `src/link.rs`), user+mount+pid+net+ipc+uts namespaces, pivot_root into an empty tmpfs, Landlock, no_new_privs, caps dropped, rlimits, seccomp allowlist; gateway keeps SSH and keys. Limits: sessions per IP / total, host byte rate, viewer output queue. `scripts/docker-smoke.sh` checks it in Docker. Metrics not started. |
| M4 websocket backend | **Done** (2026-10-09): `-w`/`-z` connect each session to tmate-websocket over TCP with the control protocol v2 (`src/backend.rs`; the gateway owns the socket, the driver speaks the protocol in-process or in the worker via `wire.rs`). Header, verbatim forwarding, join/left, snapshots from the pane grids, FWD_MSG, PANE_KEYS, RESIZE in the size rule, EXEC and `explain-session-not-found`, RENAME_SESSION (named sessions, reconnection), placeholder session files for the backend's renames. 9 fake-backend tests in `tests/websocket.rs`; checked against the real backend built from its Dockerfile (notices, `tmate_web`, web client snapshot/resize/keys, exec, reconnection). |

Run: `cargo run -- --listen 0.0.0.0:2200 --host <public name>`. The server
prints its host-key fingerprint; clients need it in `tmate.conf`:

```
set -g tmate-server-host 127.0.0.1
set -g tmate-server-port 2200
set -g tmate-server-ed25519-fingerprint "SHA256:..."
```

Test like action-tmate does: `tmate -f tmate.conf -S /tmp/t.sock new-session -d`,
`wait tmate-ready`, `display -p '#{tmate_ssh}'`. Unix socket paths must be
short. The Linux client test runs in `alpine` Docker with
`--add-host=host.docker.internal:host-gateway` and `--host host.docker.internal`.

## Modules

- `msgpack.rs`: streaming msgpack codec with size/depth/length limits. Hand-written
  rather than `rmpv` because SSH delivers arbitrary chunks and framing is needed
  anyway; swapping to `rmpv` later is contained to this file plus `proto::Args`.
- `proto.rs`: protocol 6 message types (`HostMsg`) and server-to-host encoders.
  Field order follows `../tmate-ssh-server/tmate-protocol.h` exactly.
- `session.rs`: tokens (25 chars, `ro-` prefix) and the token registry.
- `gateway.rs`: russh server. `tmate` user + subsystem `tmate` = host; a token
  username + shell request = viewer. Viewers currently get a placeholder message.
- `keys.rs`: viewer input bytes to tmux 2.x `key_code` values (`KEYC_BASE + n`,
  modifier bits). Mouse reports are dropped, as the old server did.
- `render.rs`: full frame and diff frame for a viewer (pane via `vt100`, tmux-style
  status line on the bottom row).

## M1: what remains

A per-session hub (`hub.rs`), `Arc<Mutex<_>>` held by the registry and by both
connection types. Never hold the lock across an `.await`; collect
`(Handle, ChannelId, Bytes)` under the lock and send after releasing it.

State: tokens; host `Handle`+`ChannelId`; panes `BTreeMap<id, vt100::Parser>`
sized from `SYNC_LAYOUT`; last `Layout`; status left/right; viewers
`HashMap<id, {Handle, ChannelId, Access, ip, Size, last: Option<vt100::Screen>, KeyParser}>`;
`authorized_keys: Option<Vec<PublicKey>>`.

Behaviour to match the old server (`../tmate-ssh-server` + `../tmate-websocket/lib/tmate/session.ex`):

- `PTY_DATA` → feed the pane parser, then for each viewer send
  `Frame::diff(last)` and store `screen.clone()` as `last`.
- Viewer join (after `pty_request` + `shell_request`): send `Frame::full`,
  notify host `A mate has joined (ip) -- N client(s) currently connected`,
  `SET_ENV tmate_num_clients N`. Leave: same with `left`.
- Size: host pane size = min over **read-write** viewers of `(cols, rows-1)`
  (`resize.c`, read-only excluded); send `RESIZE sx sy`, or `-1 -1` with no viewers.
  Resize also on `window_change_request`; resend a full frame to that viewer.
- Keys: read-write viewers only; `PANE_KEY pane=-1 key`. Hold a lone trailing
  ESC ~50 ms then `KeyParser::flush`. Prefix (`C-b`) bindings are M2; in M1 all
  keys go to the host pane.
- `-a` authorized keys: host sends `set-option [-g] tmate-authorized-keys <path>`
  (reset + enable) then `set-option tmate-set authorized_keys=<key line>` per key.
  When enabled, viewer `auth_none` must reject (so the client tries keys) and
  `auth_publickey` accepts only a listed key. Server flag `-A` = require keys for
  every session (`AUTHORIZED_KEYS_ONLY_ERROR_MSG_*` in `tmate-daemon-decoder.c`).
- `FIN` or host disconnect: tell viewers `\r\n[tmate] session ended\r\n`, close them,
  drop the session from the registry.
- `SNAPSHOT`/`RECONNECT`: restore pane grids (cell word = flags<<24|attr<<16|bg<<8|fg,
  tmux 2.x `GRID_ATTR_*`/`GRID_FLAG_*`); M1 may keep refusing reconnects.

## Differential testing against the old server (requested)

Build the old server from `../tmate-ssh-server/Dockerfile` (alpine 3.16) and run
both. For each scenario drive the same tmate 2.4.0 client and a scripted `ssh`
viewer, and diff what the viewer's terminal shows (feed both outputs through a
`vt100::Parser` and compare `contents()`), plus the host-side `tmate_*` env vars
and notices (`tmate show-messages`):

1. handshake notices, `tmate_ssh`, `tmate_ssh_ro`, `tmate_num_clients`
2. one viewer typing `echo hi`, then a second viewer joining late (snapshot)
3. viewer resize 80x24 → 120x40 → 60x20; two viewers of different sizes
4. read-only viewer: no input accepted, excluded from size calculation
5. `-a authorized_keys`: unlisted key rejected, listed key accepted
6. colours/attributes (`ls --color`, `tput`), wide characters, the alternate screen (`vim`, `less`)
7. host `kill-server` / host network drop: what viewers see
8. join/leave notices on the host, `tmate_num_clients` counts
9. malformed input: oversized/garbage msgpack from a fake host must only end that session

Known intended differences: new host key (fingerprint changes); reconnection
(`RECONNECT`) may lag; web terminal and named sessions only with the
websocket backend (`-w`), as before.

## Security requirements carried over from the old-server review

Non-root, no capabilities; host keys only in the gateway; one sandbox per session
(uid/user namespace, no network, seccomp); every host-supplied size/count bounded
before use (see `proto::MAX_*`); authenticated links to any backend; pinned
dependencies with `cargo audit` in CI.

## M2: full parity with the old server's viewer experience

Reference: `../tmate-ssh-server` (tmux 2.2 fork). Everything below is what a
viewer of the old server got; the parity tests in `tests/parity.rs` compare it.

### Layout, several windows and panes
- Render every pane of the active window at its `xoff/yoff/sx/sy` from
  `SYNC_LAYOUT` (`tmate_sync_window_panes`), with tmux's single-line borders
  (`screen-redraw.c`: `│ ─ ┼ ┌ ┐ └ ┘ ├ ┤ ┬ ┴`, drawn in the default style; the
  active pane's border uses `pane-active-border-style` fg=green). Cursor from the
  active pane. Inactive windows are kept (their parsers live on) but not drawn.
- The host keeps one `vt100::Parser` per pane across layout changes; recreate
  on size change (tmux reflows; we may clear). Cap: `proto::MAX_PANES`, pane
  size ≤ 1000x1000, scrollback 2000 lines (`TMATE_HLIMIT`).
- `SYNC_LAYOUT` window list drives the status line: `idx:name` with `*` for the
  current window, `-` for the last window, `#`/`!`/`~` activity flags omitted.
  Host `STATUS` left/right strings replace tmux's templates (`status.c`).

### Keys, prefix and bindings (`server-client.c:server_client_handle_key`)
- Per viewer: current key table (`root` or `prefix`), repeat flag + timer.
- `prefix` option (default `C-b`, replicated via `set-option -g prefix`): in
  the root table the prefix key switches to the `prefix` table. Next key: look
  up a binding; if found dispatch it and return to root (unless `-r` and
  `repeat-time` (500 ms) not elapsed, in which case stay). Unbound key after
  prefix: ignored, back to root. `bind -n` bindings live in the root table.
- Bindings come from the host's replicated `bind-key`/`unbind-key` commands
  (parse `-n`, `-r`, `-T table`, key name via tmux `key-string.c` rules:
  `C-`, `M-`, `S-` prefixes, `^x`, names like `PPage`, `Space`, `Enter`,
  `BSpace`, hex `0x..`; `C-a` → 0x01, `C-Space` → 0, `C-?` → BSpace) with the
  bound command string kept verbatim. The server starts with tmux 2.2's default
  bindings (`key-bindings.c`) because the host replicates only user changes.
- Dispatching a binding: parse the command string with tmux's splitting rules
  (quotes, `\;` separators). Local commands (`local_cmds` in
  `tmate-daemon-encoder.c`): `detach-client` (close that viewer),
  `attach-session`, `bind-key`, `unbind-key`, `set-option`, `set-window-option`
  (update server-side options/bindings). Everything else is sent to the host as
  `EXEC_CMD client_id args…` (`tmate_client_cmd`, argv form, protocol 6);
  `send-prefix` is just another forwarded command. `FAILED_CMD client_id cause`
  comes back and is shown as a status message for that viewer for
  `display-time` (750 ms default, `options-table.c`) in reverse video on the
  status row, capitalised like `tmate_failed_cmd` does.
- `command-prompt` (`:`) and `confirm-before` run on the server: show the
  prompt on the status row, edit with emacs keys (`status-keys emacs`), on Enter
  substitute `%%`/`%1` and forward the result as above. Esc/C-c cancels.
- `display-panes` (`q`): draw big pane numbers; a digit then sends
  `select-pane -t win.pane` (`tmate_client_set_active_pane`).
- Mouse: dropped (as before). Read-only viewers: keys ignored entirely except
  resize, and they are excluded from the size calculation.
- Pasting heuristic (`assume-paste-time`): keys arriving < 1 ms apart bypass
  bindings; implement the same so pasted `C-b` text isn't eaten.

### Copy mode as the host shows it
- `SYNC_COPY_MODE pane [backing, oy, cx, cy, [selx, sely, rect], [type, prompt, input]]`
  switches the pane view to copy mode: show the pane's history scrolled by `oy`
  (lines from the top of history), cursor at `cx,cy`, selection highlighted in
  reverse (`mode-style` bg=yellow fg=black), the `[N/M]` position indicator at
  the top right in the same style, and the search/goto prompt line when `input`
  is present. Empty array = leave copy mode. `WRITE_COPY_MODE pane text` is the
  host writing into a copy-mode output buffer (`show-messages`, `list-keys`
  inside tmate): render as a scrollable text pane. Keys in copy mode go to the
  host like any other key (the host runs copy mode).
- Needs history: keep `vt100` scrollback (set `scrollback_len` 2000) and read
  rows via `Screen::rows` after `set_scrollback`.

### Host reconnect
- `RECONNECT data` + `SNAPSHOT`: the old server only supported this with the
  websocket backend; accept it by restoring pane grids from the snapshot
  (`restore_snapshot_grid`) and re-registering under the same tokens when the
  signed reconnection data names a session we still hold. Without a backend,
  tokens are not stable across server restarts, same as before.

### Connection handling parity
- `-x` PROXY protocol v1 header before SSH (`get_client_ip_proxy_protocol`):
  read `PROXY TCP4|TCP6 src dst sport dport\r\n`, use `src` as the peer IP in
  notices; invalid header → close.
- `exec` requests (`ssh token@host cmd`): the old server only served these with
  the websocket backend; reply with a one-line explanation and exit status 1.
- Grace period: 20 s from accept to a role (`TMATE_SSH_GRACE_PERIOD`);
  keepalive every 300 s (`TMATE_SSH_KEEPALIVE_SEC`); a host with no viewer for
  a long time is still kept (the old server never expired sessions itself).
- Banner `SSH-2.0-tmate` kept. Viewer auth errors: the old server printed
  `Invalid session token` / `Expired session token` texts after a random sleep;
  we reject at auth instead (the SSH client shows "Permission denied"), which
  the parity test treats as equivalent.
- Server flags to mirror: `-A/--authorized-keys-only`, `-b/--listen`, `-h/--host`,
  `-k/--keys-dir`, `-p` (listen port), `-q/--advertised-port`, `-x/--proxy-protocol`,
  `-v` (log level via `RUST_LOG`). `-w/-z` (websocket backend): ported in M4,
  see README.md "Websocket backend".

## M3: sandboxing and operations
- Linux: after accept, each session's parser/renderer should run in a child
  process with `unshare(CLONE_NEWUSER|NEWPID|NEWNET|NEWNS|NEWIPC)`, chroot into
  an empty dir, drop to an unprivileged uid, `prctl(PR_SET_NO_NEW_PRIVS)`,
  seccomp allowlist (read/write/poll/epoll/mmap/munmap/brk/exit/futex/
  clock_gettime), rlimits (RLIMIT_AS 256 MiB, RLIMIT_NOFILE 64, CPU). The gateway
  keeps the SSH connection and host keys and talks to the child over a
  socketpair with the same msgpack framing. The old server did chroot +
  unshare + setuid(nobody) as root; we must never need root: use user
  namespaces, and fall back to in-process with a loud warning where they are
  unavailable (macOS, restricted containers).
- Limits: sessions per source IP, connections per minute, message rate per host,
  total sessions; metrics on `/metrics` (Prometheus) bound to localhost.
- `Dockerfile`: multi-stage, distroless/alpine runtime, non-root user, read-only
  filesystem, `EXPOSE 2200`, same env vars as the old `docker-entrypoint.sh`
  (`SSH_PORT_LISTEN`, `SSH_PORT_ADVERTISE`, `SSH_HOSTNAME`, `SSH_KEYS_PATH`,
  `USE_PROXY_PROTOCOL`).
