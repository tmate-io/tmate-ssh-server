# tmate-server-rs

A Rust replacement for [`tmate-ssh-server`](https://github.com/tmate-io/tmate-ssh-server),
the server side of [tmate](https://tmate.io): a host runs `tmate`, gets an
`ssh token@server` link, and anyone with the link sees and (unless it is the
read-only link) types into the host's terminal.

The old server was a fork of tmux 2.2 plus libssh that forked one process per
connection, ran the tmux core inside a chroot as root, and needed an Elixir
websocket backend for several features. This one is a single non-root
process on tokio and [russh](https://crates.io/crates/russh); the tmux state
the viewers see (panes, status line, copy mode, key bindings) is reproduced
here without tmux.

## Compatibility

- Unmodified tmate 2.4.0 clients (Homebrew, distribution packages, the
  static Linux binary used by `action-tmate`), protocol version 6. Older
  clients are told which version they need and disconnected.
- Viewers use plain `ssh`; the links have the same shape as before
  (`ssh -p<port> <token>@<host>`, `ro-` prefix for read-only).
- Host-side behaviour `action-tmate` and scripts rely on: `tmate wait
  tmate-ready`, `#{tmate_ssh}`, `#{tmate_ssh_ro}`, `#{tmate_num_clients}`,
  join/leave notices, `-a authorized_keys` and the server-wide `-A`.
- SSH banner `SSH-2.0-tmate`, keepalive every 300 s, a 20 s grace period
  from accept to a role (host subsystem or viewer shell), PROXY protocol v1.
- The host key is new (different fingerprint) unless you copy the old
  `ssh_host_*_key` files into the keys directory.

Differences a viewer can notice are listed in `PLAN.md` ("Known intended
differences") and checked by the parity tests.

## Build and run

Rust 1.85 or newer (edition 2024).

```
cargo build --release
./target/release/tmate-server-rs --listen 0.0.0.0:2200 --host tmate.example.org
```

The server creates `keys/ssh_host_ed25519_key` on first start (or loads
`ssh_host_ed25519_key`, `ssh_host_rsa_key` and `ssh_host_ecdsa_key` if they
exist) and logs each key's SHA256 fingerprint. Clients need it in
`~/.tmate.conf`:

```
set -g tmate-server-host tmate.example.org
set -g tmate-server-port 2200
set -g tmate-server-ed25519-fingerprint "SHA256:..."
```

`tmate-server-rs --help` lists all flags.

### Flags: old server to new

| Old `tmate-ssh-server` | `tmate-server-rs` | Notes |
|---|---|---|
| `-A` | `-A`, `--authorized-keys-only` | Refuse sessions started without `-a authorized_keys`. |
| `-b <ip>` | `-b`, `--bind <IP>` | Or `--listen <IP:PORT>`; `-b`/`-p` override its parts. |
| `-p <port>` | `-p`, `--port <PORT>` | Default 2200. |
| `-h <hostname>` | `-H`, `--host <HOSTNAME>` | `-h` prints help. Defaults to the machine hostname, as before. |
| `-k <keys_dir>` | `-k`, `--keys-dir <DIR>` | Default `keys`. |
| `-q <port>` | `-q`, `--advertised-port <PORT>` | Port written into session links; defaults to the listen port. |
| `-x` | `-x`, `--proxy-protocol` | Expect a PROXY protocol v1 line before SSH; its source IP is the viewer's IP in notices. |
| `-v` | `-v`, `-vv` | debug, trace. `RUST_LOG` overrides when set. |
| `-w <hostname>` | `-w`, `--websocket-host <HOSTNAME>` | Connect every session to a tmate-websocket backend; see "Websocket backend". |
| `-z <port>` | `-z`, `--websocket-port <PORT>` | The backend's daemon listener; default 4002, as before. |

New flags:

| Flag | Default | Meaning |
|---|---|---|
| `--sandbox auto\|off\|require` | `auto` | Run each session in a locked-down worker process; see "Sandboxing". |
| `--max-sessions-per-ip N` | 10 | Sessions one source address may hold at a time. A host over the limit is told so and disconnected. |
| `--max-sessions N` | 1000 | Sessions the server holds at a time. |
| `--host-rate-limit BYTES` | 2097152 | Bytes per second a host may send, sustained. Bursts (snapshots, a screenful) pass; a host over the limit for 5 s is dropped. |
| `--sessions-dir DIR` | `/tmp/tmate/sessions` | With `-w` only: the directory the backend's `tmux_socket_path` points at, shared with it; see "Websocket backend". |

A viewer that stops reading (a stalled ssh client) is closed once 8 MiB of
output wait for it, so one slow viewer cannot make the server buffer forever.

## Docker

```
docker build -t tmate-server-rs .
docker run --rm -p 2200:2200 -v /srv/tmate/keys:/keys \
  -e SSH_HOSTNAME=tmate.example.org tmate-server-rs
```

The image runs as uid 10001 with no shell beyond the entrypoint. The
entrypoint understands the old image's environment variables, so an
existing deployment can switch images without changing its configuration:

| Variable | Default | Flag |
|---|---|---|
| `SSH_PORT_LISTEN` | `2200` | `--listen 0.0.0.0:$SSH_PORT_LISTEN` |
| `SSH_PORT_ADVERTISE` (or the old spelling `SSH_PORT_ADVERTIZE`) | `$SSH_PORT_LISTEN` | `--advertised-port` |
| `SSH_HOSTNAME` | unset | `--host` |
| `SSH_KEYS_PATH` | `/keys` | `--keys-dir` |
| `SSH_HOST_ED25519_KEY`, `SSH_HOST_RSA_KEY` | unset | Key material written into `SSH_KEYS_PATH` (mode 600) before start, for platforms without volumes. |
| `USE_PROXY_PROTOCOL` | `0` | `--proxy-protocol` when `1` |
| `WEBSOCKET_HOSTNAME`, `HAS_WEBSOCKET` | unset | `--websocket-host` (`HAS_WEBSOCKET=1` means `localhost`), as the old image did. |
| `WEBSOCKET_PORT`, `TMATE_SESSIONS_DIR` | `4002`, `/tmp/tmate/sessions` | `--websocket-port`, `--sessions-dir` (new; the old image had no equivalent). |

Any arguments after the image name are passed through and take precedence.
`docs/DEPLOYMENT.md` covers running one instance per region (Fly.io).

For the per-session sandbox to be complete inside Docker, start the
container with the seccomp profile in `docker/seccomp.json` (see
"Sandboxing" below for why):

```
docker run --rm -p 2200:2200 --security-opt seccomp=$PWD/docker/seccomp.json \
  -v /srv/tmate/keys:/keys -e SSH_HOSTNAME=tmate.example.org tmate-server-rs
```

`scripts/docker-smoke.sh` builds the image, runs it with `--sandbox
require`, drives a real tmate 2.4.0 host and an ssh viewer in two more
containers and checks the viewer sees the screen while the log shows the
worker sandboxed.

## Sandboxing

Everything a host sends over the `tmate` channel and everything viewers
type is untrusted, and the code that parses and renders it (msgpack, the
layout, the terminal emulator, copy mode, snapshots) is where a bug would
hurt. The old server put that code in a per-connection process that ran as
root and did `chroot` + `unshare(NEWPID|NEWIPC|NEWNS|NEWNET)` + `setuid
nobody`. This server does the equivalent without root.

On Linux, with `--sandbox auto` (the default) or `require`, the server
process (the gateway) only handles SSH: host keys, authentication, the
limits, and copying bytes. At `subsystem tmate` time it starts
`tmate-server-rs --worker` for the session, with one end of a `socketpair`
as fd 3, and forwards the raw host bytes and the viewers' events over it;
the worker answers with the bytes to write to each connection
(`src/wire.rs`, length-prefixed msgpack). Before reading a single byte the
worker locks itself down (`src/sandbox.rs`), in this order:

1. closes every file descriptor except stderr and fd 3;
2. `unshare(CLONE_NEWUSER)`, mapping itself to uid 0 inside the new user
   namespace (what lets an unprivileged process do the next steps);
3. `unshare(NEWPID|NEWNET|NEWIPC|NEWUTS)`: no network at all;
4. `unshare(CLONE_NEWNS)`, mounts an empty read-only tmpfs and
   `pivot_root`s into it (chroot as a fallback): no filesystem at all;
5. Landlock, denying all filesystem and TCP access, where the kernel has it;
6. `prctl(PR_SET_NO_NEW_PRIVS)`, then drops every capability (bounding
   set, ambient set, `capset` to nothing);
7. rlimits: 256 MiB address space, 64 descriptors, `RLIMIT_NPROC` 0 (no
   processes or threads), 600 s of CPU time, no core files;
8. a seccomp-BPF allowlist; any other system call kills the worker.

The seccomp allowlist, found with `strace -f` on the Alpine image (musl,
arm64 and x86_64) around tokio's `current_thread` runtime, is: `read`,
`write`, `readv`, `writev`, `close`, `epoll_create1`, `epoll_ctl`,
`epoll_pwait`, `epoll_pwait2`, `epoll_wait` (x86_64), `eventfd2`, `futex`,
`mmap`, `munmap`, `mprotect`, `mremap`, `brk`, `madvise`, `clock_gettime`,
`clock_nanosleep`, `nanosleep`, `rt_sigaction`, `rt_sigprocmask`,
`rt_sigreturn`, `sigaltstack`, `exit`, `exit_group`, `getrandom`,
`sched_yield`, `membarrier`, `getpid`, `gettid`, `tgkill`, `ppoll`, `poll`
(x86_64), `sendto`, `recvfrom`, `shutdown` (mio reads and writes the socket
with `send`/`recv`), `socketpair` restricted to `AF_UNIX` (tokio's runtime
creates one for its signal driver), `fcntl` restricted to `F_GETFD`,
`F_SETFD`, `F_GETFL`, `F_SETFL`, `F_DUPFD_CLOEXEC`, and `ioctl` restricted
to `FIONBIO`. The ones actually observed in a session are `mmap`, `munmap`,
`brk`, `write`, `close`, `fcntl`, `epoll_*`, `eventfd2`, `socketpair`,
`sendto`, `recvfrom`, `shutdown` and `exit_group`; the rest are what the
allocator, `Mutex`, timers and the panic path can need. Setting
`TMATE_SECCOMP_LOG=1` makes a stray call get logged by the kernel (audit
or `dmesg`) instead of killing the worker, for finding out what a new libc
or tokio needs; never set it in production.

A worker holds no secrets: the host keys, the HMAC key that signs
reconnection data and the token registry stay in the gateway, which treats
the worker's frames as untrusted too. A session is one worker; a worker
that dies (a bug, the memory limit, a SIGSYS) ends only that session, and
the host's tmate client reconnects on its own. A compromised worker can
read and write its own session's bytes and burn 256 MiB and 10 CPU-minutes,
nothing else.

Every step is best effort and reported. At startup the server runs a
probe worker and logs the outcome:

- `sandbox: each session runs in a locked-down worker process` with the
  per-step summary: everything worked;
- `sandbox only partial: ...`: workers run with seccomp, rlimits and
  Landlock but without user namespaces (no empty root, no separate network
  namespace), because `unshare` is not permitted. This is what a plain
  `docker run` gives you, see below;
- `sandbox unavailable: ...`: sessions run in the server process, as on
  macOS.

`--sandbox require` turns the last two into a startup error (and makes a
per-session worker refuse to run if a step fails later). `--sandbox off`
keeps everything in one process; the test-suite runs that way on macOS.

### Docker

Docker's default seccomp profile only allows `unshare`, `mount` and
`umount2` to containers with `CAP_SYS_ADMIN`, and not `pivot_root` at all,
so user namespaces fail inside a default container and the server reports
"sandbox only partial". The container does **not** need `--privileged`,
`--cap-add SYS_ADMIN` or `seccomp=unconfined`; what it needs is those
four system calls, which `docker/seccomp.json` (Docker's default profile
plus one rule) permits:

```
docker run --security-opt seccomp=/path/to/docker/seccomp.json ... tmate-server-rs
```

Tested on Docker Desktop (Linux kernel 6.x/7.x VM, arm64): with the
profile the probe reports every step ok; without it, "sandbox only
partial"; with `--sandbox require` and without it the server refuses to
start. `--security-opt seccomp=unconfined` also works but drops Docker's
own filter for the gateway as well, so prefer the profile. `--cap-add
SYS_ADMIN` works too (with chroot instead of pivot_root) but grants more
than needed. On hosts where AppArmor restricts unprivileged user
namespaces (recent Ubuntu, `kernel.apparmor_restrict_unprivileged_userns`),
`unshare` fails with EPERM even with the profile; the log says so, and the
server runs with the partial sandbox unless `--sandbox require` is set.

On Fly.io and other Firecracker-style platforms the container is not
under Docker's seccomp profile and user namespaces are available to
unprivileged processes; check the startup log line.

## Websocket backend

The old server delegated named sessions (`tmate -n name` with an API key),
the web terminal (`tmate.io/t/<token>`), exec requests (`ssh token@host
command`, used for `explain-session-not-found`) and session reconnection
to [tmate-websocket](https://github.com/tmate-io/tmate-websocket), an
Elixir service, over a private TCP "control protocol" (version 2, msgpack;
`tmate-websocket.c` and `tmate-protocol.h` in the old tree). This server
speaks the same protocol, so an existing backend works unchanged:

```
tmate-server-rs --listen 0.0.0.0:2200 --host tmate.example.org \
  --websocket-host 127.0.0.1 --websocket-port 4002
```

Without `-w` nothing changes: sessions have random tokens, the server
produces the host's notices and links itself, exec requests are answered
with `tmate: command execution is not supported on this server` (exit
status 1), a host asking for a named session is told `Named sessions are
not supported (no websocket server)`, and reconnection only works while
the same server process lives.

With `-w`, every session gets a TCP connection to the backend when its
host connects (if that fails, the session is refused with a notice and
the host's tmate client retries, which is how the old server "died
early"), and from then on, as `tmate-websocket.c` did:

- the host's HEADER becomes `CTL_HEADER` (ip, key, tokens, the `ssh
  -p<port> %s@<host>` format, client version and protocol), and every
  message the host sends is forwarded verbatim as `CTL_DEAMON_OUT_MSG`
  after it was handled here, FIN included;
- the backend, not the server, produces the host's notices, `tmate_ssh`,
  `tmate_ssh_ro`, `tmate_web`, `tmate_web_ro`, `tmate_num_clients`,
  `tmate_reconnection_data` and the READY, delivered as
  `CTL_DEAMON_FWD_MSG` and written to the host as is;
- ssh viewers are announced with `CTL_CLIENT_JOIN` (client id, ip, key,
  read-only) and `CTL_CLIENT_LEFT`; the join/leave notices come back from
  the backend, which counts web clients too;
- `CTL_REQUEST_SNAPSHOT` is answered with `CTL_SNAPSHOT` from the server's
  own pane grids, in the old `do_snapshot` format (per pane: id, cursor,
  mode word, lines as text plus one packed `flags<<24|attr<<16|bg<<8|fg`
  word per written cell), which is what a web client starts from;
- `CTL_PANE_KEYS` from web clients are typed into the host's pane (one key
  per byte), and `CTL_RESIZE` (the smallest web client) takes part in the
  pane size rule next to the ssh viewers;
- exec requests open a connection of their own, send `CTL_EXEC` (user, ip,
  key, command) and relay the `CTL_EXEC_RESPONSE` message and exit status
  to the ssh client; a viewer presenting a token no session holds is let
  in and turned into an `explain-session-not-found` exec so the backend
  can say what became of the session (tokens may then look like session
  names: `[A-Za-z0-9_/-]`, more than two characters);
- `CTL_RENAME_SESSION` (named sessions, and reconnection: the backend
  verifies the host's `RECONNECT` data itself and renames the new session
  to its old tokens) re-registers the session under the new tokens;
- losing the backend connection ends the session (the host reconnects).

The backend keeps one piece of state outside the protocol: it renames the
old server's tmux socket files (`<token>` and the `ro-<token>` symlink) in
its `tmux_socket_path` before it sends `CTL_RENAME_SESSION`, and crashes
the session when they are missing. This server has no sockets, so with
`-w` it creates empty placeholders in `--sessions-dir` (default
`/tmp/tmate/sessions`, the backend's default) and removes them, under
whatever name they ended up with, when the session ends. The directory
must be shared with the backend (a volume, when both run in containers)
for named sessions and reconnection to work; without it the rest still
does. `CTL_LATENCY` is not sent; the old server never sent it either.

Checked against the real backend (built from its Dockerfile, elixir
1.9): a tmate 2.4.0 host gets its notices, `tmate_web` and
`tmate_num_clients` from the backend; a web client over the backend's
websocket receives the layout and snapshot, resizes the pane and types
into it; exec and unknown-token requests are answered by the backend; and
after a restart of this server the host resumes under the same tokens.

## Tests

- `cargo test` runs the unit tests and, when a `tmate` binary is in `PATH`,
  the live tests in `tests/live.rs` (a real tmate 2.4.0 host and scripted
  SSH viewers against this server) and `tests/websocket.rs` (the same host
  with the server in backend mode against a scripted fake backend speaking
  the control protocol). Without `tmate` those tests print "skipping" and
  pass.
- `scripts/parity.sh [path-to-tmate-ssh-server]` builds the old C server
  from its own Dockerfile, runs it as the reference, and runs
  `tests/parity.rs`: the same scenarios against both servers, diffing what
  viewers see and what the host is told. Needs Docker and `tmate`.
- `scripts/docker-smoke.sh` builds the Docker image and checks a real
  tmate 2.4.0 host and an ssh viewer through a sandboxed session worker
  (`--sandbox require`). Needs Docker.
- `cargo clippy` is expected to be clean.
