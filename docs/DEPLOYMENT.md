# Deployment

The server is a single static binary listening on one TCP port. It needs no
database and no other service. What it does need is a host key that is the
same everywhere, because tmate clients pin the fingerprint of `ssh.tmate.io`
(or whatever `tmate-server-host` they are configured with).

## Container

```sh
docker build -t tmate-server-rs .
docker run -p 22:2200 -e SSH_HOSTNAME=tmate.example -e SSH_PORT_ADVERTISE=22 \
  -v /srv/tmate/keys:/keys tmate-server-rs
```

Environment variables (same names as the old `tmate-ssh-server` image):

| Variable | Default | Meaning |
|---|---|---|
| `SSH_PORT_LISTEN` | `2200` | port inside the container |
| `SSH_PORT_ADVERTISE` | listen port | port written into session links |
| `SSH_HOSTNAME` | container hostname | hostname written into session links |
| `SSH_KEYS_PATH` | `/keys` | directory with `ssh_host_{ed25519,rsa,ecdsa}_key` (an ed25519 key is generated if none exists) |
| `SSH_HOST_ED25519_KEY` | – | key material; written to `SSH_KEYS_PATH/ssh_host_ed25519_key` (mode 600) at start |
| `SSH_HOST_RSA_KEY` | – | same for `ssh_host_rsa_key` |
| `USE_PROXY_PROTOCOL` | `0` | `1`: expect a PROXY protocol v1 line from the load balancer before SSH (`--proxy-protocol`); its source IP is the viewer IP in join notices. Connections without a valid header are closed. |
| `WEBSOCKET_HOSTNAME`, `HAS_WEBSOCKET` | – | `--websocket-host` (`HAS_WEBSOCKET=1` means `localhost`): connect every session to a tmate-websocket backend |
| `WEBSOCKET_PORT` | `4002` | `--websocket-port`, the backend's daemon listener |
| `TMATE_SESSIONS_DIR` | `/tmp/tmate/sessions` | `--sessions-dir`, a directory shared with the backend (its `tmux_socket_path`) |

Arguments after the image name are appended to the server command line and
take precedence over the variables (`tmate-server-rs --help` lists them).

The container runs as an unprivileged user and needs no capabilities. Each
session is handled by a worker process that drops into its own user,
mount, pid, network, ipc and uts namespaces, an empty root, Landlock,
rlimits and a seccomp allowlist (README.md, "Sandboxing"). Inside Docker
that needs the `unshare`, `mount`, `umount2` and `pivot_root` system
calls, which Docker's default seccomp profile withholds from unprivileged
containers, so run the image with the profile shipped in the repository:

```sh
docker run -p 22:2200 --security-opt seccomp=$PWD/docker/seccomp.json \
  -e SSH_HOSTNAME=tmate.example -e SSH_PORT_ADVERTISE=22 \
  -v /srv/tmate/keys:/keys tmate-server-rs
```

Without it the server starts anyway and logs `sandbox only partial`
(workers still get seccomp, rlimits and Landlock, but no namespaces); add
`--sandbox require` after the image name to make that a startup error
instead. No `--privileged`, `--cap-add` or `seccomp=unconfined` is needed.

Limits (flags after the image name): `--max-sessions-per-ip` (10),
`--max-sessions` (1000), `--host-rate-limit` (2 MiB/s sustained per host);
a viewer with 8 MiB of unread output is dropped.

## Global service on Fly.io

The 2.4.0 client resolves every A record of `tmate-server-host`, connects to
all of them in parallel and keeps the fastest. Each server writes its own
hostname into the link it hands out. So a global service is **one app per
region**, each with a dedicated IPv4 and its own DNS name, no shared state:

```
ssh.tmate.example   A  <ip of tmate-nyc>   A  <ip of tmate-fra>   A  <ip of tmate-sin>
nyc1.tmate.example  A  <ip of tmate-nyc>
fra1.tmate.example  A  <ip of tmate-fra>
```

Per region:

```sh
ssh-keygen -t ed25519 -N '' -f host_ed25519   # once, shared by all regions
fly apps create tmate-nyc
fly ips allocate-v4 -a tmate-nyc              # dedicated, ~$2/month
fly secrets set -a tmate-nyc SSH_HOST_ED25519_KEY="$(cat host_ed25519)"
sed -e 's/^app = .*/app = "tmate-nyc"/' -e 's/^primary_region = .*/primary_region = "ewr"/' \
    -e 's/^SSH_HOSTNAME = .*/SSH_HOSTNAME = "nyc1.tmate.example"/' fly.toml > fly.nyc.toml
fly deploy -a tmate-nyc -c fly.nyc.toml
```

Repeat with `fra`, `sin`, … and publish the fingerprint from
`ssh-keygen -lf host_ed25519.pub -E sha256` for clients'
`tmate-server-ed25519-fingerprint`.

Sizing: a `shared-cpu-1x` / 256 MB machine per region is enough to start (the
old service ran its whole fleet for under $100/month). `fly.toml` sets
`auto_stop_machines = false`: a stopped machine would drop every live session.
Each session is a worker process (a few MB resident; its address space is
capped at 256 MiB), so size memory for the number of concurrent sessions
and set `--max-sessions` to match. Fly machines are not under Docker's
seccomp profile, so the sandbox should report every step ok; check the
first log lines after a deploy (`fly logs`) for
`sandbox: each session runs in a locked-down worker process`.

Not supported on Fly's anycast ("one hostname, any machine") model: a viewer
must reach the exact machine holding the host's session. That needs a session
store and node-to-node forwarding (what upterm does with Consul); it is not
implemented and the per-region layout above does not need it.

## Operations checklist

- Keep the host key out of the image; rotate it only together with a client
  release or a fingerprint announcement, since clients pin it.
- Watch `RUST_LOG=info` output for `session ready` / `host session closed`;
  Prometheus metrics are planned (PLAN.md, M3).
- Check the startup log for the sandbox line; `sandbox only partial` or
  `sandbox unavailable` means the platform withholds user namespaces (see
  README.md, "Sandboxing") and the container is the main isolation boundary.
- `session worker killed by SIGSYS` in the log means a worker made a system
  call outside the allowlist (after a libc or tokio upgrade, typically);
  `TMATE_SECCOMP_LOG=1` finds the call. Other worker deaths (`killed by
  signal 9`, the 256 MiB limit) end that one session; its host reconnects.
