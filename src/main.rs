mod accept;
mod backend;
mod bindings;
mod cmdline;
mod commands;
mod copymode;
mod cut;
mod driver;
mod gateway;
mod grid;
mod hub;
mod keys;
mod layout;
mod limits;
mod link;
mod msgpack;
mod prompt;
mod proto;
mod proxy;
mod reconnect;
mod render;
mod sandbox;
mod session;
mod snapshot;
mod wire;
mod worker;

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{ArgAction, Parser};
use russh::keys::{Algorithm, HashAlg, PrivateKey};
use tracing::{info, warn};

use crate::sandbox::SandboxMode;

const AFTER_HELP: &str = "\
Flags of the old tmate-ssh-server and their equivalents here:
  -A              -A, --authorized-keys-only
  -b <ip>         -b, --bind <IP>          (or --listen <IP:PORT>)
  -p <port>       -p, --port <PORT>        (or --listen <IP:PORT>)
  -h <hostname>   -H, --host <HOSTNAME>    (-h prints this help)
  -k <keys_dir>   -k, --keys-dir <DIR>
  -q <port>       -q, --advertised-port <PORT>
  -x              -x, --proxy-protocol
  -v              -v (repeat for more; or set RUST_LOG)
  -w <hostname>   -w, --websocket-host <HOSTNAME>
  -z <port>       -z, --websocket-port <PORT>  (default 4002)
                  --sessions-dir <DIR>         (default /tmp/tmate/sessions)

With -w, every session is connected to a tmate-websocket backend over TCP
and speaks its control protocol: the backend produces the host's notices
and links (including web links), names sessions, serves exec requests and
web clients. Without it, sessions have random tokens and ssh viewers only.

Host keys are read from <DIR>/ssh_host_{ed25519,rsa,ecdsa}_key; an ed25519
key is generated when none exists. The fingerprint is logged at startup.

Sandboxing (--sandbox): on Linux every session runs in a worker process
locked down with user namespaces, an empty root, seccomp and rlimits; the
startup log says which mode is active. See README.md, \"Sandboxing\".";

/// tmate server: lets tmate 2.4.0 clients share a terminal over ssh.
#[derive(Parser, Debug)]
#[command(version, about, after_help = AFTER_HELP, args_override_self = true)]
struct Cli {
    /// Address to listen on; -b and -p override its parts.
    #[arg(long, default_value = "0.0.0.0:2200", value_name = "IP:PORT")]
    listen: SocketAddr,

    /// IP to bind (the old -b).
    #[arg(short = 'b', long, value_name = "IP")]
    bind: Option<IpAddr>,

    /// Port to listen on (the old -p).
    #[arg(short = 'p', long, value_name = "PORT")]
    port: Option<u16>,

    /// Directory holding the ssh host keys.
    #[arg(short = 'k', long, default_value = "keys", value_name = "DIR")]
    keys_dir: PathBuf,

    /// Hostname put in the session links given to hosts (the old -h).
    /// Defaults to this machine's hostname, as the old server did.
    #[arg(short = 'H', long, value_name = "HOSTNAME")]
    host: Option<String>,

    /// Port put in the session links; defaults to the listen port.
    #[arg(short = 'q', long, value_name = "PORT")]
    advertised_port: Option<u16>,

    /// Refuse sessions whose host did not provide `-a authorized_keys`.
    #[arg(short = 'A', long)]
    authorized_keys_only: bool,

    /// Expect a PROXY protocol v1 header from a load balancer before SSH.
    #[arg(short = 'x', long)]
    proxy_protocol: bool,

    /// tmate-websocket backend to connect every session to (the old -w).
    #[arg(short = 'w', long, value_name = "HOSTNAME")]
    websocket_host: Option<String>,

    /// Port of the websocket backend's daemon listener (the old -z).
    #[arg(short = 'z', long, default_value_t = backend::DEFAULT_PORT, value_name = "PORT")]
    websocket_port: u16,

    /// With -w: the backend's `tmux_socket_path`, shared with it, where
    /// it expects a file per session (it renames them for named and
    /// resumed sessions). The old server kept its sockets there.
    #[arg(long, default_value = "/tmp/tmate/sessions", value_name = "DIR")]
    sessions_dir: PathBuf,

    /// More logging: -v for debug, -vv for trace. RUST_LOG, if set, wins.
    #[arg(short = 'v', long, action = ArgAction::Count)]
    verbose: u8,

    /// Run each session in a sandboxed worker process (Linux).
    #[arg(long, value_enum, default_value_t = SandboxMode::Auto, value_name = "MODE")]
    sandbox: SandboxMode,

    /// Most sessions one source address may hold at a time.
    #[arg(long, default_value_t = 10, value_name = "N")]
    max_sessions_per_ip: usize,

    /// Most sessions the server holds at a time.
    #[arg(long, default_value_t = 1000, value_name = "N")]
    max_sessions: usize,

    /// Bytes per second a host may send, sustained; a host over the
    /// limit for 5 s is dropped. Bursts (snapshots) are fine.
    #[arg(long, default_value_t = 2 * 1024 * 1024, value_name = "BYTES")]
    host_rate_limit: usize,

    /// Internal: run as a session worker on fd 3 (started by the gateway).
    #[arg(long, hide = true)]
    worker: bool,
}

/// The address to bind: `--listen` with `-b`/`-p` applied on top.
fn listen_addr(listen: SocketAddr, bind: Option<IpAddr>, port: Option<u16>) -> SocketAddr {
    SocketAddr::new(bind.unwrap_or(listen.ip()), port.unwrap_or(listen.port()))
}

/// The `tracing` filter: `RUST_LOG` when set, otherwise derived from `-v`.
/// russh is noisy, so it is held one level below ours.
fn log_filter(verbose: u8, rust_log: Option<&str>) -> String {
    match rust_log {
        Some(filter) if !filter.is_empty() => filter.to_string(),
        _ => match verbose {
            0 => "info,russh=warn".into(),
            1 => "debug,russh=info".into(),
            _ => "trace".into(),
        },
    }
}

const HOST_KEY_FILES: [&str; 3] = [
    "ssh_host_ed25519_key",
    "ssh_host_rsa_key",
    "ssh_host_ecdsa_key",
];

fn load_or_create_keys(dir: &Path) -> Result<Vec<PrivateKey>> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let mut keys = Vec::new();
    for name in HOST_KEY_FILES {
        let path = dir.join(name);
        if path.exists() {
            let key = russh::keys::load_secret_key(&path, None)
                .with_context(|| format!("loading {}", path.display()))?;
            keys.push(key);
        }
    }
    if keys.is_empty() {
        let path = dir.join("ssh_host_ed25519_key");
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;
        key.write_openssh_file(&path, russh::keys::ssh_key::LineEnding::LF)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        info!(path = %path.display(), "generated new host key");
        keys.push(key);
    }
    Ok(keys)
}

fn main() -> Result<std::process::ExitCode> {
    let cli = Cli::parse();

    // Logs (and the host-key fingerprint operators need) go to stderr so
    // stdout stays free for whatever supervises the server.
    let rust_log = std::env::var("RUST_LOG").ok();
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::new(log_filter(
            cli.verbose,
            rust_log.as_deref(),
        )))
        .init();

    if cli.worker {
        // The worker must lock itself down while still single-threaded,
        // so it builds its own runtime afterwards.
        return Ok(worker::main(cli.sandbox));
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(serve(cli))?;
    Ok(std::process::ExitCode::SUCCESS)
}

/// Decides where sessions run, from `--sandbox` and what a probe worker
/// manages on this machine. Logs the decision and why.
async fn choose_mode(sandbox: SandboxMode, verbose: u8) -> Result<link::Mode> {
    match sandbox {
        SandboxMode::Off => {
            warn!("sandbox off: sessions run in the server process (--sandbox off)");
            return Ok(link::Mode::InProcess);
        }
        SandboxMode::Auto | SandboxMode::Require => {}
    }
    if !cfg!(target_os = "linux") {
        if sandbox == SandboxMode::Require {
            bail!(
                "--sandbox require: sandboxing needs Linux (user namespaces, seccomp); this is {}",
                std::env::consts::OS
            );
        }
        warn!(
            os = std::env::consts::OS,
            "sandbox unavailable on this platform: sessions run in the server process"
        );
        return Ok(link::Mode::InProcess);
    }
    let exe = std::env::current_exe().context("finding our own executable for worker processes")?;
    match link::probe_sandbox(&exe, sandbox, verbose).await {
        Ok((level, summary)) if level >= 2 => {
            info!(%summary, "sandbox: each session runs in a locked-down worker process");
        }
        Ok((level, summary)) => {
            if sandbox == SandboxMode::Require {
                bail!("--sandbox require: a worker could not fully lock itself down: {summary}");
            }
            if level == 0 {
                warn!(%summary, "sandbox unavailable: sessions run in the server process. See README.md, Sandboxing");
                return Ok(link::Mode::InProcess);
            }
            warn!(%summary, "sandbox only partial: sessions run in worker processes without user namespaces. See README.md, Sandboxing");
        }
        Err(e) => {
            if sandbox == SandboxMode::Require {
                bail!("--sandbox require: cannot run a sandboxed worker: {e}");
            }
            warn!(error = %e, "sandbox unavailable: sessions run in the server process. See README.md, Sandboxing");
            return Ok(link::Mode::InProcess);
        }
    }
    Ok(link::Mode::Worker {
        exe,
        sandbox,
        verbose,
    })
}

async fn serve(cli: Cli) -> Result<()> {
    let keys = load_or_create_keys(&cli.keys_dir)?;
    for key in &keys {
        info!(
            algorithm = %key.algorithm(),
            fingerprint = %key.public_key().fingerprint(HashAlg::Sha256),
            "host key"
        );
    }

    let listen = listen_addr(cli.listen, cli.bind, cli.port);
    let advertised = Arc::new(driver::Advertised {
        host: cli.host.unwrap_or_else(local_hostname),
        port: cli.advertised_port.unwrap_or(listen.port()),
    });
    let mode = choose_mode(cli.sandbox, cli.verbose).await?;
    let backend = cli.websocket_host.map(|host| backend::Addr {
        host,
        port: cli.websocket_port,
    });
    let sessions_dir = match &backend {
        Some(addr) => {
            info!(backend = %addr, "sessions are connected to the websocket backend");
            match std::fs::create_dir_all(&cli.sessions_dir) {
                Ok(()) => Some(cli.sessions_dir),
                Err(e) => {
                    warn!(dir = %cli.sessions_dir.display(), error = %e, "cannot create the sessions directory the backend shares; it will not be able to name or resume sessions");
                    None
                }
            }
        }
        None => {
            info!("no websocket backend (-w): random tokens, ssh viewers only");
            None
        }
    };
    let server = gateway::Gateway {
        env: Arc::new(link::Env {
            registry: session::Registry::new(),
            advertised,
            keys_required: cli.authorized_keys_only,
            mode,
            backend,
            sessions_dir,
        }),
        sessions: limits::SessionCounter::new(limits::SessionLimits {
            per_ip: cli.max_sessions_per_ip,
            total: cli.max_sessions,
        }),
        host_rate_limit: cli.host_rate_limit,
    };
    let config = Arc::new(gateway::ssh_config(keys));
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("listening on {listen}"))?;
    info!(
        listen = %listen,
        proxy_protocol = cli.proxy_protocol,
        max_sessions = cli.max_sessions,
        max_sessions_per_ip = cli.max_sessions_per_ip,
        host_rate_limit = cli.host_rate_limit,
        "accepting connections"
    );
    let options = accept::Options {
        proxy_protocol: cli.proxy_protocol,
        grace_period: accept::GRACE_PERIOD,
    };
    accept::serve(server, config, listener, options).await?;
    Ok(())
}

/// The old server advertised `gethostname()` when `-h` was not given.
fn local_hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for its whole length and gethostname
    // writes at most that many bytes.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return "localhost".into();
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    match std::str::from_utf8(&buf[..end]) {
        Ok(name) if !name.is_empty() => name.to_string(),
        _ => "localhost".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn old_short_flags_parse() {
        let cli = Cli::parse_from([
            "tmate-server-rs",
            "-A",
            "-b",
            "127.0.0.1",
            "-p",
            "2222",
            "-H",
            "example.org",
            "-k",
            "/keys",
            "-q",
            "22",
            "-x",
            "-w",
            "ws.internal",
            "-z",
            "4010",
            "-vv",
        ]);
        assert!(cli.authorized_keys_only);
        assert_eq!(cli.websocket_host.as_deref(), Some("ws.internal"));
        assert_eq!(cli.websocket_port, 4010);
        assert_eq!(
            listen_addr(cli.listen, cli.bind, cli.port),
            "127.0.0.1:2222".parse().unwrap()
        );
        assert_eq!(cli.host.as_deref(), Some("example.org"));
        assert_eq!(cli.keys_dir, PathBuf::from("/keys"));
        assert_eq!(cli.advertised_port, Some(22));
        assert!(cli.proxy_protocol);
        assert_eq!(cli.verbose, 2);
    }

    #[test]
    fn bind_and_port_override_listen_parts() {
        let listen: SocketAddr = "0.0.0.0:2200".parse().unwrap();
        assert_eq!(listen_addr(listen, None, None), listen);
        assert_eq!(
            listen_addr(listen, None, Some(22)),
            "0.0.0.0:22".parse().unwrap()
        );
        assert_eq!(
            listen_addr(listen, Some("::1".parse().unwrap()), None),
            "[::1]:2200".parse().unwrap()
        );
        let cli = Cli::parse_from(["x", "--listen", "10.0.0.1:2200", "-p", "2300"]);
        assert_eq!(
            listen_addr(cli.listen, cli.bind, cli.port),
            "10.0.0.1:2300".parse().unwrap()
        );
    }

    #[test]
    fn later_flags_override_earlier_ones() {
        // docker-entrypoint.sh puts its defaults first and the user's args last.
        let cli = Cli::parse_from([
            "x",
            "--host",
            "a",
            "--host",
            "b",
            "--listen",
            "0.0.0.0:1",
            "--listen",
            "0.0.0.0:2",
        ]);
        assert_eq!(cli.host.as_deref(), Some("b"));
        assert_eq!(cli.listen.port(), 2);
    }

    #[test]
    fn verbosity_maps_to_log_levels_unless_rust_log_is_set() {
        assert_eq!(log_filter(0, None), "info,russh=warn");
        assert_eq!(log_filter(1, None), "debug,russh=info");
        assert_eq!(log_filter(2, None), "trace");
        assert_eq!(log_filter(5, Some("")), "trace");
        assert_eq!(log_filter(2, Some("warn")), "warn");
    }

    #[test]
    fn sandbox_and_limit_flags_parse() {
        let cli = Cli::parse_from(["x"]);
        assert_eq!(cli.websocket_host, None);
        assert_eq!(cli.websocket_port, backend::DEFAULT_PORT);
        assert_eq!(cli.sessions_dir, PathBuf::from("/tmp/tmate/sessions"));
        assert_eq!(cli.sandbox, SandboxMode::Auto);
        assert_eq!((cli.max_sessions_per_ip, cli.max_sessions), (10, 1000));
        assert_eq!(cli.host_rate_limit, 2 * 1024 * 1024);
        assert!(!cli.worker);
        let cli = Cli::parse_from([
            "x",
            "--sandbox",
            "require",
            "--max-sessions",
            "5",
            "--max-sessions-per-ip",
            "2",
            "--host-rate-limit",
            "1000",
            "--worker",
        ]);
        assert_eq!(cli.sandbox, SandboxMode::Require);
        assert_eq!((cli.max_sessions_per_ip, cli.max_sessions), (2, 5));
        assert_eq!(cli.host_rate_limit, 1000);
        assert!(cli.worker);
    }

    #[test]
    fn help_mentions_the_old_flags() {
        let help = Cli::command().render_long_help().to_string();
        for flag in ["-A", "-b", "-p", "-H", "-k", "-q", "-x", "-v", "-w", "-z"] {
            assert!(help.contains(flag), "help lacks {flag}:\n{help}");
        }
    }

    #[test]
    fn loads_every_host_key_type_present() {
        let dir = tempfile::tempdir().unwrap();
        for (name, algorithm) in [
            ("ssh_host_ed25519_key", Algorithm::Ed25519),
            ("ssh_host_rsa_key", Algorithm::Rsa { hash: None }),
            (
                "ssh_host_ecdsa_key",
                Algorithm::Ecdsa {
                    curve: russh::keys::EcdsaCurve::NistP256,
                },
            ),
        ] {
            let key = PrivateKey::random(&mut rand::rng(), algorithm).unwrap();
            key.write_openssh_file(dir.path().join(name), russh::keys::ssh_key::LineEnding::LF)
                .unwrap();
        }
        let keys = load_or_create_keys(dir.path()).unwrap();
        assert_eq!(keys.len(), 3);
        assert!(
            keys.iter()
                .any(|k| matches!(k.algorithm(), Algorithm::Ecdsa { .. }))
        );
    }

    #[test]
    fn generates_an_ed25519_key_when_the_directory_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let keys = load_or_create_keys(&dir.path().join("keys")).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].algorithm(), Algorithm::Ed25519);
        assert!(dir.path().join("keys/ssh_host_ed25519_key").exists());
    }
}
