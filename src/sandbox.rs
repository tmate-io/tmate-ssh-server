//! Locking a session worker down before it touches a byte from the host.
//!
//! The old server ran as root and did `chroot` + `unshare(NEWPID|NEWIPC|
//! NEWNS|NEWNET)` + `setuid(nobody)` per connection. This does the same or
//! better without privileges, in this order:
//!
//! 1. close every file descriptor but stderr and the gateway socket;
//! 2. `unshare(CLONE_NEWUSER)` and map ourselves to uid 0 inside it, which
//!    is what lets an unprivileged process do the next two steps;
//! 3. `unshare(NEWPID|NEWNET|NEWIPC|NEWUTS)`: no network at all;
//! 4. `unshare(CLONE_NEWNS)`, mount an empty read-only tmpfs and
//!    `pivot_root` into it: no filesystem at all;
//! 5. Landlock (belt and braces for 3 and 4 where the kernel has it);
//! 6. `PR_SET_NO_NEW_PRIVS`, then drop every capability the user namespace
//!    gave us;
//! 7. rlimits: 256 MiB of address space, 64 fds, no new processes or
//!    threads, 10 CPU-minutes;
//! 8. a seccomp allowlist of the system calls a tokio `current_thread`
//!    runtime reading one socket needs (`ALLOWED_SYSCALLS`); anything
//!    else kills the process.
//!
//! Every step is best effort and reported; `--sandbox require` refuses to
//! run unless the essential ones (2, 4, 6, 8) all worked.

use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SandboxMode {
    /// Worker processes where the platform allows; in-process otherwise.
    Auto,
    /// Everything in one process (how the macOS test-suite runs).
    Off,
    /// Refuse to start unless workers can be fully sandboxed.
    Require,
}

impl SandboxMode {
    pub fn as_str(self) -> &'static str {
        match self {
            SandboxMode::Auto => "auto",
            SandboxMode::Off => "off",
            SandboxMode::Require => "require",
        }
    }
}

#[derive(Debug)]
pub struct Step {
    pub name: &'static str,
    pub essential: bool,
    pub outcome: Result<String, String>,
}

#[derive(Debug, Default)]
pub struct Report {
    pub steps: Vec<Step>,
}

impl Report {
    fn ok(&self, name: &str) -> bool {
        self.steps
            .iter()
            .any(|s| s.name == name && s.outcome.is_ok())
    }

    /// 2: all essential steps worked; 1: at least seccomp or the user
    /// namespace did; 0: no isolation worth the name.
    pub fn level(&self) -> u8 {
        if self
            .steps
            .iter()
            .filter(|s| s.essential)
            .all(|s| s.outcome.is_ok())
            && !self.steps.is_empty()
        {
            2
        } else if self.ok("seccomp") || self.ok("userns") {
            1
        } else {
            0
        }
    }

    /// One line for the gateway's log.
    pub fn summary(&self) -> String {
        self.steps
            .iter()
            .map(|s| match &s.outcome {
                Ok(detail) if detail.is_empty() => format!("{} ok", s.name),
                Ok(detail) => format!("{} ok ({detail})", s.name),
                Err(why) => format!("{} FAILED ({why})", s.name),
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    pub fn log(&self) {
        for s in &self.steps {
            match &s.outcome {
                Ok(detail) => tracing::debug!(step = s.name, %detail, "sandbox step"),
                Err(why) if s.essential => {
                    tracing::warn!(step = s.name, %why, "sandbox step failed")
                }
                Err(why) => tracing::warn!(step = s.name, %why, "optional sandbox step failed"),
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn lockdown(_keep_fd: i32) -> Report {
    Report {
        steps: vec![Step {
            name: "linux",
            essential: true,
            outcome: Err("sandboxing needs Linux (user namespaces, seccomp)".into()),
        }],
    }
}

#[cfg(target_os = "linux")]
pub use linux::lockdown;

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::io::Error;

    use super::{Report, Step};

    /// System calls the worker may make, as a list for the documentation
    /// (`seccomp()` below is the one that counts). Found by running a
    /// worker under `strace -f` on Alpine 3.21 (musl) and from what tokio's
    /// `current_thread` runtime, musl's allocator and Rust's panic path
    /// use. `fcntl` and `ioctl` are restricted by argument.
    #[allow(dead_code)]
    pub const ALLOWED_SYSCALLS: &[&str] = &[
        "read",
        "write",
        "readv",
        "writev",
        "close",
        "epoll_create1",
        "epoll_ctl",
        "epoll_pwait",
        "epoll_pwait2",
        "epoll_wait",
        "eventfd2",
        "futex",
        "mmap",
        "munmap",
        "mprotect",
        "mremap",
        "brk",
        "madvise",
        "clock_gettime",
        "clock_nanosleep",
        "nanosleep",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "sigaltstack",
        "exit",
        "exit_group",
        "getrandom",
        "sched_yield",
        "membarrier",
        "getpid",
        "gettid",
        "tgkill",
        "ppoll",
        "poll",
        "sendto",
        "recvfrom",
        "shutdown",
        "socketpair (AF_UNIX only; tokio's signal driver makes one)",
        "fcntl (F_GETFD, F_SETFD, F_GETFL, F_SETFL, F_DUPFD_CLOEXEC)",
        "ioctl (FIONBIO)",
    ];

    fn errno() -> String {
        Error::last_os_error().to_string()
    }

    fn cstr(s: &str) -> CString {
        CString::new(s).expect("no interior NUL")
    }

    pub fn lockdown(keep_fd: i32) -> Report {
        let mut steps = Vec::new();
        steps.push(Step {
            name: "fds",
            essential: false,
            outcome: close_fds(keep_fd),
        });
        let userns = user_namespace();
        let have_userns = userns.is_ok();
        steps.push(Step {
            name: "userns",
            essential: true,
            outcome: userns,
        });
        if have_userns {
            steps.push(Step {
                name: "namespaces",
                essential: false,
                outcome: other_namespaces(),
            });
            steps.push(Step {
                name: "root",
                essential: true,
                outcome: empty_root(),
            });
        } else {
            for name in ["namespaces", "root"] {
                steps.push(Step {
                    name,
                    essential: name == "root",
                    outcome: Err("skipped: no user namespace".into()),
                });
            }
        }
        steps.push(Step {
            name: "landlock",
            essential: false,
            outcome: landlock(),
        });
        steps.push(Step {
            name: "no_new_privs",
            essential: true,
            outcome: no_new_privs(),
        });
        steps.push(Step {
            name: "caps",
            essential: false,
            outcome: drop_capabilities(),
        });
        steps.push(Step {
            name: "rlimits",
            essential: false,
            outcome: rlimits(),
        });
        steps.push(Step {
            name: "seccomp",
            essential: true,
            outcome: seccomp(),
        });
        Report { steps }
    }

    fn close_fds(keep_fd: i32) -> Result<String, String> {
        // SAFETY: plain syscalls on descriptor numbers.
        unsafe {
            for fd in 3..keep_fd {
                libc::close(fd);
            }
            let first = libc::c_uint::try_from(keep_fd + 1).unwrap_or(4);
            if libc::syscall(libc::SYS_close_range, first, libc::c_uint::MAX, 0) == 0 {
                return Ok(format!("kept 0-2 and {keep_fd}"));
            }
            // Kernels before 5.9: close one by one up to the current limit.
            let mut lim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            let max = if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 {
                lim.rlim_cur.min(65536) as i32
            } else {
                1024
            };
            for fd in keep_fd + 1..max {
                libc::close(fd);
            }
            Ok(format!("kept 0-2 and {keep_fd} (close_range unavailable)"))
        }
    }

    fn write_file(path: &str, contents: &str) -> Result<(), String> {
        std::fs::write(path, contents).map_err(|e| format!("{path}: {e}"))
    }

    fn user_namespace() -> Result<String, String> {
        // SAFETY: getuid/getgid/unshare take no pointers.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
            return Err(format!("unshare(CLONE_NEWUSER): {}", errno()));
        }
        // Older kernels have no setgroups file; denying is then implicit.
        if let Err(e) = write_file("/proc/self/setgroups", "deny")
            && !e.contains("No such file")
        {
            return Err(e);
        }
        write_file("/proc/self/gid_map", &format!("0 {gid} 1\n"))?;
        write_file("/proc/self/uid_map", &format!("0 {uid} 1\n"))?;
        Ok(format!("uid {uid} mapped to 0"))
    }

    fn other_namespaces() -> Result<String, String> {
        let all = libc::CLONE_NEWPID | libc::CLONE_NEWNET | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;
        // SAFETY: no pointers.
        if unsafe { libc::unshare(all) } == 0 {
            return Ok("pid, net, ipc, uts".into());
        }
        let first = errno();
        let mut got = Vec::new();
        let mut failed = Vec::new();
        for (flag, name) in [
            (libc::CLONE_NEWNET, "net"),
            (libc::CLONE_NEWPID, "pid"),
            (libc::CLONE_NEWIPC, "ipc"),
            (libc::CLONE_NEWUTS, "uts"),
        ] {
            if unsafe { libc::unshare(flag) } == 0 {
                got.push(name);
            } else {
                failed.push(name);
            }
        }
        if failed.is_empty() {
            Ok(got.join(", "))
        } else if got.is_empty() {
            Err(format!("unshare: {first}"))
        } else {
            Err(format!(
                "only {}; {} failed: {first}",
                got.join(", "),
                failed.join(", ")
            ))
        }
    }

    /// Directories that are likely to exist to mount the new root on; the
    /// first that works is used (it only has to exist).
    const MOUNT_POINTS: &[&str] = &[
        "/tmp", "/run", "/dev/shm", "/var/tmp", "/mnt", "/opt", "/srv", "/proc",
    ];

    fn empty_root() -> Result<String, String> {
        // SAFETY: the strings are valid C strings for the duration of
        // each call; the syscalls take no other pointers.
        unsafe {
            if libc::unshare(libc::CLONE_NEWNS) != 0 {
                return Err(format!("unshare(CLONE_NEWNS): {}", errno()));
            }
            let root = cstr("/");
            if libc::mount(
                std::ptr::null(),
                root.as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ) != 0
            {
                return Err(format!("making mounts private: {}", errno()));
            }
            let tmpfs = cstr("tmpfs");
            let opts = cstr("size=16k,mode=0555");
            let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_RDONLY;
            let mut mounted = None;
            let mut last_err = String::new();
            for dir in MOUNT_POINTS {
                let target = cstr(dir);
                if libc::mount(
                    tmpfs.as_ptr(),
                    target.as_ptr(),
                    tmpfs.as_ptr(),
                    flags,
                    opts.as_ptr().cast(),
                ) == 0
                {
                    mounted = Some(*dir);
                    break;
                }
                last_err = format!("{dir}: {}", errno());
            }
            let Some(dir) = mounted else {
                return Err(format!("mounting an empty tmpfs: {last_err}"));
            };
            let target = cstr(dir);
            if libc::chdir(target.as_ptr()) != 0 {
                return Err(format!("chdir({dir}): {}", errno()));
            }
            let dot = cstr(".");
            // pivot_root(".", ".") then detaching "." drops the old root
            // without needing a put_old directory (see pivot_root(2)).
            if libc::syscall(libc::SYS_pivot_root, dot.as_ptr(), dot.as_ptr()) == 0 {
                if libc::umount2(dot.as_ptr(), libc::MNT_DETACH) != 0 {
                    return Err(format!("detaching the old root: {}", errno()));
                }
                libc::chdir(root.as_ptr());
                Ok(format!(
                    "pivot_root into an empty read-only tmpfs (was {dir})"
                ))
            } else {
                let why = errno();
                if libc::chroot(dot.as_ptr()) != 0 {
                    return Err(format!("pivot_root: {why}; chroot: {}", errno()));
                }
                libc::chdir(root.as_ptr());
                Ok(format!(
                    "chroot into an empty read-only tmpfs (pivot_root failed: {why})"
                ))
            }
        }
    }

    fn landlock() -> Result<String, String> {
        use landlock::{ABI, Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetStatus};
        // Ask for everything the newest ABI knows; the crate's best-effort
        // mode drops what the running kernel lacks and reports it.
        let abi = ABI::V9;
        let err = |e: landlock::RulesetError| e.to_string();
        let status = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .map_err(err)?
            .handle_access(AccessNet::from_all(abi))
            .map_err(err)?
            .create()
            .map_err(err)?
            .restrict_self()
            .map_err(err)?;
        match status.ruleset {
            RulesetStatus::FullyEnforced => Ok("all filesystem and TCP access denied".into()),
            RulesetStatus::PartiallyEnforced => Ok("partially enforced (older kernel)".into()),
            RulesetStatus::NotEnforced => Err("not enforced (kernel without Landlock?)".into()),
        }
    }

    fn no_new_privs() -> Result<String, String> {
        // SAFETY: prctl with integer arguments.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(errno());
        }
        Ok(String::new())
    }

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    const PR_CAP_AMBIENT: libc::c_int = 47;
    const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;

    fn drop_capabilities() -> Result<String, String> {
        // SAFETY: prctl with integers; capset with pointers to properly
        // laid out structs that outlive the call.
        unsafe {
            let mut dropped = 0;
            for cap in 0..64 {
                if libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) == 0 {
                    dropped += 1;
                } else if *libc::__errno_location() == libc::EINVAL {
                    break;
                }
            }
            libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
            let mut header = CapHeader {
                version: LINUX_CAPABILITY_VERSION_3,
                pid: 0,
            };
            let data = [CapData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            }; 2];
            if libc::syscall(
                libc::SYS_capset,
                &mut header as *mut CapHeader,
                data.as_ptr(),
            ) != 0
            {
                return Err(format!("capset: {}", errno()));
            }
            Ok(format!(
                "bounding set of {dropped} dropped, all sets cleared"
            ))
        }
    }

    pub const RLIMIT_AS_BYTES: u64 = 256 * 1024 * 1024;
    pub const RLIMIT_NOFILE_COUNT: u64 = 64;
    pub const RLIMIT_CPU_SECS: u64 = 600;

    fn rlimits() -> Result<String, String> {
        let set = |res: libc::c_int, cur: u64, max: u64, name: &str| -> Result<(), String> {
            let lim = libc::rlimit {
                rlim_cur: cur as libc::rlim_t,
                rlim_max: max as libc::rlim_t,
            };
            // SAFETY: pointer to a struct that outlives the call.
            if unsafe { libc::setrlimit(res as _, &lim) } != 0 {
                return Err(format!("{name}: {}", errno()));
            }
            Ok(())
        };
        set(
            libc::RLIMIT_AS as _,
            RLIMIT_AS_BYTES,
            RLIMIT_AS_BYTES,
            "RLIMIT_AS",
        )?;
        set(
            libc::RLIMIT_NOFILE as _,
            RLIMIT_NOFILE_COUNT,
            RLIMIT_NOFILE_COUNT,
            "RLIMIT_NOFILE",
        )?;
        set(libc::RLIMIT_NPROC as _, 0, 0, "RLIMIT_NPROC")?;
        set(
            libc::RLIMIT_CPU as _,
            RLIMIT_CPU_SECS,
            RLIMIT_CPU_SECS + 60,
            "RLIMIT_CPU",
        )?;
        set(libc::RLIMIT_CORE as _, 0, 0, "RLIMIT_CORE")?;
        set(libc::RLIMIT_MEMLOCK as _, 0, 0, "RLIMIT_MEMLOCK")?;
        Ok(format!(
            "as {} MiB, nofile {}, nproc 0, cpu {} s",
            RLIMIT_AS_BYTES >> 20,
            RLIMIT_NOFILE_COUNT,
            RLIMIT_CPU_SECS
        ))
    }

    // libc's syscall-number and ioctl types differ between glibc and musl
    // (c_long/c_ulong vs c_int), so the conversions are needed on one and
    // flagged as useless on the other.
    #[allow(clippy::useless_conversion, clippy::unnecessary_cast)]
    fn seccomp() -> Result<String, String> {
        use seccompiler::{
            SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
            SeccompRule,
        };
        let any = Vec::new();
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        let plain: &[libc::c_long] = &[
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_readv,
            libc::SYS_writev,
            libc::SYS_close,
            libc::SYS_epoll_create1,
            libc::SYS_epoll_ctl,
            libc::SYS_epoll_pwait,
            libc::SYS_epoll_pwait2,
            libc::SYS_eventfd2,
            libc::SYS_futex,
            libc::SYS_mmap,
            libc::SYS_munmap,
            libc::SYS_mprotect,
            libc::SYS_mremap,
            libc::SYS_brk,
            libc::SYS_madvise,
            libc::SYS_clock_gettime,
            libc::SYS_clock_nanosleep,
            libc::SYS_nanosleep,
            libc::SYS_rt_sigaction,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            libc::SYS_sigaltstack,
            libc::SYS_exit,
            libc::SYS_exit_group,
            libc::SYS_getrandom,
            libc::SYS_sched_yield,
            libc::SYS_membarrier,
            libc::SYS_getpid,
            libc::SYS_gettid,
            libc::SYS_tgkill,
            libc::SYS_ppoll,
            // mio reads and writes the gateway socket with send/recv,
            // which musl implements as sendto/recvfrom.
            libc::SYS_sendto,
            libc::SYS_recvfrom,
            libc::SYS_shutdown,
            #[cfg(target_arch = "x86_64")]
            libc::SYS_epoll_wait,
            #[cfg(target_arch = "x86_64")]
            libc::SYS_poll,
        ];
        for nr in plain {
            rules.insert(i64::from(*nr), any.clone());
        }
        let arg_eq = |index: u8, value: u64| {
            SeccompCondition::new(index, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, value)
                .map_err(|e| e.to_string())
        };
        let mut fcntl = Vec::new();
        for cmd in [
            libc::F_GETFD,
            libc::F_SETFD,
            libc::F_GETFL,
            libc::F_SETFL,
            libc::F_DUPFD_CLOEXEC,
        ] {
            fcntl.push(SeccompRule::new(vec![arg_eq(1, cmd as u64)?]).map_err(|e| e.to_string())?);
        }
        rules.insert(i64::from(libc::SYS_fcntl), fcntl);
        rules.insert(
            i64::from(libc::SYS_ioctl),
            vec![
                SeccompRule::new(vec![arg_eq(1, libc::FIONBIO as u64)?])
                    .map_err(|e| e.to_string())?,
            ],
        );
        // tokio's runtime makes one AF_UNIX socketpair for its signal
        // driver even though no signal is ever awaited; nothing else.
        rules.insert(
            i64::from(libc::SYS_socketpair),
            vec![
                SeccompRule::new(vec![arg_eq(0, libc::AF_UNIX as u64)?])
                    .map_err(|e| e.to_string())?,
            ],
        );
        // TMATE_SECCOMP_LOG=1 lets a stray call through and logs it (dmesg
        // / audit) instead of killing the worker, for finding out what a
        // new libc or tokio needs. Never set it in production.
        let logging = std::env::var_os("TMATE_SECCOMP_LOG").is_some_and(|v| v == "1");
        let mismatch = if logging {
            SeccompAction::Log
        } else {
            SeccompAction::KillProcess
        };
        let arch: seccompiler::TargetArch = std::env::consts::ARCH
            .try_into()
            .map_err(|e: seccompiler::BackendError| e.to_string())?;
        let count = rules.len();
        let filter = SeccompFilter::new(rules, mismatch, SeccompAction::Allow, arch)
            .map_err(|e| e.to_string())?;
        let program: seccompiler::BpfProgram = filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| e.to_string())?;
        seccompiler::apply_filter(&program).map_err(|e| e.to_string())?;
        Ok(format!(
            "{count} syscalls allowed, others {}",
            if logging {
                "LOGGED (TMATE_SECCOMP_LOG)"
            } else {
                "kill the worker"
            }
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(name: &'static str, essential: bool, ok: bool) -> Step {
        Step {
            name,
            essential,
            outcome: if ok {
                Ok(String::new())
            } else {
                Err("no".into())
            },
        }
    }

    #[test]
    fn levels_follow_the_essential_steps() {
        let full = Report {
            steps: vec![
                step("userns", true, true),
                step("root", true, true),
                step("seccomp", true, true),
                step("landlock", false, false),
            ],
        };
        assert_eq!(full.level(), 2);
        assert!(full.summary().contains("landlock FAILED (no)"));
        let partial = Report {
            steps: vec![
                step("userns", true, false),
                step("root", true, false),
                step("seccomp", true, true),
            ],
        };
        assert_eq!(partial.level(), 1);
        let none = Report {
            steps: vec![step("userns", true, false), step("seccomp", true, false)],
        };
        assert_eq!(none.level(), 0);
        assert_eq!(Report::default().level(), 0);
    }

    #[test]
    fn mode_names_match_the_cli() {
        for m in [SandboxMode::Auto, SandboxMode::Off, SandboxMode::Require] {
            let parsed = <SandboxMode as clap::ValueEnum>::from_str(m.as_str(), false).unwrap();
            assert_eq!(parsed, m);
        }
    }
}
