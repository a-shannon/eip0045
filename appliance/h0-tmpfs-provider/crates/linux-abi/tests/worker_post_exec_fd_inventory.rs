//! Fresh-process matrix for the exact Worker post-exec fd3 inventory.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
mod selected_target {
    use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
    use rustix::fs::{CWD, Dir, Mode, OFlags, PROC_SUPER_MAGIC, fstatfs, openat};
    use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
    use rustix::net::sockopt::{set_socket_passcred, socket_passcred};
    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};
    use std::ffi::{CString, c_char};
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::process::{Child, Command, ExitStatus};
    use std::time::{Duration, Instant};

    const STAGE_ENV_V1: &str = "EIP0045_G0B3_WORKER_INVENTORY_STANDALONE_STAGE_V1";
    const SCENARIO_ENV_V1: &str = "EIP0045_G0B3_WORKER_INVENTORY_STANDALONE_SCENARIO_V1";
    const ORCHESTRATOR_STAGE_V1: &str = "orchestrator";
    const CLOSER_STAGE_V1: &str = "closer";
    const OK_PREFIX_V1: &str = "G0B3_WORKER_INVENTORY_STANDALONE_OK=";
    const WORKER_ENDPOINT_FD_V1: i32 = 3;
    const SCENARIOS_V1: [&str; 5] = [
        "exact-fd3",
        "fd0-surplus",
        "fd4-surplus",
        "fd4-alias",
        "retry-after-surplus",
    ];

    unsafe extern "C" {
        #[link_name = "execve"]
        fn c_execve(
            path: *const c_char,
            arguments: *const *const c_char,
            environment: *const *const c_char,
        ) -> i32;
        #[link_name = "_exit"]
        fn c_exit(status: i32) -> !;
    }

    fn clear_close_on_exec_v1(descriptor: BorrowedFd<'_>) {
        let mut flags = fcntl_getfd(descriptor).unwrap();
        flags.remove(FdFlags::CLOEXEC);
        fcntl_setfd(descriptor, flags).unwrap();
        assert!(!fcntl_getfd(descriptor).unwrap().contains(FdFlags::CLOEXEC));
    }

    fn worker_endpoint_v1() -> OwnedFd {
        let (worker, peer) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        assert_eq!(worker.as_raw_fd(), WORKER_ENDPOINT_FD_V1);
        set_socket_passcred(&worker, true).unwrap();
        set_socket_passcred(&peer, true).unwrap();
        assert!(socket_passcred(&worker).unwrap());
        assert!(socket_passcred(&peer).unwrap());
        drop(peer);
        clear_close_on_exec_v1(worker.as_fd());
        worker
    }

    fn expected_surplus_v1(scenario: &str) -> Option<i32> {
        match scenario {
            "exact-fd3" => None,
            "fd0-surplus" => Some(0),
            "fd4-surplus" | "fd4-alias" | "retry-after-surplus" => Some(4),
            _ => panic!("unknown Worker inventory scenario"),
        }
    }

    fn preserves_descriptor_v1(scenario: &str, descriptor: i32) -> bool {
        descriptor == WORKER_ENDPOINT_FD_V1 || expected_surplus_v1(scenario) == Some(descriptor)
    }

    fn surplus_descriptor_v1(scenario: &str, worker: BorrowedFd<'_>) -> Option<OwnedFd> {
        match scenario {
            "exact-fd3" | "fd0-surplus" => None,
            "fd4-surplus" => {
                let surplus: OwnedFd = File::open("/dev/null").unwrap().into();
                assert_eq!(surplus.as_raw_fd(), 4);
                clear_close_on_exec_v1(surplus.as_fd());
                Some(surplus)
            }
            "fd4-alias" | "retry-after-surplus" => {
                let alias = rustix::io::dup(worker).unwrap();
                assert_eq!(alias.as_raw_fd(), 4);
                assert!(
                    !fcntl_getfd(alias.as_fd())
                        .unwrap()
                        .contains(FdFlags::CLOEXEC)
                );
                Some(alias)
            }
            _ => panic!("unknown Worker inventory scenario"),
        }
    }

    fn parse_canonical_descriptor_v1(name: &[u8]) -> i32 {
        assert!(!name.is_empty());
        assert!(name.len() == 1 || name[0] != b'0');
        let mut descriptor = 0_i32;
        for byte in name {
            assert!(byte.is_ascii_digit());
            descriptor = descriptor
                .checked_mul(10)
                .and_then(|value| value.checked_add(i32::from(*byte - b'0')))
                .unwrap();
        }
        descriptor
    }

    fn open_authenticated_fd_directory_v1() -> Dir {
        let descriptor = openat(
            CWD,
            c"/proc/self/fd",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        assert_eq!(
            fstatfs(descriptor.as_fd()).unwrap().f_type,
            PROC_SUPER_MAGIC
        );
        Dir::new(descriptor).unwrap()
    }

    fn prepare_closer_v1(scenario: &str) -> (Dir, [i32; 64], usize) {
        let mut directory = open_authenticated_fd_directory_v1();
        let enumeration_descriptor = directory.fd().unwrap().as_raw_fd();
        let mut descriptors_to_close = [0_i32; 64];
        let mut close_count = 0_usize;
        let mut worker_count = 0_u8;
        let mut surplus_count = 0_u8;
        while let Some(entry) = directory.read() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let observed = parse_canonical_descriptor_v1(name);
            if observed == enumeration_descriptor {
                continue;
            }
            if observed == WORKER_ENDPOINT_FD_V1 {
                worker_count += 1;
                continue;
            }
            if expected_surplus_v1(scenario) == Some(observed) {
                surplus_count += 1;
                continue;
            }
            assert!(close_count < descriptors_to_close.len());
            descriptors_to_close[close_count] = observed;
            close_count += 1;
        }
        assert_eq!(worker_count, 1);
        assert_eq!(
            surplus_count,
            u8::from(expected_surplus_v1(scenario).is_some())
        );
        (directory, descriptors_to_close, close_count)
    }

    fn require_expected_inventory_v1(scenario: &str) {
        let mut directory = open_authenticated_fd_directory_v1();
        let enumeration_descriptor = directory.fd().unwrap().as_raw_fd();
        let mut numeric_count = 0_u8;
        let mut worker_count = 0_u8;
        let mut surplus_count = 0_u8;
        while let Some(entry) = directory.read() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let observed = parse_canonical_descriptor_v1(name);
            numeric_count += 1;
            if observed == enumeration_descriptor {
                continue;
            }
            if observed == WORKER_ENDPOINT_FD_V1 {
                worker_count += 1;
                continue;
            }
            if expected_surplus_v1(scenario) == Some(observed) {
                surplus_count += 1;
                continue;
            }
            panic!("unexpected post-close descriptor {observed}");
        }
        assert_eq!(
            numeric_count,
            2 + u8::from(expected_surplus_v1(scenario).is_some())
        );
        assert_eq!(worker_count, 1);
        assert_eq!(
            surplus_count,
            u8::from(expected_surplus_v1(scenario).is_some())
        );
        drop(directory);
    }

    fn closer_exec_v1(scenario: &str) -> ! {
        let executable =
            std::path::Path::new(env!("CARGO_BIN_EXE_worker-post-exec-fd-inventory-leaf"));
        let executable_path = CString::new(executable.as_os_str().as_bytes()).unwrap();
        let arguments = [
            CString::new(executable.as_os_str().as_bytes()).unwrap(),
            CString::new(scenario).unwrap(),
        ];
        let argument_pointers = [
            arguments[0].as_ptr(),
            arguments[1].as_ptr(),
            std::ptr::null(),
        ];
        let environment_pointers = [std::ptr::null::<c_char>()];
        let (directory, descriptors_to_close, close_count) = prepare_closer_v1(scenario);

        // SAFETY: the authenticated enumeration owns its exact directory fd,
        // proves fd3 and the optional negative surplus, and records every
        // other live fd once. The C strings and pointer arrays remain alive
        // through execve. _exit avoids stale Rust owners on any failure.
        unsafe {
            for descriptor in &descriptors_to_close[..close_count] {
                rustix::io::close(*descriptor);
            }
            drop(directory);
            for descriptor in [0, 3, 4] {
                if preserves_descriptor_v1(scenario, descriptor) {
                    let borrowed = BorrowedFd::borrow_raw(descriptor);
                    let Ok(mut flags) = fcntl_getfd(borrowed) else {
                        c_exit(120);
                    };
                    flags.remove(FdFlags::CLOEXEC);
                    if fcntl_setfd(borrowed, flags).is_err()
                        || fcntl_getfd(borrowed).map(|restored| restored.contains(FdFlags::CLOEXEC))
                            != Ok(false)
                    {
                        c_exit(121);
                    }
                }
            }
            require_expected_inventory_v1(scenario);
            let _ = c_execve(
                executable_path.as_ptr(),
                argument_pointers.as_ptr(),
                environment_pointers.as_ptr(),
            );
            c_exit(127);
        }
    }

    fn wait_for_leaf_v1(child: &mut Child) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                let status = child.wait().unwrap();
                panic!("Worker inventory leaf timed out with {status}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn orchestrator_v1(scenario: &str) {
        let worker = worker_endpoint_v1();
        let surplus = surplus_descriptor_v1(scenario, worker.as_fd());
        let mut child = Command::new(std::env::current_exe().unwrap())
            .env(STAGE_ENV_V1, CLOSER_STAGE_V1)
            .env(SCENARIO_ENV_V1, scenario)
            .spawn()
            .unwrap();
        drop(surplus);
        drop(worker);
        let status = wait_for_leaf_v1(&mut child);
        assert_eq!(
            status.code(),
            Some(42),
            "Worker inventory leaf {scenario} failed with {status}"
        );
        eprintln!("{OK_PREFIX_V1}{scenario}");
    }

    pub(super) fn main_v1() {
        let scenario = std::env::var(SCENARIO_ENV_V1);
        match std::env::var(STAGE_ENV_V1) {
            Ok(stage) if stage == ORCHESTRATOR_STAGE_V1 => {
                orchestrator_v1(&scenario.unwrap());
                return;
            }
            Ok(stage) if stage == CLOSER_STAGE_V1 => closer_exec_v1(&scenario.unwrap()),
            Ok(stage) => panic!("unknown Worker inventory stage: {stage}"),
            Err(std::env::VarError::NotPresent) => {}
            Err(error) => panic!("Worker inventory stage is not Unicode: {error}"),
        }

        assert_eq!(SCENARIOS_V1.len(), 5);
        let executable = std::env::current_exe().unwrap();
        for scenario in SCENARIOS_V1 {
            let output = Command::new("/usr/bin/timeout")
                .arg("--signal=KILL")
                .arg("20s")
                .arg(&executable)
                .env(STAGE_ENV_V1, ORCHESTRATOR_STAGE_V1)
                .env(SCENARIO_ENV_V1, scenario)
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let marker = format!("{OK_PREFIX_V1}{scenario}");
            assert!(
                output.status.success() && stderr.contains(&marker),
                "Worker inventory scenario {scenario} failed:\nstdout={stdout}\nstderr={stderr}"
            );
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
fn main() {
    selected_target::main_v1();
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux", target_env = "musl")))]
fn main() {}
