//! Runtime-only Worker fd3 inventory leaf without the Rust `std::rt` entry.

#![cfg_attr(
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl"),
    no_main
)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
mod selected_target {
    use eip0045_h0_linux_abi::ancillary::try_adopt_worker_exec_inherited_fd3_once_v1;
    use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
    use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
    use rustix::net::sockopt::{set_socket_passcred, socket_passcred};
    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};
    use std::ffi::{CStr, c_char};
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd};

    const F_GETFD_V1: i32 = 1;
    const WORKER_ENDPOINT_FD_V1: i32 = 3;

    unsafe extern "C" {
        #[link_name = "fcntl"]
        fn c_fcntl(descriptor: i32, command: i32, ...) -> i32;
    }

    fn clear_close_on_exec_v1(descriptor: BorrowedFd<'_>) -> Result<(), ()> {
        let mut flags = fcntl_getfd(descriptor).map_err(|_| ())?;
        flags.remove(FdFlags::CLOEXEC);
        fcntl_setfd(descriptor, flags).map_err(|_| ())?;
        if fcntl_getfd(descriptor)
            .map_err(|_| ())?
            .contains(FdFlags::CLOEXEC)
        {
            return Err(());
        }
        Ok(())
    }

    fn worker_endpoint_v1() -> Result<OwnedFd, ()> {
        let (worker, peer) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|_| ())?;
        if worker.as_raw_fd() != WORKER_ENDPOINT_FD_V1 {
            return Err(());
        }
        set_socket_passcred(&worker, true).map_err(|_| ())?;
        set_socket_passcred(&peer, true).map_err(|_| ())?;
        if !socket_passcred(&worker).map_err(|_| ())? || !socket_passcred(&peer).map_err(|_| ())? {
            return Err(());
        }
        drop(peer);
        clear_close_on_exec_v1(worker.as_fd())?;
        Ok(worker)
    }

    fn descriptor_is_closed_v1(descriptor: i32) -> bool {
        std::fs::read_link(format!("/proc/self/fd/{descriptor}")).is_err()
    }

    fn retry_after_surplus_v1(first_adoption_succeeded: bool) -> i32 {
        if first_adoption_succeeded {
            return 52;
        }
        if !descriptor_is_closed_v1(WORKER_ENDPOINT_FD_V1) {
            return 55;
        }
        let Ok(stdin) = File::open("/dev/null") else {
            return 56;
        };
        let Ok(stdout) = File::open("/dev/null") else {
            return 56;
        };
        let Ok(stderr) = File::open("/dev/null") else {
            return 56;
        };
        if [stdin.as_raw_fd(), stdout.as_raw_fd(), stderr.as_raw_fd()] != [0, 1, 2] {
            return 57;
        }
        let Ok(repeated) = worker_endpoint_v1() else {
            return 58;
        };
        if try_adopt_worker_exec_inherited_fd3_once_v1(repeated).is_ok() {
            return 53;
        }
        if !descriptor_is_closed_v1(WORKER_ENDPOINT_FD_V1) {
            return 59;
        }
        42
    }

    pub(super) fn main_v1(argument_count: i32, arguments: *mut *mut c_char) -> i32 {
        // SAFETY: F_GETFD validates the raw descriptor without opening one.
        // The authenticated closer makes the check-to-ownership interval
        // single-threaded and transfers the unique, non-CLOEXEC Worker fd3.
        let inherited = unsafe {
            if c_fcntl(WORKER_ENDPOINT_FD_V1, F_GETFD_V1) < 0 {
                return 60;
            }
            OwnedFd::from_raw_fd(WORKER_ENDPOINT_FD_V1)
        };
        let first_adoption = try_adopt_worker_exec_inherited_fd3_once_v1(inherited);

        // SAFETY: musl supplies argv for the C entry. It is read only after
        // the one-shot adoption has consumed fd3 and reached its verdict.
        let scenario = unsafe {
            if argument_count != 2 || arguments.is_null() {
                return 54;
            }
            let scenario = *arguments.add(1);
            if scenario.is_null() {
                return 54;
            }
            CStr::from_ptr(scenario).to_bytes()
        };

        match scenario {
            b"exact-fd3" => {
                if first_adoption.is_ok() {
                    42
                } else {
                    50
                }
            }
            b"fd0-surplus" | b"fd4-surplus" | b"fd4-alias" => {
                if first_adoption.is_ok() {
                    51
                } else if descriptor_is_closed_v1(WORKER_ENDPOINT_FD_V1) {
                    42
                } else {
                    55
                }
            }
            b"retry-after-surplus" => retry_after_surplus_v1(first_adoption.is_ok()),
            _ => 54,
        }
    }
}

/// C ABI entry used only by the selected-target runtime fixture.
#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
// SAFETY: this selected-target binary defines the sole global C `main` symbol.
#[unsafe(export_name = "main")]
pub extern "C" fn fixture_main(
    argument_count: i32,
    arguments: *mut *mut core::ffi::c_char,
    _environment: *mut *mut core::ffi::c_char,
) -> i32 {
    selected_target::main_v1(argument_count, arguments)
}

/// Non-selected targets are inventory-only and cannot run this fixture.
#[cfg(not(all(target_arch = "x86_64", target_os = "linux", target_env = "musl")))]
fn main() {}
