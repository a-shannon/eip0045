//! Diagnostic, non-authorizing xattr observation for the selected WSL host ABI.
//!
//! This boundary is specific to x86-64 Linux and the reviewed WSL kernel
//! source. Its result is one input to a larger retained-rootfs policy; it
//! does not establish kernel identity, LSM completeness, or B4 admission.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
compile_error!("the trusted-host WSL xattr ABI requires x86_64 Linux");

use std::ffi::{c_int, c_long, CStr};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

const GETXATTRAT: c_long = 464;
const LISTXATTRAT: c_long = 465;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
const ENODATA: i32 = 61;
const SELINUX_NAME: &CStr = c"security.selinux";

#[repr(C)]
struct XattrArgs {
    value: u64,
    size: u32,
    flags: u32,
}

const _: [(); 16] = [(); std::mem::size_of::<XattrArgs>()];

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
}

/// A diagnostic failure, never an authorization decision.
#[derive(Debug)]
pub enum Error {
    /// The supplied name is not one basename of a retained directory entry.
    InvalidBasename,
    /// The no-follow list operation returned at least one visible xattr name.
    ListedXattrs(c_long),
    /// A direct no-follow lookup found `security.selinux`, even if listing hid it.
    SelinuxXattrPresent(c_long),
    /// A syscall failed or returned an unexpected status; observation failed closed.
    Syscall {
        /// The syscall whose observation failed.
        operation: &'static str,
        /// The operating-system error returned by that syscall.
        source: io::Error,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBasename => formatter.write_str("invalid retained-entry basename"),
            Self::ListedXattrs(size) => write!(formatter, "listed xattrs occupy {size} bytes"),
            Self::SelinuxXattrPresent(size) => {
                write!(formatter, "security.selinux exists with {size} value bytes")
            }
            Self::Syscall { operation, source } => write!(formatter, "{operation}: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syscall { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Check two observed xattr conditions on a retained entry, without following
/// its final symlink. Success is diagnostic only; it grants no B4 authority.
///
/// The caller must retain `parent` and must separately establish the directory
/// and entry identity, complete LSM-name coverage, and all other TH/F0 policy
/// predicates. A zero-length `security.selinux` value is still treated as present.
pub fn check_leaf_xattr_absence_diagnostic(
    parent: BorrowedFd<'_>,
    basename: &CStr,
) -> Result<(), Error> {
    let bytes = basename.to_bytes();
    if bytes.is_empty()
        || bytes.len() > 255
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
    {
        return Err(Error::InvalidBasename);
    }

    // SAFETY: `parent` remains borrowed, `basename` is NUL-terminated, and a
    // null output pointer with zero size asks only for the required byte count.
    let listed = unsafe {
        syscall(
            LISTXATTRAT,
            c_int::from(parent.as_raw_fd()),
            basename.as_ptr(),
            AT_SYMLINK_NOFOLLOW,
            std::ptr::null_mut::<u8>(),
            0_usize,
        )
    };
    if listed < 0 {
        return Err(Error::Syscall {
            operation: "listxattrat",
            source: io::Error::last_os_error(),
        });
    }
    if listed != 0 {
        return Err(Error::ListedXattrs(listed));
    }

    let mut args = XattrArgs {
        value: 0,
        size: 0,
        flags: 0,
    };
    // SAFETY: `parent` and both C strings remain borrowed for this call. The
    // kernel receives the exact 16-byte UAPI argument structure, with no output
    // value buffer, so only the existence/required size is queried.
    let found = unsafe {
        syscall(
            GETXATTRAT,
            c_int::from(parent.as_raw_fd()),
            basename.as_ptr(),
            AT_SYMLINK_NOFOLLOW,
            SELINUX_NAME.as_ptr(),
            &mut args as *mut XattrArgs,
            std::mem::size_of::<XattrArgs>(),
        )
    };
    if found >= 0 {
        return Err(Error::SelinuxXattrPresent(found));
    }
    let source = io::Error::last_os_error();
    if source.raw_os_error() == Some(ENODATA) {
        Ok(())
    } else {
        Err(Error::Syscall {
            operation: "getxattrat(security.selinux)",
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    unsafe extern "C" {
        fn setxattr(
            path: *const i8,
            name: *const i8,
            value: *const u8,
            size: usize,
            flags: c_int,
        ) -> c_int;
        fn mount(
            source: *const i8,
            target: *const i8,
            filesystem_type: *const i8,
            flags: usize,
            data: *const i8,
        ) -> c_int;
        fn umount2(target: *const i8, flags: c_int) -> c_int;
    }

    fn fd_mount_id(file: &std::fs::File) -> u64 {
        let fdinfo = fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))
            .expect("retained descriptor has readable fdinfo");
        fdinfo
            .lines()
            .find_map(|line| line.strip_prefix("mnt_id:\t"))
            .expect("retained descriptor has a mount ID")
            .parse()
            .expect("mount ID is numeric")
    }

    #[test]
    fn private_tmpfs_catches_hidden_selinux_label_and_preserves_no_follow() {
        let root = std::env::var_os("EIP0045_TH_TEST_ROOT")
            .expect("test requires an explicit fresh private tmpfs root");
        let root = Path::new(&root);
        let parent = OpenOptions::new().read(true).open(root).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("leaf"))
            .unwrap();
        symlink("leaf", root.join("link")).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("listed"))
            .unwrap();
        symlink("listed", root.join("listed-link")).unwrap();

        assert!(check_leaf_xattr_absence_diagnostic(parent.as_fd(), c"leaf").is_ok());
        assert!(check_leaf_xattr_absence_diagnostic(parent.as_fd(), c"link").is_ok());
        for bad in [c"", c".", c"..", c"leaf/link"] {
            assert!(matches!(
                check_leaf_xattr_absence_diagnostic(parent.as_fd(), bad),
                Err(Error::InvalidBasename)
            ));
        }

        let path = fs::canonicalize(root.join("leaf")).unwrap();
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let sentinel = b"eip0045-th-hidden-label";
        // SAFETY: path, name, and sentinel remain valid for the duration of
        // the direct test-only setter call. The private tmpfs is discarded.
        let status = unsafe {
            setxattr(
                path.as_ptr(),
                SELINUX_NAME.as_ptr(),
                sentinel.as_ptr(),
                sentinel.len(),
                0,
            )
        };
        assert_eq!(status, 0, "setxattr: {}", io::Error::last_os_error());

        // On this selected WSL host, listing hides security.selinux. The
        // direct lookup must still reject the file and leave the symlink clean.
        assert!(matches!(
            check_leaf_xattr_absence_diagnostic(parent.as_fd(), c"leaf"),
            Err(Error::SelinuxXattrPresent(_))
        ));
        assert!(check_leaf_xattr_absence_diagnostic(parent.as_fd(), c"link").is_ok());

        let visible_path = fs::canonicalize(root.join("listed")).unwrap();
        let visible_path = std::ffi::CString::new(visible_path.as_os_str().as_bytes()).unwrap();
        let visible_name = c"user.eip0045-th-test";
        // SAFETY: all pointers remain valid during this test-only setter call.
        let status = unsafe {
            setxattr(
                visible_path.as_ptr(),
                visible_name.as_ptr(),
                sentinel.as_ptr(),
                sentinel.len(),
                0,
            )
        };
        assert_eq!(status, 0, "setxattr: {}", io::Error::last_os_error());
        assert!(matches!(
            check_leaf_xattr_absence_diagnostic(parent.as_fd(), c"listed"),
            Err(Error::ListedXattrs(_))
        ));
        assert!(check_leaf_xattr_absence_diagnostic(parent.as_fd(), c"listed-link").is_ok());
    }

    #[test]
    fn nested_private_mount_rejects_hidden_label_and_still_cleans_up() {
        let root = std::env::var_os("EIP0045_TH_TEST_ROOT")
            .expect("test requires an explicit fresh private tmpfs root");
        let root = Path::new(&root);
        let parent = OpenOptions::new().read(true).open(root).unwrap();
        let mountpoint = root.join("nested-mount");
        fs::create_dir(&mountpoint).unwrap();
        let mountpoint_c = std::ffi::CString::new(mountpoint.as_os_str().as_bytes()).unwrap();

        // SAFETY: all C strings remain alive during this test-only mount call.
        // The launcher creates a fresh private mount namespace first.
        let status = unsafe {
            mount(
                c"tmpfs".as_ptr(),
                mountpoint_c.as_ptr(),
                c"tmpfs".as_ptr(),
                0x2 | 0x4 | 0x8,
                c"size=4m".as_ptr(),
            )
        };
        assert_eq!(status, 0, "mount: {}", io::Error::last_os_error());
        let mounted = OpenOptions::new().read(true).open(&mountpoint).unwrap();
        let parent_mount = fd_mount_id(&parent);
        let child_mount = fd_mount_id(&mounted);
        assert_ne!(child_mount, parent_mount, "fresh tmpfs must have a distinct mount ID");

        let leaf_path = mountpoint.join("leaf");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&leaf_path)
            .unwrap();
        assert!(check_leaf_xattr_absence_diagnostic(mounted.as_fd(), c"leaf").is_ok());
        let leaf_path_c = std::ffi::CString::new(leaf_path.as_os_str().as_bytes()).unwrap();
        let sentinel = b"eip0045-th-nested-hidden-label";
        // SAFETY: test-only path, name, and value pointers remain valid.
        let status = unsafe {
            setxattr(
                leaf_path_c.as_ptr(),
                SELINUX_NAME.as_ptr(),
                sentinel.as_ptr(),
                sentinel.len(),
                0,
            )
        };
        assert_eq!(status, 0, "setxattr: {}", io::Error::last_os_error());
        assert!(matches!(
            check_leaf_xattr_absence_diagnostic(mounted.as_fd(), c"leaf"),
            Err(Error::SelinuxXattrPresent(_))
        ));

        fs::remove_file(&leaf_path).expect("diagnostic rejection must not block leaf cleanup");
        drop(mounted);
        // SAFETY: the mountpoint C string is retained; zero flags require an
        // ordinary unmount, so a busy mount fails instead of detaching lazily.
        let status = unsafe { umount2(mountpoint_c.as_ptr(), 0) };
        assert_eq!(status, 0, "umount2: {}", io::Error::last_os_error());
        fs::remove_dir(&mountpoint).expect("private mountpoint cleanup must succeed");
        assert!(!mountpoint.exists());
    }
}
