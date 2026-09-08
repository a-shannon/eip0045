//! Pure validation for the guest build's path-sensitive environment contract.

use std::ffi::OsStr;

pub(crate) const REQUIRED_HOME: &str = "/home/ergo/eip0045";
pub(crate) const REQUIRED_CARGO_HOME: &str = "/home/ergo/eip0045/.cargo";
pub(crate) const REQUIRED_CARGO_TARGET_DIR: &str = "/target";
pub(crate) const REQUIRED_CARGO_MANIFEST_DIR: &str = "/workspace/methods";
pub(crate) const REQUIRED_CARGO_CONFIG_PATH: &str = "/home/ergo/eip0045/.cargo/config.toml";
pub(crate) const REQUIRED_CARGO_CONFIG: &[u8] =
    include_bytes!("../reproduction/cargo-offline-config.toml");

pub(crate) fn validate_home(actual: Option<&OsStr>) -> Result<(), String> {
    validate_exact_path("HOME", actual, REQUIRED_HOME)
}

pub(crate) fn validate_cargo_home(actual: Option<&OsStr>) -> Result<(), String> {
    validate_exact_path("CARGO_HOME", actual, REQUIRED_CARGO_HOME)
}

pub(crate) fn validate_cargo_target_dir(actual: Option<&OsStr>) -> Result<(), String> {
    validate_exact_path("CARGO_TARGET_DIR", actual, REQUIRED_CARGO_TARGET_DIR)
}

pub(crate) fn validate_cargo_manifest_dir(actual: Option<&OsStr>) -> Result<(), String> {
    validate_exact_path("CARGO_MANIFEST_DIR", actual, REQUIRED_CARGO_MANIFEST_DIR)
}

pub(crate) fn validate_cargo_config(actual: &[u8]) -> Result<(), String> {
    if actual == REQUIRED_CARGO_CONFIG {
        Ok(())
    } else {
        Err(format!(
            "host guest-build requires {REQUIRED_CARGO_CONFIG_PATH} to equal the pinned reproduction Cargo config byte-for-byte"
        ))
    }
}

fn validate_exact_path(name: &str, actual: Option<&OsStr>, required: &str) -> Result<(), String> {
    match actual {
        Some(value) if value == OsStr::new(required) => Ok(()),
        Some(value) => Err(format!(
            "host guest-build requires exact {name}={required}, got {}",
            std::path::Path::new(value).display()
        )),
        None => Err(format!(
            "host guest-build requires exact {name}={required}, but {name} is unset"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_family = "unix")]
    use std::{
        path::{Path, PathBuf},
        process::{Command, Output},
        time::{SystemTime, UNIX_EPOCH},
    };

    #[cfg(target_family = "unix")]
    struct PhysicalPathFixture {
        root: PathBuf,
    }

    #[cfg(target_family = "unix")]
    impl PhysicalPathFixture {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock must follow the Unix epoch")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "eip0045-physical-path-{label}-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&root).expect("create physical-path fixture root");
            Self { root }
        }
    }

    #[cfg(target_family = "unix")]
    impl Drop for PhysicalPathFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[cfg(target_family = "unix")]
    fn run_production_physical_path_predicate(
        kind: &str,
        label: &str,
        path: &Path,
        expected_path: &Path,
    ) -> Output {
        const BEGIN: &str = "# BEGIN EIP0045 PHYSICAL PATH PREDICATE";
        const END: &str = "# END EIP0045 PHYSICAL PATH PREDICATE";

        let builder = include_str!("../reproduction/b4-build/container-build.sh");
        let start = builder
            .find(BEGIN)
            .expect("production physical-path predicate begin marker");
        let end = builder[start..]
            .find(END)
            .map(|offset| start + offset + END.len())
            .expect("production physical-path predicate end marker");
        let predicate = &builder[start..end];
        let harness = format!(
            "set -Eeuo pipefail\n\
             die() {{ printf '%s\\n' \"$*\" >&2; exit 97; }}\n\
             {predicate}\n\
             require_exact_physical_path \"$1\" \"$2\" \"$3\" \"$4\"\n"
        );

        Command::new("bash")
            .args(["-c", &harness, "physical-path-fixture", kind, label])
            .arg(path)
            .arg(expected_path)
            .output()
            .expect("run exact production physical-path predicate")
    }

    #[test]
    fn accepts_exact_path_and_config_contract() {
        assert!(validate_home(Some(OsStr::new(REQUIRED_HOME))).is_ok());
        assert!(validate_cargo_home(Some(OsStr::new(REQUIRED_CARGO_HOME))).is_ok());
        assert!(validate_cargo_target_dir(Some(OsStr::new(REQUIRED_CARGO_TARGET_DIR))).is_ok());
        assert!(validate_cargo_manifest_dir(Some(OsStr::new(REQUIRED_CARGO_MANIFEST_DIR))).is_ok());
        assert!(validate_cargo_config(REQUIRED_CARGO_CONFIG).is_ok());
    }

    #[test]
    fn rejects_home_path_drift() {
        assert!(validate_home(Some(OsStr::new("/opt/eip0045-build"))).is_err());
        let superseded_home = ["/home", "eip0045"].join("/");
        assert!(validate_home(Some(OsStr::new(&superseded_home))).is_err());
        assert!(validate_home(Some(OsStr::new("/root"))).is_err());
        assert!(validate_home(None).is_err());
    }

    #[test]
    fn rejects_cargo_home_path_drift() {
        assert!(validate_cargo_home(Some(OsStr::new("/opt/eip0045-build/.cargo"))).is_err());
        let superseded_cargo_home = ["/home", "eip0045", ".cargo"].join("/");
        assert!(validate_cargo_home(Some(OsStr::new(&superseded_cargo_home))).is_err());
        assert!(validate_cargo_home(Some(OsStr::new("/root/.cargo"))).is_err());
        assert!(validate_cargo_home(None).is_err());
    }

    #[test]
    fn rejects_cargo_target_dir_path_drift() {
        assert!(validate_cargo_target_dir(Some(OsStr::new("/target"))).is_ok());
        assert!(validate_cargo_target_dir(Some(OsStr::new("/target-e3-provider"))).is_err());
        assert!(validate_cargo_target_dir(Some(OsStr::new("/home/ergo/eip0045/target"))).is_err());
        assert!(validate_cargo_target_dir(None).is_err());
    }

    #[test]
    fn rejects_cargo_manifest_dir_path_drift() {
        assert!(validate_cargo_manifest_dir(Some(OsStr::new("/workspace/methods"))).is_ok());
        assert!(
            validate_cargo_manifest_dir(Some(OsStr::new("/home/ergo/eip0045/methods"))).is_err()
        );
        assert!(validate_cargo_manifest_dir(Some(OsStr::new("/source/methods"))).is_err());
        assert!(validate_cargo_manifest_dir(None).is_err());
    }

    #[test]
    fn rejects_changed_or_extended_cargo_config() {
        let mut changed = REQUIRED_CARGO_CONFIG.to_vec();
        changed[0] ^= 1;
        assert!(validate_cargo_config(&changed).is_err());

        let mut extended = REQUIRED_CARGO_CONFIG.to_vec();
        extended.push(b'\n');
        assert!(validate_cargo_config(&extended).is_err());
    }

    #[test]
    fn guest_manifest_declares_two_unconditional_named_bins() {
        let manifest = include_str!("guest/Cargo.toml");

        assert!(manifest.contains("autobins = false"));
        assert_eq!(manifest.matches("[[bin]]").count(), 2);
        assert!(manifest.contains("name = \"eip-0045-guest\"\npath = \"src/main.rs\""));
        assert!(manifest.contains(
            "name = \"eip-0045-alternate-program-guest\"\npath = \"src/bin/eip-0045-alternate-program-guest.rs\""
        ));
        assert!(!manifest.contains("required-features"));
    }

    #[test]
    fn guest_metadata_exposes_exactly_the_two_named_bins() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("guest/Cargo.toml");
        let output = std::process::Command::new(env!("CARGO"))
            .args([
                "metadata",
                "--manifest-path",
                manifest.to_str().unwrap(),
                "--no-deps",
                "--format-version",
                "1",
                "--offline",
            ])
            .output()
            .expect("run cargo metadata for guest manifest");
        assert!(
            output.status.success(),
            "guest cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let metadata = String::from_utf8(output.stdout).unwrap();
        assert_eq!(metadata.matches("\"kind\":[\"bin\"]").count(), 2);
        assert!(metadata.contains("\"name\":\"eip-0045-guest\""));
        assert!(metadata.contains("\"name\":\"eip-0045-alternate-program-guest\""));
    }

    #[test]
    fn alternate_guest_is_plain_only_and_has_no_external_selector() {
        let source = include_str!("guest/src/bin/eip-0045-alternate-program-guest.rs");

        assert!(source.contains("GuestInputHeader::decode"));
        assert!(source.contains("header.mode() != GuestMode::Plain"));
        assert!(source.contains("require_workload(header)"));
        assert!(source.contains("env::commit_slice"));
        assert!(source.contains("let mut header_bytes = [0u8; GUEST_INPUT_HEADER_BYTES]"));
        let decode = source.find("GuestInputHeader::decode").unwrap();
        let plain_only = source.find("header.mode() != GuestMode::Plain").unwrap();
        let workload = source.find("require_workload(header)").unwrap();
        let commit = source.find("env::commit_slice").unwrap();
        assert!(
            decode < plain_only && plain_only < workload && workload < commit,
            "alternate guest must decode, reject non-Plain, validate workload, then commit"
        );
        for forbidden in [
            "verify_assumption",
            "env::verify(",
            "std::env",
            "std::path",
            "args(",
            "ALLOWED_CONTROL_ROOT",
        ] {
            assert!(
                !source.contains(forbidden),
                "alternate guest contains forbidden selector or assumption surface: {forbidden}"
            );
        }
    }

    #[test]
    fn locked_builder_names_both_guests_without_binary_fallback() {
        let builder = include_str!("../reproduction/b4-build/container-build.sh");
        let runner = include_str!("../reproduction/b4-build.ps1");
        let linux_runner = include_str!("../reproduction/b4-build.sh");
        let checker = include_str!("../reproduction/src/b4_build_check.rs");

        for symbol in ["EIP_0045_GUEST", "EIP_0045_ALTERNATE_PROGRAM_GUEST"] {
            assert!(
                builder.contains(&format!("extract_generated_guest_path {symbol}")),
                "locked builder does not extract {symbol} by exact generated name"
            );
        }
        assert!(builder.contains("readlink -f -- \"$path\""));
        assert!(builder.contains("stat -c '%h' -- \"$canonical_path\""));
        assert!(builder.contains("/target/riscv-guest/eip-0045-methods/eip-0045-guest/"));
        assert!(!builder.contains("find /target -xdev -type f -name '*.bin'"));
        for artifact in [
            "alternate-program-guest.elf",
            "alternate-program-image-id.bin",
            "alternate-program-image-id.hex",
            "alternate-program-image-id-declaration.txt",
        ] {
            assert!(builder.contains(artifact));
            assert!(runner.contains(artifact));
            assert!(linux_runner.contains(artifact));
            assert!(checker.contains(artifact));
        }
        for script in [runner, linux_runner] {
            assert!(script.contains("schema=eip0045-b4-build-completion-v2"));
            assert!(!script.contains("schema=eip0045-b4-build-completion-v1"));
            assert!(script.contains("alternateProgramGuestElfSha256"));
            assert!(script.contains("alternateProgramImageIdSha256"));
        }
        assert!(runner.contains(
            "Assert-FileIdentityEqual (Join-Path $stagingRoot 'run-1\\alternate-program-guest.elf') (Join-Path $stagingRoot 'run-2\\alternate-program-guest.elf')"
        ));
        assert!(runner.contains(
            "Assert-FileIdentityEqual (Join-Path $stagingRoot 'run-1\\alternate-program-image-id.bin') (Join-Path $stagingRoot 'run-2\\alternate-program-image-id.bin')"
        ));
        assert!(linux_runner.contains(
            "cmp \"$staging_root/run-1/alternate-program-guest.elf\" \"$staging_root/run-2/alternate-program-guest.elf\""
        ));
        assert!(linux_runner.contains(
            "cmp \"$staging_root/run-1/alternate-program-image-id.bin\" \"$staging_root/run-2/alternate-program-image-id.bin\""
        ));
        assert!(linux_runner.contains("consumer and alternate-program image IDs must be distinct"));
        assert!(runner.contains("alternate-program image ID equals the consumer image ID"));
    }

    #[test]
    fn locked_builder_applies_one_closed_physical_path_predicate() {
        let builder = include_str!("../reproduction/b4-build/container-build.sh");

        assert_eq!(
            builder
                .matches("# BEGIN EIP0045 PHYSICAL PATH PREDICATE")
                .count(),
            1
        );
        assert_eq!(
            builder
                .matches("# END EIP0045 PHYSICAL PATH PREDICATE")
                .count(),
            1
        );
        assert!(builder.contains(
            "require_exact_physical_path directory CARGO_TARGET_DIR \"$CARGO_TARGET_DIR\" /target"
        ));
        assert!(builder.contains(
            "require_exact_physical_path directory CARGO_MANIFEST_DIR /workspace/methods /workspace/methods"
        ));
        assert!(builder.contains(
            "require_exact_physical_path regular-file \"generated ${symbol}_ELF\" \"$path\" \"$expected_path\""
        ));
        assert_eq!(
            builder
                .matches("extract_generated_guest_path EIP_0045_")
                .count(),
            2,
            "both closed guest symbols must use the same extractor and physical-path predicate"
        );
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn production_predicate_rejects_redirected_or_noncanonical_cargo_directories() {
        use std::os::unix::fs::symlink;

        let fixture = PhysicalPathFixture::new("cargo-directories");
        for (name, leaf) in [
            ("CARGO_TARGET_DIR", "target"),
            ("CARGO_MANIFEST_DIR", "methods"),
        ] {
            let physical = fixture.root.join(format!("{leaf}-physical"));
            let redirected = fixture.root.join(format!("{leaf}-redirected"));
            std::fs::create_dir(&physical).expect("create physical directory fixture");
            symlink(&physical, &redirected).expect("create directory symlink fixture");

            let accepted =
                run_production_physical_path_predicate("directory", name, &physical, &physical);
            assert!(
                accepted.status.success(),
                "{name} physical directory was rejected: {}",
                String::from_utf8_lossy(&accepted.stderr)
            );

            let symlinked =
                run_production_physical_path_predicate("directory", name, &redirected, &redirected);
            assert!(!symlinked.status.success(), "{name} symlink was accepted");
            assert!(
                String::from_utf8_lossy(&symlinked.stderr).contains("is a symlink"),
                "{name} symlink failed for the wrong predicate: {}",
                String::from_utf8_lossy(&symlinked.stderr)
            );

            let noncanonical = physical.join("..").join(
                physical
                    .file_name()
                    .expect("physical directory fixture has a leaf"),
            );
            let noncanonical_result = run_production_physical_path_predicate(
                "directory",
                name,
                &noncanonical,
                &noncanonical,
            );
            assert!(
                !noncanonical_result.status.success(),
                "{name} noncanonical path was accepted"
            );
            assert!(
                String::from_utf8_lossy(&noncanonical_result.stderr)
                    .contains("is not physically canonical"),
                "{name} noncanonical path failed for the wrong predicate: {}",
                String::from_utf8_lossy(&noncanonical_result.stderr)
            );
        }
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn production_predicate_rejects_symlinked_or_hard_linked_guest_elf() {
        use std::os::unix::fs::symlink;

        let fixture = PhysicalPathFixture::new("guest-elf");
        let physical = fixture.root.join("guest.bin");
        let redirected = fixture.root.join("guest-symlink.bin");
        let hard_link = fixture.root.join("guest-hard-link.bin");
        std::fs::write(&physical, b"ELF fixture").expect("write guest ELF fixture");

        let accepted = run_production_physical_path_predicate(
            "regular-file",
            "generated guest ELF",
            &physical,
            &physical,
        );
        assert!(
            accepted.status.success(),
            "physical guest ELF was rejected: {}",
            String::from_utf8_lossy(&accepted.stderr)
        );

        symlink(&physical, &redirected).expect("create guest ELF symlink fixture");
        let symlinked = run_production_physical_path_predicate(
            "regular-file",
            "generated guest ELF",
            &redirected,
            &redirected,
        );
        assert!(
            !symlinked.status.success(),
            "guest ELF symlink was accepted"
        );
        assert!(
            String::from_utf8_lossy(&symlinked.stderr).contains("is a symlink"),
            "guest ELF symlink failed for the wrong predicate: {}",
            String::from_utf8_lossy(&symlinked.stderr)
        );

        std::fs::hard_link(&physical, &hard_link).expect("create guest ELF hard-link fixture");
        let hard_linked = run_production_physical_path_predicate(
            "regular-file",
            "generated guest ELF",
            &physical,
            &physical,
        );
        assert!(
            !hard_linked.status.success(),
            "guest ELF with link count greater than one was accepted"
        );
        assert!(
            String::from_utf8_lossy(&hard_linked.stderr).contains("must have link count 1"),
            "hard-linked guest ELF failed for the wrong predicate: {}",
            String::from_utf8_lossy(&hard_linked.stderr)
        );
    }
}
