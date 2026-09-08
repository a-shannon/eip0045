//! Build the pinned RISC Zero guest and emit its ELF and image-ID constants.
//!
//! The reproducer runs this build inside an OS/container `network=none`
//! boundary and with the exact `/home/ergo/eip0045` home and Cargo source root whose
//! `.cargo/config.toml` enables Cargo offline mode and fixes `build.jobs = 2`
//! and `build.incremental = false`. Cargo dependency source paths can enter the
//! guest ELF's `.rodata`, so those paths are part of the image identity. These
//! external boundaries also pin whole-ELF evidence paths whose non-loadable
//! metadata need not affect the computed image ID. They are necessary
//! because `risc0-build` removes inherited `CARGO*` variables, including
//! `CARGO_NET_OFFLINE`, `CARGO_HOME`, `CARGO_BUILD_JOBS`, and
//! `CARGO_INCREMENTAL`, before spawning the pinned host Cargo 1.89
//! orchestrator with the pinned guest Rust 1.88 compiler.

#[cfg(feature = "embed-methods")]
mod build_contract;

#[cfg(feature = "embed-methods")]
const REQUIRED_LOCK_ENV: &str = "RISC0_BUILD_LOCKED";
#[cfg(feature = "embed-methods")]
const REQUIRED_RISC0_HOME_ENV: &str = "RISC0_HOME";
#[cfg(feature = "embed-methods")]
const REQUIRED_RISC0_HOME: &str = "/root/.risc0";
#[cfg(feature = "embed-methods")]
const REQUIRED_RECURSION_SOURCE_ENV: &str = "RECURSION_SRC_PATH";
#[cfg(feature = "embed-methods")]
const REQUIRED_RECURSION_SOURCE_LENGTH: u64 = 59_768_781;
#[cfg(feature = "embed-methods")]
const REQUIRED_RECURSION_SOURCE_SHA256: [u8; 32] = [
    0x74, 0x4b, 0x99, 0x9f, 0x0a, 0x35, 0xb3, 0xc8, 0x67, 0x53, 0x31, 0x1c, 0x7e, 0xfb, 0x2a, 0x00,
    0x54, 0xbe, 0x21, 0x72, 0x70, 0x95, 0xcf, 0x10, 0x5a, 0xf6, 0xee, 0x7d, 0x3f, 0x4d, 0x88, 0x49,
];
#[cfg(feature = "embed-methods")]
const FORBIDDEN_ENV: &[&str] = &[
    "RISC0_SKIP_BUILD",
    "RISC0_RUST_SRC",
    "RISC0_DOCKER_CONTAINER_TAG",
    "RISC0_BUILD_DEBUG",
    "RISC0_DEV_MODE",
    "RISC0_PROVER",
    "RISC0_EXECUTOR",
    "RISC0_SERVER_PATH",
    "RISC0_WITGEN_DEBUG",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTFLAGS",
    "CC",
    "CFLAGS",
    "HOST_CC",
    "HOST_CFLAGS",
    "TARGET_CC",
    "TARGET_CFLAGS",
    "CC_riscv32im-risc0-zkvm-elf",
    "CC_riscv32im_risc0_zkvm_elf",
    "CFLAGS_riscv32im-risc0-zkvm-elf",
    "CFLAGS_riscv32im_risc0_zkvm_elf",
];

fn main() {
    #[cfg(feature = "embed-methods")]
    {
        if std::env::var("CARGO_CFG_TARGET_OS")
            .unwrap_or_default()
            .contains("zkvm")
        {
            // The guest depends on this crate for the shared input ABI. Avoid a
            // recursive guest build when Cargo compiles that dependency for zkVM.
            return;
        }

        enforce_reproducible_environment();
        risc0_build::embed_methods();
    }
}

#[cfg(feature = "embed-methods")]
fn enforce_reproducible_environment() {
    require_path_sensitive_build_contract();
    println!("cargo:rerun-if-env-changed={REQUIRED_LOCK_ENV}");
    assert!(
        std::env::var(REQUIRED_LOCK_ENV).as_deref() == Ok("1"),
        "host guest-build requires {REQUIRED_LOCK_ENV}=1"
    );
    println!("cargo:rerun-if-env-changed={REQUIRED_RISC0_HOME_ENV}");
    assert!(
        std::env::var(REQUIRED_RISC0_HOME_ENV).as_deref() == Ok(REQUIRED_RISC0_HOME),
        "host guest-build requires {REQUIRED_RISC0_HOME_ENV}={REQUIRED_RISC0_HOME}"
    );
    require_recursion_source();

    for name in FORBIDDEN_ENV {
        println!("cargo:rerun-if-env-changed={name}");
        assert!(
            std::env::var_os(name).is_none(),
            "host guest-build forbids environment override {name}"
        );
    }

    for (name, _) in std::env::vars_os() {
        let name = name.to_string_lossy();
        assert!(
            !name.starts_with("BONSAI_"),
            "host guest-build forbids environment override {name}"
        );
    }
}

#[cfg(feature = "embed-methods")]
fn require_path_sensitive_build_contract() {
    use build_contract::{
        validate_cargo_config, validate_cargo_home, validate_cargo_manifest_dir,
        validate_cargo_target_dir, validate_home, REQUIRED_CARGO_CONFIG_PATH, REQUIRED_CARGO_HOME,
        REQUIRED_CARGO_MANIFEST_DIR, REQUIRED_CARGO_TARGET_DIR, REQUIRED_HOME,
    };
    use std::path::Path;

    println!("cargo:rerun-if-env-changed=HOME");
    validate_home(std::env::var_os("HOME").as_deref()).unwrap_or_else(|error| panic!("{error}"));
    println!("cargo:rerun-if-env-changed=CARGO_HOME");
    validate_cargo_home(std::env::var_os("CARGO_HOME").as_deref())
        .unwrap_or_else(|error| panic!("{error}"));
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_DIR");
    validate_cargo_target_dir(std::env::var_os("CARGO_TARGET_DIR").as_deref())
        .unwrap_or_else(|error| panic!("{error}"));
    println!("cargo:rerun-if-env-changed=CARGO_MANIFEST_DIR");
    validate_cargo_manifest_dir(std::env::var_os("CARGO_MANIFEST_DIR").as_deref())
        .unwrap_or_else(|error| panic!("{error}"));
    println!("cargo:rerun-if-changed=../reproduction/cargo-offline-config.toml");

    for required_directory in [
        REQUIRED_HOME,
        REQUIRED_CARGO_HOME,
        REQUIRED_CARGO_MANIFEST_DIR,
        REQUIRED_CARGO_TARGET_DIR,
    ] {
        let path = Path::new(required_directory);
        let metadata = std::fs::symlink_metadata(path).unwrap_or_else(|error| {
            panic!("host guest-build cannot inspect {required_directory}: {error}")
        });
        assert!(
            metadata.file_type().is_dir(),
            "host guest-build requires a physical directory at {required_directory}"
        );
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|error| {
            panic!("host guest-build cannot canonicalize {required_directory}: {error}")
        });
        assert_eq!(
            canonical,
            path,
            "host guest-build path is redirected rather than physically canonical: {required_directory}"
        );
    }

    let config_path = Path::new(REQUIRED_CARGO_CONFIG_PATH);
    let metadata = std::fs::symlink_metadata(config_path)
        .unwrap_or_else(|error| panic!("host guest-build cannot inspect Cargo config: {error}"));
    assert!(
        metadata.file_type().is_file(),
        "host guest-build requires a physical regular Cargo config at {REQUIRED_CARGO_CONFIG_PATH}"
    );
    let canonical = std::fs::canonicalize(config_path).unwrap_or_else(|error| {
        panic!("host guest-build cannot canonicalize Cargo config: {error}")
    });
    assert_eq!(
        canonical, config_path,
        "host guest-build Cargo config path is redirected rather than physically canonical"
    );
    let config = std::fs::read(config_path)
        .unwrap_or_else(|error| panic!("host guest-build cannot read Cargo config: {error}"));
    validate_cargo_config(&config).unwrap_or_else(|error| panic!("{error}"));
}

#[cfg(feature = "embed-methods")]
fn require_recursion_source() {
    use sha2::{Digest, Sha256};
    use std::{
        io::Read,
        path::{Component, Path, PathBuf},
    };

    println!("cargo:rerun-if-env-changed={REQUIRED_RECURSION_SOURCE_ENV}");
    let path = PathBuf::from(
        std::env::var_os(REQUIRED_RECURSION_SOURCE_ENV)
            .expect("host guest-build requires RECURSION_SRC_PATH"),
    );
    let required_suffix = Path::new("risc0/circuit/recursion/src/recursion_zkr.zip");
    assert!(
        path.is_absolute()
            && !path
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
            && path.ends_with(required_suffix),
        "host guest-build requires an absolute canonical RECURSION_SRC_PATH ending in {}",
        required_suffix.display()
    );
    let metadata = std::fs::symlink_metadata(&path)
        .expect("host guest-build cannot inspect RECURSION_SRC_PATH");
    assert!(
        metadata.file_type().is_file() && metadata.len() == REQUIRED_RECURSION_SOURCE_LENGTH,
        "host guest-build requires the exact physical recursion source length"
    );

    let mut source =
        std::fs::File::open(&path).expect("host guest-build cannot open RECURSION_SRC_PATH");
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .expect("host guest-build cannot hash RECURSION_SRC_PATH");
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual: [u8; 32] = hasher.finalize().into();
    assert_eq!(
        actual, REQUIRED_RECURSION_SOURCE_SHA256,
        "host guest-build requires the exact recursion source digest"
    );
    println!("cargo:rerun-if-changed={}", path.display());
}
