//! Command-line validation tools for non-final EIP-0045 artifacts.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
#[cfg(feature = "evidence")]
use eip_0045_reproduction::canonical::validate_lower_hex_exact;
#[cfg(feature = "evidence")]
use eip_0045_reproduction::evidence::fresh_challenge;
use eip_0045_reproduction::{
    b4::{B4_CANDIDATE_REGISTRY_PATH, B4CandidateCorpus},
    b4_build_check::{
        B4ArtifactEvidenceStatus, B4BuildExpectations, B4FilesystemBindingStatus,
        B4SourceBindingStatus, validate_published_b4_build_with_expectations,
    },
    candidate::{CandidateCorpusManifest, validate_candidate_quarantine},
    canonical::{
        canonical_json_bytes, canonical_sha256_hex, parse_json_strict,
        validate_canonical_json_source,
    },
    cargo_closure::{
        CargoClosureRole, CargoConfigurationEvidence, ProfileRootIdentity,
        derive_cargo_closure_evidence, validate_cargo_closure,
    },
    constants::validate_pinned_invariants,
    manifest::{build_proof_output_manifest, require_empty_before_generation},
    source_lock::{CandidateSourceLock, MaterializedFileEntry},
};
#[cfg(any(unix, test))]
use sha1::{Digest as _, Sha1};
#[cfg(unix)]
use sha2::Sha256;
#[cfg(unix)]
use std::fs::FileType;
#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[derive(Debug, Parser)]
#[command(name = "eip0045-reproduction")]
#[command(about = "Validate non-final EIP-0045 reproduction artifacts")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Args)]
struct B4BuildCheckArgs {
    /// Evidence root containing B4-COMPLETE and its manifest.
    #[arg(long)]
    root: PathBuf,
    /// Permit inspection without external authority; never an anchored result.
    #[arg(
        long,
        required_unless_present = "expected_evidence_root",
        conflicts_with_all = [
            "expected_source_commit",
            "expected_source_tree",
            "expected_evidence_root"
        ]
    )]
    allow_unanchored_inspection: bool,
    /// Expected commit of the builder source checkout, supplied externally.
    #[arg(
        long,
        requires = "expected_source_tree",
        requires = "expected_evidence_root"
    )]
    expected_source_commit: Option<String>,
    /// Expected tree of the builder source checkout, supplied externally.
    #[arg(
        long,
        requires = "expected_source_commit",
        requires = "expected_evidence_root"
    )]
    expected_source_tree: Option<String>,
    /// External archive commitment; required with the source pair in anchored mode.
    #[arg(
        long,
        requires = "expected_source_commit",
        requires = "expected_source_tree"
    )]
    expected_evidence_root: Option<String>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Check all construction constants fixed by the current EIP text.
    VerifyInvariants,
    /// Structurally validate the B4 candidate registry and its bound files.
    B4CorpusCheck {
        /// Repository root used to resolve and confine every bound artifact.
        #[arg(long)]
        repo_root: PathBuf,
        /// Candidate B4 registry, relative to the repository root by default.
        #[arg(long, default_value = B4_CANDIDATE_REGISTRY_PATH)]
        registry: PathBuf,
    },
    /// Validate the closed semantics of one B4 build-evidence archive.
    B4BuildCheck(B4BuildCheckArgs),
    /// Require a JSON file to already be exact RFC 8785 JCS bytes.
    CanonicalCheck {
        /// JSON source to validate.
        file: PathBuf,
    },
    /// Emit RFC 8785 JCS bytes for one strictly parsed JSON source.
    Canonicalize {
        /// JSON source to canonicalize.
        file: PathBuf,
    },
    /// Require the reserved proof-output root to be physically empty.
    PreflightProofOutput {
        /// Reserved export root checked immediately before generation.
        directory: PathBuf,
    },
    /// Emit the canonical post-generation proof-output manifest.
    ManifestProofOutput {
        /// Populated post-generation export root.
        directory: PathBuf,
    },
    /// Derive one post-precommit B7 fresh challenge.
    #[cfg(feature = "evidence")]
    FreshChallenge {
        /// SHA-256 of the exact canonical precommit bytes.
        #[arg(long)]
        precommit_digest: String,
        /// Supported segment exponent, from 15 through 22.
        #[arg(long)]
        po2: u8,
        /// Raw, non-reversed 32-byte challenge block ID.
        #[arg(long)]
        block_id: String,
    },
    /// Ensure non-final artifacts remain complete and quarantined.
    GuardCandidate {
        /// Repository root containing the candidate corpus.
        #[arg(long)]
        repo_root: PathBuf,
        /// Canonical repository-relative candidate directory.
        #[arg(long, default_value = "reproduction/schema")]
        quarantine_root: String,
        /// Candidate corpus manifest, relative to the repository root by default.
        #[arg(long, default_value = "reproduction/candidate-corpus.json")]
        manifest: PathBuf,
    },
    /// Derive and validate canonical Cargo dependency-closure evidence.
    CargoClosure {
        /// Exact `cargo metadata --format-version 1` JSON output.
        #[arg(long)]
        metadata: PathBuf,
        /// Absolute private root containing every admitted local package.
        #[arg(long)]
        profile_root: String,
        /// Portable root label emitted instead of the private path.
        #[arg(long)]
        profile_root_identity: String,
        /// Policy role for this metadata closure.
        #[arg(
            long,
            value_parser = ["generator-host", "methods-build", "guest"]
        )]
        role: String,
    },
    /// Recompute the exact Git root-tree object ID from a physical checkout.
    GitTree {
        /// Checkout root containing `.git` and Cargo's optional `.cargo-ok` marker.
        #[arg(long)]
        source_root: PathBuf,
    },
    /// Capture and validate the exact materialized RISC Zero source lock.
    SourceLock {
        /// Root of the freshly materialized Cargo Git checkout.
        #[arg(long)]
        source_root: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::VerifyInvariants => {
            validate_pinned_invariants()?;
            println!("EIP-0045 pinned invariants: ok");
        }
        Command::B4CorpusCheck {
            repo_root,
            registry,
        } => b4_corpus_check(&repo_root, registry)?,
        Command::B4BuildCheck(args) => b4_build_check(&args)?,
        Command::CanonicalCheck { file } => {
            let source = read(&file)?;
            let value = validate_canonical_json_source(&source)?;
            println!("{}", canonical_sha256_hex(&value)?);
        }
        Command::Canonicalize { file } => {
            let value = parse_json_strict(&read(&file)?)?;
            let canonical = canonical_json_bytes(&value)?;
            io::stdout().lock().write_all(&canonical)?;
        }
        Command::PreflightProofOutput { directory } => {
            require_empty_before_generation(directory)?;
            println!("EIP-0045 proof-output preflight: empty");
        }
        Command::ManifestProofOutput { directory } => {
            let manifest = build_proof_output_manifest(directory)?;
            let value = serde_json::to_value(manifest)
                .context("proof-output manifest cannot be represented as JSON")?;
            let canonical = canonical_json_bytes(&value)?;
            io::stdout().lock().write_all(&canonical)?;
        }
        #[cfg(feature = "evidence")]
        Command::FreshChallenge {
            precommit_digest,
            po2,
            block_id,
        } => {
            let precommit_digest = decode_fixed::<32>(&precommit_digest, "precommit digest")?;
            let block_id = decode_fixed::<32>(&block_id, "challenge block ID")?;
            println!(
                "{}",
                hex::encode(fresh_challenge(&precommit_digest, po2, &block_id)?)
            );
        }
        Command::GuardCandidate {
            repo_root,
            quarantine_root,
            manifest,
        } => {
            let manifest_path = if manifest.is_absolute() {
                manifest
            } else {
                repo_root.join(manifest)
            };
            let value = validate_canonical_json_source(&read(&manifest_path)?)
                .context("candidate corpus manifest is not exact RFC 8785 JCS")?;
            let manifest: CandidateCorpusManifest = serde_json::from_value(value)
                .context("candidate corpus manifest does not match its closed shape")?;
            validate_candidate_quarantine(&repo_root, &quarantine_root, &manifest)?;
            println!("EIP-0045 candidate quarantine: ok");
        }
        Command::CargoClosure {
            metadata,
            profile_root,
            profile_root_identity,
            role,
        } => {
            let metadata = parse_json_strict(&read(&metadata)?)
                .context("Cargo metadata is not one complete strict JSON document")?;
            let configuration = observe_cargo_configuration(&metadata, Path::new(&profile_root))?;
            let profile_root = ProfileRootIdentity::new(&profile_root, &profile_root_identity)
                .context("invalid private profile root or portable identity")?;
            let role = role
                .parse::<CargoClosureRole>()
                .map_err(anyhow::Error::msg)
                .context("invalid Cargo closure role")?;
            let evidence =
                derive_cargo_closure_evidence(&metadata, role, &profile_root, configuration)?;
            validate_cargo_closure(&metadata, &evidence, &profile_root)?;
            let value = serde_json::to_value(evidence)
                .context("Cargo closure evidence cannot be represented as JSON")?;
            io::stdout()
                .lock()
                .write_all(&canonical_json_bytes(&value)?)?;
        }
        Command::GitTree { source_root } => {
            println!("{}", hex::encode(compute_git_tree(&source_root)?));
        }
        Command::SourceLock { source_root } => {
            let entries = capture_materialized_entries(&source_root)?;
            let source_lock = CandidateSourceLock::from_materialized_entries(entries)?;
            let value = serde_json::to_value(source_lock)
                .context("candidate source lock cannot be represented as JSON")?;
            io::stdout()
                .lock()
                .write_all(&canonical_json_bytes(&value)?)?;
        }
    }
    Ok(())
}

fn b4_build_check(args: &B4BuildCheckArgs) -> Result<()> {
    let expectations = if args.allow_unanchored_inspection {
        B4BuildExpectations::default()
    } else {
        B4BuildExpectations {
            expected_source_commit: args.expected_source_commit.as_deref(),
            expected_source_tree: args.expected_source_tree.as_deref(),
            expected_evidence_root: args.expected_evidence_root.as_deref(),
        }
    };
    let result = validate_published_b4_build_with_expectations(&args.root, &expectations)?;
    println!("EIP-0045 B4 archive: closed-tree and selected-semantic checks satisfied");
    println!("evidenceRoot={}", result.computed_evidence_root);
    println!(
        "providedDigestMatched={}",
        match result.provided_digest_matched {
            Some(true) => "true",
            Some(false) => "false",
            None => "not-provided",
        }
    );
    println!(
        "sourceBinding={}",
        match result.source_binding {
            B4SourceBindingStatus::Unbound => "unbound",
            B4SourceBindingStatus::Matched => "matched",
        }
    );
    println!(
        "filesystemBinding={}",
        match result.filesystem_binding {
            B4FilesystemBindingStatus::UnixFileIdentityBound => "unix-dev-ino-nlink",
            B4FilesystemBindingStatus::UnavailableForInspection => {
                "unavailable-unanchored-inspection-only"
            }
        }
    );
    println!("runnerClaims=unattested");
    println!("proofGenerationMarker=exact-declaration;execution=unattested");
    for artifact in result.opaque_artifacts {
        let status = match artifact.status {
            B4ArtifactEvidenceStatus::OpaqueHashBound => "opaque-hash-bound",
        };
        println!(
            "artifact path={} status={status} size={} sha256={}",
            artifact.path, artifact.size, artifact.sha256
        );
    }
    Ok(())
}

fn b4_corpus_check(repo_root: &Path, registry: PathBuf) -> Result<()> {
    let registry_path = if registry.is_absolute() {
        registry
    } else {
        repo_root.join(registry)
    };
    let value = validate_canonical_json_source(&read(&registry_path)?)
        .context("B4 candidate registry is not exact RFC 8785 JCS")?;
    let registry: B4CandidateCorpus = serde_json::from_value(value)
        .context("B4 candidate registry does not match its closed shape")?;
    registry.validate_physical(repo_root)?;
    println!(
        "EIP-0045 B4 candidate registry: structural/physical validation ok; semantic closure not evaluated"
    );
    Ok(())
}

fn compute_git_tree(source_root: &Path) -> Result<[u8; 20]> {
    #[cfg(not(unix))]
    {
        let _ = source_root;
        bail!("Git tree reconstruction requires Unix file-mode semantics");
    }

    #[cfg(unix)]
    {
        let metadata = fs::symlink_metadata(source_root)
            .with_context(|| format!("cannot inspect Git tree root {}", source_root.display()))?;
        if !metadata.file_type().is_dir() {
            bail!(
                "Git tree root is not a physical directory: {}",
                source_root.display()
            );
        }
        hash_git_directory(source_root, true)
    }
}

#[cfg(unix)]
struct GitTreeEntry {
    name: Vec<u8>,
    sort_key: Vec<u8>,
    mode: &'static [u8],
    digest: [u8; 20],
}

#[cfg(unix)]
fn hash_git_directory(directory: &Path, is_root: bool) -> Result<[u8; 20]> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory).with_context(|| {
        format!(
            "cannot enumerate Git tree directory {}",
            directory.display()
        )
    })? {
        let entry = entry.with_context(|| {
            format!(
                "cannot enumerate Git tree entry below {}",
                directory.display()
            )
        })?;
        let name = entry.file_name().as_bytes().to_vec();
        if name.is_empty() || name.contains(&0) || name.contains(&b'/') {
            bail!("Git tree contains an invalid filename");
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("cannot inspect Git tree entry {}", path.display()))?;
        if is_root && name == b".git" {
            if !metadata.file_type().is_dir() {
                bail!("checkout .git is not a physical directory");
            }
            continue;
        }
        if is_root && name == b".cargo-ok" {
            if !metadata.file_type().is_file() {
                bail!("checkout .cargo-ok is not a physical regular file");
            }
            continue;
        }
        if name == b".git" {
            bail!("nested Git administration data entered the source tree");
        }

        let (mode, digest, directory_entry) = if metadata.file_type().is_dir() {
            (b"40000".as_slice(), hash_git_directory(&path, false)?, true)
        } else if metadata.file_type().is_file() {
            let executable = metadata.permissions().mode() & 0o111 != 0;
            (
                if executable {
                    b"100755".as_slice()
                } else {
                    b"100644".as_slice()
                },
                hash_git_blob(&path)?,
                false,
            )
        } else {
            bail!(
                "symlink or special node is not admitted in Git tree reconstruction: {}",
                path.display()
            );
        };
        let mut sort_key = name.clone();
        sort_key.push(if directory_entry { b'/' } else { 0 });
        entries.push(GitTreeEntry {
            name,
            sort_key,
            mode,
            digest,
        });
    }
    entries.sort_unstable_by(|left, right| left.sort_key.cmp(&right.sort_key));

    let mut body = Vec::new();
    for entry in entries {
        body.extend_from_slice(entry.mode);
        body.push(b' ');
        body.extend_from_slice(&entry.name);
        body.push(0);
        body.extend_from_slice(&entry.digest);
    }
    Ok(hash_git_object(b"tree", &body))
}

#[cfg(unix)]
fn hash_git_blob(path: &Path) -> Result<[u8; 20]> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("cannot open Git blob candidate {}", path.display()))?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "cannot inspect opened Git blob candidate {}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        bail!("opened Git blob candidate is not a regular file");
    }
    let mut digest = Sha1::new();
    digest.update(b"blob ");
    digest.update(metadata.len().to_string().as_bytes());
    digest.update([0]);
    let mut observed_length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("cannot hash Git blob candidate {}", path.display()))?;
        if read == 0 {
            break;
        }
        observed_length = observed_length
            .checked_add(u64::try_from(read).context("Git blob read length does not fit u64")?)
            .context("Git blob length overflow")?;
        digest.update(&buffer[..read]);
    }
    if observed_length != metadata.len() {
        bail!("Git blob candidate changed while hashing");
    }
    Ok(digest.finalize().into())
}

#[cfg(any(unix, test))]
fn hash_git_object(kind: &[u8], body: &[u8]) -> [u8; 20] {
    let mut digest = Sha1::new();
    digest.update(kind);
    digest.update(b" ");
    digest.update(body.len().to_string().as_bytes());
    digest.update([0]);
    digest.update(body);
    digest.finalize().into()
}

fn observe_cargo_configuration(
    metadata: &serde_json::Value,
    profile_root: &Path,
) -> Result<CargoConfigurationEvidence> {
    let root_metadata = fs::symlink_metadata(profile_root).with_context(|| {
        format!(
            "cannot inspect Cargo-closure profile root {}",
            profile_root.display()
        )
    })?;
    if !root_metadata.file_type().is_dir() {
        bail!(
            "Cargo-closure profile root is not a physical directory: {}",
            profile_root.display()
        );
    }
    let canonical_root = fs::canonicalize(profile_root).with_context(|| {
        format!(
            "cannot canonicalize Cargo-closure profile root {}",
            profile_root.display()
        )
    })?;

    let mut manifests = BTreeSet::new();
    let workspace_root = metadata
        .get("workspace_root")
        .and_then(serde_json::Value::as_str)
        .context("Cargo metadata lacks workspace_root")?;
    manifests.insert(PathBuf::from(workspace_root).join("Cargo.toml"));
    let packages = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .context("Cargo metadata lacks packages")?;
    for package in packages {
        if !package
            .get("source")
            .is_some_and(serde_json::Value::is_null)
        {
            continue;
        }
        let manifest = package
            .get("manifest_path")
            .and_then(serde_json::Value::as_str)
            .context("local Cargo package lacks manifest_path")?;
        manifests.insert(PathBuf::from(manifest));
    }

    let mut observation = CargoConfigurationEvidence::default();
    for manifest in manifests {
        let canonical_manifest =
            require_physical_file_within(&manifest, &canonical_root, "local Cargo manifest")?;
        let relative = canonical_manifest
            .strip_prefix(&canonical_root)
            .expect("confinement checked above")
            .to_string_lossy()
            .replace('\\', "/");
        let parsed = parse_toml_file(&canonical_manifest, "Cargo manifest")?;
        observe_manifest_toml(&parsed, &relative, &mut observation);
    }

    let mut configs = BTreeSet::new();
    let current_dir =
        fs::canonicalize(env::current_dir().context("cannot read current directory")?)
            .context("cannot canonicalize current directory")?;
    for ancestor in current_dir.ancestors() {
        configs.insert(ancestor.join(".cargo/config"));
        configs.insert(ancestor.join(".cargo/config.toml"));
    }
    if let Some(cargo_home) = env::var_os("CARGO_HOME") {
        let cargo_home = PathBuf::from(cargo_home);
        configs.insert(cargo_home.join("config"));
        configs.insert(cargo_home.join("config.toml"));
    }
    for config in configs {
        if !config.exists() {
            continue;
        }
        let metadata = fs::symlink_metadata(&config)
            .with_context(|| format!("cannot inspect Cargo config {}", config.display()))?;
        if !metadata.file_type().is_file() {
            bail!(
                "Cargo config is not a physical regular file: {}",
                config.display()
            );
        }
        let parsed = parse_toml_file(&config, "Cargo config")?;
        observe_config_toml(&parsed)?;
    }

    if ["RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WRAPPER"]
        .iter()
        .any(|name| env::var_os(name).is_some())
    {
        observation.rustc_wrapper = Some("environment rustc wrapper".to_owned());
    }
    if [
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    ]
    .iter()
    .any(|name| env::var_os(name).is_some())
    {
        observation.rustc_workspace_wrapper =
            Some("environment workspace rustc wrapper".to_owned());
    }

    Ok(observation)
}

fn observe_manifest_toml(
    parsed: &toml::Value,
    relative: &str,
    observation: &mut CargoConfigurationEvidence,
) {
    if parsed.get("patch").is_some() {
        observation.patches.push(format!("{relative}#patch"));
    }
    if parsed.get("replace").is_some() {
        observation.replacements.push(format!("{relative}#replace"));
    }
}

fn observe_config_toml(parsed: &toml::Value) -> Result<()> {
    let root = parsed
        .as_table()
        .context("Cargo config root must be a TOML table")?;
    if root.len() != 2 || !root.contains_key("build") || !root.contains_key("net") {
        bail!(
            "Cargo config differs from the exact build.jobs=2, build.incremental=false, and net.offline=true policy"
        );
    }
    let build = root
        .get("build")
        .and_then(toml::Value::as_table)
        .context("Cargo config build policy must be a table")?;
    if build.len() != 2
        || build.get("jobs").and_then(toml::Value::as_integer) != Some(2)
        || build.get("incremental").and_then(toml::Value::as_bool) != Some(false)
    {
        bail!(
            "Cargo config differs from the exact build.jobs=2 and build.incremental=false policy"
        );
    }
    let net = root
        .get("net")
        .and_then(toml::Value::as_table)
        .context("Cargo config net policy must be a table")?;
    if net.len() != 1 || net.get("offline").and_then(toml::Value::as_bool) != Some(true) {
        bail!("Cargo config differs from the exact net.offline=true policy");
    }
    Ok(())
}

fn require_physical_file_within(path: &Path, root: &Path, label: &str) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {label} {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("{label} is not a physical regular file: {}", path.display());
    }
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("cannot canonicalize {label} {}", path.display()))?;
    if !canonical.starts_with(root) {
        bail!("{label} escapes the profile root");
    }
    Ok(canonical)
}

fn parse_toml_file(path: &Path, label: &str) -> Result<toml::Value> {
    let bytes = read(path)?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("{label} is not UTF-8: {}", path.display()))?;
    text.parse::<toml::Value>()
        .with_context(|| format!("cannot parse {label} {}", path.display()))
}

fn capture_materialized_entries(source_root: &Path) -> Result<Vec<MaterializedFileEntry>> {
    #[cfg(not(unix))]
    {
        let _ = source_root;
        bail!("materialized source capture requires Unix executable-bit semantics");
    }

    #[cfg(unix)]
    {
        let root_metadata = fs::symlink_metadata(source_root)
            .with_context(|| format!("cannot inspect source root {}", source_root.display()))?;
        if !root_metadata.file_type().is_dir() {
            bail!(
                "materialized source root is not a physical directory: {}",
                source_root.display()
            );
        }

        let mut pending = vec![source_root.to_path_buf()];
        let mut entries = Vec::new();
        while let Some(directory) = pending.pop() {
            for child in fs::read_dir(&directory)
                .with_context(|| format!("cannot enumerate {}", directory.display()))?
            {
                let child = child.with_context(|| {
                    format!("cannot read an entry below {}", directory.display())
                })?;
                let path = child.path();
                let relative = path.strip_prefix(source_root).with_context(|| {
                    format!("source entry escaped its root: {}", path.display())
                })?;
                let normalized = normalized_source_path(relative)?;
                let metadata = fs::symlink_metadata(&path)
                    .with_context(|| format!("cannot inspect {}", path.display()))?;
                let file_type = metadata.file_type();

                if normalized == ".cargo-ok" {
                    if !file_type.is_file() {
                        bail!("Cargo checkout marker is not a regular file");
                    }
                    continue;
                }
                if normalized == ".git" || normalized.starts_with(".git/") {
                    bail!("Git administrative metadata is not admitted in the source lock");
                }

                if file_type.is_dir() {
                    pending.push(path);
                } else if file_type.is_file() {
                    entries.push(hash_source_file(&path, normalized, &metadata)?);
                } else {
                    reject_unsupported_file_type(&path, file_type)?;
                }
            }
        }
        entries.sort_unstable_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        Ok(entries)
    }
}

#[cfg(unix)]
fn normalized_source_path(relative: &Path) -> Result<String> {
    let value = relative
        .to_str()
        .context("materialized source path is not valid UTF-8")?
        .replace('\\', "/");
    if value.is_empty()
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains(':')
        || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        || value.split('/').any(|component| {
            component.is_empty()
                || component == "."
                || component == ".."
                || component.ends_with(['.', ' '])
        })
    {
        bail!("materialized source path is not canonical: {value:?}");
    }
    Ok(value)
}

#[cfg(unix)]
fn hash_source_file(
    path: &Path,
    normalized: String,
    path_metadata: &fs::Metadata,
) -> Result<MaterializedFileEntry> {
    if !path_metadata.file_type().is_file() {
        bail!("source entry is not a regular file: {}", path.display());
    }
    let mut file = fs::File::open(path)
        .with_context(|| format!("cannot open materialized source file {}", path.display()))?;
    let opened_metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect opened source file {}", path.display()))?;
    if !opened_metadata.file_type().is_file() {
        bail!(
            "opened source entry is not a regular file: {}",
            path.display()
        );
    }
    if path_metadata.dev() != opened_metadata.dev() || path_metadata.ino() != opened_metadata.ino()
    {
        bail!(
            "materialized source path changed while opening: {}",
            path.display()
        );
    }
    if path_metadata.nlink() != 1 || opened_metadata.nlink() != 1 {
        bail!(
            "materialized source file must have exactly one hard link: {}",
            path.display()
        );
    }

    let mut digest = Sha256::new();
    let mut byte_length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("cannot hash {}", path.display()))?;
        if read == 0 {
            break;
        }
        byte_length = byte_length
            .checked_add(u64::try_from(read).context("read length does not fit u64")?)
            .context("materialized source file length overflow")?;
        digest.update(&buffer[..read]);
    }
    if byte_length != opened_metadata.len() {
        bail!(
            "materialized source file changed while hashing: {}",
            path.display()
        );
    }

    Ok(MaterializedFileEntry {
        path: normalized,
        byte_length,
        sha256: hex::encode(digest.finalize()),
        executable: opened_metadata.permissions().mode() & 0o111 != 0,
    })
}

#[cfg(unix)]
fn reject_unsupported_file_type(path: &Path, _file_type: FileType) -> Result<()> {
    bail!(
        "symlink or special node is not admitted in the source lock: {}",
        path.display()
    )
}

fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("cannot read {}", path.display()))
}

#[cfg(feature = "evidence")]
fn decode_fixed<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    validate_lower_hex_exact(value, N).with_context(|| format!("invalid {label}"))?;
    let decoded = hex::decode(value).with_context(|| format!("cannot decode {label}"))?;
    decoded.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!("{label} has {} bytes, expected {N}", bytes.len())
    })
}

#[cfg(test)]
mod b4_build_cli_tests {
    use super::*;

    #[test]
    fn unanchored_archive_inspection_requires_an_explicit_flag() {
        assert!(
            Cli::try_parse_from([
                "eip0045-reproduction",
                "b4-build-check",
                "--root",
                "fixture",
            ])
            .is_err()
        );
    }

    #[test]
    fn explicit_unanchored_inspection_mode_parses() {
        assert!(
            Cli::try_parse_from([
                "eip0045-reproduction",
                "b4-build-check",
                "--root",
                "fixture",
                "--allow-unanchored-inspection",
            ])
            .is_ok()
        );
    }

    #[test]
    fn authoritative_mode_requires_all_three_external_values() {
        let base = [
            "eip0045-reproduction",
            "b4-build-check",
            "--root",
            "fixture",
        ];
        assert!(
            Cli::try_parse_from(base.into_iter().chain(["--expected-evidence-root", "00"]))
                .is_err()
        );
        assert!(
            Cli::try_parse_from(base.into_iter().chain([
                "--expected-source-commit",
                "11",
                "--expected-source-tree",
                "22",
                "--expected-evidence-root",
                "33",
            ]))
            .is_ok()
        );
    }

    #[test]
    fn unanchored_flag_conflicts_with_external_values() {
        assert!(
            Cli::try_parse_from([
                "eip0045-reproduction",
                "b4-build-check",
                "--root",
                "fixture",
                "--allow-unanchored-inspection",
                "--expected-source-commit",
                "11",
                "--expected-source-tree",
                "22",
                "--expected-evidence-root",
                "33",
            ])
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn source_lock_rejects_hardlinked_materialized_files() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target.rs");
        let alias = temp.path().join("alias.rs");
        fs::write(&target, b"fn fixture() {}\n").unwrap();
        fs::hard_link(&target, &alias).unwrap();

        let error = capture_materialized_entries(temp.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("must have exactly one hard link"), "{error}");
    }
}

#[cfg(test)]
mod cargo_configuration_tests {
    use super::*;

    #[test]
    fn git_blob_object_id_matches_independent_known_answer() {
        assert_eq!(
            hex::encode(hash_git_object(b"blob", b"hello\n")),
            "ce013625030ba8dba906f756967f9e9ca394464a"
        );
    }

    #[test]
    fn manifest_patch_and_replace_tables_are_observed() {
        let parsed = r#"
            [patch.crates-io]
            sha2 = { path = "vendor/sha2" }

            [replace]
            "hex:0.4.3" = { path = "vendor/hex" }
        "#
        .parse::<toml::Value>()
        .unwrap();
        let mut observation = CargoConfigurationEvidence::default();
        observe_manifest_toml(&parsed, "Cargo.toml", &mut observation);
        assert_eq!(observation.patches, ["Cargo.toml#patch"]);
        assert_eq!(observation.replacements, ["Cargo.toml#replace"]);
    }

    #[test]
    fn exact_reproduction_cargo_config_is_admitted() {
        let parsed = r"
            [build]
            jobs = 2
            incremental = false

            [net]
            offline = true
        "
        .parse::<toml::Value>()
        .unwrap();
        observe_config_toml(&parsed).unwrap();
    }

    #[test]
    fn compilation_affecting_cargo_config_is_rejected() {
        let parsed = r#"
            [build]
            jobs = 2
            incremental = false
            rustflags = ["-C", "target-cpu=native"]

            [net]
            offline = true
        "#
        .parse::<toml::Value>()
        .unwrap();
        let error = observe_config_toml(&parsed).unwrap_err();
        assert!(error.to_string().contains("build.jobs=2"));
    }

    #[test]
    fn offline_policy_with_an_extra_key_is_rejected() {
        let parsed = r"
            [build]
            jobs = 2
            incremental = false

            [net]
            offline = true
            git-fetch-with-cli = true
        "
        .parse::<toml::Value>()
        .unwrap();
        let error = observe_config_toml(&parsed).unwrap_err();
        assert!(error.to_string().contains("net.offline=true"));
    }

    #[test]
    fn missing_or_wrong_build_job_policy_is_rejected() {
        for text in [
            r"
                [net]
                offline = true
            ",
            r"
                [build]
                jobs = 4
                incremental = false

                [net]
                offline = true
            ",
            r#"
                [build]
                jobs = "2"
                incremental = false

                [net]
                offline = true
            "#,
        ] {
            let parsed = text.parse::<toml::Value>().unwrap();
            let error = observe_config_toml(&parsed).unwrap_err();
            assert!(error.to_string().contains("build.jobs=2"));
        }

        let parsed = r"
            [build]
            jobs = 2
            incremental = true

            [net]
            offline = true
        "
        .parse::<toml::Value>()
        .unwrap();
        let error = observe_config_toml(&parsed).unwrap_err();
        assert!(error.to_string().contains("build.incremental=false"));
    }
}
