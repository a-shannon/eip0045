//! Create-only local export of the fixed, cryptographically replayed fixtures.
//!
//! These path checks detect accidental replacement and reject redirected paths.
//! They do not provide hostile-concurrent-writer custody, campaign lineage, or
//! an H0/import authority. Failed staging directories are deliberately retained.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, Metadata, OpenOptions},
    io::{Read as _, Write as _},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use eip_0045_reproduction::{
    b4_terminal::{
        B4ApplicationBindingV1, B4_TERMINAL_FIXTURE_CATALOG_MAX_BYTES,
        B4_TERMINAL_FIXTURE_LAYOUT, Eip0045B4TerminalFixtureCatalogV1,
        terminal_fixture_raw_seal_path, terminal_fixture_receipt_oracle_path,
    },
    b4_terminal_oracle::replay_fixed_terminal_oracles,
    constants::{MAX_STATEMENT_BYTES, PROOF_BYTES},
    receipt_oracle_codec::RECEIPT_ORACLE_MAX_BYTES,
};
use risc0_zkvm::{Digest, LocalProver, ReceiptClaim, compute_image_id, sha::Digestible as _};

use crate::{
    recursive::RECURSIVE_ORACLE_MAX_BYTES,
    statement_bundle::MAX_GUEST_ELF_BYTES,
    terminal_fixtures::{authenticate_b4_terminal_fixture_sources, generate_b4_terminal_fixture_set},
    validate_ergo_statement_v1,
};

const FINAL_DIRECTORY: &str = "local-terminal-fixture-export";
const STAGING_DIRECTORY: &str = ".local-terminal-fixture-export.staging";
const CATALOGUE_PATH: &str =
    "reproduction/schema/b4-corpus-v1.candidate/bindings/terminal-fixture-catalog.json";
const ARTIFACT_COUNT: usize = 19;
const FIXTURE_IDS: [&str; 9] = [
    "lift-po2-14", "lift-povw-po2-18", "join-povw", "join-unwrap-povw",
    "resolve-povw", "resolve-unwrap-povw", "union", "unwrap-povw", "allowed-terminal-non-ok",
];

struct ArtifactSpec {
    path: String,
    minimum: usize,
    maximum: usize,
}

fn artifact_specs() -> Result<Vec<ArtifactSpec>> {
    ensure!(
        B4_TERMINAL_FIXTURE_LAYOUT.map(|entry| entry.fixture_id) == FIXTURE_IDS
            && B4_TERMINAL_FIXTURE_LAYOUT[0].expected_family == Some("identity"),
        "local terminal fixture order or Identity recipe drift"
    );
    let mut specs = Vec::with_capacity(ARTIFACT_COUNT);
    specs.push(ArtifactSpec {
        path: CATALOGUE_PATH.to_owned(), minimum: 1, maximum: B4_TERMINAL_FIXTURE_CATALOG_MAX_BYTES,
    });
    for id in FIXTURE_IDS {
        specs.push(ArtifactSpec {
            path: terminal_fixture_raw_seal_path(id)?, minimum: PROOF_BYTES, maximum: PROOF_BYTES,
        });
        specs.push(ArtifactSpec {
            path: terminal_fixture_receipt_oracle_path(id)?, minimum: 1, maximum: RECEIPT_ORACLE_MAX_BYTES,
        });
    }
    Ok(specs)
}

/// Authenticate the five fixed sources, generate nine fixtures, and publish locally.
///
/// The guest is supplied by the embedding caller; the CLI fixes it to its compiled ELF.
/// No existing directory entry is replaced, and failure never deletes staging data.
///
/// # Errors
/// Rejects redirected or oversized sources, invalid proofs, nonempty output roots,
/// failed replay/readback, or an existing publication destination.
pub fn generate_local_terminal_fixture_export(
    output_root: &Path,
    guest_elf: &[u8],
    statement_file: &Path,
    lift15_receipt_oracle: &Path,
    terminal_join_recursive_oracle: &Path,
    terminal_resolve_recursive_oracle: &Path,
) -> Result<PathBuf> {
    let output_root = absolute_path(output_root)?;
    require_empty_directory(&output_root)?;
    let statement = read_bounded(statement_file, 1, MAX_STATEMENT_BYTES)?;
    let image_id = expected_identity(guest_elf, &statement)?;
    let lift = read_bounded(lift15_receipt_oracle, 1, RECEIPT_ORACLE_MAX_BYTES)?;
    let join = read_bounded(terminal_join_recursive_oracle, 1, RECURSIVE_ORACLE_MAX_BYTES)?;
    let resolve = read_bounded(terminal_resolve_recursive_oracle, 1, RECURSIVE_ORACLE_MAX_BYTES)?;
    let authenticated = authenticate_b4_terminal_fixture_sources(
        guest_elf, &statement, &lift, &join, &resolve,
    )?;
    let generated = generate_b4_terminal_fixture_set(
        &LocalProver::new("eip-0045-pinned-local-terminal-fixtures"), &authenticated,
    )?;
    let mut artifacts = generated.raw_seals().clone();
    for (path, bytes) in generated.receipt_oracles() {
        ensure!(artifacts.insert(path.clone(), bytes.clone()).is_none(), "duplicate oracle path");
    }
    ensure!(artifacts.insert(CATALOGUE_PATH.to_owned(), generated.catalogue_jcs().to_vec()).is_none(),
            "duplicate catalogue path");
    publish_artifacts(&output_root, &artifacts, image_id, &statement)
}

/// Re-read the exact nineteen-file closure, replay all oracles, and bind the statement.
///
/// # Errors
/// Rejects extra/missing/redirected/oversized artifacts, failed stock replay,
/// catalogue drift, or a different expected guest/statement claim.
pub fn verify_local_terminal_fixture_export(
    export_root: &Path,
    guest_elf: &[u8],
    expected_statement: &Path,
) -> Result<()> {
    let statement = read_bounded(expected_statement, 1, MAX_STATEMENT_BYTES)?;
    let image_id = expected_identity(guest_elf, &statement)?;
    let artifacts = read_export(&absolute_path(export_root)?)?;
    replay_artifacts(&artifacts, image_id, &statement)
}

fn expected_identity(guest_elf: &[u8], statement: &[u8]) -> Result<Digest> {
    ensure!(!guest_elf.is_empty() && guest_elf.len() <= MAX_GUEST_ELF_BYTES,
            "local terminal guest ELF length");
    let image_id = compute_image_id(guest_elf)?;
    validate_ergo_statement_v1(statement, &image_id)?;
    Ok(image_id)
}

fn validate_artifacts(artifacts: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    let specs = artifact_specs()?;
    ensure!(artifacts.len() == ARTIFACT_COUNT, "local terminal artifact count");
    for spec in specs {
        let bytes = artifacts.get(&spec.path).context("missing local terminal artifact")?;
        ensure!((spec.minimum..=spec.maximum).contains(&bytes.len()), "local terminal artifact length");
    }
    Ok(())
}

fn replay_artifacts(artifacts: &BTreeMap<String, Vec<u8>>, image_id: Digest, statement: &[u8]) -> Result<()> {
    validate_artifacts(artifacts)?;
    let mut raw = BTreeMap::new();
    let mut oracles = BTreeMap::new();
    for id in FIXTURE_IDS {
        let raw_path = terminal_fixture_raw_seal_path(id)?;
        let oracle_path = terminal_fixture_receipt_oracle_path(id)?;
        raw.insert(raw_path.clone(), artifacts[&raw_path].clone());
        oracles.insert(oracle_path.clone(), artifacts[&oracle_path].clone());
    }
    let replay = replay_fixed_terminal_oracles(&raw, &oracles)?;
    replay.bind_candidate_catalogue_jcs(&artifacts[CATALOGUE_PATH])?;
    // Inspect only the independently derived catalogue after complete replay.
    let catalogue = Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(&replay.derived_catalogue_jcs()?)?;
    ensure!(catalogue.program_id == hex::encode(image_id.as_bytes()), "local terminal expected guest mismatch");
    let expected = hex::encode(ReceiptClaim::ok(image_id, statement.to_vec()).digest().as_bytes());
    let mut successful = 0;
    for fixture in &catalogue.fixtures {
        if let B4ApplicationBindingV1::Direct { binding } = &fixture.application {
            if binding.status.ok {
                ensure!(binding.application_claim_digest == expected, "local terminal expected statement mismatch");
                successful += 1;
            }
        }
    }
    ensure!(successful == 7, "local terminal successful direct claim count");
    Ok(())
}

fn publish_artifacts(
    output_root: &Path, artifacts: &BTreeMap<String, Vec<u8>>, image_id: Digest, statement: &[u8],
) -> Result<PathBuf> {
    validate_artifacts(artifacts)?;
    require_empty_directory(output_root)?;
    let staging = output_root.join(STAGING_DIRECTORY);
    create_directory(&staging)?;
    let directories = expected_directories()?;
    for relative in &directories {
        if !relative.as_os_str().is_empty() {
            create_directory(&staging.join(relative))?;
        }
    }
    for spec in artifact_specs()? {
        write_new(&staging.join(&spec.path), &artifacts[&spec.path])?;
    }
    let reread = read_export(&staging)?;
    ensure!(&reread == artifacts, "local terminal staging readback mismatch");
    replay_artifacts(&reread, image_id, statement)?;
    for directory in directories.iter().rev() {
        sync_directory(&staging.join(directory))?;
    }
    // Recheck physical paths and exact entries immediately before exclusive rename.
    require_directory(output_root)?;
    ensure!(bounded_names(output_root, 1)? == BTreeSet::from([STAGING_DIRECTORY.to_owned()]),
            "local terminal output root changed before publication");
    ensure!(read_export(&staging)? == reread, "local terminal staging changed before publication");
    let destination = output_root.join(FINAL_DIRECTORY);
    renamore::rename_exclusive(&staging, &destination).context("local terminal exclusive publication failed")?;
    sync_directory(output_root)?;
    ensure!(read_export(&destination)? == reread, "local terminal publication readback mismatch");
    Ok(destination)
}

fn expected_directories() -> Result<BTreeSet<PathBuf>> {
    let mut directories = BTreeSet::from([PathBuf::new()]);
    for spec in artifact_specs()? {
        let mut parent = Path::new(&spec.path).parent();
        while let Some(path) = parent {
            directories.insert(path.to_owned());
            parent = path.parent();
        }
    }
    Ok(directories)
}

fn read_export(root: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    require_directory(root)?;
    let specs = artifact_specs()?;
    let directories = expected_directories()?;
    for relative in &directories {
        let directory = root.join(relative);
        require_directory(&directory)?;
        let expected = directories.iter().map(PathBuf::as_path).filter(|path| path.parent() == Some(relative.as_path()))
            .chain(specs.iter().map(|spec| Path::new(&spec.path))
                .filter(|path| path.parent() == Some(relative.as_path())))
            .map(|path| path.file_name().context("closed inventory has no leaf")
                .and_then(|leaf| leaf.to_str().context("closed inventory is not UTF-8")).map(str::to_owned))
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(bounded_names(&directory, expected.len())? == expected, "local terminal directory inventory mismatch");
    }
    let mut artifacts = BTreeMap::new();
    for spec in specs {
        artifacts.insert(spec.path.clone(), read_bounded(&root.join(&spec.path), spec.minimum, spec.maximum)?);
    }
    validate_artifacts(&artifacts)?;
    Ok(artifacts)
}

fn bounded_names(directory: &Path, maximum: usize) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(directory)? {
        ensure!(names.len() < maximum, "extra local terminal directory entry");
        let entry = entry?;
        let name = entry.file_name().into_string().map_err(|_| anyhow::anyhow!("non-UTF-8 directory entry"))?;
        ensure!(names.insert(name), "duplicate local terminal directory entry");
    }
    Ok(names)
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    ensure!(!path.as_os_str().is_empty() && !path.components().any(|part| matches!(part, Component::ParentDir)),
            "empty or parent-traversing local terminal path");
    std::path::absolute(path).context("cannot make local terminal path absolute")
}

fn require_directory(path: &Path) -> Result<()> {
    let path = absolute_path(path)?;
    let mut ancestor = PathBuf::new();
    for component in path.components() {
        ancestor.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) { continue; }
        let metadata = fs::symlink_metadata(&ancestor)?;
        ensure!(metadata.is_dir() && !metadata.file_type().is_symlink() && !is_reparse_point(&metadata),
                "local terminal directory is redirected or not ordinary");
    }
    Ok(())
}

fn require_empty_directory(path: &Path) -> Result<()> {
    require_directory(path)?;
    ensure!(fs::read_dir(path)?.next().is_none(), "local terminal output root is not empty");
    Ok(())
}

fn read_bounded(path: &Path, minimum: usize, maximum: usize) -> Result<Vec<u8>> {
    let path = absolute_path(path)?;
    require_directory(path.parent().context("artifact has no parent")?)?;
    let before = fs::symlink_metadata(&path)?;
    ensure!(before.is_file() && !before.file_type().is_symlink() && !is_reparse_point(&before),
            "local terminal source is not a regular non-link file");
    ensure!((minimum as u64..=maximum as u64).contains(&before.len()), "local terminal source byte bound");
    let file = File::open(&path)?;
    let opened = file.metadata()?;
    ensure!(opened.is_file() && !is_reparse_point(&opened) && opened.len() == before.len(),
            "local terminal source changed at open");
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len())?);
    file.take(u64::try_from(maximum)?.checked_add(1).context("source bound overflow")?)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 == opened.len() && (minimum..=maximum).contains(&bytes.len()),
            "local terminal source changed length");
    require_directory(path.parent().context("artifact has no parent")?)?;
    let after = fs::symlink_metadata(&path)?;
    ensure!(after.is_file() && !after.file_type().is_symlink() && !is_reparse_point(&after)
            && after.len() == opened.len(), "local terminal source changed after read");
    Ok(bytes)
}

fn create_directory(path: &Path) -> Result<()> {
    require_directory(path.parent().context("directory has no parent")?)?;
    fs::create_dir(path)?;
    require_directory(path)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    require_directory(path.parent().context("artifact has no parent")?)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    ensure!(read_bounded(path, bytes.len(), bytes.len())? == bytes, "local terminal file readback mismatch");
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    require_directory(path)?;
    File::open(path)?.sync_all().context("local terminal directory sync")
}

#[cfg(not(unix))]
fn sync_directory(path: &Path) -> Result<()> {
    require_directory(path)
}

#[cfg(windows)]
fn is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    metadata.file_attributes() & 0x0400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_: &Metadata) -> bool { false }

#[cfg(test)]
mod tests {
    use super::*;

    fn shape_only_artifacts() -> BTreeMap<String, Vec<u8>> {
        artifact_specs().unwrap().into_iter().map(|spec| (spec.path, vec![0; spec.minimum])).collect()
    }

    fn write_shape_only_tree(root: &Path) {
        for directory in expected_directories().unwrap() {
            if !directory.as_os_str().is_empty() { create_directory(&root.join(directory)).unwrap(); }
        }
        for (path, bytes) in shape_only_artifacts() { write_new(&root.join(path), &bytes).unwrap(); }
    }

    #[test]
    fn local_terminal_inventory_has_exact_bounds_and_identity_first() {
        let specs = artifact_specs().unwrap();
        assert_eq!(specs.len(), 19);
        assert_eq!(specs[0].maximum, 262_144);
        assert_eq!(FIXTURE_IDS, B4_TERMINAL_FIXTURE_LAYOUT.map(|row| row.fixture_id));
        assert_eq!(B4_TERMINAL_FIXTURE_LAYOUT[0].expected_family, Some("identity"));
        for pair in specs[1..].chunks_exact(2) {
            assert_eq!((pair[0].minimum, pair[0].maximum), (222_668, 222_668));
            assert_eq!((pair[1].minimum, pair[1].maximum), (1, 1_048_576));
        }
    }

    #[test]
    fn local_terminal_bounds_and_create_new_are_enforced() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("input");
        write_new(&path, b"abc").unwrap();
        assert_eq!(read_bounded(&path, 3, 3).unwrap(), b"abc");
        assert!(read_bounded(&path, 1, 2).unwrap_err().to_string().contains("byte bound"));
        assert!(read_bounded(&path, 4, 4).is_err());
        assert!(write_new(&path, b"xyz").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"abc");
        assert!(absolute_path(&root.path().join("../escape")).is_err());
        assert!(require_empty_directory(root.path()).is_err());
    }

    #[test]
    fn local_terminal_inventory_rejects_missing_extra_and_wrong_sizes() {
        let root = tempfile::tempdir().unwrap();
        write_shape_only_tree(root.path());
        assert_eq!(read_export(root.path()).unwrap(), shape_only_artifacts());
        let extra = root.path().join("extra");
        write_new(&extra, b"x").unwrap();
        assert!(read_export(root.path()).is_err());
        fs::remove_file(extra).unwrap();
        let path = root.path().join(CATALOGUE_PATH);
        fs::remove_file(&path).unwrap();
        assert!(read_export(root.path()).is_err());
        write_new(&path, b"").unwrap();
        assert!(read_export(root.path()).is_err());
    }

    #[test]
    fn local_terminal_invalid_oracles_never_publish_and_staging_is_retained() {
        let root = tempfile::tempdir().unwrap();
        assert!(publish_artifacts(root.path(), &shape_only_artifacts(), Digest::ZERO, b"invalid").is_err());
        assert!(root.path().join(STAGING_DIRECTORY).is_dir());
        assert!(!root.path().join(FINAL_DIRECTORY).exists());
        assert!(publish_artifacts(root.path(), &shape_only_artifacts(), Digest::ZERO, b"invalid").is_err());
    }

    #[test]
    fn local_terminal_exclusive_rename_preserves_existing_destination() {
        let root = tempfile::tempdir().unwrap();
        let staging = root.path().join(STAGING_DIRECTORY);
        let destination = root.path().join(FINAL_DIRECTORY);
        create_directory(&staging).unwrap();
        create_directory(&destination).unwrap();
        assert!(renamore::rename_exclusive(&staging, &destination).is_err());
        assert!(staging.is_dir());
        assert!(destination.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn local_terminal_links_are_rejected_at_source_and_destination_parents() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        write_new(&source, b"x").unwrap();
        let link = root.path().join("source-link");
        symlink(&source, &link).unwrap();
        assert!(read_bounded(&link, 1, 1).is_err());
        let physical = root.path().join("physical");
        create_directory(&physical).unwrap();
        write_new(&physical.join("input"), b"x").unwrap();
        let parent_link = root.path().join("parent-link");
        symlink(&physical, &parent_link).unwrap();
        assert!(read_bounded(&parent_link.join("input"), 1, 1).is_err());
        assert!(create_directory(&parent_link.join("destination")).is_err());
        assert!(!physical.join("destination").exists());
    }

    #[cfg(feature = "embedded-method")]
    #[test]
    #[ignore = "requires genuine five-input terminal sources; runs the fixed nine-fixture prover"]
    fn real_local_terminal_fixture_export_roundtrip() {
        let input = |name| PathBuf::from(std::env::var_os(name).expect("required genuine input path"));
        let statement = input("EIP0045_B4_TERMINAL_STATEMENT");
        // Preserve the real attempt even if proving or a subsequent gate fails.
        let root = tempfile::tempdir().unwrap().keep();
        let export = generate_local_terminal_fixture_export(
            &root, eip_0045_methods::EIP_0045_GUEST_ELF, &statement,
            &input("EIP0045_B4_LIFT15_RECEIPT_ORACLE"),
            &input("EIP0045_B4_TERMINAL_JOIN_RECURSIVE_ORACLE"),
            &input("EIP0045_B4_TERMINAL_RESOLVE_RECURSIVE_ORACLE"),
        ).unwrap();
        verify_local_terminal_fixture_export(&export, eip_0045_methods::EIP_0045_GUEST_ELF, &statement).unwrap();
        assert_eq!(read_export(&export).unwrap().len(), ARTIFACT_COUNT);
        let wrong = root.join("wrong-statement.bin");
        let mut bytes = fs::read(&statement).unwrap();
        assert!(bytes.len() > 159, "the real statement mutant requires a nonempty payload");
        *bytes.last_mut().unwrap() ^= 1;
        write_new(&wrong, &bytes).unwrap();
        assert!(verify_local_terminal_fixture_export(&export, eip_0045_methods::EIP_0045_GUEST_ELF, &wrong)
            .unwrap_err().to_string().contains("expected statement mismatch"));
    }
}
