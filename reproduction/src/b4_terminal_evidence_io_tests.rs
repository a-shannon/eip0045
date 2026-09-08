use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(target_os = "linux")]
use std::os::fd::AsFd as _;
#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
use std::os::fd::BorrowedFd;

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
use std::collections::BTreeMap;

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
use anyhow::{Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
use crate::b4_terminal_evidence_packet::{
    preflight_b4_terminal_evidence_publication_from_directory_descriptor,
    publish_b4_terminal_evidence_packet_from_directory_descriptor,
};
#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
use crate::b4_terminal_evidence_packet::{
    B4_TERMINAL_EVIDENCE_FILE_COUNT, B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT,
    B4MechanicalTerminalEvidencePublicationImageV1, Eip0045B4TerminalEvidenceCompletionV1,
    Eip0045B4TerminalEvidenceManifestV1, mechanical_b4_terminal_evidence_publication_for_test,
};
use crate::b4_terminal_evidence_packet::{
    B4PreparedTerminalEvidencePublicationV1, B4TerminalEvidenceDirectPairPayloadV1,
    B4TerminalEvidenceFixturePairPayloadV1, B4TerminalEvidencePacketPayloadsV1,
    B4TerminalEvidenceProducerSourcesV1, B4TerminalEvidenceProfilePayloadsV1,
    B4TerminalEvidencePublicationLayoutV1, prepare_b4_terminal_evidence_publication,
    project_b4_terminal_evidence_publication_layout,
};
#[cfg(feature = "b4-terminal-evidence-publication")]
use crate::b4_terminal_evidence_packet::{
    B4VerifiedTerminalEvidencePacketV1, preflight_b4_terminal_evidence_publication,
    publish_b4_terminal_evidence_packet,
};

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
use super::{
    MechanicalPacketIdentity, PublicationTestFault, PublicationTestPause,
    PublicationTestReopenSeam, PublicationTestTransition,
    publish_b4_terminal_evidence_packet_with_test_preflight_fault,
    publish_prepared_b4_terminal_evidence_from_directory_descriptor_with_test_seam,
    publish_prepared_b4_terminal_evidence_with_test_seam,
    publish_prepared_b4_terminal_evidence_with_test_seam_and_trace,
    unix_publication_platform_supported,
};
use super::{
    ReopenTestEvent, reopen_b4_terminal_evidence_packet,
    reopen_b4_terminal_evidence_packet_with_hook,
};

const MANIFEST: &str = "B4-TERMINAL-EVIDENCE-MANIFEST.json";
const COMPLETION: &str = "B4-TERMINAL-EVIDENCE-COMPLETE.json";
const ACCEPTED_PUBLICATION_FINAL_COMPONENTS: &[&str] =
    &["packet", "packet-01", "packet_evidence.json"];
const REJECTED_PUBLICATION_FINAL_COMPONENTS: &[&str] =
    &["Uppercase", "évidence", "con", "trailing."];

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
fn projected_staging_path(destination: &Path) -> PathBuf {
    project_b4_terminal_evidence_publication_layout(destination)
        .unwrap()
        .reserved_staging_path()
        .to_path_buf()
}

struct ClosedImage {
    temporary: TempDir,
    root: PathBuf,
}

impl ClosedImage {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("packet");
        fs::create_dir(&root).unwrap();
        for (index, (path, minimum, _maximum)) in test_roles().iter().enumerate() {
            let bytes = vec![u8::try_from(index + 1).unwrap(); *minimum];
            write_file(&root.join(path), &bytes);
        }
        rewrite_documents(&root, None, true);
        Self { temporary, root }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }
}

#[test]
fn reopen_public_api_returns_only_verified_authority() {
    let _: fn(
        &Path,
    ) -> anyhow::Result<
        crate::b4_terminal_evidence_packet::B4VerifiedTerminalEvidencePacketV1,
    > = reopen_b4_terminal_evidence_packet;
}

#[test]
fn reopen_public_surface_is_packet_module_only() {
    let _: fn(
        &Path,
    ) -> anyhow::Result<
        crate::b4_terminal_evidence_packet::B4VerifiedTerminalEvidencePacketV1,
    > = crate::b4_terminal_evidence_packet::reopen_b4_terminal_evidence_packet;

    let lib_source = include_str!("lib.rs");
    assert!(lib_source.contains("pub(crate) mod b4_terminal_evidence_io;"));
    assert!(!lib_source.contains("pub mod b4_terminal_evidence_io;"));

    let packet_source = include_str!("b4_terminal_evidence_packet.rs");
    assert!(packet_source.contains(
        "project_b4_terminal_evidence_publication_layout,\n    reopen_b4_terminal_evidence_packet,"
    ));
}

#[test]
fn reopen_publication_preparation_is_crate_private_non_authority() {
    let _: for<'a> fn(
        B4TerminalEvidencePacketPayloadsV1<'a>,
    ) -> anyhow::Result<B4PreparedTerminalEvidencePublicationV1> =
        prepare_b4_terminal_evidence_publication;
}

#[test]
fn reopen_publication_preparation_requires_full_consumer_semantics() {
    const PROFILE_MANIFEST: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin");
    const PROFILE_ALGORITHM: &[u8] =
        include_bytes!("../../profiles/risc0-v3-succinct/algorithm.txt");
    const PROFILE_CONSTANTS: &[u8] =
        include_bytes!("../../profiles/risc0-v3-succinct/constants.bin");

    let raw_seal = vec![0_u8; 222_668];
    let profile = B4TerminalEvidenceProfilePayloadsV1::new(
        PROFILE_MANIFEST,
        PROFILE_ALGORITHM,
        PROFILE_CONSTANTS,
    )
    .unwrap();
    let sources =
        B4TerminalEvidenceProducerSourcesV1::new(b"invalid-guest", b"s", b"0", b"8", b"9").unwrap();
    let fixtures = std::array::from_fn(|_| {
        B4TerminalEvidenceFixturePairPayloadV1::new(&raw_seal, b"o").unwrap()
    });
    let direct = B4TerminalEvidenceDirectPairPayloadV1::new(&raw_seal, b"d").unwrap();
    let payloads =
        B4TerminalEvidencePacketPayloadsV1::new(profile, sources, fixtures, b"c", direct).unwrap();
    let error = match prepare_b4_terminal_evidence_publication(payloads) {
        Ok(_) => panic!("semantically invalid payloads were prepared for publication"),
        Err(error) => error,
    };
    assert!(
        format!("{error:#}").contains("packet guest.elf is not a valid encoded RISC Zero program"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn reopen_rejects_missing_and_extra_tree_entries() {
    let missing = ClosedImage::new();
    fs::remove_file(missing.path("sources/guest.elf")).unwrap();
    assert!(reopen_b4_terminal_evidence_packet(&missing.root).is_err());

    let extra_file = ClosedImage::new();
    write_file(&extra_file.path("sources/extra.bin"), b"extra");
    assert!(reopen_b4_terminal_evidence_packet(&extra_file.root).is_err());

    let extra_directory = ClosedImage::new();
    fs::create_dir(extra_directory.path("unexpected")).unwrap();
    assert!(reopen_b4_terminal_evidence_packet(&extra_directory.root).is_err());
}

#[test]
fn reopen_exact_inventory_rejects_unexpected_name_before_retention() {
    let expected = ["expected".to_owned()].into_iter().collect();
    let mut observed = std::collections::BTreeSet::new();
    let error = super::record_expected_directory_entry(
        &mut observed,
        &expected,
        "unexpected",
        Path::new("packet"),
    )
    .unwrap_err();
    assert!(observed.is_empty());
    assert!(format!("{error:#}").contains("exact compiled terminal evidence shape"));
}

#[test]
fn reopen_rejects_manifest_or_completion_byte_mutation() {
    for document in [MANIFEST, COMPLETION] {
        let image = ClosedImage::new();
        let path = image.path(document);
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] ^= 1;
        fs::write(path, bytes).unwrap();
        assert!(reopen_b4_terminal_evidence_packet(&image.root).is_err());
    }
}

#[test]
fn reopen_rejects_unknown_noncanonical_reordered_length_and_digest_manifest() {
    let unknown = ClosedImage::new();
    mutate_manifest(&unknown.root, |value| {
        value["unknown"] = Value::from(0);
    });
    assert!(reopen_b4_terminal_evidence_packet(&unknown.root).is_err());

    let noncanonical = ClosedImage::new();
    let path = noncanonical.path(MANIFEST);
    let mut bytes = fs::read(&path).unwrap();
    bytes.push(b'\n');
    fs::write(&path, &bytes).unwrap();
    rewrite_completion(&noncanonical.root, &bytes);
    assert!(reopen_b4_terminal_evidence_packet(&noncanonical.root).is_err());

    let reordered = ClosedImage::new();
    mutate_manifest(&reordered.root, |value| {
        value["files"].as_array_mut().unwrap().swap(0, 1);
    });
    assert!(reopen_b4_terminal_evidence_packet(&reordered.root).is_err());

    let wrong_length = ClosedImage::new();
    mutate_manifest(&wrong_length.root, |value| {
        let row = value["files"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|row| row["path"] == "sources/guest.elf")
            .unwrap();
        row["byteLength"] = Value::from(2_u64);
    });
    assert!(reopen_b4_terminal_evidence_packet(&wrong_length.root).is_err());

    let wrong_digest = ClosedImage::new();
    mutate_manifest(&wrong_digest.root, |value| {
        value["files"][0]["sha256"] = Value::from("00".repeat(32));
    });
    assert!(reopen_b4_terminal_evidence_packet(&wrong_digest.root).is_err());
}

#[test]
fn reopen_rejects_regular_file_hard_links() {
    let image = ClosedImage::new();
    let target = image.path("sources/statement.bin");
    let linked = image.path("sources/guest.elf");
    fs::remove_file(&linked).unwrap();
    fs::hard_link(target, linked).unwrap();
    rewrite_documents(&image.root, None, true);
    let error = require_reopen_error(reopen_b4_terminal_evidence_packet(&image.root));
    assert!(format!("{error:#}").contains("must have exactly one hard link"));
}

#[cfg(unix)]
#[test]
fn reopen_rejects_unix_symlinks() {
    use std::os::unix::fs::symlink;

    let image = ClosedImage::new();
    let linked = image.path("sources/guest.elf");
    fs::remove_file(&linked).unwrap();
    symlink("statement.bin", linked).unwrap();
    assert!(reopen_b4_terminal_evidence_packet(&image.root).is_err());
}

#[cfg(windows)]
#[test]
fn reopen_rejects_windows_reparse_points() {
    use std::process::Command;

    let image = ClosedImage::new();
    let derived = image.path("derived");
    let relocated = image.temporary.path().join("derived-relocated");
    fs::rename(&derived, &relocated).unwrap();
    let output = Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            derived.to_str().unwrap(),
            relocated.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cannot create test junction: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let error = require_reopen_error(reopen_b4_terminal_evidence_packet(&image.root));
    assert!(format!("{error:#}").contains("ordinary non-reparse directory"));
    let status = Command::new("cmd")
        .args(["/C", "rmdir", derived.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn reopen_rejects_same_size_replacement_between_identity_snapshots() {
    let image = ClosedImage::new();
    let target = image.path("sources/guest.elf");
    let displaced = image.temporary.path().join("displaced-guest.elf");
    let mut replaced = false;
    let result = reopen_b4_terminal_evidence_packet_with_hook(&image.root, |event, relative| {
        if !replaced && event == ReopenTestEvent::AfterFirstRead && relative == "sources/guest.elf"
        {
            fs::rename(&target, &displaced).unwrap();
            fs::write(&target, [0xf0]).unwrap();
            replaced = true;
        }
    });
    assert!(replaced);
    let error = require_reopen_error(result);
    assert!(format!("{error:#}").contains("changed between stable-file snapshots"));
}

#[test]
fn reopen_rejects_size_change_between_identity_snapshots() {
    let image = ClosedImage::new();
    let target = image.path("sources/guest.elf");
    let mut changed = false;
    let result = reopen_b4_terminal_evidence_packet_with_hook(&image.root, |event, relative| {
        if !changed && event == ReopenTestEvent::AfterFirstRead && relative == "sources/guest.elf" {
            fs::write(&target, [0x01, 0x02]).unwrap();
            changed = true;
        }
    });
    assert!(changed);
    let error = require_reopen_error(result);
    assert!(format!("{error:#}").contains("changed between stable-file snapshots"));
}

#[cfg(target_os = "linux")]
#[test]
fn reopen_root_pin_reauthentication_rejects_substitution() {
    let image = ClosedImage::new();
    let root = image.root.clone();
    let moved_root = image.temporary.path().join("moved-packet");
    let pinned = super::PinnedUnixDirectoryPath::open(&root, "test packet root").unwrap();
    fs::rename(&root, &moved_root).unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(root.join("decoy-sentinel"), b"decoy").unwrap();
    let error = pinned.reauthenticate().unwrap_err();
    assert!(
        format!("{error:#}").contains("no longer names the pinned identity"),
        "root substitution did not fail at final path reauthentication: {error:#}"
    );
    assert_eq!(fs::read(root.join("decoy-sentinel")).unwrap(), b"decoy");
    assert!(moved_root.join(MANIFEST).is_file());
}

#[cfg(target_os = "linux")]
#[test]
fn reopen_from_retained_directory_descriptor_ignores_replacement_pathname() {
    let image = ClosedImage::new();
    let root = image.root.clone();
    let moved_root = image.temporary.path().join("moved-packet");
    let retained = fs::File::open(&root).unwrap();

    fs::rename(&root, &moved_root).unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(root.join("decoy-sentinel"), b"decoy").unwrap();

    let error = require_reopen_error(
        crate::b4_terminal_evidence_packet::
            reopen_b4_terminal_evidence_packet_from_directory_descriptor(retained.as_fd()),
    );
    assert!(
        format!("{error:#}").contains("cannot decode the authenticated initial profile manifest"),
        "descriptor-rooted reopen followed the replacement pathname: {error:#}"
    );
    assert_eq!(fs::read(root.join("decoy-sentinel")).unwrap(), b"decoy");
    assert!(moved_root.join(MANIFEST).is_file());
}

#[cfg(target_os = "linux")]
#[test]
fn reopen_descendant_substitution_during_measurement_returns_no_authority() {
    let image = ClosedImage::new();
    let sources = image.path("sources");
    let displaced_sources = image.path("displaced-sources");
    let mut changed = false;
    let result = reopen_b4_terminal_evidence_packet_with_hook(&image.root, |event, relative| {
        if !changed && event == ReopenTestEvent::AfterFirstRead && relative == MANIFEST {
            fs::rename(&sources, &displaced_sources).unwrap();
            fs::create_dir(&sources).unwrap();
            fs::write(sources.join("decoy-sentinel"), b"decoy").unwrap();
            changed = true;
        }
    });
    assert!(changed);
    let error = require_reopen_error(result);
    assert!(
        format!("{error:#}").contains("exact compiled terminal evidence shape")
            || format!("{error:#}").contains("directory identity changed"),
        "descendant substitution did not fail at descriptor reauthentication: {error:#}"
    );
    assert_eq!(fs::read(sources.join("decoy-sentinel")).unwrap(), b"decoy");
    assert!(displaced_sources.join("guest.elf").is_file());
}

#[test]
fn reopen_rejects_extra_entry_created_during_final_snapshot() {
    let image = ClosedImage::new();
    let extra = image.path("unexpected-final-entry");
    let mut changed = false;
    let result = reopen_b4_terminal_evidence_packet_with_hook(&image.root, |event, _relative| {
        if !changed && event == ReopenTestEvent::AfterFinalSnapshot {
            fs::write(&extra, b"late").unwrap();
            changed = true;
        }
    });
    assert!(changed);
    let error = require_reopen_error(result);
    assert!(format!("{error:#}").contains("exact compiled terminal evidence shape"));
}

#[test]
fn reopen_rejects_replacement_after_its_final_snapshot() {
    let image = ClosedImage::new();
    let relative = "derived/case-8-terminal-join-final.raw-seal.bin";
    let target = image.path(relative);
    let displaced = image
        .temporary
        .path()
        .join("displaced-case-8-terminal-join-final.raw-seal.bin");
    let replacement = vec![0x5a; 222_668];
    let mut changed = false;
    let result = reopen_b4_terminal_evidence_packet_with_hook(&image.root, |event, path| {
        if !changed && event == ReopenTestEvent::AfterFinalSnapshot && path == relative {
            fs::rename(&target, &displaced).unwrap();
            fs::write(&target, &replacement).unwrap();
            changed = true;
        }
    });
    assert!(changed);
    let error = require_reopen_error(result);
    assert!(
        format!("{error:#}").contains("changed on its retained final handle")
            || format!("{error:#}").contains("changed after its final snapshot"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn reopen_prepared_publication_is_the_only_crate_visible_owned_byte_seam() {
    let source = include_str!("b4_terminal_evidence_packet.rs");
    assert!(!source.contains("pub(crate) struct B4OwnedTerminalEvidencePacketPayloadsV1"));
    assert!(!source.contains(
        "pub(crate) fn into_owned(self) -> Result<B4OwnedTerminalEvidencePacketPayloadsV1>"
    ));
    assert!(source.contains("pub(crate) struct B4PreparedTerminalEvidencePublicationV1"));
}

#[test]
fn reopen_rejects_payload_larger_than_compiled_role_bound() {
    let image = ClosedImage::new();
    fs::write(
        image.path("sources/guest.elf"),
        vec![0_u8; 4 * 1024 * 1024 + 1],
    )
    .unwrap();
    let error = require_reopen_error(reopen_b4_terminal_evidence_packet(&image.root));
    assert!(format!("{error:#}").contains("exceeds its compiled role bound"));
}

#[test]
fn reopen_mechanically_closed_payloads_reach_semantic_verification() {
    let image = ClosedImage::new();
    let error = match reopen_b4_terminal_evidence_packet(&image.root) {
        Ok(_) => panic!("mechanically valid but semantically invalid image was accepted"),
        Err(error) => error,
    };
    assert!(
        format!("{error:#}").contains("cannot decode the authenticated initial profile manifest"),
        "unexpected error: {error:#}"
    );
}

fn mutate_manifest(root: &Path, mutate: impl FnOnce(&mut Value)) {
    let path = root.join(MANIFEST);
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    mutate(&mut value);
    let bytes = crate::canonical::canonical_json_bytes(&value).unwrap();
    fs::write(path, &bytes).unwrap();
    rewrite_completion(root, &bytes);
}

fn rewrite_documents(root: &Path, manifest_override: Option<Vec<Value>>, canonical: bool) {
    let files = manifest_override.unwrap_or_else(|| {
        test_roles()
            .iter()
            .map(|(path, _minimum, _maximum)| {
                let bytes = fs::read(root.join(path)).unwrap();
                json!({
                    "byteLength": u64::try_from(bytes.len()).unwrap(),
                    "path": path,
                    "sha256": hex::encode(Sha256::digest(&bytes)),
                })
            })
            .collect()
    });
    let value = json!({
        "files": files,
        "format": "Eip0045B4TerminalEvidenceManifestV1",
        "formatVersion": 1,
    });
    let bytes = if canonical {
        crate::canonical::canonical_json_bytes(&value).unwrap()
    } else {
        serde_json::to_vec(&value).unwrap()
    };
    fs::write(root.join(MANIFEST), &bytes).unwrap();
    rewrite_completion(root, &bytes);
}

fn rewrite_completion(root: &Path, manifest: &[u8]) {
    let value = json!({
        "format": "Eip0045B4TerminalEvidenceCompletionV1",
        "formatVersion": 1,
        "manifestByteLength": u64::try_from(manifest.len()).unwrap(),
        "manifestPath": MANIFEST,
        "manifestSha256": hex::encode(Sha256::digest(manifest)),
    });
    let bytes = crate::canonical::canonical_json_bytes(&value).unwrap();
    fs::write(root.join(COMPLETION), bytes).unwrap();
}

fn write_file(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn require_reopen_error(
    result: anyhow::Result<crate::b4_terminal_evidence_packet::B4VerifiedTerminalEvidencePacketV1>,
) -> anyhow::Error {
    match result {
        Ok(_) => panic!("terminal evidence reopen unexpectedly succeeded"),
        Err(error) => error,
    }
}

fn test_roles() -> Vec<(String, usize, usize)> {
    let mut roles = vec![
        ("sources/guest.elf".to_owned(), 1, 4 * 1024 * 1024),
        ("sources/statement.bin".to_owned(), 1, 16_543),
        (
            "sources/case-0-lift-15.receipt-oracle.bincode".to_owned(),
            1,
            1024 * 1024,
        ),
        (
            "sources/case-8-terminal-join.recursive-oracle.borsh".to_owned(),
            1,
            32 * 1024 * 1024,
        ),
        (
            "sources/case-9-terminal-resolve.recursive-oracle.borsh".to_owned(),
            1,
            32 * 1024 * 1024,
        ),
        (
            "profiles/risc0-v3-succinct/manifest.bin".to_owned(),
            458,
            458,
        ),
        (
            "profiles/risc0-v3-succinct/algorithm.txt".to_owned(),
            29_773,
            29_773,
        ),
        (
            "profiles/risc0-v3-succinct/constants.bin".to_owned(),
            65_119,
            65_119,
        ),
    ];
    for fixture in [
        "allowed-terminal-non-ok",
        "join-povw",
        "join-unwrap-povw",
        "lift-po2-14",
        "lift-povw-po2-18",
        "resolve-povw",
        "resolve-unwrap-povw",
        "union",
        "unwrap-povw",
    ] {
        roles.push((
            format!(
                "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/{fixture}.raw-seal.bin"
            ),
            222_668,
            222_668,
        ));
        roles.push((
            format!(
                "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/{fixture}.receipt-oracle.bincode"
            ),
            1,
            1024 * 1024,
        ));
    }
    roles.extend([
        (
            "reproduction/schema/b4-corpus-v1.candidate/bindings/terminal-fixture-catalog.json"
                .to_owned(),
            1,
            256 * 1024,
        ),
        (
            "derived/case-8-terminal-join-final.raw-seal.bin".to_owned(),
            222_668,
            222_668,
        ),
        (
            "derived/case-8-terminal-join-final.receipt-oracle.bincode".to_owned(),
            1,
            1024 * 1024,
        ),
    ]);
    roles.sort_by(|left, right| left.0.cmp(&right.0));
    roles
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
fn publication_mechanical_reopen(root: &Path) -> Result<MechanicalPacketIdentity> {
    let manifest = fs::read(root.join(MANIFEST))?;
    let parsed = Eip0045B4TerminalEvidenceManifestV1::from_canonical_jcs(&manifest)?;
    let completion = fs::read(root.join(COMPLETION))?;
    Eip0045B4TerminalEvidenceCompletionV1::from_canonical_jcs(&completion)?
        .bind_manifest(&manifest)?;

    let mut expected = BTreeMap::new();
    expected.insert(MANIFEST.to_owned(), manifest.clone());
    expected.insert(COMPLETION.to_owned(), completion);
    for row in parsed.files {
        let bytes = fs::read(root.join(&row.path))?;
        ensure!(
            u64::try_from(bytes.len())? == row.byte_length
                && hex::encode(Sha256::digest(&bytes)) == row.sha256,
            "mechanical payload identity mismatch for {}",
            row.path
        );
        expected.insert(row.path, bytes);
    }
    ensure!(
        publication_tree_bytes(root)? == expected,
        "mechanical packet tree is not exact"
    );
    Ok(MechanicalPacketIdentity {
        manifest_byte_length: u64::try_from(manifest.len())?,
        packet_id: Sha256::digest(manifest).into(),
    })
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
fn publication_tree_bytes(root: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    fn visit(root: &Path, directory: &Path, files: &mut BTreeMap<String, Vec<u8>>) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                !metadata.file_type().is_symlink(),
                "test tree contains a symlink"
            );
            if metadata.is_dir() {
                visit(root, &path, files)?;
            } else {
                ensure!(metadata.is_file(), "test tree contains a special file");
                let relative = path
                    .strip_prefix(root)?
                    .components()
                    .map(|component| component.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                ensure!(
                    files.insert(relative, fs::read(&path)?).is_none(),
                    "duplicate test-tree path"
                );
            }
        }
        Ok(())
    }

    let mut files = BTreeMap::new();
    visit(root, root, &mut files)?;
    Ok(files)
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
fn write_publication_tree_bytes(root: &Path, files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    fs::create_dir(root)?;
    for (relative, bytes) in files {
        write_file(&root.join(relative), bytes);
    }
    Ok(())
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
fn replace_directory_identity_preserving_leaf_objects(live: &Path, displaced: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let original_directory_inode = fs::metadata(live)?.ino();
    let original_entries = fs::read_dir(live)?
        .map(|entry| {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "identity-isolation fixture requires one leaf directory"
            );
            Ok((
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("fixture entry is not UTF-8"))?,
                metadata.ino(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    ensure!(
        !original_entries.is_empty(),
        "identity-isolation fixture directory is empty"
    );

    fs::rename(live, displaced)?;
    fs::create_dir(live)?;
    for entry in fs::read_dir(displaced)? {
        let entry = entry?;
        fs::rename(entry.path(), live.join(entry.file_name()))?;
    }

    ensure!(
        fs::metadata(live)?.ino() != original_directory_inode,
        "fixture did not replace the directory inode"
    );
    ensure!(
        fs::read_dir(displaced)?.next().is_none(),
        "fixture did not move every leaf object"
    );
    for (name, inode) in original_entries {
        ensure!(
            fs::metadata(live.join(name))?.ino() == inode,
            "fixture changed a retained leaf inode"
        );
    }
    Ok(())
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
fn publication_with_fault(
    destination: &Path,
    prepared: &B4MechanicalTerminalEvidencePublicationImageV1,
    fault: PublicationTestFault<'_>,
) -> Result<MechanicalPacketIdentity> {
    let mut staged = publication_mechanical_reopen;
    let mut final_reopen = publication_mechanical_reopen;
    publish_prepared_b4_terminal_evidence_with_test_seam(
        destination,
        prepared,
        Some(fault),
        PublicationTestReopenSeam {
            staged: &mut staged,
            final_reopen: &mut final_reopen,
        },
    )
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
fn publication_without_fault(
    destination: &Path,
    prepared: &B4MechanicalTerminalEvidencePublicationImageV1,
) -> Result<MechanicalPacketIdentity> {
    let mut staged = publication_mechanical_reopen;
    let mut final_reopen = publication_mechanical_reopen;
    publish_prepared_b4_terminal_evidence_with_test_seam(
        destination,
        prepared,
        None,
        PublicationTestReopenSeam {
            staged: &mut staged,
            final_reopen: &mut final_reopen,
        },
    )
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
fn publication_expected_directory_syncs() -> Vec<String> {
    [
        "sources",
        "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures",
        "reproduction/schema/b4-corpus-v1.candidate/bindings",
        "reproduction/schema/b4-corpus-v1.candidate",
        "reproduction/schema",
        "reproduction",
        "profiles/risc0-v3-succinct",
        "profiles",
        "derived",
        ".",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
fn publication_expected_trace() -> Vec<PublicationTestTransition> {
    let mut expected = vec![PublicationTestTransition::ParentPinned];
    expected.extend(
        (0..B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT).map(PublicationTestTransition::PayloadSynced),
    );
    expected.extend([
        PublicationTestTransition::ManifestSynced,
        PublicationTestTransition::CompletionSynced,
        PublicationTestTransition::StagedReopened,
    ]);
    expected.extend(
        publication_expected_directory_syncs()
            .into_iter()
            .map(PublicationTestTransition::DirectorySynced),
    );
    expected.extend([
        PublicationTestTransition::ReadyToExclusiveRename,
        PublicationTestTransition::ExclusiveRenamed,
        PublicationTestTransition::ParentSynced,
        PublicationTestTransition::FinalReopened,
    ]);
    expected
}

#[cfg(all(
    feature = "b4-terminal-evidence-publication",
    unix,
    target_os = "linux"
))]
fn publication_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("eip0045-terminal-evidence-publication-")
        .tempdir_in("/dev/shm")
        .unwrap()
}

#[cfg(all(
    feature = "b4-terminal-evidence-publication",
    unix,
    not(target_os = "linux")
))]
fn publication_tempdir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[cfg(feature = "b4-terminal-evidence-publication")]
fn publication_invalid_payloads(raw_seal: &[u8]) -> B4TerminalEvidencePacketPayloadsV1<'_> {
    const PROFILE_MANIFEST: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin");
    const PROFILE_ALGORITHM: &[u8] =
        include_bytes!("../../profiles/risc0-v3-succinct/algorithm.txt");
    const PROFILE_CONSTANTS: &[u8] =
        include_bytes!("../../profiles/risc0-v3-succinct/constants.bin");

    let profile = B4TerminalEvidenceProfilePayloadsV1::new(
        PROFILE_MANIFEST,
        PROFILE_ALGORITHM,
        PROFILE_CONSTANTS,
    )
    .unwrap();
    let sources =
        B4TerminalEvidenceProducerSourcesV1::new(b"invalid", b"s", b"0", b"8", b"9").unwrap();
    let fixtures = std::array::from_fn(|_| {
        B4TerminalEvidenceFixturePairPayloadV1::new(raw_seal, b"o").unwrap()
    });
    let direct = B4TerminalEvidenceDirectPairPayloadV1::new(raw_seal, b"d").unwrap();
    B4TerminalEvidencePacketPayloadsV1::new(profile, sources, fixtures, b"c", direct).unwrap()
}

#[test]
fn publication_layout_projector_has_the_narrow_public_surface() {
    let _: fn(&Path) -> anyhow::Result<B4TerminalEvidencePublicationLayoutV1> =
        project_b4_terminal_evidence_publication_layout;
    let layout = project_b4_terminal_evidence_publication_layout(Path::new("packet")).unwrap();
    let _: &Path = layout.final_path();
    let _: &Path = layout.parent();
    let _: &Path = layout.reserved_staging_path();

    let lib_source = include_str!("lib.rs");
    assert!(lib_source.contains("pub(crate) mod b4_terminal_evidence_io;"));
    assert!(!lib_source.contains("pub mod b4_terminal_evidence_io;"));
    let packet_source = include_str!("b4_terminal_evidence_packet.rs");
    assert!(packet_source.contains(
        "B4TerminalEvidencePublicationLayoutV1, project_b4_terminal_evidence_publication_layout,"
    ));
}

#[cfg(feature = "b4-terminal-evidence-publication")]
#[test]
fn publication_public_surface_has_only_the_two_feature_gated_actions() {
    let _: fn(&Path) -> anyhow::Result<()> = preflight_b4_terminal_evidence_publication;
    let _: for<'a> fn(
        &Path,
        B4TerminalEvidencePacketPayloadsV1<'a>,
    ) -> anyhow::Result<B4VerifiedTerminalEvidencePacketV1> = publish_b4_terminal_evidence_packet;

    let packet_source = include_str!("b4_terminal_evidence_packet.rs");
    assert!(packet_source.contains(
        "#[cfg(feature = \"b4-terminal-evidence-publication\")]\npub use crate::b4_terminal_evidence_io::{"
    ));
    assert!(packet_source.contains(
        "preflight_b4_terminal_evidence_publication, publish_b4_terminal_evidence_packet,"
    ));

    let io_source = include_str!("b4_terminal_evidence_io.rs");
    assert!(io_source.contains("PublicationReopenMode::Full(std::marker::PhantomData)"));
    assert!(io_source.contains("PublicationImage::Prepared(&prepared)"));
    assert!(io_source.contains(
        "PublicationReopenMode::Full(_) => reopen_b4_terminal_evidence_packet_from_descriptor("
    ));
    assert!(
        !io_source.contains(
            "reopen_b4_terminal_evidence_packet(root).map(PublicationReopenedPacket::Full)"
        )
    );
    for test_only in [
        "struct PublicationTestReopenSeam",
        "enum PublicationTestFault",
        "enum PublicationTestTransition",
        "fn publish_prepared_b4_terminal_evidence_with_test_seam(",
    ] {
        let offset = io_source.find(test_only).unwrap();
        let prefix = &io_source[offset.saturating_sub(160)..offset];
        assert!(
            prefix.contains("cfg(all(test, feature = \"b4-terminal-evidence-publication\", unix))"),
            "{test_only} is not test-only"
        );
    }
    let packet_source = include_str!("b4_terminal_evidence_packet.rs");
    assert_eq!(
        packet_source
            .matches("Ok(B4PreparedTerminalEvidencePublicationV1 {")
            .count(),
        1
    );
    assert!(packet_source.contains(
        "#[cfg(test)]\npub(crate) struct B4MechanicalTerminalEvidencePublicationImageV1"
    ));
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn publication_from_retained_parent_descriptor_has_a_narrow_public_surface() {
    let _: for<'parent> fn(BorrowedFd<'parent>, &str) -> anyhow::Result<()> =
        preflight_b4_terminal_evidence_publication_from_directory_descriptor;
    let _: for<'parent, 'payload> fn(
        BorrowedFd<'parent>,
        &str,
        B4TerminalEvidencePacketPayloadsV1<'payload>,
    ) -> anyhow::Result<B4VerifiedTerminalEvidencePacketV1> =
        publish_b4_terminal_evidence_packet_from_directory_descriptor;

    let packet_source = include_str!("b4_terminal_evidence_packet.rs");
    for descriptor_entry in [
        "preflight_b4_terminal_evidence_publication_from_directory_descriptor",
        "publish_b4_terminal_evidence_packet_from_directory_descriptor",
        "reopen_b4_terminal_evidence_packet_from_directory_descriptor",
    ] {
        assert!(
            packet_source.contains(descriptor_entry),
            "{descriptor_entry} is not re-exported by the packet module"
        );
    }
    let io_source = include_str!("b4_terminal_evidence_io.rs");
    for descriptor_entry in [
        "pub fn preflight_b4_terminal_evidence_publication_from_directory_descriptor(",
        "pub fn publish_b4_terminal_evidence_packet_from_directory_descriptor(",
        "pub fn reopen_b4_terminal_evidence_packet_from_directory_descriptor(",
    ] {
        let offset = io_source.find(descriptor_entry).unwrap();
        assert!(
            io_source[offset.saturating_sub(200)..offset].contains("#[doc(hidden)]"),
            "{descriptor_entry} must not broaden the documented public surface"
        );
    }

    let publish_offset = io_source
        .find("pub fn publish_b4_terminal_evidence_packet_from_directory_descriptor(")
        .unwrap();
    let publish_end = io_source[publish_offset..]
        .find("\n}\n\n#[cfg(")
        .map(|relative| publish_offset + relative)
        .unwrap();
    let publish_source = &io_source[publish_offset..publish_end];
    let repeated_preflight = publish_source
        .find("preflight_b4_terminal_evidence_publication_from_descriptor")
        .unwrap();
    let payload_preparation = publish_source
        .find("prepare_b4_terminal_evidence_publication")
        .unwrap();
    assert!(
        repeated_preflight < payload_preparation,
        "descriptor publication must repeat live preflight before payload preparation"
    );
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn descriptor_preflight_is_nonmutating_and_rejects_occupied_final_or_staging() {
    let temporary = publication_tempdir();
    let parent = temporary.path().join("parent");
    fs::create_dir(&parent).unwrap();
    fs::write(parent.join("sentinel"), b"unchanged").unwrap();
    let retained = fs::File::open(&parent).unwrap();

    let before = publication_tree_bytes(&parent).unwrap();
    preflight_b4_terminal_evidence_publication_from_directory_descriptor(
        retained.as_fd(),
        "packet",
    )
    .unwrap();
    assert_eq!(publication_tree_bytes(&parent).unwrap(), before);
    assert!(!parent.join("packet").exists());
    assert!(!parent
        .join(".packet.b4-terminal-evidence-publication-staging")
        .exists());

    fs::write(parent.join("occupied-final"), b"occupied final").unwrap();
    let occupied_final_before = publication_tree_bytes(&parent).unwrap();
    let final_error = preflight_b4_terminal_evidence_publication_from_directory_descriptor(
        retained.as_fd(),
        "occupied-final",
    )
    .unwrap_err();
    assert!(
        format!("{final_error:#}").contains("publication destination is already occupied"),
        "descriptor preflight missed occupied final: {final_error:#}"
    );
    assert_eq!(
        publication_tree_bytes(&parent).unwrap(),
        occupied_final_before
    );

    let staging = parent.join(".occupied-staging.b4-terminal-evidence-publication-staging");
    fs::create_dir(&staging).unwrap();
    fs::write(staging.join("sentinel"), b"occupied staging").unwrap();
    let occupied_staging_before = publication_tree_bytes(&parent).unwrap();
    let staging_error = preflight_b4_terminal_evidence_publication_from_directory_descriptor(
        retained.as_fd(),
        "occupied-staging",
    )
    .unwrap_err();
    assert!(
        format!("{staging_error:#}").contains("reserved publication staging is already occupied"),
        "descriptor preflight missed occupied staging: {staging_error:#}"
    );
    assert_eq!(
        publication_tree_bytes(&parent).unwrap(),
        occupied_staging_before
    );
    assert!(!parent.join("occupied-staging").exists());
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn descriptor_publication_repeats_live_preflight_after_an_external_check() {
    let temporary = publication_tempdir();
    let parent = temporary.path().join("parent");
    fs::create_dir(&parent).unwrap();
    let retained = fs::File::open(&parent).unwrap();

    preflight_b4_terminal_evidence_publication_from_directory_descriptor(
        retained.as_fd(),
        "packet",
    )
    .unwrap();
    fs::write(parent.join("packet"), b"occupied after preflight").unwrap();
    let before = publication_tree_bytes(&parent).unwrap();

    let raw_seal = vec![0_u8; 222_668];
    let invalid_payloads = publication_invalid_payloads(&raw_seal);
    let error = match publish_b4_terminal_evidence_packet_from_directory_descriptor(
        retained.as_fd(),
        "packet",
        invalid_payloads,
    ) {
        Ok(_) => panic!("descriptor publication ignored occupation after external preflight"),
        Err(error) => error,
    };

    assert!(
        format!("{error:#}").contains("publication destination is already occupied"),
        "descriptor publication did not repeat its live preflight: {error:#}"
    );
    assert_eq!(publication_tree_bytes(&parent).unwrap(), before);
    assert!(!parent
        .join(".packet.b4-terminal-evidence-publication-staging")
        .exists());
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn publication_from_retained_parent_descriptor_ignores_replacement_parent_pathname() {
    let temporary = publication_tempdir();
    let public_parent = temporary.path().join("public-parent");
    let retained_parent = temporary.path().join("retained-parent");
    fs::create_dir(&public_parent).unwrap();
    let retained = fs::File::open(&public_parent).unwrap();

    fs::rename(&public_parent, &retained_parent).unwrap();
    fs::create_dir(&public_parent).unwrap();
    fs::create_dir(public_parent.join("decoy-directory")).unwrap();
    fs::write(public_parent.join("decoy-sentinel"), b"decoy bytes").unwrap();
    fs::write(
        public_parent
            .join("decoy-directory")
            .join("nested-sentinel"),
        b"nested decoy bytes",
    )
    .unwrap();
    let decoy_before = publication_tree_bytes(&public_parent).unwrap();

    let prepared = mechanical_b4_terminal_evidence_publication_for_test(23).unwrap();
    let mut staged = publication_mechanical_reopen;
    let mut final_reopen = publication_mechanical_reopen;
    publish_prepared_b4_terminal_evidence_from_directory_descriptor_with_test_seam(
        retained.as_fd(),
        "packet",
        &prepared,
        PublicationTestReopenSeam {
            staged: &mut staged,
            final_reopen: &mut final_reopen,
        },
    )
    .unwrap();

    assert_eq!(
        publication_tree_bytes(&public_parent).unwrap(),
        decoy_before,
        "descriptor-rooted publication changed the replacement pathname"
    );
    assert!(
        !public_parent.join("packet").exists(),
        "descriptor-rooted publication followed the replacement pathname"
    );
    publication_mechanical_reopen(&retained_parent.join("packet")).unwrap();
    assert!(
        !retained_parent
            .join(".packet.b4-terminal-evidence-publication-staging")
            .exists(),
        "descriptor-rooted publication left its reserved staging name occupied"
    );
}

#[test]
fn pure_publication_layout_projection_is_portable_nonmutating_and_future_parent_safe() {
    let temp = tempfile::tempdir().unwrap();
    let future_parent = temp.path().join("future-outer-staging");
    let destination = future_parent.join("terminal-evidence-packet");
    let before = fs::read_dir(temp.path()).unwrap().count();

    let layout: B4TerminalEvidencePublicationLayoutV1 =
        project_b4_terminal_evidence_publication_layout(&destination).unwrap();

    assert_eq!(layout.final_path(), destination);
    assert_eq!(layout.parent(), future_parent);
    assert_eq!(
        layout.reserved_staging_path(),
        future_parent.join(".terminal-evidence-packet.b4-terminal-evidence-publication-staging")
    );
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), before);
    assert!(!future_parent.exists());
}

#[test]
fn publication_layout_projector_is_the_single_reproduction_staging_formula_owner() {
    let io_source = include_str!("b4_terminal_evidence_io.rs");
    assert_eq!(
        io_source
            .matches(".b4-terminal-evidence-publication-staging")
            .count(),
        1
    );
    assert!(!io_source.contains("fn b4_terminal_evidence_staging_path("));
    assert!(io_source.contains(
        "fn preflight_b4_terminal_evidence_publication_unix(\n    layout: &B4TerminalEvidencePublicationLayoutV1,"
    ));
    assert!(io_source.contains(
        "fn publish_prepared_b4_terminal_evidence_transaction(\n    layout: &B4TerminalEvidencePublicationLayoutV1,"
    ));
}

#[test]
fn publication_layout_projection_enforces_the_canonical_portable_component_contract() {
    for final_component in ACCEPTED_PUBLICATION_FINAL_COMPONENTS {
        let destination = Path::new("parent").join(final_component);
        let layout = project_b4_terminal_evidence_publication_layout(&destination).unwrap();
        assert_eq!(layout.final_path(), destination);
        assert_eq!(layout.parent(), Path::new("parent"));
    }

    for destination in [
        Path::new(""),
        Path::new("."),
        Path::new(".."),
        Path::new("/"),
    ] {
        assert!(project_b4_terminal_evidence_publication_layout(destination).is_err());
    }
    for final_component in REJECTED_PUBLICATION_FINAL_COMPONENTS {
        assert!(
            project_b4_terminal_evidence_publication_layout(Path::new(final_component)).is_err()
        );
    }

    let maximum = PathBuf::from("a".repeat(213));
    let maximum_layout = project_b4_terminal_evidence_publication_layout(&maximum).unwrap();
    assert_eq!(
        maximum_layout
            .reserved_staging_path()
            .file_name()
            .unwrap()
            .len(),
        255
    );
    let overlong = PathBuf::from("a".repeat(214));
    let error = match project_b4_terminal_evidence_publication_layout(&overlong) {
        Ok(_) => panic!("overlong derived staging component unexpectedly projected"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("213-byte derived staging bound"));

    let temp = tempfile::tempdir().unwrap();
    let sentinel = temp.path().join("sentinel");
    fs::write(&sentinel, b"unchanged").unwrap();
    let before = fs::read_dir(temp.path()).unwrap().count();
    assert!(
        project_b4_terminal_evidence_publication_layout(
            &temp.path().join(REJECTED_PUBLICATION_FINAL_COMPONENTS[0])
        )
        .is_err()
    );
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), before);
    assert_eq!(fs::read(&sentinel).unwrap(), b"unchanged");
}

#[cfg(all(
    feature = "b4-terminal-evidence-publication",
    any(target_os = "linux", target_vendor = "apple")
))]
#[test]
fn publication_layout_shared_corpus_has_projector_preflight_and_publication_parity() {
    let prepared = mechanical_b4_terminal_evidence_publication_for_test(14).unwrap();

    for final_component in ACCEPTED_PUBLICATION_FINAL_COMPONENTS {
        let temp = publication_tempdir();
        let destination = temp.path().join(final_component);
        let layout = project_b4_terminal_evidence_publication_layout(&destination).unwrap();

        preflight_b4_terminal_evidence_publication(&destination).unwrap();
        publication_without_fault(&destination, &prepared).unwrap();

        assert_eq!(layout.final_path(), destination);
        assert!(layout.final_path().is_dir());
        assert!(!layout.reserved_staging_path().exists());
    }

    for final_component in REJECTED_PUBLICATION_FINAL_COMPONENTS {
        let temp = publication_tempdir();
        let destination = temp.path().join(final_component);
        let before = fs::read_dir(temp.path()).unwrap().count();

        assert!(project_b4_terminal_evidence_publication_layout(&destination).is_err());
        assert!(preflight_b4_terminal_evidence_publication(&destination).is_err());
        assert!(publication_without_fault(&destination, &prepared).is_err());

        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), before);
    }
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
#[test]
fn live_preflight_projects_before_physical_path_checks() {
    let temp = publication_tempdir();
    let destination = temp.path().join("Uppercase-Forbidden");
    fs::write(&destination, b"occupied").unwrap();

    let error = preflight_b4_terminal_evidence_publication(&destination).unwrap_err();

    assert!(format!("{error:#}").contains("final component is not portable"));
    assert_eq!(fs::read(&destination).unwrap(), b"occupied");
}

#[cfg(all(
    feature = "b4-terminal-evidence-publication",
    any(target_os = "linux", target_vendor = "apple")
))]
#[test]
fn publication_preflight_is_nonmutating_and_rejects_occupied_or_untrusted_paths() {
    use std::os::unix::fs::symlink;

    let temp = publication_tempdir();
    let destination = temp.path().join("packet");
    let before = fs::read_dir(temp.path()).unwrap().count();
    preflight_b4_terminal_evidence_publication(&destination).unwrap();
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), before);
    assert!(!destination.exists());
    assert!(!projected_staging_path(&destination).exists());

    fs::write(&destination, b"occupied").unwrap();
    assert!(preflight_b4_terminal_evidence_publication(&destination).is_err());
    assert_eq!(fs::read(&destination).unwrap(), b"occupied");

    let absent_parent = temp.path().join("absent").join("packet");
    assert!(preflight_b4_terminal_evidence_publication(&absent_parent).is_err());
    assert!(!temp.path().join("absent").exists());

    let parent_file = temp.path().join("parent-file");
    fs::write(&parent_file, b"parent").unwrap();
    assert!(preflight_b4_terminal_evidence_publication(&parent_file.join("packet")).is_err());
    assert_eq!(fs::read(&parent_file).unwrap(), b"parent");

    let real_parent = temp.path().join("real-parent");
    fs::create_dir(&real_parent).unwrap();
    let linked_parent = temp.path().join("linked-parent");
    symlink(&real_parent, &linked_parent).unwrap();
    assert!(preflight_b4_terminal_evidence_publication(&linked_parent.join("packet")).is_err());
    assert!(fs::read_dir(&real_parent).unwrap().next().is_none());

    let real_child = real_parent.join("real-child");
    fs::create_dir(&real_child).unwrap();
    assert!(
        preflight_b4_terminal_evidence_publication(
            &linked_parent.join("real-child").join("packet")
        )
        .is_err()
    );
    assert!(fs::read_dir(&real_child).unwrap().next().is_none());

    let staging_destination = temp.path().join("staging-occupied");
    let staging = projected_staging_path(&staging_destination);
    fs::create_dir(&staging).unwrap();
    assert!(preflight_b4_terminal_evidence_publication(&staging_destination).is_err());
    assert!(staging.is_dir());
    assert!(!staging_destination.exists());

    let staging_symlink_destination = temp.path().join("staging-symlink");
    let staging_symlink = projected_staging_path(&staging_symlink_destination);
    symlink(&real_child, &staging_symlink).unwrap();
    assert!(preflight_b4_terminal_evidence_publication(&staging_symlink_destination).is_err());
    assert!(
        fs::symlink_metadata(&staging_symlink)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(!staging_symlink_destination.exists());

    let dangling_destination = temp.path().join("staging-dangling");
    let dangling_staging = projected_staging_path(&dangling_destination);
    symlink(temp.path().join("does-not-exist"), &dangling_staging).unwrap();
    assert!(preflight_b4_terminal_evidence_publication(&dangling_destination).is_err());
    assert!(
        fs::symlink_metadata(&dangling_staging)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(!dangling_destination.exists());
}

#[cfg(all(
    feature = "b4-terminal-evidence-publication",
    any(target_os = "linux", target_vendor = "apple")
))]
#[test]
fn publication_atomic_capability_failure_precedes_preparation_and_mutation() {
    let temp = publication_tempdir();
    let destination = temp.path().join("packet");
    let raw_seal = vec![0_u8; 222_668];
    let invalid_payloads = publication_invalid_payloads(&raw_seal);
    let error = publish_b4_terminal_evidence_packet_with_test_preflight_fault(
        &destination,
        invalid_payloads,
        PublicationTestFault::AtomicUnsupported,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("atomic no-replace"));
    assert!(
        !format!("{error:#}").contains("packet guest.elf is not a valid encoded RISC Zero program")
    );
    assert!(!destination.exists());
    assert!(!projected_staging_path(&destination).exists());
}

#[cfg(all(
    feature = "b4-terminal-evidence-publication",
    any(target_os = "linux", target_vendor = "apple")
))]
#[test]
fn publication_every_pre_rename_failure_retains_only_forensic_staging_and_never_resumes_it() {
    let prepared = mechanical_b4_terminal_evidence_publication_for_test(2).unwrap();
    let mut faults = vec![
        PublicationTestFault::StagingCreate,
        PublicationTestFault::ManifestWrite,
        PublicationTestFault::CompletionWrite,
        PublicationTestFault::StagedReopen,
    ];
    faults.extend((0..B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT).map(PublicationTestFault::PayloadWrite));
    faults.extend((0..B4_TERMINAL_EVIDENCE_FILE_COUNT).map(PublicationTestFault::FileSync));
    faults.extend(
        (0..publication_expected_directory_syncs().len()).map(PublicationTestFault::DirectorySync),
    );

    for (case, fault) in faults.into_iter().enumerate() {
        let temp = publication_tempdir();
        let destination = temp.path().join(format!("packet-{case}"));
        let staging = projected_staging_path(&destination);
        let error = publication_with_fault(&destination, &prepared, fault)
            .expect_err(&format!("fault {case} unexpectedly succeeded"));
        assert!(!destination.exists(), "fault {case} exposed a final tree");
        if matches!(fault, PublicationTestFault::StagingCreate) {
            assert!(!staging.exists());
            continue;
        }
        assert!(staging.is_dir(), "fault {case} did not retain staging");
        assert!(
            format!("{error:#}").contains(&staging.display().to_string()),
            "fault {case} omitted exact retained staging path: {error:#}"
        );
        let retained = publication_tree_bytes(&staging).unwrap();
        assert!(
            publication_without_fault(&destination, &prepared).is_err(),
            "fault {case} retry resumed abandoned staging"
        );
        assert!(!destination.exists());
        assert_eq!(
            publication_tree_bytes(&staging).unwrap(),
            retained,
            "fault {case} retry modified abandoned staging"
        );
    }
}

#[cfg(all(
    feature = "b4-terminal-evidence-publication",
    any(target_os = "linux", target_vendor = "apple")
))]
#[test]
fn publication_race_winner_is_never_reopened_replaced_or_returned() {
    let temp = publication_tempdir();
    let destination = temp.path().join("packet");
    let staging = projected_staging_path(&destination);
    let losing = mechanical_b4_terminal_evidence_publication_for_test(3).unwrap();
    let winner = mechanical_b4_terminal_evidence_publication_for_test(4).unwrap();
    let final_reopens = std::cell::Cell::new(0_u8);
    let mut staged = publication_mechanical_reopen;
    let mut final_reopen = |root: &Path| {
        final_reopens.set(final_reopens.get() + 1);
        publication_mechanical_reopen(root)
    };
    let error = publish_prepared_b4_terminal_evidence_with_test_seam(
        &destination,
        &losing,
        Some(PublicationTestFault::RaceWinner(&winner)),
        PublicationTestReopenSeam {
            staged: &mut staged,
            final_reopen: &mut final_reopen,
        },
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains(&staging.display().to_string()));
    assert!(format!("{error:#}").contains("terminal-evidence publication occupation"));
    assert_eq!(final_reopens.get(), 0);
    assert!(staging.is_dir());
    let winner_identity = publication_mechanical_reopen(&destination).unwrap();
    let expected_winner_id: [u8; 32] = Sha256::digest(winner.manifest_bytes()).into();
    assert_eq!(winner_identity.packet_id, expected_winner_id);
    let retained = publication_tree_bytes(&destination).unwrap();
    assert!(publication_without_fault(&destination, &losing).is_err());
    assert_eq!(publication_tree_bytes(&destination).unwrap(), retained);
}

#[cfg(all(
    feature = "b4-terminal-evidence-publication",
    any(target_os = "linux", target_vendor = "apple")
))]
#[test]
fn publication_post_rename_failures_leave_one_complete_occupied_destination() {
    let prepared = mechanical_b4_terminal_evidence_publication_for_test(5).unwrap();
    for fault in [
        PublicationTestFault::ParentSync,
        PublicationTestFault::FinalReopen,
    ] {
        let temp = publication_tempdir();
        let destination = temp.path().join("packet");
        assert!(publication_with_fault(&destination, &prepared, fault).is_err());
        publication_mechanical_reopen(&destination).unwrap();
        assert!(!projected_staging_path(&destination).exists());
        let retained = publication_tree_bytes(&destination).unwrap();
        assert!(publication_without_fault(&destination, &prepared).is_err());
        assert_eq!(publication_tree_bytes(&destination).unwrap(), retained);
    }
}

#[cfg(all(
    feature = "b4-terminal-evidence-publication",
    any(target_os = "linux", target_vendor = "apple")
))]
#[test]
fn publication_every_final_directory_sync_failure_is_causal() {
    let prepared = mechanical_b4_terminal_evidence_publication_for_test(5).unwrap();
    for (index, relative) in publication_expected_directory_syncs()
        .into_iter()
        .enumerate()
    {
        let temp = publication_tempdir();
        let destination = temp.path().join(format!("packet-{index}"));
        let error = publication_with_fault(
            &destination,
            &prepared,
            PublicationTestFault::FinalDirectorySync(index),
        )
        .expect_err(&format!(
            "final directory sync fault {index} unexpectedly returned authority"
        ));
        assert!(
            format!("{error:#}")
                .contains("injected final durability directory synchronization failure"),
            "final directory sync fault {index} missed its exact gate: {error:#}"
        );
        let expected_path = if relative == "." {
            destination.clone()
        } else {
            destination.join(&relative)
        };
        assert!(
            format!("{error:#}").contains(&expected_path.display().to_string()),
            "final directory sync fault {index} omitted {}: {error:#}",
            expected_path.display()
        );
        publication_mechanical_reopen(&destination).unwrap();
        assert!(!projected_staging_path(&destination).exists());
    }
}

#[cfg(all(
    feature = "b4-terminal-evidence-publication",
    any(target_os = "linux", target_vendor = "apple")
))]
#[test]
fn publication_final_reopen_rejects_replacement_and_distinct_valid_identity() {
    let temp = publication_tempdir();
    let first_destination = temp.path().join("first");
    let second_destination = temp.path().join("second");
    let first = mechanical_b4_terminal_evidence_publication_for_test(6).unwrap();
    let second = mechanical_b4_terminal_evidence_publication_for_test(7).unwrap();
    let second_identity = publication_without_fault(&second_destination, &second).unwrap();

    let mut staged = publication_mechanical_reopen;
    let mut replaced = |_root: &Path| bail!("mechanical final reopen detected replacement");
    let replacement_error = publish_prepared_b4_terminal_evidence_with_test_seam(
        &first_destination,
        &first,
        None,
        PublicationTestReopenSeam {
            staged: &mut staged,
            final_reopen: &mut replaced,
        },
    )
    .unwrap_err();
    assert!(format!("{replacement_error:#}").contains("detected replacement"));
    publication_mechanical_reopen(&first_destination).unwrap();
    let first_snapshot = publication_tree_bytes(&first_destination).unwrap();
    assert!(publication_without_fault(&first_destination, &first).is_err());
    assert_eq!(
        publication_tree_bytes(&first_destination).unwrap(),
        first_snapshot
    );

    let third_destination = temp.path().join("third");
    let mut staged = publication_mechanical_reopen;
    let mut different = |_root: &Path| Ok(second_identity);
    let mut identity_trace = Vec::new();
    let identity_error = publish_prepared_b4_terminal_evidence_with_test_seam_and_trace(
        &third_destination,
        &first,
        None,
        PublicationTestReopenSeam {
            staged: &mut staged,
            final_reopen: &mut different,
        },
        &mut identity_trace,
    )
    .unwrap_err();
    assert!(format!("{identity_error:#}").contains("identity changed"));
    assert_eq!(identity_trace, publication_expected_trace());
    assert_ne!(
        publication_mechanical_reopen(&third_destination)
            .unwrap()
            .packet_id,
        second_identity.packet_id
    );
    let third_snapshot = publication_tree_bytes(&third_destination).unwrap();
    assert!(publication_without_fault(&third_destination, &second).is_err());
    assert_eq!(
        publication_tree_bytes(&third_destination).unwrap(),
        third_snapshot
    );
}

#[cfg(all(
    feature = "b4-terminal-evidence-publication",
    any(target_os = "linux", target_vendor = "apple")
))]
#[test]
fn publication_success_writes_exact_prepared_bytes_and_returns_final_identity() {
    let temp = publication_tempdir();
    let destination = temp.path().join("packet");
    let prepared = mechanical_b4_terminal_evidence_publication_for_test(8).unwrap();
    let authority = publication_without_fault(&destination, &prepared).unwrap();
    let reopened = publication_mechanical_reopen(&destination).unwrap();
    assert_eq!(authority, reopened);
    assert_eq!(
        fs::read(destination.join(MANIFEST)).unwrap(),
        prepared.manifest_bytes()
    );
    assert_eq!(
        fs::read(destination.join(COMPLETION)).unwrap(),
        prepared.completion_bytes()
    );
    prepared
        .visit_payloads(|path, bytes| {
            ensure!(fs::read(destination.join(path))? == bytes);
            Ok(())
        })
        .unwrap();
}

#[cfg(all(
    feature = "b4-terminal-evidence-publication",
    any(target_os = "linux", target_vendor = "apple")
))]
#[test]
fn publication_trace_proves_every_fault_stops_at_the_exact_ordered_transition() {
    fn run(fault: PublicationTestFault<'_>) -> (anyhow::Error, Vec<PublicationTestTransition>) {
        let temp = publication_tempdir();
        let destination = temp.path().join("packet");
        let prepared = mechanical_b4_terminal_evidence_publication_for_test(12).unwrap();
        let mut trace = Vec::new();
        let mut staged = publication_mechanical_reopen;
        let mut final_reopen = publication_mechanical_reopen;
        let error = publish_prepared_b4_terminal_evidence_with_test_seam_and_trace(
            &destination,
            &prepared,
            Some(fault),
            PublicationTestReopenSeam {
                staged: &mut staged,
                final_reopen: &mut final_reopen,
            },
            &mut trace,
        )
        .unwrap_err();
        (error, trace)
    }

    let expected = publication_expected_trace();
    let payloads_start = 1;
    let payloads_end = payloads_start + B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT;
    let manifest_end = payloads_end + 1;
    let completion_end = manifest_end + 1;
    let staged_end = completion_end + 1;
    let directories_end = staged_end + publication_expected_directory_syncs().len();
    let ready_end = directories_end + 1;
    let rename_end = ready_end + 1;
    let parent_end = rename_end + 1;

    for index in 0..B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT {
        assert_eq!(
            run(PublicationTestFault::PayloadWrite(index)).1,
            expected[..payloads_start + index],
            "payload write fault {index} crossed its transition"
        );
    }
    for index in 0..B4_TERMINAL_EVIDENCE_FILE_COUNT {
        let expected_end = if index < B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT {
            payloads_start + index
        } else if index == B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT {
            payloads_end
        } else {
            manifest_end
        };
        assert_eq!(
            run(PublicationTestFault::FileSync(index)).1,
            expected[..expected_end],
            "file sync fault {index} crossed its transition"
        );
    }
    assert_eq!(
        run(PublicationTestFault::ManifestWrite).1,
        expected[..payloads_end]
    );
    assert_eq!(
        run(PublicationTestFault::CompletionWrite).1,
        expected[..manifest_end]
    );
    assert_eq!(
        run(PublicationTestFault::StagedReopen).1,
        expected[..completion_end]
    );
    for index in 0..publication_expected_directory_syncs().len() {
        assert_eq!(
            run(PublicationTestFault::DirectorySync(index)).1,
            expected[..staged_end + index],
            "directory sync fault {index} crossed its transition"
        );
    }
    assert_eq!(
        run(PublicationTestFault::ParentSync).1,
        expected[..rename_end]
    );
    assert_eq!(
        run(PublicationTestFault::FinalReopen).1,
        expected[..parent_end]
    );

    let temp = publication_tempdir();
    let destination = temp.path().join("success");
    let prepared = mechanical_b4_terminal_evidence_publication_for_test(13).unwrap();
    let mut trace = Vec::new();
    let mut staged = publication_mechanical_reopen;
    let mut final_reopen = publication_mechanical_reopen;
    publish_prepared_b4_terminal_evidence_with_test_seam_and_trace(
        &destination,
        &prepared,
        None,
        PublicationTestReopenSeam {
            staged: &mut staged,
            final_reopen: &mut final_reopen,
        },
        &mut trace,
    )
    .unwrap();
    assert_eq!(trace, expected);

    let source = include_str!("b4_terminal_evidence_io.rs");
    assert_eq!(source.matches("renamore::rename_exclusive(").count(), 0);
}

#[cfg(all(
    feature = "b4-terminal-evidence-publication",
    any(target_os = "linux", target_vendor = "apple")
))]
#[test]
fn publication_two_writer_barrier_has_exactly_one_winner_and_immutable_bytes() {
    use std::sync::{Arc, Barrier};

    let temp = Arc::new(publication_tempdir());
    let destination = Arc::new(temp.path().join("packet"));
    let barrier = Arc::new(Barrier::new(2));
    let mut joins = Vec::new();
    for seed in [9_u8, 10_u8] {
        let temp = Arc::clone(&temp);
        let destination = Arc::clone(&destination);
        let barrier = Arc::clone(&barrier);
        joins.push(std::thread::spawn(move || {
            let _keep_temp_alive = temp;
            let prepared = mechanical_b4_terminal_evidence_publication_for_test(seed).unwrap();
            publication_with_fault(
                &destination,
                &prepared,
                PublicationTestFault::Barrier(barrier.as_ref()),
            )
        }));
    }
    let results = joins
        .into_iter()
        .map(|join| join.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    let loser_error = results
        .into_iter()
        .find_map(std::result::Result::err)
        .unwrap();
    assert!(format!("{loser_error:#}").contains("terminal-evidence publication occupation"));
    let winner = publication_mechanical_reopen(&destination).unwrap();
    let retained = publication_tree_bytes(&destination).unwrap();
    let retry = mechanical_b4_terminal_evidence_publication_for_test(11).unwrap();
    assert!(publication_without_fault(&destination, &retry).is_err());
    assert_eq!(publication_tree_bytes(&destination).unwrap(), retained);
    let first_id: [u8; 32] = Sha256::digest(
        mechanical_b4_terminal_evidence_publication_for_test(9)
            .unwrap()
            .manifest_bytes(),
    )
    .into();
    let second_id: [u8; 32] = Sha256::digest(
        mechanical_b4_terminal_evidence_publication_for_test(10)
            .unwrap()
            .manifest_bytes(),
    )
    .into();
    assert!(winner.packet_id == first_id || winner.packet_id == second_id);
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[derive(Clone, Copy)]
enum ParentSwapWindow {
    AfterPin,
    BeforeRename,
    BeforeFinalReauthentication,
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
fn assert_parent_path_swap_is_contained(window: ParentSwapWindow) {
    use std::sync::Arc;

    let temp = publication_tempdir();
    let live_parent = temp.path().join("live-parent");
    let moved_parent = temp.path().join("moved-original");
    fs::create_dir(&live_parent).unwrap();
    fs::write(live_parent.join("original-sentinel"), b"original").unwrap();
    let destination = live_parent.join("packet");
    let moved_destination = moved_parent.join("packet");
    let moved_staging = projected_staging_path(&moved_destination);
    let pause = Arc::new(PublicationTestPause::new());

    let thread_destination = destination.clone();
    let thread_pause = Arc::clone(&pause);
    let publisher = std::thread::spawn(move || {
        let prepared = mechanical_b4_terminal_evidence_publication_for_test(15).unwrap();
        let fault = match window {
            ParentSwapWindow::AfterPin => {
                PublicationTestFault::AfterParentPinned(thread_pause.as_ref())
            }
            ParentSwapWindow::BeforeRename => {
                PublicationTestFault::BeforeExclusiveRename(thread_pause.as_ref())
            }
            ParentSwapWindow::BeforeFinalReauthentication => {
                PublicationTestFault::BeforeFinalParentReauthentication(thread_pause.as_ref())
            }
        };
        publication_with_fault(&thread_destination, &prepared, fault)
    });

    pause.wait_until_reached();
    fs::rename(&live_parent, &moved_parent).unwrap();
    fs::create_dir(&live_parent).unwrap();
    fs::write(live_parent.join("decoy-sentinel"), b"decoy").unwrap();
    let decoy_snapshot = publication_tree_bytes(&live_parent).unwrap();
    pause.resume();

    let error = publisher
        .join()
        .unwrap()
        .expect_err("publication returned authority after parent substitution");
    assert!(
        format!("{error:#}").contains("no longer names the pinned directory"),
        "parent substitution did not fail at the custody boundary: {error:#}"
    );
    assert_eq!(
        publication_tree_bytes(&live_parent).unwrap(),
        decoy_snapshot,
        "descriptor-pinned publication mutated the replacement parent"
    );
    assert!(!destination.exists());
    assert!(!projected_staging_path(&destination).exists());
    assert_eq!(
        fs::read(moved_parent.join("original-sentinel")).unwrap(),
        b"original"
    );

    let expected: [u8; 32] = Sha256::digest(
        mechanical_b4_terminal_evidence_publication_for_test(15)
            .unwrap()
            .manifest_bytes(),
    )
    .into();
    match window {
        ParentSwapWindow::AfterPin => {
            assert!(!moved_destination.exists());
            assert!(!moved_staging.exists());
        }
        ParentSwapWindow::BeforeRename => {
            assert!(!moved_destination.exists());
            let retained = publication_mechanical_reopen(&moved_staging).unwrap();
            assert_eq!(retained.packet_id, expected);
        }
        ParentSwapWindow::BeforeFinalReauthentication => {
            let committed = publication_mechanical_reopen(&moved_destination).unwrap();
            assert_eq!(committed.packet_id, expected);
            assert!(!moved_staging.exists());
        }
    }
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn publication_parent_swap_after_pin_never_redirects_first_mutation() {
    assert_parent_path_swap_is_contained(ParentSwapWindow::AfterPin);
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn publication_parent_swap_before_rename_never_redirects_commit() {
    assert_parent_path_swap_is_contained(ParentSwapWindow::BeforeRename);
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn publication_parent_swap_before_final_reauthentication_returns_no_authority() {
    assert_parent_path_swap_is_contained(ParentSwapWindow::BeforeFinalReauthentication);
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn publication_staging_descendant_swap_before_payload_open_never_redirects_write() {
    use std::sync::Arc;

    let temp = publication_tempdir();
    let destination = temp.path().join("packet");
    let staging = projected_staging_path(&destination);
    let prepared = mechanical_b4_terminal_evidence_publication_for_test(16).unwrap();
    let mut first_payload = None;
    prepared
        .visit_payloads(|relative, bytes| {
            if first_payload.is_none() {
                first_payload = Some((relative.to_owned(), bytes.to_vec()));
            }
            Ok(())
        })
        .unwrap();
    let (first_relative, first_bytes) = first_payload.unwrap();
    let (first_directory, remaining_path) = first_relative
        .split_once('/')
        .expect("first mechanical payload must have a descendant directory");
    let displaced_directory = format!("displaced-{first_directory}");
    let pause = Arc::new(PublicationTestPause::new());

    let thread_destination = destination.clone();
    let thread_pause = Arc::clone(&pause);
    let publisher = std::thread::spawn(move || {
        publication_with_fault(
            &thread_destination,
            &prepared,
            PublicationTestFault::BeforePayloadOpen(0, thread_pause.as_ref()),
        )
    });

    pause.wait_until_reached();
    let pinned_directory = staging.join(first_directory);
    let displaced = staging.join(&displaced_directory);
    fs::rename(&pinned_directory, &displaced).unwrap();
    fs::create_dir(&pinned_directory).unwrap();
    fs::write(pinned_directory.join("decoy-sentinel"), b"decoy").unwrap();
    let decoy_snapshot = publication_tree_bytes(&pinned_directory).unwrap();
    pause.resume();

    let error = publisher
        .join()
        .unwrap()
        .expect_err("publication returned authority after descendant substitution");
    assert!(
        format!("{error:#}").contains(&staging.display().to_string()),
        "descendant substitution did not fail at the custody boundary: {error:#}"
    );
    assert!(!destination.exists());
    assert!(staging.is_dir());
    assert_eq!(
        publication_tree_bytes(&pinned_directory).unwrap(),
        decoy_snapshot,
        "descriptor-rooted write mutated the replacement descendant"
    );
    assert_eq!(
        fs::read(displaced.join(remaining_path)).unwrap(),
        first_bytes,
        "payload bytes were not written beneath the retained descendant descriptor"
    );
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn publication_byte_identical_leaf_replacement_after_sync_returns_no_authority() {
    use std::{os::unix::fs::MetadataExt as _, sync::Arc};

    let temp = publication_tempdir();
    let destination = temp.path().join("packet");
    let staging = projected_staging_path(&destination);
    let relative = "derived/case-8-terminal-join-final.raw-seal.bin";
    let displaced = temp.path().join("displaced-byte-identical-payload");
    let pause = Arc::new(PublicationTestPause::new());

    let thread_destination = destination.clone();
    let thread_pause = Arc::clone(&pause);
    let publisher = std::thread::spawn(move || {
        let prepared = mechanical_b4_terminal_evidence_publication_for_test(17).unwrap();
        publication_with_fault(
            &thread_destination,
            &prepared,
            PublicationTestFault::BeforeExclusiveRename(thread_pause.as_ref()),
        )
    });

    pause.wait_until_reached();
    let target = staging.join(relative);
    let original_bytes = fs::read(&target).unwrap();
    let original_inode = fs::metadata(&target).unwrap().ino();
    fs::rename(&target, &displaced).unwrap();
    fs::write(&target, &original_bytes).unwrap();
    assert_ne!(fs::metadata(&target).unwrap().ino(), original_inode);
    pause.resume();

    let error = publisher
        .join()
        .unwrap()
        .expect_err("publication returned authority for byte-identical replacement inode");
    assert!(
        format!("{error:#}").contains("physical"),
        "byte-identical replacement missed the physical closure check: {error:#}"
    );
    assert!(destination.is_dir());
    assert!(!staging.exists());
    assert_eq!(
        fs::read(destination.join(relative)).unwrap(),
        original_bytes
    );
    assert_eq!(fs::read(displaced).unwrap(), original_bytes);
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn publication_same_inode_restore_requires_final_file_durability_sync() {
    use std::{io::Write as _, os::unix::fs::MetadataExt as _, sync::Arc};

    const RELATIVE: &str = "derived/case-8-terminal-join-final.raw-seal.bin";

    let temp = publication_tempdir();
    let destination = temp.path().join("packet");
    let staging = projected_staging_path(&destination);
    let pause = Arc::new(PublicationTestPause::new());

    let thread_destination = destination.clone();
    let thread_pause = Arc::clone(&pause);
    let publisher = std::thread::spawn(move || {
        let prepared = mechanical_b4_terminal_evidence_publication_for_test(18).unwrap();
        publication_with_fault(
            &thread_destination,
            &prepared,
            PublicationTestFault::FinalFileSyncAfterBeforeRename(thread_pause.as_ref(), RELATIVE),
        )
    });

    pause.wait_until_reached();
    let target = staging.join(RELATIVE);
    let original_bytes = fs::read(&target).unwrap();
    let original_inode = fs::metadata(&target).unwrap().ino();
    let mut incorrect_bytes = original_bytes.clone();
    incorrect_bytes[0] ^= 0xff;

    let mut attacker = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&target)
        .unwrap();
    attacker.write_all(&incorrect_bytes).unwrap();
    attacker.sync_all().unwrap();
    drop(attacker);

    let mut restore = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&target)
        .unwrap();
    restore.write_all(&original_bytes).unwrap();
    restore.flush().unwrap();
    drop(restore);
    assert_eq!(fs::metadata(&target).unwrap().ino(), original_inode);
    assert_eq!(fs::read(&target).unwrap(), original_bytes);
    pause.resume();

    let error = publisher
        .join()
        .unwrap()
        .expect_err("publication returned authority without final exact-handle durability sync");
    assert!(
        format!("{error:#}").contains("injected final durability file synchronization failure"),
        "same-inode restore did not reach the final durability gate: {error:#}"
    );
    assert!(format!("{error:#}").contains(RELATIVE));
    publication_mechanical_reopen(&destination).unwrap();
    assert!(!staging.exists());
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn publication_staging_descendant_directory_identity_is_bound_before_rename() {
    use std::sync::Arc;

    const RELATIVE: &str = "profiles/risc0-v3-succinct";

    let temp = publication_tempdir();
    let destination = temp.path().join("packet");
    let staging = projected_staging_path(&destination);
    let displaced = temp.path().join("displaced-staging-profile-directory");
    let pause = Arc::new(PublicationTestPause::new());

    let thread_destination = destination.clone();
    let thread_pause = Arc::clone(&pause);
    let publisher = std::thread::spawn(move || {
        let prepared = mechanical_b4_terminal_evidence_publication_for_test(19).unwrap();
        publication_with_fault(
            &thread_destination,
            &prepared,
            PublicationTestFault::BeforeStagedPhysicalClosure(thread_pause.as_ref()),
        )
    });

    pause.wait_until_reached();
    let original_snapshot = publication_tree_bytes(&staging).unwrap();
    replace_directory_identity_preserving_leaf_objects(&staging.join(RELATIVE), &displaced)
        .unwrap();
    assert_eq!(publication_tree_bytes(&staging).unwrap(), original_snapshot);
    pause.resume();

    let error = publisher
        .join()
        .unwrap()
        .expect_err("publication accepted a replacement staged descendant directory");
    assert!(
        format!("{error:#}").contains(
            "staged publication directory physical closure differs from the created tree"
        ),
        "staged descendant replacement missed created-tree identity: {error:#}"
    );
    assert!(!destination.exists());
    assert_eq!(publication_tree_bytes(&staging).unwrap(), original_snapshot);
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn publication_final_descendant_directory_identity_matches_staged_closure() {
    use std::sync::Arc;

    const RELATIVE: &str = "profiles/risc0-v3-succinct";

    let temp = publication_tempdir();
    let destination = temp.path().join("packet");
    let staging = projected_staging_path(&destination);
    let displaced = temp.path().join("displaced-final-profile-directory");
    let pause = Arc::new(PublicationTestPause::new());

    let thread_destination = destination.clone();
    let thread_pause = Arc::clone(&pause);
    let publisher = std::thread::spawn(move || {
        let prepared = mechanical_b4_terminal_evidence_publication_for_test(20).unwrap();
        publication_with_fault(
            &thread_destination,
            &prepared,
            PublicationTestFault::BeforeFinalParentReauthentication(thread_pause.as_ref()),
        )
    });

    pause.wait_until_reached();
    let original_snapshot = publication_tree_bytes(&destination).unwrap();
    replace_directory_identity_preserving_leaf_objects(&destination.join(RELATIVE), &displaced)
        .unwrap();
    assert_eq!(
        publication_tree_bytes(&destination).unwrap(),
        original_snapshot
    );
    pause.resume();

    let error = publisher
        .join()
        .unwrap()
        .expect_err("publication accepted a replacement final descendant directory");
    assert!(
        format!("{error:#}")
            .contains("final publication physical closure differs from the staged synced closure"),
        "final descendant replacement missed staged-directory identity: {error:#}"
    );
    publication_mechanical_reopen(&destination).unwrap();
    assert!(!staging.exists());
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn publication_staging_root_swap_before_rename_fails_at_retained_root_identity() {
    use std::sync::Arc;

    let temp = publication_tempdir();
    let destination = temp.path().join("packet");
    let staging = projected_staging_path(&destination);
    let displaced_staging = temp.path().join("displaced-staging-root");
    let pause = Arc::new(PublicationTestPause::new());

    let thread_destination = destination.clone();
    let thread_pause = Arc::clone(&pause);
    let publisher = std::thread::spawn(move || {
        let prepared = mechanical_b4_terminal_evidence_publication_for_test(18).unwrap();
        publication_with_fault(
            &thread_destination,
            &prepared,
            PublicationTestFault::BeforeExclusiveRename(thread_pause.as_ref()),
        )
    });

    pause.wait_until_reached();
    fs::rename(&staging, &displaced_staging).unwrap();
    fs::create_dir(&staging).unwrap();
    fs::write(staging.join("decoy-sentinel"), b"decoy").unwrap();
    let decoy_snapshot = publication_tree_bytes(&staging).unwrap();
    pause.resume();

    let error = publisher
        .join()
        .unwrap()
        .expect_err("publication returned authority after staging-root substitution");
    assert!(
        format!("{error:#}")
            .contains("reserved staging name no longer identifies the pinned staging directory"),
        "staging-root substitution missed its exact identity check: {error:#}"
    );
    assert!(!destination.exists());
    assert_eq!(publication_tree_bytes(&staging).unwrap(), decoy_snapshot);
    publication_mechanical_reopen(&displaced_staging).unwrap();
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[derive(Clone, Copy)]
enum FinalRootSwapWindow {
    AfterRename,
    BeforeFinalReauthentication,
    AfterFinalPhysicalClosure,
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
fn assert_byte_identical_final_root_swap_is_rejected(window: FinalRootSwapWindow) {
    use std::sync::Arc;

    let temp = publication_tempdir();
    let destination = temp.path().join("packet");
    let displaced_final = temp.path().join("displaced-final-root");
    let pause = Arc::new(PublicationTestPause::new());

    let thread_destination = destination.clone();
    let thread_pause = Arc::clone(&pause);
    let publisher = std::thread::spawn(move || {
        let prepared = mechanical_b4_terminal_evidence_publication_for_test(19).unwrap();
        let fault = match window {
            FinalRootSwapWindow::AfterRename => {
                PublicationTestFault::AfterExclusiveRename(thread_pause.as_ref())
            }
            FinalRootSwapWindow::BeforeFinalReauthentication => {
                PublicationTestFault::BeforeFinalParentReauthentication(thread_pause.as_ref())
            }
            FinalRootSwapWindow::AfterFinalPhysicalClosure => {
                PublicationTestFault::AfterFinalPhysicalClosure(thread_pause.as_ref())
            }
        };
        publication_with_fault(&thread_destination, &prepared, fault)
    });

    pause.wait_until_reached();
    let original_snapshot = publication_tree_bytes(&destination).unwrap();
    fs::rename(&destination, &displaced_final).unwrap();
    write_publication_tree_bytes(&destination, &original_snapshot).unwrap();
    let decoy_snapshot = publication_tree_bytes(&destination).unwrap();
    pause.resume();

    let error = publisher
        .join()
        .unwrap()
        .expect_err("publication returned authority after byte-identical final-root substitution");
    let expected = match window {
        FinalRootSwapWindow::AfterRename => {
            "final publication root is not the retained staged directory"
        }
        FinalRootSwapWindow::BeforeFinalReauthentication => {
            "reauthenticated final publication name changed physical identity"
        }
        FinalRootSwapWindow::AfterFinalPhysicalClosure => {
            "reauthenticated final publication name changed during physical closure"
        }
    };
    assert!(
        format!("{error:#}").contains(expected),
        "final-root substitution missed {expected}: {error:#}"
    );
    assert_eq!(
        publication_tree_bytes(&destination).unwrap(),
        decoy_snapshot
    );
    publication_mechanical_reopen(&displaced_final).unwrap();
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn publication_final_root_swap_after_rename_fails_before_final_reopen() {
    assert_byte_identical_final_root_swap_is_rejected(FinalRootSwapWindow::AfterRename);
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn publication_final_root_swap_before_reauthentication_fails_exact_identity() {
    assert_byte_identical_final_root_swap_is_rejected(
        FinalRootSwapWindow::BeforeFinalReauthentication,
    );
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn publication_final_root_swap_after_physical_closure_fails_repeated_identity() {
    assert_byte_identical_final_root_swap_is_rejected(
        FinalRootSwapWindow::AfterFinalPhysicalClosure,
    );
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn publication_same_inode_leaf_mutation_after_physical_closure_returns_no_authority() {
    use std::{io::Write as _, os::unix::fs::MetadataExt as _, sync::Arc};

    const RELATIVE: &str = "derived/case-8-terminal-join-final.raw-seal.bin";

    let temp = publication_tempdir();
    let destination = temp.path().join("packet");
    let pause = Arc::new(PublicationTestPause::new());

    let thread_destination = destination.clone();
    let thread_pause = Arc::clone(&pause);
    let publisher = std::thread::spawn(move || {
        let prepared = mechanical_b4_terminal_evidence_publication_for_test(21).unwrap();
        publication_with_fault(
            &thread_destination,
            &prepared,
            PublicationTestFault::AfterFinalPhysicalClosure(thread_pause.as_ref()),
        )
    });

    pause.wait_until_reached();
    let target = destination.join(RELATIVE);
    let original_bytes = fs::read(&target).unwrap();
    let original_inode = fs::metadata(&target).unwrap().ino();
    let mut incorrect_bytes = original_bytes.clone();
    incorrect_bytes[0] ^= 0xff;
    let mut attacker = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&target)
        .unwrap();
    attacker.write_all(&incorrect_bytes).unwrap();
    attacker.sync_all().unwrap();
    drop(attacker);
    assert_eq!(fs::metadata(&target).unwrap().ino(), original_inode);
    assert_eq!(
        fs::metadata(&target).unwrap().len(),
        original_bytes.len() as u64
    );
    pause.resume();

    let error = publisher
        .join()
        .unwrap()
        .expect_err("publication returned authority after same-inode leaf mutation");
    assert!(
        format!("{error:#}").contains(&format!(
            "{RELATIVE} retained handle changed before authority"
        )),
        "same-inode leaf mutation missed retained-handle reauthentication: {error:#}"
    );
    assert_eq!(fs::read(&target).unwrap(), incorrect_bytes);
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn publication_byte_identical_leaf_replacement_after_physical_closure_returns_no_authority() {
    use std::{os::unix::fs::MetadataExt as _, sync::Arc};

    const RELATIVE: &str = "derived/case-8-terminal-join-final.raw-seal.bin";

    let temp = publication_tempdir();
    let destination = temp.path().join("packet");
    let displaced = temp.path().join("displaced-final-payload");
    let pause = Arc::new(PublicationTestPause::new());

    let thread_destination = destination.clone();
    let thread_pause = Arc::clone(&pause);
    let publisher = std::thread::spawn(move || {
        let prepared = mechanical_b4_terminal_evidence_publication_for_test(22).unwrap();
        publication_with_fault(
            &thread_destination,
            &prepared,
            PublicationTestFault::AfterFinalPhysicalClosure(thread_pause.as_ref()),
        )
    });

    pause.wait_until_reached();
    let target = destination.join(RELATIVE);
    let original_bytes = fs::read(&target).unwrap();
    let original_inode = fs::metadata(&target).unwrap().ino();
    fs::rename(&target, &displaced).unwrap();
    fs::write(&target, &original_bytes).unwrap();
    assert_ne!(fs::metadata(&target).unwrap().ino(), original_inode);
    pause.resume();

    let error = publisher
        .join()
        .unwrap()
        .expect_err("publication returned authority after byte-identical leaf replacement");
    assert!(
        format!("{error:#}").contains(&format!("{RELATIVE} named file changed before authority")),
        "byte-identical leaf replacement missed named-file reauthentication: {error:#}"
    );
    assert_eq!(fs::read(&target).unwrap(), original_bytes);
    assert_eq!(fs::read(&displaced).unwrap(), original_bytes);
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn publication_descendant_directory_replacement_after_physical_closure_returns_no_authority() {
    use std::sync::Arc;

    const RELATIVE: &str = "profiles/risc0-v3-succinct";

    let temp = publication_tempdir();
    let destination = temp.path().join("packet");
    let displaced = temp.path().join("displaced-final-profile-directory");
    let pause = Arc::new(PublicationTestPause::new());

    let thread_destination = destination.clone();
    let thread_pause = Arc::clone(&pause);
    let publisher = std::thread::spawn(move || {
        let prepared = mechanical_b4_terminal_evidence_publication_for_test(23).unwrap();
        publication_with_fault(
            &thread_destination,
            &prepared,
            PublicationTestFault::AfterFinalPhysicalClosure(thread_pause.as_ref()),
        )
    });

    pause.wait_until_reached();
    let live = destination.join(RELATIVE);
    let original_snapshot = publication_tree_bytes(&live).unwrap();
    replace_directory_identity_preserving_leaf_objects(&live, &displaced).unwrap();
    assert_eq!(publication_tree_bytes(&live).unwrap(), original_snapshot);
    pause.resume();

    let error = publisher
        .join()
        .unwrap()
        .expect_err("publication returned authority after final descendant replacement");
    assert!(
        format!("{error:#}").contains(
            "terminal evidence directory identity changed during descriptor reauthentication"
        ),
        "final descendant replacement missed terminal tree reauthentication: {error:#}"
    );
    assert_eq!(publication_tree_bytes(&live).unwrap(), original_snapshot);
    assert!(publication_tree_bytes(&displaced).unwrap().is_empty());
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn publication_second_physical_closure_rejects_byte_identical_leaf_replacement() {
    use std::{os::unix::fs::MetadataExt as _, sync::Arc};

    const RELATIVE: &str = "derived/case-8-terminal-join-final.raw-seal.bin";

    let temp = publication_tempdir();
    let destination = temp.path().join("packet");
    let displaced = temp.path().join("displaced-before-durable-closure");
    let pause = Arc::new(PublicationTestPause::new());

    let thread_destination = destination.clone();
    let thread_pause = Arc::clone(&pause);
    let publisher = std::thread::spawn(move || {
        let prepared = mechanical_b4_terminal_evidence_publication_for_test(24).unwrap();
        publication_with_fault(
            &thread_destination,
            &prepared,
            PublicationTestFault::BeforeDurableFinalPhysicalClosure(thread_pause.as_ref()),
        )
    });

    pause.wait_until_reached();
    let target = destination.join(RELATIVE);
    let original_bytes = fs::read(&target).unwrap();
    let original_inode = fs::metadata(&target).unwrap().ino();
    fs::rename(&target, &displaced).unwrap();
    fs::write(&target, &original_bytes).unwrap();
    assert_ne!(fs::metadata(&target).unwrap().ino(), original_inode);
    pause.resume();

    let error = publisher
        .join()
        .unwrap()
        .expect_err("second physical closure returned authority for a replacement leaf");
    assert!(
        format!("{error:#}").contains(
            "final publication physical closure changed during durability synchronization"
        ),
        "replacement leaf missed the second physical-closure comparison: {error:#}"
    );
    assert_eq!(fs::read(&target).unwrap(), original_bytes);
    assert_eq!(fs::read(&displaced).unwrap(), original_bytes);
}

#[cfg(all(feature = "b4-terminal-evidence-publication", target_os = "linux"))]
#[test]
fn publication_late_staging_recreation_returns_no_authority() {
    use std::sync::Arc;

    let temp = publication_tempdir();
    let destination = temp.path().join("packet");
    let staging = projected_staging_path(&destination);
    let pause = Arc::new(PublicationTestPause::new());

    let thread_destination = destination.clone();
    let thread_pause = Arc::clone(&pause);
    let publisher = std::thread::spawn(move || {
        let prepared = mechanical_b4_terminal_evidence_publication_for_test(20).unwrap();
        publication_with_fault(
            &thread_destination,
            &prepared,
            PublicationTestFault::BeforeFinalParentReauthentication(thread_pause.as_ref()),
        )
    });

    pause.wait_until_reached();
    fs::create_dir(&staging).unwrap();
    fs::write(staging.join("late-sentinel"), b"late").unwrap();
    let staging_snapshot = publication_tree_bytes(&staging).unwrap();
    pause.resume();

    let error = publisher
        .join()
        .unwrap()
        .expect_err("publication returned authority after late staging recreation");
    assert!(
        format!("{error:#}").contains("reserved publication staging is already occupied"),
        "late staging recreation missed its exact absence check: {error:#}"
    );
    publication_mechanical_reopen(&destination).unwrap();
    assert_eq!(publication_tree_bytes(&staging).unwrap(), staging_snapshot);
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
#[test]
fn publication_commit_is_relative_to_one_pinned_parent_descriptor() {
    let source = include_str!("b4_terminal_evidence_io.rs");
    assert_eq!(source.matches("renamore::rename_exclusive(").count(), 0);
    assert_eq!(source.matches("rustix::fs::renameat_with(").count(), 1);
    assert!(source.contains("RenameFlags::NOREPLACE"));
    assert!(source.contains(
        "rustix::fs::renameat_with(\n            parent,\n            staging_name,\n            parent,\n            final_name,"
    ));
    assert!(!source.contains("let staging = layout.reserved_staging_path().to_path_buf()"));
}

#[cfg(all(feature = "b4-terminal-evidence-publication", windows))]
#[test]
fn publication_windows_public_calls_are_unsupported_before_inspection_or_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().join("absent-parent").join("packet");
    let preflight_error = preflight_b4_terminal_evidence_publication(&destination).unwrap_err();
    assert!(format!("{preflight_error:#}").contains("unsupported"));

    let raw_seal = vec![0_u8; 222_668];
    let payloads = publication_invalid_payloads(&raw_seal);
    let publish_error = match publish_b4_terminal_evidence_packet(&destination, payloads) {
        Ok(_) => panic!("Windows publication unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(format!("{publish_error:#}").contains("unsupported"));
    assert!(!temp.path().join("absent-parent").exists());
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
#[test]
fn publication_support_matrix_matches_the_atomic_probe_dependency() {
    assert!(unix_publication_platform_supported("linux", false));
    assert!(unix_publication_platform_supported("macos", true));
    assert!(unix_publication_platform_supported("ios", true));
    assert!(!unix_publication_platform_supported("android", false));
    assert!(!unix_publication_platform_supported("freebsd", false));
}

#[cfg(all(
    feature = "b4-terminal-evidence-publication",
    unix,
    not(any(target_os = "linux", target_vendor = "apple"))
))]
#[test]
fn publication_other_unix_public_calls_are_unsupported_before_inspection_or_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().join("absent-parent").join("packet");
    let preflight_error = preflight_b4_terminal_evidence_publication(&destination).unwrap_err();
    assert!(format!("{preflight_error:#}").contains("unsupported"));

    let raw_seal = vec![0_u8; 222_668];
    let payloads = publication_invalid_payloads(&raw_seal);
    let publish_error = match publish_b4_terminal_evidence_packet(&destination, payloads) {
        Ok(_) => panic!("unsupported Unix publication unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(format!("{publish_error:#}").contains("unsupported"));
    assert!(!temp.path().join("absent-parent").exists());
}
