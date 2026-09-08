//! Local duplicate-assumption Lift16 acquisition and replay, without campaign authority.

use std::{collections::BTreeSet, path::Path};

use anyhow::{Context as _, Result, ensure};
use eip_0045_reproduction::{canonical::canonical_json_bytes, constants::{MAX_STATEMENT_BYTES, PROOF_BYTES}};
use risc0_zkvm::LocalProver;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    CANDIDATE_RECEIPT_ORACLE_MAX_BYTES,
    local_ancestry_shared_assumption::{Directory, Snapshot, create_fresh_directory, require_names},
    locked_negative_ancestry_guest::{LockedGuestPairV1, embedded_negative_ancestry_guest_pair},
    recursive::{LocalDuplicateAssumptionInput, RECURSIVE_ORACLE_MAX_BYTES, admit_local_duplicate_assumption},
};

const INPUT_ROLES: [&str; 4] = ["canonical-statement", "case9-recursive-oracle", "case9-assumption-raw-seal", "case9-final-raw-seal"];
const PAYLOAD_NAMES: [&str; 4] = ["duplicate-assumption.source-receipt.borsh", "duplicate-assumption.receipt-oracle.bincode", "duplicate-assumption.raw-seal.bin", "duplicate-assumption-statement.bin"];
const MANIFEST: &str = "duplicate-assumption-checkpoint.json";
const MANIFEST_MAX_BYTES: usize = 16 * 1024;
const INPUT_LIMITS: [usize; 4] = [MAX_STATEMENT_BYTES, RECURSIVE_ORACLE_MAX_BYTES, PROOF_BYTES, PROOF_BYTES];
const OUTPUT_LIMITS: [usize; 4] = [RECURSIVE_ORACLE_MAX_BYTES, CANDIDATE_RECEIPT_ORACLE_MAX_BYTES, PROOF_BYTES, MAX_STATEMENT_BYTES];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin { bytes: u64, sha256: String }

impl Pin {
    fn of(bytes: &[u8]) -> Self {
        Self { bytes: bytes.len() as u64, sha256: hex::encode(Sha256::digest(bytes)) }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamedPin { name: String, pin: Pin }

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestPin { elf: Pin, image_id: String }

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    schema: String,
    version: u32,
    role: String,
    terminal: String,
    inputs: [NamedPin; 4],
    consumer: GuestPin,
    alternate: GuestPin,
    payloads: [NamedPin; 4],
    outer_receipt_borsh: Pin,
}

impl Checkpoint {
    fn encode(&self) -> Result<Vec<u8>> {
        let bytes = canonical_json_bytes(&serde_json::to_value(self)?)?;
        ensure!(bytes.len() <= MANIFEST_MAX_BYTES, "local duplicate manifest byte bound");
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(!bytes.is_empty() && bytes.len() <= MANIFEST_MAX_BYTES, "local duplicate manifest byte bound");
        let value: Self = serde_json::from_slice(bytes).context("local duplicate manifest typed JSON")?;
        ensure!(value.encode()? == bytes, "local duplicate manifest is not canonical");
        Ok(value)
    }
}

struct Inputs { files: [Snapshot; 4] }

impl Inputs {
    fn read(paths: [&Path; 4]) -> Result<Self> {
        let files = paths.into_iter().zip(INPUT_LIMITS).map(|(path, limit)| Snapshot::read(path, limit))
            .collect::<Result<Vec<_>>>()?;
        let files: [Snapshot; 4] = files.try_into().map_err(|_| anyhow::anyhow!("local duplicate input cardinality"))?;
        ensure!(files.iter().map(Snapshot::node).collect::<BTreeSet<_>>().len() == 4,
            "local duplicate input identities are duplicated");
        ensure!(files[2].bytes().len() == PROOF_BYTES && files[3].bytes().len() == PROOF_BYTES,
            "local duplicate Case9 raw seal byte length");
        Ok(Self { files })
    }

    fn admit(&self, locked: &LockedGuestPairV1) -> Result<LocalDuplicateAssumptionInput> {
        admit_local_duplicate_assumption(locked, self.files[0].bytes(), self.files[1].bytes(),
            self.files[2].bytes(), self.files[3].bytes())
    }

    fn verify(&self) -> Result<()> {
        for file in &self.files { file.verify().context("local duplicate original input conservation")?; }
        Ok(())
    }
}

fn expected_checkpoint(inputs: &Inputs, locked: &LockedGuestPairV1,
                       payloads: &[Vec<u8>; 4], outer: &[u8]) -> Checkpoint {
    let guest = |(elf, id): (&[u8], risc0_zkvm::Digest)| GuestPin { elf: Pin::of(elf), image_id: hex::encode(id.as_bytes()) };
    Checkpoint {
        schema: "eip0045.local-ancestry-duplicate-assumption.v1".to_owned(), version: 1,
        role: "one-cache-two-equal-attachments".to_owned(), terminal: "stock-lift16".to_owned(),
        inputs: std::array::from_fn(|i| NamedPin { name: INPUT_ROLES[i].to_owned(), pin: Pin::of(inputs.files[i].bytes()) }),
        consumer: guest(locked.consumer()), alternate: guest(locked.alternate()),
        payloads: std::array::from_fn(|i| NamedPin { name: PAYLOAD_NAMES[i].to_owned(), pin: Pin::of(&payloads[i]) }),
        outer_receipt_borsh: Pin::of(outer),
    }
}

fn replay_checkpoint(inputs: &Inputs, locked: &LockedGuestPairV1, admitted: &LocalDuplicateAssumptionInput,
                     payloads: &[Vec<u8>; 4]) -> Result<Checkpoint> {
    ensure!(payloads[3] == admitted.statement(), "local duplicate canonical statement mismatch");
    let (_, lifted) = admitted.replay(&payloads[0], &payloads[1], &payloads[2])?;
    Ok(expected_checkpoint(inputs, locked, payloads, &borsh::to_vec(&lifted)?))
}

/// Prove a fixed duplicate-assumption Lift16 from four retained Case9 inputs.
///
/// # Errors
/// Rejects admission, guest, proof, full-Receipt identity, custody or conservation
/// drift. The destination must be fresh; partial output is retained after failure.
pub fn generate(paths: [&Path; 4], output_root: &Path) -> Result<()> {
    let inputs = Inputs::read(paths)?;
    let locked = embedded_negative_ancestry_guest_pair()?;
    let admitted = inputs.admit(&locked)?;
    let root = create_fresh_directory(output_root)?;
    let result = (|| {
        let (source, lifted) = admitted.prove(&LocalProver::new("local-ancestry-duplicate-assumption"))?;
        let (payloads, outer) = admitted.checkpoint_parts(&source, &lifted)?;
        let expected = expected_checkpoint(&inputs, &locked, &payloads, &outer);
        publish(&root, &payloads, &expected,
            |actual| replay_checkpoint(&inputs, &locked, &admitted, actual), || inputs.verify())
    })();
    inputs.verify()?;
    result
}

/// Reopen exactly five files and replay against original Case9 inputs and locked guests.
///
/// # Errors
/// Rejects source, proof, statement, manifest, identity or final custody drift.
/// This route does not prove, write, overwrite or remove anything.
pub fn verify(paths: [&Path; 4], checkpoint_root: &Path) -> Result<()> {
    let inputs = Inputs::read(paths)?;
    let locked = embedded_negative_ancestry_guest_pair()?;
    let admitted = inputs.admit(&locked)?;
    let root = Directory::open(checkpoint_root)?;
    let result = verify_published(&root,
        |actual| replay_checkpoint(&inputs, &locked, &admitted, actual), || inputs.verify());
    inputs.verify()?;
    result
}

fn payload_snapshots(root: &Directory) -> Result<[Snapshot; 4]> {
    let files = PAYLOAD_NAMES.into_iter().zip(OUTPUT_LIMITS)
        .map(|(name, limit)| Snapshot::read_at(root, name, limit)).collect::<Result<Vec<_>>>()?;
    files.try_into().map_err(|_| anyhow::anyhow!("local duplicate payload cardinality"))
}

fn payload_bytes(files: &[Snapshot; 4]) -> [Vec<u8>; 4] {
    std::array::from_fn(|i| files[i].bytes().to_vec())
}

fn publish(root: &Directory, payloads: &[Vec<u8>; 4], expected: &Checkpoint,
           mut replay: impl FnMut(&[Vec<u8>; 4]) -> Result<Checkpoint>,
           mut conserve: impl FnMut() -> Result<()>) -> Result<()> {
    root.verify()?;
    require_names(root, &[])?;
    for (name, bytes) in PAYLOAD_NAMES.into_iter().zip(payloads) { root.write_new(name, bytes)?; }
    require_names(root, &PAYLOAD_NAMES)?;
    let files = payload_snapshots(root)?;
    ensure!(replay(&payload_bytes(&files))? == *expected, "local duplicate rereplay identity mismatch");
    for file in &files { file.verify()?; }
    conserve()?;
    root.verify()?;
    root.write_new(MANIFEST, &expected.encode()?)?;
    root.file().sync_all()?;
    verify_published(root, &mut replay, || {
        for file in &files { file.verify()?; }
        root.verify()?;
        conserve()
    })
}

fn verify_published(root: &Directory, mut replay: impl FnMut(&[Vec<u8>; 4]) -> Result<Checkpoint>,
                    mut conserve: impl FnMut() -> Result<()>) -> Result<()> {
    root.verify()?;
    let names = [PAYLOAD_NAMES[0], PAYLOAD_NAMES[1], PAYLOAD_NAMES[2], PAYLOAD_NAMES[3], MANIFEST];
    require_names(root, &names)?;
    let manifest = Snapshot::read_at(root, MANIFEST, MANIFEST_MAX_BYTES)?;
    let expected = Checkpoint::decode(manifest.bytes())?;
    let files = payload_snapshots(root)?;
    let mut nodes = files.iter().map(Snapshot::node).collect::<BTreeSet<_>>();
    ensure!(nodes.insert(manifest.node()) && nodes.len() == 5, "local duplicate checkpoint identities are duplicated");
    ensure!(replay(&payload_bytes(&files))? == expected, "local duplicate manifest identity mismatch");
    for file in &files { file.verify()?; }
    manifest.verify()?;
    require_names(root, &names)?;
    root.verify()?;
    // No subsequent output or success write may bypass original-input conservation.
    conserve()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}, time::{SystemTime, UNIX_EPOCH}};

    const LIFT_COEFF_U_WORD: usize = 1_057;
    const FIELD_MODULUS: u32 = 15 * (1 << 27) + 1;

    fn corrupt_lift16_interior_coeff_u(seal: &mut [u32]) -> Result<()> {
        // Same reduced-word mutation as the pinned direct-seal validity-check KAT.
        // Words 0..33 are output globals and po2, not an interior proof coefficient.
        ensure!(seal.len() == eip_0045_reproduction::constants::PROOF_WORDS,
            "duplicate interior fault seal length");
        ensure!(seal.iter().enumerate().all(|(index, word)| index == 32 || *word < FIELD_MODULUS),
            "duplicate interior fault nonreduced word");
        let original = seal[LIFT_COEFF_U_WORD];
        seal[LIFT_COEFF_U_WORD] = if original + 1 < FIELD_MODULUS { original + 1 } else { original - 1 };
        Ok(())
    }

    #[test]
    fn duplicate_interior_lift_fault_preserves_format_and_changes_only_coeff_u() {
        use eip_0045_reproduction::{constants::{PROOF_WORDS, RISC0_OUTER_PO2}, seal::TOP_LEVEL_WORD_SPANS};
        assert_eq!(TOP_LEVEL_WORD_SPANS[6].name, "coeffU");
        assert_eq!(TOP_LEVEL_WORD_SPANS[6].start, LIFT_COEFF_U_WORD);
        assert!(LIFT_COEFF_U_WORD >= 33 && LIFT_COEFF_U_WORD < PROOF_WORDS);
        let seed = || {
            let mut words = vec![0_u32; PROOF_WORDS];
            words[32] = u32::from(RISC0_OUTER_PO2);
            words
        };
        for value in [0, 1, FIELD_MODULUS - 2, FIELD_MODULUS - 1] {
            let mut original = seed(); original[LIFT_COEFF_U_WORD] = value;
            let mut changed = original.clone();
            corrupt_lift16_interior_coeff_u(&mut changed).unwrap();
            assert_eq!(changed.len(), original.len());
            assert_eq!(&changed[..33], &original[..33]);
            assert_eq!(&changed[..LIFT_COEFF_U_WORD], &original[..LIFT_COEFF_U_WORD]);
            assert_eq!(&changed[LIFT_COEFF_U_WORD + 1..], &original[LIFT_COEFF_U_WORD + 1..]);
            assert_ne!(changed[LIFT_COEFF_U_WORD], value);
            assert!(changed[LIFT_COEFF_U_WORD] < FIELD_MODULUS);
            assert_eq!(changed.iter().zip(&original).filter(|(left, right)| left != right).count(), 1);
            let expected = changed.clone();
            changed[LIFT_COEFF_U_WORD] = value; assert_eq!(changed, original);
            corrupt_lift16_interior_coeff_u(&mut changed).unwrap(); assert_eq!(changed, expected);
        }
        for length in [0, PROOF_WORDS - 1, PROOF_WORDS + 1] {
            let mut changed = vec![0_u32; length]; let original = changed.clone();
            assert_eq!(corrupt_lift16_interior_coeff_u(&mut changed).unwrap_err().to_string(),
                "duplicate interior fault seal length");
            assert_eq!(changed, original);
            let mut restored = seed(); corrupt_lift16_interior_coeff_u(&mut restored).unwrap();
        }
        for index in [0, LIFT_COEFF_U_WORD, PROOF_WORDS - 1] {
            let mut changed = seed(); changed[index] = FIELD_MODULUS; let original = changed.clone();
            assert_eq!(corrupt_lift16_interior_coeff_u(&mut changed).unwrap_err().to_string(),
                "duplicate interior fault nonreduced word");
            assert_eq!(changed, original);
            changed[index] = 0; corrupt_lift16_interior_coeff_u(&mut changed).unwrap();
        }
    }

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!("local-duplicate-assumption-tests-{}-{}-{}",
                std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)));
            fs::create_dir(&root).unwrap(); Self(root)
        }
    }
    impl Drop for Fixture { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }

    fn synthetic_manifest(payloads: &[Vec<u8>; 4]) -> Checkpoint {
        let named = |name: &str, bytes: &[u8]| NamedPin { name: name.to_owned(), pin: Pin::of(bytes) };
        Checkpoint {
            schema: "eip0045.local-ancestry-duplicate-assumption.v1".to_owned(), version: 1,
            role: "one-cache-two-equal-attachments".to_owned(), terminal: "stock-lift16".to_owned(),
            inputs: std::array::from_fn(|i| named(INPUT_ROLES[i], &[i as u8])),
            consumer: GuestPin { elf: Pin::of(b"consumer fixture"), image_id: "11".repeat(32) },
            alternate: GuestPin { elf: Pin::of(b"alternate fixture"), image_id: "22".repeat(32) },
            payloads: std::array::from_fn(|i| named(PAYLOAD_NAMES[i], &payloads[i])),
            outer_receipt_borsh: Pin::of(b"synthetic full Receipt"),
        }
    }

    #[test]
    fn duplicate_manifest_requires_exact_typed_canonical_bytes() {
        let original = synthetic_manifest(&[vec![1], vec![2], vec![3], vec![4]]);
        let bytes = original.encode().unwrap();
        assert_eq!(Checkpoint::decode(&bytes).unwrap(), original);
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert_eq!(text.matches("\"version\":1").count(), 1);
        let floating = text.replacen("\"version\":1", "\"version\":1.0", 1).into_bytes();
        for changed in [vec![], [bytes.clone(), b" ".to_vec()].concat(), floating,
            vec![b' '; MANIFEST_MAX_BYTES + 1], b"{\"version\":1,\"version\":1}".to_vec()] {
            assert!(Checkpoint::decode(&changed).is_err());
        }
        for (field, value) in [("version", serde_json::json!(true)), ("unknown", serde_json::json!(1)),
                              ("inputs", serde_json::json!([])), ("payloads", serde_json::json!([]))] {
            let mut changed = serde_json::to_value(&original).unwrap(); changed[field] = value;
            assert!(Checkpoint::decode(&canonical_json_bytes(&changed).unwrap()).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn duplicate_input_join_rejects_alias_length_and_replacement_then_restores() {
        let fixture = Fixture::new();
        let paths: [PathBuf; 4] = std::array::from_fn(|i| fixture.0.join(i.to_string()));
        for (i, path) in paths.iter().enumerate() { fs::write(path, vec![i as u8; if i >= 2 { PROOF_BYTES } else { 1 }]).unwrap(); }
        let refs = std::array::from_fn(|i| paths[i].as_path());
        Inputs::read(refs).unwrap().verify().unwrap();
        assert_eq!(Inputs::read([&paths[0], &paths[0], &paths[2], &paths[3]]).err().unwrap().to_string(),
            "local duplicate input identities are duplicated");
        fs::write(&paths[2], vec![2; PROOF_BYTES - 1]).unwrap();
        assert_eq!(Inputs::read(refs).err().unwrap().to_string(), "local duplicate Case9 raw seal byte length");
        fs::write(&paths[2], vec![2; PROOF_BYTES]).unwrap();
        let inputs = Inputs::read(refs).unwrap();
        fs::rename(&paths[0], fixture.0.join("old")).unwrap(); fs::write(&paths[0], [0]).unwrap();
        assert!(inputs.verify().is_err());
        Inputs::read(refs).unwrap().verify().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn duplicate_publication_reopens_exact_payloads_and_conserves_last() {
        // Actual file custody/publication with a declared synthetic proof-replay seam.
        let fixture = Fixture::new(); let root = create_fresh_directory(&fixture.0.join("checkpoint")).unwrap();
        let payloads = [vec![1], vec![2], vec![3], vec![4]]; let expected = synthetic_manifest(&payloads);
        let calls = std::cell::RefCell::new(Vec::new());
        publish(&root, &payloads, &expected, |actual| {
            assert_eq!(actual, &payloads); calls.borrow_mut().push("replay"); Ok(expected.clone())
        }, || { calls.borrow_mut().push("conserve"); Ok(()) }).unwrap();
        assert_eq!(*calls.borrow(), ["replay", "conserve", "replay", "conserve"]);
        verify_published(&root, |_| Ok(expected.clone()), || Ok(())).unwrap();
        assert!(create_fresh_directory(&root).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn duplicate_publication_retains_first_payload_identity_across_conservation() {
        // Real publication and custody; only cryptographic replay is synthetic.
        for index in 0..PAYLOAD_NAMES.len() {
            for replace in [false, true, false] {
                let fixture = Fixture::new(); let root = create_fresh_directory(&fixture.0.join("checkpoint")).unwrap();
                let payloads = [vec![1], vec![2], vec![3], vec![4]]; let expected = synthetic_manifest(&payloads);
                let held = fixture.0.join("outside-held");
                let mut first_node = None; let mut replays = 0; let mut conservations = 0;
                let result = publish(&root, &payloads, &expected, |actual| {
                    assert_eq!(actual, &payloads); replays += 1; Ok(expected.clone())
                }, || {
                    conservations += 1;
                    if replace && conservations == 1 {
                        first_node = Some(Snapshot::read_at(&root, PAYLOAD_NAMES[index], payloads[index].len())?.node());
                        fs::rename(root.join(PAYLOAD_NAMES[index]), &held)?;
                        fs::write(root.join(PAYLOAD_NAMES[index]), &payloads[index])?;
                    }
                    Ok(())
                });
                assert_eq!(replays, 2);
                require_names(&root, &[PAYLOAD_NAMES[0], PAYLOAD_NAMES[1], PAYLOAD_NAMES[2], PAYLOAD_NAMES[3], MANIFEST]).unwrap();
                assert_eq!(fs::read(root.join(MANIFEST)).unwrap(), expected.encode().unwrap());
                if replace {
                    assert_eq!(result.unwrap_err().to_string(), "local file identity drift");
                    assert_eq!(conservations, 1);
                    let original = Snapshot::read(&held, payloads[index].len()).unwrap();
                    let replacement = Snapshot::read_at(&root, PAYLOAD_NAMES[index], payloads[index].len()).unwrap();
                    assert_eq!(Some(original.node()), first_node);
                    assert_ne!(original.node(), replacement.node());
                    assert_eq!(original.bytes(), payloads[index].as_slice());
                    assert_eq!(replacement.bytes(), original.bytes());
                } else {
                    result.unwrap(); assert_eq!(conservations, 2); assert!(!held.exists());
                    verify_published(&root, |_| Ok(expected.clone()), || Ok(())).unwrap();
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn duplicate_manifest_bindings_are_rederived_not_self_authorized() {
        let fixture = Fixture::new(); let root = create_fresh_directory(&fixture.0.join("checkpoint")).unwrap();
        let payloads = [vec![1], vec![2], vec![3], vec![4]]; let expected = synthetic_manifest(&payloads);
        publish(&root, &payloads, &expected, |_| Ok(expected.clone()), || Ok(())).unwrap();
        for fault in ["schema", "version", "role", "terminal", "input-role", "input-pin", "consumer-elf",
                      "consumer-id", "alternate-elf", "alternate-id", "pair", "payload-role", "payload-pin", "outer"] {
            let mut changed = expected.clone();
            match fault {
                "schema" => changed.schema.push('x'), "version" => changed.version += 1,
                "role" => changed.role.push('x'), "terminal" => changed.terminal = "stock-lift15".to_owned(),
                "input-role" => changed.inputs[0].name.push('x'), "input-pin" => changed.inputs[0].pin.bytes += 1,
                "consumer-elf" => changed.consumer.elf.bytes += 1, "consumer-id" => changed.consumer.image_id = "33".repeat(32),
                "alternate-elf" => changed.alternate.elf.bytes += 1, "alternate-id" => changed.alternate.image_id = "33".repeat(32),
                "pair" => std::mem::swap(&mut changed.consumer, &mut changed.alternate),
                "payload-role" => changed.payloads[0].name.push('x'), "payload-pin" => changed.payloads[0].pin.bytes += 1,
                "outer" => changed.outer_receipt_borsh.bytes += 1, _ => unreachable!(),
            }
            fs::write(root.join(MANIFEST), changed.encode().unwrap()).unwrap();
            assert_eq!(verify_published(&root, |_| Ok(expected.clone()), || Ok(())).unwrap_err().to_string(),
                "local duplicate manifest identity mismatch", "{fault}");
            fs::write(root.join(MANIFEST), expected.encode().unwrap()).unwrap();
            verify_published(&root, |_| Ok(expected.clone()), || Ok(())).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn duplicate_replay_and_final_conservation_failures_preserve_partial_output() {
        for fault in ["replay", "late-replay", "conservation"] {
            let fixture = Fixture::new(); let root = create_fresh_directory(&fixture.0.join("checkpoint")).unwrap();
            let payloads = [vec![1], vec![2], vec![3], vec![4]]; let expected = synthetic_manifest(&payloads);
            let origin = fixture.0.join("original"); fs::write(&origin, b"abc").unwrap();
            let snapshot = Snapshot::read(&origin, 3).unwrap(); let mut count = 0;
            let error = publish(&root, &payloads, &expected, |_| {
                count += 1;
                ensure!(fault != "replay" && !(fault == "late-replay" && count == 2), "synthetic duplicate replay denied");
                if fault == "conservation" && count == 2 { fs::write(&origin, b"abd")?; }
                Ok(expected.clone())
            }, || snapshot.verify()).unwrap_err();
            assert_eq!(error.to_string(), if fault == "conservation" { "local file identity drift" }
                else { "synthetic duplicate replay denied" });
            assert!(root.exists()); assert_eq!(root.join(MANIFEST).exists(), fault != "replay");
        }
    }

    #[cfg(unix)]
    #[test]
    fn duplicate_reread_closes_payload_inventory_alias_and_replacement_faults() {
        use std::os::unix::fs::symlink;
        for fault in ["extra", "missing", "hardlink", "symlink", "bytes", "replaced-after-replay", "manifest-race"] {
            let fixture = Fixture::new(); let root = create_fresh_directory(&fixture.0.join("checkpoint")).unwrap();
            let payloads = [vec![1], vec![2], vec![3], vec![4]]; let expected = synthetic_manifest(&payloads);
            if fault == "manifest-race" {
                let mut count = 0;
                assert!(publish(&root, &payloads, &expected, |_| Ok(expected.clone()), || {
                    count += 1; if count == 1 { fs::write(root.join(MANIFEST), b"occupied")?; } Ok(())
                }).is_err());
                assert_eq!(fs::read(root.join(MANIFEST)).unwrap(), b"occupied"); continue;
            }
            publish(&root, &payloads, &expected, |_| Ok(expected.clone()), || Ok(())).unwrap();
            let path = root.join(PAYLOAD_NAMES[0]);
            match fault {
                "extra" => fs::create_dir(root.join("extra")).unwrap(),
                "missing" => fs::remove_file(&path).unwrap(),
                "hardlink" => fs::hard_link(&path, fixture.0.join("outside-alias")).unwrap(),
                "symlink" => { fs::rename(&path, fixture.0.join("outside")).unwrap(); symlink(fixture.0.join("outside"), &path).unwrap(); },
                "bytes" => fs::write(&path, [9]).unwrap(), _ => (),
            }
            let error = verify_published(&root, |actual| {
                ensure!(actual == &payloads, "synthetic duplicate payload drift");
                if fault == "replaced-after-replay" {
                    fs::rename(&path, fixture.0.join("held"))?; fs::write(&path, &payloads[0])?;
                }
                Ok(expected.clone())
            }, || Ok(())).unwrap_err();
            let expected_error = match fault {
                "extra" => Some("extra local checkpoint entry"), "missing" => Some("local checkpoint inventory mismatch"),
                "hardlink" => Some("local file must have one link"), "bytes" => Some("synthetic duplicate payload drift"),
                "replaced-after-replay" => Some("local file identity drift"), "symlink" => None, _ => unreachable!(),
            };
            if let Some(message) = expected_error { assert_eq!(error.to_string(), message, "{fault}"); }
            assert!(root.exists());
        }
    }

    #[cfg(unix)]
    fn genuine_paths() -> Result<[PathBuf; 4]> {
        ["EIP0045_DUPLICATE_CANONICAL_STATEMENT", "EIP0045_DUPLICATE_CASE9_ORACLE",
         "EIP0045_DUPLICATE_CASE9_ASSUMPTION_RAW", "EIP0045_DUPLICATE_CASE9_FINAL_RAW"]
            .map(|name| std::env::var_os(name).map(PathBuf::from).with_context(|| format!("missing {name}")))
            .into_iter().collect::<Result<Vec<_>>>()?.try_into().map_err(|_| anyhow::anyhow!("genuine input count"))
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires original authentic Case9 inputs only; no checkpoint or proving"]
    fn genuine_duplicate_admission_rejects_each_original_input_fault() -> Result<()> {
        let paths = genuine_paths()?; let refs = std::array::from_fn(|i| paths[i].as_path());
        let inputs = Inputs::read(refs)?; let locked = embedded_negative_ancestry_guest_pair()?;
        inputs.admit(&locked)?;
        for index in 0..4 {
            let mut bytes: [Vec<u8>; 4] = std::array::from_fn(|i| inputs.files[i].bytes().to_vec());
            if index == 1 {
                let mut oracle = crate::recursive::decode_recursive_oracle(&bytes[1])?;
                oracle.steps[0].receipt.seal[0] ^= 1;
                bytes[1] = crate::recursive::encode_recursive_oracle(&oracle)?;
            } else { bytes[index][0] ^= 1; }
            let error = admit_local_duplicate_assumption(&locked, &bytes[0], &bytes[1], &bytes[2], &bytes[3])
                .err().context("changed original input was accepted")?;
            let message = match index {
                0 => "ErgoStatementV1 domain is not exact",
                1 => "recursive oracle failed complete replay",
                2 => "case-9 assumption receipt seal differs from the authenticated auxiliary artifact",
                3 => "local duplicate Case9 final Resolve raw seal mismatch", _ => unreachable!(),
            };
            assert!(error.chain().any(|cause| cause.to_string() == message), "input fault {index}: {error:#}");
            inputs.admit(&locked)?;
        }
        inputs.verify()
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires original Case9 inputs and separately proved duplicate checkpoint; never proves"]
    fn genuine_duplicate_checkpoint_replays_original_composite_and_isolated_faults() -> Result<()> {
        use risc0_zkvm::{Assumptions, Digest, InnerAssumptionReceipt, InnerReceipt, MaybePruned, ReceiptClaim};
        use risc0_zkvm::sha::Digestible as _;
        let paths = genuine_paths()?; let refs = std::array::from_fn(|i| paths[i].as_path());
        let root = PathBuf::from(std::env::var_os("EIP0045_DUPLICATE_CHECKPOINT").context("missing duplicate checkpoint")?);
        verify(refs, &root)?;
        let inputs = Inputs::read(refs)?; let locked = embedded_negative_ancestry_guest_pair()?;
        let admitted = inputs.admit(&locked)?; let directory = Directory::open(&root)?;
        let files = payload_snapshots(&directory)?; let payloads = payload_bytes(&files);
        let (original_source, original_lifted) = admitted.replay(&payloads[0], &payloads[1], &payloads[2])?;
        let (roundtrip, outer) = admitted.checkpoint_parts(&original_source, &original_lifted)?;
        assert_eq!(roundtrip, payloads); assert_eq!(outer, borsh::to_vec(&original_lifted)?);
        for fault in ["one-attachment", "three-attachments", "unequal-attachment", "one-head", "three-heads",
            "pruned-head", "pruned-list", "wrong-root", "wrong-claim", "segment-index", "source-journal",
            "source-proof", "lift-proof", "lift-head", "lift-claim", "terminal", "raw",
            "source-trailing", "oracle-trailing", "source-outer", "lift-outer"] {
            let mut source = original_source.clone(); let mut lifted = original_lifted.clone();
            if matches!(fault, "source-outer" | "lift-outer") {
                let changed = if fault == "source-outer" { &mut source } else { &mut lifted };
                let claim = changed.claim()?.digest(); let before = borsh::to_vec(changed)?;
                let mut digest = [0_u8; 32]; digest.copy_from_slice(changed.metadata.verifier_parameters.as_bytes());
                digest[0] ^= 1; changed.metadata.verifier_parameters = Digest::from_bytes(digest);
                assert_eq!(changed.claim()?.digest(), claim); assert_ne!(borsh::to_vec(changed)?, before);
                assert_eq!(admitted.checkpoint_parts(&source, &lifted).unwrap_err().to_string(),
                    "local shared assumption full Receipt bytes changed");
            } else {
                if fault == "source-journal" { source.journal.bytes[0] ^= 1; }
                let InnerReceipt::Composite(composite) = &mut source.inner else { unreachable!() };
                match fault {
                    "one-attachment" => { composite.assumption_receipts.pop(); },
                    "three-attachments" => composite.assumption_receipts.push(composite.assumption_receipts[0].clone()),
                    "unequal-attachment" => {
                        let InnerAssumptionReceipt::Succinct(inner) = &mut composite.assumption_receipts[0] else { unreachable!() };
                        let claim = inner.claim.digest(); inner.seal[0] ^= 1; assert_eq!(inner.claim.digest(), claim);
                    },
                    "segment-index" => composite.segments[0].index = 1,
                    "source-proof" => composite.segments[0].seal[0] ^= 1,
                    _ => (),
                }
                if matches!(fault, "one-head" | "three-heads" | "pruned-head" | "pruned-list" | "wrong-root" | "wrong-claim") {
                    let MaybePruned::Value(Some(output)) = &mut composite.segments[0].claim.output else { unreachable!() };
                    if fault == "pruned-list" { output.assumptions = MaybePruned::Pruned(output.assumptions.digest()); }
                    else {
                        let MaybePruned::Value(Assumptions(heads)) = &mut output.assumptions else { unreachable!() };
                        match fault {
                            "one-head" => heads.truncate(1), "three-heads" => heads.push(heads[0].clone()),
                            "pruned-head" => heads[0] = MaybePruned::Pruned(heads[0].digest()),
                            _ => {
                                let MaybePruned::Value(head) = &mut heads[0] else { unreachable!() };
                                if fault == "wrong-root" { head.control_root = Digest::ZERO; }
                                else { head.claim = Digest::ZERO; }
                            },
                        }
                    }
                }
                let InnerReceipt::Succinct(inner) = &mut lifted.inner else { unreachable!() };
                match fault {
                    "lift-proof" => {
                        let original = inner.clone(); let claim = original.claim.digest();
                        corrupt_lift16_interior_coeff_u(&mut inner.seal)?;
                        assert_eq!(inner.seal.len(), original.seal.len());
                        assert_eq!(&inner.seal[..33], &original.seal[..33]);
                        assert_eq!(&inner.seal[..LIFT_COEFF_U_WORD], &original.seal[..LIFT_COEFF_U_WORD]);
                        assert_eq!(&inner.seal[LIFT_COEFF_U_WORD + 1..], &original.seal[LIFT_COEFF_U_WORD + 1..]);
                        assert_ne!(inner.seal[LIFT_COEFF_U_WORD], original.seal[LIFT_COEFF_U_WORD]);
                        assert_eq!(inner.claim.digest(), claim);
                        let mut restored = inner.clone(); restored.seal = original.seal.clone();
                        assert_eq!(borsh::to_vec(&restored)?, borsh::to_vec(&original)?);
                        crate::validate_candidate_terminal_shape(inner, crate::CandidateTerminal::Lift(16), &claim)
                            .context("duplicate interior fault changed Lift16 terminal shape")?;
                    },
                    "terminal" => inner.control_id = crate::expected_normal_lift_control_id(15)?,
                    "lift-head" => {
                        let MaybePruned::Value(claim) = &mut inner.claim else { unreachable!() };
                        let MaybePruned::Value(Some(output)) = &mut claim.output else { unreachable!() };
                        let MaybePruned::Value(Assumptions(heads)) = &mut output.assumptions else { unreachable!() };
                        heads.truncate(1);
                    },
                    "lift-claim" => {
                        let MaybePruned::Value(claim) = &mut inner.claim else { unreachable!() };
                        claim.pre = MaybePruned::Pruned(Digest::ZERO);
                    }, _ => (),
                }
                let mut source_bytes = borsh::to_vec(&source)?;
                let mut oracle = crate::receipt_oracle_wire::encode_succinct_receipt_oracle::<ReceiptClaim>(inner)?;
                let mut raw = inner.get_seal_bytes();
                if fault == "raw" { raw[0] ^= 1; }
                if fault == "source-trailing" { source_bytes.push(0); }
                if fault == "oracle-trailing" { oracle.push(0); }
                let error = admitted.replay(&source_bytes, &oracle, &raw).err().context("changed duplicate proof accepted")?;
                let expected = match fault {
                    "one-attachment" | "three-attachments" => Some("local duplicate attachment count must be exactly two"),
                    "unequal-attachment" => Some("local duplicate attachment 0 differs from original Case9 receipt"),
                    "one-head" | "lift-head" => Some("guest emitted 1 assumptions, expected 2"),
                    "three-heads" => Some("guest emitted 3 assumptions, expected 2"),
                    "pruned-head" => Some("guest assumption 0 is pruned"),
                    "pruned-list" => Some("guest execution assumption list is pruned"),
                    "wrong-root" => Some("guest assumption 0 control root differs from its private mode"),
                    "wrong-claim" => Some("guest assumption 0 claim is not the exact same-program statement claim"),
                    "segment-index" => Some("local duplicate source must contain only segment zero"),
                    "source-journal" => Some("local duplicate receipt journal mismatch"),
                    "source-proof" => Some("local duplicate original composite replay failed"),
                    "lift-proof" => Some("local duplicate Lift16 replay failed"),
                    "lift-claim" => Some("local duplicate Lift does not match original source conditional claim"),
                    "terminal" => Some("local duplicate Lift16 terminal shape"),
                    "raw" => Some("local duplicate raw seal mismatch"),
                    "source-trailing" => Some("local duplicate source Receipt Borsh"),
                    "oracle-trailing" => None, _ => unreachable!(),
                };
                if let Some(message) = expected { assert_eq!(error.to_string(), message, "{fault}: {error:#}"); }
            }
            admitted.replay(&payloads[0], &payloads[1], &payloads[2])?;
        }
        let mut changed = payloads.clone(); changed[3][0] ^= 1;
        assert_eq!(replay_checkpoint(&inputs, &locked, &admitted, &changed).unwrap_err().to_string(),
            "local duplicate canonical statement mismatch");
        inputs.verify()?; for file in &files { file.verify()?; }
        verify(refs, &root)
    }
}
