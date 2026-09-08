//! Local alternate-chain-domain finals, reusing a retained shared Lift15 Receipt.
//! Checkpoint selection is not historical or campaign authority. Qualification
//! separately binds the original checkpoint bytes and full outer Receipt digest.

use std::{collections::BTreeSet, path::Path};

use anyhow::{Context as _, Result, ensure};
use eip_0045_reproduction::{canonical::canonical_json_bytes, constants::{MAX_STATEMENT_BYTES, PROOF_BYTES}};
use risc0_zkvm::LocalProver;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    CANDIDATE_RECEIPT_ORACLE_MAX_BYTES,
    local_ancestry_shared_assumption::{AuthenticatedSharedCheckpoint, Directory, Snapshot,
        create_fresh_directory, require_names},
    recursive::{LocalAlternateStatementBranch as Branch, LocalAlternateStatementFinalInput,
        RECURSIVE_ORACLE_MAX_BYTES, decode_recursive_oracle, encode_recursive_oracle},
    recursive_calibration::{RECURSIVE_CALIBRATION_MAX_BYTES, RecursiveCalibrationReport},
};

const PAYLOAD_NAMES: [&str; 4] = ["final-ancestry.borsh", "final.receipt-oracle.bincode",
    "final.raw-seal.bin", "alternate-chain-domain-statement.bin"];
const LIMITS: [usize; 4] = [RECURSIVE_ORACLE_MAX_BYTES, CANDIDATE_RECEIPT_ORACLE_MAX_BYTES,
    PROOF_BYTES, MAX_STATEMENT_BYTES];
const MANIFEST: &str = "alternate-statement-final-checkpoint.json";
const MANIFEST_MAX: usize = 16 * 1024;

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
struct Checkpoint {
    schema: String,
    version: u32,
    branch: String,
    family: String,
    recipe: String,
    candidate_only: bool,
    witness_qualified: bool,
    official_campaign: bool,
    consumer_elf: Pin,
    consumer_image_id: String,
    shared_checkpoint_manifest: Pin,
    shared_outer_receipt_borsh: Pin,
    calibration: Pin,
    payloads: [NamedPin; 4],
}
impl Checkpoint {
    fn encode(&self) -> Result<Vec<u8>> {
        let body = canonical_json_bytes(&serde_json::to_value(self)?)?;
        ensure!(body.len() <= MANIFEST_MAX, "local final manifest byte bound");
        Ok(body)
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(!bytes.is_empty() && bytes.len() <= MANIFEST_MAX, "local final manifest byte bound");
        let value: Self = serde_json::from_slice(bytes).context("local final manifest typed JSON")?;
        ensure!(value.encode()? == bytes, "local final manifest is not canonical");
        Ok(value)
    }
}

/// Neither the Receipt nor its custody can escape into an unbound publication.
struct Candidate<'a, 'b> {
    admitted: &'a LocalAlternateStatementFinalInput<'b>,
    shared: &'b AuthenticatedSharedCheckpoint,
    calibration: &'b Snapshot,
    branch: Branch,
}
impl Candidate<'_, '_> {
    fn conserve(&self) -> Result<()> {
        self.calibration.verify().context("local final calibration conservation")?;
        self.shared.verify()
    }
    fn prove(&self, prover: &LocalProver) -> Result<crate::recursive::RecursiveOracle> {
        proof_entry(self.calibration, || self.shared.verify(), || self.admitted.prove(prover))
    }
    fn replay(&self, payloads: &[Vec<u8>; 4]) -> Result<Checkpoint> {
        self.conserve()?;
        let result = (|| {
            ensure!(payloads[3] == self.shared.statement(), "local final alternate statement mismatch");
            let oracle = decode_recursive_oracle(&payloads[0])?;
            ensure!(encode_recursive_oracle(&oracle)? == payloads[0], "local final ancestry codec mismatch");
            let (raw, direct) = self.admitted.evidence(&oracle)?;
            ensure!(raw == payloads[2], "local final raw seal mismatch");
            ensure!(direct == payloads[1], "local final direct oracle mismatch");
            let (elf, image_id) = self.shared.consumer();
            Ok(Checkpoint {
                schema: "eip0045.local-ancestry-alternate-statement-final.v1".to_owned(), version: 1,
                branch: self.branch.label().to_owned(), family: self.branch.family().as_str().to_owned(),
                recipe: match self.branch { Branch::ResolveFixed22 => "fixed22", Branch::ResolveThenJoinJoin21 => "join21" }.to_owned(),
                candidate_only: true, witness_qualified: false, official_campaign: false,
                consumer_elf: Pin::of(elf), consumer_image_id: hex::encode(image_id.as_bytes()),
                shared_checkpoint_manifest: Pin::of(self.shared.manifest_bytes()),
                shared_outer_receipt_borsh: Pin::of(self.shared.outer_bytes()),
                calibration: Pin::of(self.calibration.bytes()),
                payloads: std::array::from_fn(|i| NamedPin { name: PAYLOAD_NAMES[i].to_owned(), pin: Pin::of(&payloads[i]) }),
            })
        })();
        self.conserve()?;
        result
    }
}

// This is the actual immediate proof-entry boundary, after destination creation.
// Only the callable is replaced by ordinary tests; no worker or fake proof runs.
fn proof_entry<T>(calibration: &Snapshot, mut conserve_shared: impl FnMut() -> Result<()>,
                  prove: impl FnOnce() -> Result<T>) -> Result<T> {
    calibration.verify().context("local final calibration conservation")?;
    conserve_shared()?;
    let result = prove();
    let calibration_result = calibration.verify().context("local final calibration conservation");
    let shared_result = conserve_shared();
    calibration_result?;
    shared_result?;
    result
}

fn run(paths: [&Path; 4], shared_root: &Path, calibration_path: &Path,
       destination: &Path, branch: Branch, generate: bool) -> Result<()> {
    let shared = AuthenticatedSharedCheckpoint::open(paths, shared_root)?;
    // Ownership extends beyond every nested result/calibration/candidate callback
    // to the final public-return boundary, including partial failure observations.
    let mut output: Option<RetainedOutput> = None;
    let mut calibration: Option<Snapshot> = None;
    // Any failure after admission still rechecks the original retained checkpoint.
    let result = (|| {
        calibration = Some(Snapshot::read(calibration_path, RECURSIVE_CALIBRATION_MAX_BYTES)?);
        let calibration = calibration.as_ref().expect("retained calibration input");
        let result = (|| {
            let report = RecursiveCalibrationReport::from_canonical_jcs_with_recipe(calibration.bytes(), branch.recipe())?;
            let prover = LocalProver::new("local-alternate-statement-final");
            let admitted = LocalAlternateStatementFinalInput::admit(&shared, &report, branch, &prover)?;
            calibration.verify().context("local final calibration conservation")?;
            let candidate = Candidate { admitted: &admitted, shared: &shared, calibration, branch };
            candidate.conserve()?;
            if generate {
                // Calibration authentication/rederivation precedes output creation and proving.
                output = Some(RetainedOutput { root: create_fresh_directory(destination)?, first: OutputObservations::default() });
                let retained = output.as_mut().expect("retained generated output");
                let result = (|| {
                    let oracle = candidate.prove(&prover)?;
                    let (raw, direct) = admitted.evidence(&oracle)?;
                    let payloads = [encode_recursive_oracle(&oracle)?, direct, raw, shared.statement().to_vec()];
                    let expected = candidate.replay(&payloads)?;
                    publish_retained(&retained.root, &mut retained.first, &payloads, &expected,
                        |bytes| candidate.replay(bytes), || candidate.conserve())
                })();
                retained.root.verify()?;
                candidate.conserve()?;
                result
            } else {
                output = Some(RetainedOutput { root: Directory::open(destination)?, first: OutputObservations::default() });
                let retained = output.as_mut().expect("retained verified output");
                let result = verify_published_retained(&retained.root, &mut retained.first,
                    |bytes| candidate.replay(bytes), || candidate.conserve());
                retained.root.verify()?;
                candidate.conserve()?;
                result
            }
        })();
        calibration.verify().context("local final calibration conservation")?;
        result
    })();
    finish_run(result, output.as_ref(), || {
        let shared_result = shared.verify();
        let calibration_result = match calibration.as_ref() {
            Some(first) => first.verify().context("local final calibration conservation"),
            None => Ok(()),
        };
        shared_result?;
        calibration_result
    })
}

struct RetainedOutput { root: Directory, first: OutputObservations }

// The actual last public-return join. Origin conservation and output conservation
// are separate predicates; success of either cannot stand in for the other.
fn finish_run(result: Result<()>, output: Option<&RetainedOutput>,
              conserve_origins: impl FnOnce() -> Result<()>) -> Result<()> {
    let origins = conserve_origins();
    let outputs = match output {
        Some(retained) => retained.first.verify(&retained.root, result.is_ok()),
        None => {
            ensure!(result.is_err(), "local final output observations missing");
            Ok(())
        }
    };
    origins?;
    outputs?;
    result
}

/// Generate the local TerminalResolve/Fixed22 final from a retained shared Receipt.
/// # Errors
/// Fails on input/calibration/replay/custody drift; retains partial output on failure.
pub fn generate_resolve_fixed22(paths: [&Path; 4], shared_root: &Path, calibration: &Path, output: &Path) -> Result<()> {
    run(paths, shared_root, calibration, output, Branch::ResolveFixed22, true)
}
/// Replay the local TerminalResolve/Fixed22 final; no proof generation or writes.
/// # Errors
/// Fails on calibration, full ancestry, manifest, exact shared Receipt or custody drift.
pub fn verify_resolve_fixed22(paths: [&Path; 4], shared_root: &Path, calibration: &Path, checkpoint: &Path) -> Result<()> {
    run(paths, shared_root, calibration, checkpoint, Branch::ResolveFixed22, false)
}
/// Generate the local ResolveThenJoin/Join21 final from the same retained shared Receipt.
/// # Errors
/// Fails on input/calibration/replay/custody drift; retains partial output on failure.
pub fn generate_resolve_then_join_join21(paths: [&Path; 4], shared_root: &Path, calibration: &Path, output: &Path) -> Result<()> {
    run(paths, shared_root, calibration, output, Branch::ResolveThenJoinJoin21, true)
}
/// Replay the local ResolveThenJoin/Join21 final; no proof generation or writes.
/// # Errors
/// Fails on calibration, full ancestry, manifest, exact shared Receipt or custody drift.
pub fn verify_resolve_then_join_join21(paths: [&Path; 4], shared_root: &Path, calibration: &Path, checkpoint: &Path) -> Result<()> {
    run(paths, shared_root, calibration, checkpoint, Branch::ResolveThenJoinJoin21, false)
}

#[cfg(test)]
fn payload_snapshots(root: &Directory) -> Result<[Snapshot; 4]> {
    let values = PAYLOAD_NAMES.into_iter().zip(LIMITS).map(|(name, limit)| Snapshot::read_at(root, name, limit))
        .collect::<Result<Vec<_>>>()?;
    values.try_into().map_err(|_| anyhow::anyhow!("local final payload cardinality"))
}
#[cfg(test)]
fn payload_bytes(files: &[Snapshot; 4]) -> [Vec<u8>; 4] {
    std::array::from_fn(|i| files[i].bytes().to_vec())
}

#[derive(Default)]
struct OutputObservations { files: Vec<Snapshot>, manifest: Option<Snapshot> }
impl OutputObservations {
    fn bytes(&self) -> Result<[Vec<u8>; 4]> {
        ensure!(self.files.len() == 4, "local final payload cardinality");
        Ok(std::array::from_fn(|i| self.files[i].bytes().to_vec()))
    }
    fn verify(&self, root: &Directory, complete: bool) -> Result<()> {
        for file in &self.files { file.verify()?; }
        if let Some(manifest) = &self.manifest { manifest.verify()?; }
        if complete {
            ensure!(self.files.len() == 4 && self.manifest.is_some(), "local final observation cardinality");
            require_names(root, &[PAYLOAD_NAMES[0], PAYLOAD_NAMES[1], PAYLOAD_NAMES[2], PAYLOAD_NAMES[3], MANIFEST])?;
        }
        root.verify()
    }
}
fn publish_retained(root: &Directory, first: &mut OutputObservations,
           payloads: &[Vec<u8>; 4], expected: &Checkpoint,
           mut replay: impl FnMut(&[Vec<u8>; 4]) -> Result<Checkpoint>,
           mut conserve: impl FnMut() -> Result<()>) -> Result<()> {
    ensure!(first.files.is_empty() && first.manifest.is_none(), "local final observations already acquired");
    let result = (|| {
        root.verify()?;
        require_names(root, &[])?;
        for (name, bytes) in PAYLOAD_NAMES.into_iter().zip(payloads) {
            first.files.push(root.write_new_retained(name, bytes)?);
        }
        require_names(root, &PAYLOAD_NAMES)?;
        ensure!(replay(&first.bytes()?)? == *expected, "local final rereplay identity mismatch");
        first.verify(root, false)?;
        conserve()?;
        root.verify()?;
        first.manifest = Some(root.write_new_retained(MANIFEST, &expected.encode()?)?);
        root.file().sync_all()?;
        let mut reread = OutputObservations::default();
        verify_published_retained(root, &mut reread, &mut replay, || {
            first.verify(root, true)?;
            conserve()
        })
    })();
    // Keep the SAME creation observations alive through the final callback.
    // Evaluate both checks even on failure; never adopt a post-callback baseline.
    let conservation = conserve();
    let output_conservation = first.verify(root, result.is_ok());
    conservation?;
    output_conservation?;
    result
}
fn verify_published_retained(root: &Directory, first: &mut OutputObservations,
                    mut replay: impl FnMut(&[Vec<u8>; 4]) -> Result<Checkpoint>,
                    mut conserve: impl FnMut() -> Result<()>) -> Result<()> {
    ensure!(first.files.is_empty() && first.manifest.is_none(), "local final observations already acquired");
    let result = (|| {
        let names = [PAYLOAD_NAMES[0], PAYLOAD_NAMES[1], PAYLOAD_NAMES[2], PAYLOAD_NAMES[3], MANIFEST];
        root.verify()?;
        require_names(root, &names)?;
        first.manifest = Some(Snapshot::read_at(root, MANIFEST, MANIFEST_MAX)?);
        let expected = Checkpoint::decode(first.manifest.as_ref().expect("retained manifest").bytes())?;
        for (name, limit) in PAYLOAD_NAMES.into_iter().zip(LIMITS) {
            first.files.push(Snapshot::read_at(root, name, limit)?);
        }
        let mut nodes = first.files.iter().map(Snapshot::node).collect::<BTreeSet<_>>();
        ensure!(nodes.insert(first.manifest.as_ref().expect("retained manifest").node()) && nodes.len() == 5,
            "local final identities are duplicated");
        ensure!(replay(&first.bytes()?)? == expected, "local final manifest identity mismatch");
        first.verify(root, true)?;
        require_names(root, &names)?;
        root.verify()
    })();
    let conservation = conserve();
    let output_conservation = first.verify(root, result.is_ok());
    conservation?;
    output_conservation?;
    result
}

// Test conveniences exercise the same production functions without pretending
// to authenticate Case9 or invoking a prover. Public run owns the observations.
#[cfg(test)]
fn publish(root: &Directory, payloads: &[Vec<u8>; 4], expected: &Checkpoint,
           replay: impl FnMut(&[Vec<u8>; 4]) -> Result<Checkpoint>,
           conserve: impl FnMut() -> Result<()>) -> Result<()> {
    publish_retained(root, &mut OutputObservations::default(), payloads, expected, replay, conserve)
}
#[cfg(test)]
fn verify_published(root: &Directory, replay: impl FnMut(&[Vec<u8>; 4]) -> Result<Checkpoint>,
                    conserve: impl FnMut() -> Result<()>) -> Result<()> {
    verify_published_retained(root, &mut OutputObservations::default(), replay, conserve)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}, time::{SystemTime, UNIX_EPOCH}};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!("local-statement-finals-{}-{}-{}", std::process::id(),
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(), NEXT.fetch_add(1, Ordering::Relaxed)));
            fs::create_dir(&root).unwrap(); Self(root)
        }
    }
    impl Drop for Fixture { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }
    fn synthetic(payloads: &[Vec<u8>; 4]) -> Checkpoint {
        Checkpoint {
            schema: "eip0045.local-ancestry-alternate-statement-final.v1".into(), version: 1,
            branch: Branch::ResolveFixed22.label().into(), family: "terminal-resolve".into(), recipe: "fixed22".into(),
            candidate_only: true, witness_qualified: false, official_campaign: false,
            consumer_elf: Pin::of(b"synthetic elf"), consumer_image_id: "00".repeat(32),
            shared_checkpoint_manifest: Pin::of(b"synthetic checkpoint"), shared_outer_receipt_borsh: Pin::of(b"synthetic outer"),
            calibration: Pin::of(b"synthetic report"),
            payloads: std::array::from_fn(|i| NamedPin { name: PAYLOAD_NAMES[i].into(), pin: Pin::of(&payloads[i]) }),
        }
    }
    #[test]
    fn final_manifest_is_exact_typed_canonical_and_candidate_only() {
        let expected = synthetic(&[vec![1], vec![2], vec![3], vec![4]]);
        let bytes = expected.encode().unwrap();
        assert_eq!(Checkpoint::decode(&bytes).unwrap(), expected);
        for body in [Vec::new(), [bytes.clone(), b" ".to_vec()].concat(), vec![b' '; MANIFEST_MAX + 1]] {
            assert!(Checkpoint::decode(&body).is_err());
        }
        for (field, value) in [("unknown", serde_json::json!(1)), ("version", serde_json::json!(true)),
            ("payloads", serde_json::json!([]))] {
            let mut altered = serde_json::to_value(&expected).unwrap(); altered[field] = value;
            assert!(Checkpoint::decode(&canonical_json_bytes(&altered).unwrap()).is_err(), "{field}");
        }
        for (field, value) in [("candidate_only", false), ("witness_qualified", true), ("official_campaign", true)] {
            let mut altered = serde_json::to_value(&expected).unwrap(); altered[field] = serde_json::json!(value);
            assert_ne!(Checkpoint::decode(&canonical_json_bytes(&altered).unwrap()).unwrap(), expected, "{field}");
        }
    }
    #[cfg(unix)]
    #[test]
    fn final_publication_replays_actual_bytes_and_rejects_each_manifest_binding() {
      for branch in [Branch::ResolveFixed22, Branch::ResolveThenJoinJoin21] {
        let f = Fixture::new(); let root = create_fresh_directory(&f.0.join("out")).unwrap();
        let bytes = [vec![1], vec![2], vec![3], vec![4]]; let mut expected = synthetic(&bytes);
        expected.branch = branch.label().into(); expected.family = branch.family().as_str().into();
        expected.recipe = if branch == Branch::ResolveFixed22 { "fixed22" } else { "join21" }.into();
        let replays = std::cell::Cell::new(0);
        publish(&root, &bytes, &expected, |actual| { assert_eq!(actual, &bytes); replays.set(replays.get() + 1); Ok(expected.clone()) }, || Ok(())).unwrap();
        assert_eq!(replays.get(), 2);
        let reject_then_restore = |altered: serde_json::Value, label: &str| {
            fs::write(root.join(MANIFEST), expected.encode().unwrap()).unwrap();
            verify_published(&root, |_| Ok(expected.clone()), || Ok(())).unwrap();
            fs::write(root.join(MANIFEST), canonical_json_bytes(&altered).unwrap()).unwrap();
            let calls = std::cell::Cell::new(0);
            let error = verify_published(&root, |actual| {
                assert_eq!(actual, &bytes); calls.set(calls.get() + 1); Ok(expected.clone())
            }, || Ok(())).unwrap_err();
            assert_eq!(error.to_string(), "local final manifest identity mismatch", "{label}");
            assert_eq!(calls.get(), 1, "{label}: fault must reach the deciding consumer");
            fs::write(root.join(MANIFEST), expected.encode().unwrap()).unwrap();
            verify_published(&root, |_| Ok(expected.clone()), || Ok(())).unwrap();
        };
        for field in ["branch", "family", "recipe", "consumer_image_id", "schema"] {
            let mut altered = serde_json::to_value(&expected).unwrap(); altered[field] = serde_json::json!("wrong");
            reject_then_restore(altered, field);
        }
        let mut altered = serde_json::to_value(&expected).unwrap(); altered["version"] = serde_json::json!(2);
        reject_then_restore(altered, "version");
        for (field, value) in [("candidate_only", false), ("witness_qualified", true), ("official_campaign", true)] {
            let mut altered = serde_json::to_value(&expected).unwrap(); altered[field] = serde_json::json!(value);
            reject_then_restore(altered, field);
        }
        for field in ["consumer_elf", "shared_checkpoint_manifest", "shared_outer_receipt_borsh", "calibration"] {
            for component in ["bytes", "sha256"] {
                let mut altered = serde_json::to_value(&expected).unwrap();
                altered[field][component] = if component == "bytes" {
                    serde_json::json!(altered[field][component].as_u64().unwrap() + 1)
                } else { serde_json::json!("00".repeat(32)) };
                reject_then_restore(altered, &format!("{field}.{component}"));
            }
        }
        for index in 0..4 {
            for component in ["name", "bytes", "sha256"] {
                let mut altered = serde_json::to_value(&expected).unwrap();
                if component == "name" { altered["payloads"][index]["name"] = serde_json::json!("other-name"); }
                else if component == "bytes" {
                    altered["payloads"][index]["pin"]["bytes"] = serde_json::json!(bytes[index].len() + 1);
                } else { altered["payloads"][index]["pin"]["sha256"] = serde_json::json!("00".repeat(32)); }
                reject_then_restore(altered, &format!("payloads[{index}].{component}"));
            }
        }
        fs::write(root.join(MANIFEST), expected.encode().unwrap()).unwrap();
        verify_published(&root, |_| Ok(expected.clone()), || Ok(())).unwrap();
        fs::write(root.join("extra"), b"x").unwrap();
        assert_eq!(verify_published(&root, |_| Ok(expected.clone()), || Ok(())).unwrap_err().to_string(), "extra local checkpoint entry");
      }
    }

    #[cfg(unix)]
    #[test]
    fn final_last_callbacks_cannot_replace_first_payload_or_manifest_observations() {
        for route in ["publish", "verify"] {
          for leaf in PAYLOAD_NAMES.into_iter().chain([MANIFEST]) {
            let f = Fixture::new(); let root = create_fresh_directory(&f.0.join("out")).unwrap();
            let bytes = [vec![1], vec![2], vec![3], vec![4]]; let expected = synthetic(&bytes);
            let calls = std::cell::Cell::new(0);
            let replace_at = if route == "publish" { 3 } else { 1 };
            let replace = || {
                calls.set(calls.get() + 1);
                if calls.get() == replace_at {
                    let body = fs::read(root.join(leaf))?;
                    fs::rename(root.join(leaf), f.0.join("original-retained-outside-inventory"))?;
                    fs::write(root.join(leaf), body)?;
                }
                Ok(())
            };
            let error = if route == "publish" {
                publish(&root, &bytes, &expected, |_| Ok(expected.clone()), replace).unwrap_err()
            } else {
                publish(&root, &bytes, &expected, |_| Ok(expected.clone()), || Ok(())).unwrap();
                verify_published(&root, |_| Ok(expected.clone()), replace).unwrap_err()
            };
            assert_eq!(calls.get(), replace_at, "{route}/{leaf}: exercise final callback");
            assert_eq!(error.to_string(), "local file identity drift", "{route}/{leaf}");
            assert!(root.join(MANIFEST).exists());
            // New explicit admission is the restored positive; the failed first
            // observation is never replaced or silently promoted.
            verify_published(&root, |_| Ok(expected.clone()), || Ok(())).unwrap();
            let fresh = create_fresh_directory(&f.0.join("restored-publication")).unwrap();
            publish(&fresh, &bytes, &expected, |_| Ok(expected.clone()), || Ok(())).unwrap();
          }
        }
    }

    #[cfg(unix)]
    #[test]
    fn final_proof_entry_checks_calibration_before_callable_and_conserves_errors() {
        let f = Fixture::new(); let path = f.0.join("report"); fs::write(&path, b"report").unwrap();
        let first = Snapshot::read(&path, 6).unwrap();
        let calls = std::cell::Cell::new(0); let shared_calls = std::cell::Cell::new(0);
        let shared = || { shared_calls.set(shared_calls.get() + 1); Ok(()) };
        proof_entry(&first, shared, || { calls.set(calls.get() + 1); Ok(()) }).unwrap();
        assert_eq!(calls.get(), 1); assert_eq!(shared_calls.get(), 2);
        fs::rename(&path, f.0.join("old-report")).unwrap(); fs::write(&path, b"report").unwrap();
        calls.set(0); shared_calls.set(0);
        let error = proof_entry(&first, shared, || -> Result<()> {
            calls.set(calls.get() + 1); anyhow::bail!("refusing prover must not be called")
        }).err().unwrap();
        assert_eq!(error.to_string(), "local final calibration conservation");
        assert_eq!(calls.get(), 0); assert_eq!(shared_calls.get(), 0);
        let restored = Snapshot::read(&path, 6).unwrap();
        proof_entry(&restored, shared, || { calls.set(calls.get() + 1); Ok(()) }).unwrap();
        assert_eq!(calls.get(), 1);
        shared_calls.set(0);
        let error = proof_entry(&restored, shared, || -> Result<()> { anyhow::bail!("isolated prover failure") }).unwrap_err();
        assert_eq!(error.to_string(), "isolated prover failure"); assert_eq!(shared_calls.get(), 2);
        shared_calls.set(0);
        let error = proof_entry(&restored, shared, || {
            fs::rename(&path, f.0.join("second-old-report"))?; fs::write(&path, b"report")?; Ok(())
        }).unwrap_err();
        assert_eq!(error.to_string(), "local final calibration conservation"); assert_eq!(shared_calls.get(), 2);
        let final_admission = Snapshot::read(&path, 6).unwrap();
        proof_entry(&final_admission, shared, || Ok(())).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn final_public_return_retains_all_first_outputs_after_origin_callbacks() {
        for route in ["generate", "verify"] {
          for stage in ["after-inner-return", "last-origin-callback", "prior-failure"] {
            for leaf in PAYLOAD_NAMES.into_iter().chain([MANIFEST]) {
                let f = Fixture::new(); let origin_path = f.0.join("original-input");
                fs::write(&origin_path, b"original").unwrap();
                let origin = Snapshot::read(&origin_path, 8).unwrap();
                let root = create_fresh_directory(&f.0.join("out")).unwrap();
                let bytes = [vec![1], vec![2], vec![3], vec![4]]; let expected = synthetic(&bytes);
                let mut retained = RetainedOutput { root, first: OutputObservations::default() };
                let result = if route == "generate" {
                    publish_retained(&retained.root, &mut retained.first, &bytes, &expected,
                        |_| Ok(expected.clone()), || origin.verify())
                } else {
                    publish(&retained.root, &bytes, &expected, |_| Ok(expected.clone()), || origin.verify()).unwrap();
                    verify_published_retained(&retained.root, &mut retained.first,
                        |_| Ok(expected.clone()), || origin.verify())
                };
                result.as_ref().unwrap();
                let replace = || -> Result<()> {
                    let body = fs::read(retained.root.join(leaf))?;
                    fs::rename(retained.root.join(leaf), f.0.join("replaced-first-observation"))?;
                    fs::write(retained.root.join(leaf), body)?;
                    Ok(())
                };
                if stage != "last-origin-callback" { replace().unwrap(); }
                let result = if stage == "prior-failure" { Err(anyhow::anyhow!("earlier isolated failure")) } else { result };
                let origin_calls = std::cell::Cell::new(0);
                let error = finish_run(result, Some(&retained), || {
                    origin.verify()?;
                    origin_calls.set(origin_calls.get() + 1);
                    if stage == "last-origin-callback" { replace()?; }
                    origin.verify()
                }).unwrap_err();
                assert_eq!(origin_calls.get(), 1, "{route}/{stage}/{leaf}: actual final origin check ran");
                origin.verify().unwrap();
                assert_eq!(error.to_string(), "local file identity drift", "{route}/{stage}/{leaf}: output custody alone must reject");
                assert!(retained.root.join(MANIFEST).exists());
                // Restored positive requires an explicit new output admission,
                // never replacing the original failed observation vector.
                let mut restored = RetainedOutput { root: Directory::open(&retained.root).unwrap(), first: OutputObservations::default() };
                let result = verify_published_retained(&restored.root, &mut restored.first,
                    |_| Ok(expected.clone()), || origin.verify());
                finish_run(result, Some(&restored), || origin.verify()).unwrap();
            }
          }
        }
        assert_eq!(finish_run(Ok(()), None, || Ok(())).unwrap_err().to_string(), "local final output observations missing");
    }
    #[cfg(unix)]
    #[test]
    fn final_publication_retains_first_payload_identity() {
        let f = Fixture::new(); let root = create_fresh_directory(&f.0.join("out")).unwrap();
        let bytes = [vec![1], vec![2], vec![3], vec![4]]; let expected = synthetic(&bytes);
        let changed = std::cell::Cell::new(false);
        let error = publish(&root, &bytes, &expected, |_| Ok(expected.clone()), || {
            if !changed.replace(true) {
                fs::rename(root.join(PAYLOAD_NAMES[0]), f.0.join("old-payload"))?;
                fs::write(root.join(PAYLOAD_NAMES[0]), &bytes[0])?;
            }
            Ok(())
        }).unwrap_err();
        assert_eq!(error.to_string(), "local file identity drift");
        assert!(root.join(MANIFEST).exists());
    }
    #[cfg(unix)]
    #[test]
    fn final_publication_checks_late_origins_and_conserves_on_replay_error() {
        let f = Fixture::new(); let origin = f.0.join("original"); fs::write(&origin, b"origin").unwrap();
        let retained = Snapshot::read(&origin, 6).unwrap();
        let root = create_fresh_directory(&f.0.join("out")).unwrap();
        let bytes = [vec![1], vec![2], vec![3], vec![4]]; let expected = synthetic(&bytes);
        let calls = std::cell::Cell::new(0);
        let error = publish(&root, &bytes, &expected, |_| {
            calls.set(calls.get() + 1);
            if calls.get() == 2 { fs::write(&origin, b"change")?; }
            Ok(expected.clone())
        }, || retained.verify()).unwrap_err();
        assert!(format!("{error:#}").contains("local file identity drift"));
        assert!(root.join(MANIFEST).exists());
        let root = create_fresh_directory(&f.0.join("failed")).unwrap();
        let calls = std::cell::Cell::new(0);
        let error = publish(&root, &bytes, &expected, |_| anyhow::bail!("isolated replay failure"),
            || { calls.set(calls.get() + 1); Ok(()) }).unwrap_err();
        assert_eq!(error.to_string(), "isolated replay failure"); assert_eq!(calls.get(), 1);
        assert!(root.join(PAYLOAD_NAMES[0]).exists()); assert!(!root.join(MANIFEST).exists());
    }

    #[cfg(unix)]
    #[test]
    fn final_routes_refuse_unproved_inputs_before_output_creation() {
        let f = Fixture::new();
        let files: [PathBuf; 4] = std::array::from_fn(|i| f.0.join(format!("input-{i}")));
        for i in 0..4 { fs::write(&files[i], vec![0_u8; if i >= 2 { PROOF_BYTES } else { 1 }]).unwrap(); }
        let refs = std::array::from_fn(|i| files[i].as_path());
        for branch in [Branch::ResolveFixed22, Branch::ResolveThenJoinJoin21] {
            let out = f.0.join(branch.label());
            let error = run(refs, &f.0.join("absent-shared"), &f.0.join("absent-report"), &out, branch, true).unwrap_err();
            assert_eq!(error.to_string(), format!("ErgoStatementV1 has 1 bytes, expected {}..={}",
                eip_0045_reproduction::constants::STATEMENT_PREFIX_BYTES, MAX_STATEMENT_BYTES));
            assert!(!out.exists());
        }
    }

    #[cfg(unix)]
    fn genuine_final(branch: Branch) -> Result<()> {
        let paths = ["EIP0045_SHARED_CANONICAL_STATEMENT", "EIP0045_SHARED_CASE9_ORACLE",
            "EIP0045_SHARED_CASE9_ASSUMPTION_RAW", "EIP0045_SHARED_CASE9_FINAL_RAW"]
            .map(|name| std::env::var_os(name).map(PathBuf::from).with_context(|| format!("missing {name}")))
            .into_iter().collect::<Result<Vec<_>>>()?;
        let shared_root = PathBuf::from(std::env::var_os("EIP0045_SHARED_CHECKPOINT").context("missing shared checkpoint")?);
        let report_path = PathBuf::from(std::env::var_os("EIP0045_ALTERNATE_STATEMENT_FINAL_CALIBRATION").context("missing final calibration")?);
        let output = PathBuf::from(std::env::var_os("EIP0045_ALTERNATE_STATEMENT_FINAL_CHECKPOINT").context("missing final checkpoint")?);
        let shared = AuthenticatedSharedCheckpoint::open([&paths[0], &paths[1], &paths[2], &paths[3]], &shared_root)?;
        let original_report = Snapshot::read(&report_path, RECURSIVE_CALIBRATION_MAX_BYTES)?;
        let f = Fixture::new(); let report_copy = f.0.join("report"); fs::write(&report_copy, original_report.bytes())?;
        let calibration = Snapshot::read(&report_copy, RECURSIVE_CALIBRATION_MAX_BYTES)?;
        let report = RecursiveCalibrationReport::from_canonical_jcs_with_recipe(calibration.bytes(), branch.recipe())?;
        let admitted = LocalAlternateStatementFinalInput::admit(&shared, &report, branch,
            &LocalProver::new("local-alternate-statement-final-replay-test"))?;
        let candidate = Candidate { admitted: &admitted, shared: &shared, calibration: &calibration, branch };
        let directory = Directory::open(&output)?;
        let originals = payload_snapshots(&directory)?;
        let manifest = Snapshot::read_at(&directory, MANIFEST, MANIFEST_MAX)?;
        let payloads = payload_bytes(&originals);
        let original = decode_recursive_oracle(&payloads[0])?;
        ensure!(original.final_step > 0, "genuine final must contain intermediate ancestry");
        assert_eq!(borsh::to_vec(original.assumption_receipt.as_ref().context("missing original shared receipt")?)?, shared.outer_bytes());
        let expected = candidate.replay(&payloads)?;
        assert_eq!(Checkpoint::decode(manifest.bytes())?, expected);
        verify_published(&directory, |actual| candidate.replay(actual), || candidate.conserve())?;
        for fault in ["statement", "raw", "direct", "trailing", "missing-assumption", "outer", "intermediate", "family"] {
            let mut changed = payloads.clone();
            match fault {
                "statement" => changed[3][0] ^= 1,
                "raw" => changed[2][0] ^= 1,
                "direct" => changed[1][0] ^= 1,
                "trailing" => changed[0].push(0),
                _ => {
                    let mut oracle = original.clone();
                    match fault {
                        "missing-assumption" => oracle.assumption_receipt = None,
                        "outer" => {
                            let receipt = oracle.assumption_receipt.as_mut().unwrap();
                            let original_inner = borsh::to_vec(&receipt.inner)?;
                            receipt.metadata.verifier_parameters = if receipt.metadata.verifier_parameters == risc0_zkvm::Digest::ZERO {
                                risc0_zkvm::Digest::from([1_u32; 8])
                            } else { risc0_zkvm::Digest::ZERO };
                            assert_eq!(borsh::to_vec(&receipt.inner)?, original_inner);
                            assert_ne!(borsh::to_vec(receipt)?, shared.outer_bytes());
                        }
                        "intermediate" => {
                            oracle.steps[0].receipt.seal[0] ^= 1;
                            assert_eq!(borsh::to_vec(&oracle.assumption_receipt)?, borsh::to_vec(&original.assumption_receipt)?);
                            assert_eq!(borsh::to_vec(&oracle.steps[oracle.final_step as usize])?, borsh::to_vec(&original.steps[original.final_step as usize])?);
                            assert_eq!(borsh::to_vec(&oracle.source_receipt)?, borsh::to_vec(&original.source_receipt)?);
                        }
                        "family" => oracle.family = crate::recursive::RecursiveFamily::TerminalJoin,
                        _ => unreachable!(),
                    }
                    changed[0] = encode_recursive_oracle(&oracle)?;
                }
            }
            let error = candidate.replay(&changed).unwrap_err();
            let expected_error = match fault {
                "statement" => "local final alternate statement mismatch".to_owned(),
                "raw" => "local final raw seal mismatch".to_owned(),
                "direct" => "local final direct oracle mismatch".to_owned(),
                "trailing" => "cannot decode recursive ancestry oracle as exact Borsh".to_owned(),
                "missing-assumption" => format!("{} oracle has no assumption receipt", branch.family().as_str()),
                "outer" => format!("{} oracle did not retain the one shared assumption receipt", branch.family().as_str()),
                "intermediate" => "fixed B4 recursive oracle failed complete replay".to_owned(),
                "family" => "local final family mismatch".to_owned(),
                _ => unreachable!(),
            };
            assert_eq!(error.to_string(), expected_error, "{fault}: {error:#}");
            assert_eq!(candidate.replay(&payloads)?, expected);
        }
        // The admission borrowed this exact report snapshot. A later path with the
        // same bytes does not become its replacement authority.
        fs::rename(&report_copy, f.0.join("old-report"))?; fs::write(&report_copy, original_report.bytes())?;
        assert_eq!(candidate.replay(&payloads).unwrap_err().to_string(), "local final calibration conservation");
        for file in &originals { file.verify()?; }
        manifest.verify()?; directory.verify()?; original_report.verify()?; shared.verify()
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires retained shared checkpoint, own Fixed22 calibration and completed local final; never generates proofs"]
    fn genuine_resolve_fixed22_final_replay_and_single_faults() -> Result<()> {
        genuine_final(Branch::ResolveFixed22)
    }
    #[cfg(unix)]
    #[test]
    #[ignore = "requires retained shared checkpoint, own Join21 calibration and completed local final; never generates proofs"]
    fn genuine_resolve_then_join_join21_final_replay_and_single_faults() -> Result<()> {
        genuine_final(Branch::ResolveThenJoinJoin21)
    }
}
