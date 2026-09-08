// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Authenticated negative adapter for the shared recursive-ancestry replay.
//!
//! The shared `recursive_ancestry` module owns the bounded V2 wire, family
//! graph, claim reconstruction, and upstream `ReceiptClaim::join`/`resolve`
//! semantics. This adapter adds subject framing, exact auxiliary-map decoding,
//! manifest authentication, and independent STARK verification of every
//! referenced producer seal before any typed rejection can be observed.

#[cfg(all(test, feature = "negative-materialization-set"))]
mod genuine_resolve_ancestry {
    use super::*;
    use crate::{
        b4::{B4AncestryInventoryOperation, B4AncestryInventoryTarget, B4ByteTarget,
            B4NegativeMaterialization, B4NegativeMutation},
        b4_c2_ancestry::reconstruct_genuine_resolve_ancestry,
        b4_plan::{B4NegativeQaResultCode, Eip0045B4NegativePlanV1},
        b4_subject_envelope::encode_subject_envelope,
        b4_terminal_byte_map::B4ByteMapError,
        b4_validator::negative_verifier::genuine_conditional_claim::load_authenticated,
        recursive_ancestry::{RecursiveAncestryInventoryEntry, recursive_ancestry_revealed_head_witness,
            recursive_ancestry_to_jcs},
    };

    fn envelope(ancestry: &[u8], statement: &[u8], final_seal: &[u8], map: &[u8]) -> Vec<u8> {
        encode_subject_envelope(&[ancestry, statement, final_seal, map],
            ancestry_subject_envelope_contract()).unwrap()
    }

    fn exact_error<T>(result: Result<T>, expected: &str) {
        assert_eq!(result.err().expect("private failure must not become a typed observation").to_string(), expected);
    }

    #[test]
    #[ignore = "requires genuine preserved TerminalResolve export; local diagnostic only"]
    fn genuine_resolve_ancestry_c2_producer_consumer_matrix() {
        let root = std::env::var_os("EIP0045_B4_RESOLVE_VECTOR_ROOT").expect("Resolve export root required");
        let (input, projection) = load_authenticated(std::path::Path::new(&root)).unwrap();
        let entries = input.auxiliary().iter().map(|(path, raw)| (path.as_str(), raw.as_slice())).collect::<Vec<_>>();
        let map = encode_recursive_auxiliary_map(&B4RecursiveAuxiliaryMapV1::from_exact_entries(
            RecursiveAncestryFamily::TerminalResolve, &entries).unwrap()).unwrap();
        let manifest = input.manifest();
        let positive = envelope(input.ancestry(), input.statement(), input.final_seal(), &map);
        // The real consumer verifies all three seals before its positive acceptance sentinel.
        exact_error(reject_ancestry_replay(&positive, &[manifest]), "ancestry subject was unexpectedly accepted");

        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let rows = plan.groups.iter().flat_map(|group| group.executions.iter()).collect::<Vec<_>>();
        let witness = recursive_ancestry_revealed_head_witness(&projection).unwrap();
        for (index, execution_id, qa, rejection) in [
            (144, "resolve-explicit-field-sweep--declared-explicit-root",
                B4NegativeQaResultCode::B4ResolveExplicitSemanticsMismatch, B4AncestryRejection::ResolveExplicit),
            (155, "resolve-assumption-inventory-sweep--pruned-assumption",
                B4NegativeQaResultCode::B4ResolveAssumptionInventoryInvalid, B4AncestryRejection::AssumptionInventory),
        ] {
            assert_eq!(rows[index].execution_id, execution_id);
            assert_eq!(rows[index].qa_result_code, qa);
            let closed = reconstruct_genuine_resolve_ancestry(index, input.ancestry(), input.statement(),
                input.final_seal(), &map, manifest).unwrap();
            assert_eq!(closed.derived_registry_row.execution_id, execution_id);
            assert_eq!(closed.derived_registry_row.base_selector_id, "case9-typed-ancestry-v1");
            assert_eq!(closed.base, input.ancestry());
            assert_eq!(closed.contexts, vec![manifest.to_vec()]);
            let decoded = decode_subject_envelope(&closed.subject, ancestry_subject_envelope_contract()).unwrap();
            let [ancestry, statement, final_seal, auxiliary]: [&[u8]; 4] = decoded.parts().try_into().unwrap();
            assert_eq!(statement, input.statement());
            assert_eq!(final_seal, input.final_seal());
            assert_eq!(auxiliary, map);
            let mut expected = projection.clone();
            if index == 144 {
                expected.assumption_receipt.as_mut().unwrap().requested_control_root = "00".repeat(DIGEST_BYTES);
                assert!(matches!(closed.derived_registry_row.materialization,
                    B4NegativeMaterialization::Mutation { mutation: B4NegativeMutation::ByteEdit {
                        target: B4ByteTarget::Ancestry, .. } }));
            } else {
                expected.assumption_receipt.as_mut().unwrap().source_inventory.entries =
                    vec![RecursiveAncestryInventoryEntry::Pruned { digest: hex::encode(witness.exact_digest) }];
                assert_eq!(closed.derived_registry_row.materialization,
                    B4NegativeMaterialization::Mutation { mutation: B4NegativeMutation::AncestryInventoryEdit {
                        edit: B4AncestryInventoryOperation::PruneRevealedHead {
                            before_claim_digest: hex::encode(witness.claim_digest),
                            before_control_root: hex::encode(witness.control_root),
                            exact_digest: hex::encode(witness.exact_digest),
                        }, target: B4AncestryInventoryTarget::AssumptionSourceInventoryHead } });
            }
            assert_eq!(parse_recursive_ancestry_jcs(ancestry).unwrap(), expected);
            assert_eq!(ancestry, recursive_ancestry_to_jcs(&expected).unwrap());
            let contexts = closed.contexts.iter().map(Vec::as_slice).collect::<Vec<_>>();
            assert_eq!(reject_ancestry_replay(&closed.subject, &contexts).unwrap(), rejection);
            exact_error(reconstruct_genuine_resolve_ancestry(index, ancestry, statement, final_seal, auxiliary, manifest),
                "genuine resolve ancestry base is not canonical positive evidence");

            // Each private failure preserves the actual mutation and every unselected part.
            exact_error(reject_ancestry_replay(&closed.subject, &[]),
                "ancestry replay requires exactly one manifest context");
            let mut corrupted_seal = final_seal.to_vec();
            corrupted_seal[0] ^= 1;
            let corrupted = envelope(ancestry, statement, &corrupted_seal, auxiliary);
            exact_error(reject_ancestry_replay(&corrupted, &contexts),
                "final raw seal SHA-256 differs from its binding");
            let mut wrong_map = auxiliary.to_vec();
            wrong_map[..2].copy_from_slice(&0u16.to_le_bytes());
            let malformed = envelope(ancestry, statement, final_seal, &wrong_map);
            let error = reject_ancestry_replay(&malformed, &contexts).unwrap_err();
            assert_eq!(error.to_string(), "cannot decode exact recursive auxiliary map");
            assert_eq!(error.downcast_ref::<B4ByteMapError>(), Some(&B4ByteMapError::CountNotAllowed { actual: 0 }));
        }
        exact_error(reconstruct_genuine_resolve_ancestry(149, input.ancestry(), input.statement(),
            input.final_seal(), &map, manifest), "genuine resolve ancestry seam permits only rows 144 and 155");
    }
}

#[cfg(all(test, feature = "negative-materialization-set"))]
mod genuine_alternate_root {
    use super::*;
    use crate::{
        b4::{B4NegativeMaterialization, B4NegativeMutation},
        b4_alternate_root_authority::genuine_alternate_root as alternate,
        b4_c2_alternate_root::reconstruct_genuine_alternate_root,
        b4_c2_opcode_sequence::{decode_producer_opcode_subject, encode_opcode_subject, split_raw_seal},
        b4_materialization_set::B4ClosedReconstructedExecutionV1,
        b4_plan::{B4NegativeQaResultCode, Eip0045B4NegativePlanV1},
        b4_subject_envelope::encode_subject_envelope,
        b4_terminal_byte_map::B4ByteMapError,
        b4_validator::negative_verifier::{genuine_conditional_claim::load_authenticated, reject_raw_seal_shape},
        recursive_ancestry::recursive_ancestry_to_jcs,
    };
    use sha2::{Digest as _, Sha256};
    use std::path::Path;

    fn envelope(ancestry: &[u8], statement: &[u8], seal: &[u8], map: &[u8]) -> Vec<u8> {
        encode_subject_envelope(&[ancestry, statement, seal, map], ancestry_subject_envelope_contract()).unwrap()
    }

    fn exact_error<T>(result: Result<T>, expected: &str) {
        assert_eq!(result.err().expect("private failure required").to_string(), expected);
    }

    fn require_resolve_rejection(result: Result<B4AncestryRejection>) -> Result<()> {
        ensure!(result? == B4AncestryRejection::ResolveExplicit, "alternate consumer returned another boundary");
        Ok(())
    }

    fn validate_splice(row: &B4ClosedReconstructedExecutionV1, original: &RecursiveAncestryProjection,
        ancestry: &[u8], statement: &[u8], final_seal: &[u8], map: &[u8], manifest: &[u8], alternate: &[u8]) -> Result<()> {
        ensure!(row.derived_registry_row.execution_id == "resolve-explicit-field-sweep--assumption-receipt-root"
            && row.derived_registry_row.base_selector_id == "case9-typed-ancestry-v1"
            && row.derived_registry_row.materialization == B4NegativeMaterialization::Mutation {
                mutation: B4NegativeMutation::AlternateRootAssumptionSubstitution {} }, "alternate row recipe differs");
        ensure!(row.base == ancestry && row.contexts == vec![manifest.to_vec()], "alternate row base or context differs");
        let decoded = decode_subject_envelope(&row.subject, ancestry_subject_envelope_contract())?;
        let [changed, actual_statement, actual_final, actual_map]: [&[u8]; 4] = decoded.parts().try_into().unwrap();
        ensure!(actual_statement == statement && actual_final == final_seal, "alternate row untouched envelope parts differ");
        let mut expected = original.clone();
        let assumption = expected.assumption_receipt.as_mut().unwrap();
        let assumption_path = assumption.raw_seal.path.clone();
        assumption.raw_seal.sha256 = hex::encode(Sha256::digest(alternate));
        ensure!(parse_recursive_ancestry_jcs(changed)? == expected && changed == recursive_ancestry_to_jcs(&expected)?,
            "alternate row projection changes more than the raw reference SHA");
        let profile = StarkProfileManifestV1::decode(manifest)?.profile_id()?;
        ensure!(classify_recursive_ancestry_semantics(&expected, statement, profile)? == RecursiveAncestrySemanticOutcome::Canonical,
            "alternate row is not structurally canonical");
        let before = decode_recursive_auxiliary_map(map, RecursiveAncestryFamily::TerminalResolve)?;
        let after = decode_recursive_auxiliary_map(actual_map, RecursiveAncestryFamily::TerminalResolve)?;
        for (path, bytes) in before.iter() {
            ensure!(after.get(path) == Some(if path == assumption_path { alternate } else { bytes }),
                "alternate row changed another auxiliary seal");
        }
        Ok(())
    }

    #[test]
    fn alternate_consumer_oracle_rejects_other_boundaries_and_private_failures() {
        require_resolve_rejection(Ok(B4AncestryRejection::ResolveExplicit)).unwrap();
        for boundary in [B4AncestryRejection::ResolveZeroRoot, B4AncestryRejection::ClaimEdge,
            B4AncestryRejection::AssumptionInventory] {
            exact_error(require_resolve_rejection(Ok(boundary)), "alternate consumer returned another boundary");
        }
        exact_error(require_resolve_rejection(Err(anyhow::anyhow!("ancestry subject was unexpectedly accepted"))),
            "ancestry subject was unexpectedly accepted");
    }

    #[test]
    #[ignore = "requires genuine current alternate-root and Resolve exports plus pinned guest; local diagnostic only"]
    fn genuine_alternate_root_c2_producer_consumer_matrix() {
        let resolve_root = std::env::var_os("EIP0045_B4_RESOLVE_VECTOR_ROOT").expect("Resolve root required");
        let alternate_root = std::env::var_os("EIP0045_B4_ALTERNATE_VECTOR_ROOT").expect("alternate root required");
        let guest = std::env::var_os("EIP0045_B4_GUEST_FILE").expect("pinned guest required");
        let (input, projection) = load_authenticated(Path::new(&resolve_root)).unwrap();
        assert_eq!(input.statement().len(), 160);
        assert_eq!(hex::encode(Sha256::digest(input.statement())),
            "da4f3d7483d082324d1d11a3df67fd0dbfb662e0091ad741400be32ac3c15ae1");
        let authority = alternate::load_authenticated(Path::new(&alternate_root), input.statement(), Path::new(&guest)).unwrap();
        assert_eq!(hex::encode(Sha256::digest(authority.raw_seal())),
            "c0ddfd89529fb0b3046808b6666018b66356a92826f7eab55deffff9036981a3");
        assert_eq!(authority.claim_digest(), recursive_ancestry_claim_digest(&projection.assumption_receipt.as_ref().unwrap().claim).unwrap());
        alternate::assert_single_faults(Path::new(&alternate_root), input.statement(), Path::new(&guest)).unwrap();
        let entries = input.auxiliary().iter().map(|(p, b)| (p.as_str(), b.as_slice())).collect::<Vec<_>>();
        let map = encode_recursive_auxiliary_map(&B4RecursiveAuxiliaryMapV1::from_exact_entries(
            RecursiveAncestryFamily::TerminalResolve, &entries).unwrap()).unwrap();
        let positive = envelope(input.ancestry(), input.statement(), input.final_seal(), &map);
        let contexts = [input.manifest()];
        // Actual positive consumer authenticates the final, conditional, and assumption seals.
        exact_error(reject_ancestry_replay(&positive, &contexts), "ancestry subject was unexpectedly accepted");
        let seam = |index, ancestry: &[u8], statement: &[u8], seal: &[u8], map: &[u8]| {
            reconstruct_genuine_alternate_root(index, &authority, ancestry, statement, seal, map, input.manifest())
        };
        let row = seam(146, input.ancestry(), input.statement(), input.final_seal(), &map).unwrap();
        let validate = |row: &B4ClosedReconstructedExecutionV1| validate_splice(row, &projection,
            input.ancestry(), input.statement(), input.final_seal(), &map, input.manifest(), authority.raw_seal());
        validate(&row).unwrap();
        let row_contexts = row.contexts.iter().map(Vec::as_slice).collect::<Vec<_>>();
        require_resolve_rejection(reject_ancestry_replay(&row.subject, &row_contexts)).unwrap();
        let decoded = decode_subject_envelope(&row.subject, ancestry_subject_envelope_contract()).unwrap();
        let [changed, statement, seal, changed_map]: [&[u8]; 4] = decoded.parts().try_into().unwrap();
        // Restoring exactly the original subject restores actual positive acceptance.
        exact_error(reject_ancestry_replay(&positive, &contexts), "ancestry subject was unexpectedly accepted");
        let mut mutant = row.clone();
        mutant.subject = positive.clone();
        exact_error(validate(&mutant), "alternate row projection changes more than the raw reference SHA");
        mutant = row.clone();
        mutant.derived_registry_row.execution_id.push('x');
        exact_error(validate(&mutant), "alternate row recipe differs");
        mutant = row.clone();
        mutant.contexts.clear();
        exact_error(validate(&mutant), "alternate row base or context differs");
        exact_error(reject_ancestry_replay(&row.subject, &[]), "ancestry replay requires exactly one manifest context");
        exact_error(reject_ancestry_replay(&row.subject, &[b"bad"]), "cannot decode ancestry manifest context");
        // Stale reference and changed auxiliary bytes isolate the artifact-binding gate.
        exact_error(reject_ancestry_replay(&envelope(input.ancestry(), statement, seal, changed_map), &contexts),
            "assumption raw seal SHA-256 differs from its binding");
        let mut corrupt = seal.to_vec();
        corrupt[0] ^= 1;
        exact_error(reject_ancestry_replay(&envelope(changed, statement, &corrupt, changed_map), &contexts),
            "final raw seal SHA-256 differs from its binding");
        let mut malformed = changed_map.to_vec();
        malformed[..2].copy_from_slice(&0u16.to_le_bytes());
        let error = reject_ancestry_replay(&envelope(changed, statement, seal, &malformed), &contexts).unwrap_err();
        assert_eq!(error.to_string(), "cannot decode exact recursive auxiliary map");
        assert_eq!(error.downcast_ref::<B4ByteMapError>(), Some(&B4ByteMapError::CountNotAllowed { actual: 0 }));
        let mut wrong_statement = statement.to_vec();
        wrong_statement[159] ^= 1;
        exact_error(reject_ancestry_replay(&envelope(changed, &wrong_statement, seal, changed_map), &contexts),
            "ancestry statement SHA-256 differs");
        let mut zero = projection.clone();
        zero.assumption_receipt.as_mut().unwrap().requested_control_root = "00".repeat(32);
        let zero_bytes = recursive_ancestry_to_jcs(&zero).unwrap();
        exact_error(seam(146, &zero_bytes, statement, seal, &map), "genuine alternate-root base is not canonical positive evidence");
        let mut wrong_claim = parse_recursive_ancestry_jcs(changed).unwrap();
        wrong_claim.assumption_receipt.as_mut().unwrap().claim.user_exit ^= 1;
        let wrong_claim_bytes = recursive_ancestry_to_jcs(&wrong_claim).unwrap();
        exact_error(reject_ancestry_replay(&envelope(&wrong_claim_bytes, statement, seal, changed_map), &contexts),
            "ancestry producer seal failed claim binding");
        // A requested-root change can yield the same public class; the splice oracle must reject it.
        let mut extra = parse_recursive_ancestry_jcs(changed).unwrap();
        extra.assumption_receipt.as_mut().unwrap().requested_control_root = "00".repeat(32);
        mutant = row.clone();
        mutant.subject = envelope(&recursive_ancestry_to_jcs(&extra).unwrap(), statement, seal, changed_map);
        exact_error(validate(&mutant), "alternate row projection changes more than the raw reference SHA");
        mutant = row.clone();
        mutant.subject = envelope(changed, &wrong_statement, seal, changed_map);
        exact_error(validate(&mutant), "alternate row untouched envelope parts differ");
        for index in [0, 107, 109, 144, 145, 147, 149, 155, usize::MAX] {
            exact_error(seam(index, &[], &[], &[], &[]), "genuine alternate-root seam permits only rows 108 and 146");
        }
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let rows = plan.groups.iter().flat_map(|g| g.executions.iter()).collect::<Vec<_>>();
        assert_eq!(rows[146].qa_result_code, B4NegativeQaResultCode::B4ResolveExplicitSemanticsMismatch);
        assert_eq!(rows[108].qa_result_code, B4NegativeQaResultCode::RawSealInnerControlRootMismatch);
        let raw = seam(108, input.ancestry(), statement, seal, &map).unwrap();
        assert_eq!(raw.derived_registry_row.execution_id, "terminal-inner-root-mismatch--inner-control-root");
        assert_eq!(raw.derived_registry_row.base_selector_id, "alternate-root-lift-po2-15-v1");
        assert_eq!(raw.derived_registry_row.materialization, B4NegativeMaterialization::FixtureSelection {
            fixture_id: "alternate-root-lift-po2-15-v1".into() });
        assert_eq!(raw.base, authority.raw_seal());
        assert_eq!(raw.contexts, vec![input.manifest().to_vec()]);
        let opcode = decode_producer_opcode_subject(&raw.subject).unwrap();
        assert_eq!(opcode.proof_chunks().concat(), authority.raw_seal());
        let parsed = crate::ergo_statement::parse_ergo_statement_v1(statement).unwrap();
        assert_eq!(raw.subject, encode_opcode_subject(&split_raw_seal(authority.raw_seal()).unwrap(),
            parsed.application_payload(), &parsed.program_id(), &parsed.profile_id()).unwrap());
        let boundary = reject_raw_seal_shape(&raw.subject, &raw.contexts.iter().map(Vec::as_slice).collect::<Vec<_>>()).unwrap();
        assert_eq!((boundary.class(), boundary.stage()), ("inner-control-root-mismatch", "inner-control-root-binding"));
    }
}

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail, ensure};
use risc0_zkp::field::baby_bear::{BabyBearElem, P as BABY_BEAR_MODULUS};

use crate::{
    b4_recursive_auxiliary_map::decode_recursive_auxiliary_map,
    b4_subject_envelope::{ancestry_subject_envelope_contract, decode_subject_envelope},
    canonical::validate_lower_hex_exact,
    constants::{
        B4_ALTERNATE_CONTROL_ROOT, DIGEST_BYTES, TERMINAL_CONTROL_KIND_JOIN,
        TERMINAL_CONTROL_KIND_LIFT, TERMINAL_CONTROL_KIND_RESOLVE,
    },
    profile_manifest::StarkProfileManifestV1,
    recursive_ancestry::{
        RecursiveAncestryArtifactReference, RecursiveAncestryClaim, RecursiveAncestryFamily,
        RecursiveAncestryOperation, RecursiveAncestryProjection, RecursiveAncestrySemanticOutcome,
        RecursiveAncestryTerminal, classify_recursive_ancestry_semantics,
        parse_recursive_ancestry_jcs, recursive_ancestry_claim_digest,
        recursive_ancestry_expected_auxiliary_paths, validate_recursive_ancestry_artifacts,
        validate_recursive_ancestry_structure,
    },
    seal::decode_seal_words,
};

#[cfg(test)]
use crate::b4_recursive_auxiliary_map::{
    B4RecursiveAuxiliaryMapV1, encode_recursive_auxiliary_map,
};
#[cfg(test)]
use crate::constants::PROOF_BYTES;

use super::{
    stark::verify_stark,
    terminal::{B4TerminalKind, B4VerifiedTerminal},
};

const OUTPUT_WORDS: usize = 32;
const INNER_ROOT_WORDS: usize = 16;
const OUTER_PO2_WORD_INDEX: usize = OUTPUT_WORDS;

/// Stable ancestry-policy rejection returned only after framing and producer
/// evidence have reached the selected consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum B4AncestryRejection {
    ClaimEdge,
    ResolveExplicit,
    ResolveZeroRoot,
    AssumptionInventory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UntrustedSealOutput {
    inner_root: [u8; DIGEST_BYTES],
    claim_digest: [u8; DIGEST_BYTES],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthenticatedSealProducer {
    inner_root: [u8; DIGEST_BYTES],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SealProducerRole {
    AssumptionLift,
    Lift,
    Join,
    Resolve,
}

impl SealProducerRole {
    const fn from_operation(operation: &RecursiveAncestryOperation) -> Self {
        match operation {
            RecursiveAncestryOperation::Lift { .. } => Self::Lift,
            RecursiveAncestryOperation::Join { .. } => Self::Join,
            RecursiveAncestryOperation::Resolve { .. } => Self::Resolve,
        }
    }

    const fn terminal_kind(self) -> B4TerminalKind {
        match self {
            Self::AssumptionLift | Self::Lift => B4TerminalKind::Lift,
            Self::Join => B4TerminalKind::Join,
            Self::Resolve => B4TerminalKind::Resolve,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SealProducerRootBinding {
    InitialProfile,
    FixedAlternateAssumption,
}

struct PreparedAncestry<'a> {
    projection: RecursiveAncestryProjection,
    statement: &'a [u8],
    profile_id: [u8; DIGEST_BYTES],
    authenticated_assumption_root: Option<[u8; DIGEST_BYTES]>,
}

/// Exercise the authenticated ancestry projection and return a typed policy
/// rejection.
///
/// Framing, JCS, manifest, path, artifact, raw-seal, STARK, root, claim, and
/// terminal failures return `Err`; none can become public observations.
pub(super) fn reject_ancestry_replay(
    subject: &[u8],
    contexts: &[&[u8]],
) -> Result<B4AncestryRejection> {
    ensure!(
        contexts.len() == 1,
        "ancestry replay requires exactly one manifest context"
    );
    let decoded = decode_subject_envelope(subject, ancestry_subject_envelope_contract())
        .context("invalid ancestry subject envelope")?;
    let [ancestry, statement, final_seal, auxiliary_map]: [&[u8]; 4] =
        decoded
            .parts()
            .try_into()
            .map_err(|_| anyhow::anyhow!("ancestry envelope part count changed after decoding"))?;

    let prepared = prepare_ancestry(ancestry, statement, final_seal, auxiliary_map, contexts[0])?;
    classify_semantics(&prepared)?.context("ancestry subject was unexpectedly accepted")
}

#[allow(
    clippy::too_many_lines,
    reason = "producer framing and authentication remain in one fail-closed validation order"
)]
fn prepare_ancestry<'a>(
    ancestry: &[u8],
    statement: &'a [u8],
    final_seal: &[u8],
    auxiliary_map: &[u8],
    manifest_bytes: &[u8],
) -> Result<PreparedAncestry<'a>> {
    let projection = parse_recursive_ancestry_jcs(ancestry)?;
    let manifest = StarkProfileManifestV1::decode(manifest_bytes)
        .context("cannot decode ancestry manifest context")?;
    ensure!(
        manifest.encode()?.as_slice() == manifest_bytes,
        "ancestry manifest decode/re-encode changed bytes"
    );
    manifest
        .validate_initial_profile_target()
        .context("ancestry manifest differs from the frozen initial target")?;
    let profile_id = manifest.profile_id()?;

    validate_recursive_ancestry_structure(&projection, statement, profile_id)?;
    let borrowed_auxiliary = decode_recursive_auxiliary_map(auxiliary_map, projection.family)?;
    ensure!(
        borrowed_auxiliary.family() == projection.family,
        "decoded auxiliary family differs from parsed ancestry"
    );
    let auxiliary = borrowed_auxiliary
        .iter()
        .map(|(path, bytes)| (path.to_owned(), bytes))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        auxiliary.len() == borrowed_auxiliary.len(),
        "decoded auxiliary inventory lost one compiled path"
    );
    validate_recursive_ancestry_artifacts(&projection, statement, final_seal, &auxiliary)?;

    let final_step = projection
        .steps
        .last()
        .context("ancestry projection has no final step")?;
    let _final_producer = authenticate_seal_producer(
        final_seal,
        &manifest,
        SealProducerRole::from_operation(&final_step.operation),
        &final_step.terminal,
        recursive_ancestry_claim_digest(&final_step.claim)?,
    )?;

    let mut authenticated_assumption_root = None;
    for path in recursive_ancestry_expected_auxiliary_paths(projection.family) {
        let bytes = borrowed_auxiliary
            .get(&path)
            .with_context(|| format!("missing parsed-family producer seal {path}"))?;
        let (role, terminal, claim, reference) = auxiliary_producer_contract(&projection, &path)?;
        ensure!(
            reference.path == path,
            "auxiliary producer reference changed after shared artifact validation"
        );
        let producer = authenticate_seal_producer(
            bytes,
            &manifest,
            role,
            terminal,
            recursive_ancestry_claim_digest(claim)?,
        )?;
        if role == SealProducerRole::AssumptionLift {
            ensure!(
                authenticated_assumption_root
                    .replace(producer.inner_root)
                    .is_none(),
                "ancestry authenticated more than one assumption receipt"
            );
        }
    }
    ensure!(
        authenticated_assumption_root.is_some() == projection.family.uses_assumption(),
        "authenticated assumption-root presence differs from the ancestry family"
    );

    Ok(PreparedAncestry {
        projection,
        statement,
        profile_id,
        authenticated_assumption_root,
    })
}

fn classify_semantics(prepared: &PreparedAncestry<'_>) -> Result<Option<B4AncestryRejection>> {
    let outcome = classify_recursive_ancestry_semantics(
        &prepared.projection,
        prepared.statement,
        prepared.profile_id,
    )?;
    if outcome != RecursiveAncestrySemanticOutcome::Canonical {
        return Ok(map_semantic_outcome(outcome));
    }
    let requested_assumption_root = prepared
        .projection
        .assumption_receipt
        .as_ref()
        .map(|assumption| {
            parse_digest(
                &assumption.requested_control_root,
                "assumption requested control root",
            )
        })
        .transpose()?;
    classify_authenticated_assumption_root(
        prepared.projection.family,
        requested_assumption_root,
        prepared.authenticated_assumption_root,
    )
}

fn classify_authenticated_assumption_root(
    family: RecursiveAncestryFamily,
    requested: Option<[u8; DIGEST_BYTES]>,
    authenticated: Option<[u8; DIGEST_BYTES]>,
) -> Result<Option<B4AncestryRejection>> {
    match family {
        RecursiveAncestryFamily::TerminalJoin => {
            ensure!(
                requested.is_none() && authenticated.is_none(),
                "terminal-join unexpectedly retained an assumption root"
            );
            Ok(None)
        }
        RecursiveAncestryFamily::TerminalResolve => {
            let requested =
                requested.context("explicit resolve lost its requested control root")?;
            let authenticated =
                authenticated.context("explicit resolve lost its authenticated receipt root")?;
            Ok((requested != authenticated).then_some(B4AncestryRejection::ResolveExplicit))
        }
        RecursiveAncestryFamily::ResolveThenJoin => {
            ensure!(
                requested == Some([0; DIGEST_BYTES]) && authenticated.is_some(),
                "zero-root resolve lost its requested or authenticated assumption root"
            );
            Ok(None)
        }
    }
}

const fn map_semantic_outcome(
    outcome: RecursiveAncestrySemanticOutcome,
) -> Option<B4AncestryRejection> {
    match outcome {
        RecursiveAncestrySemanticOutcome::Canonical => None,
        RecursiveAncestrySemanticOutcome::ClaimEdge => Some(B4AncestryRejection::ClaimEdge),
        RecursiveAncestrySemanticOutcome::ResolveExplicit => {
            Some(B4AncestryRejection::ResolveExplicit)
        }
        RecursiveAncestrySemanticOutcome::ResolveZeroRoot => {
            Some(B4AncestryRejection::ResolveZeroRoot)
        }
        RecursiveAncestrySemanticOutcome::AssumptionInventory(_) => {
            Some(B4AncestryRejection::AssumptionInventory)
        }
    }
}

fn auxiliary_producer_contract<'a>(
    projection: &'a RecursiveAncestryProjection,
    path: &str,
) -> Result<(
    SealProducerRole,
    &'a RecursiveAncestryTerminal,
    &'a RecursiveAncestryClaim,
    &'a RecursiveAncestryArtifactReference,
)> {
    if let Some(assumption) = projection
        .assumption_receipt
        .as_ref()
        .filter(|assumption| assumption.raw_seal.path == path)
    {
        return Ok((
            SealProducerRole::AssumptionLift,
            &assumption.terminal,
            &assumption.claim,
            &assumption.raw_seal,
        ));
    }
    let step = projection
        .steps
        .iter()
        .take(projection.steps.len() - 1)
        .find(|step| step.raw_seal.path == path)
        .context("parsed-family auxiliary path has no producer contract")?;
    Ok((
        SealProducerRole::from_operation(&step.operation),
        &step.terminal,
        &step.claim,
        &step.raw_seal,
    ))
}

fn authenticate_seal_producer(
    raw_seal: &[u8],
    manifest: &StarkProfileManifestV1,
    role: SealProducerRole,
    projected_terminal: &RecursiveAncestryTerminal,
    expected_claim: [u8; DIGEST_BYTES],
) -> Result<AuthenticatedSealProducer> {
    let output = decode_untrusted_seal_output(raw_seal, manifest)?;
    let verified = verify_stark(manifest, raw_seal)
        .context("ancestry producer seal failed pinned STARK verification")?;
    let root_binding = require_supported_producer_root(role, output.inner_root, manifest)?;
    let root_bound = match root_binding {
        SealProducerRootBinding::InitialProfile => verified.bind_inner_control_root(),
        SealProducerRootBinding::FixedAlternateAssumption => {
            verified.bind_fixed_alternate_inner_control_root()
        }
    }
    .context("ancestry producer seal failed closed root binding")?;
    let bound = root_bound
        .bind_claim(expected_claim)
        .context("ancestry producer seal failed claim binding")?;
    ensure!(
        bound.inner_control_root() == output.inner_root
            && bound.claim_digest() == output.claim_digest,
        "ancestry producer typestate differs from independently decoded output"
    );
    ensure!(
        bound.terminal().kind() == role.terminal_kind(),
        "ancestry producer terminal kind differs from its role"
    );
    validate_projected_terminal(projected_terminal, role, manifest)?;
    bind_projected_terminal(projected_terminal, bound.terminal())?;
    Ok(AuthenticatedSealProducer {
        inner_root: bound.inner_control_root(),
    })
}

// This gate is reached only after `verify_stark`. It selects either the
// authenticated initial profile root or the one fixed alternate assumption
// witness; no caller-selected root can reach the typestate transition.
fn require_supported_producer_root(
    role: SealProducerRole,
    actual: [u8; DIGEST_BYTES],
    manifest: &StarkProfileManifestV1,
) -> Result<SealProducerRootBinding> {
    if actual == manifest.inner_control_root() {
        return Ok(SealProducerRootBinding::InitialProfile);
    }
    if role == SealProducerRole::AssumptionLift && actual == B4_ALTERNATE_CONTROL_ROOT {
        return Ok(SealProducerRootBinding::FixedAlternateAssumption);
    }
    ensure!(
        role != SealProducerRole::AssumptionLift,
        "assumption receipt root is neither the initial profile root nor the fixed alternate witness"
    );
    bail!("ancestry step producer root differs from the authenticated profile")
}

fn decode_untrusted_seal_output(
    raw_seal: &[u8],
    manifest: &StarkProfileManifestV1,
) -> Result<UntrustedSealOutput> {
    let words = decode_seal_words(raw_seal).context("cannot decode ancestry producer seal")?;
    ensure!(
        words.iter().all(|word| *word < BABY_BEAR_MODULUS),
        "ancestry producer seal contains a non-reduced word"
    );
    ensure!(
        words[OUTER_PO2_WORD_INDEX] == u32::from(manifest.outer_po2()),
        "ancestry producer seal has the wrong outer exponent"
    );

    let mut inner_root = [0u8; DIGEST_BYTES];
    for (root_index, seal_index) in (0..INNER_ROOT_WORDS).step_by(2).enumerate() {
        ensure!(
            words[seal_index + 1] == 0,
            "ancestry producer seal has nonzero root padding"
        );
        let decoded = BabyBearElem::new_raw(words[seal_index]).as_u32();
        inner_root[root_index * 4..root_index * 4 + 4].copy_from_slice(&decoded.to_le_bytes());
    }
    let mut claim_digest = [0u8; DIGEST_BYTES];
    for (offset, raw_word) in words[INNER_ROOT_WORDS..OUTPUT_WORDS]
        .iter()
        .copied()
        .enumerate()
    {
        let decoded = BabyBearElem::new_raw(raw_word).as_u32();
        let halfword =
            u16::try_from(decoded).context("ancestry producer seal claim halfword exceeds u16")?;
        claim_digest[offset * 2..offset * 2 + 2].copy_from_slice(&halfword.to_le_bytes());
    }
    Ok(UntrustedSealOutput {
        inner_root,
        claim_digest,
    })
}

fn validate_projected_terminal(
    terminal: &RecursiveAncestryTerminal,
    role: SealProducerRole,
    manifest: &StarkProfileManifestV1,
) -> Result<()> {
    let (kind, parameter, control_id) = projected_terminal_fields(terminal)?;
    ensure!(
        kind == role.terminal_kind(),
        "ancestry projected terminal kind differs from its operation"
    );
    let manifest_kind = match kind {
        B4TerminalKind::Lift => TERMINAL_CONTROL_KIND_LIFT,
        B4TerminalKind::Join => TERMINAL_CONTROL_KIND_JOIN,
        B4TerminalKind::Resolve => TERMINAL_CONTROL_KIND_RESOLVE,
    };
    let control = manifest
        .terminal_controls()
        .iter()
        .find(|entry| entry.control_kind() == manifest_kind && entry.parameter() == parameter)
        .context("ancestry terminal key is absent from the manifest")?;
    ensure!(
        control_id == control.control_id(),
        "ancestry terminal control ID differs from the manifest"
    );
    Ok(())
}

fn bind_projected_terminal(
    projected: &RecursiveAncestryTerminal,
    actual: B4VerifiedTerminal,
) -> Result<()> {
    let (kind, parameter, control_id) = projected_terminal_fields(projected)?;
    ensure!(
        (kind, parameter, control_id) == (actual.kind(), actual.parameter(), actual.control_id()),
        "ancestry projection terminal differs from its cryptographically verified producer"
    );
    Ok(())
}

fn projected_terminal_fields(
    terminal: &RecursiveAncestryTerminal,
) -> Result<(B4TerminalKind, u8, [u8; DIGEST_BYTES])> {
    match terminal {
        RecursiveAncestryTerminal::Lift {
            segment_po2,
            control_id,
        } => Ok((
            B4TerminalKind::Lift,
            u8::try_from(*segment_po2).context("lift exponent does not fit u8")?,
            parse_digest(control_id, "ancestry lift control ID")?,
        )),
        RecursiveAncestryTerminal::Join { control_id } => Ok((
            B4TerminalKind::Join,
            0,
            parse_digest(control_id, "ancestry join control ID")?,
        )),
        RecursiveAncestryTerminal::Resolve { control_id } => Ok((
            B4TerminalKind::Resolve,
            0,
            parse_digest(control_id, "ancestry resolve control ID")?,
        )),
    }
}

fn parse_digest(value: &str, label: &str) -> Result<[u8; DIGEST_BYTES]> {
    validate_lower_hex_exact(value, DIGEST_BYTES)
        .with_context(|| format!("{label} is not exact lowercase hex"))?;
    let mut bytes = [0u8; DIGEST_BYTES];
    hex::decode_to_slice(value, &mut bytes).with_context(|| format!("cannot decode {label}"))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use risc0_zkp::field::baby_bear::BabyBearElem;

    use super::*;
    use crate::recursive_ancestry::RecursiveAncestryInventoryDefect;

    const MANIFEST: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");

    #[test]
    fn shared_semantic_outcomes_have_one_closed_adapter_mapping() {
        assert_eq!(
            map_semantic_outcome(RecursiveAncestrySemanticOutcome::Canonical),
            None
        );
        assert_eq!(
            map_semantic_outcome(RecursiveAncestrySemanticOutcome::ClaimEdge),
            Some(B4AncestryRejection::ClaimEdge)
        );
        assert_eq!(
            map_semantic_outcome(RecursiveAncestrySemanticOutcome::ResolveExplicit),
            Some(B4AncestryRejection::ResolveExplicit)
        );
        assert_eq!(
            map_semantic_outcome(RecursiveAncestrySemanticOutcome::ResolveZeroRoot),
            Some(B4AncestryRejection::ResolveZeroRoot)
        );
        for defect in [
            RecursiveAncestryInventoryDefect::Missing,
            RecursiveAncestryInventoryDefect::Extra,
            RecursiveAncestryInventoryDefect::Pruned,
        ] {
            assert_eq!(
                map_semantic_outcome(RecursiveAncestrySemanticOutcome::AssumptionInventory(
                    defect
                )),
                Some(B4AncestryRejection::AssumptionInventory)
            );
        }
    }

    #[test]
    fn fabricated_producer_shape_cannot_cross_pinned_stark_verification() {
        let manifest = manifest();
        let terminal = RecursiveAncestryTerminal::Resolve {
            control_id: hex::encode(
                manifest
                    .terminal_controls()
                    .iter()
                    .find(|entry| {
                        entry.control_kind() == TERMINAL_CONTROL_KIND_RESOLVE
                            && entry.parameter() == 0
                    })
                    .unwrap()
                    .control_id(),
            ),
        };
        let claim = [0x42; DIGEST_BYTES];
        let error = authenticate_seal_producer(
            &seal_for(&manifest, claim),
            &manifest,
            SealProducerRole::Resolve,
            &terminal,
            claim,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("failed pinned STARK verification"),
            "fabricated producer failed outside pinned verification: {error:#}"
        );
    }

    #[test]
    fn auxiliary_map_is_family_exact_sorted_and_trailing_free() {
        let family = RecursiveAncestryFamily::TerminalResolve;
        let seal = vec![0u8; PROOF_BYTES];
        let paths = recursive_ancestry_expected_auxiliary_paths(family);
        let entries = paths
            .iter()
            .map(|path| (path.as_str(), seal.as_slice()))
            .collect::<Vec<_>>();
        let map = B4RecursiveAuxiliaryMapV1::from_exact_entries(family, &entries).unwrap();
        let encoded = encode_recursive_auxiliary_map(&map).unwrap();
        assert_eq!(
            decode_recursive_auxiliary_map(&encoded, family)
                .unwrap()
                .len(),
            2
        );

        let mut truncated = encoded.clone();
        truncated.pop();
        assert!(decode_recursive_auxiliary_map(&truncated, family).is_err());

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_recursive_auxiliary_map(&trailing, family).is_err());
    }

    #[test]
    fn assumption_root_gate_admits_only_initial_and_fixed_alternate_roots() {
        let manifest = manifest();
        assert!(
            require_supported_producer_root(
                SealProducerRole::AssumptionLift,
                manifest.inner_control_root(),
                &manifest,
            )
            .is_ok()
        );
        assert_eq!(
            require_supported_producer_root(
                SealProducerRole::AssumptionLift,
                B4_ALTERNATE_CONTROL_ROOT,
                &manifest,
            )
            .unwrap(),
            SealProducerRootBinding::FixedAlternateAssumption
        );
        let error = require_supported_producer_root(
            SealProducerRole::AssumptionLift,
            [0xa5; DIGEST_BYTES],
            &manifest,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("neither the initial profile root nor the fixed alternate witness")
        );
    }

    #[test]
    fn explicit_resolve_compares_the_authenticated_assumption_root() {
        let stock = [0x11; DIGEST_BYTES];
        let alternate = [0x22; DIGEST_BYTES];
        assert_eq!(
            classify_authenticated_assumption_root(
                RecursiveAncestryFamily::TerminalResolve,
                Some(stock),
                Some(stock),
            )
            .unwrap(),
            None
        );
        assert_eq!(
            classify_authenticated_assumption_root(
                RecursiveAncestryFamily::TerminalResolve,
                Some(stock),
                Some(alternate),
            )
            .unwrap(),
            Some(B4AncestryRejection::ResolveExplicit)
        );
        assert_eq!(
            classify_authenticated_assumption_root(
                RecursiveAncestryFamily::ResolveThenJoin,
                Some([0; DIGEST_BYTES]),
                Some(alternate),
            )
            .unwrap(),
            None
        );
        assert_eq!(
            classify_authenticated_assumption_root(
                RecursiveAncestryFamily::TerminalJoin,
                None,
                None,
            )
            .unwrap(),
            None
        );
    }

    fn manifest() -> StarkProfileManifestV1 {
        let manifest = StarkProfileManifestV1::decode(MANIFEST).unwrap();
        manifest.validate_initial_profile_target().unwrap();
        manifest
    }

    fn seal_for(manifest: &StarkProfileManifestV1, claim_digest: [u8; DIGEST_BYTES]) -> Vec<u8> {
        let mut words = vec![0u32; PROOF_BYTES / 4];
        for (index, chunk) in manifest.inner_control_root().chunks_exact(4).enumerate() {
            let decoded = u32::from_le_bytes(chunk.try_into().unwrap());
            words[index * 2] = BabyBearElem::new(decoded).as_u32_montgomery();
        }
        for (index, chunk) in claim_digest.chunks_exact(2).enumerate() {
            let decoded = u32::from(u16::from_le_bytes(chunk.try_into().unwrap()));
            words[INNER_ROOT_WORDS + index] = BabyBearElem::new(decoded).as_u32_montgomery();
        }
        words[OUTER_PO2_WORD_INDEX] = u32::from(manifest.outer_po2());
        words.into_iter().flat_map(u32::to_le_bytes).collect()
    }
}
