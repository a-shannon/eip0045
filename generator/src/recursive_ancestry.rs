//! Producer adapter for the shared recursive-ancestry wire and stock replay.
//!
//! The retained Borsh [`RecursiveOracle`] remains the authenticated producer
//! evidence. This module only projects that evidence into the bounded shared
//! wire owned by `eip-0045-reproduction`; it deliberately contains no second
//! JSON grammar or claim-algebra validator.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail, ensure};
use eip_0045_reproduction::{
    canonical::validate_lower_hex_exact,
    constants::DIGEST_BYTES,
    recursive_ancestry::{
        RECURSIVE_ANCESTRY_ASSUMPTION_SEAL_FILE, RECURSIVE_ANCESTRY_FINAL_SEAL_FILE,
        RECURSIVE_ANCESTRY_FORMAT, RECURSIVE_ANCESTRY_FORMAT_VERSION,
        RECURSIVE_ANCESTRY_STATEMENT_FILE, RecursiveAncestryAssumption, RecursiveAncestryClaim,
        RecursiveAncestryFamily, RecursiveAncestryInventoryEntry, RecursiveAncestryOperation,
        RecursiveAncestryProjection, RecursiveAncestryProjectionBundle,
        RecursiveAncestrySourceInventory, RecursiveAncestryStep, RecursiveAncestryTerminal,
        parse_recursive_ancestry_jcs, recursive_ancestry_artifact_reference,
        recursive_ancestry_case_path, recursive_ancestry_expected_assumption_root,
        recursive_ancestry_to_jcs, validate_canonical_recursive_ancestry,
        validate_recursive_ancestry_artifacts,
    },
};
use risc0_zkvm::{Digest, InnerReceipt, MaybePruned, ReceiptClaim, sha::Digestible as _};

use crate::{
    normal_lift_segment_po2,
    recursive::{
        RecursiveFamily, RecursiveInputs, RecursiveOperation, RecursiveOracle,
        validate_recursive_oracle,
    },
};

/// Canonical shared projection plus only the newly derived auxiliary seals.
pub type ProjectionBundle = RecursiveAncestryProjectionBundle;

/// Build the canonical V2 projection from a cryptographically replayed oracle.
///
/// The source assumption inventory is read from the validated composite
/// receipt's final segment. In particular, pruned entries use the upstream
/// `MaybePruned<Assumption>` digest; they are never synthesized from JSON.
///
/// # Errors
///
/// Returns an error for an invalid profile identifier, oracle, producer
/// inventory, shared stock replay, artifact binding, or canonical encoding.
pub fn build_projection_bundle(
    oracle: &RecursiveOracle,
    image_id: Digest,
    statement: &[u8],
    profile_id: &str,
) -> Result<ProjectionBundle> {
    let profile_id_bytes = parse_hex_digest(profile_id, "profile ID")?;
    validate_recursive_oracle(oracle, image_id, statement)
        .context("recursive oracle failed mandatory replay before projection")?;

    let family = project_family(oracle.family);
    let statement_reference = recursive_ancestry_artifact_reference(
        recursive_ancestry_case_path(family, RECURSIVE_ANCESTRY_STATEMENT_FILE),
        statement,
    )?;
    let source_inventory = if oracle.family.uses_assumption() {
        Some(project_source_inventory(oracle)?)
    } else {
        None
    };

    let mut auxiliary_seals = BTreeMap::new();
    let assumption_receipt = project_assumption_receipt(
        oracle,
        family,
        source_inventory.as_ref(),
        &mut auxiliary_seals,
    )?;
    ensure!(
        assumption_receipt.is_some() == source_inventory.is_some(),
        "producer inventory presence differs from the assumption receipt"
    );

    let final_index = oracle
        .steps
        .len()
        .checked_sub(1)
        .context("validated recursive oracle has no steps")?;
    let steps = project_steps(oracle, family, final_index, &mut auxiliary_seals)?;

    let projection = RecursiveAncestryProjection {
        format: RECURSIVE_ANCESTRY_FORMAT.to_owned(),
        format_version: RECURSIVE_ANCESTRY_FORMAT_VERSION,
        case_id: family.case_id().to_owned(),
        profile_id: profile_id.to_owned(),
        program_id: digest_hex(image_id),
        statement: statement_reference,
        family,
        assumption_receipt,
        steps,
    };
    validate_canonical_recursive_ancestry(&projection, statement, profile_id_bytes)
        .context("shared stock replay rejected producer-derived ancestry")?;
    let jcs = recursive_ancestry_to_jcs(&projection)?;
    let final_raw_seal = oracle.steps[final_index].receipt.get_seal_bytes();
    validate_recursive_ancestry_artifacts(
        &projection,
        statement,
        &final_raw_seal,
        &auxiliary_seals,
    )?;
    ensure!(
        parse_recursive_ancestry_jcs(&jcs)? == projection,
        "canonical ancestry projection changed during round trip"
    );

    Ok(ProjectionBundle {
        jcs,
        auxiliary_seals,
    })
}

fn project_assumption_receipt(
    oracle: &RecursiveOracle,
    family: RecursiveAncestryFamily,
    source_inventory: Option<&RecursiveAncestrySourceInventory>,
    auxiliary_seals: &mut BTreeMap<String, Vec<u8>>,
) -> Result<Option<RecursiveAncestryAssumption>> {
    let Some(receipt) = oracle.assumption_receipt.as_ref() else {
        return Ok(None);
    };
    let InnerReceipt::Succinct(inner) = &receipt.inner else {
        bail!("validated assumption receipt is no longer succinct");
    };
    let raw_seal_bytes = inner.get_seal_bytes();
    let path = recursive_ancestry_case_path(family, RECURSIVE_ANCESTRY_ASSUMPTION_SEAL_FILE);
    let raw_seal = recursive_ancestry_artifact_reference(path.clone(), &raw_seal_bytes)?;
    ensure!(
        auxiliary_seals.insert(path, raw_seal_bytes).is_none(),
        "duplicate assumption raw-seal path"
    );
    let requested_control_root = recursive_ancestry_expected_assumption_root(family)?
        .context("assumption receipt appears in a family with no requested root")?;
    Ok(Some(RecursiveAncestryAssumption {
        claim: project_claim(inner.claim.as_value()?),
        requested_control_root: hex::encode(requested_control_root),
        source_inventory: source_inventory
            .cloned()
            .context("assumption receipt has no producer inventory")?,
        raw_seal,
        terminal: project_terminal(RecursiveOperation::Lift, inner.control_id)?,
    }))
}

fn project_steps(
    oracle: &RecursiveOracle,
    family: RecursiveAncestryFamily,
    final_index: usize,
    auxiliary_seals: &mut BTreeMap<String, Vec<u8>>,
) -> Result<Vec<RecursiveAncestryStep>> {
    let mut steps = Vec::with_capacity(oracle.steps.len());
    for (index, step) in oracle.steps.iter().enumerate() {
        let is_final = index == final_index;
        let raw_seal_bytes = step.receipt.get_seal_bytes();
        let path = if is_final {
            recursive_ancestry_case_path(family, RECURSIVE_ANCESTRY_FINAL_SEAL_FILE)
        } else {
            recursive_ancestry_case_path(
                family,
                &format!("candidate-ancestry-step-{:02}-raw-seal.bin", step.ordinal),
            )
        };
        let raw_seal = recursive_ancestry_artifact_reference(path.clone(), &raw_seal_bytes)?;
        if !is_final {
            ensure!(
                auxiliary_seals.insert(path, raw_seal_bytes).is_none(),
                "duplicate intermediate raw-seal path"
            );
        }
        steps.push(RecursiveAncestryStep {
            ordinal: step.ordinal,
            operation: project_operation(step.operation, &step.inputs)?,
            claim: project_claim(step.receipt.claim.as_value()?),
            raw_seal,
            terminal: project_terminal(step.operation, step.receipt.control_id)?,
        });
    }
    Ok(steps)
}

/// Strictly re-read and bind a projection to its existing and auxiliary bytes.
///
/// This function deliberately delegates grammar, graph, claim, and stock
/// replay to the same shared consumer used by negative validation. It does not
/// replace STARK verification; generator construction establishes that through
/// [`validate_recursive_oracle`].
///
/// # Errors
///
/// Returns an error for malformed JCS, family or identity drift, noncanonical
/// stock semantics, or an exact artifact-set mismatch.
#[allow(clippy::too_many_arguments)]
pub fn validate_projection_bundle(
    source: &[u8],
    expected_family: RecursiveFamily,
    image_id: Digest,
    statement: &[u8],
    expected_profile_id: &str,
    final_raw_seal: &[u8],
    auxiliary_seals: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let profile_id = parse_hex_digest(expected_profile_id, "profile ID")?;
    let projection = parse_recursive_ancestry_jcs(source)?;
    ensure!(
        projection.family == project_family(expected_family),
        "ancestry family differs from caller expectation"
    );
    ensure!(
        projection.program_id == digest_hex(image_id),
        "ancestry program ID differs from caller expectation"
    );
    validate_canonical_recursive_ancestry(&projection, statement, profile_id)?;
    validate_recursive_ancestry_artifacts(&projection, statement, final_raw_seal, auxiliary_seals)
}

fn project_source_inventory(oracle: &RecursiveOracle) -> Result<RecursiveAncestrySourceInventory> {
    let InnerReceipt::Composite(source) = &oracle.source_receipt.inner else {
        bail!("validated recursive source receipt is no longer composite");
    };
    let final_segment = source
        .segments
        .last()
        .context("validated source composite has no final segment")?;
    let output = final_segment
        .claim
        .output
        .as_value()
        .context("source final-segment output is pruned")?
        .as_ref()
        .context("source final-segment claim has no output")?;
    let assumptions = output
        .assumptions
        .as_value()
        .context("source final-segment assumption list is pruned")?;
    let entries = assumptions
        .iter()
        .map(|entry| match entry {
            MaybePruned::Value(assumption) => Ok(RecursiveAncestryInventoryEntry::Revealed {
                claim_digest: digest_hex(assumption.claim),
                control_root: digest_hex(assumption.control_root),
            }),
            MaybePruned::Pruned(digest) => Ok(RecursiveAncestryInventoryEntry::Pruned {
                digest: digest_hex(*digest),
            }),
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(RecursiveAncestrySourceInventory { entries })
}

pub(crate) const fn project_family(family: RecursiveFamily) -> RecursiveAncestryFamily {
    match family {
        RecursiveFamily::TerminalJoin => RecursiveAncestryFamily::TerminalJoin,
        RecursiveFamily::TerminalResolve => RecursiveAncestryFamily::TerminalResolve,
        RecursiveFamily::ResolveThenJoin => RecursiveAncestryFamily::ResolveThenJoin,
    }
}

fn project_operation(
    operation: RecursiveOperation,
    inputs: &RecursiveInputs,
) -> Result<RecursiveAncestryOperation> {
    match (operation, inputs) {
        (RecursiveOperation::Lift, RecursiveInputs::Lift { segment_index }) => {
            Ok(RecursiveAncestryOperation::Lift {
                segment_index: *segment_index,
            })
        }
        (
            RecursiveOperation::Join,
            RecursiveInputs::Join {
                left_step,
                right_step,
            },
        ) => Ok(RecursiveAncestryOperation::Join {
            left_step: *left_step,
            right_step: *right_step,
        }),
        (RecursiveOperation::Resolve, RecursiveInputs::Resolve { conditional_step }) => {
            Ok(RecursiveAncestryOperation::Resolve {
                conditional_step: *conditional_step,
            })
        }
        _ => bail!("recursive operation differs from its producer inputs"),
    }
}

fn project_terminal(
    operation: RecursiveOperation,
    control_id: Digest,
) -> Result<RecursiveAncestryTerminal> {
    let control_id_hex = digest_hex(control_id);
    match operation {
        RecursiveOperation::Lift => Ok(RecursiveAncestryTerminal::Lift {
            segment_po2: normal_lift_segment_po2(&control_id)?,
            control_id: control_id_hex,
        }),
        RecursiveOperation::Join => Ok(RecursiveAncestryTerminal::Join {
            control_id: control_id_hex,
        }),
        RecursiveOperation::Resolve => Ok(RecursiveAncestryTerminal::Resolve {
            control_id: control_id_hex,
        }),
    }
}

fn project_claim(claim: &ReceiptClaim) -> RecursiveAncestryClaim {
    let (system_exit, user_exit) = claim.exit_code.into_pair();
    RecursiveAncestryClaim {
        input_digest: digest_hex(claim.input.digest()),
        pre_state_digest: digest_hex(claim.pre.digest()),
        post_state_digest: digest_hex(claim.post.digest()),
        system_exit,
        user_exit,
        output_digest: digest_hex(claim.output.digest()),
    }
}

fn parse_hex_digest(value: &str, label: &str) -> Result<[u8; DIGEST_BYTES]> {
    validate_lower_hex_exact(value, DIGEST_BYTES)
        .with_context(|| format!("{label} is not exactly 32 lowercase hexadecimal bytes"))?;
    let bytes = hex::decode(value).with_context(|| format!("cannot decode {label}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} does not contain exactly 32 bytes"))
}

fn digest_hex(digest: Digest) -> String {
    hex::encode(digest.as_bytes())
}
