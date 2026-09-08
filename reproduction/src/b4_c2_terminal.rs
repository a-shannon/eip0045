//! Closed C2 producers for the 18 deterministic terminal-policy rows.
//!
//! These rows do not select receipt fixtures. They project one admitted
//! terminal callback record from the authenticated initial-profile manifest,
//! then replace only its 32-byte control ID with either the fixed unknown-zero
//! sentinel or one exact stock control outside the manifest allowlist.

use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

use crate::{
    b4::{
        B4ArtifactBinding, B4ArtifactEncoding, B4BindingState, B4ByteOperation, B4ByteTarget,
        B4NegativeCase, B4NegativeMaterialization, B4NegativeMutation,
    },
    b4_materialization_set::{
        B4AuthenticatedMaterializationTopLevelV1, B4ClosedReconstructedExecutionV1,
        close_production_execution,
    },
    b4_mutation::{B4MaterializationReplayAdapterV1, reconstruct_byte_edit},
    b4_plan::{
        B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanExecutionV1,
        B4NegativeQaResultCode,
    },
    b4_terminal::{
        B4_EIP_ALLOWED_CONTROL_COUNT, B4_EIP_EXCLUDED_CONTROL_COUNT, B4_STOCK_CONTROL_COUNT,
        B4_STOCK_CONTROL_LAYOUT,
    },
    profile_manifest::StarkProfileManifestV1,
};

const TERMINAL_FIRST_INDEX: usize = 113;
const TERMINAL_END_INDEX_EXCLUSIVE: usize = 131;
const TERMINAL_RECORD_BYTES: usize = 36;
const TERMINAL_CONTROL_OFFSET: usize = 4;
const TERMINAL_CONTROL_OFFSET_U64: u64 = 4;
const CONTROL_ID_BYTES: usize = 32;
const UNKNOWN_CONTROL_ID: [u8; CONTROL_ID_BYTES] = [0; CONTROL_ID_BYTES];
const UNKNOWN_EXECUTION_ID: &str = "terminal-control-id-unknown--unknown-control-id";
const UNKNOWN_BASE_SELECTOR: &str = "stock-control-table-v1";
const EXCLUDED_EXECUTION_PREFIX: &str = "terminal-excluded-control-id-sweep--";
const EXCLUDED_BASE_SELECTOR: &str = "stock-excluded-control-table-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "the four distinct protocol identifiers intentionally retain their full identity suffixes"
)]
struct TerminalReplacement {
    execution_id: String,
    variant_id: String,
    base_selector_id: &'static str,
    control_id: [u8; CONTROL_ID_BYTES],
}

#[derive(Clone, Copy, Debug)]
struct TerminalPolicyReplayAdapterV1<'a> {
    base_selector_id: &'a str,
    base: &'a [u8],
    output: &'a [u8],
    before_control_id: [u8; CONTROL_ID_BYTES],
    replacement_control_id: [u8; CONTROL_ID_BYTES],
}

impl B4MaterializationReplayAdapterV1 for TerminalPolicyReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::ArtifactValidator
    }

    fn base_bytes(&self) -> &[u8] {
        self.base
    }

    fn output_bytes(&self) -> &[u8] {
        self.output
    }

    fn replay_recipe(
        &self,
        base_selector_id: &str,
        materialization: &B4NegativeMaterialization,
    ) -> Result<()> {
        ensure!(
            base_selector_id == self.base_selector_id,
            "terminal-policy recipe selects the wrong compiled base"
        );
        let B4NegativeMaterialization::Mutation {
            mutation: B4NegativeMutation::ByteEdit { edit, target },
        } = materialization
        else {
            anyhow::bail!("terminal-policy recipe is not one exact byte replacement");
        };
        let B4ByteOperation::Replace {
            before_hex,
            replacement_hex,
            offset,
        } = edit
        else {
            anyhow::bail!("terminal-policy recipe is not one exact byte replacement");
        };
        ensure!(
            *target == B4ByteTarget::TerminalPolicyProbe,
            "terminal-policy recipe selects a different byte target"
        );
        ensure!(
            *offset == TERMINAL_CONTROL_OFFSET_U64
                && before_hex == &hex::encode(self.before_control_id)
                && replacement_hex == &hex::encode(self.replacement_control_id),
            "terminal-policy replacement differs from the compiled control transition"
        );
        ensure!(
            reconstruct_byte_edit(self.base, edit)? == self.output,
            "terminal-policy output differs from the exact byte replacement"
        );
        Ok(())
    }
}

/// Reconstruct one of the exact terminal-policy executions at indices
/// `113..=130`.
///
/// Indices outside that range are deliberately ignored without inspecting the
/// supplied plan row or top-level authority, allowing the composite producer
/// to delegate them to a different closed module.
pub(crate) fn reconstruct_terminal_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    if !is_terminal_index(execution_index) {
        return Ok(None);
    }
    let manifest_source = authenticated_initial_manifest(top_level)?;
    reconstruct_terminal_execution_from_manifest(
        execution_index,
        planned,
        &top_level.negative_plan,
        manifest_source,
    )
    .map(Some)
}

fn reconstruct_terminal_execution_from_manifest(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    manifest_source: &[u8],
) -> Result<B4ClosedReconstructedExecutionV1> {
    ensure!(
        is_terminal_index(execution_index),
        "terminal-policy producer received an index outside its closed range"
    );
    let manifest = StarkProfileManifestV1::decode(manifest_source)
        .context("cannot decode authenticated initial-profile manifest")?;
    manifest
        .validate_initial_profile_target()
        .context("authenticated manifest is not the compiled initial profile")?;

    let replacements = derive_terminal_replacements(&manifest)?;
    let replacement = replacements
        .get(execution_index - TERMINAL_FIRST_INDEX)
        .context("terminal-policy replacement index is outside the closed table")?;
    validate_planned_execution(planned, replacement)?;

    let base_control_id = manifest.terminal_controls()[0].control_id();
    let base = terminal_record(manifest.outer_po2(), base_control_id);
    let materialization = terminal_materialization(base_control_id, replacement.control_id);
    let registry_row = B4NegativeCase {
        execution_id: replacement.execution_id.clone(),
        base_selector_id: replacement.base_selector_id.to_owned(),
        materialization_domain: B4MaterializationDomain::ArtifactValidator,
        materialization,
    };
    let subject = replace_terminal_control(&base, replacement.control_id)?;
    let adapter = TerminalPolicyReplayAdapterV1 {
        base_selector_id: replacement.base_selector_id,
        base: &base,
        output: &subject,
        before_control_id: base_control_id,
        replacement_control_id: replacement.control_id,
    };

    close_production_execution(
        execution_index,
        planned,
        negative_plan_jcs,
        registry_row,
        &adapter,
        &adapter,
        subject.clone(),
        vec![manifest_source.to_vec()],
    )
}

fn authenticated_initial_manifest(
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
) -> Result<&[u8]> {
    let binding = &top_level.expanded_registry.profile.manifest;
    let source = top_level
        .source_artifacts
        .get(&binding.path)
        .context("authenticated source inventory lacks the profile manifest")?;
    validate_authenticated_manifest_binding(
        source,
        binding,
        &top_level.expanded_registry.profile.profile_id,
    )?;
    Ok(source)
}

fn validate_authenticated_manifest_binding(
    source: &[u8],
    binding: &B4ArtifactBinding,
    expected_profile_id: &str,
) -> Result<()> {
    ensure!(
        binding.state == B4BindingState::Bound && binding.encoding == B4ArtifactEncoding::RawBytes,
        "expanded registry does not bind one raw initial-profile manifest"
    );
    ensure!(
        u64::try_from(source.len())? == binding.byte_length
            && hex::encode(Sha256::digest(source)) == binding.sha256,
        "profile-manifest bytes differ from the authenticated registry binding"
    );
    let manifest = StarkProfileManifestV1::decode(source)
        .context("authenticated profile-manifest bytes do not decode")?;
    manifest
        .validate_initial_profile_target()
        .context("authenticated profile manifest differs from the initial profile target")?;
    ensure!(
        hex::encode(manifest.profile_id()?) == expected_profile_id,
        "authenticated manifest and expanded registry bind different profile IDs"
    );
    Ok(())
}

fn derive_terminal_replacements(
    manifest: &StarkProfileManifestV1,
) -> Result<Vec<TerminalReplacement>> {
    let allowed = manifest
        .terminal_controls()
        .iter()
        .map(|control| control.control_id())
        .collect::<BTreeSet<_>>();
    ensure!(
        allowed.len() == B4_EIP_ALLOWED_CONTROL_COUNT,
        "initial manifest does not contain exactly ten distinct terminal controls"
    );

    let mut stock = BTreeSet::new();
    let mut families = BTreeSet::new();
    let mut excluded = Vec::with_capacity(B4_EIP_EXCLUDED_CONTROL_COUNT);
    for (position, row) in B4_STOCK_CONTROL_LAYOUT.into_iter().enumerate() {
        ensure!(
            usize::try_from(row.stock_index)? == position,
            "compiled stock-control index differs from its array position"
        );
        ensure!(
            families.insert(row.family),
            "compiled stock-control table contains a duplicate family label"
        );
        let control_id = decode_control_id(row.control_id)?;
        ensure!(
            stock.insert(control_id),
            "compiled stock-control table contains a duplicate control ID"
        );
        let admitted_by_manifest = allowed.contains(&control_id);
        ensure!(
            row.eip_allowed == admitted_by_manifest,
            "compiled stock disposition differs from the manifest allowlist for {}",
            row.family
        );
        if !admitted_by_manifest {
            excluded.push((row.family, control_id));
        }
    }
    ensure!(
        stock.len() == B4_STOCK_CONTROL_COUNT
            && excluded.len() == B4_EIP_EXCLUDED_CONTROL_COUNT
            && stock.difference(&allowed).count() == B4_EIP_EXCLUDED_CONTROL_COUNT
            && allowed.difference(&stock).next().is_none(),
        "compiled stock/manifest control partition is not exactly 27 = 10 + 17"
    );
    ensure!(
        !stock.contains(&UNKNOWN_CONTROL_ID),
        "fixed unknown control sentinel unexpectedly appears in the stock table"
    );

    let mut replacements = Vec::with_capacity(1 + B4_EIP_EXCLUDED_CONTROL_COUNT);
    replacements.push(TerminalReplacement {
        execution_id: UNKNOWN_EXECUTION_ID.to_owned(),
        variant_id: "unknown-control-id".to_owned(),
        base_selector_id: UNKNOWN_BASE_SELECTOR,
        control_id: UNKNOWN_CONTROL_ID,
    });
    replacements.extend(
        excluded
            .into_iter()
            .map(|(family, control_id)| TerminalReplacement {
                execution_id: format!("{EXCLUDED_EXECUTION_PREFIX}{family}"),
                variant_id: family.to_owned(),
                base_selector_id: EXCLUDED_BASE_SELECTOR,
                control_id,
            }),
    );
    ensure!(
        replacements.len() == TERMINAL_END_INDEX_EXCLUSIVE - TERMINAL_FIRST_INDEX,
        "terminal-policy replacement table does not contain exactly 18 rows"
    );
    Ok(replacements)
}

fn validate_planned_execution(
    planned: &B4NegativePlanExecutionV1,
    replacement: &TerminalReplacement,
) -> Result<()> {
    ensure!(
        planned.execution_id == replacement.execution_id
            && planned.variant_id == replacement.variant_id
            && planned.base_selector_id == replacement.base_selector_id
            && planned.materialization_domain == B4MaterializationDomain::ArtifactValidator
            && planned.execution_surface == B4NegativeExecutionSurface::TerminalPolicy
            && planned.qa_result_code == B4NegativeQaResultCode::RawSealControlIdNotAllowed,
        "canonical plan row differs from the closed terminal-policy mapping"
    );
    Ok(())
}

const fn is_terminal_index(execution_index: usize) -> bool {
    execution_index >= TERMINAL_FIRST_INDEX && execution_index < TERMINAL_END_INDEX_EXCLUSIVE
}

fn terminal_record(outer_po2: u8, control_id: [u8; CONTROL_ID_BYTES]) -> Vec<u8> {
    let mut record = Vec::with_capacity(TERMINAL_RECORD_BYTES);
    record.extend_from_slice(&u32::from(outer_po2).to_le_bytes());
    record.extend_from_slice(&control_id);
    debug_assert_eq!(record.len(), TERMINAL_RECORD_BYTES);
    record
}

fn terminal_materialization(
    before_control_id: [u8; CONTROL_ID_BYTES],
    replacement_control_id: [u8; CONTROL_ID_BYTES],
) -> B4NegativeMaterialization {
    B4NegativeMaterialization::Mutation {
        mutation: B4NegativeMutation::ByteEdit {
            edit: B4ByteOperation::Replace {
                before_hex: hex::encode(before_control_id),
                replacement_hex: hex::encode(replacement_control_id),
                offset: TERMINAL_CONTROL_OFFSET_U64,
            },
            target: B4ByteTarget::TerminalPolicyProbe,
        },
    }
}

fn replace_terminal_control(
    base: &[u8],
    replacement_control_id: [u8; CONTROL_ID_BYTES],
) -> Result<Vec<u8>> {
    ensure!(
        base.len() == TERMINAL_RECORD_BYTES,
        "terminal-policy base is not exactly 36 bytes"
    );
    let mut output = base.to_vec();
    output[TERMINAL_CONTROL_OFFSET..].copy_from_slice(&replacement_control_id);
    Ok(output)
}

fn decode_control_id(source: &str) -> Result<[u8; CONTROL_ID_BYTES]> {
    hex::decode(source)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("stock control ID is not exactly 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        b4_mutation::Eip0045B4MaterializationIdentityV1,
        b4_negative_io::Eip0045B4NegativeVerifierInputV1, b4_plan::Eip0045B4NegativePlanV1,
    };

    const MANIFEST: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin");

    fn manifest() -> StarkProfileManifestV1 {
        let manifest = StarkProfileManifestV1::decode(MANIFEST).unwrap();
        manifest.validate_initial_profile_target().unwrap();
        manifest
    }

    fn plan_and_source() -> (Eip0045B4NegativePlanV1, Vec<u8>) {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let source = plan.to_canonical_jcs().unwrap();
        (plan, source)
    }

    fn planned_at(plan: &Eip0045B4NegativePlanV1, index: usize) -> &B4NegativePlanExecutionV1 {
        plan.groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .nth(index)
            .unwrap()
    }

    #[test]
    fn stock_minus_manifest_is_the_exact_ordered_seventeen_row_partition() {
        let replacements = derive_terminal_replacements(&manifest()).unwrap();
        assert_eq!(replacements.len(), 18);
        assert_eq!(
            replacements
                .iter()
                .map(|replacement| replacement.variant_id.as_str())
                .collect::<Vec<_>>(),
            [
                "unknown-control-id",
                "identity",
                "join-povw",
                "join-unwrap-povw",
                "lift-po2-14",
                "lift-povw-po2-14",
                "lift-povw-po2-15",
                "lift-povw-po2-16",
                "lift-povw-po2-17",
                "lift-povw-po2-18",
                "lift-povw-po2-19",
                "lift-povw-po2-20",
                "lift-povw-po2-21",
                "lift-povw-po2-22",
                "resolve-povw",
                "resolve-unwrap-povw",
                "union",
                "unwrap-povw",
            ]
        );
        assert_eq!(replacements[0].control_id, UNKNOWN_CONTROL_ID);
        assert_eq!(
            replacements
                .iter()
                .map(|replacement| replacement.control_id)
                .collect::<BTreeSet<_>>()
                .len(),
            replacements.len()
        );
    }

    #[test]
    fn every_terminal_row_closes_exact_base_subject_context_and_documents() {
        let profile = manifest();
        let base_control_id = profile.terminal_controls()[0].control_id();
        let expected_base = terminal_record(profile.outer_po2(), base_control_id);
        let replacements = derive_terminal_replacements(&profile).unwrap();
        let (plan, plan_source) = plan_and_source();

        for index in TERMINAL_FIRST_INDEX..TERMINAL_END_INDEX_EXCLUSIVE {
            let planned = planned_at(&plan, index);
            let closed = reconstruct_terminal_execution_from_manifest(
                index,
                planned,
                &plan_source,
                MANIFEST,
            )
            .unwrap();
            let expected = &replacements[index - TERMINAL_FIRST_INDEX];

            assert_eq!(
                closed.derived_registry_row.execution_id,
                expected.execution_id
            );
            assert_eq!(
                closed.derived_registry_row.base_selector_id,
                expected.base_selector_id
            );
            assert_eq!(closed.base, expected_base);
            assert_eq!(closed.subject.len(), TERMINAL_RECORD_BYTES);
            assert_eq!(&closed.subject[..TERMINAL_CONTROL_OFFSET], &[18, 0, 0, 0]);
            assert_eq!(
                &closed.subject[TERMINAL_CONTROL_OFFSET..],
                expected.control_id.as_slice()
            );
            assert_eq!(closed.contexts, vec![MANIFEST.to_vec()]);

            let identity = Eip0045B4MaterializationIdentityV1::from_canonical_jcs(
                &closed.materialization_identity_jcs,
            )
            .unwrap();
            assert_eq!(
                identity.base_byte_length,
                u64::try_from(TERMINAL_RECORD_BYTES).unwrap()
            );
            assert_eq!(
                identity.output_byte_length,
                u64::try_from(TERMINAL_RECORD_BYTES).unwrap()
            );

            let input =
                Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&closed.negative_input_jcs)
                    .unwrap();
            assert_eq!(input.context.len(), 1);
            assert_eq!(input.context[0].role, "context-00");
            assert_eq!(input.context[0].path, "context/00.bin");
            assert_eq!(
                input.context[0].byte_length,
                u64::try_from(MANIFEST.len()).unwrap()
            );
        }
    }

    #[test]
    fn terminal_replay_adapter_rejects_selector_target_offset_and_id_drift() {
        let profile = manifest();
        let before = profile.terminal_controls()[0].control_id();
        let replacement = UNKNOWN_CONTROL_ID;
        let base = terminal_record(profile.outer_po2(), before);
        let output = replace_terminal_control(&base, replacement).unwrap();
        let adapter = TerminalPolicyReplayAdapterV1 {
            base_selector_id: UNKNOWN_BASE_SELECTOR,
            base: &base,
            output: &output,
            before_control_id: before,
            replacement_control_id: replacement,
        };
        let exact = terminal_materialization(before, replacement);
        adapter
            .replay_recipe(UNKNOWN_BASE_SELECTOR, &exact)
            .unwrap();
        assert!(
            adapter
                .replay_recipe(EXCLUDED_BASE_SELECTOR, &exact)
                .is_err()
        );

        let wrong_target = B4NegativeMaterialization::Mutation {
            mutation: B4NegativeMutation::ByteEdit {
                edit: B4ByteOperation::Replace {
                    before_hex: hex::encode(before),
                    replacement_hex: hex::encode(replacement),
                    offset: TERMINAL_CONTROL_OFFSET_U64,
                },
                target: B4ByteTarget::RawSeal,
            },
        };
        assert!(
            adapter
                .replay_recipe(UNKNOWN_BASE_SELECTOR, &wrong_target)
                .is_err()
        );

        let wrong_offset = B4NegativeMaterialization::Mutation {
            mutation: B4NegativeMutation::ByteEdit {
                edit: B4ByteOperation::Replace {
                    before_hex: hex::encode(before),
                    replacement_hex: hex::encode(replacement),
                    offset: 0,
                },
                target: B4ByteTarget::TerminalPolicyProbe,
            },
        };
        assert!(
            adapter
                .replay_recipe(UNKNOWN_BASE_SELECTOR, &wrong_offset)
                .is_err()
        );

        let mut wrong_before = before;
        wrong_before[0] ^= 1;
        let wrong_before_recipe = terminal_materialization(wrong_before, replacement);
        assert!(
            adapter
                .replay_recipe(UNKNOWN_BASE_SELECTOR, &wrong_before_recipe)
                .is_err()
        );

        let mut wrong_replacement = replacement;
        wrong_replacement[0] = 1;
        let wrong_replacement_recipe = terminal_materialization(before, wrong_replacement);
        assert!(
            adapter
                .replay_recipe(UNKNOWN_BASE_SELECTOR, &wrong_replacement_recipe)
                .is_err()
        );
    }

    #[test]
    fn authenticated_manifest_binding_is_isolated_and_fail_closed() {
        let profile = manifest();
        let expected_profile_id = hex::encode(profile.profile_id().unwrap());
        let binding = B4ArtifactBinding {
            byte_length: u64::try_from(MANIFEST.len()).unwrap(),
            encoding: B4ArtifactEncoding::RawBytes,
            path: "profiles/risc0-v3-succinct/manifest.bin".to_owned(),
            sha256: hex::encode(Sha256::digest(MANIFEST)),
            state: B4BindingState::Bound,
        };
        validate_authenticated_manifest_binding(MANIFEST, &binding, &expected_profile_id).unwrap();

        let mut wrong_sha256 = binding.clone();
        wrong_sha256.sha256 = "00".repeat(32);
        assert!(
            validate_authenticated_manifest_binding(MANIFEST, &wrong_sha256, &expected_profile_id)
                .is_err()
        );

        let mut wrong_length = binding.clone();
        wrong_length.byte_length += 1;
        assert!(
            validate_authenticated_manifest_binding(MANIFEST, &wrong_length, &expected_profile_id)
                .is_err()
        );

        let mut wrong_encoding = binding.clone();
        wrong_encoding.encoding = B4ArtifactEncoding::Rfc8785Jcs;
        assert!(
            validate_authenticated_manifest_binding(
                MANIFEST,
                &wrong_encoding,
                &expected_profile_id
            )
            .is_err()
        );

        let mut wrong_state = binding.clone();
        wrong_state.state = B4BindingState::Pending;
        assert!(
            validate_authenticated_manifest_binding(MANIFEST, &wrong_state, &expected_profile_id)
                .is_err()
        );

        assert!(
            validate_authenticated_manifest_binding(MANIFEST, &binding, &"00".repeat(32)).is_err()
        );

        let mut mutated_manifest = MANIFEST.to_vec();
        mutated_manifest[0] ^= 1;
        let mut rebound_mutation = binding;
        rebound_mutation.sha256 = hex::encode(Sha256::digest(&mutated_manifest));
        assert!(
            validate_authenticated_manifest_binding(
                &mutated_manifest,
                &rebound_mutation,
                &expected_profile_id
            )
            .is_err()
        );
    }

    #[test]
    fn index_dispatch_is_exactly_113_through_130() {
        assert!(!is_terminal_index(112));
        assert!(is_terminal_index(113));
        assert!(is_terminal_index(130));
        assert!(!is_terminal_index(131));

        let replacements = derive_terminal_replacements(&manifest()).unwrap();
        assert_eq!(
            replacements
                .iter()
                .enumerate()
                .map(|(offset, replacement)| {
                    (
                        TERMINAL_FIRST_INDEX + offset,
                        replacement.execution_id.as_str(),
                    )
                })
                .collect::<Vec<_>>()
                .first()
                .copied(),
            Some((113, UNKNOWN_EXECUTION_ID))
        );
        assert_eq!(
            replacements.last().unwrap().execution_id,
            "terminal-excluded-control-id-sweep--unwrap-povw"
        );
    }
}
