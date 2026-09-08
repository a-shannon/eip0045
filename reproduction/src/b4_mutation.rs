//! Authenticated reconstruction and domain-generic B4 materialization identities.
//!
//! A materialization identity is a digest-only evidence record: it never
//! archives the materialized output. Its authority comes from replay against
//! three independently supplied inputs: the exact canonical negative plan,
//! the exact registry row (including its materialization recipe), and a
//! domain-typed adapter carrying the exact base and output bytes.

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::b4::{
    B4BoundaryShiftDirection, B4ByteOperation, B4NegativeCase, B4NegativeMaterialization,
    B4NegativeMutation, B4SequenceOperation, B4SequenceTarget, validate_byte_operation,
    validate_sequence_operation,
};
use crate::b4_plan::{B4MaterializationDomain, B4NegativePlanExecutionV1, Eip0045B4NegativePlanV1};
use crate::b4_subject::{B4SequenceSubjectElement, Eip0045B4SequenceSubjectV1};
use crate::canonical::{canonical_json_bytes, validate_canonical_json_source};

/// Exact format label for one B4 materialization identity.
pub const B4_MATERIALIZATION_IDENTITY_FORMAT: &str = "Eip0045B4MaterializationIdentityV1";
/// Exact format version for one B4 materialization identity.
pub const B4_MATERIALIZATION_IDENTITY_FORMAT_VERSION: u8 = 1;

const MAX_MATERIALIZATION_BYTES: usize = 512 * 1024 * 1024;
const MAX_MATERIALIZATION_IDENTITY_BYTES: usize = 64 * 1024;
const MAX_MATERIALIZATION_RECIPE_BYTES: usize = 8 * 1024 * 1024;
const MAX_NEGATIVE_PLAN_BYTES: usize = 128 * 1024;
const MAX_SEMANTIC_ID_BYTES: usize = 128;

/// Deterministic materialization replay point used by the semantic validator.
///
/// This trait is an integration boundary, not evidence by itself. The
/// canonical semantic report must bind the exact implementation artifact and
/// use the canonical adapter for the plan row's domain. A materialization
/// identity only records the bindings produced after this adapter succeeds; it
/// does not prove that an arbitrary adapter implementation is correct.
pub trait B4MaterializationReplayAdapterV1: std::fmt::Debug {
    /// Closed domain implemented by this adapter.
    fn materialization_domain(&self) -> B4MaterializationDomain;

    /// Exact independently selected base bytes.
    fn base_bytes(&self) -> &[u8];

    /// Exact materialized bytes consumed by the named validator domain.
    fn output_bytes(&self) -> &[u8];

    /// Replay and validate the exact registry recipe against the supplied
    /// plan selector and the adapter's base/output bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the recipe is outside this adapter's grammar or
    /// reconstruction differs from the supplied output.
    fn replay_recipe(
        &self,
        base_selector_id: &str,
        materialization: &B4NegativeMaterialization,
    ) -> Result<()>;
}

/// Generic adapter for a byte edit over an independently projected byte base.
///
/// It proves the byte edit only. Selection and inverse projection of the base
/// remain obligations of the canonical domain adapter and semantic report.
#[derive(Clone, Copy, Debug)]
pub struct B4ByteEditReplayAdapterV1<'a> {
    /// Domain which consumes the projected bytes.
    pub materialization_domain: B4MaterializationDomain,
    /// Exact independently projected base bytes.
    pub base: &'a [u8],
    /// Exact reconstructed output bytes.
    pub output: &'a [u8],
}

impl B4MaterializationReplayAdapterV1 for B4ByteEditReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        self.materialization_domain
    }

    fn base_bytes(&self) -> &[u8] {
        self.base
    }

    fn output_bytes(&self) -> &[u8] {
        self.output
    }

    fn replay_recipe(
        &self,
        _base_selector_id: &str,
        materialization: &B4NegativeMaterialization,
    ) -> Result<()> {
        let B4NegativeMaterialization::Mutation {
            mutation: B4NegativeMutation::ByteEdit { edit, .. },
        } = materialization
        else {
            bail!("byte-edit adapter received a non-byte materialization recipe");
        };
        let reconstructed = reconstruct_byte_edit(self.base, edit)?;
        ensure!(
            reconstructed == self.output,
            "byte-edit adapter output differs from independent reconstruction"
        );
        Ok(())
    }
}

/// Generic adapter for an edit over an exact
/// [`Eip0045B4SequenceSubjectV1`] base.
///
/// It must not be used for domain formats such as the abstract tree probe. Such
/// formats provide their own trait implementation.
#[derive(Clone, Copy, Debug)]
pub struct B4SequenceSubjectReplayAdapterV1<'a> {
    /// Domain which consumes the sequence subject.
    pub materialization_domain: B4MaterializationDomain,
    /// Exact canonical sequence-subject base bytes.
    pub base: &'a [u8],
    /// Exact canonical reconstructed sequence-subject bytes.
    pub output: &'a [u8],
}

impl B4MaterializationReplayAdapterV1 for B4SequenceSubjectReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        self.materialization_domain
    }

    fn base_bytes(&self) -> &[u8] {
        self.base
    }

    fn output_bytes(&self) -> &[u8] {
        self.output
    }

    fn replay_recipe(
        &self,
        _base_selector_id: &str,
        materialization: &B4NegativeMaterialization,
    ) -> Result<()> {
        let B4NegativeMaterialization::Mutation {
            mutation: B4NegativeMutation::SequenceEdit { edit, target },
        } = materialization
        else {
            bail!("sequence-subject adapter received a non-sequence materialization recipe");
        };
        let reconstructed = reconstruct_sequence_edit(self.base, *target, edit)?;
        ensure!(
            reconstructed == self.output,
            "sequence-subject adapter output differs from independent reconstruction"
        );
        Ok(())
    }
}

/// Adapter for selecting one already authenticated fixture without mutation.
#[derive(Clone, Copy, Debug)]
pub struct B4FixtureSelectionReplayAdapterV1<'a> {
    /// Domain which consumes the selected fixture.
    pub materialization_domain: B4MaterializationDomain,
    /// Exact independently authenticated fixture bytes.
    pub fixture: &'a [u8],
}

impl B4MaterializationReplayAdapterV1 for B4FixtureSelectionReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        self.materialization_domain
    }

    fn base_bytes(&self) -> &[u8] {
        self.fixture
    }

    fn output_bytes(&self) -> &[u8] {
        self.fixture
    }

    fn replay_recipe(
        &self,
        base_selector_id: &str,
        materialization: &B4NegativeMaterialization,
    ) -> Result<()> {
        let B4NegativeMaterialization::FixtureSelection { fixture_id } = materialization else {
            bail!("fixture-selection adapter received a mutation recipe");
        };
        ensure!(
            fixture_id == base_selector_id,
            "fixture selection differs from the plan base selector"
        );
        Ok(())
    }
}

/// Canonical identity binding one plan row, registry recipe, base, and output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4MaterializationIdentityV1 {
    /// Exact identity format label.
    pub format: String,
    /// Exact identity format version.
    pub format_version: u8,
    /// Exact selector copied from and checked against the plan and registry row.
    pub base_selector_id: String,
    /// Exact base byte length.
    pub base_byte_length: u64,
    /// SHA-256 of the exact base bytes.
    pub base_sha256: String,
    /// Exact closed-plan execution ID (`group-id--variant-id`).
    pub execution_id: String,
    /// Closed owner of materialization and validation.
    pub materialization_domain: B4MaterializationDomain,
    /// Exact canonical registry materialization-recipe byte length.
    pub materialization_recipe_byte_length: u64,
    /// SHA-256 of the exact canonical registry materialization recipe.
    pub materialization_recipe_sha256: String,
    /// Exact canonical negative-plan byte length.
    pub negative_plan_byte_length: u64,
    /// SHA-256 of the exact canonical negative-plan bytes.
    pub negative_plan_sha256: String,
    /// Exact reconstructed output byte length.
    pub output_byte_length: u64,
    /// SHA-256 of the exact reconstructed output bytes.
    pub output_sha256: String,
}

impl Eip0045B4MaterializationIdentityV1 {
    /// Parse an exact RFC 8785 identity and reject duplicate or unknown fields.
    ///
    /// # Errors
    ///
    /// Returns an error for non-canonical source bytes, a closed-shape defect,
    /// invalid digest/length facts, or a family mismatch.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            source.len() <= MAX_MATERIALIZATION_IDENTITY_BYTES,
            "B4 materialization identity exceeds the canonical-byte bound"
        );
        let value = validate_canonical_json_source(source)
            .context("B4 materialization identity is not exact RFC 8785 JCS")?;
        let identity: Self =
            serde_json::from_value(value).context("invalid B4 materialization identity shape")?;
        identity.validate()?;
        ensure!(
            identity.to_canonical_jcs()? == source,
            "B4 materialization identity does not round-trip byte-exactly"
        );
        Ok(identity)
    }

    /// Serialize this identity to exact RFC 8785 JCS bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the identity is invalid or exceeds the V1 bound.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value =
            serde_json::to_value(self).context("cannot serialize B4 materialization identity")?;
        let bytes = canonical_json_bytes(&value)?;
        ensure!(
            bytes.len() <= MAX_MATERIALIZATION_IDENTITY_BYTES,
            "B4 materialization identity exceeds the canonical-byte bound"
        );
        Ok(bytes)
    }

    /// Validate the identity's closed lexical and arithmetic invariants.
    ///
    /// Full trust requires [`verify_materialization_identity_with_adapter`],
    /// which replays the exact plan row and registry recipe through the
    /// canonical domain-specific adapter.
    ///
    /// # Errors
    ///
    /// Returns an error for a format, identifier, digest, or length defect.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == B4_MATERIALIZATION_IDENTITY_FORMAT,
            "wrong B4 materialization-identity format label"
        );
        ensure!(
            self.format_version == B4_MATERIALIZATION_IDENTITY_FORMAT_VERSION,
            "wrong B4 materialization-identity format version"
        );
        validate_semantic_id(&self.base_selector_id, "materialization base selector ID")?;
        validate_execution_id(&self.execution_id)?;
        validate_digest(&self.base_sha256, "materialization base SHA-256")?;
        validate_digest(
            &self.materialization_recipe_sha256,
            "materialization-recipe SHA-256",
        )?;
        validate_digest(&self.negative_plan_sha256, "negative-plan SHA-256")?;
        validate_digest(&self.output_sha256, "materialization output SHA-256")?;
        ensure!(
            (1..=MAX_MATERIALIZATION_RECIPE_BYTES as u64)
                .contains(&self.materialization_recipe_byte_length),
            "materialization-recipe length is outside the closed bound"
        );
        ensure!(
            (1..=MAX_NEGATIVE_PLAN_BYTES as u64).contains(&self.negative_plan_byte_length),
            "negative-plan length is outside the closed bound"
        );
        ensure!(
            self.base_byte_length <= MAX_MATERIALIZATION_BYTES as u64
                && self.output_byte_length <= MAX_MATERIALIZATION_BYTES as u64,
            "materialization base or output length exceeds the closed bound"
        );
        Ok(())
    }
}

/// Reconstruct one authenticated byte edit.
///
/// # Errors
///
/// Returns an error when the base or result exceeds the bound, an index/range
/// is impossible, a before-witness differs, or the operation would be a no-op.
pub fn reconstruct_byte_edit(base: &[u8], operation: &B4ByteOperation) -> Result<Vec<u8>> {
    ensure!(
        base.len() <= MAX_MATERIALIZATION_BYTES,
        "byte-mutation base exceeds the closed bound"
    );
    validate_byte_operation(operation)?;

    let output = match operation {
        B4ByteOperation::Delete { before_hex, offset } => {
            let before = decode_hex(before_hex, "deleted bytes")?;
            let start = checked_index(*offset, "byte deletion offset")?;
            let end = start
                .checked_add(before.len())
                .context("byte deletion range overflows usize")?;
            ensure!(end <= base.len(), "byte deletion range exceeds the base");
            ensure!(
                base[start..end] == before,
                "byte deletion witness does not match the base range"
            );
            let mut output = Vec::with_capacity(base.len() - before.len());
            output.extend_from_slice(&base[..start]);
            output.extend_from_slice(&base[end..]);
            output
        }
        B4ByteOperation::Insert {
            inserted_hex,
            offset,
        } => {
            let inserted = decode_hex(inserted_hex, "inserted bytes")?;
            let start = checked_index(*offset, "byte insertion offset")?;
            ensure!(
                start <= base.len(),
                "byte insertion offset exceeds the base"
            );
            let output_len = base
                .len()
                .checked_add(inserted.len())
                .context("byte insertion output length overflows usize")?;
            ensure!(
                output_len <= MAX_MATERIALIZATION_BYTES,
                "byte insertion output exceeds the closed bound"
            );
            let mut output = Vec::with_capacity(output_len);
            output.extend_from_slice(&base[..start]);
            output.extend_from_slice(&inserted);
            output.extend_from_slice(&base[start..]);
            output
        }
        B4ByteOperation::Replace {
            before_hex,
            replacement_hex,
            offset,
        } => {
            let before = decode_hex(before_hex, "replaced bytes")?;
            let replacement = decode_hex(replacement_hex, "replacement bytes")?;
            let start = checked_index(*offset, "byte replacement offset")?;
            let end = start
                .checked_add(before.len())
                .context("byte replacement range overflows usize")?;
            ensure!(end <= base.len(), "byte replacement range exceeds the base");
            ensure!(
                base[start..end] == before,
                "byte replacement witness does not match the base range"
            );
            let mut output = base.to_vec();
            output[start..end].copy_from_slice(&replacement);
            output
        }
        B4ByteOperation::Truncate {
            before_hex,
            new_length,
            original_length,
        } => {
            let declared_original = checked_index(*original_length, "original byte length")?;
            ensure!(
                declared_original == base.len(),
                "truncation originalLength does not equal the base length"
            );
            let boundary = checked_index(*new_length, "truncation boundary")?;
            let witness = decode_hex(before_hex, "truncation witness")?;
            let witness_end = boundary
                .checked_add(witness.len())
                .context("truncation witness range overflows usize")?;
            ensure!(
                witness_end <= base.len(),
                "truncation witness exceeds the removed suffix"
            );
            ensure!(
                base[boundary..witness_end] == witness,
                "truncation witness does not match the removed suffix boundary"
            );
            base[..boundary].to_vec()
        }
    };

    ensure!(output != base, "byte mutation reconstructed a no-op");
    ensure!(
        output.len() <= MAX_MATERIALIZATION_BYTES,
        "byte-mutation output exceeds the closed bound"
    );
    Ok(output)
}

/// Reconstruct one authenticated edit over an exact canonical sequence subject.
///
/// The returned bytes are the complete mutated subject in exact RFC 8785 JCS.
///
/// # Errors
///
/// Returns an error when the base is not a canonical subject for `target`, an
/// index/range/witness is invalid, an inserted/replacement element is invalid,
/// uniqueness would be lost, or the result would be a no-op.
pub fn reconstruct_sequence_edit(
    base: &[u8],
    target: B4SequenceTarget,
    operation: &B4SequenceOperation,
) -> Result<Vec<u8>> {
    validate_sequence_operation(target, operation)?;
    let mut subject = Eip0045B4SequenceSubjectV1::from_canonical_jcs(base)?;
    ensure!(
        subject.target == target,
        "sequence mutation target differs from the detached base subject"
    );
    let base_consumer_elements = decoded_element_payloads(&subject.elements)?;

    apply_sequence_operation(&mut subject, target, operation)?;

    subject.validate()?;
    let output_consumer_elements = decoded_element_payloads(&subject.elements)?;
    ensure!(
        output_consumer_elements != base_consumer_elements,
        "sequence mutation changes only detached metadata, not consumer-visible elements"
    );
    let output = subject.to_canonical_jcs()?;
    ensure!(output != base, "sequence mutation reconstructed a no-op");
    Ok(output)
}

fn apply_sequence_operation(
    subject: &mut Eip0045B4SequenceSubjectV1,
    target: B4SequenceTarget,
    operation: &B4SequenceOperation,
) -> Result<()> {
    match operation {
        B4SequenceOperation::Empty {} => {
            ensure!(
                !subject.elements.is_empty(),
                "empty sequence operation has an already-empty base"
            );
            subject.elements.clear();
        }
        B4SequenceOperation::Insert {
            inserted_element,
            index,
        } => {
            let index = checked_index(*index, "sequence insertion index")?;
            ensure!(
                index <= subject.elements.len(),
                "sequence insertion index exceeds the base"
            );
            inserted_element.validate_for(target)?;
            subject.elements.insert(index, inserted_element.clone());
        }
        B4SequenceOperation::Move {
            before_element_id,
            before_element_sha256,
            from_index,
            to_index,
        } => {
            let from = checked_index(*from_index, "sequence move source index")?;
            ensure!(
                from < subject.elements.len(),
                "sequence move source is absent"
            );
            authenticate_element(
                &subject.elements[from],
                before_element_id,
                before_element_sha256,
                "moved",
            )?;
            let element = subject.elements.remove(from);
            let to = checked_index(*to_index, "sequence move final index")?;
            ensure!(
                to <= subject.elements.len(),
                "sequence move final index exceeds the shortened sequence"
            );
            subject.elements.insert(to, element);
        }
        B4SequenceOperation::Omit {
            before_element_id,
            before_element_sha256,
            index,
        } => {
            let index = checked_index(*index, "sequence omission index")?;
            ensure!(
                index < subject.elements.len(),
                "sequence omission target is absent"
            );
            authenticate_element(
                &subject.elements[index],
                before_element_id,
                before_element_sha256,
                "omitted",
            )?;
            subject.elements.remove(index);
        }
        B4SequenceOperation::Replace {
            before_element_id,
            before_element_sha256,
            index,
            replacement_element,
        } => {
            let index = checked_index(*index, "sequence replacement index")?;
            ensure!(
                index < subject.elements.len(),
                "sequence replacement target is absent"
            );
            authenticate_element(
                &subject.elements[index],
                before_element_id,
                before_element_sha256,
                "replaced",
            )?;
            replacement_element.validate_for(target)?;
            subject.elements[index] = replacement_element.clone();
        }
        B4SequenceOperation::ShiftBoundary {
            byte_count,
            direction,
            left_chunk_index,
        } => shift_boundary(subject, *left_chunk_index, *byte_count, *direction)?,
    }
    Ok(())
}

/// Reconstruct one complete mutation family from exact base bytes.
///
/// # Errors
///
/// Returns the applicable byte/sequence reconstruction error. Domain-semantic
/// ancestry edits are rejected here and must be replayed by their typed
/// ancestry adapter.
pub fn reconstruct_mutation(base: &[u8], mutation: &B4NegativeMutation) -> Result<Vec<u8>> {
    mutation.validate()?;
    match mutation {
        B4NegativeMutation::AlternateRootAssumptionSubstitution {} => bail!(
            "generic mutation reconstruction refuses the fixed alternate-root assumption substitution"
        ),
        B4NegativeMutation::AncestryInventoryEdit { .. } => {
            bail!(
                "generic mutation reconstruction refuses a domain-semantic ancestry-inventory edit"
            )
        }
        B4NegativeMutation::AncestryWitnessSubstitution { .. } => bail!(
            "generic mutation reconstruction refuses a domain-semantic ancestry-witness substitution"
        ),
        B4NegativeMutation::ByteEdit { edit, .. } => reconstruct_byte_edit(base, edit),
        B4NegativeMutation::SequenceEdit { edit, target } => {
            reconstruct_sequence_edit(base, *target, edit)
        }
    }
}

/// Serialize one registry materialization recipe to exact RFC 8785 JCS.
///
/// # Errors
///
/// Returns an error for an invalid recipe or an oversized serialization.
pub fn canonical_materialization_recipe_jcs(
    materialization: &B4NegativeMaterialization,
) -> Result<Vec<u8>> {
    validate_materialization_recipe(materialization)?;
    let value = serde_json::to_value(materialization)
        .context("cannot serialize B4 registry materialization recipe")?;
    let bytes = canonical_json_bytes(&value)?;
    ensure!(
        (1..=MAX_MATERIALIZATION_RECIPE_BYTES).contains(&bytes.len()),
        "B4 registry materialization recipe exceeds the canonical-byte bound"
    );
    Ok(bytes)
}

/// Construct a canonical identity after replaying the exact plan row and
/// registry recipe through a domain-specific adapter.
///
/// # Errors
///
/// Returns an error for a noncanonical plan, a registry/plan mismatch, a
/// domain mismatch, a reconstruction defect, or an identity invariant defect.
pub fn create_materialization_identity_with_adapter(
    negative_plan_source: &[u8],
    registry_row: &B4NegativeCase,
    adapter: &dyn B4MaterializationReplayAdapterV1,
) -> Result<Eip0045B4MaterializationIdentityV1> {
    let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(negative_plan_source)?;
    let execution =
        validate_registry_row_against_plan(&plan, registry_row, adapter.materialization_domain())?;
    let recipe_jcs = canonical_materialization_recipe_jcs(&registry_row.materialization)?;
    let base = adapter.base_bytes();
    let output = adapter.output_bytes();
    ensure!(
        base.len() <= MAX_MATERIALIZATION_BYTES && output.len() <= MAX_MATERIALIZATION_BYTES,
        "materialization base or output exceeds the closed bound"
    );
    adapter.replay_recipe(&execution.base_selector_id, &registry_row.materialization)?;
    let identity = Eip0045B4MaterializationIdentityV1 {
        format: B4_MATERIALIZATION_IDENTITY_FORMAT.to_owned(),
        format_version: B4_MATERIALIZATION_IDENTITY_FORMAT_VERSION,
        base_selector_id: execution.base_selector_id.clone(),
        base_byte_length: usize_to_u64(base.len(), "base byte length")?,
        base_sha256: sha256_hex(base),
        execution_id: execution.execution_id.clone(),
        materialization_domain: execution.materialization_domain,
        materialization_recipe_byte_length: usize_to_u64(
            recipe_jcs.len(),
            "materialization-recipe byte length",
        )?,
        materialization_recipe_sha256: sha256_hex(&recipe_jcs),
        negative_plan_byte_length: usize_to_u64(
            negative_plan_source.len(),
            "negative-plan byte length",
        )?,
        negative_plan_sha256: sha256_hex(negative_plan_source),
        output_byte_length: usize_to_u64(output.len(), "output byte length")?,
        output_sha256: sha256_hex(output),
    };
    identity.validate()?;
    Ok(identity)
}

/// Verify every identity binding by independently rebuilding it from the exact
/// plan, registry row, and domain-specific replay material.
///
/// # Errors
///
/// Returns an error for any plan, registry, domain, recipe, base, output,
/// reconstruction, digest, length, or derived-fact mismatch.
pub fn verify_materialization_identity_with_adapter(
    identity: &Eip0045B4MaterializationIdentityV1,
    negative_plan_source: &[u8],
    registry_row: &B4NegativeCase,
    adapter: &dyn B4MaterializationReplayAdapterV1,
) -> Result<()> {
    identity.validate()?;
    let expected =
        create_materialization_identity_with_adapter(negative_plan_source, registry_row, adapter)?;
    ensure!(
        identity == &expected,
        "materialization identity differs from independently replayed bindings"
    );
    Ok(())
}

fn validate_materialization_recipe(materialization: &B4NegativeMaterialization) -> Result<()> {
    match materialization {
        B4NegativeMaterialization::Mutation { mutation } => mutation.validate(),
        B4NegativeMaterialization::FixtureSelection { fixture_id } => {
            validate_semantic_id(fixture_id, "fixture-selection ID")
        }
    }
}

fn validate_registry_row_against_plan<'a>(
    plan: &'a Eip0045B4NegativePlanV1,
    registry_row: &B4NegativeCase,
    adapter_domain: B4MaterializationDomain,
) -> Result<&'a B4NegativePlanExecutionV1> {
    validate_execution_id(&registry_row.execution_id)?;
    validate_semantic_id(&registry_row.base_selector_id, "registry base selector ID")?;
    let execution = find_execution(plan, &registry_row.execution_id)?;
    ensure!(
        registry_row.base_selector_id == execution.base_selector_id,
        "registry materialization names a different plan base selector"
    );
    ensure!(
        registry_row.materialization_domain == execution.materialization_domain,
        "registry materialization names a different plan domain"
    );
    ensure!(
        adapter_domain == execution.materialization_domain,
        "materialization replay adapter does not match the plan domain"
    );
    validate_materialization_recipe(&registry_row.materialization)?;
    Ok(execution)
}

fn find_execution<'a>(
    plan: &'a Eip0045B4NegativePlanV1,
    execution_id: &str,
) -> Result<&'a B4NegativePlanExecutionV1> {
    let mut matches = plan
        .groups
        .iter()
        .flat_map(|group| group.executions.iter())
        .filter(|execution| execution.execution_id == execution_id);
    let execution = matches
        .next()
        .with_context(|| format!("negative plan has no execution {execution_id}"))?;
    ensure!(
        matches.next().is_none(),
        "negative plan contains duplicate execution IDs"
    );
    Ok(execution)
}

fn shift_boundary(
    subject: &mut Eip0045B4SequenceSubjectV1,
    left_chunk_index: u64,
    byte_count: u64,
    direction: B4BoundaryShiftDirection,
) -> Result<()> {
    ensure!(
        subject.target == B4SequenceTarget::ProofChunks,
        "boundary shift requires a proof-chunk subject"
    );
    let left_index = checked_index(left_chunk_index, "proof-chunk left boundary index")?;
    let right_index = left_index
        .checked_add(1)
        .context("proof-chunk boundary index overflows usize")?;
    ensure!(
        right_index < subject.elements.len(),
        "proof-chunk boundary has no right neighbor"
    );
    let count = checked_index(byte_count, "proof-chunk boundary byte count")?;
    let original_count = subject.elements.len();
    let original_concat = concatenated_payload(&subject.elements)?;
    let mut left = subject.elements[left_index].decoded_bytes()?;
    let mut right = subject.elements[right_index].decoded_bytes()?;

    match direction {
        B4BoundaryShiftDirection::LeftToRight => {
            ensure!(
                count < left.len(),
                "left-to-right shift must leave the left donor nonempty"
            );
            let moved = left.split_off(left.len() - count);
            let mut shifted_right = Vec::with_capacity(moved.len() + right.len());
            shifted_right.extend_from_slice(&moved);
            shifted_right.extend_from_slice(&right);
            right = shifted_right;
        }
        B4BoundaryShiftDirection::RightToLeft => {
            ensure!(
                count < right.len(),
                "right-to-left shift must leave the right donor nonempty"
            );
            let remaining_right = right.split_off(count);
            left.extend_from_slice(&right);
            right = remaining_right;
        }
    }

    subject.elements[left_index] =
        subject.elements[left_index].with_bytes(B4SequenceTarget::ProofChunks, &left)?;
    subject.elements[right_index] =
        subject.elements[right_index].with_bytes(B4SequenceTarget::ProofChunks, &right)?;
    ensure!(
        subject.elements.len() == original_count,
        "boundary shift changed the proof-chunk count"
    );
    ensure!(
        concatenated_payload(&subject.elements)? == original_concat,
        "boundary shift changed concatenated proof bytes"
    );
    Ok(())
}

fn authenticate_element(
    element: &B4SequenceSubjectElement,
    expected_id: &str,
    expected_sha256: &str,
    action: &str,
) -> Result<()> {
    ensure!(
        element.element_id == expected_id,
        "{action} sequence element ID witness differs from the base"
    );
    ensure!(
        element.sha256 == expected_sha256,
        "{action} sequence element digest witness differs from the base"
    );
    element.decoded_bytes()?;
    Ok(())
}

fn concatenated_payload(elements: &[B4SequenceSubjectElement]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    for element in elements {
        let bytes = element.decoded_bytes()?;
        let new_length = output
            .len()
            .checked_add(bytes.len())
            .context("concatenated sequence payload length overflows usize")?;
        output.reserve(new_length - output.len());
        output.extend_from_slice(&bytes);
    }
    Ok(output)
}

fn decoded_element_payloads(elements: &[B4SequenceSubjectElement]) -> Result<Vec<Vec<u8>>> {
    elements
        .iter()
        .map(B4SequenceSubjectElement::decoded_bytes)
        .collect()
}

fn decode_hex(value: &str, label: &str) -> Result<Vec<u8>> {
    hex::decode(value).with_context(|| format!("cannot decode {label}"))
}

fn checked_index(value: u64, label: &str) -> Result<usize> {
    usize::try_from(value).with_context(|| format!("{label} does not fit usize"))
}

fn usize_to_u64(value: usize, label: &str) -> Result<u64> {
    u64::try_from(value).with_context(|| format!("{label} does not fit u64"))
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} is not exactly 32 lowercase hexadecimal bytes");
    }
    Ok(())
}

fn validate_semantic_id(value: &str, label: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= MAX_SEMANTIC_ID_BYTES,
        "{label} is empty or too long"
    );
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "{label} is not lower-kebab ASCII"
    );
    ensure!(
        !value.starts_with('-') && !value.ends_with('-') && !value.contains("--"),
        "{label} is not canonical lower-kebab ASCII"
    );
    Ok(())
}

fn validate_execution_id(value: &str) -> Result<()> {
    let (group_id, variant_id) = value
        .split_once("--")
        .context("materialization execution ID has no group/variant separator")?;
    ensure!(
        !variant_id.contains("--"),
        "materialization execution ID has more than one group/variant separator"
    );
    validate_semantic_id(group_id, "materialization execution group ID")?;
    validate_semantic_id(variant_id, "materialization execution variant ID")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::b4::{B4ByteTarget, B4NegativeMutation};
    use crate::canonical::canonical_json_bytes;
    use serde_json::json;

    fn digest(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn structured_element(id: &str, ordinal: u8) -> B4SequenceSubjectElement {
        let bytes = canonical_json_bytes(&json!({"id": id, "ordinal": ordinal})).unwrap();
        B4SequenceSubjectElement::from_bytes(id, &bytes).unwrap()
    }

    fn structured_subject() -> Eip0045B4SequenceSubjectV1 {
        Eip0045B4SequenceSubjectV1::new(
            B4SequenceTarget::RegistryPositiveCases,
            vec![
                structured_element("case-a", 0),
                structured_element("case-b", 1),
                structured_element("case-c", 2),
            ],
        )
        .unwrap()
    }

    fn proof_subject() -> Eip0045B4SequenceSubjectV1 {
        Eip0045B4SequenceSubjectV1::new(
            B4SequenceTarget::ProofChunks,
            vec![
                B4SequenceSubjectElement::from_bytes("chunk-a", b"abcd").unwrap(),
                B4SequenceSubjectElement::from_bytes("chunk-b", b"efgh").unwrap(),
                B4SequenceSubjectElement::from_bytes("chunk-c", b"ij").unwrap(),
            ],
        )
        .unwrap()
    }

    fn sequence_output(
        base: &Eip0045B4SequenceSubjectV1,
        operation: &B4SequenceOperation,
    ) -> Eip0045B4SequenceSubjectV1 {
        let output =
            reconstruct_sequence_edit(&base.to_canonical_jcs().unwrap(), base.target, operation)
                .unwrap();
        Eip0045B4SequenceSubjectV1::from_canonical_jcs(&output).unwrap()
    }

    #[test]
    fn generic_reconstruction_rejects_domain_semantic_ancestry_inventory_edits() {
        let mutation = serde_json::from_value::<B4NegativeMutation>(json!({
            "edit": {
                "beforeClaimDigest": digest(0x11),
                "beforeControlRoot": digest(0x22),
                "exactDigest": digest(0x33),
                "operation": "prune-revealed-head"
            },
            "family": "ancestry-inventory-edit",
            "target": {
                "targetKind": "assumption-source-inventory-head"
            }
        }))
        .unwrap();
        let error =
            reconstruct_mutation(b"not-an-ancestry-byte-replacement", &mutation).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("domain-semantic ancestry-inventory edit")
        );
    }

    #[test]
    fn generic_reconstruction_rejects_ancestry_witness_substitutions() {
        let mutation = serde_json::from_value::<B4NegativeMutation>(json!({
            "family": "ancestry-witness-substitution",
            "recipe": "reuse-case9-assumption-at-terminal-join-step0"
        }))
        .expect("the typed ancestry substitution must parse before reconstruction");
        let error = reconstruct_mutation(b"not-a-domain-semantic-receipt", &mutation).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("domain-semantic ancestry-witness substitution")
        );
    }

    #[test]
    fn byte_reconstruction_covers_all_operations_and_exact_witnesses() {
        let base = b"abcdef";
        assert_eq!(
            reconstruct_byte_edit(
                base,
                &B4ByteOperation::Delete {
                    before_hex: "6263".to_owned(),
                    offset: 1,
                }
            )
            .unwrap(),
            b"adef"
        );
        assert_eq!(
            reconstruct_byte_edit(
                base,
                &B4ByteOperation::Insert {
                    inserted_hex: "3031".to_owned(),
                    offset: 3,
                }
            )
            .unwrap(),
            b"abc01def"
        );
        assert_eq!(
            reconstruct_byte_edit(
                base,
                &B4ByteOperation::Replace {
                    before_hex: "6364".to_owned(),
                    replacement_hex: "3031".to_owned(),
                    offset: 2,
                }
            )
            .unwrap(),
            b"ab01ef"
        );
        assert_eq!(
            reconstruct_byte_edit(
                base,
                &B4ByteOperation::Truncate {
                    before_hex: "6465".to_owned(),
                    new_length: 3,
                    original_length: 6,
                }
            )
            .unwrap(),
            b"abc"
        );
    }

    #[test]
    fn byte_ranges_witnesses_and_no_ops_fail_closed() {
        let base = b"abcdef";
        for operation in [
            B4ByteOperation::Delete {
                before_hex: "6264".to_owned(),
                offset: 1,
            },
            B4ByteOperation::Delete {
                before_hex: "6566".to_owned(),
                offset: 5,
            },
            B4ByteOperation::Insert {
                inserted_hex: "00".to_owned(),
                offset: 7,
            },
            B4ByteOperation::Replace {
                before_hex: "6264".to_owned(),
                replacement_hex: "3031".to_owned(),
                offset: 1,
            },
            B4ByteOperation::Truncate {
                before_hex: "6566".to_owned(),
                new_length: 3,
                original_length: 7,
            },
            B4ByteOperation::Truncate {
                before_hex: "6466".to_owned(),
                new_length: 3,
                original_length: 6,
            },
        ] {
            assert!(reconstruct_byte_edit(base, &operation).is_err());
        }
        assert!(
            reconstruct_byte_edit(
                base,
                &B4ByteOperation::Replace {
                    before_hex: "62".to_owned(),
                    replacement_hex: "62".to_owned(),
                    offset: 1,
                }
            )
            .is_err()
        );
    }

    #[test]
    fn structured_insert_replace_omit_and_both_move_directions_are_exact() {
        let base = structured_subject();

        let inserted = structured_element("case-d", 3);
        let output = sequence_output(
            &base,
            &B4SequenceOperation::Insert {
                inserted_element: inserted.clone(),
                index: 1,
            },
        );
        assert_eq!(
            output
                .elements
                .iter()
                .map(|element| element.element_id.as_str())
                .collect::<Vec<_>>(),
            ["case-a", "case-d", "case-b", "case-c"]
        );

        let replacement = structured_element("case-d", 4);
        let output = sequence_output(
            &base,
            &B4SequenceOperation::Replace {
                before_element_id: "case-b".to_owned(),
                before_element_sha256: base.elements[1].sha256.clone(),
                index: 1,
                replacement_element: replacement.clone(),
            },
        );
        assert_eq!(output.elements[1], replacement);

        let output = sequence_output(
            &base,
            &B4SequenceOperation::Omit {
                before_element_id: "case-b".to_owned(),
                before_element_sha256: base.elements[1].sha256.clone(),
                index: 1,
            },
        );
        assert_eq!(
            output
                .elements
                .iter()
                .map(|element| element.element_id.as_str())
                .collect::<Vec<_>>(),
            ["case-a", "case-c"]
        );

        let forward = sequence_output(
            &base,
            &B4SequenceOperation::Move {
                before_element_id: "case-a".to_owned(),
                before_element_sha256: base.elements[0].sha256.clone(),
                from_index: 0,
                to_index: 2,
            },
        );
        assert_eq!(
            forward
                .elements
                .iter()
                .map(|element| element.element_id.as_str())
                .collect::<Vec<_>>(),
            ["case-b", "case-c", "case-a"]
        );

        let backward = sequence_output(
            &base,
            &B4SequenceOperation::Move {
                before_element_id: "case-c".to_owned(),
                before_element_sha256: base.elements[2].sha256.clone(),
                from_index: 2,
                to_index: 0,
            },
        );
        assert_eq!(
            backward
                .elements
                .iter()
                .map(|element| element.element_id.as_str())
                .collect::<Vec<_>>(),
            ["case-c", "case-a", "case-b"]
        );
    }

    #[test]
    fn empty_and_both_boundary_shifts_obey_exact_proof_chunk_semantics() {
        let base = proof_subject();
        let base_concat = concatenated_payload(&base.elements).unwrap();

        let empty = sequence_output(&base, &B4SequenceOperation::Empty {});
        assert!(empty.elements.is_empty());

        let left_to_right = sequence_output(
            &base,
            &B4SequenceOperation::ShiftBoundary {
                byte_count: 2,
                direction: B4BoundaryShiftDirection::LeftToRight,
                left_chunk_index: 0,
            },
        );
        assert_eq!(left_to_right.elements[0].decoded_bytes().unwrap(), b"ab");
        assert_eq!(
            left_to_right.elements[1].decoded_bytes().unwrap(),
            b"cdefgh"
        );
        assert_eq!(left_to_right.elements.len(), base.elements.len());
        assert_eq!(
            concatenated_payload(&left_to_right.elements).unwrap(),
            base_concat
        );

        let right_to_left = sequence_output(
            &base,
            &B4SequenceOperation::ShiftBoundary {
                byte_count: 2,
                direction: B4BoundaryShiftDirection::RightToLeft,
                left_chunk_index: 0,
            },
        );
        assert_eq!(
            right_to_left.elements[0].decoded_bytes().unwrap(),
            b"abcdef"
        );
        assert_eq!(right_to_left.elements[1].decoded_bytes().unwrap(), b"gh");
        assert_eq!(right_to_left.elements.len(), base.elements.len());
        assert_eq!(
            concatenated_payload(&right_to_left.elements).unwrap(),
            base_concat
        );
    }

    #[test]
    fn structured_sequence_targets_indices_witnesses_and_uniqueness_fail_closed() {
        let structured = structured_subject();
        let structured_bytes = structured.to_canonical_jcs().unwrap();

        let failures = [
            B4SequenceOperation::Insert {
                inserted_element: structured_element("case-d", 4),
                index: 4,
            },
            B4SequenceOperation::Insert {
                inserted_element: structured.elements[0].clone(),
                index: 1,
            },
            B4SequenceOperation::Omit {
                before_element_id: "case-x".to_owned(),
                before_element_sha256: structured.elements[0].sha256.clone(),
                index: 0,
            },
            B4SequenceOperation::Omit {
                before_element_id: "case-a".to_owned(),
                before_element_sha256: digest(9),
                index: 0,
            },
            B4SequenceOperation::Omit {
                before_element_id: "case-a".to_owned(),
                before_element_sha256: structured.elements[0].sha256.clone(),
                index: 3,
            },
            B4SequenceOperation::Move {
                before_element_id: "case-a".to_owned(),
                before_element_sha256: structured.elements[0].sha256.clone(),
                from_index: 0,
                to_index: 3,
            },
            B4SequenceOperation::Replace {
                before_element_id: "case-b".to_owned(),
                before_element_sha256: structured.elements[1].sha256.clone(),
                index: 1,
                replacement_element: structured.elements[0].clone(),
            },
        ];
        for operation in failures {
            assert!(
                reconstruct_sequence_edit(
                    &structured_bytes,
                    B4SequenceTarget::RegistryPositiveCases,
                    &operation
                )
                .is_err()
            );
        }

        assert!(
            reconstruct_sequence_edit(
                &structured_bytes,
                B4SequenceTarget::RegistryNegativeCases,
                &B4SequenceOperation::Omit {
                    before_element_id: "case-a".to_owned(),
                    before_element_sha256: structured.elements[0].sha256.clone(),
                    index: 0,
                }
            )
            .is_err()
        );
        assert!(
            reconstruct_sequence_edit(
                &structured_bytes,
                B4SequenceTarget::RegistryPositiveCases,
                &B4SequenceOperation::Empty {}
            )
            .is_err()
        );
    }

    #[test]
    fn sequence_edits_must_change_consumer_visible_elements() {
        let structured = structured_subject();
        let structured_bytes = structured.to_canonical_jcs().unwrap();
        let relabelled = B4SequenceSubjectElement::from_bytes(
            "case-relabelled",
            &structured.elements[1].decoded_bytes().unwrap(),
        )
        .unwrap();
        assert!(
            reconstruct_sequence_edit(
                &structured_bytes,
                B4SequenceTarget::RegistryPositiveCases,
                &B4SequenceOperation::Replace {
                    before_element_id: structured.elements[1].element_id.clone(),
                    before_element_sha256: structured.elements[1].sha256.clone(),
                    index: 1,
                    replacement_element: relabelled,
                },
            )
            .is_err()
        );

        let duplicate_payload_chunks = Eip0045B4SequenceSubjectV1::new(
            B4SequenceTarget::ProofChunks,
            vec![
                B4SequenceSubjectElement::from_bytes("chunk-a", b"same").unwrap(),
                B4SequenceSubjectElement::from_bytes("chunk-b", b"same").unwrap(),
            ],
        )
        .unwrap();
        assert!(
            reconstruct_sequence_edit(
                &duplicate_payload_chunks.to_canonical_jcs().unwrap(),
                B4SequenceTarget::ProofChunks,
                &B4SequenceOperation::Move {
                    before_element_id: "chunk-a".to_owned(),
                    before_element_sha256: duplicate_payload_chunks.elements[0].sha256.clone(),
                    from_index: 0,
                    to_index: 1,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn proof_sequence_donors_boundaries_and_empty_base_fail_closed() {
        let proof = proof_subject();
        let proof_bytes = proof.to_canonical_jcs().unwrap();

        for operation in [
            B4SequenceOperation::ShiftBoundary {
                byte_count: 4,
                direction: B4BoundaryShiftDirection::LeftToRight,
                left_chunk_index: 0,
            },
            B4SequenceOperation::ShiftBoundary {
                byte_count: 4,
                direction: B4BoundaryShiftDirection::RightToLeft,
                left_chunk_index: 0,
            },
            B4SequenceOperation::ShiftBoundary {
                byte_count: 1,
                direction: B4BoundaryShiftDirection::LeftToRight,
                left_chunk_index: 2,
            },
        ] {
            assert!(
                reconstruct_sequence_edit(&proof_bytes, B4SequenceTarget::ProofChunks, &operation)
                    .is_err()
            );
        }

        let empty = Eip0045B4SequenceSubjectV1::new(B4SequenceTarget::ProofChunks, vec![])
            .unwrap()
            .to_canonical_jcs()
            .unwrap();
        assert!(
            reconstruct_sequence_edit(
                &empty,
                B4SequenceTarget::ProofChunks,
                &B4SequenceOperation::Empty {}
            )
            .is_err()
        );
    }

    fn exact_execution(
        plan: &Eip0045B4NegativePlanV1,
        execution_id: &str,
    ) -> B4NegativePlanExecutionV1 {
        plan.groups
            .iter()
            .flat_map(|group| &group.executions)
            .find(|execution| execution.execution_id == execution_id)
            .unwrap()
            .clone()
    }

    fn byte_materialization(
        execution: &B4NegativePlanExecutionV1,
        mutation: B4NegativeMutation,
    ) -> B4NegativeCase {
        B4NegativeCase {
            execution_id: execution.execution_id.clone(),
            base_selector_id: execution.base_selector_id.clone(),
            materialization_domain: execution.materialization_domain,
            materialization: B4NegativeMaterialization::Mutation { mutation },
        }
    }

    #[test]
    fn materialization_identity_binds_plan_registry_recipe_base_and_output() {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let plan_source = plan.to_canonical_jcs().unwrap();
        let execution = exact_execution(&plan, "statement-field-byte-sweep--profile-id");
        let base = b"abcdef";
        let mutation = B4NegativeMutation::ByteEdit {
            edit: B4ByteOperation::Replace {
                before_hex: "6364".to_owned(),
                replacement_hex: "3031".to_owned(),
                offset: 2,
            },
            target: B4ByteTarget::Statement,
        };
        let output = reconstruct_mutation(base, &mutation).unwrap();
        let row = byte_materialization(&execution, mutation);
        let adapter = B4ByteEditReplayAdapterV1 {
            materialization_domain: B4MaterializationDomain::VerifierInput,
            base,
            output: &output,
        };
        let identity =
            create_materialization_identity_with_adapter(&plan_source, &row, &adapter).unwrap();
        let recipe_jcs = canonical_materialization_recipe_jcs(&row.materialization).unwrap();

        assert_eq!(identity.format, B4_MATERIALIZATION_IDENTITY_FORMAT);
        assert_eq!(
            identity.format_version,
            B4_MATERIALIZATION_IDENTITY_FORMAT_VERSION
        );
        assert_eq!(identity.execution_id, execution.execution_id);
        assert_eq!(identity.base_selector_id, execution.base_selector_id);
        assert_eq!(
            identity.materialization_domain,
            B4MaterializationDomain::VerifierInput
        );
        assert_eq!(
            identity.materialization_recipe_byte_length,
            u64::try_from(recipe_jcs.len()).unwrap()
        );
        assert_eq!(
            identity.materialization_recipe_sha256,
            sha256_hex(&recipe_jcs)
        );
        assert_eq!(
            identity.negative_plan_byte_length,
            u64::try_from(plan_source.len()).unwrap()
        );
        assert_eq!(identity.negative_plan_sha256, sha256_hex(&plan_source));
        assert_eq!(identity.base_sha256, sha256_hex(base));
        assert_eq!(identity.output_sha256, sha256_hex(&output));

        verify_materialization_identity_with_adapter(&identity, &plan_source, &row, &adapter)
            .unwrap();
        let source = identity.to_canonical_jcs().unwrap();
        assert_eq!(
            Eip0045B4MaterializationIdentityV1::from_canonical_jcs(&source).unwrap(),
            identity
        );
    }

    #[test]
    fn sequence_subject_adapter_is_explicit_and_rejects_other_recipe_families() {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let plan_source = plan.to_canonical_jcs().unwrap();
        let execution = exact_execution(
            &plan,
            "proof-boundary-shift-sweep--boundary-zero-left-short-right-long",
        );
        let subject = proof_subject();
        let base = subject.to_canonical_jcs().unwrap();
        let mutation = B4NegativeMutation::SequenceEdit {
            edit: B4SequenceOperation::ShiftBoundary {
                byte_count: 2,
                direction: B4BoundaryShiftDirection::LeftToRight,
                left_chunk_index: 0,
            },
            target: B4SequenceTarget::ProofChunks,
        };
        let output = reconstruct_mutation(&base, &mutation).unwrap();
        let row = byte_materialization(&execution, mutation);
        let adapter = B4SequenceSubjectReplayAdapterV1 {
            materialization_domain: execution.materialization_domain,
            base: &base,
            output: &output,
        };
        create_materialization_identity_with_adapter(&plan_source, &row, &adapter).unwrap();

        let byte_row = byte_materialization(
            &execution,
            B4NegativeMutation::ByteEdit {
                edit: B4ByteOperation::Delete {
                    before_hex: "00".to_owned(),
                    offset: 0,
                },
                target: B4ByteTarget::RawSeal,
            },
        );
        assert!(
            create_materialization_identity_with_adapter(&plan_source, &byte_row, &adapter)
                .is_err()
        );
    }

    #[test]
    fn fixture_selection_binds_exact_plan_selector_without_fabricating_a_mutation() {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let plan_source = plan.to_canonical_jcs().unwrap();
        let execution = exact_execution(
            &plan,
            "terminal-excluded-shipping-family-sweep--lift-po2-14",
        );
        let row = B4NegativeCase {
            execution_id: execution.execution_id.clone(),
            base_selector_id: execution.base_selector_id.clone(),
            materialization_domain: execution.materialization_domain,
            materialization: B4NegativeMaterialization::FixtureSelection {
                fixture_id: execution.base_selector_id.clone(),
            },
        };
        let fixture = b"independently-authenticated-receipt";
        let adapter = B4FixtureSelectionReplayAdapterV1 {
            materialization_domain: execution.materialization_domain,
            fixture,
        };
        let identity =
            create_materialization_identity_with_adapter(&plan_source, &row, &adapter).unwrap();
        assert_eq!(identity.base_sha256, identity.output_sha256);
        assert_eq!(identity.base_byte_length, identity.output_byte_length);
        verify_materialization_identity_with_adapter(&identity, &plan_source, &row, &adapter)
            .unwrap();

        let mut wrong = row;
        wrong.materialization = B4NegativeMaterialization::FixtureSelection {
            fixture_id: "different-fixture".to_owned(),
        };
        assert!(
            create_materialization_identity_with_adapter(&plan_source, &wrong, &adapter).is_err()
        );
    }

    #[derive(Debug)]
    struct ExactBindingAdapter<'a> {
        domain: B4MaterializationDomain,
        base: &'a [u8],
        output: &'a [u8],
        recipe_sha256: String,
    }

    impl B4MaterializationReplayAdapterV1 for ExactBindingAdapter<'_> {
        fn materialization_domain(&self) -> B4MaterializationDomain {
            self.domain
        }

        fn base_bytes(&self) -> &[u8] {
            self.base
        }

        fn output_bytes(&self) -> &[u8] {
            self.output
        }

        fn replay_recipe(
            &self,
            _base_selector_id: &str,
            materialization: &B4NegativeMaterialization,
        ) -> Result<()> {
            ensure!(
                sha256_hex(&canonical_materialization_recipe_jcs(materialization)?)
                    == self.recipe_sha256,
                "test adapter received a different exact recipe"
            );
            Ok(())
        }
    }

    #[test]
    fn exact_plan_rows_require_matching_adapters_in_all_three_domains() {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let plan_source = plan.to_canonical_jcs().unwrap();
        for domain in [
            B4MaterializationDomain::VerifierInput,
            B4MaterializationDomain::ArtifactValidator,
            B4MaterializationDomain::TreeValidator,
        ] {
            let execution = plan
                .groups
                .iter()
                .flat_map(|group| &group.executions)
                .find(|execution| execution.materialization_domain == domain)
                .unwrap()
                .clone();
            let materialization = B4NegativeMaterialization::FixtureSelection {
                fixture_id: execution.base_selector_id.clone(),
            };
            let row = B4NegativeCase {
                execution_id: execution.execution_id,
                base_selector_id: execution.base_selector_id,
                materialization_domain: execution.materialization_domain,
                materialization,
            };
            let recipe_sha256 =
                sha256_hex(&canonical_materialization_recipe_jcs(&row.materialization).unwrap());
            let adapter = ExactBindingAdapter {
                domain,
                base: b"base",
                output: b"domain-specific-output",
                recipe_sha256,
            };
            let identity =
                create_materialization_identity_with_adapter(&plan_source, &row, &adapter).unwrap();
            assert_eq!(identity.materialization_domain, domain);

            let wrong_domain = match domain {
                B4MaterializationDomain::VerifierInput => {
                    B4MaterializationDomain::ArtifactValidator
                }
                B4MaterializationDomain::ArtifactValidator
                | B4MaterializationDomain::TreeValidator => B4MaterializationDomain::VerifierInput,
            };
            let wrong_adapter = ExactBindingAdapter {
                domain: wrong_domain,
                ..adapter
            };
            assert!(
                create_materialization_identity_with_adapter(&plan_source, &row, &wrong_adapter,)
                    .is_err()
            );
        }
    }

    #[test]
    fn coordinated_identity_drift_cannot_replace_external_plan_registry_or_adapter() {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let plan_source = plan.to_canonical_jcs().unwrap();
        let execution = exact_execution(&plan, "statement-field-byte-sweep--profile-id");
        let base = b"abcdef";
        let mutation = B4NegativeMutation::ByteEdit {
            edit: B4ByteOperation::Delete {
                before_hex: "62".to_owned(),
                offset: 1,
            },
            target: B4ByteTarget::Statement,
        };
        let output = reconstruct_mutation(base, &mutation).unwrap();
        let row = byte_materialization(&execution, mutation);
        let adapter = B4ByteEditReplayAdapterV1 {
            materialization_domain: execution.materialization_domain,
            base,
            output: &output,
        };
        let identity =
            create_materialization_identity_with_adapter(&plan_source, &row, &adapter).unwrap();

        let mut forged = identity.clone();
        forged.materialization_recipe_sha256 = digest(7);
        forged.output_sha256 = digest(8);
        forged.output_byte_length = 99;
        assert!(
            verify_materialization_identity_with_adapter(&forged, &plan_source, &row, &adapter,)
                .is_err()
        );

        let mut coordinated_plan: serde_json::Value = serde_json::from_slice(&plan_source).unwrap();
        coordinated_plan["groups"][0]["executions"][0]["baseSelectorId"] =
            json!("coordinated-selector");
        let changed_plan = canonical_json_bytes(&coordinated_plan).unwrap();
        let mut changed_row = row;
        changed_row.base_selector_id = "coordinated-selector".to_owned();
        assert!(
            create_materialization_identity_with_adapter(&changed_plan, &changed_row, &adapter,)
                .is_err()
        );
    }

    #[test]
    fn identity_parser_rejects_unknown_duplicate_and_noncanonical_sources() {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let plan_source = plan.to_canonical_jcs().unwrap();
        let execution = exact_execution(&plan, "statement-field-byte-sweep--profile-id");
        let base = b"abcdef";
        let mutation = B4NegativeMutation::ByteEdit {
            edit: B4ByteOperation::Delete {
                before_hex: "62".to_owned(),
                offset: 1,
            },
            target: B4ByteTarget::Statement,
        };
        let output = reconstruct_mutation(base, &mutation).unwrap();
        let row = byte_materialization(&execution, mutation);
        let adapter = B4ByteEditReplayAdapterV1 {
            materialization_domain: execution.materialization_domain,
            base,
            output: &output,
        };
        let identity =
            create_materialization_identity_with_adapter(&plan_source, &row, &adapter).unwrap();
        let canonical = identity.to_canonical_jcs().unwrap();

        let mut value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        value["unexpected"] = json!(true);
        assert!(
            Eip0045B4MaterializationIdentityV1::from_canonical_jcs(
                &canonical_json_bytes(&value).unwrap(),
            )
            .is_err()
        );

        let text = String::from_utf8(canonical.clone()).unwrap();
        let duplicate = format!(
            "{{\"format\":\"{}\",{}",
            B4_MATERIALIZATION_IDENTITY_FORMAT,
            &text[1..],
        );
        assert!(
            Eip0045B4MaterializationIdentityV1::from_canonical_jcs(duplicate.as_bytes()).is_err()
        );

        let pretty = serde_json::to_vec_pretty(
            &serde_json::from_slice::<serde_json::Value>(&canonical).unwrap(),
        )
        .unwrap();
        assert!(Eip0045B4MaterializationIdentityV1::from_canonical_jcs(&pretty).is_err());
    }
}
