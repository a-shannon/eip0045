//! Descriptor-rooted producers for the four cryptographic-depth rows.
//!
//! The authority authenticates the positive case-0 raw seal and receipt oracle,
//! verifies the original receipt with the full stock verifier, derives four
//! same-length one-word mutations, and requires stock/instrumented agreement at
//! one exact typed checkpoint before any row can be reconstructed.

use anyhow::{Context as _, Result, bail, ensure};

use crate::{
    b4::{
        B4ByteOperation, B4ByteTarget, B4NegativeCase, B4NegativeMaterialization,
        B4NegativeMutation, B4PositiveArtifactRole,
    },
    b4_fixture_sources::{B4FixtureSourceResolverV1, B4MaterializationFixtureSourceResolverV2},
    b4_materialization_set::{
        B4AuthenticatedMaterializationTopLevelV1, B4AuthenticatedMaterializationTopLevelV2,
        B4ClosedReconstructedExecutionV1, close_production_execution,
    },
    b4_mutation::{B4MaterializationReplayAdapterV1, reconstruct_byte_edit},
    b4_plan::{
        B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanExecutionV1,
        B4NegativePlanFixture, B4NegativeQaResultCode, Eip0045B4NegativePlanV1,
    },
    constants::PROOF_BYTES,
    receipt_oracle_replay::{
        CompiledStockSuccinctReplayV1, DirectSealCheckpointMutationV1,
        derive_direct_seal_checkpoint_mutation,
    },
    seal::decode_seal_words,
};

const LIFT_SELECTOR: &str = "lift-po2-15";
const WORD_BYTES: usize = 4;

#[derive(Clone, Copy, Debug)]
struct ExpectedCryptoRow {
    index: usize,
    execution_id: &'static str,
    variant_id: &'static str,
    target: DirectSealCheckpointMutationV1,
    qa_result: B4NegativeQaResultCode,
}

const EXPECTED_ROWS: [ExpectedCryptoRow; 4] = [
    ExpectedCryptoRow {
        index: 156,
        execution_id: "crypto-early-check-value-mismatch--check-value",
        variant_id: "check-value",
        target: DirectSealCheckpointMutationV1::ValidityCheck,
        qa_result: B4NegativeQaResultCode::B4CryptoEarlyCheckpointRejected,
    },
    ExpectedCryptoRow {
        index: 157,
        execution_id: "crypto-middle-fri-round-two-mismatch--fri-query-00",
        variant_id: "fri-query-00",
        target: DirectSealCheckpointMutationV1::FriRoundTwoQueryZero,
        qa_result: B4NegativeQaResultCode::B4CryptoMiddleCheckpointRejected,
    },
    ExpectedCryptoRow {
        index: 158,
        execution_id: "crypto-late-final-opening-mismatch--fri-query-00",
        variant_id: "fri-query-00",
        target: DirectSealCheckpointMutationV1::FriFinalPolynomialQueryZero,
        qa_result: B4NegativeQaResultCode::B4CryptoLateCheckpointRejected,
    },
    ExpectedCryptoRow {
        index: 159,
        execution_id: "crypto-final-expected-claim-mismatch--claim-query-49",
        variant_id: "claim-query-49",
        target: DirectSealCheckpointMutationV1::FriInnerQueryFortyNine,
        qa_result: B4NegativeQaResultCode::B4CryptoFinalCheckpointRejected,
    },
];

struct AuthenticatedCryptoRow {
    expected: ExpectedCryptoRow,
    subject: Vec<u8>,
    edit: B4ByteOperation,
}

#[derive(Clone, Copy, Debug)]
struct CryptoSources<'a> {
    case_index: usize,
    case_id: &'a str,
    raw_seal: &'a [u8],
    profile_manifest: &'a [u8],
    receipt_oracle: &'a [u8],
}

impl<'a> CryptoSources<'a> {
    fn authenticate_v1(top_level: &'a B4AuthenticatedMaterializationTopLevelV1) -> Result<Self> {
        let resolver = B4FixtureSourceResolverV1::from_authenticated(top_level)
            .context("cryptographic producer cannot authenticate fixture sources")?;
        let positive = resolver
            .positive_case(0, LIFT_SELECTOR)
            .context("cryptographic producer cannot authenticate positive case zero")?;
        let input = resolver
            .positive_input()
            .context("cryptographic producer cannot authenticate the positive input")?;
        input
            .initial_profile_manifest()
            .context("cryptographic producer requires the exact initial profile")?;
        let receipt_oracle = positive
            .artifact(B4PositiveArtifactRole::ReceiptOracle)
            .context("cryptographic producer lacks the case-0 receipt oracle")?;
        Self::from_authenticated_parts(
            positive.case_index(),
            positive.case_id(),
            positive.raw_seal(),
            input.profile_manifest(),
            receipt_oracle,
        )
    }

    fn authenticate_v2(
        top_level: &'a B4AuthenticatedMaterializationTopLevelV2,
    ) -> Result<(Self, &'a [u8])> {
        let resolver = B4MaterializationFixtureSourceResolverV2::from_authenticated(top_level)
            .context("V2 cryptographic producer cannot authenticate fixture sources")?;
        let positive = resolver
            .positive_case(0, LIFT_SELECTOR)
            .context("V2 cryptographic producer cannot authenticate positive case zero")?;
        let input = resolver
            .positive_input()
            .context("V2 cryptographic producer cannot authenticate the positive input")?;
        input
            .initial_profile_manifest()
            .context("V2 cryptographic producer requires the exact initial profile")?;
        let receipt_oracle = positive
            .artifact(B4PositiveArtifactRole::ReceiptOracle)
            .context("V2 cryptographic producer lacks the case-0 receipt oracle")?;
        let sources = Self::from_authenticated_parts(
            positive.case_index(),
            positive.case_id(),
            positive.raw_seal(),
            input.profile_manifest(),
            receipt_oracle,
        )?;
        Ok((sources, resolver.negative_plan_jcs()))
    }

    fn from_authenticated_parts(
        case_index: usize,
        case_id: &'a str,
        raw_seal: &'a [u8],
        profile_manifest: &'a [u8],
        receipt_oracle: &'a [u8],
    ) -> Result<Self> {
        ensure!(
            case_index == 0 && case_id == LIFT_SELECTOR,
            "cryptographic producer selected a different positive case"
        );
        Ok(Self {
            case_index,
            case_id,
            raw_seal,
            profile_manifest,
            receipt_oracle,
        })
    }
}

struct DirectSealCheckpointMutationAuthorityParts {
    base_raw_seal: Vec<u8>,
    contexts: [Vec<u8>; 2],
    rows: [AuthenticatedCryptoRow; 4],
}

impl DirectSealCheckpointMutationAuthorityParts {
    fn from_authenticated_sources(sources: CryptoSources<'_>) -> Result<Self> {
        let replay = CompiledStockSuccinctReplayV1::from_compiled_profile()
            .map_err(|error| anyhow::anyhow!(error.to_string()))
            .context("cryptographic producer cannot construct the stock replay")?;
        let verified = replay
            .verify_direct_oracle(sources.receipt_oracle)
            .map_err(|error| anyhow::anyhow!(error.to_string()))
            .context("cryptographic producer cannot verify the original receipt oracle")?;
        let verified_raw_seal = verified.raw_seal_bytes();
        ensure!(
            sources.raw_seal == verified_raw_seal,
            "case-0 raw seal differs from the full stock-verified receipt seal"
        );

        let mut rows = Vec::with_capacity(EXPECTED_ROWS.len());
        for expected in EXPECTED_ROWS {
            let subject = derive_direct_seal_checkpoint_mutation(&verified, expected.target)
                .map_err(|error| anyhow::anyhow!(error.to_string()))
                .with_context(|| {
                    format!(
                        "cryptographic producer cannot derive exact row {}",
                        expected.index
                    )
                })?;
            let edit = exact_single_word_replace(&verified_raw_seal, &subject)?;
            ensure!(
                reconstruct_byte_edit(&verified_raw_seal, &edit)? == subject,
                "cryptographic row does not replay from its exact one-word recipe"
            );
            rows.push(AuthenticatedCryptoRow {
                expected,
                subject,
                edit,
            });
        }
        Ok(Self {
            base_raw_seal: verified_raw_seal,
            contexts: [
                sources.profile_manifest.to_vec(),
                sources.receipt_oracle.to_vec(),
            ],
            rows: rows
                .try_into()
                .map_err(|_| anyhow::anyhow!("cryptographic row authority is not four rows"))?,
        })
    }

    fn row(&self, execution_index: usize) -> Option<&AuthenticatedCryptoRow> {
        self.rows
            .iter()
            .find(|row| row.expected.index == execution_index)
    }

    fn verify_source_binding(&self, sources: CryptoSources<'_>) -> Result<()> {
        ensure!(
            sources.case_index == 0
                && sources.case_id == LIFT_SELECTOR
                && sources.raw_seal == self.base_raw_seal
                && sources.profile_manifest == self.contexts[0]
                && sources.receipt_oracle == self.contexts[1],
            "cryptographic mutation authority differs from the authenticated fixture sources"
        );
        Ok(())
    }

    #[cfg(test)]
    fn from_test_subjects(
        base_raw_seal: Vec<u8>,
        profile_manifest: Vec<u8>,
        receipt_oracle: Vec<u8>,
        subjects: [Vec<u8>; 4],
    ) -> Result<Self> {
        ensure!(base_raw_seal.len() == PROOF_BYTES);
        let mut rows = Vec::with_capacity(4);
        for (expected, subject) in EXPECTED_ROWS.into_iter().zip(subjects) {
            let edit = exact_single_word_replace(&base_raw_seal, &subject)?;
            rows.push(AuthenticatedCryptoRow {
                expected,
                subject,
                edit,
            });
        }
        Ok(Self {
            base_raw_seal,
            contexts: [profile_manifest, receipt_oracle],
            rows: rows.try_into().unwrap_or_else(|_| unreachable!()),
        })
    }
}

/// Opaque derive-first V1 authority for exactly rows 156 through 159.
pub(crate) struct B4DirectSealCheckpointMutationAuthorityV1 {
    parts: DirectSealCheckpointMutationAuthorityParts,
}

impl B4DirectSealCheckpointMutationAuthorityV1 {
    /// Authenticate case 0 and derive the four exact checkpoint mutations once.
    pub(crate) fn from_authenticated(
        top_level: &B4AuthenticatedMaterializationTopLevelV1,
    ) -> Result<Self> {
        Ok(Self {
            parts: DirectSealCheckpointMutationAuthorityParts::from_authenticated_sources(
                CryptoSources::authenticate_v1(top_level)?,
            )?,
        })
    }

    #[cfg(test)]
    fn from_test_subjects(
        base_raw_seal: Vec<u8>,
        profile_manifest: Vec<u8>,
        receipt_oracle: Vec<u8>,
        subjects: [Vec<u8>; 4],
    ) -> Result<Self> {
        Ok(Self {
            parts: DirectSealCheckpointMutationAuthorityParts::from_test_subjects(
                base_raw_seal,
                profile_manifest,
                receipt_oracle,
                subjects,
            )?,
        })
    }
}

/// Opaque V2-only authority derived from one authenticated V2 materialization wrapper.
///
/// It is intentionally affine: it has no cloning, serialization, default, or V1 conversion path.
pub(crate) struct B4DirectSealCheckpointMutationAuthorityV2 {
    parts: DirectSealCheckpointMutationAuthorityParts,
}

impl B4DirectSealCheckpointMutationAuthorityV2 {
    /// Authenticate V2 case 0 and derive the four exact checkpoint mutations once.
    pub(crate) fn from_authenticated(
        top_level: &B4AuthenticatedMaterializationTopLevelV2,
    ) -> Result<Self> {
        Ok(Self {
            parts: DirectSealCheckpointMutationAuthorityParts::from_authenticated_sources(
                CryptoSources::authenticate_v2(top_level)?.0,
            )?,
        })
    }

    #[cfg(test)]
    fn from_test_subjects(
        base_raw_seal: Vec<u8>,
        profile_manifest: Vec<u8>,
        receipt_oracle: Vec<u8>,
        subjects: [Vec<u8>; 4],
    ) -> Result<Self> {
        Ok(Self {
            parts: DirectSealCheckpointMutationAuthorityParts::from_test_subjects(
                base_raw_seal,
                profile_manifest,
                receipt_oracle,
                subjects,
            )?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct CryptoReplayAdapterV1<'a> {
    base: &'a [u8],
    subject: &'a [u8],
    materialization: &'a B4NegativeMaterialization,
}

impl B4MaterializationReplayAdapterV1 for CryptoReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::VerifierInput
    }

    fn base_bytes(&self) -> &[u8] {
        self.base
    }

    fn output_bytes(&self) -> &[u8] {
        self.subject
    }

    fn replay_recipe(
        &self,
        base_selector_id: &str,
        materialization: &B4NegativeMaterialization,
    ) -> Result<()> {
        ensure!(
            base_selector_id == LIFT_SELECTOR && materialization == self.materialization,
            "cryptographic replay received a selector or recipe outside its closed row"
        );
        let B4NegativeMaterialization::Mutation {
            mutation:
                B4NegativeMutation::ByteEdit {
                    target: B4ByteTarget::RawSeal,
                    edit: B4ByteOperation::Replace { .. },
                },
        } = materialization
        else {
            bail!("cryptographic replay received a non-raw-seal replacement recipe");
        };
        ensure!(
            reconstruct_byte_edit(
                self.base,
                match materialization {
                    B4NegativeMaterialization::Mutation {
                        mutation: B4NegativeMutation::ByteEdit { edit, .. },
                    } => edit,
                    _ => unreachable!(),
                },
            )? == self.subject,
            "cryptographic replay output differs from its exact replacement"
        );
        Ok(())
    }
}

/// Reconstruct only E7 rows 156 through 159 from the retained mutation authority.
pub(crate) fn reconstruct_crypto_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
    authority: &B4DirectSealCheckpointMutationAuthorityV1,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    reconstruct_crypto_execution_core(
        execution_index,
        planned,
        &top_level.negative_plan,
        &authority.parts,
    )
}

/// Reconstruct only E7 rows 156 through 159 from V2-authenticated sources.
pub(crate) fn reconstruct_crypto_execution_v2(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV2,
    authority: &B4DirectSealCheckpointMutationAuthorityV2,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    if authority.parts.row(execution_index).is_none() {
        return Ok(None);
    }
    let (sources, negative_plan_jcs) = CryptoSources::authenticate_v2(top_level)?;
    authority.parts.verify_source_binding(sources)?;
    reconstruct_crypto_execution_core(
        execution_index,
        planned,
        negative_plan_jcs,
        &authority.parts,
    )
}

fn reconstruct_crypto_execution_core(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    authority: &DirectSealCheckpointMutationAuthorityParts,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    let Some(row) = authority.row(execution_index) else {
        return Ok(None);
    };
    validate_planned_execution(row.expected, planned, negative_plan_jcs)?;
    let materialization = B4NegativeMaterialization::Mutation {
        mutation: B4NegativeMutation::ByteEdit {
            target: B4ByteTarget::RawSeal,
            edit: row.edit.clone(),
        },
    };
    let registry_row = B4NegativeCase {
        execution_id: row.expected.execution_id.to_owned(),
        base_selector_id: LIFT_SELECTOR.to_owned(),
        materialization_domain: B4MaterializationDomain::VerifierInput,
        materialization,
    };
    let expected_materialization = registry_row.materialization.clone();
    let raw_adapter = CryptoReplayAdapterV1 {
        base: &authority.base_raw_seal,
        subject: &row.subject,
        materialization: &expected_materialization,
    };
    let final_adapter = raw_adapter;
    close_production_execution(
        execution_index,
        planned,
        negative_plan_jcs,
        registry_row,
        &raw_adapter,
        &final_adapter,
        row.subject.clone(),
        authority.contexts.to_vec(),
    )
    .map(Some)
}

fn validate_planned_execution(
    expected: ExpectedCryptoRow,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
) -> Result<()> {
    let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(negative_plan_jcs)
        .context("cryptographic producer negative plan is not canonical")?;
    let canonical = plan
        .groups
        .iter()
        .flat_map(|group| group.executions.iter())
        .nth(expected.index)
        .context("cryptographic producer index is outside the canonical plan")?;
    ensure!(
        canonical == planned
            && planned.execution_id == expected.execution_id
            && planned.variant_id == expected.variant_id
            && planned.base_selector_id == LIFT_SELECTOR
            && planned.fixture == B4NegativePlanFixture::LiftPo215
            && planned.materialization_domain == B4MaterializationDomain::VerifierInput
            && planned.execution_surface == B4NegativeExecutionSurface::Risc0CryptographicVerifier
            && planned.qa_result_code == expected.qa_result
            && planned.parser_truncation_words.is_none(),
        "cryptographic execution differs from its exact canonical-plan contract"
    );
    Ok(())
}

fn exact_single_word_replace(base: &[u8], subject: &[u8]) -> Result<B4ByteOperation> {
    ensure!(
        base.len() == PROOF_BYTES && subject.len() == base.len(),
        "cryptographic mutation differs from the exact same-length proof shape"
    );
    let base_words = decode_seal_words(base).context("cryptographic base seal is malformed")?;
    let subject_words =
        decode_seal_words(subject).context("cryptographic subject seal is malformed")?;
    let changed = base_words
        .iter()
        .zip(&subject_words)
        .enumerate()
        .filter_map(|(index, (before, after))| (before != after).then_some((index, before, after)))
        .collect::<Vec<_>>();
    let [(word_index, before, replacement)] = changed.as_slice() else {
        bail!("cryptographic mutation must replace exactly one raw-seal word");
    };
    Ok(B4ByteOperation::Replace {
        before_hex: hex::encode(before.to_le_bytes()),
        replacement_hex: hex::encode(replacement.to_le_bytes()),
        offset: u64::try_from(
            word_index
                .checked_mul(WORD_BYTES)
                .context("cryptographic mutation word offset overflows usize")?,
        )?,
    })
}

#[cfg(test)]
pub(crate) fn synthetic_crypto_authority_for_tests(
    base_raw_seal: Vec<u8>,
    profile_manifest: Vec<u8>,
    receipt_oracle: Vec<u8>,
) -> Result<B4DirectSealCheckpointMutationAuthorityV1> {
    let subjects = synthetic_crypto_subjects(&base_raw_seal)?;
    B4DirectSealCheckpointMutationAuthorityV1::from_test_subjects(
        base_raw_seal,
        profile_manifest,
        receipt_oracle,
        subjects,
    )
}

#[cfg(test)]
pub(crate) fn synthetic_crypto_authority_v2_for_tests(
    base_raw_seal: Vec<u8>,
    profile_manifest: Vec<u8>,
    receipt_oracle: Vec<u8>,
) -> Result<B4DirectSealCheckpointMutationAuthorityV2> {
    let subjects = synthetic_crypto_subjects(&base_raw_seal)?;
    B4DirectSealCheckpointMutationAuthorityV2::from_test_subjects(
        base_raw_seal,
        profile_manifest,
        receipt_oracle,
        subjects,
    )
}

#[cfg(test)]
fn synthetic_crypto_subjects(base_raw_seal: &[u8]) -> Result<[Vec<u8>; 4]> {
    let mut subjects: [Vec<u8>; 4] = std::array::from_fn(|_| base_raw_seal.to_vec());
    for (index, subject) in subjects.iter_mut().enumerate() {
        let offset = index * WORD_BYTES;
        let original = u32::from_le_bytes(subject[offset..offset + WORD_BYTES].try_into()?);
        let replacement = original.wrapping_add(1);
        subject[offset..offset + WORD_BYTES].copy_from_slice(&replacement.to_le_bytes());
    }
    Ok(subjects)
}

/// Local test join over externally retained real case-0 files. This is neither
/// campaign lineage nor a constructor for a V1/V2 materialization authority.
#[cfg(test)]
pub(crate) mod genuine_crypto_join {
    use std::{
        fs::{self, File, Metadata},
        io::Read as _,
        path::{Component, Path, PathBuf},
    };

    use anyhow::{Context as _, Result, ensure};
    use bincode::Options as _;
    use risc0_zkvm::{Digest, InnerReceipt, Receipt, ReceiptClaim, sha::Digestible as _};
    use sha2::{Digest as _, Sha256};

    use super::{
        CryptoSources, DirectSealCheckpointMutationAuthorityParts, LIFT_SELECTOR,
        reconstruct_crypto_execution_core,
    };
    use crate::{
        b4_materialization_set::B4ClosedReconstructedExecutionV1,
        b4_plan::Eip0045B4NegativePlanV1,
        constants::{MAX_STATEMENT_BYTES, PROOF_BYTES, RISC0_NORMAL_LIFT_CONTROL_IDS_HEX},
        ergo_statement::parse_ergo_statement_v1,
        profile_manifest::StarkProfileManifestV1,
        receipt_oracle_codec::{RECEIPT_ORACLE_MAX_BYTES, receipt_oracle_bincode_options},
        receipt_oracle_replay::{CompiledStockSuccinctReplayV1, decode_exact},
    };

    const MANIFEST: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin");
    const PROOF_DIRECTORY: &str = "proof/candidate-proof-export/proof-output";
    const ROW_INDICES: [usize; 4] = [156, 157, 158, 159];

    /// Authenticated local bytes; `oracle` is the canonical inner succinct
    /// receipt, not the on-disk outer Receipt. Private hashes prevent changing
    /// the borrowed test projections before starting the expensive derivation.
    pub(crate) struct Fixture {
        pub(crate) raw: Vec<u8>,
        pub(crate) manifest: Vec<u8>,
        pub(crate) oracle: Vec<u8>,
        raw_sha: [u8; 32],
        oracle_sha: [u8; 32],
    }

    impl Fixture {
        /// Derive all four bounded checkpoint mutations exactly once, then
        /// invoke the same production core separately for each canonical row.
        pub(crate) fn reconstruct(&self) -> Result<Vec<B4ClosedReconstructedExecutionV1>> {
            ensure!(self.manifest == MANIFEST
                && <[u8; 32]>::from(Sha256::digest(&self.raw)) == self.raw_sha
                && <[u8; 32]>::from(Sha256::digest(&self.oracle)) == self.oracle_sha,
                "local crypto fixture changed after authentication");
            let sources = CryptoSources::from_authenticated_parts(
                0, LIFT_SELECTOR, &self.raw, &self.manifest, &self.oracle,
            )?;
            // Do not move this call into the row loop: it derives the entire
            // fixed matrix, including the two source-bounded FRI searches.
            let authority = DirectSealCheckpointMutationAuthorityParts::from_authenticated_sources(sources)?;
            authority.verify_source_binding(sources)?;
            let plan = Eip0045B4NegativePlanV1::canonical()?;
            let plan_jcs = plan.to_canonical_jcs()?;
            let planned = plan.groups.iter().flat_map(|group| group.executions.iter()).collect::<Vec<_>>();
            ROW_INDICES.into_iter().map(|index| {
                reconstruct_crypto_execution_core(
                    index, planned.get(index).context("local crypto canonical plan row absent")?,
                    &plan_jcs, &authority,
                )?.context("local crypto core omitted its fixed row")
            }).collect()
        }
    }

    /// Load a genuine case-0 vector root without deriving any mutation. The
    /// eight external files have fixed roles and a combined input cap below
    /// 1.3 MiB; each size is checked before allocation. The existing bounded
    /// codec and disabled-dev stock replay own all receipt interpretation.
    pub(crate) fn load_fixture(root: &Path) -> Result<Fixture> {
        authenticate_fixture_inputs(read_fixture_inputs(root)?)
    }

    fn read_fixture_inputs(root: &Path) -> Result<[Vec<u8>; 8]> {
        require_directory(root)?;
        let statement = read_bounded(&root.join("statement/candidate-statement.bin"), 159, MAX_STATEMENT_BYTES)?;
        let program = read_bounded(&root.join("statement/candidate-program-id.bin"), 32, 32)?;
        let proof = root.join(PROOF_DIRECTORY);
        let raw = read_bounded(&proof.join("candidate-raw-seal.bin"), PROOF_BYTES, PROOF_BYTES)?;
        let outer_bytes = read_bounded(&proof.join("candidate-receipt-oracle.bincode"), 1, RECEIPT_ORACLE_MAX_BYTES)?;
        let journal = read_bounded(&proof.join("candidate-journal.bin"), 159, MAX_STATEMENT_BYTES)?;
        let image = read_bounded(&proof.join("candidate-image-id.bin"), 32, 32)?;
        let claim = read_bounded(&proof.join("candidate-claim-digest.bin"), 32, 32)?;
        let control = read_bounded(&proof.join("candidate-control-id.bin"), 32, 32)?;
        Ok([statement, program, raw, outer_bytes, journal, image, claim, control])
    }

    fn authenticate_fixture_inputs(inputs: [Vec<u8>; 8]) -> Result<Fixture> {
        let [statement, program, raw, outer_bytes, journal, image, claim, control] = inputs;
        ensure!((159..=MAX_STATEMENT_BYTES).contains(&statement.len())
            && (159..=MAX_STATEMENT_BYTES).contains(&journal.len())
            && program.len() == 32 && image.len() == 32 && claim.len() == 32 && control.len() == 32
            && raw.len() == PROOF_BYTES && (1..=RECEIPT_ORACLE_MAX_BYTES).contains(&outer_bytes.len()),
            "local crypto input memory byte bound");
        let profile = StarkProfileManifestV1::decode(MANIFEST)?;
        profile.validate_initial_profile_target()?;
        let parsed = parse_ergo_statement_v1(&statement)?;
        ensure!(parsed.profile_id() == profile.profile_id()?, "local crypto statement profile mismatch");
        ensure!(parsed.program_id().as_slice() == program && program == image,
                "local crypto statement/program/image mismatch");
        ensure!(journal == statement, "local crypto retained journal mismatch");
        let program_id = Digest::from(parsed.program_id());
        let expected_claim = ReceiptClaim::ok(program_id, statement.clone()).digest();
        ensure!(claim == expected_claim.as_bytes(), "local crypto retained claim mismatch");

        let replay = CompiledStockSuccinctReplayV1::from_compiled_profile()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let outer: Receipt = decode_exact(&outer_bytes)
            .map_err(|error| anyhow::anyhow!(error.to_string()))
            .context("local crypto outer oracle codec mismatch")?;
        ensure!(outer.journal.bytes == statement, "local crypto outer journal mismatch");
        outer.verify_with_context(replay.context(), program_id)
            .context("local crypto outer disabled-dev stock verification failed")?;
        ensure!(outer.claim()?.digest() == expected_claim, "local crypto outer claim mismatch");
        let InnerReceipt::Succinct(inner) = &outer.inner else {
            anyhow::bail!("local crypto source is not a direct succinct receipt");
        };
        ensure!(hex::encode(inner.control_id.as_bytes()) == RISC0_NORMAL_LIFT_CONTROL_IDS_HEX[0]
                && control == inner.control_id.as_bytes(), "local crypto source is not exact Lift-15");
        ensure!(inner.claim.as_value()?.digest() == expected_claim, "local crypto inner claim mismatch");
        ensure!(inner.get_seal_bytes() == raw, "local crypto outer/raw seal mismatch");
        let oracle = receipt_oracle_bincode_options().serialize(inner)?;
        let verified = replay.verify_direct_oracle(&oracle)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        ensure!(verified.stock().family == "lift-po2-15" && verified.raw_seal_bytes() == raw
                && verified.claim_digest() == expected_claim, "local crypto direct stock binding mismatch");
        Ok(Fixture {
            raw_sha: Sha256::digest(&raw).into(), oracle_sha: Sha256::digest(&oracle).into(),
            raw, manifest: MANIFEST.to_vec(), oracle,
        })
    }

    /// Exercise every external input binding without creating a mutation
    /// authority or running a FRI search. All counterfactuals are private copies.
    pub(crate) fn assert_loader_single_fault_negatives(root: &Path) -> Result<()> {
        let positive = read_fixture_inputs(root)?;
        authenticate_fixture_inputs(positive.clone())?;
        // Slot order is the exact read_fixture_inputs order. The statement
        // counterfactual changes its profile field, preserving its grammar.
        let cases = [
            (0, 59, "local crypto statement profile mismatch"),
            (1, 0, "local crypto statement/program/image mismatch"),
            (5, 0, "local crypto statement/program/image mismatch"),
            (4, 0, "local crypto retained journal mismatch"),
            (6, 0, "local crypto retained claim mismatch"),
            (7, 0, "local crypto source is not exact Lift-15"),
            (2, 0, "local crypto outer/raw seal mismatch"),
        ];
        for (slot, offset, expected) in cases {
            let mut altered = positive.clone();
            altered[slot][offset] ^= 1;
            ensure!(altered.iter().zip(&positive).filter(|(left, right)| left != right).count() == 1,
                "loader counterfactual changed multiple inputs");
            ensure!(altered[slot].len() == positive[slot].len()
                && altered[slot].iter().zip(&positive[slot]).filter(|(left, right)| left != right).count() == 1,
                "loader counterfactual is not one byte");
            let error = authenticate_fixture_inputs(altered).err()
                .context("loader accepted a single-fault counterfactual")?;
            ensure!(error.to_string() == expected, "loader counterfactual rejected at wrong guard: {error}");
        }
        let mut truncated_outer = positive.clone();
        ensure!(truncated_outer[3].len() > 1, "positive outer oracle too short for codec negative");
        truncated_outer[3].pop();
        ensure!(truncated_outer.iter().zip(&positive).enumerate()
            .all(|(slot, (left, right))| slot == 3 || left == right),
            "outer codec counterfactual changed another input");
        ensure!(truncated_outer[3] == positive[3][..positive[3].len() - 1],
            "outer codec counterfactual is not exact one-byte truncation");
        let error = authenticate_fixture_inputs(truncated_outer).err()
            .context("loader accepted a truncated outer oracle")?;
        ensure!(error.to_string() == "local crypto outer oracle codec mismatch",
            "truncated outer oracle rejected at wrong guard: {error}");
        Ok(())
    }

    fn read_bounded(path: &Path, minimum: usize, maximum: usize) -> Result<Vec<u8>> {
        require_directory(path.parent().context("local crypto input has no parent")?)?;
        let metadata = fs::symlink_metadata(path)?;
        ensure!(metadata.is_file() && !metadata.file_type().is_symlink() && !is_reparse_point(&metadata),
                "local crypto input is not a physical regular file");
        ensure!((minimum as u64..=maximum as u64).contains(&metadata.len()), "local crypto input byte bound");
        let file = File::open(path)?;
        let opened = file.metadata()?;
        ensure!(opened.is_file() && !is_reparse_point(&opened) && opened.len() == metadata.len(),
                "local crypto input changed at open");
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(usize::try_from(opened.len())?)?;
        file.take(u64::try_from(maximum)?.checked_add(1).context("local crypto input limit overflow")?)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() as u64 == opened.len() && (minimum..=maximum).contains(&bytes.len()),
                "local crypto input changed length");
        Ok(bytes)
    }

    fn require_directory(path: &Path) -> Result<()> {
        ensure!(path.is_absolute() && !path.components().any(|part| matches!(part, Component::ParentDir)),
                "local crypto root must be absolute without parent traversal");
        let mut ancestor = PathBuf::new();
        for component in path.components() {
            ancestor.push(component.as_os_str());
            if matches!(component, Component::Prefix(_)) { continue; }
            let metadata = fs::symlink_metadata(&ancestor)?;
            ensure!(metadata.is_dir() && !metadata.file_type().is_symlink() && !is_reparse_point(&metadata),
                    "local crypto directory is redirected");
        }
        Ok(())
    }

    #[cfg(windows)]
    fn is_reparse_point(metadata: &Metadata) -> bool {
        use std::os::windows::fs::MetadataExt as _;
        metadata.file_attributes() & 0x0400 != 0
    }

    #[cfg(not(windows))]
    fn is_reparse_point(_: &Metadata) -> bool { false }

    #[test]
    fn genuine_crypto_input_reader_enforces_exact_bounds() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("bounded-input");
        fs::write(&path, b"abc").unwrap();
        assert_eq!(read_bounded(&path, 3, 3).unwrap(), b"abc");
        assert!(read_bounded(&path, 1, 2).unwrap_err().to_string().contains("byte bound"));
        assert!(read_bounded(&path, 4, 4).unwrap_err().to_string().contains("byte bound"));
        assert!(load_fixture(root.path()).is_err());
    }

    #[test]
    fn genuine_crypto_manifest_and_row_prerequisites_are_fixed() {
        let manifest = StarkProfileManifestV1::decode(MANIFEST).unwrap();
        manifest.validate_initial_profile_target().unwrap();
        assert_eq!(ROW_INDICES, [156, 157, 158, 159]);
        assert_eq!(super::EXPECTED_ROWS.map(|row| row.index), ROW_INDICES);
        assert_eq!(LIFT_SELECTOR, "lift-po2-15");
        assert_eq!(RECEIPT_ORACLE_MAX_BYTES, 1_048_576);
        assert_eq!(PROOF_BYTES, 222_668);
    }

    #[cfg(unix)]
    #[test]
    fn genuine_crypto_input_reader_rejects_redirected_leaf_and_parent() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("physical");
        fs::create_dir(&directory).unwrap();
        let input = directory.join("input");
        fs::write(&input, b"x").unwrap();
        let leaf = directory.join("leaf-link");
        symlink(&input, &leaf).unwrap();
        assert!(read_bounded(&leaf, 1, 1).unwrap_err().to_string().contains("physical regular"));
        let parent = root.path().join("parent-link");
        symlink(&directory, &parent).unwrap();
        assert!(read_bounded(&parent.join("input"), 1, 1).unwrap_err().to_string().contains("redirected"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_row(index: usize) -> B4NegativePlanExecutionV1 {
        Eip0045B4NegativePlanV1::canonical()
            .unwrap()
            .groups
            .into_iter()
            .flat_map(|group| group.executions)
            .nth(index)
            .unwrap()
    }

    fn assert_same_closed_execution(
        left: &B4ClosedReconstructedExecutionV1,
        right: &B4ClosedReconstructedExecutionV1,
    ) {
        assert_eq!(left.derived_registry_row, right.derived_registry_row);
        assert_eq!(left.base, right.base);
        assert_eq!(
            left.materialization_identity_jcs,
            right.materialization_identity_jcs
        );
        assert_eq!(left.negative_input_jcs, right.negative_input_jcs);
        assert_eq!(left.subject, right.subject);
        assert_eq!(left.contexts, right.contexts);
    }

    #[test]
    fn synthetic_v2_authority_reconstructs_the_same_closed_row_as_v1() {
        let base_raw_seal = vec![0; PROOF_BYTES];
        let profile_manifest = b"authenticated-profile-manifest".to_vec();
        let receipt_oracle = b"authenticated-receipt-oracle".to_vec();
        let v1 = synthetic_crypto_authority_for_tests(
            base_raw_seal.clone(),
            profile_manifest.clone(),
            receipt_oracle.clone(),
        )
        .unwrap();
        let v2 = synthetic_crypto_authority_v2_for_tests(
            base_raw_seal,
            profile_manifest,
            receipt_oracle,
        )
        .unwrap();
        let negative_plan_jcs = Eip0045B4NegativePlanV1::canonical()
            .unwrap()
            .to_canonical_jcs()
            .unwrap();
        let planned = canonical_row(156);

        let v1_row =
            reconstruct_crypto_execution_core(156, &planned, &negative_plan_jcs, &v1.parts)
                .unwrap()
                .unwrap();
        let v2_row =
            reconstruct_crypto_execution_core(156, &planned, &negative_plan_jcs, &v2.parts)
                .unwrap()
                .unwrap();
        assert_same_closed_execution(&v1_row, &v2_row);
    }

    #[test]
    fn v2_authority_rejects_each_authenticated_source_drift_independently() {
        let base_raw_seal = vec![0; PROOF_BYTES];
        let profile_manifest = b"authenticated-profile-manifest".to_vec();
        let receipt_oracle = b"authenticated-receipt-oracle".to_vec();
        let authority = synthetic_crypto_authority_v2_for_tests(
            base_raw_seal.clone(),
            profile_manifest.clone(),
            receipt_oracle.clone(),
        )
        .unwrap();
        let assert_rejected = |raw_seal: &[u8], profile: &[u8], receipt: &[u8]| {
            let changed_sources = CryptoSources::from_authenticated_parts(
                0,
                LIFT_SELECTOR,
                raw_seal,
                profile,
                receipt,
            )
            .unwrap();
            let error = authority
                .parts
                .verify_source_binding(changed_sources)
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "cryptographic mutation authority differs from the authenticated fixture sources"
            );
        };

        let mut changed_raw_seal = base_raw_seal;
        changed_raw_seal[WORD_BYTES * 8] ^= 1;
        assert_rejected(&changed_raw_seal, &profile_manifest, &receipt_oracle);
        assert_rejected(
            &authority.parts.base_raw_seal,
            b"authenticated-profile-manifest-drift",
            &receipt_oracle,
        );
        assert_rejected(
            &authority.parts.base_raw_seal,
            &profile_manifest,
            b"authenticated-receipt-oracle-drift",
        );
    }

    #[test]
    fn v2_production_path_is_wrapper_rooted_affine_and_version_exclusive() {
        let source = include_str!("b4_c2_crypto.rs");
        let source_authentication = source
            .split("fn authenticate_v2(")
            .nth(1)
            .unwrap()
            .split("fn from_authenticated_parts(")
            .next()
            .unwrap();
        assert!(source_authentication.contains("B4MaterializationFixtureSourceResolverV2"));
        assert!(source_authentication.contains("from_authenticated(top_level)"));
        assert!(source_authentication.contains("resolver.negative_plan_jcs()"));
        assert!(!source_authentication.contains("B4FixtureSourceResolverV1"));
        assert!(!source_authentication.contains(".storage()"));

        let constructor = source
            .split("impl B4DirectSealCheckpointMutationAuthorityV2 {")
            .nth(1)
            .unwrap()
            .split("#[derive(Clone, Copy, Debug)]\nstruct CryptoReplayAdapterV1")
            .next()
            .unwrap();
        assert!(constructor.contains("B4AuthenticatedMaterializationTopLevelV2"));
        assert!(constructor.contains("CryptoSources::authenticate_v2(top_level)?"));
        assert!(!constructor.contains("B4AuthenticatedMaterializationTopLevelV1"));
        assert!(!constructor.contains("B4FixtureSourceResolverV1"));
        assert!(!constructor.contains(".storage()"));

        let entrypoint = source
            .split("pub(crate) fn reconstruct_crypto_execution_v2(")
            .nth(1)
            .unwrap()
            .split("fn reconstruct_crypto_execution_core(")
            .next()
            .unwrap();
        assert!(entrypoint.contains("B4AuthenticatedMaterializationTopLevelV2"));
        assert!(entrypoint.contains("CryptoSources::authenticate_v2(top_level)?"));
        assert!(entrypoint.contains("verify_source_binding(sources)?"));
        assert!(!entrypoint.contains("B4AuthenticatedMaterializationTopLevelV1"));
        assert!(!entrypoint.contains("B4FixtureSourceResolverV1"));
        assert!(!entrypoint.contains(".storage()"));

        let core = source
            .split("fn reconstruct_crypto_execution_core(")
            .nth(1)
            .unwrap()
            .split("fn validate_planned_execution(")
            .next()
            .unwrap();
        assert!(core.contains("negative_plan_jcs: &[u8]"));
        assert!(!core.contains("B4AuthenticatedMaterializationTopLevel"));
        assert!(!core.contains("FixtureSourceResolver"));

        let v2_type = source
            .split("pub(crate) struct B4DirectSealCheckpointMutationAuthorityV2")
            .nth(1)
            .unwrap()
            .split("impl B4DirectSealCheckpointMutationAuthorityV2")
            .next()
            .unwrap();
        assert!(!v2_type.contains("derive("));
        let v2_name = "B4DirectSealCheckpointMutationAuthorityV2";
        assert!(!source.contains(&format!("impl Clone for {v2_name}")));
        assert!(!source.contains(&format!("impl Default for {v2_name}")));
        assert!(!source.contains(&format!("impl serde::Serialize for {v2_name}")));
        assert!(!source.contains(&format!("impl serde::Deserialize for {v2_name}")));
        assert!(!source.contains(&format!(
            "impl From<B4DirectSealCheckpointMutationAuthorityV1> for {v2_name}"
        )));
        assert!(!source.contains(&format!(
            "impl From<{v2_name}> for B4DirectSealCheckpointMutationAuthorityV1"
        )));
    }
}
