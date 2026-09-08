//! Closed C2 producers for raw statement, proof-order, and raw-seal rows.
//!
//! The exact row table is deliberately literal. Data-dependent seal offsets
//! are derived later from authenticated case-0 bytes; this table owns only the
//! immutable plan positions and execution identities.

use anyhow::{Context, Result, bail, ensure};

use crate::{
    b4::{
        B4ByteOperation, B4ByteTarget, B4NegativeCase, B4NegativeMaterialization,
        B4NegativeMutation, B4SequenceOperation, B4SequenceTarget,
    },
    b4_c2_opcode_sequence::{
        decode_producer_opcode_subject, encode_opcode_subject, proof_subject_from_raw_seal,
        split_raw_seal,
    },
    b4_fixture_sources::{B4FixtureSourceResolverV1, B4MaterializationFixtureSourceResolverV2},
    b4_materialization_set::{
        B4AuthenticatedMaterializationTopLevelV1, B4AuthenticatedMaterializationTopLevelV2,
        B4ClosedReconstructedExecutionV1, close_production_execution,
    },
    b4_mutation::{
        B4MaterializationReplayAdapterV1, reconstruct_byte_edit, reconstruct_sequence_edit,
    },
    b4_plan::{
        B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanExecutionV1,
        B4NegativePlanFixture, B4NegativeQaResultCode, Eip0045B4NegativePlanV1,
    },
    b4_subject::Eip0045B4SequenceSubjectV1,
    ergo_statement::{ErgoStatementFieldV1, ErgoStatementV1, parse_ergo_statement_v1},
    seal::{
        SealSemanticProjection, SealSemanticRole, decode_seal_words,
        derive_seal_semantic_projection, first_byte_order_candidate, fixed_semantic_representative,
    },
};

const LIFT_CASE_ID: &str = "lift-po2-15";
const LIFT_SELECTOR: &str = "lift-po2-15";
const REFERENCE_STATEMENT_SELECTOR: &str = "lift-po2-15-reference-statement-v1";
const WORD_BYTES: usize = 4;

const RAW_EXECUTION_IDS: [(usize, &str); 48] = [
    (
        0,
        "statement-field-byte-sweep--chain-domain-byte-order-reversed",
    ),
    (1, "statement-field-byte-sweep--profile-id"),
    (2, "statement-field-byte-sweep--program-id"),
    (
        3,
        "statement-field-byte-sweep--contract-id-byte-order-reversed",
    ),
    (4, "statement-field-byte-sweep--application-payload"),
    (5, "statement-profile-id-byte-order--profile-id"),
    (6, "statement-program-id-byte-order--program-id"),
    (29, "proof-chunks-reordered--first-two-chunks-swapped"),
    (33, "outer-root-padding-sweep--padding-word-01"),
    (34, "outer-root-padding-sweep--padding-word-03"),
    (35, "outer-root-padding-sweep--padding-word-05"),
    (36, "outer-root-padding-sweep--padding-word-07"),
    (37, "outer-root-padding-sweep--padding-word-09"),
    (38, "outer-root-padding-sweep--padding-word-11"),
    (39, "outer-root-padding-sweep--padding-word-13"),
    (40, "outer-root-padding-sweep--padding-word-15"),
    (41, "outer-claim-halfword-overflow-sweep--claim-word-16"),
    (42, "outer-claim-halfword-overflow-sweep--claim-word-17"),
    (43, "outer-claim-halfword-overflow-sweep--claim-word-18"),
    (44, "outer-claim-halfword-overflow-sweep--claim-word-19"),
    (45, "outer-claim-halfword-overflow-sweep--claim-word-20"),
    (46, "outer-claim-halfword-overflow-sweep--claim-word-21"),
    (47, "outer-claim-halfword-overflow-sweep--claim-word-22"),
    (48, "outer-claim-halfword-overflow-sweep--claim-word-23"),
    (49, "outer-claim-halfword-overflow-sweep--claim-word-24"),
    (50, "outer-claim-halfword-overflow-sweep--claim-word-25"),
    (51, "outer-claim-halfword-overflow-sweep--claim-word-26"),
    (52, "outer-claim-halfword-overflow-sweep--claim-word-27"),
    (53, "outer-claim-halfword-overflow-sweep--claim-word-28"),
    (54, "outer-claim-halfword-overflow-sweep--claim-word-29"),
    (55, "outer-claim-halfword-overflow-sweep--claim-word-30"),
    (56, "outer-claim-halfword-overflow-sweep--claim-word-31"),
    (57, "outer-field-modulus-role-sweep--output-root"),
    (58, "outer-field-modulus-role-sweep--output-claim"),
    (59, "outer-field-modulus-role-sweep--merkle-top"),
    (60, "outer-field-modulus-role-sweep--coefficient"),
    (61, "outer-field-modulus-role-sweep--final-coefficient"),
    (62, "outer-field-modulus-role-sweep--merkle-opening-leaf"),
    (63, "outer-field-modulus-role-sweep--merkle-opening-sibling"),
    (64, "outer-field-byte-order-role-sweep--output-root"),
    (65, "outer-field-byte-order-role-sweep--output-claim"),
    (66, "outer-field-byte-order-role-sweep--merkle-top"),
    (67, "outer-field-byte-order-role-sweep--coefficient"),
    (68, "outer-field-byte-order-role-sweep--final-coefficient"),
    (69, "outer-field-byte-order-role-sweep--merkle-opening-leaf"),
    (
        70,
        "outer-field-byte-order-role-sweep--merkle-opening-sibling",
    ),
    (71, "outer-po2-montgomery-encoding--outer-po2-literal"),
    (109, "terminal-outer-po2-mismatch--outer-po2"),
];

fn expected_execution_id(index: usize) -> Option<&'static str> {
    RAW_EXECUTION_IDS
        .iter()
        .find_map(|(candidate, id)| (*candidate == index).then_some(*id))
}

#[derive(Clone, Debug)]
struct RawSources<'a> {
    manifest: &'a [u8],
    raw_seal: &'a [u8],
    raw_seal_words: Vec<u32>,
    proof_chunks: Vec<Vec<u8>>,
    proof_subject: Vec<u8>,
    statement_bytes: &'a [u8],
    statement: ErgoStatementV1<'a>,
    profile_id: [u8; 32],
    program_id: [u8; 32],
    semantic_projection: SealSemanticProjection,
    outer_po2: u8,
}

impl<'a> RawSources<'a> {
    fn authenticate_v1(top_level: &'a B4AuthenticatedMaterializationTopLevelV1) -> Result<Self> {
        let resolver = B4FixtureSourceResolverV1::from_authenticated(top_level)
            .context("raw producer cannot authenticate the fixture source inventory")?;
        let positive = resolver
            .positive_case(0, LIFT_CASE_ID)
            .context("raw producer cannot select exact positive case zero")?;
        let input = resolver
            .positive_input()
            .context("raw producer cannot authenticate the positive input package")?;
        let manifest = input
            .initial_profile_manifest()
            .context("raw producer initial profile manifest is invalid")?;
        let reference = resolver
            .case_zero_reference_statement()
            .context("raw producer cannot authenticate the case-0 reference statement")?;
        Self::from_authenticated_parts(
            positive.case_index(),
            positive.case_id(),
            input.profile_manifest(),
            manifest.outer_po2(),
            input.profile_constants(),
            positive.raw_seal(),
            reference.statement_bytes(),
            reference.statement(),
            reference.profile_id(),
            reference.program_id(),
        )
    }

    fn authenticate_v2(
        top_level: &'a B4AuthenticatedMaterializationTopLevelV2,
    ) -> Result<(Self, &'a [u8])> {
        let resolver = B4MaterializationFixtureSourceResolverV2::from_authenticated(top_level)
            .context("V2 raw producer cannot authenticate the fixture source inventory")?;
        let positive = resolver
            .positive_case(0, LIFT_CASE_ID)
            .context("V2 raw producer cannot select exact positive case zero")?;
        let input = resolver
            .positive_input()
            .context("V2 raw producer cannot authenticate the positive input package")?;
        let manifest = input
            .initial_profile_manifest()
            .context("V2 raw producer initial profile manifest is invalid")?;
        let reference = resolver
            .case_zero_reference_statement()
            .context("V2 raw producer cannot authenticate the case-0 reference statement")?;
        let sources = Self::from_authenticated_parts(
            positive.case_index(),
            positive.case_id(),
            input.profile_manifest(),
            manifest.outer_po2(),
            input.profile_constants(),
            positive.raw_seal(),
            reference.statement_bytes(),
            reference.statement(),
            reference.profile_id(),
            reference.program_id(),
        )?;
        Ok((sources, resolver.negative_plan_jcs()))
    }

    #[allow(clippy::too_many_arguments)]
    fn from_authenticated_parts(
        case_index: usize,
        case_id: &str,
        manifest: &'a [u8],
        outer_po2: u8,
        profile_constants: &[u8],
        raw_seal: &'a [u8],
        statement_bytes: &'a [u8],
        statement: ErgoStatementV1<'a>,
        profile_id: [u8; 32],
        program_id: [u8; 32],
    ) -> Result<Self> {
        ensure!(
            case_index == 0 && case_id == LIFT_CASE_ID,
            "raw producer selected a different positive case"
        );
        ensure!(
            profile_id == statement.profile_id() && program_id == statement.program_id(),
            "raw producer reference statement identities differ from their independent sources"
        );
        let raw_seal_words =
            decode_seal_words(raw_seal).context("raw producer seal has the wrong exact grammar")?;
        let semantic_projection = derive_seal_semantic_projection(profile_constants)
            .context("raw producer cannot derive its semantic seal projection from B2")?;
        let modulus = semantic_projection.modulus();
        ensure!(
            raw_seal_words.iter().all(|word| *word < modulus),
            "raw producer base contains a non-reduced field word"
        );
        ensure!(
            (1..16)
                .step_by(2)
                .all(|index| raw_seal_words.get(index) == Some(&0)),
            "raw producer base contains nonzero inner-root padding"
        );
        ensure!(
            raw_seal_words.get(32) == Some(&u32::from(outer_po2)),
            "raw producer base outer exponent differs from the authenticated manifest literal"
        );
        let claim_words = raw_seal_words
            .get(16..32)
            .context("raw producer base lacks the exact sixteen-word claim span")?;
        for (offset, raw_word) in claim_words.iter().copied().enumerate() {
            ensure!(
                u16::try_from(montgomery_decode(raw_word, modulus)?).is_ok(),
                "raw producer base claim word {} does not decode to one halfword",
                16 + offset
            );
        }
        let proof_chunks = split_raw_seal(raw_seal)
            .context("raw producer cannot derive the exact proof chunks")?;
        let proof_subject = proof_subject_from_raw_seal(raw_seal)
            .context("raw producer cannot derive the detached proof-chunk subject")?;
        Ok(Self {
            manifest,
            raw_seal,
            raw_seal_words,
            proof_chunks,
            proof_subject,
            statement_bytes,
            statement,
            profile_id,
            program_id,
            semantic_projection,
            outer_po2,
        })
    }
}

fn montgomery_radix(modulus: u32) -> Result<u32> {
    ensure!(modulus > 2, "Montgomery modulus is too small");
    Ok(u32::try_from((1_u64 << 32) % u64::from(modulus))?)
}

fn modular_pow(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut accumulator = 1_u64;
    while exponent > 0 {
        if exponent & 1 == 1 {
            accumulator = (accumulator * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent >>= 1;
    }
    accumulator
}

fn montgomery_encode(value: u32, modulus: u32) -> Result<u32> {
    ensure!(value < modulus, "Montgomery input is not a field element");
    Ok(u32::try_from(
        (u64::from(value) * u64::from(montgomery_radix(modulus)?)) % u64::from(modulus),
    )?)
}

fn montgomery_decode(raw: u32, modulus: u32) -> Result<u32> {
    ensure!(raw < modulus, "Montgomery residue is not reduced");
    let radix = u64::from(montgomery_radix(modulus)?);
    let inverse = modular_pow(radix, u64::from(modulus) - 2, u64::from(modulus));
    ensure!(
        (radix * inverse) % u64::from(modulus) == 1,
        "authenticated modulus does not admit the Montgomery radix inverse"
    );
    Ok(u32::try_from(
        (u64::from(raw) * inverse) % u64::from(modulus),
    )?)
}

fn seal_role(relative: usize) -> Result<SealSemanticRole> {
    SealSemanticRole::ALL
        .get(relative)
        .copied()
        .context("raw seal role index is outside the exact seven-role table")
}

fn replace_word(
    sources: &RawSources<'_>,
    word_index: usize,
    replacement: u32,
) -> Result<B4ByteOperation> {
    let before = sources
        .raw_seal_words
        .get(word_index)
        .copied()
        .context("raw seal mutation word is outside the authenticated proof")?;
    ensure!(
        before != replacement,
        "raw seal word replacement would be a no-op"
    );
    let byte_offset = word_index
        .checked_mul(WORD_BYTES)
        .context("raw seal word offset overflows usize")?;
    Ok(B4ByteOperation::Replace {
        before_hex: hex::encode(before.to_le_bytes()),
        replacement_hex: hex::encode(replacement.to_le_bytes()),
        offset: u64::try_from(byte_offset)?,
    })
}

fn seal_edit(index: usize, sources: &RawSources<'_>) -> Result<B4ByteOperation> {
    let modulus = sources.semantic_projection.modulus();
    match index {
        33..=40 => {
            let word_index = 1 + (index - 33) * 2;
            ensure!(
                sources.raw_seal_words.get(word_index) == Some(&0),
                "raw seal padding recipe base is not exact zero"
            );
            replace_word(sources, word_index, 1)
        }
        41..=56 => {
            let word_index = 16 + (index - 41);
            let before = *sources
                .raw_seal_words
                .get(word_index)
                .context("raw seal claim word is absent")?;
            ensure!(
                u16::try_from(montgomery_decode(before, modulus)?).is_ok(),
                "raw seal claim recipe base is already outside one halfword"
            );
            let replacement = montgomery_encode(u32::from(u16::MAX) + 1, modulus)?;
            ensure!(
                replacement == 0x0ffd_ddde,
                "authenticated BabyBear Montgomery encoding of 65536 drifted"
            );
            replace_word(sources, word_index, replacement)
        }
        57..=63 => {
            let role = seal_role(index - 57)?;
            let word_index = fixed_semantic_representative(&sources.semantic_projection, role)?;
            replace_word(sources, word_index, modulus)
        }
        64..=70 => {
            let role = seal_role(index - 64)?;
            let selected =
                first_byte_order_candidate(sources.raw_seal, &sources.semantic_projection, role)
                    .context("raw seal role lacks its exact first byte-order rejection")?;
            let byte_offset = selected
                .word_index()
                .checked_mul(WORD_BYTES)
                .context("raw seal byte-order offset overflows usize")?;
            ensure!(
                sources.raw_seal_words.get(selected.word_index())
                    == Some(&selected.original_word())
                    && selected.reversed_word() >= modulus,
                "raw seal byte-order witness differs from its authenticated semantic role"
            );
            Ok(B4ByteOperation::Replace {
                before_hex: hex::encode(selected.before_bytes()),
                replacement_hex: hex::encode(selected.replacement_bytes()),
                offset: u64::try_from(byte_offset)?,
            })
        }
        71 => {
            let before = u32::from(sources.outer_po2);
            ensure!(
                sources.raw_seal_words.get(32) == Some(&before),
                "raw seal Montgomery-po2 base is not the manifest literal"
            );
            let replacement = montgomery_encode(before, modulus)?;
            ensure!(
                replacement == 0x2fff_ffda && replacement < modulus,
                "authenticated manifest outerPo2 Montgomery encoding drifted"
            );
            replace_word(sources, 32, replacement)
        }
        109 => {
            let before = u32::from(sources.outer_po2);
            ensure!(
                sources.raw_seal_words.get(32) == Some(&before),
                "raw seal alternate-po2 base is not the manifest literal"
            );
            let replacement = before
                .checked_add(1)
                .context("manifest outerPo2 has no deterministic next literal")?;
            ensure!(
                replacement < modulus,
                "deterministic alternate outerPo2 literal is not reduced"
            );
            replace_word(sources, 32, replacement)
        }
        _ => bail!("raw seal execution index is outside its closed row set"),
    }
}

fn seal_materialization(
    index: usize,
    sources: &RawSources<'_>,
) -> Result<B4NegativeMaterialization> {
    Ok(B4NegativeMaterialization::Mutation {
        mutation: B4NegativeMutation::ByteEdit {
            target: B4ByteTarget::RawSeal,
            edit: seal_edit(index, sources)?,
        },
    })
}

fn replacement_parts(edit: &B4ByteOperation) -> Result<(usize, Vec<u8>, Vec<u8>)> {
    let B4ByteOperation::Replace {
        before_hex,
        replacement_hex,
        offset,
    } = edit
    else {
        bail!("raw seal recipe is not an exact replacement");
    };
    let start = usize::try_from(*offset).context("raw seal replacement offset exceeds usize")?;
    let before = hex::decode(before_hex).context("raw seal before witness is not valid hex")?;
    let replacement =
        hex::decode(replacement_hex).context("raw seal replacement witness is not valid hex")?;
    ensure!(
        before.len() == WORD_BYTES && replacement.len() == WORD_BYTES,
        "raw seal replacement is not exactly one word"
    );
    Ok((start, before, replacement))
}

fn independent_replace_splice(base: &[u8], edit: &B4ByteOperation) -> Result<Vec<u8>> {
    let (start, before, replacement) = replacement_parts(edit)?;
    let end = start
        .checked_add(before.len())
        .context("raw seal replacement range overflows usize")?;
    ensure!(
        base.get(start..end) == Some(before.as_slice()),
        "raw seal replacement witness differs from the authenticated source"
    );
    let mut output = Vec::with_capacity(base.len());
    output.extend_from_slice(
        base.get(..start)
            .context("raw seal replacement prefix is outside the source")?,
    );
    output.extend_from_slice(&replacement);
    output.extend_from_slice(
        base.get(end..)
            .context("raw seal replacement suffix is outside the source")?,
    );
    ensure!(
        output.len() == base.len(),
        "raw seal replacement changed the exact proof length"
    );
    Ok(output)
}

fn validate_seal_rejection_projection(
    index: usize,
    sources: &RawSources<'_>,
    mutated: &[u8],
) -> Result<()> {
    let words = decode_seal_words(mutated)?;
    let modulus = sources.semantic_projection.modulus();
    match index {
        33..=40 => {
            let word_index = 1 + (index - 33) * 2;
            let selected = words
                .get(word_index)
                .copied()
                .context("raw padding mutation word is absent")?;
            ensure!(
                selected == 1
                    && words
                        .iter()
                        .enumerate()
                        .all(|(candidate, word)| candidate == word_index || *word < modulus),
                "raw padding mutation does not isolate one reduced nonzero padding word"
            );
        }
        41..=56 => {
            let word_index = 16 + (index - 41);
            let selected = words
                .get(word_index)
                .copied()
                .context("raw claim mutation word is absent")?;
            let claim_words = words
                .get(16..32)
                .context("raw claim mutation lacks the exact claim span")?;
            ensure!(
                words.iter().all(|word| *word < modulus)
                    && montgomery_decode(selected, modulus)? == u32::from(u16::MAX) + 1
                    && claim_words.iter().enumerate().all(|(offset, word)| {
                        16 + offset == word_index
                            || montgomery_decode(*word, modulus)
                                .is_ok_and(|value| u16::try_from(value).is_ok())
                    }),
                "raw claim mutation does not isolate the selected overflowing halfword"
            );
        }
        57..=70 => {
            let (word_index, _, _) = replacement_parts(&seal_edit(index, sources)?)?;
            let word_index = word_index / WORD_BYTES;
            let selected = words
                .get(word_index)
                .copied()
                .context("raw field mutation word is absent")?;
            ensure!(
                selected >= modulus
                    && words
                        .iter()
                        .enumerate()
                        .all(|(candidate, word)| candidate == word_index || *word < modulus),
                "raw field mutation does not isolate one non-reduced word"
            );
        }
        71 => {
            let selected = words
                .get(32)
                .copied()
                .context("raw Montgomery-po2 mutation word is absent")?;
            ensure!(
                words.iter().all(|word| *word < modulus)
                    && selected == montgomery_encode(u32::from(sources.outer_po2), modulus)?
                    && selected != u32::from(sources.outer_po2),
                "raw Montgomery-po2 mutation does not isolate the literal preflight mismatch"
            );
        }
        109 => {
            let selected = words
                .get(32)
                .copied()
                .context("raw alternate-po2 mutation word is absent")?;
            ensure!(
                words.iter().all(|word| *word < modulus)
                    && selected == u32::from(sources.outer_po2) + 1,
                "raw alternate-po2 mutation does not isolate the literal preflight mismatch"
            );
        }
        _ => bail!("raw seal rejection projection received an unsupported row"),
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct SealRawReplayAdapterV1<'a> {
    index: usize,
    sources: &'a RawSources<'a>,
    expected_materialization: &'a B4NegativeMaterialization,
    output: &'a [u8],
}

impl B4MaterializationReplayAdapterV1 for SealRawReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::VerifierInput
    }

    fn base_bytes(&self) -> &[u8] {
        self.sources.raw_seal
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
            base_selector_id == LIFT_SELECTOR
                && materialization == self.expected_materialization
                && *materialization == seal_materialization(self.index, self.sources)?,
            "raw seal replay received a selector or recipe outside its closed row"
        );
        let B4NegativeMaterialization::Mutation {
            mutation:
                B4NegativeMutation::ByteEdit {
                    target: B4ByteTarget::RawSeal,
                    edit,
                },
        } = materialization
        else {
            bail!("raw seal replay received a non-seal byte recipe");
        };
        let replayed = reconstruct_byte_edit(self.sources.raw_seal, edit)
            .context("raw seal replay cannot reconstruct its authenticated byte edit")?;
        ensure!(
            replayed == self.output,
            "raw seal replay output differs from generic byte reconstruction"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct SealFinalReplayAdapterV1<'a> {
    index: usize,
    sources: &'a RawSources<'a>,
    expected_materialization: &'a B4NegativeMaterialization,
    output: &'a [u8],
}

impl B4MaterializationReplayAdapterV1 for SealFinalReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::VerifierInput
    }

    fn base_bytes(&self) -> &[u8] {
        self.sources.raw_seal
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
            base_selector_id == LIFT_SELECTOR
                && materialization == self.expected_materialization
                && *materialization == seal_materialization(self.index, self.sources)?,
            "final seal replay received a selector or recipe outside its closed row"
        );
        let B4NegativeMaterialization::Mutation {
            mutation:
                B4NegativeMutation::ByteEdit {
                    target: B4ByteTarget::RawSeal,
                    edit,
                },
        } = materialization
        else {
            bail!("final seal replay received a non-seal byte recipe");
        };
        let decoded = decode_producer_opcode_subject(self.output)
            .context("final seal opcode subject does not decode independently")?;
        ensure!(
            decoded.application_payload() == self.sources.statement.application_payload()
                && decoded.program_id() == self.sources.program_id
                && decoded.profile_id() == self.sources.profile_id
                && decoded.proof_chunks().len() == self.sources.proof_chunks.len(),
            "final seal opcode subject changed an unchanged positional input"
        );
        for (actual, original) in decoded
            .proof_chunks()
            .iter()
            .zip(&self.sources.proof_chunks)
        {
            ensure!(
                actual.len() == original.len(),
                "final seal opcode subject changed a canonical chunk boundary"
            );
        }
        let mutated = decoded
            .proof_chunks()
            .iter()
            .flat_map(|chunk| chunk.iter().copied())
            .collect::<Vec<_>>();
        let (start, before, replacement) = replacement_parts(edit)?;
        let end = start
            .checked_add(before.len())
            .context("final seal replacement range overflows usize")?;
        ensure!(
            self.sources.raw_seal.get(start..end) == Some(before.as_slice())
                && mutated.get(start..end) == Some(replacement.as_slice())
                && mutated.get(..start) == self.sources.raw_seal.get(..start)
                && mutated.get(end..) == self.sources.raw_seal.get(end..),
            "final seal opcode subject is not the exact source prefix/replacement/suffix splice"
        );
        validate_seal_rejection_projection(self.index, self.sources, &mutated)
    }
}

#[derive(Clone, Copy, Debug)]
enum StatementEditKind {
    Reverse(ErgoStatementFieldV1),
    ToggleFirst(ErgoStatementFieldV1),
}

fn statement_edit_kind(index: usize) -> Result<StatementEditKind> {
    Ok(match index {
        0 => StatementEditKind::Reverse(ErgoStatementFieldV1::ChainDomainId),
        1 => StatementEditKind::ToggleFirst(ErgoStatementFieldV1::ProfileId),
        2 => StatementEditKind::ToggleFirst(ErgoStatementFieldV1::ProgramId),
        3 => StatementEditKind::Reverse(ErgoStatementFieldV1::ContractId),
        4 => StatementEditKind::ToggleFirst(ErgoStatementFieldV1::ApplicationPayload),
        5 => StatementEditKind::Reverse(ErgoStatementFieldV1::ProfileId),
        6 => StatementEditKind::Reverse(ErgoStatementFieldV1::ProgramId),
        _ => bail!("raw statement execution index is outside its closed row set"),
    })
}

fn statement_selector(index: usize) -> Result<&'static str> {
    match index {
        0..=4 => Ok(REFERENCE_STATEMENT_SELECTOR),
        5..=6 => Ok(LIFT_SELECTOR),
        _ => bail!("raw statement execution index is outside its closed row set"),
    }
}

fn derive_statement_edit(
    index: usize,
    statement: ErgoStatementV1<'_>,
    statement_bytes: &[u8],
) -> Result<B4ByteOperation> {
    ensure!(
        statement.encode()?.as_slice() == statement_bytes,
        "raw statement source does not re-encode exactly"
    );
    let layout = statement.layout()?;
    let edit = match statement_edit_kind(index)? {
        StatementEditKind::Reverse(field) => {
            let span = layout.span(field);
            let before = span.bytes(statement_bytes)?;
            let replacement = before.iter().rev().copied().collect::<Vec<_>>();
            ensure!(
                replacement != before,
                "raw statement byte-order field is palindromic"
            );
            B4ByteOperation::Replace {
                before_hex: hex::encode(before),
                replacement_hex: hex::encode(replacement),
                offset: u64::try_from(span.start())?,
            }
        }
        StatementEditKind::ToggleFirst(field) => {
            let span = layout.span(field);
            let before = *span
                .bytes(statement_bytes)?
                .first()
                .context("raw statement selected field is empty")?;
            B4ByteOperation::Replace {
                before_hex: format!("{before:02x}"),
                replacement_hex: format!("{:02x}", before ^ 1),
                offset: u64::try_from(span.start())?,
            }
        }
    };
    Ok(edit)
}

fn statement_materialization(
    index: usize,
    sources: &RawSources<'_>,
) -> Result<B4NegativeMaterialization> {
    Ok(B4NegativeMaterialization::Mutation {
        mutation: B4NegativeMutation::ByteEdit {
            target: B4ByteTarget::Statement,
            edit: derive_statement_edit(index, sources.statement, sources.statement_bytes)?,
        },
    })
}

fn chunk_move_materialization(sources: &RawSources<'_>) -> Result<B4NegativeMaterialization> {
    let subject = Eip0045B4SequenceSubjectV1::from_canonical_jcs(&sources.proof_subject)
        .context("raw chunk-move base is not a canonical detached sequence")?;
    ensure!(
        subject.target == B4SequenceTarget::ProofChunks && subject.elements.len() == 4,
        "raw chunk-move base does not contain exactly four proof chunks"
    );
    for (index, (element, expected_chunk)) in subject
        .elements
        .iter()
        .zip(&sources.proof_chunks)
        .enumerate()
    {
        ensure!(
            element.element_id == format!("chunk-{index:02}")
                && element.decoded_bytes()? == *expected_chunk,
            "raw chunk-move element {index} differs from its authenticated seal projection"
        );
    }
    let moved = subject
        .elements
        .first()
        .context("raw chunk-move base lacks chunk 0")?;
    Ok(B4NegativeMaterialization::Mutation {
        mutation: B4NegativeMutation::SequenceEdit {
            target: B4SequenceTarget::ProofChunks,
            edit: B4SequenceOperation::Move {
                before_element_id: moved.element_id.clone(),
                before_element_sha256: moved.sha256.clone(),
                from_index: 0,
                to_index: 1,
            },
        },
    })
}

#[derive(Clone, Copy, Debug)]
struct ChunkMoveRawReplayAdapterV1<'a> {
    sources: &'a RawSources<'a>,
    expected_materialization: &'a B4NegativeMaterialization,
    output: &'a [u8],
}

impl B4MaterializationReplayAdapterV1 for ChunkMoveRawReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::VerifierInput
    }

    fn base_bytes(&self) -> &[u8] {
        &self.sources.proof_subject
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
            base_selector_id == LIFT_SELECTOR
                && materialization == self.expected_materialization
                && *materialization == chunk_move_materialization(self.sources)?,
            "raw chunk-move replay received a selector or recipe outside row 29"
        );
        let B4NegativeMaterialization::Mutation {
            mutation:
                B4NegativeMutation::SequenceEdit {
                    target: B4SequenceTarget::ProofChunks,
                    edit,
                },
        } = materialization
        else {
            bail!("raw chunk-move replay received a non-proof sequence recipe");
        };
        let replayed = reconstruct_sequence_edit(
            &self.sources.proof_subject,
            B4SequenceTarget::ProofChunks,
            edit,
        )
        .context("raw chunk-move replay cannot reconstruct its sequence edit")?;
        ensure!(
            replayed == self.output,
            "raw chunk-move replay output differs from generic sequence reconstruction"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct ChunkMoveFinalReplayAdapterV1<'a> {
    sources: &'a RawSources<'a>,
    expected_materialization: &'a B4NegativeMaterialization,
    output: &'a [u8],
}

impl B4MaterializationReplayAdapterV1 for ChunkMoveFinalReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::VerifierInput
    }

    fn base_bytes(&self) -> &[u8] {
        &self.sources.proof_subject
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
            base_selector_id == LIFT_SELECTOR
                && materialization == self.expected_materialization
                && *materialization == chunk_move_materialization(self.sources)?,
            "final chunk-move replay received a selector or recipe outside row 29"
        );
        let B4NegativeMaterialization::Mutation {
            mutation:
                B4NegativeMutation::SequenceEdit {
                    target: B4SequenceTarget::ProofChunks,
                    edit:
                        B4SequenceOperation::Move {
                            before_element_id,
                            before_element_sha256,
                            from_index,
                            to_index,
                        },
                },
        } = materialization
        else {
            bail!("final chunk-move replay received a non-move proof recipe");
        };
        let original = Eip0045B4SequenceSubjectV1::from_canonical_jcs(&self.sources.proof_subject)
            .context("final chunk-move base no longer parses independently")?;
        let first = original
            .elements
            .first()
            .context("final chunk-move source lacks chunk 0")?;
        ensure!(
            original.target == B4SequenceTarget::ProofChunks
                && original.elements.len() == 4
                && *from_index == 0
                && *to_index == 1
                && first.element_id == *before_element_id
                && first.sha256 == *before_element_sha256,
            "final chunk-move recipe does not authenticate exact chunk 0 moved to final index 1"
        );
        for (index, (element, expected)) in original
            .elements
            .iter()
            .zip(&self.sources.proof_chunks)
            .enumerate()
        {
            ensure!(
                element.element_id == format!("chunk-{index:02}")
                    && element.decoded_bytes()? == *expected,
                "final chunk-move source element {index} differs from the authenticated chunk"
            );
        }

        let decoded = decode_producer_opcode_subject(self.output)
            .context("final chunk-move opcode subject does not decode independently")?;
        ensure!(
            decoded.application_payload() == self.sources.statement.application_payload()
                && decoded.program_id() == self.sources.program_id
                && decoded.profile_id() == self.sources.profile_id,
            "final chunk-move opcode subject changed an unchanged positional input"
        );
        let expected_order = [1_usize, 0, 2, 3];
        ensure!(
            decoded.proof_chunks().len() == expected_order.len(),
            "final chunk-move opcode subject has the wrong chunk count"
        );
        for (final_index, source_index) in expected_order.into_iter().enumerate() {
            let actual = decoded
                .proof_chunks()
                .get(final_index)
                .context("final chunk-move opcode subject lacks an expected final chunk")?;
            let expected = self
                .sources
                .proof_chunks
                .get(source_index)
                .context("final chunk-move source lacks an expected original chunk")?;
            ensure!(
                *actual == expected.as_slice(),
                "final chunk-move opcode subject differs from exact source order [1,0,2,3]"
            );
        }
        let moved_seal = decoded
            .proof_chunks()
            .iter()
            .flat_map(|chunk| chunk.iter().copied())
            .collect::<Vec<_>>();
        let moved_words = decode_seal_words(&moved_seal)
            .context("final chunk-move concatenation changed the exact proof length")?;
        ensure!(
            moved_words
                .iter()
                .any(|word| *word >= self.sources.semantic_projection.modulus()),
            "final chunk-move concatenation does not reach reduced-word rejection"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct StatementRawReplayAdapterV1<'a> {
    index: usize,
    sources: &'a RawSources<'a>,
    expected_materialization: &'a B4NegativeMaterialization,
    output: &'a [u8],
}

impl B4MaterializationReplayAdapterV1 for StatementRawReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::VerifierInput
    }

    fn base_bytes(&self) -> &[u8] {
        self.sources.statement_bytes
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
            base_selector_id == statement_selector(self.index)?
                && materialization == self.expected_materialization,
            "raw statement replay received a selector or recipe outside its closed row"
        );
        let B4NegativeMaterialization::Mutation {
            mutation:
                B4NegativeMutation::ByteEdit {
                    target: B4ByteTarget::Statement,
                    edit,
                },
        } = materialization
        else {
            bail!("raw statement replay received a non-statement byte recipe");
        };
        let replayed = reconstruct_byte_edit(self.sources.statement_bytes, edit)
            .context("raw statement replay cannot reconstruct its authenticated byte edit")?;
        ensure!(
            replayed == self.output,
            "raw statement replay output differs from generic byte reconstruction"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct StatementFinalReplayAdapterV1<'a> {
    index: usize,
    sources: &'a RawSources<'a>,
    expected_materialization: &'a B4NegativeMaterialization,
    output: &'a [u8],
}

impl B4MaterializationReplayAdapterV1 for StatementFinalReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::VerifierInput
    }

    fn base_bytes(&self) -> &[u8] {
        self.sources.statement_bytes
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
            base_selector_id == statement_selector(self.index)?
                && materialization == self.expected_materialization
                && *materialization == statement_materialization(self.index, self.sources)?,
            "final statement replay received a selector or recipe outside its closed row"
        );
        let B4NegativeMaterialization::Mutation {
            mutation:
                B4NegativeMutation::ByteEdit {
                    target: B4ByteTarget::Statement,
                    edit:
                        B4ByteOperation::Replace {
                            before_hex,
                            replacement_hex,
                            offset,
                        },
                },
        } = materialization
        else {
            bail!("final statement replay received a non-replacement statement recipe");
        };
        let start =
            usize::try_from(*offset).context("final statement replacement offset exceeds usize")?;
        let before =
            hex::decode(before_hex).context("final statement before witness is not valid hex")?;
        let replacement = hex::decode(replacement_hex)
            .context("final statement replacement witness is not valid hex")?;
        ensure!(
            before.len() == replacement.len(),
            "final statement replacement changes field width"
        );
        let end = start
            .checked_add(before.len())
            .context("final statement replacement range overflows")?;
        ensure!(
            self.sources.statement_bytes.get(start..end) == Some(before.as_slice())
                && self.output.get(start..end) == Some(replacement.as_slice())
                && self.output.get(..start) == self.sources.statement_bytes.get(..start)
                && self.output.get(end..) == self.sources.statement_bytes.get(end..),
            "final statement output is not the exact source prefix/replacement/suffix splice"
        );

        let original = parse_ergo_statement_v1(self.sources.statement_bytes)
            .context("final statement base no longer parses")?;
        let mutated = parse_ergo_statement_v1(self.output)
            .context("final statement output does not parse")?;
        ensure!(
            original.encode()?.as_slice() == self.sources.statement_bytes
                && mutated.encode()?.as_slice() == self.output,
            "final statement parse/re-encode is not byte exact"
        );
        let original_layout = original.layout()?;
        let mutated_layout = mutated.layout()?;
        ensure!(
            original_layout == mutated_layout,
            "final statement mutation changed the typed field layout"
        );
        let selected = match statement_edit_kind(self.index)? {
            StatementEditKind::Reverse(field) | StatementEditKind::ToggleFirst(field) => field,
        };
        for field in ErgoStatementFieldV1::ALL {
            let span = original_layout.span(field);
            let original_field = span.bytes(self.sources.statement_bytes)?;
            let mutated_field = span.bytes(self.output)?;
            ensure!(
                (field == selected && original_field != mutated_field)
                    || (field != selected && original_field == mutated_field),
                "final statement mutation changed the wrong typed field"
            );
        }
        let length_span = original_layout.span(ErgoStatementFieldV1::PayloadLength);
        ensure!(
            length_span.bytes(self.sources.statement_bytes)? == length_span.bytes(self.output)?,
            "final statement mutation changed the payload-length prefix"
        );
        Ok(())
    }
}

/// Reconstruct one exact raw-producer execution.
pub(crate) fn reconstruct_raw_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    if expected_execution_id(execution_index).is_none() {
        return Ok(None);
    }
    let sources = RawSources::authenticate_v1(top_level)?;
    reconstruct_raw_execution_core(execution_index, planned, &top_level.negative_plan, &sources)
        .map(Some)
}

/// Reconstruct one exact raw-producer execution from V2-authenticated sources.
pub(crate) fn reconstruct_raw_execution_v2(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV2,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    if expected_execution_id(execution_index).is_none() {
        return Ok(None);
    }
    let (sources, negative_plan_jcs) = RawSources::authenticate_v2(top_level)?;
    reconstruct_raw_execution_core(execution_index, planned, negative_plan_jcs, &sources).map(Some)
}

fn reconstruct_raw_execution_core(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    sources: &RawSources<'_>,
) -> Result<B4ClosedReconstructedExecutionV1> {
    validate_planned_row(execution_index, planned, negative_plan_jcs)?;
    match execution_index {
        0..=6 => {
            reconstruct_statement_execution(execution_index, planned, negative_plan_jcs, sources)
        }
        29 => {
            reconstruct_chunk_move_execution(execution_index, planned, negative_plan_jcs, sources)
        }
        33..=71 | 109 => {
            reconstruct_seal_execution(execution_index, planned, negative_plan_jcs, sources)
        }
        _ => bail!("raw producer admitted an index without a closed reconstruction"),
    }
}

fn reconstruct_seal_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    sources: &RawSources<'_>,
) -> Result<B4ClosedReconstructedExecutionV1> {
    let materialization = seal_materialization(execution_index, sources)?;
    let B4NegativeMaterialization::Mutation {
        mutation:
            B4NegativeMutation::ByteEdit {
                target: B4ByteTarget::RawSeal,
                edit,
            },
    } = &materialization
    else {
        bail!("raw seal producer constructed a non-seal materialization");
    };
    let raw_output = reconstruct_byte_edit(sources.raw_seal, edit)?;
    let independent_mutated_seal = independent_replace_splice(sources.raw_seal, edit)?;
    let chunks = split_raw_seal(&independent_mutated_seal)
        .context("raw seal producer cannot split its independently spliced proof")?;
    let subject = encode_opcode_subject(
        &chunks,
        sources.statement.application_payload(),
        &sources.program_id,
        &sources.profile_id,
    )
    .context("raw seal producer cannot encode exact opcode inputs")?;
    let registry_row = B4NegativeCase {
        execution_id: planned.execution_id.clone(),
        base_selector_id: LIFT_SELECTOR.to_owned(),
        materialization_domain: B4MaterializationDomain::VerifierInput,
        materialization,
    };
    let expected_materialization = registry_row.materialization.clone();
    let raw_adapter = SealRawReplayAdapterV1 {
        index: execution_index,
        sources,
        expected_materialization: &expected_materialization,
        output: &raw_output,
    };
    let final_adapter = SealFinalReplayAdapterV1 {
        index: execution_index,
        sources,
        expected_materialization: &expected_materialization,
        output: &subject,
    };
    close_production_execution(
        execution_index,
        planned,
        negative_plan_jcs,
        registry_row,
        &raw_adapter,
        &final_adapter,
        subject.clone(),
        vec![sources.manifest.to_vec()],
    )
}

fn reconstruct_chunk_move_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    sources: &RawSources<'_>,
) -> Result<B4ClosedReconstructedExecutionV1> {
    let materialization = chunk_move_materialization(sources)?;
    let B4NegativeMaterialization::Mutation {
        mutation:
            B4NegativeMutation::SequenceEdit {
                target: B4SequenceTarget::ProofChunks,
                edit,
            },
    } = &materialization
    else {
        bail!("raw chunk-move producer constructed a non-sequence materialization");
    };
    let raw_output =
        reconstruct_sequence_edit(&sources.proof_subject, B4SequenceTarget::ProofChunks, edit)?;
    let reordered_chunks = [1_usize, 0, 2, 3]
        .into_iter()
        .map(|index| {
            sources
                .proof_chunks
                .get(index)
                .cloned()
                .context("raw chunk-move source lacks an exact canonical chunk")
        })
        .collect::<Result<Vec<_>>>()?;
    let subject = encode_opcode_subject(
        &reordered_chunks,
        sources.statement.application_payload(),
        &sources.program_id,
        &sources.profile_id,
    )
    .context("raw chunk-move producer cannot encode exact opcode inputs")?;
    let registry_row = B4NegativeCase {
        execution_id: planned.execution_id.clone(),
        base_selector_id: LIFT_SELECTOR.to_owned(),
        materialization_domain: B4MaterializationDomain::VerifierInput,
        materialization,
    };
    let expected_materialization = registry_row.materialization.clone();
    let raw_adapter = ChunkMoveRawReplayAdapterV1 {
        sources,
        expected_materialization: &expected_materialization,
        output: &raw_output,
    };
    let final_adapter = ChunkMoveFinalReplayAdapterV1 {
        sources,
        expected_materialization: &expected_materialization,
        output: &subject,
    };
    close_production_execution(
        execution_index,
        planned,
        negative_plan_jcs,
        registry_row,
        &raw_adapter,
        &final_adapter,
        subject.clone(),
        vec![sources.manifest.to_vec()],
    )
}

fn reconstruct_statement_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    sources: &RawSources<'_>,
) -> Result<B4ClosedReconstructedExecutionV1> {
    let materialization = statement_materialization(execution_index, sources)?;
    let B4NegativeMaterialization::Mutation {
        mutation: B4NegativeMutation::ByteEdit { edit, .. },
    } = &materialization
    else {
        bail!("raw statement producer constructed a non-byte materialization");
    };
    let subject = reconstruct_byte_edit(sources.statement_bytes, edit)?;
    let registry_row = B4NegativeCase {
        execution_id: planned.execution_id.clone(),
        base_selector_id: statement_selector(execution_index)?.to_owned(),
        materialization_domain: B4MaterializationDomain::VerifierInput,
        materialization,
    };
    let expected_materialization = registry_row.materialization.clone();
    let raw_adapter = StatementRawReplayAdapterV1 {
        index: execution_index,
        sources,
        expected_materialization: &expected_materialization,
        output: &subject,
    };
    let final_adapter = StatementFinalReplayAdapterV1 {
        index: execution_index,
        sources,
        expected_materialization: &expected_materialization,
        output: &subject,
    };
    close_production_execution(
        execution_index,
        planned,
        negative_plan_jcs,
        registry_row,
        &raw_adapter,
        &final_adapter,
        subject.clone(),
        vec![sources.manifest.to_vec(), sources.raw_seal.to_vec()],
    )
}

fn validate_planned_row(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
) -> Result<()> {
    let canonical_plan = Eip0045B4NegativePlanV1::from_canonical_jcs(negative_plan_jcs)
        .context("raw producer negative plan is not canonical")?;
    let canonical_row = canonical_plan
        .groups
        .iter()
        .flat_map(|group| group.executions.iter())
        .nth(execution_index)
        .context("raw producer index is outside the canonical plan")?;
    ensure!(
        canonical_row == planned
            && expected_execution_id(execution_index) == Some(planned.execution_id.as_str())
            && planned.materialization_domain == B4MaterializationDomain::VerifierInput
            && planned.parser_truncation_words.is_none(),
        "raw execution differs from its canonical-plan identity"
    );
    match execution_index {
        0..=4 => ensure!(
            planned.base_selector_id == REFERENCE_STATEMENT_SELECTOR
                && planned.fixture == B4NegativePlanFixture::LiftPo215ReferenceStatementV1
                && planned.execution_surface
                    == B4NegativeExecutionSurface::RawStatementClaimBinding
                && planned.qa_result_code == B4NegativeQaResultCode::RawSealClaimMismatch,
            "raw statement execution differs from its reference-statement row contract"
        ),
        5..=6 => ensure!(
            planned.base_selector_id == LIFT_SELECTOR
                && planned.fixture == B4NegativePlanFixture::LiftPo215
                && planned.execution_surface
                    == B4NegativeExecutionSurface::RawStatementClaimBinding
                && planned.qa_result_code == B4NegativeQaResultCode::RawSealClaimMismatch,
            "raw statement execution differs from its lift statement row contract"
        ),
        29 => ensure!(
            planned.base_selector_id == LIFT_SELECTOR
                && planned.fixture == B4NegativePlanFixture::LiftPo215
                && planned.execution_surface == B4NegativeExecutionSurface::RawSealShape
                && planned.qa_result_code == B4NegativeQaResultCode::RawSealWordNotReduced,
            "raw chunk-move execution differs from its exact row contract"
        ),
        33..=40 => ensure!(
            planned.base_selector_id == LIFT_SELECTOR
                && planned.fixture == B4NegativePlanFixture::LiftPo215
                && planned.execution_surface == B4NegativeExecutionSurface::RawSealShape
                && planned.qa_result_code == B4NegativeQaResultCode::RawSealNonzeroRootPadding,
            "raw root-padding execution differs from its exact row contract"
        ),
        41..=56 => ensure!(
            planned.base_selector_id == LIFT_SELECTOR
                && planned.fixture == B4NegativePlanFixture::LiftPo215
                && planned.execution_surface == B4NegativeExecutionSurface::RawSealShape
                && planned.qa_result_code == B4NegativeQaResultCode::RawSealClaimHalfwordOutOfRange,
            "raw claim-halfword execution differs from its exact row contract"
        ),
        57..=63 => ensure!(
            planned.base_selector_id == LIFT_SELECTOR
                && planned.fixture == B4NegativePlanFixture::LiftPo215
                && planned.execution_surface == B4NegativeExecutionSurface::RawSealShape
                && planned.qa_result_code == B4NegativeQaResultCode::RawSealWordNotReduced,
            "raw modulus execution differs from its exact row contract"
        ),
        64..=70 => ensure!(
            planned.base_selector_id == LIFT_SELECTOR
                && planned.fixture == B4NegativePlanFixture::LiftPo215
                && planned.execution_surface == B4NegativeExecutionSurface::RawSealShape
                && planned.qa_result_code
                    == B4NegativeQaResultCode::B4ByteOrderRejectedAtBoundCheckpoint,
            "raw byte-order execution differs from its exact row contract"
        ),
        71 | 109 => ensure!(
            planned.base_selector_id == LIFT_SELECTOR
                && planned.fixture == B4NegativePlanFixture::LiftPo215
                && planned.execution_surface == B4NegativeExecutionSurface::RawSealShape
                && planned.qa_result_code == B4NegativeQaResultCode::RawSealWrongOuterPo2,
            "raw outer-po2 execution differs from its exact row contract"
        ),
        _ => {}
    }
    Ok(())
}

/// Local test seam for externally authenticated bytes, not cryptographic or
/// campaign authority. It does not fabricate a V1 or V2 authenticated top level.
#[cfg(all(test, feature = "validator"))]
pub(crate) fn reconstruct_raw_shape_for_test(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    raw_seal: &[u8],
    statement_bytes: &[u8],
) -> Result<B4ClosedReconstructedExecutionV1> {
    ensure!(
        matches!(execution_index, 29 | 33..=71 | 109),
        "local raw-shape test seam requires a closed proof-order or raw-seal row"
    );
    let manifest_bytes = include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin");
    let constants_bytes = include_bytes!("../../profiles/risc0-v3-succinct/constants.bin");
    let manifest = crate::profile_manifest::StarkProfileManifestV1::decode(manifest_bytes)
        .context("local raw-shape test manifest does not decode")?;
    manifest
        .validate_initial_profile_target()
        .context("local raw-shape test manifest differs from the initial profile target")?;
    let statement = parse_ergo_statement_v1(statement_bytes)
        .context("local raw-shape test statement does not parse")?;
    let profile_id = statement.profile_id();
    let program_id = statement.program_id();
    let sources = RawSources::from_authenticated_parts(
        0,
        LIFT_CASE_ID,
        manifest_bytes,
        manifest.outer_po2(),
        constants_bytes,
        raw_seal,
        statement_bytes,
        statement,
        profile_id,
        program_id,
    )?;
    reconstruct_raw_execution_core(execution_index, planned, negative_plan_jcs, &sources)
}

/// Local statement-claim test seam for externally authenticated bytes. This
/// creates no cryptographic/campaign authority and fabricates no V1/V2 top level.
#[cfg(all(test, feature = "validator"))]
pub(crate) fn reconstruct_statement_claim_for_test(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    raw_seal: &[u8],
    statement_bytes: &[u8],
) -> Result<B4ClosedReconstructedExecutionV1> {
    ensure!(
        matches!(execution_index, 0..=6),
        "local statement-claim test seam requires a closed statement row"
    );
    let manifest_bytes = include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin");
    let constants_bytes = include_bytes!("../../profiles/risc0-v3-succinct/constants.bin");
    let manifest = crate::profile_manifest::StarkProfileManifestV1::decode(manifest_bytes)
        .context("local statement-claim test manifest does not decode")?;
    manifest
        .validate_initial_profile_target()
        .context("local statement-claim test manifest differs from the initial profile target")?;
    let statement = parse_ergo_statement_v1(statement_bytes)
        .context("local statement-claim test statement does not parse")?;
    let profile_id = statement.profile_id();
    let program_id = statement.program_id();
    let sources = RawSources::from_authenticated_parts(
        0,
        LIFT_CASE_ID,
        manifest_bytes,
        manifest.outer_po2(),
        constants_bytes,
        raw_seal,
        statement_bytes,
        statement,
        profile_id,
        program_id,
    )?;
    reconstruct_raw_execution_core(execution_index, planned, negative_plan_jcs, &sources)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        b4::{
            B4ByteOperation, B4NegativeMaterialization, B4NegativeMutation, B4PositiveArtifactRole,
        },
        b4_materialization_set::{
            authority_tdd_tests::production_shaped_fixture_top_level, positive_artifact_layout,
        },
        b4_plan::{
            B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanFixture,
            B4NegativeQaResultCode, Eip0045B4NegativePlanV1,
        },
        canonical::canonical_json_bytes,
        manifest::ManifestEntry,
    };
    use sha2::{Digest as _, Sha256};

    fn flattened_plan() -> Vec<B4NegativePlanExecutionV1> {
        Eip0045B4NegativePlanV1::canonical()
            .unwrap()
            .groups
            .into_iter()
            .flat_map(|group| group.executions)
            .collect()
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn rebind_case_zero_raw_seal(
        top_level: &mut B4AuthenticatedMaterializationTopLevelV1,
        raw_seal: Vec<u8>,
    ) {
        let raw_basename = positive_artifact_layout(0)
            .unwrap()
            .iter()
            .find_map(|(role, basename)| {
                (*role == B4PositiveArtifactRole::RawSeal).then_some(*basename)
            })
            .unwrap();
        let digest = sha256_hex(&raw_seal);
        let byte_length = u64::try_from(raw_seal.len()).unwrap();
        let raw_artifact = top_level.expanded_registry.positive_cases[0]
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.role == B4PositiveArtifactRole::RawSeal)
            .unwrap();
        raw_artifact.byte_length = byte_length;
        raw_artifact.sha256.clone_from(&digest);
        top_level.positive_exports[0].raw_seal = raw_seal;
        let mut manifest: Vec<ManifestEntry> =
            serde_json::from_slice(&top_level.positive_exports[0].proof_output_manifest_jcs)
                .unwrap();
        let entry = manifest
            .iter_mut()
            .find(|entry| entry.path == raw_basename)
            .unwrap();
        entry.length = byte_length.to_string();
        entry.sha256 = digest;
        top_level.positive_exports[0].proof_output_manifest_jcs =
            canonical_json_bytes(&serde_json::to_value(manifest).unwrap()).unwrap();
    }

    #[test]
    fn exact_literal_table_names_all_and_only_the_forty_eight_raw_rows() {
        let plan = flattened_plan();
        assert_eq!(RAW_EXECUTION_IDS.len(), 48);
        let expected_indices = (0..=6)
            .chain([29])
            .chain(33..=71)
            .chain([109])
            .collect::<Vec<_>>();
        assert_eq!(
            RAW_EXECUTION_IDS
                .iter()
                .map(|(index, _)| *index)
                .collect::<Vec<_>>(),
            expected_indices
        );
        for &(index, execution_id) in &RAW_EXECUTION_IDS {
            assert_eq!(plan[index].execution_id, execution_id);
            assert_eq!(expected_execution_id(index), Some(execution_id));
        }
        for index in 0..=254 {
            assert_eq!(
                expected_execution_id(index).is_some(),
                expected_indices.contains(&index),
                "raw row membership drift at index {index}"
            );
        }
    }

    #[test]
    fn reconstructs_all_seven_statement_rows_with_exact_one_field_recipes() {
        let top_level = production_shaped_fixture_top_level();
        let plan = flattened_plan();
        let statement = RawSources::authenticate_v1(&top_level).unwrap();
        let expected_offsets = [27_u64, 59, 91, 123, 159, 59, 91];
        let expected_widths = [32_usize, 1, 1, 32, 1, 32, 32];

        for index in 0..=6 {
            let reconstructed = reconstruct_raw_execution(index, &plan[index], &top_level)
                .unwrap()
                .unwrap();
            assert_eq!(reconstructed.base, statement.statement_bytes);
            assert_eq!(
                reconstructed.contexts,
                vec![statement.manifest.to_vec(), statement.raw_seal.to_vec()]
            );
            let B4NegativeMaterialization::Mutation {
                mutation:
                    B4NegativeMutation::ByteEdit {
                        target: B4ByteTarget::Statement,
                        edit:
                            B4ByteOperation::Replace {
                                before_hex,
                                replacement_hex,
                                offset,
                            },
                    },
            } = &reconstructed.derived_registry_row.materialization
            else {
                panic!("statement row {index} has the wrong recipe")
            };
            assert_eq!(*offset, expected_offsets[index]);
            assert_eq!(before_hex.len(), expected_widths[index] * 2);
            assert_eq!(replacement_hex.len(), expected_widths[index] * 2);
            assert_ne!(before_hex, replacement_hex);
            let before = hex::decode(before_hex).unwrap();
            let replacement = hex::decode(replacement_hex).unwrap();
            if matches!(index, 0 | 3 | 5 | 6) {
                assert_eq!(
                    replacement,
                    before.iter().rev().copied().collect::<Vec<_>>()
                );
            } else {
                assert_eq!(replacement, vec![before[0] ^ 1]);
            }
            assert_eq!(
                parse_ergo_statement_v1(&reconstructed.subject)
                    .unwrap()
                    .encode()
                    .unwrap(),
                reconstructed.subject
            );
        }
    }

    #[test]
    fn row_29_moves_authenticated_chunk_zero_to_final_index_one_and_frames_it_independently() {
        let top_level = production_shaped_fixture_top_level();
        let plan = flattened_plan();
        let sources = RawSources::authenticate_v1(&top_level).unwrap();
        let reconstructed = reconstruct_raw_execution(29, &plan[29], &top_level)
            .unwrap()
            .unwrap();
        assert_eq!(reconstructed.base, sources.proof_subject);
        assert_eq!(reconstructed.contexts, vec![sources.manifest.to_vec()]);
        let detached =
            Eip0045B4SequenceSubjectV1::from_canonical_jcs(&sources.proof_subject).unwrap();
        let B4NegativeMaterialization::Mutation {
            mutation:
                B4NegativeMutation::SequenceEdit {
                    target: B4SequenceTarget::ProofChunks,
                    edit:
                        B4SequenceOperation::Move {
                            before_element_id,
                            before_element_sha256,
                            from_index,
                            to_index,
                        },
                },
        } = &reconstructed.derived_registry_row.materialization
        else {
            panic!("row 29 has the wrong recipe")
        };
        assert_eq!(before_element_id, "chunk-00");
        assert_eq!(before_element_sha256, &detached.elements[0].sha256);
        assert_eq!((*from_index, *to_index), (0, 1));
        let raw_output = reconstruct_sequence_edit(
            &sources.proof_subject,
            B4SequenceTarget::ProofChunks,
            match &reconstructed.derived_registry_row.materialization {
                B4NegativeMaterialization::Mutation {
                    mutation:
                        B4NegativeMutation::SequenceEdit {
                            target: B4SequenceTarget::ProofChunks,
                            edit,
                        },
                } => edit,
                _ => panic!("row 29 lost its exact proof-sequence recipe"),
            },
        )
        .unwrap();
        let moved_subject = Eip0045B4SequenceSubjectV1::from_canonical_jcs(&raw_output).unwrap();
        assert_eq!(
            moved_subject
                .elements
                .iter()
                .map(|element| element.element_id.as_str())
                .collect::<Vec<_>>(),
            ["chunk-01", "chunk-00", "chunk-02", "chunk-03"]
        );
        for (element, source_index) in moved_subject.elements.iter().zip([1_usize, 0, 2, 3]) {
            assert_eq!(
                element.decoded_bytes().unwrap(),
                sources.proof_chunks[source_index]
            );
            assert_eq!(
                element.sha256,
                sha256_hex(&sources.proof_chunks[source_index])
            );
        }

        let decoded = decode_producer_opcode_subject(&reconstructed.subject).unwrap();
        let expected_order = [1_usize, 0, 2, 3];
        assert_eq!(decoded.proof_chunks().len(), 4);
        for (actual, source_index) in decoded.proof_chunks().iter().zip(expected_order) {
            assert_eq!(*actual, sources.proof_chunks[source_index]);
        }
        assert_eq!(
            decoded.application_payload(),
            sources.statement.application_payload()
        );
        assert_eq!(decoded.program_id(), sources.program_id);
        assert_eq!(decoded.profile_id(), sources.profile_id);
        let moved = decoded
            .proof_chunks()
            .iter()
            .flat_map(|chunk| chunk.iter().copied())
            .collect::<Vec<_>>();
        let words = decode_seal_words(&moved).unwrap();
        assert_eq!(words[0], sources.semantic_projection.modulus());
        assert!(
            sources
                .raw_seal_words
                .iter()
                .all(|word| *word < sources.semantic_projection.modulus())
        );
    }

    #[test]
    fn reconstructs_all_forty_seal_rows_with_exact_word_recipes_and_opcode_projection() {
        let top_level = production_shaped_fixture_top_level();
        let plan = flattened_plan();
        let sources = RawSources::authenticate_v1(&top_level).unwrap();
        let fixed_words = [0_usize, 16, 33, 1_057, 4_461, 4_717, 4_729];
        let indices = (33..=71).chain([109]).collect::<Vec<_>>();

        for index in indices {
            let reconstructed = reconstruct_raw_execution(index, &plan[index], &top_level)
                .unwrap()
                .unwrap();
            assert_eq!(reconstructed.base, sources.raw_seal);
            assert_eq!(reconstructed.contexts, vec![sources.manifest.to_vec()]);
            let B4NegativeMaterialization::Mutation {
                mutation:
                    B4NegativeMutation::ByteEdit {
                        target: B4ByteTarget::RawSeal,
                        edit:
                            B4ByteOperation::Replace {
                                before_hex,
                                replacement_hex,
                                offset,
                            },
                    },
            } = &reconstructed.derived_registry_row.materialization
            else {
                panic!("seal row {index} has the wrong recipe")
            };
            let expected_word = match index {
                33..=40 => 1 + (index - 33) * 2,
                41..=56 => 16 + (index - 41),
                57..=63 => fixed_words[index - 57],
                64..=70 => fixed_words[index - 64],
                71 | 109 => 32,
                _ => unreachable!("test iterates only exact seal rows"),
            };
            assert_eq!(*offset, u64::try_from(expected_word * WORD_BYTES).unwrap());
            assert_eq!(
                before_hex,
                &hex::encode(sources.raw_seal_words[expected_word].to_le_bytes())
            );
            assert_eq!(before_hex.len(), 8);
            assert_eq!(replacement_hex.len(), 8);
            assert_ne!(before_hex, replacement_hex);
            match index {
                33..=40 => assert_eq!(replacement_hex, "01000000"),
                41..=56 => assert_eq!(replacement_hex, "deddfd0f"),
                57..=63 => assert_eq!(replacement_hex, "01000078"),
                64..=70 => {
                    let mut reversed = hex::decode(before_hex).unwrap();
                    reversed.reverse();
                    assert_eq!(replacement_hex, &hex::encode(reversed));
                }
                71 => assert_eq!(replacement_hex, "daffff2f"),
                109 => assert_eq!(replacement_hex, "13000000"),
                _ => unreachable!("test iterates only exact seal rows"),
            }

            let decoded = decode_producer_opcode_subject(&reconstructed.subject).unwrap();
            assert_eq!(decoded.proof_chunks().len(), 4);
            assert_eq!(
                decoded.application_payload(),
                sources.statement.application_payload()
            );
            assert_eq!(decoded.program_id(), sources.program_id);
            assert_eq!(decoded.profile_id(), sources.profile_id);
            let mutated = decoded
                .proof_chunks()
                .iter()
                .flat_map(|chunk| chunk.iter().copied())
                .collect::<Vec<_>>();
            let start = expected_word * WORD_BYTES;
            assert_eq!(&mutated[..start], &sources.raw_seal[..start]);
            assert_eq!(
                &mutated[start..start + WORD_BYTES],
                hex::decode(replacement_hex).unwrap()
            );
            assert_eq!(
                &mutated[start + WORD_BYTES..],
                &sources.raw_seal[start + WORD_BYTES..]
            );
            validate_seal_rejection_projection(index, &sources, &mutated).unwrap();
        }
    }

    #[test]
    fn raw_producer_returns_none_outside_exact_rows_and_rejects_every_plan_field_drift() {
        let top_level = production_shaped_fixture_top_level();
        let plan = flattened_plan();
        for index in 0..=254 {
            if expected_execution_id(index).is_none() {
                assert!(
                    reconstruct_raw_execution(index, &plan[index.min(253)], &top_level)
                        .unwrap()
                        .is_none(),
                    "raw producer admitted outside index {index}"
                );
            }
        }

        for index in [0_usize, 29, 33, 41, 57, 64, 71, 109] {
            let source = &plan[index];
            let mut drifts = Vec::new();
            let mut execution_id = source.clone();
            execution_id.execution_id.push('x');
            drifts.push(execution_id);
            let mut selector = source.clone();
            selector.base_selector_id = "wrong-selector".to_owned();
            drifts.push(selector);
            let mut fixture = source.clone();
            fixture.fixture = B4NegativePlanFixture::TerminalJoin;
            drifts.push(fixture);
            let mut domain = source.clone();
            domain.materialization_domain = B4MaterializationDomain::ArtifactValidator;
            drifts.push(domain);
            let mut surface = source.clone();
            surface.execution_surface = B4NegativeExecutionSurface::OpcodePreflight;
            drifts.push(surface);
            let mut qa = source.clone();
            qa.qa_result_code = B4NegativeQaResultCode::OpcodeProfileIdLengthInvalid;
            drifts.push(qa);
            for drift in drifts {
                assert!(
                    reconstruct_raw_execution(index, &drift, &top_level).is_err(),
                    "raw producer accepted plan drift at index {index}"
                );
            }
        }
        assert!(reconstruct_raw_execution(0, &plan[1], &top_level).is_err());
        let mut wrong_plan = top_level.clone();
        let last = wrong_plan.negative_plan.len() - 1;
        wrong_plan.negative_plan[last] ^= 1;
        assert!(reconstruct_raw_execution(0, &plan[0], &wrong_plan).is_err());
    }

    #[test]
    fn statement_recipes_fail_closed_on_empty_payload_and_palindromic_reversals() {
        let profile_id = [0x22; 32];
        let program_id = [0x33; 32];
        let empty =
            ErgoStatementV1::new([0x11; 32], profile_id, program_id, [0x44; 32], b"").unwrap();
        let empty_bytes = empty.encode().unwrap();
        assert!(derive_statement_edit(4, empty, &empty_bytes).is_err());

        let palindromic =
            ErgoStatementV1::new([0x11; 32], profile_id, program_id, [0x44; 32], b"x").unwrap();
        let bytes = palindromic.encode().unwrap();
        for index in [0, 3, 5, 6] {
            assert!(
                derive_statement_edit(index, palindromic, &bytes).is_err(),
                "accepted palindromic reversal row {index}"
            );
        }
    }

    #[test]
    fn authenticated_raw_sources_reject_length_cross_case_b2_and_structural_drift() {
        let honest = production_shaped_fixture_top_level();

        let mut wrong_length = honest.clone();
        wrong_length.positive_exports[0].raw_seal.pop();
        assert!(RawSources::authenticate_v1(&wrong_length).is_err());

        let mut cross_case = honest.clone();
        cross_case.positive_exports.swap(0, 1);
        assert!(RawSources::authenticate_v1(&cross_case).is_err());

        let mut b2_drift = honest.clone();
        b2_drift
            .source_artifacts
            .get_mut("profiles/risc0-v3-succinct/constants.bin")
            .unwrap()[0] ^= 1;
        assert!(RawSources::authenticate_v1(&b2_drift).is_err());

        let modulus = RawSources::authenticate_v1(&honest)
            .unwrap()
            .semantic_projection
            .modulus();
        let mut variants = Vec::new();

        let mut non_reduced = honest.positive_exports[0].raw_seal.clone();
        non_reduced[800..804].copy_from_slice(&modulus.to_le_bytes());
        variants.push(non_reduced);

        let mut nonzero_padding = honest.positive_exports[0].raw_seal.clone();
        nonzero_padding[4..8].copy_from_slice(&1_u32.to_le_bytes());
        variants.push(nonzero_padding);

        let mut invalid_claim = honest.positive_exports[0].raw_seal.clone();
        invalid_claim[16 * WORD_BYTES..17 * WORD_BYTES]
            .copy_from_slice(&montgomery_encode(65_536, modulus).unwrap().to_le_bytes());
        variants.push(invalid_claim);

        let mut wrong_po2 = honest.positive_exports[0].raw_seal.clone();
        wrong_po2[32 * WORD_BYTES..33 * WORD_BYTES].copy_from_slice(&19_u32.to_le_bytes());
        variants.push(wrong_po2);

        for raw_seal in variants {
            let mut drifted = honest.clone();
            rebind_case_zero_raw_seal(&mut drifted, raw_seal);
            assert!(RawSources::authenticate_v1(&drifted).is_err());
        }
    }

    #[test]
    fn byte_order_recipe_is_data_derived_for_first_later_and_absent_role_candidates() {
        const CANDIDATE: u32 = 0x0100_0078;
        let honest = production_shaped_fixture_top_level();

        let first = RawSources::authenticate_v1(&honest).unwrap();
        let B4ByteOperation::Replace { offset, .. } = seal_edit(64, &first).unwrap() else {
            panic!("byte-order recipe is not replace")
        };
        assert_eq!(offset, 0);

        let mut later_top = honest.clone();
        let mut later = later_top.positive_exports[0].raw_seal.clone();
        later[..4].copy_from_slice(&0_u32.to_le_bytes());
        later[8..12].copy_from_slice(&CANDIDATE.to_le_bytes());
        rebind_case_zero_raw_seal(&mut later_top, later);
        let later_sources = RawSources::authenticate_v1(&later_top).unwrap();
        let B4ByteOperation::Replace { offset, .. } = seal_edit(64, &later_sources).unwrap() else {
            panic!("later byte-order recipe is not replace")
        };
        assert_eq!(offset, 8);

        let mut absent_top = honest;
        let mut absent = absent_top.positive_exports[0].raw_seal.clone();
        for word_index in (0..16).step_by(2) {
            absent[word_index * WORD_BYTES..(word_index + 1) * WORD_BYTES]
                .copy_from_slice(&0_u32.to_le_bytes());
        }
        rebind_case_zero_raw_seal(&mut absent_top, absent);
        let absent_sources = RawSources::authenticate_v1(&absent_top).unwrap();
        assert!(seal_edit(64, &absent_sources).is_err());
    }

    #[test]
    fn raw_and_final_adapters_reject_forged_outputs_independently() {
        let top_level = production_shaped_fixture_top_level();
        let sources = RawSources::authenticate_v1(&top_level).unwrap();

        let statement_materialization = statement_materialization(0, &sources).unwrap();
        let mut forged_statement_raw = sources.statement_bytes.to_vec();
        forged_statement_raw[27] ^= 1;
        let statement_raw = StatementRawReplayAdapterV1 {
            index: 0,
            sources: &sources,
            expected_materialization: &statement_materialization,
            output: &forged_statement_raw,
        };
        assert!(
            statement_raw
                .replay_recipe(REFERENCE_STATEMENT_SELECTOR, &statement_materialization)
                .is_err()
        );
        let B4NegativeMaterialization::Mutation {
            mutation: B4NegativeMutation::ByteEdit { edit, .. },
        } = &statement_materialization
        else {
            panic!("statement materialization is not byte edit")
        };
        let mut forged_statement_final =
            reconstruct_byte_edit(sources.statement_bytes, edit).unwrap();
        forged_statement_final[123] ^= 1;
        let statement_final = StatementFinalReplayAdapterV1 {
            index: 0,
            sources: &sources,
            expected_materialization: &statement_materialization,
            output: &forged_statement_final,
        };
        assert!(
            statement_final
                .replay_recipe(REFERENCE_STATEMENT_SELECTOR, &statement_materialization)
                .is_err()
        );

        let move_materialization = chunk_move_materialization(&sources).unwrap();
        let chunk_raw = ChunkMoveRawReplayAdapterV1 {
            sources: &sources,
            expected_materialization: &move_materialization,
            output: &sources.proof_subject,
        };
        assert!(
            chunk_raw
                .replay_recipe(LIFT_SELECTOR, &move_materialization)
                .is_err()
        );
        let original_opcode = encode_opcode_subject(
            &sources.proof_chunks,
            sources.statement.application_payload(),
            &sources.program_id,
            &sources.profile_id,
        )
        .unwrap();
        let chunk_final = ChunkMoveFinalReplayAdapterV1 {
            sources: &sources,
            expected_materialization: &move_materialization,
            output: &original_opcode,
        };
        assert!(
            chunk_final
                .replay_recipe(LIFT_SELECTOR, &move_materialization)
                .is_err()
        );

        let seal_materialization = seal_materialization(33, &sources).unwrap();
        let seal_raw = SealRawReplayAdapterV1 {
            index: 33,
            sources: &sources,
            expected_materialization: &seal_materialization,
            output: sources.raw_seal,
        };
        assert!(
            seal_raw
                .replay_recipe(LIFT_SELECTOR, &seal_materialization)
                .is_err()
        );
        let original_opcode = encode_opcode_subject(
            &sources.proof_chunks,
            sources.statement.application_payload(),
            &sources.program_id,
            &sources.profile_id,
        )
        .unwrap();
        let seal_final = SealFinalReplayAdapterV1 {
            index: 33,
            sources: &sources,
            expected_materialization: &seal_materialization,
            output: &original_opcode,
        };
        assert!(
            seal_final
                .replay_recipe(LIFT_SELECTOR, &seal_materialization)
                .is_err()
        );
    }

    #[test]
    fn final_adapters_do_not_delegate_to_generic_raw_replay_mechanisms() {
        fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
            let start = source.find(start).unwrap();
            let tail = &source[start..];
            let end = tail.find(end).unwrap();
            &tail[..end]
        }

        let source = include_str!("b4_c2_raw.rs");
        let sections = [
            section(
                source,
                "impl B4MaterializationReplayAdapterV1 for SealFinalReplayAdapterV1",
                "enum StatementEditKind",
            ),
            section(
                source,
                "impl B4MaterializationReplayAdapterV1 for ChunkMoveFinalReplayAdapterV1",
                "struct StatementRawReplayAdapterV1",
            ),
            section(
                source,
                "impl B4MaterializationReplayAdapterV1 for StatementFinalReplayAdapterV1",
                "pub(crate) fn reconstruct_raw_execution",
            ),
        ];
        for final_adapter in sections {
            assert!(!final_adapter.contains("reconstruct_byte_edit"));
            assert!(!final_adapter.contains("reconstruct_sequence_edit"));
            assert!(!final_adapter.contains("RawReplayAdapterV1"));
        }
        assert!(sections[0].contains("decode_producer_opcode_subject"));
        assert!(sections[1].contains("decode_producer_opcode_subject"));
        assert!(sections[2].contains("parse_ergo_statement_v1"));
    }

    #[test]
    fn v2_entrypoint_uses_only_the_v2_wrapper_resolver_and_shared_core() {
        fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
            source
                .split(start)
                .nth(1)
                .unwrap()
                .split(end)
                .next()
                .unwrap()
        }

        let source = include_str!("b4_c2_raw.rs");
        let authentication = section(
            source,
            "fn authenticate_v2(",
            "fn from_authenticated_parts(",
        );
        assert!(authentication.contains("B4MaterializationFixtureSourceResolverV2"));
        assert!(authentication.contains("resolver.negative_plan_jcs()"));
        assert!(!authentication.contains("B4FixtureSourceResolverV1"));
        assert!(!authentication.contains(".storage()"));

        let entrypoint = section(
            source,
            "pub(crate) fn reconstruct_raw_execution_v2(",
            "fn reconstruct_raw_execution_core(",
        );
        assert!(entrypoint.contains("B4AuthenticatedMaterializationTopLevelV2"));
        assert!(entrypoint.contains("RawSources::authenticate_v2(top_level)"));
        assert!(!entrypoint.contains("B4AuthenticatedMaterializationTopLevelV1"));
        assert!(!entrypoint.contains("B4FixtureSourceResolverV1"));
        assert!(!entrypoint.contains(".storage()"));

        let core = section(
            source,
            "fn reconstruct_raw_execution_core(",
            "fn reconstruct_seal_execution(",
        );
        assert!(core.contains("negative_plan_jcs: &[u8]"));
        assert!(!core.contains("B4AuthenticatedMaterializationTopLevel"));
        assert!(!core.contains("FixtureSourceResolver"));
    }
}
