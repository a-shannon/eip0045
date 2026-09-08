// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Typed parser-prefix adapter for the pinned succinct STARK grammar.
//!
//! The phase census is derived from the authenticated profile, canonical B2
//! constants, and the pinned recursion circuit's actual tap metadata.  It does
//! not consume case IDs, variant IDs, expected offsets, or QA codes.  A parser
//! boundary is returned only when the independently derived checked cursor
//! identifies an incomplete read and the stock-compatible public `verify`
//! entrypoint of the exact pinned reviewed fork returns its typed
//! `ReceiptFormatError`.

#![allow(
    dead_code,
    reason = "the single negative-handler table wires this reviewed adapter in the integration lot"
)]

use core::fmt;

use risc0_zkp::{
    adapter::{
        CircuitInfo, REGISTER_GROUP_ACCUM, REGISTER_GROUP_CODE, REGISTER_GROUP_DATA, TapsProvider,
    },
    core::{digest::DIGEST_WORDS, hash::poseidon2::Poseidon2HashSuite},
    field::{
        ExtElem as _,
        baby_bear::{BabyBearExtElem, P as BABY_BEAR_MODULUS},
    },
};

use crate::{
    b4_negative_handler_contract::B4ParserRejectionStage,
    constants::{BINARY_DATA_ARTIFACT_KIND, BYTES_PER_PROOF_WORD, PROOF_WORDS},
    constants_artifact,
    profile_manifest::{ProfileArtifactReference, StarkProfileManifestV1},
};

use super::{
    errors::{B4Risc0Failure, B4StarkError, B4StarkErrorClass, B4StarkRejectionBoundary},
    terminal::TerminalCapture,
};

const FROZEN_CONSTANTS: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/constants.bin");
const OUTER_PO2_WORD_INDEX: usize = 32;
#[cfg(test)]
pub(super) const AUTHENTICATED_PARSER_SEAL: &[u8] = include_bytes!(
    "../../../generator/testdata/alternate-root-lift-po2-15-v1/candidate-proof-export/proof-output/candidate-raw-seal.bin"
);
#[cfg(test)]
const AUTHENTICATED_PARSER_SEAL_SHA256: &str =
    "c1d823c92398a03c70fa06c85661317f65f7682c066c66e0a22272d7ccfa12fd";
#[cfg(test)]
const AUTHENTICATED_PARSER_MANIFEST: &[u8] =
    include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");

/// Closed query-opening kinds in actual upstream read order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum B4ParserQueryOpening {
    Accum,
    Code,
    Data,
    Check,
    FriRoundOne,
    FriRoundTwo,
    FriRoundThree,
}

/// Closed parser phases derived from actual upstream read operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum B4ParserPhase {
    /// `read_slice_with_po2` reads output globals and outer `po2` together.
    OutputAndOuterPo2,
    CodeMerkleTop,
    DataMerkleTop,
    AccumMerkleTop,
    CheckMerkleTop,
    CoefficientU,
    FriRoundMerkleTop {
        round: u8,
    },
    FinalCoefficients,
    QueryOpening {
        query: u8,
        opening: B4ParserQueryOpening,
    },
}

/// Stable parser EOF boundary independently derived from a prefix length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct B4ParserBoundary {
    phase: B4ParserPhase,
    cursor_words: u32,
    required_words: u32,
    /// Words already available from `cursor_words` before the attempted read.
    available_words: u32,
}

impl B4ParserBoundary {
    pub(super) const fn phase(self) -> B4ParserPhase {
        self.phase
    }

    pub(super) const fn cursor_words(self) -> u32 {
        self.cursor_words
    }

    pub(super) const fn required_words(self) -> u32 {
        self.required_words
    }

    pub(super) const fn available_words(self) -> u32 {
        self.available_words
    }

    #[allow(
        clippy::unused_self,
        reason = "the boundary projection intentionally mirrors the other typed adapters"
    )]
    pub(super) const fn class(self) -> &'static str {
        B4StarkErrorClass::Risc0Parser.as_str()
    }

    /// Project exactly one of the 36 planned physical EOF cuts.
    ///
    /// The match deliberately includes the complete typed boundary.  A
    /// different phase, cursor, read width, or partial-read position is not a
    /// campaign rejection even when the stock parser also reports EOF there.
    pub(super) fn planned_stage(self) -> Option<&'static str> {
        planned_parser_stage(self).map(B4ParserRejectionStage::as_str)
    }
}

fn planned_parser_stage(boundary: B4ParserBoundary) -> Option<B4ParserRejectionStage> {
    use B4ParserPhase as P;
    use B4ParserRejectionStage as S;

    match boundary.phase {
        P::OutputAndOuterPo2 => output_stage(boundary),
        P::CodeMerkleTop => exact_read_stages(
            boundary,
            33,
            256,
            S::CodeTopBeforeRead,
            S::CodeTopAtLastRequiredWord,
        ),
        P::DataMerkleTop => exact_read_stages(
            boundary,
            289,
            256,
            S::DataTopBeforeRead,
            S::DataTopAtLastRequiredWord,
        ),
        P::AccumMerkleTop => exact_read_stages(
            boundary,
            545,
            256,
            S::AccumTopBeforeRead,
            S::AccumTopAtLastRequiredWord,
        ),
        P::CheckMerkleTop => exact_read_stages(
            boundary,
            801,
            256,
            S::CheckTopBeforeRead,
            S::CheckTopAtLastRequiredWord,
        ),
        P::CoefficientU => exact_read_stages(
            boundary,
            1_057,
            2_636,
            S::CoeffUBeforeRead,
            S::CoeffUAtLastRequiredWord,
        ),
        P::FriRoundMerkleTop { round } => fri_top_stage(boundary, round),
        P::FinalCoefficients => exact_read_stages(
            boundary,
            4_461,
            256,
            S::FinalCoefficientsBeforeRead,
            S::FinalCoefficientsAtLastRequiredWord,
        ),
        P::QueryOpening { query, opening } => query_stage(boundary, query, opening),
    }
}

fn output_stage(boundary: B4ParserBoundary) -> Option<B4ParserRejectionStage> {
    use B4ParserRejectionStage as S;

    if (boundary.cursor_words, boundary.required_words) != (0, 33) {
        return None;
    }
    match boundary.available_words {
        0 => Some(S::OutputBeforeRead),
        31 => Some(S::OutputAtLastRequiredWord),
        32 => Some(S::OuterPo2BeforeRead),
        _ => None,
    }
}

fn fri_top_stage(boundary: B4ParserBoundary, round: u8) -> Option<B4ParserRejectionStage> {
    use B4ParserRejectionStage as S;

    match round {
        1 => exact_read_stages(
            boundary,
            3_693,
            256,
            S::FriRoundOneTopBeforeRead,
            S::FriRoundOneTopAtLastRequiredWord,
        ),
        2 => exact_read_stages(
            boundary,
            3_949,
            256,
            S::FriRoundTwoTopBeforeRead,
            S::FriRoundTwoTopAtLastRequiredWord,
        ),
        3 => exact_read_stages(
            boundary,
            4_205,
            256,
            S::FriRoundThreeTopBeforeRead,
            S::FriRoundThreeTopAtLastRequiredWord,
        ),
        _ => None,
    }
}

fn query_stage(
    boundary: B4ParserBoundary,
    query: u8,
    opening: B4ParserQueryOpening,
) -> Option<B4ParserRejectionStage> {
    use B4ParserQueryOpening as O;
    use B4ParserRejectionStage as S;

    match (query, opening) {
        (0, O::Accum) => exact_read_stages(
            boundary,
            4_717,
            132,
            S::QueriesBeforeRead,
            S::QueryZeroAccumOpeningAtLastRequiredWord,
        ),
        (0, O::Code) => exact_read_stages(
            boundary,
            4_849,
            143,
            S::QueryZeroCodeOpeningBeforeRead,
            S::QueryZeroCodeOpeningAtLastRequiredWord,
        ),
        (0, O::Data) => exact_read_stages(
            boundary,
            4_992,
            248,
            S::QueryZeroDataOpeningBeforeRead,
            S::QueryZeroDataOpeningAtLastRequiredWord,
        ),
        (0, O::Check) => exact_read_stages(
            boundary,
            5_240,
            136,
            S::QueryZeroCheckOpeningBeforeRead,
            S::QueryZeroCheckOpeningAtLastRequiredWord,
        ),
        (0, O::FriRoundOne) => exact_read_stages(
            boundary,
            5_376,
            152,
            S::QueryZeroFriRoundOneOpeningBeforeRead,
            S::QueryZeroFriRoundOneOpeningAtLastRequiredWord,
        ),
        (0, O::FriRoundTwo) => exact_read_stages(
            boundary,
            5_528,
            120,
            S::QueryZeroFriRoundTwoOpeningBeforeRead,
            S::QueryZeroFriRoundTwoOpeningAtLastRequiredWord,
        ),
        (0, O::FriRoundThree) => exact_read_stages(
            boundary,
            5_648,
            88,
            S::QueryZeroFriRoundThreeOpeningBeforeRead,
            S::QueryZeroFriRoundThreeOpeningAtLastRequiredWord,
        ),
        (49, O::FriRoundThree) => {
            exact_last_stage(boundary, 55_579, 88, S::QueriesAtLastRequiredWord)
        }
        _ => None,
    }
}

fn exact_read_stages(
    boundary: B4ParserBoundary,
    cursor_words: u32,
    required_words: u32,
    before: B4ParserRejectionStage,
    last: B4ParserRejectionStage,
) -> Option<B4ParserRejectionStage> {
    if (boundary.cursor_words, boundary.required_words) != (cursor_words, required_words) {
        return None;
    }
    match boundary.available_words {
        0 => Some(before),
        available if available == required_words - 1 => Some(last),
        _ => None,
    }
}

fn exact_last_stage(
    boundary: B4ParserBoundary,
    cursor_words: u32,
    required_words: u32,
    last: B4ParserRejectionStage,
) -> Option<B4ParserRejectionStage> {
    ((
        boundary.cursor_words,
        boundary.required_words,
        boundary.available_words,
    ) == (cursor_words, required_words, required_words - 1))
        .then_some(last)
}

/// Private failures which cannot become campaign observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum B4ParserAdapterError {
    ContextCardinality {
        actual: usize,
        expected: usize,
    },
    ProfileContext,
    SubjectNotWordAligned {
        actual_bytes: usize,
    },
    SubjectIsNotStrictPrefix {
        actual_words: usize,
        exact_words: usize,
    },
    WordNotReduced {
        index: usize,
        word: u32,
    },
    AllocationFailure,
    GrammarAuthority,
    UnplannedCampaignBoundary(B4ParserBoundary),
    UnexpectedStockAcceptance,
    UnexpectedStockBoundary(B4StarkRejectionBoundary),
}

impl fmt::Display for B4ParserAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for B4ParserAdapterError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParserOperation {
    phase: B4ParserPhase,
    start: usize,
    words: usize,
}

impl ParserOperation {
    fn end(self) -> Result<usize, B4ParserAdapterError> {
        self.start
            .checked_add(self.words)
            .ok_or(B4ParserAdapterError::GrammarAuthority)
    }
}

#[derive(Debug)]
struct B4ParserGrammar {
    operations: Vec<ParserOperation>,
    exact_words: usize,
}

impl B4ParserGrammar {
    fn locate_truncation(
        &self,
        prefix_words: usize,
    ) -> Result<B4ParserBoundary, B4ParserAdapterError> {
        if prefix_words >= self.exact_words {
            return Err(B4ParserAdapterError::SubjectIsNotStrictPrefix {
                actual_words: prefix_words,
                exact_words: self.exact_words,
            });
        }
        let operation = self
            .operations
            .iter()
            .copied()
            .find(|operation| operation.end().is_ok_and(|end| prefix_words < end))
            .ok_or(B4ParserAdapterError::GrammarAuthority)?;
        if prefix_words < operation.start {
            return Err(B4ParserAdapterError::GrammarAuthority);
        }
        let available = prefix_words
            .checked_sub(operation.start)
            .ok_or(B4ParserAdapterError::GrammarAuthority)?;
        Ok(B4ParserBoundary {
            phase: operation.phase,
            cursor_words: u32::try_from(operation.start)
                .map_err(|_| B4ParserAdapterError::GrammarAuthority)?,
            required_words: u32::try_from(operation.words)
                .map_err(|_| B4ParserAdapterError::GrammarAuthority)?,
            available_words: u32::try_from(available)
                .map_err(|_| B4ParserAdapterError::GrammarAuthority)?,
        })
    }
}

/// Validate a raw word-aligned seal prefix against the independently derived
/// parser grammar and the stock-compatible public `verify` entrypoint of the
/// exact pinned reviewed fork.
///
/// The fixed full-length transport check is intentionally bypassed.  Every
/// other locally available base check remains: frozen profile authentication,
/// exact word alignment, strict-prefix length, canonical field-word encoding,
/// profile `po2` agreement when that word is present, and stock terminal
/// policy when the callback is reached.
pub(super) fn reject_parser_prefix(
    subject: &[u8],
    contexts: &[&[u8]],
) -> Result<B4ParserBoundary, B4ParserAdapterError> {
    let manifest = decode_manifest_context(contexts)?;
    let words = decode_prefix_words(subject)?;
    let grammar = derive_parser_grammar(&manifest, &words)?;
    let boundary = grammar.locate_truncation(words.len())?;

    let capture = TerminalCapture::new(&manifest);
    let suite = Poseidon2HashSuite::new_suite();
    let upstream = risc0_zkp::verify::verify(
        &risc0_circuit_recursion::CIRCUIT,
        &suite,
        &words,
        |po2, code_root| capture.check_code(po2, code_root),
    );
    match capture.finish(upstream) {
        Err(B4StarkError::Risc0Verifier(B4Risc0Failure::ReceiptFormat)) => Ok(boundary),
        Err(error) => Err(B4ParserAdapterError::UnexpectedStockBoundary(
            error.rejection_boundary(),
        )),
        Ok(_) => Err(B4ParserAdapterError::UnexpectedStockAcceptance),
    }
}

/// Derive every canonical parser-prefix fixture from one tracked, real STARK
/// seal and the sole canonical plan.
///
/// This test-only bridge deliberately returns subjects and stable boundaries,
/// never an observation or handler authority. The caller must still traverse
/// the authenticated dispatcher.
#[cfg(test)]
pub(super) fn authenticated_parser_prefix_fixture_cases() -> Vec<(Vec<u8>, &'static str)> {
    use sha2::{Digest as _, Sha256};

    use crate::{
        b4_negative_handler_contract::exact_negative_rejection_boundary,
        b4_plan::{B4MaterializationDomain, B4NegativeExecutionSurface, Eip0045B4NegativePlanV1},
    };

    assert_eq!(
        AUTHENTICATED_PARSER_SEAL.len(),
        PROOF_WORDS * BYTES_PER_PROOF_WORD
    );
    assert_eq!(
        hex::encode(Sha256::digest(AUTHENTICATED_PARSER_SEAL)),
        AUTHENTICATED_PARSER_SEAL_SHA256
    );
    let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
    let executions = plan
        .groups
        .iter()
        .flat_map(|group| &group.executions)
        .filter(|execution| {
            execution.materialization_domain == B4MaterializationDomain::VerifierInput
                && execution.execution_surface == B4NegativeExecutionSurface::Risc0ParserInternal
        })
        .collect::<Vec<_>>();
    assert_eq!(executions.len(), 36);

    executions
        .into_iter()
        .map(|execution| {
            let words = usize::try_from(execution.parser_truncation_words.unwrap()).unwrap();
            let prefix = AUTHENTICATED_PARSER_SEAL[..words * BYTES_PER_PROOF_WORD].to_vec();
            let observed = reject_parser_prefix(&prefix, &[AUTHENTICATED_PARSER_MANIFEST]).unwrap();
            let expected = exact_negative_rejection_boundary(execution).unwrap();
            assert_eq!(observed.class(), expected.class());
            assert_eq!(observed.planned_stage(), Some(expected.stage()));
            (prefix, expected.stage())
        })
        .collect()
}

fn decode_manifest_context(
    contexts: &[&[u8]],
) -> Result<StarkProfileManifestV1, B4ParserAdapterError> {
    if contexts.len() != 1 {
        return Err(B4ParserAdapterError::ContextCardinality {
            actual: contexts.len(),
            expected: 1,
        });
    }
    let manifest = StarkProfileManifestV1::decode(contexts[0])
        .map_err(|_| B4ParserAdapterError::ProfileContext)?;
    if manifest
        .encode()
        .map_err(|_| B4ParserAdapterError::ProfileContext)?
        .as_slice()
        != contexts[0]
        || manifest.validate_initial_profile_target().is_err()
    {
        return Err(B4ParserAdapterError::ProfileContext);
    }
    Ok(manifest)
}

fn decode_prefix_words(subject: &[u8]) -> Result<Vec<u32>, B4ParserAdapterError> {
    if subject.len() % BYTES_PER_PROOF_WORD != 0 {
        return Err(B4ParserAdapterError::SubjectNotWordAligned {
            actual_bytes: subject.len(),
        });
    }
    let word_count = subject.len() / BYTES_PER_PROOF_WORD;
    if word_count >= PROOF_WORDS {
        return Err(B4ParserAdapterError::SubjectIsNotStrictPrefix {
            actual_words: word_count,
            exact_words: PROOF_WORDS,
        });
    }
    let mut words = Vec::new();
    words
        .try_reserve_exact(word_count)
        .map_err(|_| B4ParserAdapterError::AllocationFailure)?;
    for (index, chunk) in subject.chunks_exact(BYTES_PER_PROOF_WORD).enumerate() {
        let word = u32::from_le_bytes(chunk.try_into().map_err(|_| {
            B4ParserAdapterError::SubjectNotWordAligned {
                actual_bytes: subject.len(),
            }
        })?);
        if word >= BABY_BEAR_MODULUS {
            return Err(B4ParserAdapterError::WordNotReduced { index, word });
        }
        words.push(word);
    }
    Ok(words)
}

#[allow(
    clippy::too_many_lines,
    reason = "one linear function mirrors the pinned verifier read order for mechanical review"
)]
fn derive_parser_grammar(
    manifest: &StarkProfileManifestV1,
    prefix_words: &[u32],
) -> Result<B4ParserGrammar, B4ParserAdapterError> {
    let constants = constants_artifact::verify_canonical(FROZEN_CONSTANTS)
        .map_err(|_| B4ParserAdapterError::GrammarAuthority)?;
    let expected_constants_reference =
        ProfileArtifactReference::from_artifact(BINARY_DATA_ARTIFACT_KIND, FROZEN_CONSTANTS)
            .map_err(|_| B4ParserAdapterError::GrammarAuthority)?;
    if manifest.binary_data_artifact() != expected_constants_reference {
        return Err(B4ParserAdapterError::GrammarAuthority);
    }
    let stark = &constants.stark;
    let taps = risc0_circuit_recursion::CIRCUIT.get_taps();

    let output_size = usize::from(stark.output_size);
    let check_size = usize::from(stark.check_size);
    let queries = usize::from(stark.queries);
    let inverse_rate = usize::from(stark.inverse_rate);
    let fri_fold = usize::from(stark.fri_fold);
    let fri_min_degree = usize::from(stark.fri_min_degree);
    let digest_words = usize::from(constants.poseidon2.output_cells);
    let extension_words = BabyBearExtElem::EXT_SIZE;

    if output_size != <risc0_circuit_recursion::CircuitImpl as CircuitInfo>::OUTPUT_SIZE
        || usize::from(stark.mix_size)
            != <risc0_circuit_recursion::CircuitImpl as CircuitInfo>::MIX_SIZE
        || queries != risc0_zkp::QUERIES
        || inverse_rate != risc0_zkp::INV_RATE
        || fri_fold != risc0_zkp::FRI_FOLD
        || digest_words != DIGEST_WORDS
        || check_size != inverse_rate * extension_words
        || constants.taps.group_sizes
            != [
                u8::try_from(taps.group_size(REGISTER_GROUP_ACCUM))
                    .map_err(|_| B4ParserAdapterError::GrammarAuthority)?,
                u8::try_from(taps.group_size(REGISTER_GROUP_CODE))
                    .map_err(|_| B4ParserAdapterError::GrammarAuthority)?,
                u8::try_from(taps.group_size(REGISTER_GROUP_DATA))
                    .map_err(|_| B4ParserAdapterError::GrammarAuthority)?,
            ]
    {
        return Err(B4ParserAdapterError::GrammarAuthority);
    }

    let exact_bytes = usize::try_from(manifest.exact_proof_bytes())
        .map_err(|_| B4ParserAdapterError::GrammarAuthority)?;
    if exact_bytes % BYTES_PER_PROOF_WORD != 0 {
        return Err(B4ParserAdapterError::GrammarAuthority);
    }
    let exact_words = exact_bytes / BYTES_PER_PROOF_WORD;
    if exact_words != PROOF_WORDS {
        return Err(B4ParserAdapterError::GrammarAuthority);
    }

    let po2 = usize::from(manifest.outer_po2());
    if let Some(actual_po2) = prefix_words.get(OUTER_PO2_WORD_INDEX)
        && usize::try_from(*actual_po2).ok() != Some(po2)
    {
        return Err(B4ParserAdapterError::GrammarAuthority);
    }
    let degree = 1_usize
        .checked_shl(u32::try_from(po2).map_err(|_| B4ParserAdapterError::GrammarAuthority)?)
        .ok_or(B4ParserAdapterError::GrammarAuthority)?;
    let domain = inverse_rate
        .checked_mul(degree)
        .ok_or(B4ParserAdapterError::GrammarAuthority)?;
    if !domain.is_power_of_two()
        || !fri_fold.is_power_of_two()
        || fri_fold <= 1
        || fri_min_degree == 0
        || queries == 0
    {
        return Err(B4ParserAdapterError::GrammarAuthority);
    }

    let top_layer =
        usize::try_from(queries.ilog2()).map_err(|_| B4ParserAdapterError::GrammarAuthority)?;
    let top_size = 1_usize
        .checked_shl(u32::try_from(top_layer).map_err(|_| B4ParserAdapterError::GrammarAuthority)?)
        .ok_or(B4ParserAdapterError::GrammarAuthority)?;
    let merkle_top_words = top_size
        .checked_mul(digest_words)
        .ok_or(B4ParserAdapterError::GrammarAuthority)?;

    let mut operations = Vec::new();
    let operation_capacity = queries
        .checked_mul(7)
        .and_then(|count| count.checked_add(10))
        .ok_or(B4ParserAdapterError::GrammarAuthority)?;
    operations
        .try_reserve_exact(operation_capacity)
        .map_err(|_| B4ParserAdapterError::AllocationFailure)?;
    let mut cursor = 0_usize;
    push_operation(
        &mut operations,
        &mut cursor,
        B4ParserPhase::OutputAndOuterPo2,
        output_size
            .checked_add(1)
            .ok_or(B4ParserAdapterError::GrammarAuthority)?,
    )?;
    for phase in [
        B4ParserPhase::CodeMerkleTop,
        B4ParserPhase::DataMerkleTop,
        B4ParserPhase::AccumMerkleTop,
        B4ParserPhase::CheckMerkleTop,
    ] {
        push_operation(&mut operations, &mut cursor, phase, merkle_top_words)?;
    }
    let coefficient_words = taps
        .tap_size()
        .checked_add(check_size)
        .and_then(|count| count.checked_mul(extension_words))
        .ok_or(B4ParserAdapterError::GrammarAuthority)?;
    push_operation(
        &mut operations,
        &mut cursor,
        B4ParserPhase::CoefficientU,
        coefficient_words,
    )?;

    let mut fri_degree = degree;
    let mut fri_domain = domain;
    let mut fri_round_domains = Vec::new();
    while fri_degree > fri_min_degree {
        if fri_degree % fri_fold != 0 || fri_domain % fri_fold != 0 {
            return Err(B4ParserAdapterError::GrammarAuthority);
        }
        fri_degree = fri_degree
            .checked_div(fri_fold)
            .ok_or(B4ParserAdapterError::GrammarAuthority)?;
        fri_domain = fri_domain
            .checked_div(fri_fold)
            .ok_or(B4ParserAdapterError::GrammarAuthority)?;
        if fri_degree == 0 || fri_domain == 0 || !fri_domain.is_power_of_two() {
            return Err(B4ParserAdapterError::GrammarAuthority);
        }
        fri_round_domains.push(fri_domain);
        let round = u8::try_from(fri_round_domains.len())
            .map_err(|_| B4ParserAdapterError::GrammarAuthority)?;
        push_operation(
            &mut operations,
            &mut cursor,
            B4ParserPhase::FriRoundMerkleTop { round },
            merkle_top_words,
        )?;
    }
    if fri_round_domains.len() != 3 {
        return Err(B4ParserAdapterError::GrammarAuthority);
    }
    let final_coefficient_words = extension_words
        .checked_mul(fri_degree)
        .ok_or(B4ParserAdapterError::GrammarAuthority)?;
    push_operation(
        &mut operations,
        &mut cursor,
        B4ParserPhase::FinalCoefficients,
        final_coefficient_words,
    )?;

    let group_opening_words = [
        merkle_opening_words(
            domain,
            taps.group_size(REGISTER_GROUP_ACCUM),
            top_layer,
            digest_words,
        )?,
        merkle_opening_words(
            domain,
            taps.group_size(REGISTER_GROUP_CODE),
            top_layer,
            digest_words,
        )?,
        merkle_opening_words(
            domain,
            taps.group_size(REGISTER_GROUP_DATA),
            top_layer,
            digest_words,
        )?,
        merkle_opening_words(domain, check_size, top_layer, digest_words)?,
    ];
    let fri_column_words = fri_fold
        .checked_mul(extension_words)
        .ok_or(B4ParserAdapterError::GrammarAuthority)?;
    let fri_opening_words = [
        merkle_opening_words(
            fri_round_domains[0],
            fri_column_words,
            top_layer,
            digest_words,
        )?,
        merkle_opening_words(
            fri_round_domains[1],
            fri_column_words,
            top_layer,
            digest_words,
        )?,
        merkle_opening_words(
            fri_round_domains[2],
            fri_column_words,
            top_layer,
            digest_words,
        )?,
    ];

    for query in 0..queries {
        let query = u8::try_from(query).map_err(|_| B4ParserAdapterError::GrammarAuthority)?;
        for (opening, words) in [
            (B4ParserQueryOpening::Accum, group_opening_words[0]),
            (B4ParserQueryOpening::Code, group_opening_words[1]),
            (B4ParserQueryOpening::Data, group_opening_words[2]),
            (B4ParserQueryOpening::Check, group_opening_words[3]),
            (B4ParserQueryOpening::FriRoundOne, fri_opening_words[0]),
            (B4ParserQueryOpening::FriRoundTwo, fri_opening_words[1]),
            (B4ParserQueryOpening::FriRoundThree, fri_opening_words[2]),
        ] {
            push_operation(
                &mut operations,
                &mut cursor,
                B4ParserPhase::QueryOpening { query, opening },
                words,
            )?;
        }
    }
    if cursor != exact_words {
        return Err(B4ParserAdapterError::GrammarAuthority);
    }
    Ok(B4ParserGrammar {
        operations,
        exact_words,
    })
}

fn push_operation(
    operations: &mut Vec<ParserOperation>,
    cursor: &mut usize,
    phase: B4ParserPhase,
    words: usize,
) -> Result<(), B4ParserAdapterError> {
    if words == 0 {
        return Err(B4ParserAdapterError::GrammarAuthority);
    }
    let operation = ParserOperation {
        phase,
        start: *cursor,
        words,
    };
    *cursor = operation.end()?;
    operations.push(operation);
    Ok(())
}

fn merkle_opening_words(
    row_size: usize,
    column_words: usize,
    top_layer: usize,
    digest_words: usize,
) -> Result<usize, B4ParserAdapterError> {
    if !row_size.is_power_of_two() {
        return Err(B4ParserAdapterError::GrammarAuthority);
    }
    let layers =
        usize::try_from(row_size.ilog2()).map_err(|_| B4ParserAdapterError::GrammarAuthority)?;
    let sibling_layers = layers
        .checked_sub(top_layer)
        .ok_or(B4ParserAdapterError::GrammarAuthority)?;
    column_words
        .checked_add(
            sibling_layers
                .checked_mul(digest_words)
                .ok_or(B4ParserAdapterError::GrammarAuthority)?,
        )
        .ok_or(B4ParserAdapterError::GrammarAuthority)
}

/// Genuine local C2 join, separate from the historical embedded-prefix tests.
/// These tests do not create a campaign authority or physical negative corpus.
#[cfg(all(test, feature = "negative-materialization-set"))]
mod genuine_parser {
    use super::*;
    use anyhow::{Result as AnyResult, ensure};
    use sha2::{Digest as _, Sha256};
    use crate::{
        b4::{B4ByteOperation, B4ByteTarget, B4NegativeMaterialization, B4NegativeMutation},
        b4_c2_parser::genuine_parser::{Fixture, load_fixture},
        b4_materialization_set::B4ClosedReconstructedExecutionV1,
        b4_mutation::{Eip0045B4MaterializationIdentityV1, canonical_materialization_recipe_jcs},
        b4_negative_io::{B4NegativeFileEncoding, Eip0045B4NegativeVerifierInputV1},
        b4_plan::{B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanFixture,
            B4NegativeQaResultCode, Eip0045B4NegativePlanV1},
    };

    // Literal canonical order, independent of the producer's source table.
    const ROWS: [(usize, &str); 36] = [
        (0, "output-before-read"), (31, "output-at-last-required-word"), (32, "outer-po2-before-read"),
        (33, "code-top-before-read"), (288, "code-top-at-last-required-word"),
        (289, "data-top-before-read"), (544, "data-top-at-last-required-word"),
        (545, "accum-top-before-read"), (800, "accum-top-at-last-required-word"),
        (801, "check-top-before-read"), (1056, "check-top-at-last-required-word"),
        (1057, "coeff-u-before-read"), (3692, "coeff-u-at-last-required-word"),
        (3693, "fri-round-one-top-before-read"), (3948, "fri-round-one-top-at-last-required-word"),
        (3949, "fri-round-two-top-before-read"), (4204, "fri-round-two-top-at-last-required-word"),
        (4205, "fri-round-three-top-before-read"), (4460, "fri-round-three-top-at-last-required-word"),
        (4461, "final-coefficients-before-read"), (4716, "final-coefficients-at-last-required-word"),
        (4717, "queries-before-read"), (55666, "queries-at-last-required-word"),
        (4848, "query-zero-accum-opening-at-last-required-word"),
        (4849, "query-zero-code-opening-before-read"), (4991, "query-zero-code-opening-at-last-required-word"),
        (4992, "query-zero-data-opening-before-read"), (5239, "query-zero-data-opening-at-last-required-word"),
        (5240, "query-zero-check-opening-before-read"), (5375, "query-zero-check-opening-at-last-required-word"),
        (5376, "query-zero-fri-round-one-opening-before-read"), (5527, "query-zero-fri-round-one-opening-at-last-required-word"),
        (5528, "query-zero-fri-round-two-opening-before-read"), (5647, "query-zero-fri-round-two-opening-at-last-required-word"),
        (5648, "query-zero-fri-round-three-opening-before-read"), (5735, "query-zero-fri-round-three-opening-at-last-required-word"),
    ];

    fn sha(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }

    fn fixture() -> Fixture {
        let root = std::env::var_os("EIP0045_B4_REAL_VECTOR_ROOT").expect("real case0 vector root required");
        // This performs the existing disabled-dev receipt/claim/control/raw replay.
        // Do not call the crypto Fixture::reconstruct: no mutation search is needed.
        let fixture = load_fixture(std::path::Path::new(&root)).unwrap();
        assert_eq!(fixture.raw().len(), 222668);
        assert_eq!(sha(fixture.raw()), "9580a6d7f9dd4d8314a3c16202eec86fdd0c511f61e4374f433015aec493765f");
        fixture
    }

    fn validate_row(fixture: &Fixture, index: usize, closed: &B4ClosedReconstructedExecutionV1) -> AnyResult<()> {
        ensure!((72..108).contains(&index), "parser matrix foreign row");
        let (words, variant) = ROWS[index - 72];
        let cut = words * 4;
        let plan = Eip0045B4NegativePlanV1::canonical()?;
        let plan_jcs = plan.to_canonical_jcs()?;
        let planned = plan.groups.iter().flat_map(|g| g.executions.iter()).nth(index).unwrap();
        ensure!(planned.execution_id == format!("parser-phase-truncation-sweep--{variant}")
            && planned.variant_id == variant && planned.parser_truncation_words == Some(words as u32)
            && planned.base_selector_id == "lift-po2-15-parser-oracle"
            && planned.fixture == B4NegativePlanFixture::LiftPo215ParserOracle
            && planned.materialization_domain == B4MaterializationDomain::VerifierInput
            && planned.execution_surface == B4NegativeExecutionSurface::Risc0ParserInternal
            && planned.qa_result_code == B4NegativeQaResultCode::B4ParserUnexpectedEofAtPhase,
            "parser matrix canonical row differs");
        let recipe = B4NegativeMaterialization::Mutation { mutation: B4NegativeMutation::ByteEdit {
            target: B4ByteTarget::RawSeal, edit: B4ByteOperation::Truncate {
                before_hex: hex::encode(&fixture.raw()[cut..cut + 4]), new_length: cut as u64,
                original_length: 222668 } } };
        ensure!(closed.derived_registry_row.execution_id == planned.execution_id
            && closed.derived_registry_row.base_selector_id == planned.base_selector_id
            && closed.derived_registry_row.materialization_domain == planned.materialization_domain
            && closed.derived_registry_row.materialization == recipe, "parser matrix recipe differs");
        ensure!(closed.base == fixture.raw() && closed.subject == fixture.raw()[..cut]
            && closed.contexts == vec![fixture.manifest().to_vec()], "parser matrix exact source prefix or context differs");
        let identity = Eip0045B4MaterializationIdentityV1::from_canonical_jcs(&closed.materialization_identity_jcs)?;
        let recipe_jcs = canonical_materialization_recipe_jcs(&recipe)?;
        ensure!(identity.to_canonical_jcs()? == closed.materialization_identity_jcs
            && identity.execution_id == planned.execution_id && identity.base_selector_id == planned.base_selector_id
            && identity.materialization_domain == planned.materialization_domain
            && identity.base_byte_length == 222668 && identity.base_sha256 == sha(fixture.raw())
            && identity.output_byte_length == cut as u64 && identity.output_sha256 == sha(&closed.subject)
            && identity.materialization_recipe_byte_length == recipe_jcs.len() as u64
            && identity.materialization_recipe_sha256 == sha(&recipe_jcs)
            && identity.negative_plan_byte_length == plan_jcs.len() as u64
            && identity.negative_plan_sha256 == sha(&plan_jcs), "parser matrix materialization identity differs");
        let input = Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&closed.negative_input_jcs)?;
        ensure!(input.to_canonical_jcs()? == closed.negative_input_jcs
            && input.materialization_domain == planned.materialization_domain
            && input.validation_surface == planned.execution_surface
            && input.subject.role == "subject" && input.subject.path == "subject.bin"
            && input.subject.encoding == B4NegativeFileEncoding::RawBytes
            && input.subject.byte_length == cut as u64 && input.subject.sha256 == sha(&closed.subject)
            && input.context.len() == 1, "parser matrix neutral input differs");
        let context = &input.context[0];
        ensure!(context.role == "context-00" && context.path == "context/00.bin"
            && context.encoding == B4NegativeFileEncoding::RawBytes
            && context.byte_length == fixture.manifest().len() as u64
            && context.sha256 == sha(fixture.manifest()), "parser matrix neutral context differs");
        Ok(())
    }

    fn validate_boundary(index: usize, observed: B4ParserBoundary, grammar: &B4ParserGrammar) -> AnyResult<()> {
        ensure!((72..108).contains(&index), "parser matrix foreign observation");
        let (words, variant) = ROWS[index - 72];
        let expected_stage = format!("risc0-read-iop-{variant}");
        ensure!(observed.class() == "risc0-parser-invalid"
            && observed.planned_stage() == Some(expected_stage.as_str())
            && observed == grammar.locate_truncation(words)?, "parser matrix exact boundary differs");
        Ok(())
    }

    fn validate_observations(observed: &[(usize, B4ParserBoundary)], grammar: &B4ParserGrammar) -> AnyResult<()> {
        ensure!(observed.len() == 36, "parser matrix cardinality differs");
        for (position, &(index, boundary)) in observed.iter().enumerate() {
            ensure!(index == 72 + position, "parser matrix row order differs");
            validate_boundary(index, boundary, grammar)?;
        }
        Ok(())
    }

    fn exact_error<T>(result: AnyResult<T>, expected: &str) {
        assert_eq!(result.err().expect("negative oracle must reject").to_string(), expected);
    }

    #[test]
    fn parser_truth_map_rejects_missing_duplicate_neighbor_and_wrong_stage() {
        let manifest = StarkProfileManifestV1::decode(AUTHENTICATED_PARSER_MANIFEST).unwrap();
        let grammar = derive_parser_grammar(&manifest, &[]).unwrap();
        // Grammar-only oracle controls, not proof-consuming evidence.
        let observed = ROWS.iter().enumerate().map(|(i, &(cut, _))|
            (72 + i, grammar.locate_truncation(cut).unwrap())).collect::<Vec<_>>();
        validate_observations(&observed, &grammar).unwrap();
        exact_error(validate_observations(&observed[..35], &grammar), "parser matrix cardinality differs");
        let mut changed = observed.clone();
        changed[1] = changed[0];
        exact_error(validate_observations(&changed, &grammar), "parser matrix row order differs");
        changed = observed.clone();
        changed[0].1 = grammar.locate_truncation(1).unwrap();
        exact_error(validate_observations(&changed, &grammar), "parser matrix exact boundary differs");
        changed = observed.clone();
        changed[0].1 = observed[1].1;
        exact_error(validate_observations(&changed, &grammar), "parser matrix exact boundary differs");
        changed = observed.clone();
        changed[0].1.required_words += 1;
        exact_error(validate_observations(&changed, &grammar), "parser matrix exact boundary differs");
    }

    #[test]
    #[ignore = "requires preserved authenticated case0 vector; run before the complete local parser matrix"]
    fn genuine_parser_late_prefix_row94() {
        let fixture = fixture();
        let row = fixture.reconstruct(94).unwrap();
        validate_row(&fixture, 94, &row).unwrap();
        assert_eq!(row.subject.len(), 222664);
        let boundary = reject_parser_prefix(&row.subject, &row.contexts.iter().map(Vec::as_slice).collect::<Vec<_>>()).unwrap();
        assert_eq!(boundary.class(), "risc0-parser-invalid");
        assert_eq!(boundary.planned_stage(), Some("risc0-read-iop-queries-at-last-required-word"));
        assert_eq!(boundary, B4ParserBoundary {
            phase: B4ParserPhase::QueryOpening { query: 49, opening: B4ParserQueryOpening::FriRoundThree },
            cursor_words: 55_579, required_words: 88, available_words: 87,
        });
        let manifest = StarkProfileManifestV1::decode(fixture.manifest()).unwrap();
        validate_boundary(94, boundary, &derive_parser_grammar(&manifest, &[]).unwrap()).unwrap();
    }

    #[test]
    #[ignore = "requires preserved authenticated case0 vector; local C2 diagnostic, not campaign evidence"]
    fn genuine_parser_c2_producer_consumer_matrix() {
        let fixture = fixture();
        let manifest = StarkProfileManifestV1::decode(fixture.manifest()).unwrap();
        let grammar = derive_parser_grammar(&manifest, &[]).unwrap();
        let mut observations = Vec::new();
        for index in 72..108 {
            let row = fixture.reconstruct(index).unwrap();
            validate_row(&fixture, index, &row).unwrap();
            let contexts = row.contexts.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let boundary = reject_parser_prefix(&row.subject, &contexts).unwrap();
            validate_boundary(index, boundary, &grammar).unwrap();
            observations.push((index, boundary));
            let mut changed = row.clone();
            changed.subject.extend_from_slice(&fixture.raw()[row.subject.len()..row.subject.len() + 4]);
            exact_error(validate_row(&fixture, index, &changed), "parser matrix exact source prefix or context differs");
            changed = row.clone();
            changed.contexts.clear();
            exact_error(validate_row(&fixture, index, &changed), "parser matrix exact source prefix or context differs");
        }
        validate_observations(&observations, &grammar).unwrap();
        exact_error(validate_observations(&observations[..35], &grammar), "parser matrix cardinality differs");
        let mut duplicate = observations.clone();
        duplicate[1] = duplicate[0];
        exact_error(validate_observations(&duplicate, &grammar), "parser matrix row order differs");
        let mut wrong_stage = observations.clone();
        wrong_stage[0].1 = observations[1].1;
        exact_error(validate_observations(&wrong_stage, &grammar), "parser matrix exact boundary differs");
        let row = fixture.reconstruct(94).unwrap();
        let mut recipe_drift = row.clone();
        let B4NegativeMaterialization::Mutation { mutation: B4NegativeMutation::ByteEdit {
            edit: B4ByteOperation::Truncate { before_hex, .. }, .. } } = &mut recipe_drift.derived_registry_row.materialization
            else { panic!("real row lost its truncate recipe") };
        let mut witness = hex::decode(&*before_hex).unwrap();
        witness[0] ^= 1;
        *before_hex = hex::encode(witness);
        exact_error(validate_row(&fixture, 94, &recipe_drift), "parser matrix recipe differs");
        let mut identity_drift = row.clone();
        let mut identity = Eip0045B4MaterializationIdentityV1::from_canonical_jcs(&row.materialization_identity_jcs).unwrap();
        identity.output_sha256 = "00".repeat(32);
        identity_drift.materialization_identity_jcs = identity.to_canonical_jcs().unwrap();
        exact_error(validate_row(&fixture, 94, &identity_drift), "parser matrix materialization identity differs");
        let mut context_drift = row.clone();
        let mut input = Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&row.negative_input_jcs).unwrap();
        input.context[0].sha256 = "00".repeat(32);
        context_drift.negative_input_jcs = input.to_canonical_jcs().unwrap();
        exact_error(validate_row(&fixture, 94, &context_drift), "parser matrix neutral context differs");
        assert_eq!(reject_parser_prefix(&row.subject, &[]),
            Err(B4ParserAdapterError::ContextCardinality { actual: 0, expected: 1 }));
        assert_eq!(reject_parser_prefix(&row.subject, &[b"bad"]), Err(B4ParserAdapterError::ProfileContext));
        assert_eq!(reject_parser_prefix(fixture.raw(), &[fixture.manifest()]),
            Err(B4ParserAdapterError::SubjectIsNotStrictPrefix { actual_words: 55667, exact_words: 55667 }));
        let mut nonreduced = row.subject.clone();
        nonreduced[..4].copy_from_slice(&BABY_BEAR_MODULUS.to_le_bytes());
        assert_eq!(reject_parser_prefix(&nonreduced, &[fixture.manifest()]),
            Err(B4ParserAdapterError::WordNotReduced { index: 0, word: BABY_BEAR_MODULUS }));
        assert_eq!(reject_parser_prefix(&row.subject[..row.subject.len() - 1], &[fixture.manifest()]),
            Err(B4ParserAdapterError::SubjectNotWordAligned { actual_bytes: 222663 }));
        // Word 33 is the first code-Merkle-top word, not the outer exponent.
        // A reduced change reaches stock verification. TerminalCapture::finish
        // preserves its check_code failure instead of admitting it as parser EOF.
        let offset = 33 * 4;
        let before = u32::from_le_bytes(row.subject[offset..offset + 4].try_into().unwrap());
        assert!(before < BABY_BEAR_MODULUS);
        let replacement = (before + 1) % BABY_BEAR_MODULUS;
        let mut code_top = row.subject.clone();
        code_top[offset..offset + 4].copy_from_slice(&replacement.to_le_bytes());
        assert_ne!(before, replacement);
        assert_eq!(&code_top[..offset], &row.subject[..offset]);
        assert_eq!(&code_top[offset + 4..], &row.subject[offset + 4..]);
        assert_eq!(code_top.len(), row.subject.len());
        assert_eq!(reject_parser_prefix(&code_top, &[fixture.manifest()]),
            Err(B4ParserAdapterError::UnexpectedStockBoundary(B4StarkRejectionBoundary {
                class: B4StarkErrorClass::TerminalPolicy,
                stage: crate::b4_validator::errors::B4StarkErrorStage::TerminalControlId,
            })));
        // The original prefix still reaches the exact observed EOF boundary.
        assert_eq!(reject_parser_prefix(&row.subject, &[fixture.manifest()]), Ok(observations[94 - 72].1));
        for index in [0, 71, 108, 253, usize::MAX] {
            exact_error(fixture.reconstruct(index), "genuine parser seam permits only rows 72 through 107");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        b4_plan::Eip0045B4NegativePlanV1,
        seal::{QUERY_WORD_SPANS, TOP_LEVEL_WORD_SPANS},
    };

    const MANIFEST: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");
    const CANONICAL_TRUNCATION_WORDS: [usize; 36] = [
        0, 31, 32, 33, 288, 289, 544, 545, 800, 801, 1_056, 1_057, 3_692, 3_693, 3_948, 3_949,
        4_204, 4_205, 4_460, 4_461, 4_716, 4_717, 55_666, 4_848, 4_849, 4_991, 4_992, 5_239, 5_240,
        5_375, 5_376, 5_527, 5_528, 5_647, 5_648, 5_735,
    ];

    fn manifest() -> StarkProfileManifestV1 {
        let manifest = StarkProfileManifestV1::decode(MANIFEST).unwrap();
        manifest.validate_initial_profile_target().unwrap();
        manifest
    }

    fn grammar() -> B4ParserGrammar {
        derive_parser_grammar(&manifest(), &[]).unwrap()
    }

    #[test]
    fn derived_census_is_exactly_fifty_five_thousand_six_hundred_sixty_seven_words() {
        let grammar = grammar();
        assert_eq!(grammar.exact_words, 55_667);
        assert_eq!(grammar.exact_words, PROOF_WORDS);
        assert_eq!(grammar.operations.len(), 10 + 50 * 7);
        assert_eq!(grammar.operations.first().unwrap().start, 0);
        assert_eq!(
            grammar.operations.last().unwrap().end().unwrap(),
            grammar.exact_words
        );
        for pair in grammar.operations.windows(2) {
            assert_eq!(pair[0].end().unwrap(), pair[1].start);
        }
    }

    #[test]
    fn derived_top_level_and_query_zero_spans_match_the_frozen_public_grammar() {
        let grammar = grammar();
        let top = &grammar.operations[..10];
        assert_eq!(
            top.iter()
                .map(|operation| operation.start)
                .collect::<Vec<_>>(),
            [0, 33, 289, 545, 801, 1_057, 3_693, 3_949, 4_205, 4_461]
        );
        assert_eq!(
            top.iter()
                .map(|operation| operation.words)
                .collect::<Vec<_>>(),
            [33, 256, 256, 256, 256, 2_636, 256, 256, 256, 256]
        );
        assert_eq!(
            top.iter()
                .map(|operation| operation.phase)
                .collect::<Vec<_>>(),
            [
                B4ParserPhase::OutputAndOuterPo2,
                B4ParserPhase::CodeMerkleTop,
                B4ParserPhase::DataMerkleTop,
                B4ParserPhase::AccumMerkleTop,
                B4ParserPhase::CheckMerkleTop,
                B4ParserPhase::CoefficientU,
                B4ParserPhase::FriRoundMerkleTop { round: 1 },
                B4ParserPhase::FriRoundMerkleTop { round: 2 },
                B4ParserPhase::FriRoundMerkleTop { round: 3 },
                B4ParserPhase::FinalCoefficients,
            ]
        );
        assert_eq!(
            TOP_LEVEL_WORD_SPANS.last().unwrap().end,
            grammar.exact_words
        );

        let query_zero = &grammar.operations[10..17];
        assert_eq!(
            query_zero
                .iter()
                .map(|operation| operation.phase)
                .collect::<Vec<_>>(),
            [
                B4ParserPhase::QueryOpening {
                    query: 0,
                    opening: B4ParserQueryOpening::Accum,
                },
                B4ParserPhase::QueryOpening {
                    query: 0,
                    opening: B4ParserQueryOpening::Code,
                },
                B4ParserPhase::QueryOpening {
                    query: 0,
                    opening: B4ParserQueryOpening::Data,
                },
                B4ParserPhase::QueryOpening {
                    query: 0,
                    opening: B4ParserQueryOpening::Check,
                },
                B4ParserPhase::QueryOpening {
                    query: 0,
                    opening: B4ParserQueryOpening::FriRoundOne,
                },
                B4ParserPhase::QueryOpening {
                    query: 0,
                    opening: B4ParserQueryOpening::FriRoundTwo,
                },
                B4ParserPhase::QueryOpening {
                    query: 0,
                    opening: B4ParserQueryOpening::FriRoundThree,
                },
            ]
        );
        assert_eq!(
            query_zero
                .iter()
                .map(|operation| operation.start - 4_717)
                .collect::<Vec<_>>(),
            QUERY_WORD_SPANS
                .iter()
                .map(|span| span.start)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            query_zero
                .iter()
                .map(|operation| operation.words)
                .collect::<Vec<_>>(),
            QUERY_WORD_SPANS
                .iter()
                .map(|span| span.len())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            grammar.locate_truncation(PROOF_WORDS - 1).unwrap().phase(),
            B4ParserPhase::QueryOpening {
                query: 49,
                opening: B4ParserQueryOpening::FriRoundThree,
            }
        );
    }

    #[test]
    fn exactly_the_thirty_six_plan_offsets_project_to_exact_stable_stages() {
        let grammar = grammar();
        let mut observed_offsets = CANONICAL_TRUNCATION_WORDS
            .into_iter()
            .map(|offset| (offset, grammar.locate_truncation(offset).unwrap()))
            .collect::<Vec<_>>();
        observed_offsets.sort_by_key(|(offset, _)| *offset);
        observed_offsets.dedup_by_key(|(offset, _)| *offset);
        assert_eq!(observed_offsets.len(), 36);
        for (offset, boundary) in &observed_offsets {
            assert_eq!(
                usize::try_from(boundary.cursor_words).unwrap()
                    + usize::try_from(boundary.available_words).unwrap(),
                *offset
            );
            assert!(
                boundary.available_words < boundary.required_words,
                "{boundary:?}"
            );
            assert!(
                boundary.planned_stage().is_some(),
                "planned offset {offset} has no stable parser stage"
            );
        }

        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let group = plan
            .groups
            .iter()
            .find(|group| group.case_id == "parser-phase-truncation-sweep")
            .unwrap();
        let mut planned = group
            .executions
            .iter()
            .map(|execution| {
                (
                    usize::try_from(execution.parser_truncation_words.unwrap()).unwrap(),
                    format!("risc0-read-iop-{}", execution.variant_id),
                )
            })
            .collect::<Vec<_>>();
        planned.sort_by_key(|(offset, _)| *offset);

        let projected = (0..grammar.exact_words)
            .filter_map(|offset| {
                grammar
                    .locate_truncation(offset)
                    .unwrap()
                    .planned_stage()
                    .map(|stage| (offset, stage.to_owned()))
            })
            .collect::<Vec<_>>();
        assert_eq!(projected, planned);
    }

    #[test]
    fn parser_stage_projection_is_tuple_exact_and_aliases_are_canonical() {
        let grammar = grammar();
        assert_eq!(
            grammar
                .locate_truncation(32)
                .unwrap()
                .planned_stage()
                .unwrap(),
            "risc0-read-iop-outer-po2-before-read"
        );
        assert_eq!(
            grammar
                .locate_truncation(4_717)
                .unwrap()
                .planned_stage()
                .unwrap(),
            "risc0-read-iop-queries-before-read"
        );
        assert_eq!(
            grammar
                .locate_truncation(55_666)
                .unwrap()
                .planned_stage()
                .unwrap(),
            "risc0-read-iop-queries-at-last-required-word"
        );

        let baseline = grammar.locate_truncation(0).unwrap();
        for mutated in [
            B4ParserBoundary {
                phase: B4ParserPhase::CodeMerkleTop,
                ..baseline
            },
            B4ParserBoundary {
                cursor_words: 1,
                ..baseline
            },
            B4ParserBoundary {
                required_words: 34,
                ..baseline
            },
            B4ParserBoundary {
                available_words: 1,
                ..baseline
            },
        ] {
            assert_eq!(mutated.planned_stage(), None, "{mutated:?}");
        }
    }

    #[test]
    fn every_read_operation_has_checked_before_last_and_after_boundaries() {
        let grammar = grammar();
        for (index, operation) in grammar.operations.iter().copied().enumerate() {
            let end = operation.end().unwrap();
            let before = grammar.locate_truncation(operation.start).unwrap();
            assert_eq!(before.phase, operation.phase);
            assert_eq!(before.available_words, 0);
            assert_eq!(
                usize::try_from(before.required_words).unwrap(),
                operation.words
            );

            let at_last = grammar.locate_truncation(end - 1).unwrap();
            assert_eq!(at_last.phase, operation.phase);
            assert_eq!(
                usize::try_from(at_last.available_words).unwrap(),
                operation.words - 1
            );

            if let Some(next) = grammar.operations.get(index + 1).copied() {
                let after = grammar.locate_truncation(end).unwrap();
                assert_eq!(after.phase, next.phase);
                assert_eq!(after.available_words, 0);
                if next.words > 1 {
                    let one_into_next = grammar.locate_truncation(end + 1).unwrap();
                    assert_eq!(one_into_next.phase, next.phase);
                    assert_eq!(one_into_next.available_words, 1);
                }
            } else {
                assert_eq!(
                    grammar.locate_truncation(end),
                    Err(B4ParserAdapterError::SubjectIsNotStrictPrefix {
                        actual_words: PROOF_WORDS,
                        exact_words: PROOF_WORDS
                    })
                );
            }
        }
    }

    #[test]
    fn malformed_framing_and_noncanonical_words_remain_private_failures() {
        assert_eq!(
            reject_parser_prefix(&[0], &[MANIFEST]),
            Err(B4ParserAdapterError::SubjectNotWordAligned { actual_bytes: 1 })
        );
        assert_eq!(
            reject_parser_prefix(&[], &[]),
            Err(B4ParserAdapterError::ContextCardinality {
                actual: 0,
                expected: 1
            })
        );
        let mut invalid_manifest = MANIFEST.to_vec();
        invalid_manifest[0] ^= 1;
        assert_eq!(
            reject_parser_prefix(&[], &[&invalid_manifest]),
            Err(B4ParserAdapterError::ProfileContext)
        );
        let mut unbound_constants = MANIFEST.to_vec();
        *unbound_constants.last_mut().unwrap() ^= 1;
        assert_eq!(
            reject_parser_prefix(&[], &[&unbound_constants]),
            Err(B4ParserAdapterError::GrammarAuthority)
        );
        assert_eq!(
            reject_parser_prefix(&BABY_BEAR_MODULUS.to_le_bytes(), &[MANIFEST]),
            Err(B4ParserAdapterError::WordNotReduced {
                index: 0,
                word: BABY_BEAR_MODULUS
            })
        );
        assert_eq!(
            reject_parser_prefix(&vec![0; PROOF_WORDS * 4], &[MANIFEST]),
            Err(B4ParserAdapterError::SubjectIsNotStrictPrefix {
                actual_words: PROOF_WORDS,
                exact_words: PROOF_WORDS
            })
        );
    }

    #[test]
    fn every_tracked_authentic_prefix_is_receipt_format_in_the_pinned_public_verifier() {
        let seal = AUTHENTICATED_PARSER_SEAL;
        assert_eq!(seal.len(), PROOF_WORDS * BYTES_PER_PROOF_WORD);
        let grammar = grammar();
        for words in CANONICAL_TRUNCATION_WORDS {
            let prefix = &seal[..words * BYTES_PER_PROOF_WORD];
            assert_eq!(
                reject_parser_prefix(prefix, &[MANIFEST]).unwrap(),
                grammar.locate_truncation(words).unwrap(),
                "pinned-verifier/parser disagreement at prefix word {words}"
            );
        }
    }
}
