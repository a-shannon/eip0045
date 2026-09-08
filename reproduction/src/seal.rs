//! Exact raw-seal byte/word grammar for the initial candidate profile.

use anyhow::{Result, anyhow, ensure};

use crate::constants::{PROOF_BYTES, PROOF_WORDS};
#[cfg(any(feature = "positive-gate", feature = "validator"))]
use crate::constants_artifact::{self, ConstantsArtifact};

/// One half-open word span in the frozen raw-seal grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealWordSpan {
    /// Stable implementer-facing region name.
    pub name: &'static str,
    /// Inclusive word offset.
    pub start: usize,
    /// Exclusive word offset.
    pub end: usize,
}

impl SealWordSpan {
    /// Number of words in this span.
    #[must_use]
    pub const fn len(self) -> usize {
        self.end - self.start
    }

    /// Whether this span contains no words.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }
}

/// Number of FRI query records in the initial profile.
pub const QUERY_COUNT: usize = 50;
/// Exact number of words in one FRI query record.
pub const QUERY_RECORD_WORDS: usize = 1_019;

/// Absolute top-level seal layout. Initial Merkle tops deliberately occur in
/// `code, data, accum, check` order.
pub const TOP_LEVEL_WORD_SPANS: [SealWordSpan; 12] = [
    SealWordSpan {
        name: "output",
        start: 0,
        end: 32,
    },
    SealWordSpan {
        name: "outerPo2",
        start: 32,
        end: 33,
    },
    SealWordSpan {
        name: "codeTop",
        start: 33,
        end: 289,
    },
    SealWordSpan {
        name: "dataTop",
        start: 289,
        end: 545,
    },
    SealWordSpan {
        name: "accumTop",
        start: 545,
        end: 801,
    },
    SealWordSpan {
        name: "checkTop",
        start: 801,
        end: 1_057,
    },
    SealWordSpan {
        name: "coeffU",
        start: 1_057,
        end: 3_693,
    },
    SealWordSpan {
        name: "friRound1Top",
        start: 3_693,
        end: 3_949,
    },
    SealWordSpan {
        name: "friRound2Top",
        start: 3_949,
        end: 4_205,
    },
    SealWordSpan {
        name: "friRound3Top",
        start: 4_205,
        end: 4_461,
    },
    SealWordSpan {
        name: "finalCoefficients",
        start: 4_461,
        end: 4_717,
    },
    SealWordSpan {
        name: "queries",
        start: 4_717,
        end: 55_667,
    },
];

/// Relative layout of each query record. Query openings deliberately occur in
/// `accum, code, data, check` order, unlike the initial Merkle tops.
pub const QUERY_WORD_SPANS: [SealWordSpan; 7] = [
    SealWordSpan {
        name: "accumOpening",
        start: 0,
        end: 132,
    },
    SealWordSpan {
        name: "codeOpening",
        start: 132,
        end: 275,
    },
    SealWordSpan {
        name: "dataOpening",
        start: 275,
        end: 523,
    },
    SealWordSpan {
        name: "checkOpening",
        start: 523,
        end: 659,
    },
    SealWordSpan {
        name: "friRound1Opening",
        start: 659,
        end: 811,
    },
    SealWordSpan {
        name: "friRound2Opening",
        start: 811,
        end: 931,
    },
    SealWordSpan {
        name: "friRound3Opening",
        start: 931,
        end: 1_019,
    },
];

#[cfg(any(feature = "positive-gate", feature = "validator"))]
const SEMANTIC_MERKLE_TOP_SPAN_INDICES: [usize; 7] = [2, 3, 4, 5, 7, 8, 9];
#[cfg(any(feature = "positive-gate", feature = "validator"))]
const SEMANTIC_MERKLE_TOP_SPAN_NAMES: [&str; 7] = [
    "codeTop",
    "dataTop",
    "accumTop",
    "checkTop",
    "friRound1Top",
    "friRound2Top",
    "friRound3Top",
];

/// Semantic raw-seal word families used by isolated B4 field mutations.
///
/// The order is closed and matches the negative-plan role order. It is not a
/// parser dispatch surface.
#[cfg(any(feature = "positive-gate", feature = "validator"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SealSemanticRole {
    /// Eight field-valued words of the 16-word inner control root. The
    /// interleaved odd words are the grammar's required zero padding.
    RootOutput,
    /// Sixteen field-valued receipt-claim output words.
    ClaimOutput,
    /// Seven serialized 256-word Merkle tops.
    MerkleTops,
    /// The `coeffU` coefficient block.
    Coefficients,
    /// The terminal FRI coefficient block.
    FinalCoefficients,
    /// Column values at every query opening.
    OpeningLeaves,
    /// Merkle sibling words at every query opening.
    OpeningSiblings,
}

#[cfg(any(feature = "positive-gate", feature = "validator"))]
#[allow(
    dead_code,
    reason = "the semantic authority is consumed by the next raw-producer task"
)]
impl SealSemanticRole {
    /// Exact closed role order.
    pub(crate) const ALL: [Self; 7] = [
        Self::RootOutput,
        Self::ClaimOutput,
        Self::MerkleTops,
        Self::Coefficients,
        Self::FinalCoefficients,
        Self::OpeningLeaves,
        Self::OpeningSiblings,
    ];

    const fn ordinal(self) -> usize {
        match self {
            Self::RootOutput => 0,
            Self::ClaimOutput => 1,
            Self::MerkleTops => 2,
            Self::Coefficients => 3,
            Self::FinalCoefficients => 4,
            Self::OpeningLeaves => 5,
            Self::OpeningSiblings => 6,
        }
    }
}

/// B2-bound semantic projection over the frozen absolute seal grammar.
///
/// Fields are private so producers cannot construct a projection from
/// unauthenticated widths or a caller-selected modulus.
#[cfg(any(feature = "positive-gate", feature = "validator"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SealSemanticProjection {
    modulus: u32,
    opening_column_widths: [usize; 7],
    words_by_role: [Vec<usize>; 7],
}

#[cfg(any(feature = "positive-gate", feature = "validator"))]
#[allow(
    dead_code,
    reason = "the semantic authority is consumed by the next raw-producer task"
)]
impl SealSemanticProjection {
    /// Candidate word indices for one role, in raw-seal serialization order.
    pub(crate) fn words(&self, role: SealSemanticRole) -> &[usize] {
        &self.words_by_role[role.ordinal()]
    }

    /// Column widths derived from authenticated B2 parameters.
    pub(crate) const fn opening_column_widths(&self) -> [usize; 7] {
        self.opening_column_widths
    }

    /// `BabyBear` modulus authenticated by B2.
    pub(crate) const fn modulus(&self) -> u32 {
        self.modulus
    }
}

/// One first-in-role byte-order rejection witness.
#[cfg(any(feature = "positive-gate", feature = "validator"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SealByteOrderCandidate {
    word_index: usize,
    original_word: u32,
    reversed_word: u32,
    before_bytes: [u8; 4],
    replacement_bytes: [u8; 4],
}

#[cfg(any(feature = "positive-gate", feature = "validator"))]
#[allow(
    dead_code,
    reason = "the semantic authority is consumed by the next raw-producer task"
)]
impl SealByteOrderCandidate {
    /// Absolute raw-seal word index.
    pub(crate) const fn word_index(self) -> usize {
        self.word_index
    }

    /// Canonical reduced word before mutation.
    pub(crate) const fn original_word(self) -> u32 {
        self.original_word
    }

    /// Little-endian value obtained after reversing the four serialized bytes.
    pub(crate) const fn reversed_word(self) -> u32 {
        self.reversed_word
    }

    /// Exact four source bytes.
    pub(crate) const fn before_bytes(self) -> [u8; 4] {
        self.before_bytes
    }

    /// Exact reversed replacement bytes.
    pub(crate) const fn replacement_bytes(self) -> [u8; 4] {
        self.replacement_bytes
    }
}

/// Derive all seven semantic candidate sets from authenticated B2 parameters
/// and the frozen absolute grammar in this module.
///
/// B2 decides the output width, opening-column widths, query count, and field
/// modulus. `TOP_LEVEL_WORD_SPANS` and `QUERY_WORD_SPANS` decide absolute
/// positions and serialized order. In the output grammar, the first half is a
/// 16-word inner-root encoding whose eight field values occupy the even words
/// and whose odd words are required zero padding; the second half is the
/// 16-word claim digest. This semantic split is an algorithm rule, not an
/// inference available from `output_size` alone.
///
/// # Errors
///
/// Returns an error if authenticated parameters and the frozen seal grammar do
/// not close the exact layout or candidate census.
#[cfg(any(feature = "positive-gate", feature = "validator"))]
#[allow(
    dead_code,
    reason = "the semantic authority is consumed by the next raw-producer task"
)]
pub(crate) fn derive_seal_semantic_projection(b2_bytes: &[u8]) -> Result<SealSemanticProjection> {
    let b2 = constants_artifact::verify_canonical(b2_bytes)?;
    derive_seal_semantic_projection_from_constants(&b2)
}

#[cfg(any(feature = "positive-gate", feature = "validator"))]
fn derive_seal_semantic_projection_from_constants(
    b2: &ConstantsArtifact,
) -> Result<SealSemanticProjection> {
    validate_seal_layout()?;
    let output = TOP_LEVEL_WORD_SPANS[0];
    let output_words = usize::from(b2.stark.output_size);
    ensure!(
        output.name == "output" && output.len() == output_words && output_words == 32,
        "authenticated B2 output width differs from the frozen output grammar"
    );
    ensure!(
        usize::from(b2.stark.queries) == QUERY_COUNT,
        "authenticated B2 query count differs from the frozen seal grammar"
    );
    let fri_width = usize::from(b2.stark.fri_fold)
        .checked_mul(usize::from(b2.baby_bear.extension_degree))
        .ok_or_else(|| anyhow!("authenticated B2 FRI opening width overflows"))?;
    let opening_column_widths = [
        usize::from(b2.taps.group_sizes[0]),
        usize::from(b2.taps.group_sizes[1]),
        usize::from(b2.taps.group_sizes[2]),
        usize::from(b2.stark.check_size),
        fri_width,
        fri_width,
        fri_width,
    ];
    ensure!(
        opening_column_widths == [12, 23, 128, 16, 64, 64, 64],
        "authenticated B2 opening widths differ from the frozen algorithm"
    );

    let root_output = (output.start..output.start + output_words / 2)
        .step_by(2)
        .collect::<Vec<_>>();
    let claim_output = (output.start + output_words / 2..output.end).collect::<Vec<_>>();
    ensure!(
        SEMANTIC_MERKLE_TOP_SPAN_INDICES.map(|index| TOP_LEVEL_WORD_SPANS[index].name)
            == SEMANTIC_MERKLE_TOP_SPAN_NAMES,
        "frozen Merkle-top positions or names differ from the algorithm"
    );
    let merkle_tops = SEMANTIC_MERKLE_TOP_SPAN_INDICES
        .map(|index| TOP_LEVEL_WORD_SPANS[index])
        .into_iter()
        .flat_map(|span| span.start..span.end)
        .collect::<Vec<_>>();
    let coefficients =
        (TOP_LEVEL_WORD_SPANS[6].start..TOP_LEVEL_WORD_SPANS[6].end).collect::<Vec<_>>();
    let final_coefficients =
        (TOP_LEVEL_WORD_SPANS[10].start..TOP_LEVEL_WORD_SPANS[10].end).collect::<Vec<_>>();

    let (opening_leaves, opening_siblings) = derive_opening_word_partition(opening_column_widths)?;

    let words_by_role = [
        root_output,
        claim_output,
        merkle_tops,
        coefficients,
        final_coefficients,
        opening_leaves,
        opening_siblings,
    ];
    let expected_counts = [8, 16, 1_792, 2_636, 256, 18_550, 32_400];
    ensure!(
        words_by_role.iter().map(Vec::len).eq(expected_counts),
        "derived semantic role census differs from the frozen algorithm"
    );
    for (role, words) in SealSemanticRole::ALL.iter().zip(&words_by_role) {
        ensure!(
            !words.is_empty()
                && words.iter().all(|word| *word < PROOF_WORDS)
                && words.windows(2).all(|pair| pair[0] < pair[1]),
            "derived {role:?} candidates are empty, out of bounds, or not serialized"
        );
    }
    Ok(SealSemanticProjection {
        modulus: b2.baby_bear.modulus,
        opening_column_widths,
        words_by_role,
    })
}

#[cfg(any(feature = "positive-gate", feature = "validator"))]
fn derive_opening_word_partition(
    opening_column_widths: [usize; 7],
) -> Result<(Vec<usize>, Vec<usize>)> {
    let query_region = TOP_LEVEL_WORD_SPANS[11];
    let leaf_words = opening_column_widths.iter().sum::<usize>();
    let mut opening_leaves = Vec::with_capacity(QUERY_COUNT * leaf_words);
    let mut opening_siblings = Vec::with_capacity(QUERY_COUNT * (QUERY_RECORD_WORDS - leaf_words));
    for query in 0..QUERY_COUNT {
        let query_start = query_region
            .start
            .checked_add(
                query
                    .checked_mul(QUERY_RECORD_WORDS)
                    .ok_or_else(|| anyhow!("query record offset overflows"))?,
            )
            .ok_or_else(|| anyhow!("query record offset overflows"))?;
        for (opening, width) in QUERY_WORD_SPANS.iter().zip(opening_column_widths) {
            ensure!(
                width <= opening.len(),
                "authenticated B2 opening width exceeds the frozen opening span"
            );
            let leaf_start = query_start
                .checked_add(opening.start)
                .ok_or_else(|| anyhow!("opening leaf offset overflows"))?;
            let leaf_end = leaf_start
                .checked_add(width)
                .ok_or_else(|| anyhow!("opening leaf width overflows"))?;
            let opening_end = query_start
                .checked_add(opening.end)
                .ok_or_else(|| anyhow!("opening sibling offset overflows"))?;
            opening_leaves.extend(leaf_start..leaf_end);
            opening_siblings.extend(leaf_end..opening_end);
        }
    }
    Ok((opening_leaves, opening_siblings))
}

/// Return the first serialized word of one semantic role.
///
/// # Errors
///
/// Returns an error only if the authenticated projection is internally empty.
#[cfg(any(feature = "positive-gate", feature = "validator"))]
#[allow(
    dead_code,
    reason = "the semantic authority is consumed by the next raw-producer task"
)]
pub(crate) fn fixed_semantic_representative(
    projection: &SealSemanticProjection,
    role: SealSemanticRole,
) -> Result<usize> {
    projection
        .words(role)
        .first()
        .copied()
        .ok_or_else(|| anyhow!("authenticated semantic role has no representative"))
}

/// Select the first role-local word whose serialized byte reversal is a
/// distinct non-canonical `BabyBear` value.
///
/// The complete base is range-checked before the role scan. A non-reduced word
/// anywhere therefore fails before a candidate can be returned.
///
/// # Errors
///
/// Returns an error for wrong seal length, any non-reduced base word, or if the
/// selected role contains no qualifying first rejection.
#[cfg(any(feature = "positive-gate", feature = "validator"))]
#[allow(
    dead_code,
    reason = "the semantic authority is consumed by the next raw-producer task"
)]
pub(crate) fn first_byte_order_candidate(
    raw_seal: &[u8],
    projection: &SealSemanticProjection,
    role: SealSemanticRole,
) -> Result<SealByteOrderCandidate> {
    let words = decode_seal_words(raw_seal)?;
    if let Some((word_index, word)) = words
        .iter()
        .copied()
        .enumerate()
        .find(|(_, word)| *word >= projection.modulus)
    {
        return Err(anyhow!(
            "raw-seal base contains a non-reduced word at index {word_index}: {word}"
        ));
    }
    for &word_index in projection.words(role) {
        let original_word = words[word_index];
        let before_bytes = original_word.to_le_bytes();
        let replacement_bytes = [
            before_bytes[3],
            before_bytes[2],
            before_bytes[1],
            before_bytes[0],
        ];
        let reversed_word = u32::from_le_bytes(replacement_bytes);
        if replacement_bytes != before_bytes && reversed_word >= projection.modulus {
            return Ok(SealByteOrderCandidate {
                word_index,
                original_word,
                reversed_word,
                before_bytes,
                replacement_bytes,
            });
        }
    }
    Err(anyhow!(
        "raw-seal role {role:?} has no byte-order rejection candidate"
    ))
}

/// Validate every census and contiguity equation in the frozen seal layout.
///
/// # Errors
///
/// Returns an error if a span is empty, overlaps, leaves a gap, or if the query
/// census does not end at the frozen proof length.
pub fn validate_seal_layout() -> Result<()> {
    validate_contiguous(&TOP_LEVEL_WORD_SPANS, 0, PROOF_WORDS, "top-level")?;
    validate_contiguous(&QUERY_WORD_SPANS, 0, QUERY_RECORD_WORDS, "query-record")?;
    let query_region = TOP_LEVEL_WORD_SPANS
        .last()
        .copied()
        .ok_or_else(|| anyhow!("raw-seal top-level layout is empty"))?;
    let expected_query_words = QUERY_COUNT
        .checked_mul(QUERY_RECORD_WORDS)
        .ok_or_else(|| anyhow!("raw-seal query census overflow"))?;
    ensure!(
        query_region.name == "queries" && query_region.len() == expected_query_words,
        "raw-seal query region has {} words, expected {expected_query_words}",
        query_region.len()
    );
    Ok(())
}

fn validate_contiguous(
    spans: &[SealWordSpan],
    expected_start: usize,
    expected_end: usize,
    label: &str,
) -> Result<()> {
    let mut cursor = expected_start;
    for span in spans {
        ensure!(
            span.start == cursor && span.end > span.start,
            "raw-seal {label} span {} is non-contiguous or empty",
            span.name
        );
        cursor = span.end;
    }
    ensure!(
        cursor == expected_end,
        "raw-seal {label} layout ends at {cursor}, expected {expected_end}"
    );
    Ok(())
}

/// Decode exact little-endian raw-seal bytes to words.
///
/// # Errors
///
/// Returns an error unless the input length is exactly the frozen proof length.
/// In particular, this profile has no FRI grinding nonce or optional trailing
/// word: any appended bytes are rejected before decoding.
pub fn decode_seal_words(raw_seal: &[u8]) -> Result<Vec<u32>> {
    validate_seal_layout()?;
    ensure!(
        raw_seal.len() == PROOF_BYTES,
        "raw seal has {} bytes, expected {PROOF_BYTES}",
        raw_seal.len()
    );
    raw_seal
        .chunks_exact(4)
        .map(|chunk| {
            let bytes: [u8; 4] = chunk
                .try_into()
                .map_err(|_| anyhow!("internal raw-seal chunk length mismatch"))?;
            Ok(u32::from_le_bytes(bytes))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(feature = "positive-gate", feature = "validator"))]
    const FROZEN_B2: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/constants.bin");

    #[test]
    fn executable_layout_matches_the_full_frozen_census() {
        validate_seal_layout().unwrap();
        assert_eq!(TOP_LEVEL_WORD_SPANS[11].len(), 50_950);
        assert_eq!(
            QUERY_WORD_SPANS.map(SealWordSpan::len),
            [132, 143, 248, 136, 152, 120, 88]
        );
        assert_eq!(
            TOP_LEVEL_WORD_SPANS[2..6]
                .iter()
                .map(|span| span.name)
                .collect::<Vec<_>>(),
            ["codeTop", "dataTop", "accumTop", "checkTop"]
        );
        assert_eq!(
            QUERY_WORD_SPANS[..4]
                .iter()
                .map(|span| span.name)
                .collect::<Vec<_>>(),
            ["accumOpening", "codeOpening", "dataOpening", "checkOpening"]
        );
    }

    #[test]
    fn decoder_is_exact_little_endian_and_length_gated() {
        let mut raw = vec![0_u8; PROOF_BYTES];
        raw[..8].copy_from_slice(&[1, 2, 3, 4, 0xfc, 0xfd, 0xfe, 0xff]);
        let words = decode_seal_words(&raw).unwrap();
        assert_eq!(words.len(), PROOF_WORDS);
        assert_eq!(words[0], 0x0403_0201);
        assert_eq!(words[1], 0xfffe_fdfc);
        assert!(decode_seal_words(&raw[..raw.len() - 1]).is_err());
    }

    #[test]
    fn decoder_rejects_an_appended_grinding_nonce_word() {
        let mut raw = vec![0_u8; PROOF_BYTES];
        raw.extend_from_slice(&0x4433_2211_u32.to_le_bytes());
        let error = decode_seal_words(&raw).unwrap_err();
        assert!(error.to_string().contains(&format!(
            "raw seal has {} bytes, expected {PROOF_BYTES}",
            PROOF_BYTES + 4
        )));
    }

    #[cfg(any(feature = "positive-gate", feature = "validator"))]
    fn semantic_projection() -> SealSemanticProjection {
        derive_seal_semantic_projection(FROZEN_B2).unwrap()
    }

    #[cfg(any(feature = "positive-gate", feature = "validator"))]
    #[test]
    fn semantic_projection_has_the_exact_seven_sets_counts_and_serialized_order() {
        let projection = semantic_projection();
        assert_eq!(SealSemanticRole::ALL.len(), 7);
        assert_eq!(
            SealSemanticRole::ALL.map(|role| projection.words(role).len()),
            [8, 16, 1_792, 2_636, 256, 18_550, 32_400]
        );
        assert_eq!(
            projection.words(SealSemanticRole::RootOutput),
            &[0, 2, 4, 6, 8, 10, 12, 14]
        );
        assert_eq!(
            projection.words(SealSemanticRole::ClaimOutput),
            (16..32).collect::<Vec<_>>()
        );
        assert_eq!(
            projection.words(SealSemanticRole::Coefficients),
            (1_057..3_693).collect::<Vec<_>>()
        );
        assert_eq!(
            projection.words(SealSemanticRole::FinalCoefficients),
            (4_461..4_717).collect::<Vec<_>>()
        );

        let expected_tops = [2, 3, 4, 5, 7, 8, 9]
            .map(|index| TOP_LEVEL_WORD_SPANS[index])
            .into_iter()
            .flat_map(|span| span.start..span.end)
            .collect::<Vec<_>>();
        assert_eq!(
            projection.words(SealSemanticRole::MerkleTops),
            expected_tops
        );
        for role in SealSemanticRole::ALL {
            assert!(
                projection
                    .words(role)
                    .windows(2)
                    .all(|pair| pair[0] < pair[1]),
                "{role:?} is not in serialized word order"
            );
        }
    }

    #[cfg(any(feature = "positive-gate", feature = "validator"))]
    #[test]
    fn semantic_projection_rejects_same_length_b2_byte_drift() {
        let mut changed = FROZEN_B2.to_vec();
        changed[0] ^= 1;
        assert!(derive_seal_semantic_projection(&changed).is_err());
    }

    #[cfg(any(feature = "positive-gate", feature = "validator"))]
    #[test]
    fn opening_partition_uses_corrected_fri_widths_and_covers_every_query_once() {
        let projection = semantic_projection();
        let widths = projection.opening_column_widths();
        assert_eq!(widths, [12, 23, 128, 16, 64, 64, 64]);

        let leaves = projection.words(SealSemanticRole::OpeningLeaves);
        let siblings = projection.words(SealSemanticRole::OpeningSiblings);
        let query_region = TOP_LEVEL_WORD_SPANS[11];
        let mut leaf_cursor = 0;
        let mut sibling_cursor = 0;
        for query in 0..QUERY_COUNT {
            let query_start = query_region.start + query * QUERY_RECORD_WORDS;
            let mut combined = Vec::with_capacity(QUERY_RECORD_WORDS);
            for (opening, width) in QUERY_WORD_SPANS.iter().zip(widths) {
                let leaf_start = query_start + opening.start;
                let leaf_end = leaf_start + width;
                let sibling_end = query_start + opening.end;
                let query_leaves = &leaves[leaf_cursor..leaf_cursor + width];
                let sibling_count = sibling_end - leaf_end;
                let query_siblings = &siblings[sibling_cursor..sibling_cursor + sibling_count];
                assert_eq!(query_leaves, (leaf_start..leaf_end).collect::<Vec<_>>());
                assert_eq!(query_siblings, (leaf_end..sibling_end).collect::<Vec<_>>());
                combined.extend_from_slice(query_leaves);
                combined.extend_from_slice(query_siblings);
                leaf_cursor += width;
                sibling_cursor += sibling_count;
            }
            combined.sort_unstable();
            assert_eq!(
                combined,
                (query_start..query_start + QUERY_RECORD_WORDS).collect::<Vec<_>>()
            );
        }
        assert_eq!(leaf_cursor, leaves.len());
        assert_eq!(sibling_cursor, siblings.len());
    }

    #[cfg(any(feature = "positive-gate", feature = "validator"))]
    #[test]
    fn fixed_representatives_are_derived_from_each_roles_first_serialized_word() {
        let projection = semantic_projection();
        assert_eq!(
            SealSemanticRole::ALL
                .map(|role| fixed_semantic_representative(&projection, role).unwrap()),
            [0, 16, 33, 1_057, 4_461, 4_717, 4_729]
        );
    }

    #[cfg(any(feature = "positive-gate", feature = "validator"))]
    #[test]
    fn byte_order_selection_is_first_in_role_and_fails_closed_on_absence_or_any_non_reduced_word() {
        let projection = semantic_projection();
        let candidate_word = 0x0100_0078_u32;
        assert_eq!(candidate_word.swap_bytes(), projection.modulus());

        for role in SealSemanticRole::ALL {
            let role_words = projection.words(role);
            let mut first = vec![0_u8; PROOF_BYTES];
            for &word_index in role_words.iter().take(2) {
                first[word_index * 4..word_index * 4 + 4]
                    .copy_from_slice(&candidate_word.to_le_bytes());
            }
            let selected = first_byte_order_candidate(&first, &projection, role).unwrap();
            assert_eq!(selected.word_index(), role_words[0]);
            assert_eq!(selected.original_word(), candidate_word);
            assert_eq!(selected.reversed_word(), projection.modulus());
            assert_eq!(selected.before_bytes(), candidate_word.to_le_bytes());
            assert_eq!(selected.replacement_bytes(), candidate_word.to_be_bytes());

            let mut later = vec![0_u8; PROOF_BYTES];
            later[role_words[0] * 4..role_words[0] * 4 + 4].copy_from_slice(&1_u32.to_le_bytes());
            later[role_words[1] * 4..role_words[1] * 4 + 4]
                .copy_from_slice(&candidate_word.to_le_bytes());
            assert_eq!(
                first_byte_order_candidate(&later, &projection, role)
                    .unwrap()
                    .word_index(),
                role_words[1]
            );

            assert!(
                first_byte_order_candidate(&vec![0_u8; PROOF_BYTES], &projection, role).is_err()
            );

            let mut non_reduced_elsewhere = first;
            let outside_role = (0..PROOF_WORDS)
                .find(|word| !role_words.contains(word))
                .unwrap();
            non_reduced_elsewhere[outside_role * 4..outside_role * 4 + 4]
                .copy_from_slice(&projection.modulus().to_le_bytes());
            let error =
                first_byte_order_candidate(&non_reduced_elsewhere, &projection, role).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("base contains a non-reduced word")
            );
        }
    }

    #[cfg(any(feature = "positive-gate", feature = "validator"))]
    #[test]
    #[ignore = "preflight-only: requires EIP0045_B4_REAL_VECTOR_ROOT with candidate-raw-seal.bin"]
    fn known_preflight_only_real_seal_derives_its_reviewed_role_selection_tuple() {
        use sha2::{Digest as _, Sha256};

        // These two exact digests corroborate selection mechanics only. They
        // are neither final B4 case authority nor handler-freeze evidence.
        let root = std::env::var_os("EIP0045_B4_REAL_VECTOR_ROOT").unwrap();
        let path = std::path::Path::new(&root)
            .join("proof/candidate-proof-export/proof-output/candidate-raw-seal.bin");
        let raw_seal = std::fs::read(path).unwrap();
        let digest = hex::encode(Sha256::digest(&raw_seal));
        let expected = match digest.as_str() {
            "088e6a306c7143f5a3e057924c42f63a6eb58dd3c30686a8ade5082fac4b386e" => {
                [0, 16, 33, 1_057, 4_461, 4_717, 4_729]
            }
            "d7bdef7d0b3759a6d8ba43c9b531b017112b07e42af2761fbe654a596d759d79" => {
                [0, 16, 35, 1_057, 4_461, 4_719, 4_732]
            }
            _ => panic!("the supplied raw seal is not either reviewed preflight vector"),
        };
        let projection = semantic_projection();
        let actual = SealSemanticRole::ALL.map(|role| {
            first_byte_order_candidate(&raw_seal, &projection, role)
                .unwrap()
                .word_index()
        });
        assert_eq!(actual, expected);
    }
}
