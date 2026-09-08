//! Direct, bounded verification of the initial profile's raw succinct STARK.

use risc0_zkp::{
    adapter::CircuitInfo,
    core::hash::poseidon2::Poseidon2HashSuite,
    field::baby_bear::{BabyBearElem, P as BABY_BEAR_MODULUS},
};

#[cfg(any(feature = "validator", test))]
use crate::constants::B4_ALTERNATE_CONTROL_ROOT;
use crate::{
    constants::{PROOF_BYTES, PROOF_WORDS},
    profile_manifest::StarkProfileManifestV1,
    seal::decode_seal_words,
};

use super::{
    errors::B4StarkError,
    terminal::{B4VerifiedTerminal, TerminalCapture},
};

const OUTPUT_WORDS: usize = 32;
const INNER_ROOT_WORDS: usize = 16;
const CLAIM_WORDS: usize = 16;
const OUTER_PO2_WORD_INDEX: usize = OUTPUT_WORDS;
const _: () =
    assert!(<risc0_circuit_recursion::CircuitImpl as CircuitInfo>::OUTPUT_SIZE == OUTPUT_WORDS);

/// STARK-verified envelope whose output globals are not yet profile-root bound.
///
/// This type has no public constructor. It is returned only after the pinned
/// upstream verifier completes, including strict IOP EOF, and the terminal
/// callback has succeeded exactly once.
pub(super) struct VerifiedStarkEnvelope {
    globals: VerifiedOutputGlobals,
    terminal: B4VerifiedTerminal,
    expected_inner_control_root: [u8; 32],
}

impl VerifiedStarkEnvelope {
    /// Consume this state and bind the verified output to the same manifest
    /// root used during terminal verification.
    ///
    /// # Errors
    ///
    /// Returns [`B4StarkError::InnerControlRootMismatch`] when the verified
    /// output root differs from the authenticated profile manifest.
    pub(super) fn bind_inner_control_root(self) -> Result<RootBoundStarkEnvelope, B4StarkError> {
        let expected = self.expected_inner_control_root;
        self.bind_exact_inner_control_root(expected)
    }

    /// Consume this state and bind the verified output to the one fixed B4
    /// alternate-root witness.
    ///
    /// This named transition exposes no caller-selected root. It exists only
    /// for the independently generated negative-campaign witness and does not
    /// make that root part of the activated profile.
    #[cfg(any(feature = "validator", test))]
    pub(super) fn bind_fixed_alternate_inner_control_root(
        self,
    ) -> Result<RootBoundStarkEnvelope, B4StarkError> {
        self.bind_exact_inner_control_root(B4_ALTERNATE_CONTROL_ROOT)
    }

    fn bind_exact_inner_control_root(
        self,
        expected: [u8; 32],
    ) -> Result<RootBoundStarkEnvelope, B4StarkError> {
        let actual = decode_inner_control_root(&self.globals.words)?;
        if actual != expected {
            return Err(B4StarkError::InnerControlRootMismatch { expected, actual });
        }
        Ok(RootBoundStarkEnvelope {
            globals: self.globals,
            terminal: self.terminal,
            inner_control_root: actual,
        })
    }
}

/// STARK-verified envelope bound to one closed expected inner control root.
///
/// The claim output remains unavailable until [`Self::bind_claim`] succeeds.
pub(super) struct RootBoundStarkEnvelope {
    globals: VerifiedOutputGlobals,
    terminal: B4VerifiedTerminal,
    inner_control_root: [u8; 32],
}

impl RootBoundStarkEnvelope {
    /// Consume this state and bind the verified output to an independently
    /// derived successful receipt claim.
    ///
    /// # Errors
    ///
    /// Returns [`B4StarkError::ClaimDigestMismatch`] when the verified output
    /// claim differs from `expected_claim`.
    pub(super) fn bind_claim(
        self,
        expected_claim: [u8; 32],
    ) -> Result<ClaimBoundStarkEnvelope, B4StarkError> {
        let actual = decode_claim_digest(&self.globals.words)?;
        if actual != expected_claim {
            return Err(B4StarkError::ClaimDigestMismatch {
                expected: expected_claim,
                actual,
            });
        }
        Ok(ClaimBoundStarkEnvelope {
            terminal: self.terminal,
            inner_control_root: self.inner_control_root,
            claim_digest: actual,
        })
    }
}

/// Final STARK envelope bound to the terminal, inner root, and expected claim.
///
/// Construction order is enforced by consuming transitions:
/// `VerifiedStarkEnvelope -> RootBoundStarkEnvelope -> ClaimBoundStarkEnvelope`.
pub(super) struct ClaimBoundStarkEnvelope {
    terminal: B4VerifiedTerminal,
    inner_control_root: [u8; 32],
    claim_digest: [u8; 32],
}

impl ClaimBoundStarkEnvelope {
    /// Terminal tuple authenticated by the completed STARK.
    #[must_use]
    pub(super) const fn terminal(&self) -> B4VerifiedTerminal {
        self.terminal
    }

    /// Closed expected inner root authenticated by the completed STARK.
    #[must_use]
    pub(super) const fn inner_control_root(&self) -> [u8; 32] {
        self.inner_control_root
    }

    /// Independently expected claim authenticated by the completed STARK.
    #[must_use]
    pub(super) const fn claim_digest(&self) -> [u8; 32] {
        self.claim_digest
    }
}

struct PreflightStarkEnvelope {
    seal_words: Vec<u32>,
    globals: UntrustedOutputGlobals,
    expected_inner_control_root: [u8; 32],
}

struct UntrustedOutputGlobals {
    words: [u32; OUTPUT_WORDS],
}

struct VerifiedOutputGlobals {
    words: [u32; OUTPUT_WORDS],
}

/// Verify one exact raw seal with the pinned recursion circuit and Poseidon2
/// suite.
///
/// No verifier implementation, circuit, hash suite, control ID, query count,
/// depth, or cost parameter is caller-injectable. The supplied manifest must
/// first equal the frozen initial-profile target. Raw output globals are kept
/// private and do not become root/claim authority until the two consuming
/// binding transitions succeed.
///
/// # Errors
///
/// Returns the first typed preflight, terminal-policy, or upstream-verifier
/// failure. A value is returned only after upstream verification reaches
/// strict proof EOF.
pub(super) fn verify_stark(
    manifest: &StarkProfileManifestV1,
    raw_seal: &[u8],
) -> Result<VerifiedStarkEnvelope, B4StarkError> {
    manifest
        .validate_initial_profile_target()
        .map_err(|_| B4StarkError::InitialProfileTarget)?;
    let prepared = preflight(manifest, raw_seal)?;
    let capture = TerminalCapture::new(manifest);
    let suite = Poseidon2HashSuite::new_suite();
    let upstream = risc0_zkp::verify::verify(
        &risc0_circuit_recursion::CIRCUIT,
        &suite,
        &prepared.seal_words,
        |po2, code_root| capture.check_code(po2, code_root),
    );
    let terminal = capture.finish(upstream)?;

    Ok(VerifiedStarkEnvelope {
        globals: VerifiedOutputGlobals {
            words: prepared.globals.words,
        },
        terminal,
        expected_inner_control_root: prepared.expected_inner_control_root,
    })
}

fn preflight(
    manifest: &StarkProfileManifestV1,
    raw_seal: &[u8],
) -> Result<PreflightStarkEnvelope, B4StarkError> {
    if raw_seal.len() != PROOF_BYTES {
        return Err(B4StarkError::RawSealLength {
            actual: raw_seal.len(),
            expected: PROOF_BYTES,
        });
    }
    let seal_words = decode_seal_words(raw_seal).map_err(|_| B4StarkError::RawSealDecode)?;
    if seal_words.len() != PROOF_WORDS {
        return Err(B4StarkError::RawSealDecode);
    }

    for (index, word) in seal_words.iter().copied().enumerate() {
        if word >= BABY_BEAR_MODULUS {
            return Err(B4StarkError::RawSealWordNotReduced { index, word });
        }
    }

    let actual_outer_po2 = seal_words[OUTER_PO2_WORD_INDEX];
    let expected_outer_po2 = u32::from(manifest.outer_po2());
    if actual_outer_po2 != expected_outer_po2 {
        return Err(B4StarkError::OuterPo2Mismatch {
            actual: actual_outer_po2,
            expected: expected_outer_po2,
        });
    }

    let globals = UntrustedOutputGlobals {
        words: seal_words[..OUTPUT_WORDS]
            .try_into()
            .map_err(|_| B4StarkError::RawSealDecode)?,
    };
    validate_output_shape(&globals.words)?;

    Ok(PreflightStarkEnvelope {
        seal_words,
        globals,
        expected_inner_control_root: manifest.inner_control_root(),
    })
}

fn validate_output_shape(globals: &[u32; OUTPUT_WORDS]) -> Result<(), B4StarkError> {
    for index in (1..INNER_ROOT_WORDS).step_by(2) {
        if globals[index] != 0 {
            return Err(B4StarkError::NonzeroInnerRootPadding { index });
        }
    }
    for (offset, raw_word) in globals[INNER_ROOT_WORDS..OUTPUT_WORDS]
        .iter()
        .copied()
        .enumerate()
    {
        let index = INNER_ROOT_WORDS + offset;
        let value = BabyBearElem::new_raw(raw_word).as_u32();
        if u16::try_from(value).is_err() {
            return Err(B4StarkError::ClaimHalfwordOutOfRange { index, value });
        }
    }
    Ok(())
}

fn decode_inner_control_root(globals: &[u32; OUTPUT_WORDS]) -> Result<[u8; 32], B4StarkError> {
    let mut root = [0_u8; 32];
    for (root_index, seal_index) in (0..INNER_ROOT_WORDS).step_by(2).enumerate() {
        let word = globals[seal_index];
        if word >= BABY_BEAR_MODULUS {
            return Err(B4StarkError::RawSealWordNotReduced {
                index: seal_index,
                word,
            });
        }
        if globals[seal_index + 1] != 0 {
            return Err(B4StarkError::NonzeroInnerRootPadding {
                index: seal_index + 1,
            });
        }
        let decoded = BabyBearElem::new_raw(word).as_u32();
        root[root_index * 4..root_index * 4 + 4].copy_from_slice(&decoded.to_le_bytes());
    }
    Ok(root)
}

fn decode_claim_digest(globals: &[u32; OUTPUT_WORDS]) -> Result<[u8; 32], B4StarkError> {
    let mut claim = [0_u8; 32];
    for (offset, raw_word) in globals[INNER_ROOT_WORDS..INNER_ROOT_WORDS + CLAIM_WORDS]
        .iter()
        .copied()
        .enumerate()
    {
        let index = INNER_ROOT_WORDS + offset;
        if raw_word >= BABY_BEAR_MODULUS {
            return Err(B4StarkError::RawSealWordNotReduced {
                index,
                word: raw_word,
            });
        }
        let value = BabyBearElem::new_raw(raw_word).as_u32();
        let halfword = u16::try_from(value)
            .map_err(|_| B4StarkError::ClaimHalfwordOutOfRange { index, value })?;
        claim[offset * 2..offset * 2 + 2].copy_from_slice(&halfword.to_le_bytes());
    }
    Ok(claim)
}

#[cfg(test)]
mod tests {
    use super::*;
    use risc0_zkp::core::digest::Digest;

    const MANIFEST: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");

    fn manifest() -> StarkProfileManifestV1 {
        let manifest = StarkProfileManifestV1::decode(MANIFEST).unwrap();
        manifest.validate_initial_profile_target().unwrap();
        manifest
    }

    fn bounded_raw_seal() -> Vec<u8> {
        let mut raw = vec![0_u8; PROOF_BYTES];
        raw[OUTER_PO2_WORD_INDEX * 4..OUTER_PO2_WORD_INDEX * 4 + 4]
            .copy_from_slice(&u32::from(manifest().outer_po2()).to_le_bytes());
        raw
    }

    fn set_word(raw: &mut [u8], index: usize, word: u32) {
        raw[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }

    fn terminal(manifest: &StarkProfileManifestV1) -> B4VerifiedTerminal {
        let control = manifest.terminal_controls()[0];
        let mut words = [0_u32; 8];
        for (index, chunk) in control.control_id().chunks_exact(4).enumerate() {
            words[index] = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        let digest = Digest::from(words);
        let capture = TerminalCapture::new(manifest);
        capture
            .check_code(u32::from(manifest.outer_po2()), &digest)
            .unwrap();
        capture.finish(Ok(())).unwrap()
    }

    fn synthetic_verified_envelope(
        manifest: &StarkProfileManifestV1,
        claim: [u8; 32],
    ) -> VerifiedStarkEnvelope {
        synthetic_verified_envelope_with_root(manifest, claim, manifest.inner_control_root())
    }

    fn synthetic_verified_envelope_with_root(
        manifest: &StarkProfileManifestV1,
        claim: [u8; 32],
        inner_control_root: [u8; 32],
    ) -> VerifiedStarkEnvelope {
        let mut words = [0_u32; OUTPUT_WORDS];
        for (index, chunk) in inner_control_root.chunks_exact(4).enumerate() {
            let decoded = u32::from_le_bytes(chunk.try_into().unwrap());
            words[index * 2] = BabyBearElem::new(decoded).as_u32_montgomery();
        }
        for (index, chunk) in claim.chunks_exact(2).enumerate() {
            let decoded = u32::from(u16::from_le_bytes(chunk.try_into().unwrap()));
            words[INNER_ROOT_WORDS + index] = BabyBearElem::new(decoded).as_u32_montgomery();
        }
        VerifiedStarkEnvelope {
            globals: VerifiedOutputGlobals { words },
            terminal: terminal(manifest),
            expected_inner_control_root: manifest.inner_control_root(),
        }
    }

    #[test]
    fn preflight_checks_length_before_allocating_or_decoding() {
        let manifest = manifest();
        for actual in [0, PROOF_BYTES - 1, PROOF_BYTES + 1] {
            let raw = vec![0_u8; actual];
            assert_eq!(
                preflight(&manifest, &raw).err(),
                Some(B4StarkError::RawSealLength {
                    actual,
                    expected: PROOF_BYTES,
                })
            );
        }
    }

    #[test]
    fn preflight_checks_every_word_is_a_reduced_babybear_element() {
        let manifest = manifest();
        for index in [0, 16, OUTER_PO2_WORD_INDEX, 33, PROOF_WORDS - 1] {
            let mut raw = bounded_raw_seal();
            set_word(&mut raw, index, BABY_BEAR_MODULUS);
            assert_eq!(
                preflight(&manifest, &raw).err(),
                Some(B4StarkError::RawSealWordNotReduced {
                    index,
                    word: BABY_BEAR_MODULUS,
                })
            );
        }
    }

    #[test]
    fn preflight_rejects_each_nonzero_root_padding_word() {
        let manifest = manifest();
        for index in (1..INNER_ROOT_WORDS).step_by(2) {
            let mut raw = bounded_raw_seal();
            set_word(&mut raw, index, 1);
            assert_eq!(
                preflight(&manifest, &raw).err(),
                Some(B4StarkError::NonzeroInnerRootPadding { index })
            );
        }
    }

    #[test]
    fn preflight_rejects_a_montgomery_decoded_claim_value_above_u16() {
        let manifest = manifest();
        let index = INNER_ROOT_WORDS + 7;
        let mut raw = bounded_raw_seal();
        set_word(
            &mut raw,
            index,
            BabyBearElem::new(0x1_0000).as_u32_montgomery(),
        );

        assert_eq!(
            preflight(&manifest, &raw).err(),
            Some(B4StarkError::ClaimHalfwordOutOfRange {
                index,
                value: 0x1_0000,
            })
        );
    }

    #[test]
    fn preflight_rejects_the_wrong_outer_po2_before_upstream_verification() {
        let manifest = manifest();
        let mut raw = bounded_raw_seal();
        set_word(
            &mut raw,
            OUTER_PO2_WORD_INDEX,
            u32::from(manifest.outer_po2()) + 1,
        );

        assert_eq!(
            preflight(&manifest, &raw).err(),
            Some(B4StarkError::OuterPo2Mismatch {
                actual: u32::from(manifest.outer_po2()) + 1,
                expected: u32::from(manifest.outer_po2()),
            })
        );
    }

    #[test]
    fn structurally_bounded_zero_body_reaches_the_prepared_state_only() {
        let manifest = manifest();
        let prepared = preflight(&manifest, &bounded_raw_seal()).unwrap();

        assert_eq!(prepared.seal_words.len(), PROOF_WORDS);
        assert_eq!(
            prepared.seal_words[OUTER_PO2_WORD_INDEX],
            u32::from(manifest.outer_po2())
        );
        assert_eq!(prepared.globals.words[0], 0);
        assert_eq!(
            prepared.expected_inner_control_root,
            manifest.inner_control_root()
        );
    }

    #[test]
    fn root_and_claim_bindings_are_separate_consuming_states() {
        let manifest = manifest();
        let claim = core::array::from_fn(|index| u8::try_from(index).unwrap());
        let verified = synthetic_verified_envelope(&manifest, claim);

        let root_bound = verified.bind_inner_control_root().unwrap();
        assert_eq!(root_bound.inner_control_root, manifest.inner_control_root());
        assert_eq!(root_bound.terminal.parameter(), 15);

        let claim_bound = root_bound.bind_claim(claim).unwrap();
        assert_eq!(claim_bound.claim_digest(), claim);
        assert_eq!(
            claim_bound.inner_control_root(),
            manifest.inner_control_root()
        );
        assert_eq!(claim_bound.terminal().parameter(), 15);
    }

    #[test]
    fn alternate_root_binding_is_named_and_exact() {
        let manifest = manifest();
        let claim = [0x3c; 32];
        let alternate =
            synthetic_verified_envelope_with_root(&manifest, claim, B4_ALTERNATE_CONTROL_ROOT)
                .bind_fixed_alternate_inner_control_root()
                .unwrap()
                .bind_claim(claim)
                .unwrap();
        assert_eq!(alternate.inner_control_root(), B4_ALTERNATE_CONTROL_ROOT);

        assert!(matches!(
            synthetic_verified_envelope(&manifest, claim).bind_fixed_alternate_inner_control_root(),
            Err(B4StarkError::InnerControlRootMismatch { .. })
        ));
    }

    #[test]
    fn post_stark_root_and_claim_mismatches_stay_distinct() {
        let manifest = manifest();
        let claim = [0x5a; 32];

        let mut wrong_root = synthetic_verified_envelope(&manifest, claim);
        wrong_root.globals.words[0] = BabyBearElem::new(1).as_u32_montgomery();
        assert!(matches!(
            wrong_root.bind_inner_control_root(),
            Err(B4StarkError::InnerControlRootMismatch { .. })
        ));

        let root_bound = synthetic_verified_envelope(&manifest, claim)
            .bind_inner_control_root()
            .unwrap();
        assert_eq!(
            root_bound.bind_claim([0x5b; 32]).err(),
            Some(B4StarkError::ClaimDigestMismatch {
                expected: [0x5b; 32],
                actual: claim,
            })
        );
    }
}
