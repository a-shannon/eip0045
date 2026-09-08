//! Bounded STARK core for the EIP-0045 B4 Rust reference validator.
//!
//! The production path calls the pinned RISC Zero verifier directly. It has no
//! injectable verifier trait and exposes only consuming authority states:
//! cryptographic verification, profile-root binding, then expected-claim
//! binding.

#[cfg_attr(
    all(feature = "materializer-replay", not(feature = "validator")),
    allow(
        dead_code,
        reason = "materializer replay preserves typed STARK failures for anyhow propagation; the stable public classification API remains validator-only"
    )
)]
mod errors;
mod input;
#[cfg(feature = "validator")]
mod negative;
#[cfg(feature = "validator")]
mod negative_ancestry;
#[cfg(feature = "validator")]
mod negative_artifact_catalog;
#[cfg(feature = "validator")]
mod negative_artifact_profile;
#[cfg(feature = "validator")]
mod negative_crypto;
#[cfg(feature = "validator")]
mod negative_input;
#[cfg(feature = "validator")]
mod negative_parser;
#[cfg(feature = "validator")]
mod negative_verifier;
mod positive;
mod profile;
mod stark;
mod terminal;
#[cfg(feature = "validator")]
mod terminal_metadata;

#[cfg(feature = "validator")]
pub use crate::b4_negative_io::{
    B4NegativeObservationRejectionV1, B4NegativeObservationVerdict, Eip0045B4NegativeObservationV1,
};
#[cfg(feature = "validator")]
pub use errors::{
    B4Risc0Failure, B4StarkError, B4StarkErrorClass, B4StarkErrorStage, B4StarkRejectionBoundary,
};
#[cfg(feature = "validator")]
pub use input::{
    B4PositiveFileEncoding, B4PositiveFileIdentityV1, Eip0045B4PositiveVerifierInputV1,
    GUEST_ELF_FILE, POSITIVE_INPUT_FILE, PROFILE_ALGORITHM_FILE, PROFILE_CONSTANTS_FILE,
    PROFILE_MANIFEST_FILE, RAW_SEAL_FILE, STATEMENT_FILE,
};
#[cfg(any(
    feature = "materializer-replay",
    feature = "b4-terminal-evidence-packet",
))]
pub(crate) use input::{B4PositiveVerifierRootSources, synthesize_positive_verifier_input_v1};
#[cfg(feature = "validator")]
pub use negative::verify_negative_root;
#[cfg(feature = "validator")]
pub use negative_input::NEGATIVE_INPUT_FILE;
#[cfg(any(
    feature = "materializer-replay",
    feature = "b4-terminal-evidence-packet",
))]
pub(crate) use positive::verify_positive_sources_with_manifest_evidence;
#[cfg(all(feature = "materializer-replay", not(feature = "validator")))]
pub(crate) use positive::{
    B4PositiveTerminalKind, B4PositiveTerminalObservationV1, Eip0045B4PositiveObservationV1,
};
#[cfg(feature = "validator")]
pub use positive::{
    B4PositiveTerminalKind, B4PositiveTerminalObservationV1, Eip0045B4PositiveObservationV1,
    verify_positive_root,
};
#[cfg(feature = "validator")]
pub use profile::INITIAL_PROFILE_ID_HEX;
#[cfg(feature = "b4-terminal-evidence-packet")]
pub(crate) use profile::authenticate_initial_profile_package;

#[cfg(feature = "negative-materialization-set")]
#[cfg_attr(
    not(any(test, target_os = "linux")),
    allow(
        dead_code,
        reason = "the sole production caller is the Linux descriptor-rooted E6 closure"
    )
)]
pub(crate) struct B4FixedAlternateRootStarkReplayV1 {
    pub(crate) terminal_is_lift: bool,
    pub(crate) terminal_parameter: u8,
    pub(crate) terminal_control_id: [u8; 32],
    pub(crate) inner_control_root: [u8; 32],
    pub(crate) claim_digest: [u8; 32],
}

#[cfg(feature = "negative-materialization-set")]
#[cfg_attr(
    not(any(test, target_os = "linux")),
    allow(
        dead_code,
        reason = "the sole production caller is the Linux descriptor-rooted E6 closure"
    )
)]
pub(crate) fn verify_fixed_alternate_root_stark(
    raw_seal: &[u8],
    expected_claim: [u8; 32],
) -> Result<B4FixedAlternateRootStarkReplayV1, errors::B4StarkError> {
    const MANIFEST: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");

    let manifest = crate::profile_manifest::StarkProfileManifestV1::decode(MANIFEST)
        .map_err(|_| errors::B4StarkError::InitialProfileTarget)?;
    let bound = stark::verify_stark(&manifest, raw_seal)?
        .bind_fixed_alternate_inner_control_root()?
        .bind_claim(expected_claim)?;
    let terminal = bound.terminal();
    Ok(B4FixedAlternateRootStarkReplayV1 {
        terminal_is_lift: matches!(terminal.kind(), terminal::B4TerminalKind::Lift),
        terminal_parameter: terminal.parameter(),
        terminal_control_id: terminal.control_id(),
        inner_control_root: bound.inner_control_root(),
        claim_digest: bound.claim_digest(),
    })
}

#[cfg(all(test, feature = "materializer-replay"))]
mod materializer_replay_tests {
    use core::mem::size_of;

    use super::{
        B4PositiveTerminalKind, B4PositiveTerminalObservationV1, B4PositiveVerifierRootSources,
        Eip0045B4PositiveObservationV1, synthesize_positive_verifier_input_v1,
        verify_positive_sources_with_manifest_evidence,
    };
    use crate::{
        constants::{MANIFEST_BYTES, PROOF_BYTES},
        ergo_statement::ErgoStatementV1,
        profile_manifest::StarkProfileManifestV1,
    };

    const PROFILE_ALGORITHM: &[u8] =
        include_bytes!("../../../profiles/risc0-v3-succinct/algorithm.txt");
    const PROFILE_CONSTANTS: &[u8] =
        include_bytes!("../../../profiles/risc0-v3-succinct/constants.bin");
    const PROFILE_MANIFEST: &[u8] =
        include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");

    #[test]
    fn materializer_replay_reaches_the_shared_direct_stark_boundary() {
        let (guest_elf, program_id) = crate::test_support::valid_program_fixture();
        let profile_id = StarkProfileManifestV1::decode(PROFILE_MANIFEST)
            .unwrap()
            .profile_id()
            .unwrap();
        let statement = ErgoStatementV1::new(
            [0x11; 32],
            profile_id,
            program_id,
            [0x22; 32],
            b"materializer replay",
        )
        .unwrap()
        .encode()
        .unwrap();
        let raw_seal = vec![0_u8; PROOF_BYTES];
        let verifier_input = synthesize_positive_verifier_input_v1(
            PROFILE_MANIFEST,
            PROFILE_ALGORITHM,
            PROFILE_CONSTANTS,
            &guest_elf,
            &statement,
            &raw_seal,
        )
        .unwrap();
        let sources = B4PositiveVerifierRootSources {
            verifier_input: &verifier_input,
            profile_manifest: PROFILE_MANIFEST,
            profile_algorithm: PROFILE_ALGORITHM,
            profile_constants: PROFILE_CONSTANTS,
            guest_elf: &guest_elf,
            statement: &statement,
            raw_seal: &raw_seal,
        };
        let replay: for<'a> fn(
            B4PositiveVerifierRootSources<'a>,
        ) -> anyhow::Result<(
            Eip0045B4PositiveObservationV1,
            [u8; MANIFEST_BYTES],
        )> = verify_positive_sources_with_manifest_evidence;

        let error = replay(sources).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<super::errors::B4StarkError>(),
            Some(super::errors::B4StarkError::OuterPo2Mismatch {
                actual: 0,
                expected: 18
            })
        ));
        let _: B4PositiveTerminalKind = B4PositiveTerminalKind::Lift;
        let _: usize = size_of::<B4PositiveTerminalObservationV1>();
    }
}
