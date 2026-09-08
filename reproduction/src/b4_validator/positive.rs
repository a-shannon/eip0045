// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Complete positive B4 verification and authority-minimal observation.
//!
//! The only successful path is:
//!
//! 1. authenticate the closed seven-file root;
//! 2. prepare the profile, program, statement, and expected OK claim;
//! 3. call the pinned STARK verifier directly;
//! 4. bind the verified inner root;
//! 5. bind the independently derived claim; and
//! 6. serialize an observation from the final consuming state.
//!
//! No expected verdict, case label, verifier callback, or implementation
//! choice is accepted as input.

#[cfg(feature = "validator")]
use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use serde::Serialize;

#[cfg(feature = "validator")]
use crate::canonical::canonical_json_bytes;
use crate::constants::MANIFEST_BYTES;

#[cfg(feature = "validator")]
use super::input::load_positive_verifier_root;
use super::{
    input::{
        B4PositiveVerifierRoot, B4PositiveVerifierRootSources,
        load_positive_verifier_root_from_sources,
    },
    profile::{B4PreparedPositiveProfile, prepare_positive_profile},
    stark::{ClaimBoundStarkEnvelope, verify_stark},
    terminal::{B4TerminalKind, B4VerifiedTerminal},
};

const POSITIVE_OBSERVATION_FORMAT: &str = "Eip0045B4PositiveObservationV1";
const POSITIVE_OBSERVATION_FORMAT_VERSION: u8 = 1;
#[cfg(feature = "validator")]
const POSITIVE_OBSERVATION_MAX_BYTES: usize = 65_536;

/// Closed terminal kind emitted by the positive observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum B4PositiveTerminalKind {
    /// Normal RV32IM lift.
    Lift,
    /// Stock recursive join.
    Join,
    /// Stock recursive resolve.
    Resolve,
}

impl From<B4TerminalKind> for B4PositiveTerminalKind {
    fn from(value: B4TerminalKind) -> Self {
        match value {
            B4TerminalKind::Lift => Self::Lift,
            B4TerminalKind::Join => Self::Join,
            B4TerminalKind::Resolve => Self::Resolve,
        }
    }
}

/// Terminal tuple authenticated by the completed STARK.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4PositiveTerminalObservationV1 {
    /// Verified terminal-program kind.
    pub kind: B4PositiveTerminalKind,
    /// Verified kind-specific parameter.
    pub parameter: u8,
    /// Lowercase hexadecimal control ID authenticated by the STARK callback.
    pub control_id: String,
}

impl B4PositiveTerminalObservationV1 {
    fn from_verified(terminal: B4VerifiedTerminal) -> Self {
        Self {
            kind: terminal.kind().into(),
            parameter: terminal.parameter(),
            control_id: hex::encode(terminal.control_id()),
        }
    }

    fn validate(&self) -> Result<()> {
        match self.kind {
            B4PositiveTerminalKind::Lift => ensure!(
                (15..=22).contains(&self.parameter),
                "positive lift terminal parameter is outside the initial profile"
            ),
            B4PositiveTerminalKind::Join | B4PositiveTerminalKind::Resolve => ensure!(
                self.parameter == 0,
                "positive non-lift terminal parameter is not canonical"
            ),
        }
        validate_digest(&self.control_id, "positive terminal control ID")
    }
}

/// Canonical observation emitted only after all positive bindings succeed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4PositiveObservationV1 {
    format: String,
    format_version: u8,
    verdict: String,
    profile_id: String,
    program_id: String,
    statement_sha256: String,
    claim_digest: String,
    final_status: String,
    final_assumption_count: u8,
    terminal: B4PositiveTerminalObservationV1,
}

impl Eip0045B4PositiveObservationV1 {
    fn from_verified(
        prepared: &B4PreparedPositiveProfile,
        verified: &ClaimBoundStarkEnvelope,
    ) -> Result<Self> {
        ensure!(
            verified.inner_control_root() == prepared.manifest().inner_control_root(),
            "final verified state lost the authenticated manifest root binding"
        );
        ensure!(
            verified.claim_digest() == prepared.expected_claim(),
            "final verified state lost the independently expected claim binding"
        );
        let observation = Self {
            format: POSITIVE_OBSERVATION_FORMAT.to_owned(),
            format_version: POSITIVE_OBSERVATION_FORMAT_VERSION,
            verdict: "accept".to_owned(),
            profile_id: hex::encode(prepared.profile_id()),
            program_id: hex::encode(prepared.program_id()),
            statement_sha256: hex::encode(prepared.statement_sha256()),
            claim_digest: hex::encode(verified.claim_digest()),
            final_status: "ok".to_owned(),
            final_assumption_count: 0,
            terminal: B4PositiveTerminalObservationV1::from_verified(verified.terminal()),
        };
        observation.validate()?;
        Ok(observation)
    }

    /// Serialize the observation as exact RFC 8785 JCS.
    ///
    /// # Errors
    ///
    /// Returns an error only if the internally derived observation violates
    /// its closed V1 grammar or exceeds the fixed output bound.
    #[cfg(feature = "validator")]
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value =
            serde_json::to_value(self).context("cannot serialize B4 positive observation")?;
        let bytes = canonical_json_bytes(&value)?;
        ensure!(
            bytes.len() <= POSITIVE_OBSERVATION_MAX_BYTES,
            "B4 positive observation exceeds its canonical-byte bound"
        );
        Ok(bytes)
    }

    /// Recomputed profile ID authenticated by the accepted proof context.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Recomputed program ID authenticated by the accepted proof context.
    #[must_use]
    pub fn program_id(&self) -> &str {
        &self.program_id
    }

    /// SHA-256 of the exact statement used to derive the accepted claim.
    #[must_use]
    pub fn statement_sha256(&self) -> &str {
        &self.statement_sha256
    }

    /// Claim digest actually present in the verified STARK output.
    #[must_use]
    pub fn claim_digest(&self) -> &str {
        &self.claim_digest
    }

    /// Terminal tuple actually accepted by the verified callback.
    #[must_use]
    pub const fn terminal(&self) -> &B4PositiveTerminalObservationV1 {
        &self.terminal
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.format == POSITIVE_OBSERVATION_FORMAT
                && self.format_version == POSITIVE_OBSERVATION_FORMAT_VERSION,
            "wrong B4 positive observation format"
        );
        ensure!(
            self.verdict == "accept"
                && self.final_status == "ok"
                && self.final_assumption_count == 0,
            "wrong B4 positive observation success semantics"
        );
        ensure!(
            self.profile_id == super::profile::INITIAL_PROFILE_ID_HEX,
            "positive observation profile ID differs from the initial profile"
        );
        validate_digest(&self.profile_id, "positive observation profile ID")?;
        validate_digest(&self.program_id, "positive observation program ID")?;
        validate_digest(
            &self.statement_sha256,
            "positive observation statement SHA-256",
        )?;
        validate_digest(&self.claim_digest, "positive observation claim digest")?;
        self.terminal.validate()
    }
}

/// Verify one physical positive root and return its canonical observation.
///
/// # Errors
///
/// Returns the first filesystem, input, profile, image, statement, claim,
/// STARK, terminal, root-binding, or claim-binding error. No observation is
/// constructed on any failure.
#[cfg(feature = "validator")]
pub fn verify_positive_root(root: &Path) -> Result<Eip0045B4PositiveObservationV1> {
    let (observation, _) = verify_positive_root_with_manifest_evidence(root)?;
    Ok(observation)
}

/// Verify one positive root while retaining the manifest bytes from the same
/// authenticated open-handle measurement.
///
/// This is an internal producer boundary for consumers which must bind a
/// derived positive observation to exact profile evidence without rereading a
/// path after verification.
#[cfg(feature = "validator")]
pub(super) fn verify_positive_root_with_manifest_evidence(
    root: &Path,
) -> Result<(Eip0045B4PositiveObservationV1, [u8; MANIFEST_BYTES])> {
    let loaded = load_positive_verifier_root(root)
        .context("cannot authenticate the closed B4 positive verifier root")?;
    let manifest_evidence = loaded
        .profile_manifest()
        .bytes()
        .try_into()
        .context("authenticated positive manifest has the wrong fixed length")?;
    let observation = verify_loaded_positive_root(&loaded)?;
    Ok((observation, manifest_evidence))
}

/// Verify immutable byte views of one positive root while retaining its exact
/// manifest evidence.
///
/// This is the replay boundary used by negative consumers. It enforces the
/// same descriptor and cryptographic path as the filesystem entry point, but
/// receives only positional bytes already measured inside the neutral
/// negative root.
pub(crate) fn verify_positive_sources_with_manifest_evidence(
    sources: B4PositiveVerifierRootSources<'_>,
) -> Result<(Eip0045B4PositiveObservationV1, [u8; MANIFEST_BYTES])> {
    let loaded = load_positive_verifier_root_from_sources(sources)
        .context("cannot authenticate B4 positive verifier-root byte views")?;
    let manifest_evidence = loaded
        .profile_manifest()
        .bytes()
        .try_into()
        .context("authenticated positive manifest has the wrong fixed length")?;
    let observation = verify_loaded_positive_root(&loaded)?;
    Ok((observation, manifest_evidence))
}

/// Verify an already measured positive root and return its observation.
///
/// This entry point exists so a CLI can separate bounded filesystem failures
/// from cryptographic failures without rereading files. It still calls the
/// pinned STARK implementation directly and accepts no verifier injection.
///
/// # Errors
///
/// Returns the first profile, image, statement, claim, STARK, terminal,
/// root-binding, or claim-binding error.
fn verify_loaded_positive_root(
    root: &B4PositiveVerifierRoot,
) -> Result<Eip0045B4PositiveObservationV1> {
    let prepared = prepare_positive_profile(root)
        .context("cannot prepare B4 positive profile and statement bindings")?;

    let stark = verify_stark(prepared.manifest(), root.raw_seal().bytes())
        .context("B4 raw seal failed direct STARK verification")?;
    let root_bound = stark
        .bind_inner_control_root()
        .context("B4 verified STARK output failed late inner-root binding")?;
    let claim_bound = root_bound
        .bind_claim(prepared.expected_claim())
        .context("B4 root-bound STARK output failed final claim binding")?;

    Eip0045B4PositiveObservationV1::from_verified(&prepared, &claim_bound)
        .context("cannot construct observation from final verified authority")
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} is not exact lowercase hexadecimal"
    );
    Ok(())
}

#[cfg(all(test, feature = "validator"))]
mod tests {
    use std::{fs, path::Path};

    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::{
        constants::PROOF_BYTES, ergo_statement::ErgoStatementV1,
        profile_manifest::StarkProfileManifestV1,
    };

    use super::super::input::{
        B4PositiveFileEncoding, B4PositiveFileIdentityV1, Eip0045B4PositiveVerifierInputV1,
        GUEST_ELF_FILE, POSITIVE_INPUT_FILE, PROFILE_ALGORITHM_FILE, PROFILE_CONSTANTS_FILE,
        PROFILE_MANIFEST_FILE, RAW_SEAL_FILE, STATEMENT_FILE,
    };

    const B1: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/algorithm.txt");
    const B2: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/constants.bin");
    const MANIFEST: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");

    fn identity(path: &str, bytes: &[u8]) -> B4PositiveFileIdentityV1 {
        B4PositiveFileIdentityV1 {
            path: path.to_owned(),
            byte_length: u64::try_from(bytes.len()).unwrap(),
            sha256: hex::encode(Sha256::digest(bytes)),
            encoding: B4PositiveFileEncoding::RawBytes,
        }
    }

    fn write_zero_seal_root(root: &Path) {
        let (guest, program_id) = crate::test_support::valid_program_fixture();
        let profile_id = StarkProfileManifestV1::decode(MANIFEST)
            .unwrap()
            .profile_id()
            .unwrap();
        let statement = ErgoStatementV1::new(
            [0x11; 32],
            profile_id,
            program_id,
            [0x22; 32],
            b"application",
        )
        .unwrap()
        .encode()
        .unwrap();
        let seal = vec![0_u8; PROOF_BYTES];
        let input = Eip0045B4PositiveVerifierInputV1 {
            format: "Eip0045B4PositiveVerifierInputV1".to_owned(),
            format_version: 1,
            profile_manifest: identity(PROFILE_MANIFEST_FILE, MANIFEST),
            profile_algorithm: identity(PROFILE_ALGORITHM_FILE, B1),
            profile_constants: identity(PROFILE_CONSTANTS_FILE, B2),
            guest_elf: identity(GUEST_ELF_FILE, &guest),
            statement: identity(STATEMENT_FILE, &statement),
            raw_seal: identity(RAW_SEAL_FILE, &seal),
        };
        fs::write(root.join(PROFILE_MANIFEST_FILE), MANIFEST).unwrap();
        fs::write(root.join(PROFILE_ALGORITHM_FILE), B1).unwrap();
        fs::write(root.join(PROFILE_CONSTANTS_FILE), B2).unwrap();
        fs::write(root.join(GUEST_ELF_FILE), guest).unwrap();
        fs::write(root.join(STATEMENT_FILE), statement).unwrap();
        fs::write(root.join(RAW_SEAL_FILE), seal).unwrap();
        fs::write(
            root.join(POSITIVE_INPUT_FILE),
            input.to_canonical_jcs().unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn invalid_real_seal_path_cannot_construct_an_accept_observation() {
        let temp = crate::test_support::tempdir().unwrap();
        write_zero_seal_root(temp.path());
        let error = verify_positive_root(temp.path()).unwrap_err();
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("direct STARK verification"));
        assert!(matches!(
            error.downcast_ref::<super::super::errors::B4StarkError>(),
            Some(super::super::errors::B4StarkError::OuterPo2Mismatch {
                actual: 0,
                expected: 18
            })
        ));
    }

    #[test]
    fn malformed_statement_fails_before_the_direct_stark_call() {
        let temp = crate::test_support::tempdir().unwrap();
        write_zero_seal_root(temp.path());
        let mut statement = fs::read(temp.path().join(STATEMENT_FILE)).unwrap();
        statement[0] ^= 1;
        fs::write(temp.path().join(STATEMENT_FILE), &statement).unwrap();

        let source = fs::read(temp.path().join(POSITIVE_INPUT_FILE)).unwrap();
        let mut input = Eip0045B4PositiveVerifierInputV1::from_canonical_jcs(&source).unwrap();
        input.statement = identity(STATEMENT_FILE, &statement);
        fs::write(
            temp.path().join(POSITIVE_INPUT_FILE),
            input.to_canonical_jcs().unwrap(),
        )
        .unwrap();

        let diagnostic = format!("{:#}", verify_positive_root(temp.path()).unwrap_err());
        assert!(diagnostic.contains("ErgoStatementV1"));
        assert!(!diagnostic.contains("direct STARK verification"));
    }

    #[test]
    fn observation_grammar_contains_no_expectation_or_case_attribution() {
        let observation = Eip0045B4PositiveObservationV1 {
            format: POSITIVE_OBSERVATION_FORMAT.to_owned(),
            format_version: POSITIVE_OBSERVATION_FORMAT_VERSION,
            verdict: "accept".to_owned(),
            profile_id: super::super::profile::INITIAL_PROFILE_ID_HEX.to_owned(),
            program_id: "11".repeat(32),
            statement_sha256: "22".repeat(32),
            claim_digest: "33".repeat(32),
            final_status: "ok".to_owned(),
            final_assumption_count: 0,
            terminal: B4PositiveTerminalObservationV1 {
                kind: B4PositiveTerminalKind::Lift,
                parameter: 15,
                control_id: "44".repeat(32),
            },
        };
        let bytes = observation.to_canonical_jcs().unwrap();
        assert!(!bytes.ends_with(b"\n"));
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 10);
        for forbidden in [
            "caseId",
            "caseLabel",
            "expectedResult",
            "implementation",
            "inputPath",
        ] {
            assert!(!object.contains_key(forbidden));
        }
        assert_eq!(value["terminal"]["kind"], "lift");
    }

    #[test]
    fn observation_rejects_noncanonical_terminal_semantics() {
        let mut observation = Eip0045B4PositiveObservationV1 {
            format: POSITIVE_OBSERVATION_FORMAT.to_owned(),
            format_version: POSITIVE_OBSERVATION_FORMAT_VERSION,
            verdict: "accept".to_owned(),
            profile_id: super::super::profile::INITIAL_PROFILE_ID_HEX.to_owned(),
            program_id: "11".repeat(32),
            statement_sha256: "22".repeat(32),
            claim_digest: "33".repeat(32),
            final_status: "ok".to_owned(),
            final_assumption_count: 0,
            terminal: B4PositiveTerminalObservationV1 {
                kind: B4PositiveTerminalKind::Join,
                parameter: 1,
                control_id: "44".repeat(32),
            },
        };
        assert!(observation.to_canonical_jcs().is_err());
        observation.terminal.parameter = 0;
        observation.terminal.control_id = "AA".repeat(32);
        assert!(observation.to_canonical_jcs().is_err());
    }
}
