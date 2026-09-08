// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Positive-profile, program, statement, and successful-claim preparation.
//!
//! This module contains no proof-verifier abstraction. It authenticates the
//! fixed initial profile package, derives the program ID from the measured
//! encoded program, strictly round-trips `ErgoStatementV1`, and derives the
//! empty-assumptions OK receipt claim that the STARK must authenticate.

use anyhow::{Context as _, Result, ensure};
use risc0_binfmt::compute_image_id;

use crate::{
    claim::ok_receipt_claim_digests,
    constants::DIGEST_BYTES,
    constants_artifact,
    ergo_statement::parse_ergo_statement_v1,
    profile_algorithm::authenticate_profile_algorithm,
    profile_manifest::{ProfileArtifacts, StarkProfileManifestV1, validate_profile_package_v1},
};

use super::input::B4PositiveVerifierRoot;

/// Frozen initial-profile identifier authorized by EIP-0045.
pub const INITIAL_PROFILE_ID_HEX: &str =
    "23c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383";

/// Fully prepared positive verification context before cryptographic proof use.
///
/// The manifest, program ID, statement, and expected claim are derived only
/// from the already measured seven-file root. This type does not imply that
/// the raw seal is valid.
#[derive(Clone, Debug)]
pub(super) struct B4PreparedPositiveProfile {
    manifest: StarkProfileManifestV1,
    profile_id: [u8; DIGEST_BYTES],
    program_id: [u8; DIGEST_BYTES],
    statement_sha256: [u8; DIGEST_BYTES],
    expected_claim: [u8; DIGEST_BYTES],
}

impl B4PreparedPositiveProfile {
    /// Strictly decoded, re-encoded, package-bound initial manifest.
    #[must_use]
    pub(super) const fn manifest(&self) -> &StarkProfileManifestV1 {
        &self.manifest
    }

    /// Frozen profile ID recomputed from the manifest.
    #[must_use]
    pub(super) const fn profile_id(&self) -> [u8; DIGEST_BYTES] {
        self.profile_id
    }

    /// RISC Zero image ID recomputed from the measured program.
    #[must_use]
    pub(super) const fn program_id(&self) -> [u8; DIGEST_BYTES] {
        self.program_id
    }

    /// SHA-256 of the exact statement bytes used as the receipt journal.
    #[must_use]
    pub(super) const fn statement_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.statement_sha256
    }

    /// Independently derived empty-assumptions OK receipt claim.
    #[must_use]
    pub(super) const fn expected_claim(&self) -> [u8; DIGEST_BYTES] {
        self.expected_claim
    }
}

/// Authenticate the exact three-file frozen initial-profile package.
///
/// This shared prefix is the sole packet/verifier authority for Manifest V1
/// round-trip, B1 authentication, canonical B2 verification, the frozen
/// initial target and profile ID, and complete package binding.
pub(crate) fn authenticate_initial_profile_package(
    manifest: &[u8],
    algorithm: &[u8],
    constants: &[u8],
) -> Result<StarkProfileManifestV1> {
    let decoded = StarkProfileManifestV1::decode(manifest)
        .context("cannot decode the authenticated initial profile manifest")?;
    ensure!(
        decoded.encode()?.as_slice() == manifest,
        "Manifest V1 decode/re-encode changed bytes"
    );

    let authenticated_algorithm = authenticate_profile_algorithm(algorithm, &decoded)
        .context("cannot authenticate the frozen B1 algorithm artifact")?;
    ensure!(
        authenticated_algorithm.bytes() == algorithm,
        "B1 authentication did not retain the exact measured bytes"
    );
    ensure!(
        authenticated_algorithm.artifact_reference() == decoded.algorithm_artifact(),
        "B1 authentication did not retain the manifest artifact reference"
    );
    ensure!(
        hex::encode(authenticated_algorithm.preimage_sha256())
            == crate::profile_algorithm::ALGORITHM_PREIMAGE_SHA256,
        "B1 authentication did not retain the frozen artifact preimage"
    );

    let decoded_constants = constants_artifact::verify_canonical(constants)
        .context("cannot authenticate the frozen B2 constants artifact")?;
    ensure!(
        constants_artifact::encode(&decoded_constants)?.as_slice() == constants,
        "B2 decode/re-encode changed bytes"
    );

    decoded
        .validate_initial_profile_target()
        .context("manifest differs from the frozen initial-profile target")?;
    let expected_profile_id = decode_frozen_profile_id()?;
    let package = validate_profile_package_v1(
        manifest,
        ProfileArtifacts {
            algorithm,
            binary_data: constants,
        },
        &expected_profile_id,
    )
    .context("initial profile package is not internally bound")?;
    ensure!(
        package.manifest().encode()?.as_slice() == manifest,
        "validated profile package did not retain exact manifest bytes"
    );
    ensure!(
        package.artifacts().algorithm == algorithm && package.artifacts().binary_data == constants,
        "validated profile package did not retain exact artifact bytes"
    );
    ensure!(
        decoded.profile_id()? == expected_profile_id,
        "recomputed initial profile ID differs from the frozen authority"
    );
    Ok(decoded)
}

/// Prepare every non-STARK binding for one positive verification.
///
/// The function authenticates B1, strictly decodes/re-encodes B2 and Manifest
/// V1, validates the complete artifact package and initial target, recomputes
/// the profile and program IDs, round-trips the statement, binds its profile
/// and program fields, and derives the exact successful receipt claim with
/// empty assumptions.
///
/// # Errors
///
/// Returns an error at the first profile, artifact, image, statement, or claim
/// mismatch. It never examines or verifies the raw seal.
pub(super) fn prepare_positive_profile(
    root: &B4PositiveVerifierRoot,
) -> Result<B4PreparedPositiveProfile> {
    let manifest_bytes = root.profile_manifest().bytes();
    let manifest = authenticate_initial_profile_package(
        manifest_bytes,
        root.profile_algorithm().bytes(),
        root.profile_constants().bytes(),
    )?;
    let algorithm = authenticate_profile_algorithm(root.profile_algorithm().bytes(), &manifest)
        .context("cannot authenticate the frozen B1 algorithm artifact")?;
    ensure!(
        algorithm.sha256() == root.profile_algorithm().sha256(),
        "B1 authentication did not retain the measured SHA-256 identity"
    );
    let profile_id = manifest.profile_id()?;

    let program_id: [u8; DIGEST_BYTES] = compute_image_id(root.guest_elf().bytes())
        .context("measured guest.elf is not a valid encoded RISC Zero program")?
        .into();
    let statement = parse_ergo_statement_v1(root.statement().bytes())
        .context("cannot decode measured ErgoStatementV1")?;
    ensure!(
        statement.encode()?.as_slice() == root.statement().bytes(),
        "ErgoStatementV1 decode/re-encode changed bytes"
    );
    ensure!(
        statement.profile_id() == profile_id,
        "statement profile ID differs from the authenticated profile"
    );
    ensure!(
        statement.program_id() == program_id,
        "statement program ID differs from the measured guest image ID"
    );

    let claim = ok_receipt_claim_digests(&program_id, root.statement().bytes())
        .context("cannot derive the empty-assumptions OK receipt claim")?;
    let statement_sha256 = root.statement().sha256();
    ensure!(
        claim.journal_digest == statement_sha256,
        "receipt journal digest differs from the measured statement SHA-256"
    );

    Ok(B4PreparedPositiveProfile {
        manifest,
        profile_id,
        program_id,
        statement_sha256,
        expected_claim: claim.expected_claim,
    })
}

fn decode_frozen_profile_id() -> Result<[u8; DIGEST_BYTES]> {
    let bytes = hex::decode(INITIAL_PROFILE_ID_HEX)
        .context("frozen initial profile ID is not valid hexadecimal")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("frozen initial profile ID has the wrong width"))
}

#[cfg(all(test, feature = "validator"))]
mod tests {
    use std::{fs, path::Path};

    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::{
        constants::{PROOF_BYTES, STATEMENT_PREFIX_BYTES},
        ergo_statement::ErgoStatementV1,
    };

    use super::super::input::{
        B4PositiveFileEncoding, B4PositiveFileIdentityV1, Eip0045B4PositiveVerifierInputV1,
        GUEST_ELF_FILE, POSITIVE_INPUT_FILE, PROFILE_ALGORITHM_FILE, PROFILE_CONSTANTS_FILE,
        PROFILE_MANIFEST_FILE, RAW_SEAL_FILE, STATEMENT_FILE, load_positive_verifier_root,
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

    fn write_root(root: &Path, statement_profile: [u8; 32], statement_program: [u8; 32]) {
        let (guest, _) = crate::test_support::valid_program_fixture();
        let statement = ErgoStatementV1::new(
            [0x11; 32],
            statement_profile,
            statement_program,
            [0x22; 32],
            b"application",
        )
        .unwrap()
        .encode()
        .unwrap();
        assert!(statement.len() >= STATEMENT_PREFIX_BYTES);
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

    fn profile_id() -> [u8; 32] {
        decode_frozen_profile_id().unwrap()
    }

    #[test]
    fn frozen_package_program_statement_and_claim_prepare_together() {
        let temp = crate::test_support::tempdir().unwrap();
        let (_, program_id) = crate::test_support::valid_program_fixture();
        write_root(temp.path(), profile_id(), program_id);
        let root = load_positive_verifier_root(temp.path()).unwrap();
        let prepared = prepare_positive_profile(&root).unwrap();

        assert_eq!(prepared.profile_id(), profile_id());
        assert_eq!(prepared.program_id(), program_id);
        let statement_sha256: [u8; DIGEST_BYTES] = Sha256::digest(root.statement().bytes()).into();
        assert_eq!(prepared.statement_sha256(), statement_sha256);
        assert_eq!(
            prepared.expected_claim(),
            ok_receipt_claim_digests(&program_id, root.statement().bytes())
                .unwrap()
                .expected_claim
        );
        assert_eq!(
            prepared.manifest().encode().unwrap().as_slice(),
            root.profile_manifest().bytes()
        );
    }

    #[test]
    fn statement_profile_mismatch_is_rejected_before_proof_use() {
        let temp = crate::test_support::tempdir().unwrap();
        let (_, program_id) = crate::test_support::valid_program_fixture();
        write_root(temp.path(), [0x44; 32], program_id);
        let root = load_positive_verifier_root(temp.path()).unwrap();
        assert!(prepare_positive_profile(&root).is_err());
    }

    #[test]
    fn malformed_program_is_rejected_before_statement_or_proof_authority() {
        let temp = crate::test_support::tempdir().unwrap();
        let (_, program_id) = crate::test_support::valid_program_fixture();
        write_root(temp.path(), profile_id(), program_id);

        let malformed = b"not-an-encoded-program";
        fs::write(temp.path().join(GUEST_ELF_FILE), malformed).unwrap();
        let input_source = fs::read(temp.path().join(POSITIVE_INPUT_FILE)).unwrap();
        let mut input =
            Eip0045B4PositiveVerifierInputV1::from_canonical_jcs(&input_source).unwrap();
        input.guest_elf = identity(GUEST_ELF_FILE, malformed);
        fs::write(
            temp.path().join(POSITIVE_INPUT_FILE),
            input.to_canonical_jcs().unwrap(),
        )
        .unwrap();

        let root = load_positive_verifier_root(temp.path()).unwrap();
        assert!(prepare_positive_profile(&root).is_err());
    }

    #[test]
    fn statement_program_mismatch_is_rejected_after_image_derivation() {
        let temp = crate::test_support::tempdir().unwrap();
        let (_, actual_program) = crate::test_support::valid_program_fixture();
        let mut wrong_program = actual_program;
        wrong_program[0] ^= 1;
        write_root(temp.path(), profile_id(), wrong_program);
        let root = load_positive_verifier_root(temp.path()).unwrap();
        assert!(prepare_positive_profile(&root).is_err());
    }
}
