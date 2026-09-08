// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Authentication boundary for the frozen B1 normative algorithm artifact.
//!
//! The API accepts bytes supplied by the caller. It performs no path lookup and
//! returns an opaque value only after text-shape, fixed identity, and manifest
//! artifact-envelope checks all agree.

use anyhow::{Result, ensure};
use sha2::{Digest as _, Sha256};

use crate::{
    constants::{ALGORITHM_ARTIFACT_KIND, DIGEST_BYTES, PROFILE_ARTIFACT_DOMAIN},
    profile_manifest::{ProfileArtifactReference, StarkProfileManifestV1, profile_artifact_digest},
};

/// Exact frozen B1 byte length.
pub const ALGORITHM_BYTES: usize = 29_773;
/// SHA-256 of the exact frozen `algorithm.txt` bytes.
pub const ALGORITHM_SHA256: &str =
    "90a884da420a09f2c1108d7388c2ac74db8dbdb195de704206e2bf8ec1ad0bee";
/// SHA-256 of the exact artifact-envelope preimage.
pub const ALGORITHM_PREIMAGE_SHA256: &str =
    "f763635568ba7a277ddd8d64b5a9971e2a3844c4f419494cf0331436eacf82f3";
/// Domain-separated BLAKE2b-256 digest stored in Manifest V1.
pub const ALGORITHM_ARTIFACT_DIGEST: &str =
    "6ed8a807a7b55177fa664de51c1d6f0daad81daf879e651da32367fed9d171c4";

/// Exact byte length of the B1 artifact-envelope preimage.
pub const ALGORITHM_PREIMAGE_BYTES: usize =
    PROFILE_ARTIFACT_DOMAIN.len() + 1 + 2 + 4 + ALGORITHM_BYTES;

/// B1 bytes whose fixed identity and enclosing manifest reference agree.
#[derive(Clone, Copy, Debug)]
pub struct AuthenticatedProfileAlgorithm<'a> {
    bytes: &'a [u8],
    sha256: [u8; DIGEST_BYTES],
    artifact_reference: ProfileArtifactReference,
    preimage_sha256: [u8; DIGEST_BYTES],
}

impl<'a> AuthenticatedProfileAlgorithm<'a> {
    /// Exact authenticated algorithm bytes.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Raw SHA-256 identity of the exact algorithm bytes.
    #[must_use]
    pub const fn sha256(&self) -> [u8; DIGEST_BYTES] {
        self.sha256
    }

    /// Manifest V1 artifact reference recomputed from the exact bytes.
    #[must_use]
    pub const fn artifact_reference(&self) -> ProfileArtifactReference {
        self.artifact_reference
    }

    /// SHA-256 of the exact domain-separated artifact preimage.
    #[must_use]
    pub const fn preimage_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.preimage_sha256
    }
}

/// Authenticate exact B1 bytes and bind them to one decoded Manifest V1.
///
/// # Errors
///
/// Returns an error for any length, text-shape, frozen SHA-256, preimage, or
/// manifest artifact-reference mismatch.
pub fn authenticate_profile_algorithm<'a>(
    bytes: &'a [u8],
    manifest: &StarkProfileManifestV1,
) -> Result<AuthenticatedProfileAlgorithm<'a>> {
    validate_text_shape(bytes)?;

    let sha256: [u8; DIGEST_BYTES] = Sha256::digest(bytes).into();
    ensure!(
        hex::encode(sha256) == ALGORITHM_SHA256,
        "B1 SHA-256 differs from the frozen algorithm artifact"
    );

    let artifact_reference =
        ProfileArtifactReference::from_artifact(ALGORITHM_ARTIFACT_KIND, bytes)?;
    ensure!(
        hex::encode(artifact_reference.artifact_digest()) == ALGORITHM_ARTIFACT_DIGEST,
        "B1 domain-separated artifact digest differs from the frozen identity"
    );
    ensure!(
        artifact_reference == manifest.algorithm_artifact(),
        "B1 artifact envelope differs from the decoded manifest"
    );

    let preimage_sha256: [u8; DIGEST_BYTES] = Sha256::digest(artifact_preimage(bytes)?).into();
    ensure!(
        hex::encode(preimage_sha256) == ALGORITHM_PREIMAGE_SHA256,
        "B1 artifact-preimage SHA-256 differs from the frozen identity"
    );

    Ok(AuthenticatedProfileAlgorithm {
        bytes,
        sha256,
        artifact_reference,
        preimage_sha256,
    })
}

fn validate_text_shape(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() == ALGORITHM_BYTES,
        "B1 has {} bytes, expected {ALGORITHM_BYTES}",
        bytes.len()
    );
    ensure!(
        !bytes.starts_with(&[0xef, 0xbb, 0xbf]),
        "B1 has a UTF-8 BOM"
    );
    ensure!(!bytes.contains(&0), "B1 contains a NUL byte");
    ensure!(!bytes.contains(&b'\r'), "B1 contains a CR byte");
    ensure!(bytes.is_ascii(), "B1 is not exact ASCII");
    ensure!(bytes.ends_with(b"\n"), "B1 does not end in LF");
    ensure!(!bytes.ends_with(b"\n\n"), "B1 has more than one final LF");
    Ok(())
}

fn artifact_preimage(bytes: &[u8]) -> Result<Vec<u8>> {
    let length = u32::try_from(bytes.len())?;
    let mut preimage = Vec::with_capacity(ALGORITHM_PREIMAGE_BYTES);
    preimage.extend_from_slice(PROFILE_ARTIFACT_DOMAIN);
    preimage.push(0);
    preimage.extend_from_slice(&ALGORITHM_ARTIFACT_KIND.to_le_bytes());
    preimage.extend_from_slice(&length.to_le_bytes());
    preimage.extend_from_slice(bytes);
    ensure!(
        preimage.len() == ALGORITHM_PREIMAGE_BYTES,
        "B1 artifact-preimage length is inconsistent"
    );
    ensure!(
        profile_artifact_digest(ALGORITHM_ARTIFACT_KIND, bytes)?
            == blake2b_256_from_preimage(&preimage),
        "B1 artifact-preimage and manifest digest formulas disagree"
    );
    Ok(preimage)
}

fn blake2b_256_from_preimage(preimage: &[u8]) -> [u8; DIGEST_BYTES] {
    use blake2::{Blake2b, digest::consts::U32};
    type Blake2b256 = Blake2b<U32>;
    Blake2b256::digest(preimage).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FROZEN_B1: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/algorithm.txt");
    const FROZEN_MANIFEST: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin");

    fn manifest() -> StarkProfileManifestV1 {
        StarkProfileManifestV1::decode(FROZEN_MANIFEST).unwrap()
    }

    #[test]
    fn frozen_algorithm_authenticates_against_the_manifest_envelope() {
        let authenticated = authenticate_profile_algorithm(FROZEN_B1, &manifest()).unwrap();
        assert_eq!(authenticated.bytes(), FROZEN_B1);
        assert_eq!(hex::encode(authenticated.sha256()), ALGORITHM_SHA256);
        assert_eq!(
            hex::encode(authenticated.preimage_sha256()),
            ALGORITHM_PREIMAGE_SHA256
        );
        assert_eq!(
            hex::encode(authenticated.artifact_reference().artifact_digest()),
            ALGORITHM_ARTIFACT_DIGEST
        );
        assert_eq!(
            artifact_preimage(FROZEN_B1).unwrap().len(),
            ALGORITHM_PREIMAGE_BYTES
        );
    }

    #[test]
    fn exact_length_bounds_are_enforced_before_authentication() {
        assert!(
            authenticate_profile_algorithm(&FROZEN_B1[..ALGORITHM_BYTES - 1], &manifest()).is_err()
        );
        let mut trailing = FROZEN_B1.to_vec();
        trailing.push(b'\n');
        assert!(authenticate_profile_algorithm(&trailing, &manifest()).is_err());
    }

    #[test]
    fn every_text_shape_restriction_has_an_isolated_negative() {
        let mut bom = FROZEN_B1.to_vec();
        bom[..3].copy_from_slice(&[0xef, 0xbb, 0xbf]);
        assert!(authenticate_profile_algorithm(&bom, &manifest()).is_err());

        let mut nul = FROZEN_B1.to_vec();
        nul[10] = 0;
        assert!(authenticate_profile_algorithm(&nul, &manifest()).is_err());

        let mut cr = FROZEN_B1.to_vec();
        cr[10] = b'\r';
        assert!(authenticate_profile_algorithm(&cr, &manifest()).is_err());

        let mut non_ascii = FROZEN_B1.to_vec();
        non_ascii[10] = 0x80;
        assert!(authenticate_profile_algorithm(&non_ascii, &manifest()).is_err());

        let mut no_final_lf = FROZEN_B1.to_vec();
        *no_final_lf.last_mut().unwrap() = b'.';
        assert!(authenticate_profile_algorithm(&no_final_lf, &manifest()).is_err());

        let mut double_final_lf = FROZEN_B1.to_vec();
        let penultimate = double_final_lf.len() - 2;
        double_final_lf[penultimate] = b'\n';
        assert!(authenticate_profile_algorithm(&double_final_lf, &manifest()).is_err());
    }

    #[test]
    fn well_formed_ascii_mutation_fails_the_fixed_identity() {
        let mut changed = FROZEN_B1.to_vec();
        let index = changed.iter().position(|byte| *byte == b'a').unwrap();
        changed[index] = b'A';
        assert!(authenticate_profile_algorithm(&changed, &manifest()).is_err());
    }

    #[test]
    fn coordinated_manifest_substitution_does_not_bypass_fixed_b1_identity() {
        let mut changed_algorithm = FROZEN_B1.to_vec();
        let index = changed_algorithm
            .iter()
            .position(|byte| *byte == b'a')
            .unwrap();
        changed_algorithm[index] = b'A';

        let mut changed_manifest = FROZEN_MANIFEST.to_vec();
        let reference =
            ProfileArtifactReference::from_artifact(ALGORITHM_ARTIFACT_KIND, &changed_algorithm)
                .unwrap();
        let algorithm_reference_offset = FROZEN_MANIFEST.len() - 2 * (2 + 4 + DIGEST_BYTES);
        changed_manifest[algorithm_reference_offset..algorithm_reference_offset + 2]
            .copy_from_slice(&reference.artifact_kind().to_le_bytes());
        changed_manifest[algorithm_reference_offset + 2..algorithm_reference_offset + 6]
            .copy_from_slice(&reference.artifact_length().to_le_bytes());
        changed_manifest
            [algorithm_reference_offset + 6..algorithm_reference_offset + 6 + DIGEST_BYTES]
            .copy_from_slice(&reference.artifact_digest());
        let changed_manifest = StarkProfileManifestV1::decode(&changed_manifest).unwrap();

        assert!(authenticate_profile_algorithm(&changed_algorithm, &changed_manifest).is_err());
    }

    #[test]
    fn manifest_envelope_mismatch_is_rejected_even_for_exact_b1_bytes() {
        let mut changed_manifest = FROZEN_MANIFEST.to_vec();
        let algorithm_digest_offset = FROZEN_MANIFEST.len() - 2 * (2 + 4 + DIGEST_BYTES) + 6;
        changed_manifest[algorithm_digest_offset] ^= 1;
        let changed_manifest = StarkProfileManifestV1::decode(&changed_manifest).unwrap();
        assert!(authenticate_profile_algorithm(FROZEN_B1, &changed_manifest).is_err());
    }
}
