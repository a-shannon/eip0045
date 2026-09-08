//! Authentication of the exact compiled terminal-evidence profile.

use anyhow::{Context as _, Result, ensure};
use eip_0045_reproduction::{
    parse_ergo_statement_v1,
    profile_manifest::{ProfileArtifacts, StarkProfileManifestV1, validate_profile_package_v1},
};
use sha2::{Digest as _, Sha256};

use crate::profile_freeze::build_profile_freeze_bundle;

const COMPILED_MANIFEST: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin");
const COMPILED_ALGORITHM: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/algorithm.txt");
const COMPILED_CONSTANTS: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/constants.bin");

const MANIFEST_BYTES: usize = 458;
const ALGORITHM_BYTES: usize = 29_773;
const CONSTANTS_BYTES: usize = 65_119;
const MANIFEST_SHA256: &str = "deffb2cb231f98a348cbd166d5f1c43315661ccd8bd212099f16f238d0fe8946";
const ALGORITHM_SHA256: &str = "90a884da420a09f2c1108d7388c2ac74db8dbdb195de704206e2bf8ec1ad0bee";
const CONSTANTS_SHA256: &str = "8c4a92b7d354890481eefdef233d4ca43f6bcd9f7cb00e4dd9e709da47789ef3";

/// Exact compiled profile bytes authenticated for terminal-evidence replay.
pub(crate) struct B4AuthenticatedCompiledTerminalEvidenceProfileV1 {
    manifest: &'static [u8],
    algorithm: &'static [u8],
    constants: &'static [u8],
}

impl B4AuthenticatedCompiledTerminalEvidenceProfileV1 {
    pub(crate) const fn manifest(&self) -> &[u8] {
        self.manifest
    }

    pub(crate) const fn algorithm(&self) -> &[u8] {
        self.algorithm
    }

    pub(crate) const fn constants(&self) -> &[u8] {
        self.constants
    }
}

pub(crate) fn authenticate_compiled_terminal_evidence_profile(
    statement: &[u8],
) -> Result<B4AuthenticatedCompiledTerminalEvidenceProfileV1> {
    authenticate_terminal_evidence_profile_bytes(
        COMPILED_MANIFEST,
        COMPILED_ALGORITHM,
        COMPILED_CONSTANTS,
        statement,
    )?;
    Ok(B4AuthenticatedCompiledTerminalEvidenceProfileV1 {
        manifest: COMPILED_MANIFEST,
        algorithm: COMPILED_ALGORITHM,
        constants: COMPILED_CONSTANTS,
    })
}

fn authenticate_terminal_evidence_profile_bytes(
    manifest: &[u8],
    algorithm: &[u8],
    constants: &[u8],
    statement: &[u8],
) -> Result<()> {
    require_fixed_identity(
        "compiled terminal-evidence manifest",
        manifest,
        MANIFEST_BYTES,
        MANIFEST_SHA256,
    )?;
    require_fixed_identity(
        "compiled terminal-evidence algorithm",
        algorithm,
        ALGORITHM_BYTES,
        ALGORITHM_SHA256,
    )?;
    require_fixed_identity(
        "compiled terminal-evidence constants",
        constants,
        CONSTANTS_BYTES,
        CONSTANTS_SHA256,
    )?;

    let rebuilt = build_profile_freeze_bundle(algorithm, constants)
        .context("cannot rebuild the compiled terminal-evidence profile")?;
    ensure!(
        rebuilt.manifest().as_slice() == manifest,
        "compiled terminal-evidence manifest differs from the rebuilt profile"
    );

    let decoded = StarkProfileManifestV1::decode(manifest)
        .context("cannot decode the compiled terminal-evidence manifest")?;
    ensure!(
        decoded.encode()?.as_slice() == manifest,
        "compiled terminal-evidence manifest decode/re-encode changed bytes"
    );
    let package = validate_profile_package_v1(
        manifest,
        ProfileArtifacts {
            algorithm,
            binary_data: constants,
        },
        rebuilt.profile_id(),
    )
    .context("compiled terminal-evidence profile package is not internally bound")?;
    ensure!(
        package.manifest().encode()?.as_slice() == manifest
            && package.artifacts().algorithm == algorithm
            && package.artifacts().binary_data == constants,
        "validated terminal-evidence profile package did not retain exact bytes"
    );
    decoded
        .validate_initial_profile_target()
        .context("compiled terminal-evidence profile differs from the initial target")?;

    let parsed_statement = parse_ergo_statement_v1(statement)
        .context("cannot parse the terminal-evidence ErgoStatementV1")?;
    ensure!(
        parsed_statement.encode()?.as_slice() == statement,
        "terminal-evidence statement decode/re-encode changed bytes"
    );
    ensure!(
        parsed_statement.profile_id() == *rebuilt.profile_id(),
        "terminal-evidence statement profile ID differs from the compiled profile"
    );
    Ok(())
}

fn require_fixed_identity(
    role: &str,
    bytes: &[u8],
    expected_length: usize,
    expected_sha256: &str,
) -> Result<()> {
    ensure!(
        bytes.len() == expected_length,
        "{role} has {} bytes, expected exactly {expected_length}",
        bytes.len()
    );
    ensure!(
        hex::encode(Sha256::digest(bytes)) == expected_sha256,
        "{role} SHA-256 differs from the fixed identity table"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use eip_0045_reproduction::ErgoStatementV1;
    use sha2::{Digest as _, Sha256};

    use super::{
        authenticate_compiled_terminal_evidence_profile,
        authenticate_terminal_evidence_profile_bytes,
    };
    use crate::profile_freeze::build_profile_freeze_bundle;

    const MANIFEST: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin");
    const ALGORITHM: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/algorithm.txt");
    const CONSTANTS: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/constants.bin");

    fn statement(profile_id: [u8; 32]) -> Vec<u8> {
        ErgoStatementV1::new(
            [0x11; 32],
            profile_id,
            [0x22; 32],
            [0x33; 32],
            b"terminal-evidence-profile",
        )
        .unwrap()
        .encode()
        .unwrap()
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    #[test]
    fn compiled_terminal_evidence_profile_matches_fixed_identity_table() {
        assert_eq!(MANIFEST.len(), 458);
        assert_eq!(
            sha256_hex(MANIFEST),
            "deffb2cb231f98a348cbd166d5f1c43315661ccd8bd212099f16f238d0fe8946"
        );
        assert_eq!(ALGORITHM.len(), 29_773);
        assert_eq!(
            sha256_hex(ALGORITHM),
            "90a884da420a09f2c1108d7388c2ac74db8dbdb195de704206e2bf8ec1ad0bee"
        );
        assert_eq!(CONSTANTS.len(), 65_119);
        assert_eq!(
            sha256_hex(CONSTANTS),
            "8c4a92b7d354890481eefdef233d4ca43f6bcd9f7cb00e4dd9e709da47789ef3"
        );

        let bundle = build_profile_freeze_bundle(ALGORITHM, CONSTANTS).unwrap();
        let authority =
            authenticate_compiled_terminal_evidence_profile(&statement(*bundle.profile_id()))
                .unwrap();
        assert_eq!(authority.manifest(), MANIFEST);
        assert_eq!(authority.algorithm(), ALGORITHM);
        assert_eq!(authority.constants(), CONSTANTS);
    }

    #[test]
    fn compiled_terminal_evidence_profile_rejects_single_and_coordinated_drift() {
        let bundle = build_profile_freeze_bundle(ALGORITHM, CONSTANTS).unwrap();
        let valid_statement = statement(*bundle.profile_id());

        let mut changed_manifest = MANIFEST.to_vec();
        changed_manifest[0] ^= 1;
        assert!(
            authenticate_terminal_evidence_profile_bytes(
                &changed_manifest,
                ALGORITHM,
                CONSTANTS,
                &valid_statement,
            )
            .is_err()
        );

        let mut changed_algorithm = ALGORITHM.to_vec();
        changed_algorithm[0] ^= 1;
        assert!(
            authenticate_terminal_evidence_profile_bytes(
                MANIFEST,
                &changed_algorithm,
                CONSTANTS,
                &valid_statement,
            )
            .is_err()
        );

        let mut changed_constants = CONSTANTS.to_vec();
        changed_constants[0] ^= 1;
        assert!(
            authenticate_terminal_evidence_profile_bytes(
                MANIFEST,
                ALGORITHM,
                &changed_constants,
                &valid_statement,
            )
            .is_err()
        );

        assert!(
            authenticate_terminal_evidence_profile_bytes(
                MANIFEST,
                ALGORITHM,
                CONSTANTS,
                &statement([0x44; 32]),
            )
            .is_err()
        );

        let mut coordinated_algorithm = ALGORITHM.to_vec();
        let changed_index = coordinated_algorithm
            .iter()
            .position(|byte| *byte == b'a')
            .unwrap();
        coordinated_algorithm[changed_index] = b'A';
        let coordinated_bundle =
            build_profile_freeze_bundle(&coordinated_algorithm, CONSTANTS).unwrap();
        assert_ne!(coordinated_bundle.manifest(), MANIFEST);
        assert!(
            authenticate_terminal_evidence_profile_bytes(
                coordinated_bundle.manifest(),
                &coordinated_algorithm,
                CONSTANTS,
                &statement(*coordinated_bundle.profile_id()),
            )
            .is_err()
        );
    }
}
