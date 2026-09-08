// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Shared pure projection of one verified terminal callback into the exact
//! terminal-metadata record consumed by B4.

use crate::{
    b4_validator::{B4PositiveTerminalKind, B4PositiveTerminalObservationV1},
    constants::{MANIFEST_CONTROL_ENTRY_BYTES, TERMINAL_CONTROL_KIND_JOIN},
    profile_manifest::StarkProfileManifestV1,
};

/// Closed failures of the pure terminal-record projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum B4TerminalMetadataRecordError {
    /// The observed control ID is not exact lowercase hexadecimal.
    Encoding,
    /// The observed tuple is not the sole Join/0 entry in the initial profile.
    ProfileBinding,
}

/// Project one verified Join callback into its exact 34-byte manifest-entry
/// representation.
///
/// The control ID bytes are copied from the observation without word or byte
/// reversal. Their order was fixed when the verified callback emitted its
/// explicit little-endian word encoding.
pub(crate) fn project_verified_join_terminal_record(
    terminal: &B4PositiveTerminalObservationV1,
    manifest: &StarkProfileManifestV1,
) -> Result<[u8; MANIFEST_CONTROL_ENTRY_BYTES], B4TerminalMetadataRecordError> {
    if terminal.kind != B4PositiveTerminalKind::Join || terminal.parameter != 0 {
        return Err(B4TerminalMetadataRecordError::ProfileBinding);
    }
    if terminal.control_id.len() != 64
        || !terminal
            .control_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(B4TerminalMetadataRecordError::Encoding);
    }

    let mut control_id = [0_u8; MANIFEST_CONTROL_ENTRY_BYTES - 2];
    hex::decode_to_slice(&terminal.control_id, &mut control_id)
        .map_err(|_| B4TerminalMetadataRecordError::Encoding)?;
    if manifest.validate_initial_profile_target().is_err() {
        return Err(B4TerminalMetadataRecordError::ProfileBinding);
    }
    let exact_matches = manifest
        .terminal_controls()
        .iter()
        .filter(|control| {
            control.control_kind() == TERMINAL_CONTROL_KIND_JOIN
                && control.parameter() == terminal.parameter
                && control.control_id() == control_id
        })
        .count();
    if exact_matches != 1 {
        return Err(B4TerminalMetadataRecordError::ProfileBinding);
    }

    let mut record = [0_u8; MANIFEST_CONTROL_ENTRY_BYTES];
    record[0] = TERMINAL_CONTROL_KIND_JOIN;
    record[1] = terminal.parameter;
    record[2..].copy_from_slice(&control_id);
    Ok(record)
}

#[cfg(test)]
mod tests {
    use crate::{
        b4_validator::{B4PositiveTerminalKind, B4PositiveTerminalObservationV1},
        constants::{MANIFEST_BYTES, TERMINAL_CONTROL_KIND_JOIN},
        profile_manifest::StarkProfileManifestV1,
    };

    use super::{B4TerminalMetadataRecordError, project_verified_join_terminal_record};

    const MANIFEST: &[u8; MANIFEST_BYTES] =
        include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin");

    fn manifest() -> StarkProfileManifestV1 {
        let manifest = StarkProfileManifestV1::decode(MANIFEST).unwrap();
        manifest.validate_initial_profile_target().unwrap();
        manifest
    }

    fn join_observation() -> B4PositiveTerminalObservationV1 {
        let manifest = manifest();
        let join = manifest
            .terminal_controls()
            .iter()
            .find(|control| {
                control.control_kind() == TERMINAL_CONTROL_KIND_JOIN && control.parameter() == 0
            })
            .unwrap();
        B4PositiveTerminalObservationV1 {
            kind: B4PositiveTerminalKind::Join,
            parameter: 0,
            control_id: hex::encode(join.control_id()),
        }
    }

    #[test]
    fn verified_join_projects_the_exact_manifest_control_entry_bytes() {
        let manifest = manifest();
        let observation = join_observation();

        let record = project_verified_join_terminal_record(&observation, &manifest).unwrap();

        assert_eq!(record[0], TERMINAL_CONTROL_KIND_JOIN);
        assert_eq!(record[1], 0);
        assert_eq!(hex::encode(&record[2..]), observation.control_id);
    }

    #[test]
    fn non_join_nonzero_malformed_and_unbound_observations_fail_closed() {
        let manifest = manifest();

        let mut non_join = join_observation();
        non_join.kind = B4PositiveTerminalKind::Resolve;
        assert_eq!(
            project_verified_join_terminal_record(&non_join, &manifest),
            Err(B4TerminalMetadataRecordError::ProfileBinding)
        );

        let mut nonzero = join_observation();
        nonzero.parameter = 1;
        assert_eq!(
            project_verified_join_terminal_record(&nonzero, &manifest),
            Err(B4TerminalMetadataRecordError::ProfileBinding)
        );

        let mut malformed = join_observation();
        malformed.control_id = "AA".repeat(32);
        assert_eq!(
            project_verified_join_terminal_record(&malformed, &manifest),
            Err(B4TerminalMetadataRecordError::Encoding)
        );

        let mut unbound = join_observation();
        let mut control_id = hex::decode(&unbound.control_id).unwrap();
        control_id[0] ^= 1;
        unbound.control_id = hex::encode(control_id);
        assert_eq!(
            project_verified_join_terminal_record(&unbound, &manifest),
            Err(B4TerminalMetadataRecordError::ProfileBinding)
        );
    }
}
