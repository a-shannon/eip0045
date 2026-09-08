// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Single compiled path authority for recursive positive auxiliary seals.

use anyhow::Result;

const NO_AUXILIARY_ARTIFACT_PATHS: [&str; 0] = [];
const TERMINAL_JOIN_AUXILIARY_ARTIFACT_PATHS: [&str; 2] = [
    "reproduction/schema/b4-corpus-v1.candidate/positive/terminal-join/candidate-ancestry-step-00-raw-seal.bin",
    "reproduction/schema/b4-corpus-v1.candidate/positive/terminal-join/candidate-ancestry-step-01-raw-seal.bin",
];
const TERMINAL_RESOLVE_AUXILIARY_ARTIFACT_PATHS: [&str; 2] = [
    "reproduction/schema/b4-corpus-v1.candidate/positive/terminal-resolve-explicit-root/candidate-ancestry-assumption-raw-seal.bin",
    "reproduction/schema/b4-corpus-v1.candidate/positive/terminal-resolve-explicit-root/candidate-ancestry-step-00-raw-seal.bin",
];
const RESOLVE_THEN_JOIN_AUXILIARY_ARTIFACT_PATHS: [&str; 4] = [
    "reproduction/schema/b4-corpus-v1.candidate/positive/resolve-zero-root-then-join/candidate-ancestry-assumption-raw-seal.bin",
    "reproduction/schema/b4-corpus-v1.candidate/positive/resolve-zero-root-then-join/candidate-ancestry-step-00-raw-seal.bin",
    "reproduction/schema/b4-corpus-v1.candidate/positive/resolve-zero-root-then-join/candidate-ancestry-step-01-raw-seal.bin",
    "reproduction/schema/b4-corpus-v1.candidate/positive/resolve-zero-root-then-join/candidate-ancestry-step-02-raw-seal.bin",
];

/// Path set whose four exact seals define the largest admitted auxiliary map.
pub(crate) const MAX_RECURSIVE_AUXILIARY_ARTIFACT_PATHS: &[&str] =
    &RESOLVE_THEN_JOIN_AUXILIARY_ARTIFACT_PATHS;

/// Return the exact auxiliary raw-seal path sequence for one positive case.
///
/// Lift cases have an empty inventory; recursive cases have the sole compiled
/// path sequence admitted by generation, custody, materialization, and replay.
pub(crate) fn compiled_positive_auxiliary_artifact_paths(
    case_index: usize,
) -> Result<&'static [&'static str]> {
    match case_index {
        0..=7 => Ok(&NO_AUXILIARY_ARTIFACT_PATHS),
        8 => Ok(&TERMINAL_JOIN_AUXILIARY_ARTIFACT_PATHS),
        9 => Ok(&TERMINAL_RESOLVE_AUXILIARY_ARTIFACT_PATHS),
        10 => Ok(MAX_RECURSIVE_AUXILIARY_ARTIFACT_PATHS),
        _ => anyhow::bail!("positive generation case index is outside the closed eleven-case plan"),
    }
}

#[cfg(test)]
mod tests {
    use super::compiled_positive_auxiliary_artifact_paths;

    #[test]
    fn compiled_paths_cover_exactly_the_three_recursive_case_inventories() {
        assert_eq!(
            compiled_positive_auxiliary_artifact_paths(8).unwrap(),
            [
                "reproduction/schema/b4-corpus-v1.candidate/positive/terminal-join/candidate-ancestry-step-00-raw-seal.bin",
                "reproduction/schema/b4-corpus-v1.candidate/positive/terminal-join/candidate-ancestry-step-01-raw-seal.bin",
            ]
        );
        assert_eq!(
            compiled_positive_auxiliary_artifact_paths(9).unwrap(),
            [
                "reproduction/schema/b4-corpus-v1.candidate/positive/terminal-resolve-explicit-root/candidate-ancestry-assumption-raw-seal.bin",
                "reproduction/schema/b4-corpus-v1.candidate/positive/terminal-resolve-explicit-root/candidate-ancestry-step-00-raw-seal.bin",
            ]
        );
        assert_eq!(
            compiled_positive_auxiliary_artifact_paths(10).unwrap(),
            [
                "reproduction/schema/b4-corpus-v1.candidate/positive/resolve-zero-root-then-join/candidate-ancestry-assumption-raw-seal.bin",
                "reproduction/schema/b4-corpus-v1.candidate/positive/resolve-zero-root-then-join/candidate-ancestry-step-00-raw-seal.bin",
                "reproduction/schema/b4-corpus-v1.candidate/positive/resolve-zero-root-then-join/candidate-ancestry-step-01-raw-seal.bin",
                "reproduction/schema/b4-corpus-v1.candidate/positive/resolve-zero-root-then-join/candidate-ancestry-step-02-raw-seal.bin",
            ]
        );
    }

    #[test]
    fn lift_cases_are_empty_and_out_of_range_is_rejected() {
        for index in 0..8 {
            assert!(
                compiled_positive_auxiliary_artifact_paths(index)
                    .unwrap()
                    .is_empty()
            );
        }
        assert!(compiled_positive_auxiliary_artifact_paths(11).is_err());
    }

    #[test]
    fn every_compiled_inventory_is_strict_unsigned_path_order() {
        for index in 8..=10 {
            let paths = compiled_positive_auxiliary_artifact_paths(index).unwrap();
            assert!(
                paths
                    .windows(2)
                    .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
            );
        }
    }
}
