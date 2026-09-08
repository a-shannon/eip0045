// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Closed command-line shell for the EIP-0045 B4 reference validator.

use std::{
    io::{self, Write as _},
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    process::ExitCode,
    str::FromStr,
};

use anyhow::{Context as _, Error};
use clap::{Args, Parser, Subcommand};
use eip_0045_reproduction::b4_validator::{
    B4StarkError, B4StarkErrorClass, Eip0045B4NegativeObservationV1, NEGATIVE_INPUT_FILE,
    POSITIVE_INPUT_FILE, verify_negative_root, verify_positive_root,
};

const PROOF_REJECTION_EXIT: u8 = 10;
const INPUT_REJECTION_EXIT: u8 = 11;
const RUNTIME_FAILURE_EXIT: u8 = 12;
const MAX_DIAGNOSTIC_BYTES: usize = 512;

#[derive(Debug, Parser)]
#[command(name = "eip0045-b4-validator")]
#[command(about = "Run the closed EIP-0045 B4 reference validator")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify one closed positive-root package.
    VerifyPositive(PositiveVerifyArgs),
    /// Verify one closed negative-root package.
    VerifyNegative(NegativeVerifyArgs),
}

#[derive(Debug, Args)]
struct PositiveVerifyArgs {
    /// Closed verifier root containing the fixed seven-file package.
    #[arg(long)]
    root: PathBuf,
    /// Fixed canonical positive-input filename.
    #[arg(long)]
    input: PositiveInputName,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PositiveInputName;

impl FromStr for PositiveInputName {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == POSITIVE_INPUT_FILE {
            Ok(Self)
        } else {
            Err(format!(
                "input must be the exact fixed name {POSITIVE_INPUT_FILE}"
            ))
        }
    }
}

#[derive(Debug, Args)]
struct NegativeVerifyArgs {
    /// Closed verifier root containing the negative execution package.
    #[arg(long)]
    root: PathBuf,
    /// Fixed canonical negative-input filename.
    #[arg(long)]
    input: NegativeInputName,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NegativeInputName;

impl FromStr for NegativeInputName {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == NEGATIVE_INPUT_FILE {
            Ok(Self)
        } else {
            Err(format!(
                "input must be the exact fixed name {NEGATIVE_INPUT_FILE}"
            ))
        }
    }
}

#[derive(Debug)]
struct CliFailure {
    exit_code: u8,
    diagnostic: String,
}

impl CliFailure {
    fn input(diagnostic: impl Into<String>) -> Self {
        Self {
            exit_code: INPUT_REJECTION_EXIT,
            diagnostic: diagnostic.into(),
        }
    }

    fn from_verification(error: &Error) -> Self {
        let boundary = error.chain().find_map(|source| {
            source
                .downcast_ref::<B4StarkError>()
                .map(B4StarkError::rejection_boundary)
        });

        match boundary {
            Some(boundary)
                if matches!(
                    boundary.class,
                    B4StarkErrorClass::TerminalPolicy
                        | B4StarkErrorClass::Risc0CryptographicVerifier
                ) =>
            {
                Self {
                    exit_code: PROOF_REJECTION_EXIT,
                    diagnostic: format!(
                        "proof rejected (class={}, stage={})",
                        boundary.class.as_str(),
                        boundary.stage.as_str()
                    ),
                }
            }
            Some(boundary) => Self {
                exit_code: INPUT_REJECTION_EXIT,
                diagnostic: format!(
                    "input or binding rejected (class={}, stage={})",
                    boundary.class.as_str(),
                    boundary.stage.as_str()
                ),
            },
            None => Self::input(format!("input or profile rejected: {error}")),
        }
    }

    fn runtime(diagnostic: impl Into<String>) -> Self {
        Self {
            exit_code: RUNTIME_FAILURE_EXIT,
            diagnostic: diagnostic.into(),
        }
    }
}

fn main() -> ExitCode {
    match prepare_output_with_panic_boundary() {
        Ok(observation) => {
            let stdout = io::stdout();
            let mut output = stdout.lock();
            match output.write_all(&observation).and_then(|()| output.flush()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(&CliFailure::runtime(format!(
                    "cannot flush canonical observation: {error}"
                ))),
            }
        }
        Err(error) => fail(&error),
    }
}

fn prepare_output_with_panic_boundary() -> Result<Vec<u8>, CliFailure> {
    run_with_silent_panic_boundary(|| {
        let cli = Cli::try_parse().map_err(|error| CliFailure::input(error.to_string()))?;
        execute(cli)
    })
}

fn run_with_silent_panic_boundary<F>(operation: F) -> Result<Vec<u8>, CliFailure>
where
    F: FnOnce() -> Result<Vec<u8>, CliFailure>,
{
    let prior_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(operation));
    std::panic::set_hook(prior_hook);

    match result {
        Ok(result) => result,
        Err(_) => Err(CliFailure::runtime("internal validator panic")),
    }
}

fn execute(cli: Cli) -> Result<Vec<u8>, CliFailure> {
    match cli.command {
        Command::VerifyPositive(args) => {
            let PositiveVerifyArgs {
                root,
                input: PositiveInputName,
            } = args;
            let observation = verify_positive_root(&root)
                .map_err(|error| CliFailure::from_verification(&error))?;
            observation
                .to_canonical_jcs()
                .context("cannot serialize the accepted positive observation")
                .map_err(|error| CliFailure::from_verification(&error))
        }
        Command::VerifyNegative(args) => {
            let NegativeVerifyArgs {
                root,
                input: NegativeInputName,
            } = args;
            let observation = verify_negative_root(&root).map_err(|error| {
                CliFailure::runtime(format!(
                    "negative verification failed without an observation: {error}"
                ))
            })?;
            serialize_negative_observation(&observation)
        }
    }
}

fn serialize_negative_observation(
    observation: &Eip0045B4NegativeObservationV1,
) -> Result<Vec<u8>, CliFailure> {
    observation
        .to_canonical_jcs()
        .context("cannot serialize the rejected negative observation")
        .map_err(|error| {
            CliFailure::runtime(format!(
                "negative observation serialization failed: {error}"
            ))
        })
}

fn fail(failure: &CliFailure) -> ExitCode {
    write_bounded_diagnostic(&failure.diagnostic);
    ExitCode::from(failure.exit_code)
}

fn write_bounded_diagnostic(diagnostic: &str) {
    let prefix = "eip0045-b4-validator: ";
    let mut bounded = String::with_capacity(MAX_DIAGNOSTIC_BYTES);
    bounded.push_str(prefix);

    for character in diagnostic.chars() {
        if bounded.len() >= MAX_DIAGNOSTIC_BYTES - 1 {
            break;
        }
        let character = if character.is_ascii_graphic() || character == ' ' {
            character
        } else {
            '?'
        };
        bounded.push(character);
    }
    bounded.truncate(MAX_DIAGNOSTIC_BYTES - 1);
    bounded.push('\n');
    let _ = io::stderr().lock().write_all(bounded.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use eip_0045_reproduction::{
        b4_negative_io::{B4_NEGATIVE_OBSERVATION_FORMAT, B4_NEGATIVE_OBSERVATION_FORMAT_VERSION},
        b4_plan::{B4MaterializationDomain, B4NegativeExecutionSurface},
        b4_validator::{
            B4NegativeObservationRejectionV1, B4NegativeObservationVerdict, B4Risc0Failure,
        },
    };

    fn parse(arguments: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(
            std::iter::once("eip0045-b4-validator").chain(arguments.iter().copied()),
        )
    }

    #[test]
    fn parser_accepts_only_the_fixed_input_name_for_both_commands() {
        assert!(
            parse(&[
                "verify-positive",
                "--root",
                "root",
                "--input",
                POSITIVE_INPUT_FILE
            ])
            .is_ok()
        );
        assert!(
            parse(&[
                "verify-positive",
                "--root",
                "root",
                "--input",
                NEGATIVE_INPUT_FILE
            ])
            .is_err()
        );
        assert!(
            parse(&[
                "verify-positive",
                "--root",
                "root",
                "--input",
                "./verifier-input.json"
            ])
            .is_err()
        );

        assert!(
            parse(&[
                "verify-negative",
                "--root",
                "root",
                "--input",
                NEGATIVE_INPUT_FILE
            ])
            .is_ok()
        );
        assert!(
            parse(&[
                "verify-negative",
                "--root",
                "root",
                "--input",
                POSITIVE_INPUT_FILE
            ])
            .is_err()
        );
        assert!(
            parse(&[
                "verify-negative",
                "--root",
                "root",
                "--input",
                "./negative-input.json"
            ])
            .is_err()
        );
    }

    #[test]
    fn negative_command_invokes_root_custody_and_fails_without_an_observation() {
        let failure = execute(
            parse(&[
                "verify-negative",
                "--root",
                "missing-negative-root",
                "--input",
                NEGATIVE_INPUT_FILE,
            ])
            .unwrap(),
        )
        .unwrap_err();
        assert_eq!(failure.exit_code, RUNTIME_FAILURE_EXIT);
        assert!(failure.diagnostic.contains("failed without an observation"));
        assert!(!failure.diagnostic.contains("temporarily fail-closed"));
    }

    #[test]
    fn panic_boundary_maps_internal_panics_to_private_runtime_failure() {
        let failure = run_with_silent_panic_boundary(|| -> Result<Vec<u8>, CliFailure> {
            panic!("private panic payload")
        })
        .unwrap_err();
        assert_eq!(failure.exit_code, RUNTIME_FAILURE_EXIT);
        assert_eq!(failure.diagnostic, "internal validator panic");
    }

    #[test]
    fn intended_negative_rejection_serializes_as_exact_canonical_jcs() {
        let observation = Eip0045B4NegativeObservationV1 {
            format: B4_NEGATIVE_OBSERVATION_FORMAT.to_owned(),
            format_version: B4_NEGATIVE_OBSERVATION_FORMAT_VERSION,
            materialization_domain: B4MaterializationDomain::ArtifactValidator,
            validation_surface: B4NegativeExecutionSurface::ProfileManifestCodec,
            negative_input_sha256: "aa".repeat(32),
            subject_byte_length: 1,
            subject_sha256: "bb".repeat(32),
            verdict: B4NegativeObservationVerdict::Reject,
            rejection: B4NegativeObservationRejectionV1 {
                class: "profile-manifest-invalid".to_owned(),
                stage: "profile-manifest-byte-length".to_owned(),
            },
        };
        let output = serialize_negative_observation(&observation).unwrap();
        assert_eq!(
            Eip0045B4NegativeObservationV1::from_canonical_jcs(&output).unwrap(),
            observation
        );
        assert!(!output.ends_with(b"\n"));
    }

    #[test]
    fn typed_errors_are_found_through_anyhow_contexts_and_classified() {
        let cryptographic = anyhow!(B4StarkError::Risc0Verifier(B4Risc0Failure::InvalidProof))
            .context("outer context");
        assert_eq!(
            CliFailure::from_verification(&cryptographic).exit_code,
            PROOF_REJECTION_EXIT
        );

        let terminal = anyhow!(B4StarkError::TerminalCallbackMissing).context("outer context");
        assert_eq!(
            CliFailure::from_verification(&terminal).exit_code,
            PROOF_REJECTION_EXIT
        );

        let parser = anyhow!(B4StarkError::Risc0Verifier(B4Risc0Failure::ReceiptFormat))
            .context("outer context");
        assert_eq!(
            CliFailure::from_verification(&parser).exit_code,
            INPUT_REJECTION_EXIT
        );

        let binding = anyhow!(B4StarkError::ClaimDigestMismatch {
            expected: [0; 32],
            actual: [1; 32],
        })
        .context("outer context");
        assert_eq!(
            CliFailure::from_verification(&binding).exit_code,
            INPUT_REJECTION_EXIT
        );
    }

    #[test]
    fn diagnostics_are_ascii_and_bounded() {
        let long = "é\n".repeat(MAX_DIAGNOSTIC_BYTES);
        let prefix = "eip0045-b4-validator: ";
        let mut bounded = String::with_capacity(MAX_DIAGNOSTIC_BYTES);
        bounded.push_str(prefix);
        for character in long.chars() {
            if bounded.len() >= MAX_DIAGNOSTIC_BYTES - 1 {
                break;
            }
            bounded.push(if character.is_ascii_graphic() || character == ' ' {
                character
            } else {
                '?'
            });
        }
        bounded.truncate(MAX_DIAGNOSTIC_BYTES - 1);
        bounded.push('\n');
        assert!(bounded.is_ascii());
        assert!(bounded.len() <= MAX_DIAGNOSTIC_BYTES);
        assert!(bounded.ends_with('\n'));
    }
}
