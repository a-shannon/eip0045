// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Closed dispatcher for one physically authenticated B4 negative root.
//!
//! Dispatch authority comes only from the sole twenty-row handler table.  A
//! pathless observation can be constructed only from one typed rejection
//! returned by the selected production adapter.  Custody, framing,
//! unavailable-producer, unexpected-rejection, and unexpected-acceptance
//! failures remain private runtime errors and produce no observation.

use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use sha2::{Digest as _, Sha256};

use crate::{
    b4_negative_handler_contract::{
        B4NegativeHandlerSelector, planned_negative_handler_contract,
        validate_negative_rejection_boundary,
    },
    b4_negative_io::{
        B4_NEGATIVE_OBSERVATION_FORMAT, B4_NEGATIVE_OBSERVATION_FORMAT_VERSION,
        B4NegativeObservationRejectionV1, B4NegativeObservationVerdict,
        Eip0045B4NegativeObservationV1, Eip0045B4NegativeVerifierInputV1,
    },
};

use super::{
    negative_ancestry::{B4AncestryRejection, reject_ancestry_replay},
    negative_artifact_catalog::{
        B4ArtifactCatalogRejection, reject_artifact_terminal_policy, reject_candidate_registry,
        reject_negative_binding_index, reject_sequence_subject_catalog,
        reject_terminal_fixture_catalog, reject_terminal_metadata, reject_tree_corpus_closure,
    },
    negative_artifact_profile::{B4ArtifactProfileRejection, validate_profile_negative},
    negative_crypto::{B4CryptoBoundary, reject_crypto_depth},
    negative_input::{B4NegativeVerifierRoot, load_negative_verifier_root},
    negative_parser::{B4ParserBoundary, reject_parser_prefix},
    negative_verifier::{
        B4NegativeVerifierBoundary, reject_opcode_preflight, reject_raw_seal_shape,
        reject_raw_statement_claim_binding, reject_receipt_claim_policy, reject_terminal_policy,
    },
};

#[derive(Clone, Copy)]
struct AuthenticatedFileView<'a> {
    bytes: &'a [u8],
    sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StableRejectionBoundary {
    class: &'static str,
    stage: &'static str,
}

impl StableRejectionBoundary {
    const fn new(class: &'static str, stage: &'static str) -> Self {
        Self { class, stage }
    }
}

/// Authenticate and verify one closed negative-root package.
///
/// # Errors
///
/// Returns an error without an observation on unsupported custody platforms,
/// physical or canonical-input drift, a pending handler row, private adapter
/// framing, unavailable producer or instrumentation, unexpected acceptance,
/// an unintended consumer rejection, or observation-construction failure.
pub fn verify_negative_root(root: impl AsRef<Path>) -> Result<Eip0045B4NegativeObservationV1> {
    let root = load_negative_verifier_root(root.as_ref())?;
    verify_authenticated_root(&root)
}

fn verify_authenticated_root(
    root: &B4NegativeVerifierRoot,
) -> Result<Eip0045B4NegativeObservationV1> {
    let contexts = root
        .contexts()
        .iter()
        .map(|file| AuthenticatedFileView {
            bytes: file.bytes(),
            sha256: file.sha256(),
        })
        .collect::<Vec<_>>();
    verify_authenticated_parts(
        AuthenticatedFileView {
            bytes: root.negative_input_file().bytes(),
            sha256: root.negative_input_file().sha256(),
        },
        root.input(),
        AuthenticatedFileView {
            bytes: root.subject().bytes(),
            sha256: root.subject().sha256(),
        },
        &contexts,
    )
}

fn verify_authenticated_parts(
    negative_input_file: AuthenticatedFileView<'_>,
    input: &Eip0045B4NegativeVerifierInputV1,
    subject: AuthenticatedFileView<'_>,
    contexts: &[AuthenticatedFileView<'_>],
) -> Result<Eip0045B4NegativeObservationV1> {
    authenticate_file_view(negative_input_file, "negative input")?;
    let reparsed_input =
        Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(negative_input_file.bytes)
            .context("authenticated negative input cannot be parsed")?;
    ensure!(
        reparsed_input == *input,
        "retained negative input differs from its authenticated canonical bytes"
    );

    authenticate_file_view(subject, "negative subject")?;
    ensure!(
        input.subject.byte_length
            == u64::try_from(subject.bytes.len())
                .context("negative subject byte length does not fit u64")?,
        "negative subject measured length differs from the neutral input"
    );
    ensure!(
        input.subject.sha256 == hex::encode(subject.sha256),
        "negative subject measured digest differs from the neutral input"
    );

    let contract =
        planned_negative_handler_contract(input.materialization_domain, input.validation_surface)?
            .context("negative input has no handler in the sole canonical table")?;
    ensure!(
        contract.is_frozen(),
        "selected negative handler remains pending and cannot produce an observation"
    );
    let custody = contract.custody();
    ensure!(
        custody.subject().contains(
            u64::try_from(subject.bytes.len())
                .context("negative subject byte length does not fit u64")?
        ),
        "negative subject measured length is outside the selected handler contract"
    );
    ensure!(
        contexts.len() == custody.contexts().len()
            && input.context.len() == custody.contexts().len(),
        "negative context cardinality differs from the selected handler contract"
    );

    for (index, ((view, identity), bounds)) in contexts
        .iter()
        .zip(&input.context)
        .zip(custody.contexts())
        .enumerate()
    {
        authenticate_file_view(*view, "negative context")?;
        let measured_length = u64::try_from(view.bytes.len())
            .context("negative context byte length does not fit u64")?;
        ensure!(
            bounds.contains(measured_length),
            "negative context {index:02} measured length is outside the selected handler contract"
        );
        ensure!(
            identity.byte_length == measured_length,
            "negative context {index:02} measured length differs from the neutral input"
        );
        ensure!(
            identity.sha256 == hex::encode(view.sha256),
            "negative context {index:02} measured digest differs from the neutral input"
        );
    }

    let context_bytes = contexts.iter().map(|file| file.bytes).collect::<Vec<_>>();
    let rejection = invoke_selected_adapter(contract.selector(), subject.bytes, &context_bytes)?;
    validate_negative_rejection_boundary(
        input.materialization_domain,
        input.validation_surface,
        rejection.class,
        rejection.stage,
    )
    .map_err(|_| private_adapter_failure(contract.selector()))?;
    let observation = Eip0045B4NegativeObservationV1 {
        format: B4_NEGATIVE_OBSERVATION_FORMAT.to_owned(),
        format_version: B4_NEGATIVE_OBSERVATION_FORMAT_VERSION,
        materialization_domain: input.materialization_domain,
        validation_surface: input.validation_surface,
        negative_input_sha256: hex::encode(negative_input_file.sha256),
        subject_byte_length: u64::try_from(subject.bytes.len())
            .context("negative subject byte length does not fit u64")?,
        subject_sha256: hex::encode(subject.sha256),
        verdict: B4NegativeObservationVerdict::Reject,
        rejection: B4NegativeObservationRejectionV1 {
            class: rejection.class.to_owned(),
            stage: rejection.stage.to_owned(),
        },
    };
    observation.validate()?;
    Ok(observation)
}

fn authenticate_file_view(view: AuthenticatedFileView<'_>, label: &str) -> Result<()> {
    ensure!(
        sha256(view.bytes) == view.sha256,
        "{label} retained digest differs from its measured bytes"
    );
    Ok(())
}

fn invoke_selected_adapter(
    selector: B4NegativeHandlerSelector,
    subject: &[u8],
    contexts: &[&[u8]],
) -> Result<StableRejectionBoundary> {
    use B4NegativeHandlerSelector as H;

    match selector {
        H::VerifierOpcodePreflight => reject_opcode_preflight(subject, contexts)
            .map(verifier_boundary)
            .map_err(|_| private_adapter_failure(selector)),
        H::VerifierRawStatementClaimBinding => {
            reject_raw_statement_claim_binding(subject, contexts)
                .map(verifier_boundary)
                .map_err(|_| private_adapter_failure(selector))
        }
        H::VerifierRawSealShape => reject_raw_seal_shape(subject, contexts)
            .map(verifier_boundary)
            .map_err(|_| private_adapter_failure(selector)),
        H::VerifierRisc0ParserInternal => reject_parser_prefix(subject, contexts)
            .and_then(parser_boundary)
            .map_err(|_| private_adapter_failure(selector)),
        H::VerifierRisc0CryptographicVerifier => reject_crypto_depth(subject, contexts)
            .map(crypto_boundary)
            .map_err(|_| private_adapter_failure(selector)),
        H::VerifierTerminalPolicy => reject_terminal_policy(subject, contexts)
            .map(verifier_boundary)
            .map_err(|_| private_adapter_failure(selector)),
        H::VerifierReceiptClaimPolicy => reject_receipt_claim_policy(subject, contexts)
            .map(verifier_boundary)
            .map_err(|_| private_adapter_failure(selector)),
        H::VerifierAncestryReplay => reject_ancestry_replay(subject, contexts)
            .map(ancestry_boundary)
            .map_err(|_| private_adapter_failure(selector)),
        H::ArtifactTerminalPolicy => reject_artifact_terminal_policy(subject, contexts[0])
            .map(catalog_boundary)
            .map_err(|_| private_adapter_failure(selector)),
        H::ArtifactProfileManifestCodec
        | H::ArtifactInitialProfileTarget
        | H::ArtifactProfileArtifactEnvelope
        | H::ArtifactActivatedProfilePackage
        | H::ArtifactProfileIdPreimage => validate_profile_negative(selector, subject, contexts)
            .map(profile_boundary)
            .map_err(|_| private_adapter_failure(selector)),
        H::ArtifactTerminalFixtureCatalog => reject_terminal_fixture_catalog(subject)
            .map(catalog_boundary)
            .map_err(|_| private_adapter_failure(selector)),
        H::ArtifactSequenceSubjectCatalog => reject_sequence_subject_catalog(subject)
            .map(catalog_boundary)
            .map_err(|_| private_adapter_failure(selector)),
        H::ArtifactTerminalMetadata => reject_terminal_metadata(subject, contexts)
            .map(catalog_boundary)
            .map_err(|_| private_adapter_failure(selector)),
        H::ArtifactCandidateRegistry => reject_candidate_registry(subject)
            .map(catalog_boundary)
            .map_err(|_| private_adapter_failure(selector)),
        H::ArtifactNegativeBindingIndex => reject_negative_binding_index(subject)
            .map(catalog_boundary)
            .map_err(|_| private_adapter_failure(selector)),
        H::TreeCorpusClosure => reject_tree_corpus_closure(subject)
            .map(catalog_boundary)
            .map_err(|_| private_adapter_failure(selector)),
    }
}

fn private_adapter_failure(selector: B4NegativeHandlerSelector) -> anyhow::Error {
    anyhow::anyhow!(
        "selected negative adapter {selector:?} failed privately; no observation was produced"
    )
}

const fn verifier_boundary(boundary: B4NegativeVerifierBoundary) -> StableRejectionBoundary {
    StableRejectionBoundary::new(boundary.class(), boundary.stage())
}

fn parser_boundary(
    boundary: B4ParserBoundary,
) -> Result<StableRejectionBoundary, super::negative_parser::B4ParserAdapterError> {
    let stage = boundary
        .planned_stage()
        .ok_or(super::negative_parser::B4ParserAdapterError::UnplannedCampaignBoundary(boundary))?;
    Ok(StableRejectionBoundary::new(boundary.class(), stage))
}

const fn crypto_boundary(boundary: B4CryptoBoundary) -> StableRejectionBoundary {
    StableRejectionBoundary::new(boundary.class(), boundary.stage())
}

const fn ancestry_boundary(rejection: B4AncestryRejection) -> StableRejectionBoundary {
    use B4AncestryRejection as R;

    match rejection {
        R::ClaimEdge => StableRejectionBoundary::new("ancestry-replay-mismatch", "claim-edge"),
        R::ResolveExplicit => {
            StableRejectionBoundary::new("ancestry-replay-mismatch", "resolve-explicit-semantics")
        }
        R::ResolveZeroRoot => {
            StableRejectionBoundary::new("ancestry-replay-mismatch", "resolve-zero-root-semantics")
        }
        R::AssumptionInventory => {
            StableRejectionBoundary::new("ancestry-replay-mismatch", "resolve-assumption-inventory")
        }
    }
}

const fn profile_boundary(rejection: B4ArtifactProfileRejection) -> StableRejectionBoundary {
    use B4ArtifactProfileRejection as R;

    match rejection {
        R::ManifestLength => {
            StableRejectionBoundary::new("profile-manifest-invalid", "profile-manifest-byte-length")
        }
        R::ManifestVersion => StableRejectionBoundary::new(
            "profile-manifest-invalid",
            "profile-manifest-format-version",
        ),
        R::ManifestProofLength => StableRejectionBoundary::new(
            "profile-manifest-invalid",
            "profile-manifest-proof-byte-length",
        ),
        R::ManifestTerminalKind { .. } => StableRejectionBoundary::new(
            "profile-manifest-invalid",
            "profile-manifest-terminal-kind",
        ),
        R::ManifestTerminalParameter { .. } => StableRejectionBoundary::new(
            "profile-manifest-invalid",
            "profile-manifest-terminal-parameter",
        ),
        R::ManifestTerminalOrder { .. } => StableRejectionBoundary::new(
            "profile-manifest-invalid",
            "profile-manifest-terminal-order",
        ),
        R::ManifestTerminalControlIdDuplicate { .. } => StableRejectionBoundary::new(
            "profile-manifest-invalid",
            "profile-manifest-terminal-control-id-uniqueness",
        ),
        R::ManifestArtifactKind { .. } => StableRejectionBoundary::new(
            "profile-manifest-invalid",
            "profile-manifest-artifact-kind",
        ),
        R::ManifestArtifactEmpty { .. } => StableRejectionBoundary::new(
            "profile-manifest-invalid",
            "profile-manifest-artifact-byte-length",
        ),
        R::InitialExactProofBytes => {
            StableRejectionBoundary::new("initial-profile-target-mismatch", "exact-proof-bytes")
        }
        R::InitialMaximumPayload => StableRejectionBoundary::new(
            "initial-profile-target-mismatch",
            "maximum-application-payload-bytes",
        ),
        R::InitialOuterPo2 => {
            StableRejectionBoundary::new("initial-profile-target-mismatch", "outer-po2")
        }
        R::InitialInnerControlRoot => {
            StableRejectionBoundary::new("initial-profile-target-mismatch", "inner-control-root")
        }
        R::InitialTerminalControl { .. } => {
            StableRejectionBoundary::new("initial-profile-target-mismatch", "terminal-control-id")
        }
        R::ArtifactLength { .. } => StableRejectionBoundary::new(
            "profile-artifact-package-mismatch",
            "profile-artifact-byte-length",
        ),
        R::ArtifactDigest { .. } => StableRejectionBoundary::new(
            "profile-artifact-package-mismatch",
            "profile-artifact-digest",
        ),
        R::ActivatedProfileId => StableRejectionBoundary::new(
            "activated-profile-package-mismatch",
            "activated-profile-id",
        ),
        R::ProfileIdPreimage => StableRejectionBoundary::new(
            "profile-id-preimage-mismatch",
            "profile-id-preimage-binding",
        ),
    }
}

const fn catalog_boundary(rejection: B4ArtifactCatalogRejection) -> StableRejectionBoundary {
    use B4ArtifactCatalogRejection as R;

    match rejection {
        R::TerminalPolicy => {
            StableRejectionBoundary::new("terminal-policy-mismatch", "terminal-control-id")
        }
        R::TerminalFixtureCatalogBinding => StableRejectionBoundary::new(
            "terminal-fixture-catalog-mismatch",
            "terminal-fixture-catalog-binding",
        ),
        R::TerminalMetadataBinding => {
            StableRejectionBoundary::new("terminal-metadata-mismatch", "terminal-metadata-binding")
        }
        R::SequenceSubjectCatalog => StableRejectionBoundary::new(
            "sequence-subject-catalog-invalid",
            "sequence-subject-catalog-validation",
        ),
        R::CandidateRegistry => StableRejectionBoundary::new(
            "candidate-registry-invalid",
            "candidate-registry-validation",
        ),
        R::NegativeBindingIndexCodec => StableRejectionBoundary::new(
            "negative-binding-index-invalid",
            "negative-binding-index-codec",
        ),
        R::NegativeBindingIndexPlanBinding => StableRejectionBoundary::new(
            "negative-binding-index-invalid",
            "negative-binding-index-plan-binding",
        ),
        R::CorpusRequiredRoleMissing => {
            StableRejectionBoundary::new("corpus-closure-mismatch", "corpus-required-role")
        }
        R::CorpusUnexpectedRole => {
            StableRejectionBoundary::new("corpus-closure-mismatch", "corpus-unexpected-role")
        }
    }
}

fn sha256(source: &[u8]) -> [u8; 32] {
    Sha256::digest(source).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        b4_negative_io::{
            B4_NEGATIVE_VERIFIER_INPUT_FORMAT, B4_NEGATIVE_VERIFIER_INPUT_FORMAT_VERSION,
            B4NegativeFileEncoding, B4NegativeNamedIdentityV1,
        },
        b4_plan::{B4MaterializationDomain, B4NegativeExecutionSurface},
        b4_validator::negative_parser::{
            AUTHENTICATED_PARSER_SEAL, B4ParserAdapterError,
            authenticated_parser_prefix_fixture_cases,
        },
        constants::{BYTES_PER_PROOF_WORD, PROOF_BYTES},
    };

    fn identity(role: &str, path: &str, bytes: &[u8]) -> B4NegativeNamedIdentityV1 {
        B4NegativeNamedIdentityV1 {
            role: role.to_owned(),
            path: path.to_owned(),
            byte_length: u64::try_from(bytes.len()).unwrap(),
            sha256: hex::encode(sha256(bytes)),
            encoding: B4NegativeFileEncoding::RawBytes,
        }
    }

    fn input_for(
        domain: B4MaterializationDomain,
        surface: B4NegativeExecutionSurface,
        subject: &[u8],
        contexts: &[&[u8]],
    ) -> (Eip0045B4NegativeVerifierInputV1, Vec<u8>) {
        let input = Eip0045B4NegativeVerifierInputV1 {
            format: B4_NEGATIVE_VERIFIER_INPUT_FORMAT.to_owned(),
            format_version: B4_NEGATIVE_VERIFIER_INPUT_FORMAT_VERSION,
            materialization_domain: domain,
            validation_surface: surface,
            subject: identity("subject", "subject.bin", subject),
            context: contexts
                .iter()
                .enumerate()
                .map(|(index, bytes)| {
                    identity(
                        &format!("context-{index:02}"),
                        &format!("context/{index:02}.bin"),
                        bytes,
                    )
                })
                .collect(),
        };
        let source = input.to_canonical_jcs().unwrap();
        (input, source)
    }

    fn verify_like_authenticated_root(
        input: &Eip0045B4NegativeVerifierInputV1,
        input_source: &[u8],
        subject: &[u8],
        contexts: &[&[u8]],
    ) -> Result<Eip0045B4NegativeObservationV1> {
        let context_views = contexts
            .iter()
            .map(|bytes| AuthenticatedFileView {
                bytes,
                sha256: sha256(bytes),
            })
            .collect::<Vec<_>>();
        verify_authenticated_parts(
            AuthenticatedFileView {
                bytes: input_source,
                sha256: sha256(input_source),
            },
            input,
            AuthenticatedFileView {
                bytes: subject,
                sha256: sha256(subject),
            },
            &context_views,
        )
    }

    #[test]
    fn authenticated_manifest_rejection_emits_one_pathless_canonical_observation() {
        let subject = [0_u8];
        let (input, source) = input_for(
            B4MaterializationDomain::ArtifactValidator,
            B4NegativeExecutionSurface::ProfileManifestCodec,
            &subject,
            &[],
        );
        let observation = verify_like_authenticated_root(&input, &source, &subject, &[]).unwrap();

        assert_eq!(
            observation.rejection,
            B4NegativeObservationRejectionV1 {
                class: "profile-manifest-invalid".to_owned(),
                stage: "profile-manifest-byte-length".to_owned(),
            }
        );
        assert_eq!(
            observation.negative_input_sha256,
            hex::encode(sha256(&source))
        );
        assert_eq!(observation.subject_sha256, hex::encode(sha256(&subject)));
        assert_eq!(observation.subject_byte_length, 1);
        let canonical = observation.to_canonical_jcs().unwrap();
        assert_eq!(
            Eip0045B4NegativeObservationV1::from_canonical_jcs(&canonical).unwrap(),
            observation
        );
        let text = String::from_utf8(canonical).unwrap();
        assert!(!text.contains("subject.bin"));
        assert!(!text.contains("context/"));
        assert!(!text.contains("diagnostic"));
    }

    #[test]
    fn retained_input_or_subject_digest_drift_is_private() {
        let subject = [0_u8];
        let (input, source) = input_for(
            B4MaterializationDomain::ArtifactValidator,
            B4NegativeExecutionSurface::ProfileManifestCodec,
            &subject,
            &[],
        );
        let result = verify_authenticated_parts(
            AuthenticatedFileView {
                bytes: &source,
                sha256: [0_u8; 32],
            },
            &input,
            AuthenticatedFileView {
                bytes: &subject,
                sha256: sha256(&subject),
            },
            &[],
        );
        assert!(result.is_err());

        let result = verify_authenticated_parts(
            AuthenticatedFileView {
                bytes: &source,
                sha256: sha256(&source),
            },
            &input,
            AuthenticatedFileView {
                bytes: &subject,
                sha256: [0_u8; 32],
            },
            &[],
        );
        assert!(result.is_err());
    }

    #[test]
    fn wrong_context_cardinality_is_private_before_adapter_dispatch() {
        let subject = [0_u8];
        let context = [1_u8];
        let (input, source) = input_for(
            B4MaterializationDomain::ArtifactValidator,
            B4NegativeExecutionSurface::ProfileManifestCodec,
            &subject,
            &[&context],
        );
        assert!(verify_like_authenticated_root(&input, &source, &subject, &[&context]).is_err());
    }

    #[test]
    fn authenticated_parser_prefixes_traverse_the_dispatcher_pathlessly() {
        let manifest = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");
        let cases = authenticated_parser_prefix_fixture_cases();
        assert_eq!(cases.len(), 36);
        for (subject, expected_stage) in cases {
            let (input, source) = input_for(
                B4MaterializationDomain::VerifierInput,
                B4NegativeExecutionSurface::Risc0ParserInternal,
                &subject,
                &[manifest],
            );
            let observation =
                verify_like_authenticated_root(&input, &source, &subject, &[manifest]).unwrap();
            assert_eq!(
                observation.rejection,
                B4NegativeObservationRejectionV1 {
                    class: "risc0-parser-invalid".to_owned(),
                    stage: expected_stage.to_owned(),
                }
            );
            assert_eq!(
                observation.materialization_domain,
                B4MaterializationDomain::VerifierInput
            );
            assert_eq!(
                observation.validation_surface,
                B4NegativeExecutionSurface::Risc0ParserInternal
            );
            assert_eq!(
                observation.negative_input_sha256,
                hex::encode(sha256(&source))
            );
            assert_eq!(
                observation.subject_byte_length,
                u64::try_from(subject.len()).unwrap()
            );
            assert_eq!(observation.subject_sha256, hex::encode(sha256(&subject)));
            let canonical = observation.to_canonical_jcs().unwrap();
            assert_eq!(
                Eip0045B4NegativeObservationV1::from_canonical_jcs(&canonical).unwrap(),
                observation
            );
            let text = String::from_utf8(canonical).unwrap();
            assert!(!text.contains("subject.bin"));
            assert!(!text.contains("context/"));
            assert!(!text.contains("diagnostic"));
        }
    }

    #[test]
    fn parser_cardinality_alignment_and_field_failures_remain_private() {
        let manifest = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");

        let no_context_subject = [];
        let (input, source) = input_for(
            B4MaterializationDomain::VerifierInput,
            B4NegativeExecutionSurface::Risc0ParserInternal,
            &no_context_subject,
            &[],
        );
        assert!(verify_like_authenticated_root(&input, &source, &no_context_subject, &[]).is_err());

        let unaligned_subject = [0_u8];
        let (input, source) = input_for(
            B4MaterializationDomain::VerifierInput,
            B4NegativeExecutionSurface::Risc0ParserInternal,
            &unaligned_subject,
            &[manifest],
        );
        assert!(
            verify_like_authenticated_root(&input, &source, &unaligned_subject, &[manifest])
                .is_err()
        );

        let unreduced_subject = risc0_zkp::field::baby_bear::P.to_le_bytes();
        let (input, source) = input_for(
            B4MaterializationDomain::VerifierInput,
            B4NegativeExecutionSurface::Risc0ParserInternal,
            &unreduced_subject,
            &[manifest],
        );
        assert!(
            verify_like_authenticated_root(&input, &source, &unreduced_subject, &[manifest])
                .is_err()
        );
    }

    #[test]
    fn parser_unplanned_and_non_receipt_format_failures_remain_private() {
        const DATA_TOP_BEFORE_READ_WORDS: usize = 289;
        const CODE_ROOT_FIRST_WORD: usize = 33;

        let manifest = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");

        let unplanned_subject = &AUTHENTICATED_PARSER_SEAL[..BYTES_PER_PROOF_WORD];
        let unplanned_boundary = reject_parser_prefix(unplanned_subject, &[manifest]).unwrap();
        assert_eq!(unplanned_boundary.planned_stage(), None);
        let (input, source) = input_for(
            B4MaterializationDomain::VerifierInput,
            B4NegativeExecutionSurface::Risc0ParserInternal,
            unplanned_subject,
            &[manifest],
        );
        assert!(
            verify_like_authenticated_root(&input, &source, unplanned_subject, &[manifest])
                .is_err()
        );

        let mut non_receipt_format_subject =
            AUTHENTICATED_PARSER_SEAL[..DATA_TOP_BEFORE_READ_WORDS * BYTES_PER_PROOF_WORD].to_vec();
        let offset = CODE_ROOT_FIRST_WORD * BYTES_PER_PROOF_WORD;
        let original = u32::from_le_bytes(
            non_receipt_format_subject[offset..offset + BYTES_PER_PROOF_WORD]
                .try_into()
                .unwrap(),
        );
        let modulus = risc0_zkp::field::baby_bear::P;
        let replacement = if original + 1 < modulus {
            original + 1
        } else {
            original - 1
        };
        non_receipt_format_subject[offset..offset + BYTES_PER_PROOF_WORD]
            .copy_from_slice(&replacement.to_le_bytes());
        assert!(matches!(
            reject_parser_prefix(&non_receipt_format_subject, &[manifest]),
            Err(B4ParserAdapterError::UnexpectedStockBoundary(_))
        ));
        let (input, source) = input_for(
            B4MaterializationDomain::VerifierInput,
            B4NegativeExecutionSurface::Risc0ParserInternal,
            &non_receipt_format_subject,
            &[manifest],
        );
        assert!(
            verify_like_authenticated_root(
                &input,
                &source,
                &non_receipt_format_subject,
                &[manifest],
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_ancestry_reaches_adapter_but_produces_no_observation() {
        let subject = vec![0_u8; 1];
        let manifest = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");
        let (input, source) = input_for(
            B4MaterializationDomain::VerifierInput,
            B4NegativeExecutionSurface::AncestryReplay,
            &subject,
            &[manifest],
        );
        let error =
            verify_like_authenticated_root(&input, &source, &subject, &[manifest]).unwrap_err();
        assert_eq!(error.to_string(),
            "selected negative adapter VerifierAncestryReplay failed privately; no observation was produced");
    }

    #[test]
    fn unexpected_acceptance_is_private() {
        let manifest = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");
        let (input, source) = input_for(
            B4MaterializationDomain::ArtifactValidator,
            B4NegativeExecutionSurface::ProfileManifestCodec,
            manifest,
            &[],
        );
        assert!(verify_like_authenticated_root(&input, &source, manifest, &[]).is_err());
    }

    #[test]
    fn typed_boundary_vocabulary_is_closed_and_placeholder_free() {
        let profile_boundaries = [
            profile_boundary(B4ArtifactProfileRejection::ManifestLength),
            profile_boundary(B4ArtifactProfileRejection::ManifestVersion),
            profile_boundary(B4ArtifactProfileRejection::ManifestProofLength),
            profile_boundary(B4ArtifactProfileRejection::ManifestTerminalKind { index: 0 }),
            profile_boundary(B4ArtifactProfileRejection::ManifestTerminalParameter { index: 0 }),
            profile_boundary(B4ArtifactProfileRejection::ManifestTerminalOrder { index: 0 }),
            profile_boundary(
                B4ArtifactProfileRejection::ManifestTerminalControlIdDuplicate { index: 0 },
            ),
            profile_boundary(B4ArtifactProfileRejection::ManifestArtifactKind { index: 0 }),
            profile_boundary(B4ArtifactProfileRejection::ManifestArtifactEmpty { index: 0 }),
            profile_boundary(B4ArtifactProfileRejection::InitialExactProofBytes),
            profile_boundary(B4ArtifactProfileRejection::InitialMaximumPayload),
            profile_boundary(B4ArtifactProfileRejection::InitialOuterPo2),
            profile_boundary(B4ArtifactProfileRejection::InitialInnerControlRoot),
            profile_boundary(B4ArtifactProfileRejection::InitialTerminalControl { index: 0 }),
            profile_boundary(B4ArtifactProfileRejection::ArtifactLength { kind: 1 }),
            profile_boundary(B4ArtifactProfileRejection::ArtifactDigest { kind: 1 }),
            profile_boundary(B4ArtifactProfileRejection::ActivatedProfileId),
            profile_boundary(B4ArtifactProfileRejection::ProfileIdPreimage),
        ];
        let catalog_boundaries = [
            catalog_boundary(B4ArtifactCatalogRejection::TerminalPolicy),
            catalog_boundary(B4ArtifactCatalogRejection::TerminalFixtureCatalogBinding),
            catalog_boundary(B4ArtifactCatalogRejection::SequenceSubjectCatalog),
            catalog_boundary(B4ArtifactCatalogRejection::TerminalMetadataBinding),
            catalog_boundary(B4ArtifactCatalogRejection::CandidateRegistry),
            catalog_boundary(B4ArtifactCatalogRejection::NegativeBindingIndexCodec),
            catalog_boundary(B4ArtifactCatalogRejection::NegativeBindingIndexPlanBinding),
            catalog_boundary(B4ArtifactCatalogRejection::CorpusRequiredRoleMissing),
            catalog_boundary(B4ArtifactCatalogRejection::CorpusUnexpectedRole),
        ];
        let ancestry_boundaries = [
            ancestry_boundary(B4AncestryRejection::ClaimEdge),
            ancestry_boundary(B4AncestryRejection::ResolveExplicit),
            ancestry_boundary(B4AncestryRejection::ResolveZeroRoot),
            ancestry_boundary(B4AncestryRejection::AssumptionInventory),
        ];
        for boundary in profile_boundaries
            .into_iter()
            .chain(catalog_boundaries)
            .chain(ancestry_boundaries)
        {
            B4NegativeObservationRejectionV1 {
                class: boundary.class.to_owned(),
                stage: boundary.stage.to_owned(),
            }
            .validate()
            .unwrap();
        }
    }
}
