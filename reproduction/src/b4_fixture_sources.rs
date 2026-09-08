//! Typed authenticated source views for closed B4 fixture-backed producers.
#![allow(dead_code)] // Connected by Tasks 2-5; kept internal until those producers land.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use risc0_binfmt::compute_image_id;
use sha2::{Digest as _, Sha256};

use crate::{
    b4::{B4PositiveArtifactRole, validate_canonical_positive_case_artifact_path},
    b4_campaign_contract::{B4ContractArtifactEncodingV1, B4ContractArtifactIdentityV1},
    b4_materialization_set::{
        B4AuthenticatedMaterializationTopLevelV1, B4AuthenticatedMaterializationTopLevelV2,
        B4AuthenticatedPositiveInputSourcesV2, B4AuthenticatedPostproofDocumentsV2,
        compiled_positive_case_id, parse_positive_input_sources, parse_positive_input_sources_v2,
        positive_artifact_encoding, positive_artifact_layout, positive_artifact_role_name,
        reparse_v2_postproof_documents, validate_positive_artifact_length,
    },
    b4_positive_gate::positive_auxiliary_artifact_paths,
    b4_positive_source_auth::{
        B4AuthenticatedPositiveCaseSourceV2, B4PositiveCaseSourceV2, B4PositiveSourceBytesV2,
        authenticate_positive_case_source_v2, bind_external_path,
    },
    b4_statement_bundle_manifest::StatementBundleManifestV1,
    b4_terminal::{
        B4_TERMINAL_FIXTURE_COUNT, B4_TERMINAL_FIXTURE_LAYOUT, Eip0045B4TerminalFixtureCatalogV1,
    },
    canonical::validate_canonical_json_source,
    claim::ReceiptClaimDigests,
    constants::PROOF_BYTES,
    constants_artifact,
    ergo_statement::{ErgoStatementV1, parse_ergo_statement_v1},
    manifest::{ProofOutputManifest, validate_manifest_shape},
    profile_algorithm::authenticate_profile_algorithm,
    profile_manifest::{ProfileArtifacts, StarkProfileManifestV1, validate_profile_package_v1},
};

#[cfg(feature = "recursive-ancestry")]
use crate::{
    b4_recursive_auxiliary_map::{B4RecursiveAuxiliaryMapV1, encode_recursive_auxiliary_map},
    recursive_ancestry::{
        RecursiveAncestryFamily, RecursiveAncestryOperation, RecursiveAncestryProjection,
        RecursiveAncestryTerminal, parse_recursive_ancestry_jcs, recursive_ancestry_claim_digest,
        recursive_ancestry_to_jcs, validate_canonical_recursive_ancestry,
        validate_recursive_ancestry_artifacts, validate_recursive_ancestry_structure,
    },
};

/// Narrow, read-only authenticated view over exactly one positive case.
pub(crate) struct B4PositiveFixtureSourceViewV1<'a> {
    case_index: usize,
    case_id: &'a str,
    artifacts: BTreeMap<B4PositiveArtifactRole, &'a [u8]>,
    raw_seal: &'a [u8],
    proof_output_manifest_jcs: &'a [u8],
}

impl<'a> B4PositiveFixtureSourceViewV1<'a> {
    /// Exact compiled case ordinal.
    pub(crate) fn case_index(&self) -> usize {
        self.case_index
    }

    /// Exact compiled case ID.
    pub(crate) fn case_id(&self) -> &'a str {
        self.case_id
    }

    /// Return one authenticated non-seal artifact.
    pub(crate) fn artifact(&self, role: B4PositiveArtifactRole) -> Result<&'a [u8]> {
        ensure!(
            role != B4PositiveArtifactRole::RawSeal,
            "raw seal is available only through the positive-export channel"
        );
        self.artifacts.get(&role).copied().with_context(|| {
            format!(
                "authenticated positive view lacks {}",
                positive_artifact_role_name(role)
            )
        })
    }

    /// Return the authenticated raw seal supplied only by the ordered export.
    pub(crate) fn raw_seal(&self) -> &'a [u8] {
        self.raw_seal
    }

    /// Exact authenticated proof-output manifest JCS for this case.
    pub(crate) fn proof_output_manifest_jcs(&self) -> &'a [u8] {
        self.proof_output_manifest_jcs
    }
}

/// Fully authenticated source view for one closed recursive positive case.
///
/// This view validates source custody, graph structure, canonical positive
/// semantics, primary terminal artifacts, and all referenced raw-seal bytes.
/// It does not perform STARK verification.
#[cfg(feature = "recursive-ancestry")]
pub(crate) struct B4RecursiveAncestrySourceViewV1<'a> {
    family: RecursiveAncestryFamily,
    profile_manifest_context: &'a [u8],
    ancestry_jcs: &'a [u8],
    projection: RecursiveAncestryProjection,
    statement: &'a [u8],
    final_raw_seal: &'a [u8],
    auxiliary_seals: B4RecursiveAuxiliaryMapV1<'a>,
}

#[cfg(feature = "recursive-ancestry")]
impl<'a> B4RecursiveAncestrySourceViewV1<'a> {
    /// Closed recursive family selected by the resolver.
    pub(crate) const fn family(&self) -> RecursiveAncestryFamily {
        self.family
    }

    /// Authenticated initial-profile manifest context.
    pub(crate) const fn profile_manifest_context(&self) -> &'a [u8] {
        self.profile_manifest_context
    }

    /// Exact canonical ancestry JCS.
    pub(crate) const fn ancestry_jcs(&self) -> &'a [u8] {
        self.ancestry_jcs
    }

    /// Parsed, structurally and semantically validated ancestry projection.
    pub(crate) const fn projection(&self) -> &RecursiveAncestryProjection {
        &self.projection
    }

    /// Globally unanimous authenticated statement.
    pub(crate) const fn statement(&self) -> &'a [u8] {
        self.statement
    }

    /// Authenticated final raw seal for this positive case.
    pub(crate) const fn final_raw_seal(&self) -> &'a [u8] {
        self.final_raw_seal
    }

    /// Borrow all non-final producer seals in exact compiled path order.
    pub(crate) const fn auxiliary_seals(&self) -> &B4RecursiveAuxiliaryMapV1<'a> {
        &self.auxiliary_seals
    }

    /// Encode the exact auxiliary-seal map used by `AncestryBundle`.
    pub(crate) fn encoded_auxiliary_map(&self) -> Result<Vec<u8>> {
        encode_recursive_auxiliary_map(&self.auxiliary_seals)
            .context("cannot encode authenticated recursive auxiliary map")
    }
}

/// Selector-free case-9 source for the conditional receipt-claim policy row.
///
/// The type deliberately carries neither the final seal nor the full ancestry
/// projection, preventing receipt-claim producers from selecting the accepted
/// final Resolve receipt by mistake.
#[cfg(feature = "recursive-ancestry")]
pub(crate) struct B4Case9ConditionalReceiptSourceViewV1<'a> {
    profile_manifest_context: &'a [u8],
    statement_context: &'a [u8],
    conditional_raw_seal_path: &'static str,
    conditional_raw_seal: &'a [u8],
}

#[cfg(feature = "recursive-ancestry")]
impl<'a> B4Case9ConditionalReceiptSourceViewV1<'a> {
    /// Authenticated initial-profile manifest context.
    pub(crate) const fn profile_manifest_context(&self) -> &'a [u8] {
        self.profile_manifest_context
    }

    /// Authenticated case-9 statement context.
    pub(crate) const fn statement_context(&self) -> &'a [u8] {
        self.statement_context
    }

    /// Sole compiled path of the case-9 step-00 conditional receipt.
    pub(crate) const fn conditional_raw_seal_path(&self) -> &'static str {
        self.conditional_raw_seal_path
    }

    /// Authenticated case-9 step-00 conditional raw seal.
    pub(crate) const fn conditional_raw_seal(&self) -> &'a [u8] {
        self.conditional_raw_seal
    }
}

/// Narrow, read-only authenticated view over the initial-profile inputs.
pub(crate) struct B4PositiveInputSourceViewV1<'a> {
    positive_input_set: &'a [u8],
    profile_id: &'a str,
    guest_image_id: &'a str,
    profile_manifest: &'a [u8],
    profile_algorithm: &'a [u8],
    profile_constants: &'a [u8],
    guest_elf: &'a [u8],
    reference_statement_manifest: &'a [u8],
    reference_contract_id: [u8; 32],
    reference_statement_byte_length: u64,
    reference_statement_sha256: [u8; 32],
    reference_chain_domain_id: [u8; 32],
    reference_application_payload_byte_length: u64,
    reference_application_payload_sha256: [u8; 32],
}

impl<'a> B4PositiveInputSourceViewV1<'a> {
    /// Exact canonical positive-input-set bytes.
    pub(crate) fn positive_input_set(&self) -> &'a [u8] {
        self.positive_input_set
    }

    /// Exact profile ID bound by both the input set and expanded registry.
    pub(crate) fn profile_id(&self) -> &'a str {
        self.profile_id
    }

    /// Exact guest image ID bound by both the input set and expanded registry.
    pub(crate) fn guest_image_id(&self) -> &'a str {
        self.guest_image_id
    }

    /// Authenticated initial-profile manifest bytes.
    pub(crate) fn profile_manifest(&self) -> &'a [u8] {
        self.profile_manifest
    }

    /// Authenticated B1 algorithm artifact bytes.
    pub(crate) fn profile_algorithm(&self) -> &'a [u8] {
        self.profile_algorithm
    }

    /// Authenticated B2 constants artifact bytes.
    pub(crate) fn profile_constants(&self) -> &'a [u8] {
        self.profile_constants
    }

    /// Authenticated guest ELF bytes.
    pub(crate) fn guest_elf(&self) -> &'a [u8] {
        self.guest_elf
    }

    /// Exact authenticated canonical reference statement-bundle manifest.
    pub(crate) const fn reference_statement_manifest(&self) -> &'a [u8] {
        self.reference_statement_manifest
    }

    /// Typed contract ID declared by the authenticated reference-statement input.
    pub(crate) const fn reference_contract_id(&self) -> [u8; 32] {
        self.reference_contract_id
    }

    /// Exact byte length declared for the reference statement.
    pub(crate) const fn reference_statement_byte_length(&self) -> u64 {
        self.reference_statement_byte_length
    }

    /// Typed SHA-256 declared for the exact reference statement bytes.
    pub(crate) const fn reference_statement_sha256(&self) -> [u8; 32] {
        self.reference_statement_sha256
    }

    /// Typed chain-domain ID declared for the reference statement.
    pub(crate) const fn reference_chain_domain_id(&self) -> [u8; 32] {
        self.reference_chain_domain_id
    }

    /// Exact application-payload byte length declared by the positive input.
    pub(crate) const fn reference_application_payload_byte_length(&self) -> u64 {
        self.reference_application_payload_byte_length
    }

    /// Typed SHA-256 declared for the exact application payload.
    pub(crate) const fn reference_application_payload_sha256(&self) -> [u8; 32] {
        self.reference_application_payload_sha256
    }

    /// Decode the already authenticated initial-profile manifest.
    pub(crate) fn initial_profile_manifest(&self) -> Result<StarkProfileManifestV1> {
        let manifest = StarkProfileManifestV1::decode(self.profile_manifest)
            .context("authenticated profile manifest does not decode")?;
        manifest
            .validate_initial_profile_target()
            .context("authenticated profile manifest differs from the initial profile target")?;
        Ok(manifest)
    }
}

/// One globally unanimous positive reference statement, independent of any
/// positive-case ordinal or case ID.
pub(crate) struct B4ReferenceStatementSourceViewV1<'a> {
    statement_bytes: &'a [u8],
    statement: ErgoStatementV1<'a>,
    claim: ReceiptClaimDigests,
}

impl<'a> B4ReferenceStatementSourceViewV1<'a> {
    /// Exact bytes carried identically by every positive Journal artifact.
    pub(crate) const fn statement_bytes(&self) -> &'a [u8] {
        self.statement_bytes
    }

    /// Strict statement value borrowing the exact unanimous Journal bytes.
    pub(crate) const fn statement(&self) -> ErgoStatementV1<'a> {
        self.statement
    }

    /// Independently reconstructed successful receipt-claim digest chain.
    pub(crate) const fn claim_digests(&self) -> ReceiptClaimDigests {
        self.claim
    }
}

/// Exact case-0 Journal after all positive-input and positive-case identities
/// have been cross-bound.
pub(crate) struct B4CaseZeroReferenceStatementSourceViewV1<'a> {
    statement_bytes: &'a [u8],
    statement: ErgoStatementV1<'a>,
    profile_id: [u8; 32],
    program_id: [u8; 32],
}

impl<'a> B4CaseZeroReferenceStatementSourceViewV1<'a> {
    /// Exact authenticated Journal bytes.
    pub(crate) const fn statement_bytes(&self) -> &'a [u8] {
        self.statement_bytes
    }

    /// Strictly parsed statement value borrowing the exact Journal bytes.
    pub(crate) const fn statement(&self) -> ErgoStatementV1<'a> {
        self.statement
    }

    /// Profile identity independently sourced from the positive input set.
    pub(crate) const fn profile_id(&self) -> [u8; 32] {
        self.profile_id
    }

    /// Program identity independently sourced from the input set and case-0
    /// `ImageId` artifact.
    pub(crate) const fn program_id(&self) -> [u8; 32] {
        self.program_id
    }
}

/// Narrow, read-only authenticated view over one terminal fixture.
pub(crate) struct B4TerminalFixtureSourceViewV1<'a> {
    fixture_index: usize,
    fixture_id: &'a str,
    raw_seal: &'a [u8],
    receipt_oracle: &'a [u8],
}

impl<'a> B4TerminalFixtureSourceViewV1<'a> {
    /// Exact compiled terminal-catalogue position.
    pub(crate) fn fixture_index(&self) -> usize {
        self.fixture_index
    }

    /// Exact compiled terminal fixture ID.
    pub(crate) fn fixture_id(&self) -> &'a str {
        self.fixture_id
    }

    /// Authenticated raw terminal seal.
    pub(crate) fn raw_seal(&self) -> &'a [u8] {
        self.raw_seal
    }

    /// Authenticated typed terminal receipt oracle bytes.
    pub(crate) fn receipt_oracle(&self) -> &'a [u8] {
        self.receipt_oracle
    }
}

/// Narrow V2-authenticated view over exactly one positive case.
pub(crate) struct B4PositiveFixtureSourceViewV2<'a> {
    case_index: usize,
    case_id: &'a str,
    artifacts: BTreeMap<B4PositiveArtifactRole, &'a [u8]>,
    raw_seal: &'a [u8],
    proof_output_manifest_jcs: &'a [u8],
}

impl<'a> B4PositiveFixtureSourceViewV2<'a> {
    pub(crate) const fn case_index(&self) -> usize {
        self.case_index
    }

    pub(crate) const fn case_id(&self) -> &'a str {
        self.case_id
    }

    pub(crate) fn artifact(&self, role: B4PositiveArtifactRole) -> Result<&'a [u8]> {
        ensure!(
            role != B4PositiveArtifactRole::RawSeal,
            "raw seal is available only through the V2 positive-export channel"
        );
        self.artifacts.get(&role).copied().with_context(|| {
            format!(
                "V2 authenticated positive view lacks {}",
                positive_artifact_role_name(role)
            )
        })
    }

    pub(crate) const fn raw_seal(&self) -> &'a [u8] {
        self.raw_seal
    }

    pub(crate) const fn proof_output_manifest_jcs(&self) -> &'a [u8] {
        self.proof_output_manifest_jcs
    }
}

/// V2-authenticated initial-profile inputs retained from the V2 input set.
pub(crate) struct B4PositiveInputSourceViewV2<'a> {
    positive_input_set: &'a [u8],
    profile_id: &'a str,
    guest_image_id: &'a str,
    profile_manifest: &'a [u8],
    profile_algorithm: &'a [u8],
    profile_constants: &'a [u8],
    guest_elf: &'a [u8],
    reference_statement_manifest: &'a [u8],
    reference_contract_id: [u8; 32],
    reference_statement_byte_length: u64,
    reference_statement_sha256: [u8; 32],
    reference_chain_domain_id: [u8; 32],
    reference_application_payload_byte_length: u64,
    reference_application_payload_sha256: [u8; 32],
}

impl<'a> B4PositiveInputSourceViewV2<'a> {
    pub(crate) const fn positive_input_set(&self) -> &'a [u8] {
        self.positive_input_set
    }

    pub(crate) const fn profile_id(&self) -> &'a str {
        self.profile_id
    }

    pub(crate) const fn guest_image_id(&self) -> &'a str {
        self.guest_image_id
    }

    pub(crate) const fn profile_manifest(&self) -> &'a [u8] {
        self.profile_manifest
    }

    pub(crate) const fn profile_algorithm(&self) -> &'a [u8] {
        self.profile_algorithm
    }

    pub(crate) const fn profile_constants(&self) -> &'a [u8] {
        self.profile_constants
    }

    pub(crate) const fn guest_elf(&self) -> &'a [u8] {
        self.guest_elf
    }

    pub(crate) const fn reference_statement_manifest(&self) -> &'a [u8] {
        self.reference_statement_manifest
    }

    pub(crate) const fn reference_contract_id(&self) -> [u8; 32] {
        self.reference_contract_id
    }

    pub(crate) const fn reference_statement_byte_length(&self) -> u64 {
        self.reference_statement_byte_length
    }

    pub(crate) const fn reference_statement_sha256(&self) -> [u8; 32] {
        self.reference_statement_sha256
    }

    pub(crate) const fn reference_chain_domain_id(&self) -> [u8; 32] {
        self.reference_chain_domain_id
    }

    pub(crate) const fn reference_application_payload_byte_length(&self) -> u64 {
        self.reference_application_payload_byte_length
    }

    pub(crate) const fn reference_application_payload_sha256(&self) -> [u8; 32] {
        self.reference_application_payload_sha256
    }

    pub(crate) fn initial_profile_manifest(&self) -> Result<StarkProfileManifestV1> {
        let manifest = StarkProfileManifestV1::decode(self.profile_manifest)
            .context("V2 authenticated profile manifest does not decode")?;
        manifest
            .validate_initial_profile_target()
            .context("V2 authenticated profile manifest differs from the initial profile target")?;
        Ok(manifest)
    }
}

/// Globally unanimous statement authenticated through the V2 input authority.
pub(crate) struct B4ReferenceStatementSourceViewV2<'a> {
    statement_bytes: &'a [u8],
    statement: ErgoStatementV1<'a>,
    claim: ReceiptClaimDigests,
}

impl<'a> B4ReferenceStatementSourceViewV2<'a> {
    pub(crate) const fn statement_bytes(&self) -> &'a [u8] {
        self.statement_bytes
    }

    pub(crate) const fn statement(&self) -> ErgoStatementV1<'a> {
        self.statement
    }

    pub(crate) const fn claim_digests(&self) -> ReceiptClaimDigests {
        self.claim
    }
}

/// Exact case-0 statement cross-bound to the V2 input authority.
pub(crate) struct B4CaseZeroReferenceStatementSourceViewV2<'a> {
    statement_bytes: &'a [u8],
    statement: ErgoStatementV1<'a>,
    profile_id: [u8; 32],
    program_id: [u8; 32],
}

impl<'a> B4CaseZeroReferenceStatementSourceViewV2<'a> {
    pub(crate) const fn statement_bytes(&self) -> &'a [u8] {
        self.statement_bytes
    }

    pub(crate) const fn statement(&self) -> ErgoStatementV1<'a> {
        self.statement
    }

    pub(crate) const fn profile_id(&self) -> [u8; 32] {
        self.profile_id
    }

    pub(crate) const fn program_id(&self) -> [u8; 32] {
        self.program_id
    }
}

#[cfg(feature = "recursive-ancestry")]
pub(crate) struct B4RecursiveAncestrySourceViewV2<'a> {
    family: RecursiveAncestryFamily,
    profile_manifest_context: &'a [u8],
    ancestry_jcs: &'a [u8],
    projection: RecursiveAncestryProjection,
    statement: &'a [u8],
    final_raw_seal: &'a [u8],
    auxiliary_seals: B4RecursiveAuxiliaryMapV1<'a>,
}

#[cfg(feature = "recursive-ancestry")]
impl<'a> B4RecursiveAncestrySourceViewV2<'a> {
    pub(crate) const fn family(&self) -> RecursiveAncestryFamily {
        self.family
    }

    pub(crate) const fn profile_manifest_context(&self) -> &'a [u8] {
        self.profile_manifest_context
    }

    pub(crate) const fn ancestry_jcs(&self) -> &'a [u8] {
        self.ancestry_jcs
    }

    pub(crate) const fn projection(&self) -> &RecursiveAncestryProjection {
        &self.projection
    }

    pub(crate) const fn statement(&self) -> &'a [u8] {
        self.statement
    }

    pub(crate) const fn final_raw_seal(&self) -> &'a [u8] {
        self.final_raw_seal
    }

    pub(crate) const fn auxiliary_seals(&self) -> &B4RecursiveAuxiliaryMapV1<'a> {
        &self.auxiliary_seals
    }

    pub(crate) fn encoded_auxiliary_map(&self) -> Result<Vec<u8>> {
        encode_recursive_auxiliary_map(&self.auxiliary_seals)
            .context("cannot encode V2 authenticated recursive auxiliary map")
    }
}

#[cfg(feature = "recursive-ancestry")]
pub(crate) struct B4Case9ConditionalReceiptSourceViewV2<'a> {
    profile_manifest_context: &'a [u8],
    statement_context: &'a [u8],
    conditional_raw_seal_path: &'static str,
    conditional_raw_seal: &'a [u8],
}

#[cfg(feature = "recursive-ancestry")]
impl<'a> B4Case9ConditionalReceiptSourceViewV2<'a> {
    pub(crate) const fn profile_manifest_context(&self) -> &'a [u8] {
        self.profile_manifest_context
    }

    pub(crate) const fn statement_context(&self) -> &'a [u8] {
        self.statement_context
    }

    pub(crate) const fn conditional_raw_seal_path(&self) -> &'static str {
        self.conditional_raw_seal_path
    }

    pub(crate) const fn conditional_raw_seal(&self) -> &'a [u8] {
        self.conditional_raw_seal
    }
}

/// Resolver that exposes only exact typed source views to closed producers.
pub(crate) struct B4FixtureSourceResolverV1<'a> {
    top_level: &'a B4AuthenticatedMaterializationTopLevelV1,
}

/// V2-only post-proof resolver. It remeasures every nested input identity and
/// keeps the V1 resolver and authority path completely separate.
pub(crate) struct B4FixtureSourceResolverV2 {
    postproof: B4AuthenticatedPostproofDocumentsV2,
    input_paths: BTreeSet<String>,
}

/// Top-level materialization resolver minted only from the authenticated V2 wrapper.
pub(crate) struct B4MaterializationFixtureSourceResolverV2<'a> {
    top_level: &'a B4AuthenticatedMaterializationTopLevelV2,
}

impl B4FixtureSourceResolverV2 {
    pub(crate) fn from_postproof_documents(
        input_set_jcs: &[u8],
        generation_set_jcs: &[u8],
        proof_generator: B4PositiveSourceBytesV2<'_>,
        nested_input_sources: &[B4PositiveSourceBytesV2<'_>],
    ) -> Result<Self> {
        let postproof =
            reparse_v2_postproof_documents(input_set_jcs, generation_set_jcs, proof_generator)?;
        ensure!(
            nested_input_sources.len() == postproof.input.artifacts.len(),
            "V2 nested input-source inventory has the wrong cardinality"
        );
        let mut input_paths = BTreeSet::new();
        for external in nested_input_sources {
            bind_external_path(
                &mut input_paths,
                external.path,
                false,
                "V2 nested positive-input source",
            )?;
            let expected = postproof
                .input
                .artifacts
                .get(external.path)
                .context("V2 nested input source is not selected by the positive input set")?;
            let measured = B4ContractArtifactIdentityV1::from_bytes(
                external.path,
                expected.encoding,
                external.bytes,
            )?;
            ensure!(
                measured == *expected,
                "V2 nested input source path, length, digest, or encoding drift"
            );
            if expected.encoding == B4ContractArtifactEncodingV1::Rfc8785Jcs {
                validate_canonical_json_source(external.bytes)
                    .context("V2 nested JCS input source is not exact canonical JCS")?;
            }
        }
        ensure!(
            input_paths.iter().eq(postproof.input.artifacts.keys()),
            "V2 nested input-source paths differ from the canonical input-set inventory"
        );
        Ok(Self {
            postproof,
            input_paths,
        })
    }

    pub(crate) fn positive_case<'bytes>(
        &self,
        case_index: usize,
        source: B4PositiveCaseSourceV2<'bytes, '_>,
    ) -> Result<B4AuthenticatedPositiveCaseSourceV2<'bytes>> {
        let mut paths = self.input_paths.clone();
        authenticate_positive_case_source_v2(
            &self.postproof.generation,
            case_index,
            source,
            &mut paths,
        )
    }

    pub(crate) const fn postproof(&self) -> &B4AuthenticatedPostproofDocumentsV2 {
        &self.postproof
    }
}

impl<'a> B4MaterializationFixtureSourceResolverV2<'a> {
    pub(crate) fn from_authenticated(
        top_level: &'a B4AuthenticatedMaterializationTopLevelV2,
    ) -> Result<Self> {
        let storage = top_level.storage();
        ensure!(
            storage.expanded_registry.positive_cases.len() == 11
                && storage.positive_exports.len() == 11,
            "V2 authenticated positive source inventory must contain exactly eleven cases and exports"
        );
        for index in 0..11 {
            authenticate_positive_case(storage, index)?;
        }
        parse_positive_input_sources_v2(&storage.positive_input_set)
            .context("V2 authenticated top level does not retain a V2 positive input set")?;
        Ok(Self { top_level })
    }

    /// Exact canonical negative-plan bytes retained by the same authenticated V2 wrapper.
    pub(crate) fn negative_plan_jcs(&self) -> &'a [u8] {
        &self.top_level.storage().negative_plan
    }

    pub(crate) fn positive_case(
        &self,
        case_index: usize,
        case_id: &str,
    ) -> Result<B4PositiveFixtureSourceViewV2<'a>> {
        ensure!(
            compiled_positive_case_id(case_index)?.as_str() == case_id,
            "V2 positive case selector does not match the compiled index and case ID"
        );
        let storage = self.top_level.storage();
        authenticate_positive_case(storage, case_index)?;
        let case = &storage.expanded_registry.positive_cases[case_index];
        let mut artifacts = BTreeMap::new();
        for artifact in &case.artifacts {
            if artifact.role == B4PositiveArtifactRole::RawSeal {
                continue;
            }
            let bytes = storage
                .source_artifacts
                .get(&artifact.path)
                .with_context(|| {
                    format!(
                        "missing V2 authenticated {} source",
                        positive_artifact_role_name(artifact.role)
                    )
                })?;
            artifacts.insert(artifact.role, bytes.as_slice());
        }
        Ok(B4PositiveFixtureSourceViewV2 {
            case_index,
            case_id: &case.case_id,
            artifacts,
            raw_seal: &storage.positive_exports[case_index].raw_seal,
            proof_output_manifest_jcs: &storage.positive_exports[case_index]
                .proof_output_manifest_jcs,
        })
    }

    pub(crate) fn positive_input(&self) -> Result<B4PositiveInputSourceViewV2<'a>> {
        let storage = self.top_level.storage();
        let input = parse_positive_input_sources_v2(&storage.positive_input_set)?;
        let profile_manifest = authenticate_positive_input_artifact(
            storage,
            &input.profile_manifest,
            B4ContractArtifactEncodingV1::RawBytes,
            "V2 profile manifest",
        )?;
        let profile_algorithm = authenticate_positive_input_artifact(
            storage,
            &input.profile_algorithm,
            B4ContractArtifactEncodingV1::RawBytes,
            "V2 profile algorithm",
        )?;
        let profile_constants = authenticate_positive_input_artifact(
            storage,
            &input.profile_constants,
            B4ContractArtifactEncodingV1::RawBytes,
            "V2 profile constants",
        )?;
        let upstream_guest_elf = authenticate_positive_input_artifact(
            storage,
            &input.guest_elf,
            B4ContractArtifactEncodingV1::RawBytes,
            "V2 guest ELF",
        )?;
        let upstream_reference_statement_manifest = authenticate_positive_input_artifact(
            storage,
            input.reference_statement_manifest(),
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "V2 reference statement-bundle manifest",
        )?;
        authenticate_registry_profile_binding(storage, &input.profile_manifest, &input.profile_id)?;
        authenticate_registry_guest_binding_v2(storage, &input.guest_elf, &input.guest_image_id)?;
        authenticate_registry_reference_statement_binding_v2(storage, &input)?;
        let guest_elf = authenticate_registry_quarantine_copy_artifact(
            storage,
            &storage.expanded_registry.bindings.guest.elf,
            &input.guest_elf,
            upstream_guest_elf,
            B4ContractArtifactEncodingV1::RawBytes,
            "V2 guest ELF",
        )?;
        let reference_statement_manifest = authenticate_registry_quarantine_copy_artifact(
            storage,
            &storage
                .expanded_registry
                .bindings
                .reference_statement_bundle
                .manifest,
            input.reference_statement_manifest(),
            upstream_reference_statement_manifest,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "V2 reference statement-bundle manifest",
        )?;

        let view = B4PositiveInputSourceViewV2 {
            positive_input_set: &storage.positive_input_set,
            profile_id: &storage.expanded_registry.profile.profile_id,
            guest_image_id: &storage.expanded_registry.bindings.guest.image_id,
            profile_manifest,
            profile_algorithm,
            profile_constants,
            guest_elf,
            reference_statement_manifest,
            reference_contract_id: decode_digest(
                input.reference_contract_id(),
                "V2 positive-input reference contract ID",
            )?,
            reference_statement_byte_length: input.reference_statement_byte_length(),
            reference_statement_sha256: decode_digest(
                input.reference_statement_sha256(),
                "V2 positive-input reference statement SHA-256",
            )?,
            reference_chain_domain_id: decode_digest(
                input.reference_chain_domain_id(),
                "V2 positive-input reference chain-domain ID",
            )?,
            reference_application_payload_byte_length: input
                .reference_application_payload_byte_length(),
            reference_application_payload_sha256: decode_digest(
                input.reference_application_payload_sha256(),
                "V2 positive-input reference application-payload SHA-256",
            )?,
        };
        let manifest = view.initial_profile_manifest()?;
        let declared_profile_id = decode_profile_id(&input.profile_id)?;
        ensure!(
            manifest.profile_id()? == declared_profile_id,
            "V2 positive-input declared profile ID differs from the authenticated manifest"
        );
        validate_profile_package_v1(
            view.profile_manifest,
            ProfileArtifacts {
                algorithm: view.profile_algorithm,
                binary_data: view.profile_constants,
            },
            &declared_profile_id,
        )
        .context("V2 authenticated profile package does not bind its B1/B2 envelopes")?;
        authenticate_profile_algorithm(view.profile_algorithm, &manifest)
            .context("V2 authenticated B1 algorithm artifact is invalid")?;
        constants_artifact::verify_canonical(view.profile_constants)
            .context("V2 authenticated B2 constants artifact is invalid")?;
        Ok(view)
    }

    pub(crate) fn case_zero_reference_statement(
        &self,
    ) -> Result<B4CaseZeroReferenceStatementSourceViewV2<'a>> {
        let case = self.positive_case(0, "lift-po2-15")?;
        let input = self.positive_input()?;
        let statement_bytes = case.artifact(B4PositiveArtifactRole::Journal)?;
        let statement = parse_ergo_statement_v1(statement_bytes)
            .context("V2 authenticated case-0 Journal is not an exact ErgoStatementV1")?;
        ensure!(
            statement.encode()?.as_slice() == statement_bytes,
            "V2 authenticated case-0 Journal does not re-encode exactly"
        );
        let profile_id = decode_digest(input.profile_id(), "V2 positive-input profile ID")?;
        let program_id = decode_digest(input.guest_image_id(), "V2 positive-input guest image ID")?;
        let case_image_id: [u8; 32] = case
            .artifact(B4PositiveArtifactRole::ImageId)?
            .try_into()
            .context("V2 authenticated case-0 ImageId is not exactly 32 bytes")?;
        ensure!(
            case_image_id == program_id
                && statement.profile_id() == profile_id
                && statement.program_id() == program_id
                && statement.contract_id() == input.reference_contract_id(),
            "V2 authenticated case-0 statement identities differ from the positive input"
        );
        ensure!(
            <[u8; 32]>::from(Sha256::digest(statement_bytes)) == input.reference_statement_sha256(),
            "V2 authenticated case-0 Journal SHA-256 differs from the positive input"
        );
        Ok(B4CaseZeroReferenceStatementSourceViewV2 {
            statement_bytes,
            statement,
            profile_id,
            program_id,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the V2 global statement seam keeps all independently authenticated identities visible"
    )]
    pub(crate) fn global_reference_statement(
        &self,
    ) -> Result<B4ReferenceStatementSourceViewV2<'a>> {
        let input = self.positive_input()?;
        let manifest =
            StatementBundleManifestV1::from_canonical_jcs(input.reference_statement_manifest())
                .context("V2 authenticated reference statement-bundle manifest is invalid")?;
        let profile_id = input.initial_profile_manifest()?.profile_id()?;
        let declared_profile_id =
            decode_digest(input.profile_id(), "V2 positive-input profile ID")?;
        ensure!(
            profile_id == declared_profile_id && manifest.profile_id() == profile_id,
            "V2 reference statement profile ID differs across manifest and positive input"
        );
        let declared_program_id =
            decode_digest(input.guest_image_id(), "V2 positive-input guest image ID")?;
        let computed_program_id: [u8; 32] = compute_image_id(input.guest_elf())
            .context("V2 authenticated guest ELF cannot produce a RISC Zero image ID")?
            .into();
        ensure!(
            declared_program_id == computed_program_id
                && manifest.program_id() == computed_program_id,
            "V2 reference statement program ID differs from the authenticated guest ELF"
        );
        ensure!(
            manifest.contract_id() == input.reference_contract_id()
                && manifest.chain_domain_id() == input.reference_chain_domain_id(),
            "V2 reference statement identities differ between manifest and positive input"
        );
        ensure!(
            u64::try_from(manifest.statement_length())? == input.reference_statement_byte_length()
                && manifest.statement_sha256() == input.reference_statement_sha256()
                && u64::try_from(manifest.application_payload_length())?
                    == input.reference_application_payload_byte_length()
                && manifest.application_payload_sha256()
                    == input.reference_application_payload_sha256(),
            "V2 reference statement measurements differ between manifest and positive input"
        );

        let storage = self.top_level.storage();
        let terminal_catalogue = Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(
            &storage.terminal_fixture_catalog_jcs,
        )
        .context("V2 authenticated terminal fixture catalogue is invalid")?;
        ensure!(
            decode_digest(
                &terminal_catalogue.program_id,
                "V2 terminal-fixture catalogue program ID",
            )? == computed_program_id,
            "V2 terminal fixture catalogue differs from the authenticated guest ELF"
        );

        let mut representative: Option<&'a [u8]> = None;
        let mut case_claim_digests: Vec<[u8; 32]> = Vec::with_capacity(11);
        for index in 0..11 {
            let case_id = compiled_positive_case_id(index)?;
            let case = self.positive_case(index, &case_id)?;
            let journal = case.artifact(B4PositiveArtifactRole::Journal)?;
            if let Some(expected) = representative {
                ensure!(
                    journal == expected,
                    "V2 positive Journals differ at case {index}"
                );
            } else {
                representative = Some(journal);
            }
            ensure!(
                u64::try_from(journal.len())? == input.reference_statement_byte_length()
                    && <[u8; 32]>::from(Sha256::digest(journal))
                        == input.reference_statement_sha256(),
                "V2 positive Journal measurement differs at case {index}"
            );
            let case_program_id: [u8; 32] = case
                .artifact(B4PositiveArtifactRole::ImageId)?
                .try_into()
                .with_context(|| format!("V2 positive ImageId has wrong length at case {index}"))?;
            ensure!(
                case_program_id == computed_program_id,
                "V2 positive ImageId differs at case {index}"
            );
            case_claim_digests.push(
                case.artifact(B4PositiveArtifactRole::ClaimDigest)?
                    .try_into()
                    .with_context(|| {
                        format!("V2 positive ClaimDigest has wrong length at case {index}")
                    })?,
            );
        }
        let statement_bytes =
            representative.context("V2 positive Journal inventory is unexpectedly empty")?;
        let authenticated = manifest
            .authenticate_statement(statement_bytes)
            .context("V2 unanimous positive Journal differs from its bundle manifest")?;
        ensure!(
            case_claim_digests
                .iter()
                .all(|digest| *digest == authenticated.claim_digests().expected_claim),
            "one or more V2 positive ClaimDigest artifacts differ from the reconstructed claim"
        );
        Ok(B4ReferenceStatementSourceViewV2 {
            statement_bytes,
            statement: authenticated.statement(),
            claim: authenticated.claim_digests(),
        })
    }
}

#[cfg(feature = "recursive-ancestry")]
impl<'a> B4MaterializationFixtureSourceResolverV2<'a> {
    #[allow(
        clippy::too_many_lines,
        reason = "the V2 recursive source authority keeps graph, terminal, and auxiliary custody checks together"
    )]
    pub(crate) fn recursive_ancestry_source(
        &self,
        family: RecursiveAncestryFamily,
    ) -> Result<B4RecursiveAncestrySourceViewV2<'a>> {
        let case_index = family.positive_case_index();
        let case = self.positive_case(case_index, family.case_id())?;
        let input = self.positive_input()?;
        let profile_id = input.initial_profile_manifest()?.profile_id()?;
        let global_statement = self.global_reference_statement()?;
        let statement = global_statement.statement_bytes();
        ensure!(
            case.artifact(B4PositiveArtifactRole::Journal)? == statement,
            "V2 recursive case statement differs from the global reference statement"
        );

        let ancestry_jcs = case.artifact(B4PositiveArtifactRole::Ancestry)?;
        let projection = parse_recursive_ancestry_jcs(ancestry_jcs)
            .context("V2 authenticated recursive ancestry is not exact canonical JCS")?;
        ensure!(
            recursive_ancestry_to_jcs(&projection)?.as_slice() == ancestry_jcs,
            "V2 authenticated recursive ancestry does not re-encode byte-exactly"
        );
        ensure!(
            projection.family == family,
            "V2 authenticated recursive ancestry family differs from the typed selector"
        );
        validate_recursive_ancestry_structure(&projection, statement, profile_id)
            .context("V2 authenticated recursive ancestry structure is invalid")?;
        validate_canonical_recursive_ancestry(&projection, statement, profile_id)
            .context("V2 authenticated recursive ancestry is not canonical positive evidence")?;

        let case_program_id: [u8; 32] = case
            .artifact(B4PositiveArtifactRole::ImageId)?
            .try_into()
            .context("V2 recursive case ImageId is not exactly 32 bytes")?;
        ensure!(
            case_program_id == global_statement.statement().program_id(),
            "V2 recursive case ImageId differs from its statement"
        );
        let final_step = projection
            .steps
            .last()
            .context("V2 authenticated recursive ancestry has no final step")?;
        let case_claim_digest: [u8; 32] = case
            .artifact(B4PositiveArtifactRole::ClaimDigest)?
            .try_into()
            .context("V2 recursive case ClaimDigest is not exactly 32 bytes")?;
        ensure!(
            case_claim_digest == recursive_ancestry_claim_digest(&final_step.claim)?,
            "V2 recursive case ClaimDigest differs from its final ancestry claim"
        );
        let terminal_control_id = match &final_step.terminal {
            RecursiveAncestryTerminal::Lift { control_id, .. }
            | RecursiveAncestryTerminal::Join { control_id }
            | RecursiveAncestryTerminal::Resolve { control_id } => {
                decode_digest(control_id, "V2 recursive final terminal control ID")?
            }
        };
        let case_control_id: [u8; 32] = case
            .artifact(B4PositiveArtifactRole::ControlId)?
            .try_into()
            .context("V2 recursive case ControlId is not exactly 32 bytes")?;
        ensure!(
            case_control_id == terminal_control_id,
            "V2 recursive case ControlId differs from its final ancestry terminal"
        );

        let expected_paths = positive_auxiliary_artifact_paths(case_index)?;
        let storage = self.top_level.storage();
        let export = &storage.positive_exports[case_index];
        ensure!(
            export.auxiliary_artifacts.len() == expected_paths.len(),
            "V2 recursive export auxiliary inventory changed after authentication"
        );
        let entries =
            expected_paths
                .iter()
                .copied()
                .zip(&export.auxiliary_artifacts)
                .map(|(expected_path, identity)| {
                    ensure!(
                        identity.path == expected_path,
                        "V2 recursive export auxiliary order changed after authentication"
                    );
                    let bytes = storage.source_artifacts.get(expected_path).with_context(|| {
                    format!("missing V2 authenticated recursive auxiliary source {expected_path}")
                })?;
                    Ok((expected_path, bytes.as_slice()))
                })
                .collect::<Result<Vec<_>>>()?;
        let auxiliary_seals = B4RecursiveAuxiliaryMapV1::from_exact_entries(family, &entries)
            .context("V2 recursive auxiliary sources differ from the exact family map")?;
        let borrowed_artifacts = auxiliary_seals
            .iter()
            .map(|(path, bytes)| (path.to_owned(), bytes))
            .collect::<BTreeMap<_, _>>();
        validate_recursive_ancestry_artifacts(
            &projection,
            statement,
            case.raw_seal(),
            &borrowed_artifacts,
        )
        .context("V2 authenticated recursive ancestry artifact references are invalid")?;

        Ok(B4RecursiveAncestrySourceViewV2 {
            family,
            profile_manifest_context: input.profile_manifest(),
            ancestry_jcs,
            projection,
            statement,
            final_raw_seal: case.raw_seal(),
            auxiliary_seals,
        })
    }

    pub(crate) fn case9_conditional_receipt_source(
        &self,
    ) -> Result<B4Case9ConditionalReceiptSourceViewV2<'a>> {
        let ancestry = self.recursive_ancestry_source(RecursiveAncestryFamily::TerminalResolve)?;
        let step = ancestry
            .projection()
            .steps
            .first()
            .context("V2 case-9 ancestry has no conditional step")?;
        ensure!(
            step.ordinal == 0
                && step.operation == RecursiveAncestryOperation::Lift { segment_index: 0 },
            "V2 case-9 first ancestry step is not the compiled conditional Lift"
        );
        let (conditional_raw_seal_path, conditional_raw_seal) = ancestry
            .auxiliary_seals()
            .iter()
            .find(|(path, _)| path.as_bytes() == step.raw_seal.path.as_bytes())
            .context("V2 case-9 conditional step has no authenticated auxiliary seal")?;
        Ok(B4Case9ConditionalReceiptSourceViewV2 {
            profile_manifest_context: ancestry.profile_manifest_context(),
            statement_context: ancestry.statement(),
            conditional_raw_seal_path,
            conditional_raw_seal,
        })
    }
}

impl<'a> B4FixtureSourceResolverV1<'a> {
    /// Reauthenticate the fixture inventories retained at the materialization boundary.
    pub(crate) fn from_authenticated(
        top_level: &'a B4AuthenticatedMaterializationTopLevelV1,
    ) -> Result<Self> {
        ensure!(
            top_level.expanded_registry.positive_cases.len() == 11
                && top_level.positive_exports.len() == 11,
            "authenticated positive source inventory must contain exactly eleven cases and exports"
        );
        for index in 0..11 {
            authenticate_positive_case(top_level, index)?;
        }
        Ok(Self { top_level })
    }

    /// Select one compiled positive case using both ordinal and exact case ID.
    pub(crate) fn positive_case(
        &self,
        case_index: usize,
        case_id: &str,
    ) -> Result<B4PositiveFixtureSourceViewV1<'a>> {
        ensure!(
            compiled_positive_case_id(case_index)?.as_str() == case_id,
            "positive case selector does not match the compiled index and case ID"
        );
        authenticate_positive_case(self.top_level, case_index)?;
        let case = &self.top_level.expanded_registry.positive_cases[case_index];
        let mut artifacts = BTreeMap::new();
        for artifact in &case.artifacts {
            if artifact.role == B4PositiveArtifactRole::RawSeal {
                continue;
            }
            let bytes = self
                .top_level
                .source_artifacts
                .get(&artifact.path)
                .with_context(|| {
                    format!(
                        "missing authenticated {} source",
                        positive_artifact_role_name(artifact.role)
                    )
                })?;
            artifacts.insert(artifact.role, bytes.as_slice());
        }
        Ok(B4PositiveFixtureSourceViewV1 {
            case_index,
            case_id: &case.case_id,
            artifacts,
            raw_seal: &self.top_level.positive_exports[case_index].raw_seal,
            proof_output_manifest_jcs: &self.top_level.positive_exports[case_index]
                .proof_output_manifest_jcs,
        })
    }

    /// Resolve the exact initial-profile input set and its typed source bytes.
    pub(crate) fn positive_input(&self) -> Result<B4PositiveInputSourceViewV1<'a>> {
        let input = parse_positive_input_sources(&self.top_level.positive_input_set)?;
        let profile_manifest = authenticate_positive_input_artifact(
            self.top_level,
            &input.profile_manifest,
            B4ContractArtifactEncodingV1::RawBytes,
            "profile manifest",
        )?;
        let profile_algorithm = authenticate_positive_input_artifact(
            self.top_level,
            &input.profile_algorithm,
            B4ContractArtifactEncodingV1::RawBytes,
            "profile algorithm",
        )?;
        let profile_constants = authenticate_positive_input_artifact(
            self.top_level,
            &input.profile_constants,
            B4ContractArtifactEncodingV1::RawBytes,
            "profile constants",
        )?;
        let upstream_guest_elf = authenticate_positive_input_artifact(
            self.top_level,
            &input.guest_elf,
            B4ContractArtifactEncodingV1::RawBytes,
            "guest ELF",
        )?;
        let upstream_reference_statement_manifest = authenticate_positive_input_artifact(
            self.top_level,
            input.reference_statement_manifest(),
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "reference statement-bundle manifest",
        )?;
        authenticate_registry_profile_binding(
            self.top_level,
            &input.profile_manifest,
            &input.profile_id,
        )?;
        authenticate_registry_guest_binding(
            self.top_level,
            &input.guest_elf,
            &input.guest_image_id,
        )?;
        authenticate_registry_reference_statement_binding(self.top_level, &input)?;
        let guest_elf = authenticate_registry_quarantine_copy_artifact(
            self.top_level,
            &self.top_level.expanded_registry.bindings.guest.elf,
            &input.guest_elf,
            upstream_guest_elf,
            B4ContractArtifactEncodingV1::RawBytes,
            "guest ELF",
        )?;
        let reference_statement_manifest = authenticate_registry_quarantine_copy_artifact(
            self.top_level,
            &self
                .top_level
                .expanded_registry
                .bindings
                .reference_statement_bundle
                .manifest,
            input.reference_statement_manifest(),
            upstream_reference_statement_manifest,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "reference statement-bundle manifest",
        )?;
        let reference_contract_id = decode_digest(
            input.reference_contract_id(),
            "positive-input reference contract ID",
        )?;
        let reference_statement_sha256 = decode_digest(
            input.reference_statement_sha256(),
            "positive-input reference statement SHA-256",
        )?;
        let reference_chain_domain_id = decode_digest(
            input.reference_chain_domain_id(),
            "positive-input reference chain-domain ID",
        )?;
        let reference_application_payload_sha256 = decode_digest(
            input.reference_application_payload_sha256(),
            "positive-input reference application-payload SHA-256",
        )?;

        let view = B4PositiveInputSourceViewV1 {
            positive_input_set: &self.top_level.positive_input_set,
            profile_id: &self.top_level.expanded_registry.profile.profile_id,
            guest_image_id: &self.top_level.expanded_registry.bindings.guest.image_id,
            profile_manifest,
            profile_algorithm,
            profile_constants,
            guest_elf,
            reference_statement_manifest,
            reference_contract_id,
            reference_statement_byte_length: input.reference_statement_byte_length(),
            reference_statement_sha256,
            reference_chain_domain_id,
            reference_application_payload_byte_length: input
                .reference_application_payload_byte_length(),
            reference_application_payload_sha256,
        };
        let manifest = view.initial_profile_manifest()?;
        let declared_profile_id = decode_profile_id(&input.profile_id)?;
        ensure!(
            manifest.profile_id()? == declared_profile_id,
            "positive-input declared profile ID differs from the authenticated manifest"
        );
        validate_profile_package_v1(
            view.profile_manifest,
            ProfileArtifacts {
                algorithm: view.profile_algorithm,
                binary_data: view.profile_constants,
            },
            &declared_profile_id,
        )
        .context("authenticated profile package does not bind its B1/B2 artifact envelopes")?;
        authenticate_profile_algorithm(view.profile_algorithm, &manifest)
            .context("authenticated B1 algorithm artifact is invalid")?;
        constants_artifact::verify_canonical(view.profile_constants)
            .context("authenticated B2 constants artifact is invalid")?;
        Ok(view)
    }

    /// Cross-bind the exact case-0 Journal to the authenticated positive-input
    /// profile, guest program, reference contract, and statement SHA-256.
    ///
    /// # Errors
    ///
    /// Returns an error for any positive-case/input drift, statement grammar
    /// failure, identity mismatch, or non-exact statement measurement.
    pub(crate) fn case_zero_reference_statement(
        &self,
    ) -> Result<B4CaseZeroReferenceStatementSourceViewV1<'a>> {
        let case = self.positive_case(0, "lift-po2-15")?;
        let input = self.positive_input()?;
        let statement_bytes = case.artifact(B4PositiveArtifactRole::Journal)?;
        let statement = parse_ergo_statement_v1(statement_bytes)
            .context("authenticated case-0 Journal is not an exact ErgoStatementV1")?;
        ensure!(
            statement.encode()?.as_slice() == statement_bytes,
            "authenticated case-0 Journal does not re-encode exactly"
        );
        let profile_id = decode_digest(input.profile_id(), "positive-input profile ID")?;
        let program_id = decode_digest(input.guest_image_id(), "positive-input guest image ID")?;
        let case_image_id: [u8; 32] = case
            .artifact(B4PositiveArtifactRole::ImageId)?
            .try_into()
            .context("authenticated case-0 ImageId is not exactly 32 bytes")?;
        ensure!(
            case_image_id == program_id,
            "authenticated case-0 ImageId differs from the positive-input guest image ID"
        );
        ensure!(
            statement.profile_id() == profile_id,
            "authenticated case-0 Journal profile ID differs from the positive input"
        );
        ensure!(
            statement.program_id() == program_id,
            "authenticated case-0 Journal program ID differs from the positive input"
        );
        ensure!(
            statement.contract_id() == input.reference_contract_id(),
            "authenticated case-0 Journal contract ID differs from the positive input"
        );
        let measured_statement_sha256: [u8; 32] = Sha256::digest(statement_bytes).into();
        ensure!(
            measured_statement_sha256 == input.reference_statement_sha256(),
            "authenticated case-0 Journal SHA-256 differs from the positive input"
        );
        Ok(B4CaseZeroReferenceStatementSourceViewV1 {
            statement_bytes,
            statement,
            profile_id,
            program_id,
        })
    }

    /// Resolve the sole reference statement only after all eleven positive
    /// cases carry byte-identical Journals and matching image/claim identities.
    ///
    /// Proposition bytes are not retained by this materialization boundary.
    /// Their manifest identity is therefore kept as typed custody, but this
    /// resolver does not claim to rederive the proposition's `BLAKE2b` contract
    /// ID. The upstream source used to derive the chain-domain ID is likewise
    /// outside this seam; only its authenticated declared value is cross-bound.
    /// Those derivations remain owned by the statement-bundle producer.
    ///
    /// # Errors
    ///
    /// Returns an error for any input, manifest, profile, guest ELF, terminal
    /// catalogue, positive Journal, `ImageId`, or `ClaimDigest` disagreement.
    #[allow(
        clippy::too_many_lines,
        reason = "the global security seam keeps every independent identity source visibly cross-bound"
    )]
    pub(crate) fn global_reference_statement(
        &self,
    ) -> Result<B4ReferenceStatementSourceViewV1<'a>> {
        let input = self.positive_input()?;
        let manifest =
            StatementBundleManifestV1::from_canonical_jcs(input.reference_statement_manifest())
                .context("authenticated reference statement-bundle manifest is invalid")?;

        let profile_id = input.initial_profile_manifest()?.profile_id()?;
        let declared_profile_id = decode_digest(input.profile_id(), "positive-input profile ID")?;
        ensure!(
            profile_id == declared_profile_id && manifest.profile_id() == profile_id,
            "reference statement profile ID differs across manifest and positive input"
        );

        let declared_program_id =
            decode_digest(input.guest_image_id(), "positive-input guest image ID")?;
        let computed_program_id: [u8; 32] = compute_image_id(input.guest_elf())
            .context("authenticated guest ELF cannot produce a RISC Zero image ID")?
            .into();
        ensure!(
            declared_program_id == computed_program_id
                && manifest.program_id() == computed_program_id,
            "reference statement program ID differs from the authenticated guest ELF"
        );

        ensure!(
            manifest.contract_id() == input.reference_contract_id(),
            "reference statement contract ID differs between manifest and positive input"
        );
        ensure!(
            manifest.chain_domain_id() == input.reference_chain_domain_id(),
            "reference statement chain-domain ID differs between manifest and positive input"
        );
        ensure!(
            u64::try_from(manifest.statement_length())? == input.reference_statement_byte_length()
                && manifest.statement_sha256() == input.reference_statement_sha256(),
            "reference statement measurement differs between manifest and positive input"
        );
        ensure!(
            u64::try_from(manifest.application_payload_length())?
                == input.reference_application_payload_byte_length()
                && manifest.application_payload_sha256()
                    == input.reference_application_payload_sha256(),
            "reference statement application-payload measurement differs between manifest and positive input"
        );

        let terminal_catalogue = Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(
            &self.top_level.terminal_fixture_catalog_jcs,
        )
        .context("authenticated terminal fixture catalogue is invalid")?;
        ensure!(
            decode_digest(
                &terminal_catalogue.program_id,
                "terminal-fixture catalogue program ID",
            )? == computed_program_id,
            "terminal fixture catalogue differs from the authenticated guest ELF"
        );

        let mut representative: Option<&'a [u8]> = None;
        let mut journals = Vec::with_capacity(11);
        let mut case_claim_digests = Vec::with_capacity(11);
        for index in 0..11 {
            let case_id = compiled_positive_case_id(index)?;
            let case = self.positive_case(index, &case_id)?;
            let journal = case.artifact(B4PositiveArtifactRole::Journal)?;
            if let Some(expected) = representative {
                ensure!(
                    journal == expected,
                    "positive Journals are not byte-identical at case {index}"
                );
            } else {
                representative = Some(journal);
            }
            journals.push(journal);

            let case_program_id: [u8; 32] = case
                .artifact(B4PositiveArtifactRole::ImageId)?
                .try_into()
                .with_context(|| {
                    format!("positive ImageId is not exactly 32 bytes at case {index}")
                })?;
            ensure!(
                case_program_id == computed_program_id,
                "positive ImageId differs from the authenticated guest ELF at case {index}"
            );
            let case_claim_digest: [u8; 32] = case
                .artifact(B4PositiveArtifactRole::ClaimDigest)?
                .try_into()
                .with_context(|| {
                    format!("positive ClaimDigest is not exactly 32 bytes at case {index}")
                })?;
            case_claim_digests.push(case_claim_digest);
        }

        for (index, journal) in journals.iter().copied().enumerate() {
            ensure!(
                u64::try_from(journal.len())? == input.reference_statement_byte_length()
                    && <[u8; 32]>::from(Sha256::digest(journal))
                        == input.reference_statement_sha256(),
                "positive Journal measurement differs from the global reference statement at case {index}"
            );
        }
        let statement_bytes =
            representative.context("positive Journal inventory is unexpectedly empty")?;
        let authenticated = manifest
            .authenticate_statement(statement_bytes)
            .context("unanimous positive Journal differs from its statement-bundle manifest")?;
        ensure!(
            case_claim_digests
                .iter()
                .all(|digest| *digest == authenticated.claim_digests().expected_claim),
            "one or more positive ClaimDigest artifacts differ from the reconstructed successful receipt claim"
        );
        Ok(B4ReferenceStatementSourceViewV1 {
            statement_bytes,
            statement: authenticated.statement(),
            claim: authenticated.claim_digests(),
        })
    }

    /// Resolve one closed recursive positive case into a fully bound source view.
    ///
    /// # Errors
    ///
    /// Returns an error before producer selection for any family, profile,
    /// statement, graph, semantic, primary-artifact, reference, or auxiliary
    /// custody mismatch.
    #[cfg(feature = "recursive-ancestry")]
    #[allow(
        clippy::too_many_lines,
        reason = "the recursive source authority keeps profile, statement, graph, terminal, and auxiliary custody checks in one fail-closed sequence"
    )]
    pub(crate) fn recursive_ancestry_source(
        &self,
        family: RecursiveAncestryFamily,
    ) -> Result<B4RecursiveAncestrySourceViewV1<'a>> {
        let case_index = family.positive_case_index();
        let case = self.positive_case(case_index, family.case_id())?;
        let input = self.positive_input()?;
        let profile_manifest = input.initial_profile_manifest()?;
        let profile_id = profile_manifest.profile_id()?;
        let global_statement = self.global_reference_statement()?;
        let statement = global_statement.statement_bytes();
        ensure!(
            case.artifact(B4PositiveArtifactRole::Journal)? == statement,
            "recursive case statement differs from the global reference statement"
        );

        let ancestry_jcs = case.artifact(B4PositiveArtifactRole::Ancestry)?;
        let projection = parse_recursive_ancestry_jcs(ancestry_jcs)
            .context("authenticated recursive ancestry is not exact canonical JCS")?;
        ensure!(
            recursive_ancestry_to_jcs(&projection)?.as_slice() == ancestry_jcs,
            "authenticated recursive ancestry does not re-encode byte-exactly"
        );
        ensure!(
            projection.family == family,
            "authenticated recursive ancestry family differs from the typed selector"
        );
        validate_recursive_ancestry_structure(&projection, statement, profile_id)
            .context("authenticated recursive ancestry structure is invalid")?;
        validate_canonical_recursive_ancestry(&projection, statement, profile_id)
            .context("authenticated recursive ancestry is not canonical positive evidence")?;

        let case_program_id: [u8; 32] = case
            .artifact(B4PositiveArtifactRole::ImageId)?
            .try_into()
            .context("recursive case ImageId is not exactly 32 bytes")?;
        ensure!(
            case_program_id == global_statement.statement().program_id(),
            "recursive case ImageId differs from its authenticated ancestry statement"
        );
        let final_step = projection
            .steps
            .last()
            .context("authenticated recursive ancestry has no final step")?;
        let case_claim_digest: [u8; 32] = case
            .artifact(B4PositiveArtifactRole::ClaimDigest)?
            .try_into()
            .context("recursive case ClaimDigest is not exactly 32 bytes")?;
        ensure!(
            case_claim_digest == recursive_ancestry_claim_digest(&final_step.claim)?,
            "recursive case ClaimDigest differs from its final ancestry claim"
        );
        let terminal_control_id = match &final_step.terminal {
            RecursiveAncestryTerminal::Lift { control_id, .. }
            | RecursiveAncestryTerminal::Join { control_id }
            | RecursiveAncestryTerminal::Resolve { control_id } => {
                decode_digest(control_id, "recursive final terminal control ID")?
            }
        };
        let case_control_id: [u8; 32] = case
            .artifact(B4PositiveArtifactRole::ControlId)?
            .try_into()
            .context("recursive case ControlId is not exactly 32 bytes")?;
        ensure!(
            case_control_id == terminal_control_id,
            "recursive case ControlId differs from its final ancestry terminal"
        );

        let expected_paths = positive_auxiliary_artifact_paths(case_index)?;
        let export = &self.top_level.positive_exports[case_index];
        ensure!(
            export.auxiliary_artifacts.len() == expected_paths.len(),
            "recursive export auxiliary inventory changed after authentication"
        );
        let entries = expected_paths
            .iter()
            .copied()
            .zip(&export.auxiliary_artifacts)
            .map(|(expected_path, identity)| {
                ensure!(
                    identity.path == expected_path,
                    "recursive export auxiliary order changed after authentication"
                );
                let bytes = self
                    .top_level
                    .source_artifacts
                    .get(expected_path)
                    .with_context(|| {
                        format!("missing authenticated recursive auxiliary source {expected_path}")
                    })?;
                Ok((expected_path, bytes.as_slice()))
            })
            .collect::<Result<Vec<_>>>()?;
        let auxiliary_seals = B4RecursiveAuxiliaryMapV1::from_exact_entries(family, &entries)
            .context("recursive auxiliary sources differ from the exact family map")?;
        let borrowed_artifacts = auxiliary_seals
            .iter()
            .map(|(path, bytes)| (path.to_owned(), bytes))
            .collect::<BTreeMap<_, _>>();
        validate_recursive_ancestry_artifacts(
            &projection,
            statement,
            case.raw_seal(),
            &borrowed_artifacts,
        )
        .context("authenticated recursive ancestry artifact references are invalid")?;

        Ok(B4RecursiveAncestrySourceViewV1 {
            family,
            profile_manifest_context: input.profile_manifest(),
            ancestry_jcs,
            projection,
            statement,
            final_raw_seal: case.raw_seal(),
            auxiliary_seals,
        })
    }

    /// Resolve only the case-9 step-00 conditional receipt source.
    ///
    /// The returned type cannot expose the final Resolve seal.
    #[cfg(feature = "recursive-ancestry")]
    pub(crate) fn case9_conditional_receipt_source(
        &self,
    ) -> Result<B4Case9ConditionalReceiptSourceViewV1<'a>> {
        let ancestry = self.recursive_ancestry_source(RecursiveAncestryFamily::TerminalResolve)?;
        let step = ancestry
            .projection()
            .steps
            .first()
            .context("case-9 ancestry has no conditional step")?;
        ensure!(
            step.ordinal == 0
                && step.operation == RecursiveAncestryOperation::Lift { segment_index: 0 },
            "case-9 first ancestry step is not the compiled conditional Lift"
        );
        let (conditional_raw_seal_path, conditional_raw_seal) = ancestry
            .auxiliary_seals()
            .iter()
            .find(|(path, _)| path.as_bytes() == step.raw_seal.path.as_bytes())
            .context("case-9 conditional step has no authenticated auxiliary seal")?;
        Ok(B4Case9ConditionalReceiptSourceViewV1 {
            profile_manifest_context: ancestry.profile_manifest_context(),
            statement_context: ancestry.statement(),
            conditional_raw_seal_path,
            conditional_raw_seal,
        })
    }

    /// Select one exact terminal fixture by compiled position and fixture ID.
    pub(crate) fn terminal_fixture(
        &self,
        fixture_index: usize,
        fixture_id: &str,
    ) -> Result<B4TerminalFixtureSourceViewV1<'a>> {
        ensure!(
            B4_TERMINAL_FIXTURE_LAYOUT
                .get(fixture_index)
                .is_some_and(|layout| layout.fixture_id == fixture_id),
            "terminal fixture selector does not match the compiled position and ID"
        );
        let terminal_catalogue = Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(
            &self.top_level.terminal_fixture_catalog_jcs,
        )
        .context("authenticated terminal fixture catalogue is invalid")?;
        ensure!(
            terminal_catalogue.fixtures.len() == B4_TERMINAL_FIXTURE_COUNT,
            "authenticated terminal fixture catalogue has the wrong cardinality"
        );
        let fixture = terminal_catalogue
            .fixtures
            .get(fixture_index)
            .context("terminal fixture index is outside the authenticated catalogue")?;
        ensure!(
            fixture.fixture_id == fixture_id
                && fixture.fixture_id == B4_TERMINAL_FIXTURE_LAYOUT[fixture_index].fixture_id,
            "terminal fixture identity differs from the compiled catalogue"
        );
        let raw_seal = authenticate_terminal_artifact(
            self.top_level,
            &fixture.raw_seal.path,
            fixture.raw_seal.byte_length,
            &fixture.raw_seal.sha256,
            "raw seal",
        )?;
        let receipt_oracle = authenticate_terminal_artifact(
            self.top_level,
            &fixture.receipt_oracle.path,
            fixture.receipt_oracle.byte_length,
            &fixture.receipt_oracle.sha256,
            "receipt oracle",
        )?;
        Ok(B4TerminalFixtureSourceViewV1 {
            fixture_index,
            fixture_id: B4_TERMINAL_FIXTURE_LAYOUT[fixture_index].fixture_id,
            raw_seal,
            receipt_oracle,
        })
    }
}

fn decode_profile_id(profile_id: &str) -> Result<[u8; 32]> {
    decode_digest(profile_id, "positive-input declared profile ID")
}

fn decode_digest(value: &str, label: &str) -> Result<[u8; 32]> {
    let decoded = hex::decode(value).with_context(|| format!("{label} is not hexadecimal"))?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} is not exactly 32 bytes"))
}

fn authenticate_positive_input_artifact<'a>(
    top_level: &'a B4AuthenticatedMaterializationTopLevelV1,
    identity: &B4ContractArtifactIdentityV1,
    expected_encoding: B4ContractArtifactEncodingV1,
    label: &str,
) -> Result<&'a [u8]> {
    ensure!(
        identity.encoding == expected_encoding,
        "positive-input {label} uses the wrong encoding"
    );
    let bytes = top_level
        .source_artifacts
        .get(&identity.path)
        .with_context(|| format!("authenticated positive-input source lacks {label}"))?;
    ensure!(
        identity.byte_length == u64::try_from(bytes.len())? && identity.sha256 == sha256_hex(bytes),
        "authenticated positive-input {label} path, length, or digest drift"
    );
    Ok(bytes)
}

fn authenticate_registry_quarantine_copy_artifact<'a>(
    top_level: &'a B4AuthenticatedMaterializationTopLevelV1,
    binding: &crate::b4::B4ArtifactBinding,
    upstream_identity: &B4ContractArtifactIdentityV1,
    upstream_bytes: &[u8],
    expected_encoding: B4ContractArtifactEncodingV1,
    label: &str,
) -> Result<&'a [u8]> {
    let expected_registry_encoding = match expected_encoding {
        B4ContractArtifactEncodingV1::RawBytes => crate::b4::B4ArtifactEncoding::RawBytes,
        B4ContractArtifactEncodingV1::Rfc8785Jcs => crate::b4::B4ArtifactEncoding::Rfc8785Jcs,
        B4ContractArtifactEncodingV1::GitBundle => {
            anyhow::bail!("registry quarantine copy cannot bind Git bundle {label}")
        }
    };
    ensure!(
        upstream_identity.encoding == expected_encoding
            && upstream_identity.byte_length == u64::try_from(upstream_bytes.len())?
            && upstream_identity.sha256 == sha256_hex(upstream_bytes),
        "authenticated upstream {label} differs from its positive-input identity"
    );
    ensure!(
        binding.state == crate::b4::B4BindingState::Bound
            && binding.encoding == expected_registry_encoding
            && binding.path != upstream_identity.path
            && binding
                .path
                .starts_with("reproduction/schema/b4-corpus-v1.candidate/")
            && binding.byte_length == upstream_identity.byte_length
            && binding.sha256 == upstream_identity.sha256,
        "expanded-registry {label} quarantine-copy identity differs from the authenticated upstream occurrence"
    );
    let candidate_bytes = top_level
        .source_artifacts
        .get(&binding.path)
        .with_context(|| format!("authenticated source inventory lacks candidate {label}"))?;
    ensure!(
        binding.byte_length == u64::try_from(candidate_bytes.len())?
            && binding.sha256 == sha256_hex(candidate_bytes)
            && candidate_bytes.as_slice() == upstream_bytes,
        "authenticated candidate {label} bytes differ from the registry and upstream occurrence"
    );
    if expected_encoding == B4ContractArtifactEncodingV1::Rfc8785Jcs {
        validate_canonical_json_source(candidate_bytes).with_context(|| {
            format!("authenticated candidate {label} is not exact canonical JCS")
        })?;
    }
    Ok(candidate_bytes)
}

fn authenticate_registry_profile_binding(
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
    input_manifest: &B4ContractArtifactIdentityV1,
    input_profile_id: &str,
) -> Result<()> {
    let binding = &top_level.expanded_registry.profile.manifest;
    ensure!(
        binding.state == crate::b4::B4BindingState::Bound
            && binding.encoding == crate::b4::B4ArtifactEncoding::RawBytes
            && binding.path == input_manifest.path
            && binding.byte_length == input_manifest.byte_length
            && binding.sha256 == input_manifest.sha256
            && top_level.expanded_registry.profile.profile_id == input_profile_id,
        "expanded registry profile binding differs from the authenticated positive input set"
    );
    Ok(())
}

fn authenticate_registry_guest_binding(
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
    input_elf: &B4ContractArtifactIdentityV1,
    input_image_id: &str,
) -> Result<()> {
    let binding = &top_level.expanded_registry.bindings.guest;
    ensure!(
        binding.state == crate::b4::B4BindingState::Bound
            && binding.elf.state == crate::b4::B4BindingState::Bound
            && binding.elf.encoding == crate::b4::B4ArtifactEncoding::RawBytes
            && binding.elf.path != input_elf.path
            && binding
                .elf
                .path
                .starts_with("reproduction/schema/b4-corpus-v1.candidate/")
            && binding.elf.byte_length == input_elf.byte_length
            && binding.elf.sha256 == input_elf.sha256
            && binding.image_id == input_image_id,
        "expanded registry guest quarantine copy differs from the authenticated positive input set"
    );
    Ok(())
}

fn authenticate_registry_guest_binding_v2(
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
    input_elf: &B4ContractArtifactIdentityV1,
    input_image_id: &str,
) -> Result<()> {
    let binding = &top_level.expanded_registry.bindings.guest;
    ensure!(
        binding.state == crate::b4::B4BindingState::Bound
            && binding.elf.state == crate::b4::B4BindingState::Bound
            && binding.elf.encoding == crate::b4::B4ArtifactEncoding::RawBytes
            && binding.elf.path != input_elf.path
            && binding
                .elf
                .path
                .starts_with("reproduction/schema/b4-corpus-v1.candidate/")
            && binding.elf.byte_length == input_elf.byte_length
            && binding.elf.sha256 == input_elf.sha256
            && binding.image_id == input_image_id,
        "expanded registry V2 guest quarantine copy differs from the authenticated positive input set"
    );
    Ok(())
}

fn authenticate_registry_reference_statement_binding(
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
    input: &crate::b4_materialization_set::B4AuthenticatedPositiveInputSourcesV1,
) -> Result<()> {
    let binding = &top_level
        .expanded_registry
        .bindings
        .reference_statement_bundle;
    let manifest = &binding.manifest;
    let input_manifest = input.reference_statement_manifest();
    ensure!(
        binding.state == crate::b4::B4BindingState::Bound
            && manifest.state == crate::b4::B4BindingState::Bound
            && manifest.encoding == crate::b4::B4ArtifactEncoding::Rfc8785Jcs
            && manifest.path != input_manifest.path
            && manifest
                .path
                .starts_with("reproduction/schema/b4-corpus-v1.candidate/")
            && manifest.byte_length == input_manifest.byte_length
            && manifest.sha256 == input_manifest.sha256
            && binding.contract_id == input.reference_contract_id()
            && binding.statement_sha256 == input.reference_statement_sha256(),
        "expanded registry reference-statement quarantine copy differs from the authenticated positive input set"
    );
    Ok(())
}

fn authenticate_registry_reference_statement_binding_v2(
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
    input: &B4AuthenticatedPositiveInputSourcesV2,
) -> Result<()> {
    let binding = &top_level
        .expanded_registry
        .bindings
        .reference_statement_bundle;
    let manifest = &binding.manifest;
    let input_manifest = input.reference_statement_manifest();
    ensure!(
        binding.state == crate::b4::B4BindingState::Bound
            && manifest.state == crate::b4::B4BindingState::Bound
            && manifest.encoding == crate::b4::B4ArtifactEncoding::Rfc8785Jcs
            && manifest.path != input_manifest.path
            && manifest
                .path
                .starts_with("reproduction/schema/b4-corpus-v1.candidate/")
            && manifest.byte_length == input_manifest.byte_length
            && manifest.sha256 == input_manifest.sha256
            && binding.contract_id == input.reference_contract_id()
            && binding.statement_sha256 == input.reference_statement_sha256(),
        "expanded registry reference-statement binding differs from the authenticated V2 positive input set"
    );
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the closed positive-case authentication keeps role, path, export, and manifest bindings together"
)]
fn authenticate_positive_case(
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
    index: usize,
) -> Result<()> {
    let expected_case_id = compiled_positive_case_id(index)?;
    let case = top_level
        .expanded_registry
        .positive_cases
        .get(index)
        .context("authenticated positive case inventory is incomplete")?;
    let export = top_level
        .positive_exports
        .get(index)
        .context("authenticated positive export inventory is incomplete")?;
    ensure!(
        usize::from(case.index) == index
            && case.case_id == expected_case_id
            && usize::from(export.case_index) == index,
        "positive case or export order/index/ID differs from the compiled inventory"
    );
    let expected_roles = positive_artifact_layout(index)?;
    ensure!(
        case.artifacts.len() == expected_roles.len(),
        "positive case artifact cardinality differs from its exact compiled inventory"
    );
    for (position, (&(expected_role, expected_basename), artifact)) in
        expected_roles.iter().zip(&case.artifacts).enumerate()
    {
        ensure!(
            artifact.role == expected_role,
            "positive case artifact role/order drift at case {index}, position {position}"
        );
        let (_, expected_encoding) = positive_artifact_encoding(expected_role);
        ensure!(
            artifact.encoding == expected_encoding,
            "positive case artifact encoding drift for {}",
            positive_artifact_role_name(expected_role)
        );
        validate_positive_artifact_length(index, expected_role, artifact.byte_length)
            .with_context(|| {
                format!(
                    "positive case artifact length drift for {}",
                    positive_artifact_role_name(expected_role)
                )
            })?;
        validate_canonical_positive_case_artifact_path(
            &case.case_id,
            &artifact.path,
            expected_basename,
        )
        .with_context(|| {
            format!(
                "positive case artifact path drift for {}",
                positive_artifact_role_name(expected_role)
            )
        })?;
        if expected_role == B4PositiveArtifactRole::RawSeal {
            ensure!(
                !top_level.source_artifacts.contains_key(&artifact.path),
                "raw seal was supplied through the ordinary source-artifact channel"
            );
            ensure!(
                artifact.byte_length == u64::try_from(export.raw_seal.len())?
                    && artifact.sha256 == sha256_hex(&export.raw_seal),
                "positive export raw seal differs from the expanded-registry artifact"
            );
        } else {
            let bytes = top_level
                .source_artifacts
                .get(&artifact.path)
                .with_context(|| {
                    format!(
                        "missing authenticated {} source",
                        positive_artifact_role_name(expected_role)
                    )
                })?;
            ensure!(
                artifact.byte_length == u64::try_from(bytes.len())?
                    && artifact.sha256 == sha256_hex(bytes),
                "positive source artifact path, length, or digest drift for {}",
                positive_artifact_role_name(expected_role)
            );
        }
    }
    let manifest_value = validate_canonical_json_source(&export.proof_output_manifest_jcs)
        .context("positive export proof-output manifest is not exact canonical JCS")?;
    let manifest: ProofOutputManifest = serde_json::from_value(manifest_value)
        .context("positive export proof-output manifest has the wrong shape")?;
    validate_manifest_shape(&manifest)
        .context("positive export proof-output manifest has an invalid inventory")?;
    let expected_auxiliary_paths = positive_auxiliary_artifact_paths(index)?;
    ensure!(
        manifest.len() == expected_roles.len() + expected_auxiliary_paths.len(),
        "positive export proof-output manifest has the wrong artifact cardinality"
    );
    for ((expected_role, expected_path), artifact) in
        positive_artifact_layout(index)?.iter().zip(&case.artifacts)
    {
        let matches = manifest
            .iter()
            .filter(|entry| entry.path == *expected_path)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1
                && matches[0].length == artifact.byte_length.to_string()
                && matches[0].sha256 == artifact.sha256,
            "positive export manifest path, role, length, or digest drift for {}",
            positive_artifact_role_name(*expected_role)
        );
    }
    ensure!(
        export.auxiliary_artifacts.len() == expected_auxiliary_paths.len(),
        "positive export auxiliary artifact cardinality differs from its exact recursive family"
    );
    for (position, (expected_path, auxiliary)) in expected_auxiliary_paths
        .iter()
        .copied()
        .zip(&export.auxiliary_artifacts)
        .enumerate()
    {
        ensure!(
            auxiliary.path == expected_path,
            "positive export auxiliary artifact path/order drift at case {index}, position {position}"
        );
        let matches = manifest
            .iter()
            .filter(|entry| entry.path == expected_path)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1
                && matches[0].length == auxiliary.byte_length.to_string()
                && matches[0].sha256 == auxiliary.sha256,
            "positive export auxiliary manifest path, length, or digest drift at case {index}, position {position}"
        );
        let bytes = top_level
            .source_artifacts
            .get(expected_path)
            .with_context(|| {
                format!(
                    "missing authenticated recursive auxiliary source at case {index}, position {position}"
                )
            })?;
        ensure!(
            auxiliary.byte_length == PROOF_BYTES as u64
                && auxiliary.byte_length == u64::try_from(bytes.len())?
                && auxiliary.sha256 == sha256_hex(bytes),
            "positive recursive auxiliary source path, length, digest, or content drift at case {index}, position {position}"
        );
    }
    Ok(())
}

fn authenticate_terminal_artifact<'a>(
    top_level: &'a B4AuthenticatedMaterializationTopLevelV1,
    path: &str,
    byte_length: u64,
    sha256: &str,
    label: &str,
) -> Result<&'a [u8]> {
    let bytes = top_level
        .source_artifacts
        .get(path)
        .with_context(|| format!("authenticated terminal fixture lacks {label}"))?;
    ensure!(
        byte_length == u64::try_from(bytes.len())? && sha256 == sha256_hex(bytes),
        "authenticated terminal {label} path, length, or digest drift"
    );
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
pub(crate) fn synthetic_global_reference_statement_top_level()
-> B4AuthenticatedMaterializationTopLevelV1 {
    tests::populate_global_reference_statement_sources()
}

#[cfg(test)]
pub(crate) fn synthetic_v2_materialization_fixture_storage()
-> B4AuthenticatedMaterializationTopLevelV1 {
    tests::populate_v2_materialization_fixture_sources()
}

#[cfg(test)]
pub(crate) fn synthetic_case8_control_drift_top_level() -> B4AuthenticatedMaterializationTopLevelV1
{
    let mut top_level = tests::populate_global_reference_statement_sources();
    tests::replace_positive_artifact(
        &mut top_level,
        8,
        B4PositiveArtifactRole::ControlId,
        vec![0x42; 32],
    );
    top_level
}

#[cfg(all(test, feature = "recursive-ancestry"))]
pub(crate) fn synthetic_valid_recursive_ancestry_top_level()
-> B4AuthenticatedMaterializationTopLevelV1 {
    tests::populate_valid_recursive_ancestry_sources()
}

#[cfg(all(test, feature = "recursive-ancestry"))]
pub(crate) fn reseed_descriptor_rooted_recursive_sources_from_case9(
    top_level: &mut B4AuthenticatedMaterializationTopLevelV1,
    proposition: &[u8],
) -> Result<()> {
    tests::reseed_descriptor_rooted_recursive_sources_from_case9(top_level, proposition)
}

#[cfg(test)]
mod tests {
    use anyhow::Context as _;
    use sha2::{Digest as _, Sha256};

    #[cfg(feature = "recursive-ancestry")]
    use crate::recursive_ancestry::{
        RecursiveAncestryArtifactReference, RecursiveAncestryFamily, RecursiveAncestryProjection,
        RecursiveAncestryTerminal, recursive_ancestry_artifact_reference,
        recursive_ancestry_claim_digest, recursive_ancestry_to_jcs,
    };
    use crate::{
        b4::{
            B4ArtifactBinding, B4ArtifactEncoding, B4BindingState, B4PositiveArtifact,
            B4PositiveArtifactRole,
        },
        b4_materialization_set::{
            authority_tdd_tests::fixture_source_top_level, compiled_positive_generation_recipe,
            parse_positive_input_sources, parse_positive_input_sources_v2,
            positive_artifact_layout,
        },
        b4_positive_source_auth::{B4PositiveCaseSourceV2, B4PositiveSourceBytesV2},
        canonical::canonical_json_bytes,
        claim::{ReceiptClaimDigests, ok_receipt_claim_digests},
        constants::{ERGO_STATEMENT_DOMAIN, PROOF_BYTES},
        ergo_statement::{ErgoStatementV1, parse_ergo_statement_v1},
        manifest::{ManifestEntry, ProofOutputManifest},
        profile_manifest::{ProfileArtifactReference, StarkProfileManifestV1},
        test_support::valid_program_fixture,
    };

    fn digest(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn role_bytes(role: B4PositiveArtifactRole, case_index: usize) -> Vec<u8> {
        let case_byte = u8::try_from(case_index).expect("test case index fits in u8");
        match role {
            B4PositiveArtifactRole::Ancestry
            | B4PositiveArtifactRole::Calibration
            | B4PositiveArtifactRole::Metadata => b"{}".to_vec(),
            B4PositiveArtifactRole::ClaimDigest
            | B4PositiveArtifactRole::ControlId
            | B4PositiveArtifactRole::ImageId => vec![case_byte; 32],
            B4PositiveArtifactRole::Journal => vec![case_byte; 159],
            B4PositiveArtifactRole::RawSeal => vec![case_byte; PROOF_BYTES],
            B4PositiveArtifactRole::ReceiptOracle => vec![case_byte],
        }
    }

    fn role_name(role: B4PositiveArtifactRole) -> &'static str {
        match role {
            B4PositiveArtifactRole::Ancestry => "ancestry",
            B4PositiveArtifactRole::Calibration => "calibration",
            B4PositiveArtifactRole::ClaimDigest => "claim-digest",
            B4PositiveArtifactRole::ControlId => "control-id",
            B4PositiveArtifactRole::ImageId => "image-id",
            B4PositiveArtifactRole::Journal => "journal",
            B4PositiveArtifactRole::Metadata => "metadata",
            B4PositiveArtifactRole::RawSeal => "raw-seal",
            B4PositiveArtifactRole::ReceiptOracle => "receipt-oracle",
        }
    }

    fn input_identity(path: &str, bytes: &[u8], encoding: &str) -> serde_json::Value {
        serde_json::json!({
            "path": path,
            "byteLength": bytes.len(),
            "sha256": digest(bytes),
            "encoding": encoding,
        })
    }

    #[derive(Clone)]
    struct OwnedV2Source {
        path: String,
        bytes: Vec<u8>,
    }

    impl OwnedV2Source {
        fn view(&self) -> B4PositiveSourceBytesV2<'_> {
            B4PositiveSourceBytesV2 {
                path: &self.path,
                bytes: &self.bytes,
            }
        }
    }

    #[derive(Clone)]
    struct V2PostproofFixture {
        input_jcs: Vec<u8>,
        generation_jcs: Vec<u8>,
        generator: OwnedV2Source,
        nested: Vec<OwnedV2Source>,
        proof_output_manifest_jcs: Vec<u8>,
        primary: Vec<OwnedV2Source>,
        auxiliary: Vec<OwnedV2Source>,
    }

    impl V2PostproofFixture {
        #[allow(
            clippy::too_many_lines,
            reason = "the fixture constructs all eleven exact generation rows and the complete nested V2 source closure"
        )]
        fn exact() -> Self {
            let mut top_level = populate_positive_sources();
            populate_positive_input_sources(&mut top_level);

            let verifier_cli_path = "contracts/eip0045-verifier-cli-contract.json";
            let verifier_cli_jcs = b"{}".to_vec();
            top_level
                .source_artifacts
                .insert(verifier_cli_path.to_owned(), verifier_cli_jcs.clone());
            let mut input =
                crate::canonical::validate_canonical_json_source(&top_level.positive_input_set)
                    .unwrap();
            input["format"] = serde_json::json!("Eip0045B4PositiveInputSetV2");
            input["formatVersion"] = serde_json::json!(2);
            input["verifierCliContract"] =
                input_identity(verifier_cli_path, &verifier_cli_jcs, "rfc8785-jcs");
            input["validators"] = serde_json::json!([]);
            input["runnerProfiles"] = serde_json::json!([]);
            input["recursiveCalibrations"] = serde_json::json!([]);
            input["positiveCases"] = serde_json::json!([]);
            let input_jcs = canonical_json_bytes(&input).unwrap();
            let parsed_input = parse_positive_input_sources_v2(&input_jcs).unwrap();
            let nested = parsed_input
                .artifacts
                .keys()
                .map(|path| OwnedV2Source {
                    path: path.clone(),
                    bytes: top_level.source_artifacts[path].clone(),
                })
                .collect::<Vec<_>>();
            let generator = OwnedV2Source {
                path: parsed_input.generator.path.clone(),
                bytes: top_level.source_artifacts[&parsed_input.generator.path].clone(),
            };

            let cases = top_level
                .expanded_registry
                .positive_cases
                .iter()
                .enumerate()
                .map(|(index, case)| {
                    let artifacts = positive_artifact_layout(index)
                        .unwrap()
                        .iter()
                        .zip(&case.artifacts)
                        .map(|((role, basename), identity)| {
                            assert_eq!(*role, identity.role);
                            let bytes = if *role == B4PositiveArtifactRole::RawSeal {
                                &top_level.positive_exports[index].raw_seal
                            } else {
                                &top_level.source_artifacts[&identity.path]
                            };
                            let encoding = match identity.encoding {
                                B4ArtifactEncoding::RawBytes => "raw-bytes",
                                B4ArtifactEncoding::Rfc8785Jcs => "rfc8785-jcs",
                            };
                            let mut artifact = serde_json::json!({
                                "role": role_name(*role),
                                "sourceFile": basename,
                                "byteLength": bytes.len(),
                                "sha256": digest(bytes),
                                "encoding": encoding,
                            });
                            if matches!(
                                role,
                                B4PositiveArtifactRole::ClaimDigest
                                    | B4PositiveArtifactRole::ControlId
                                    | B4PositiveArtifactRole::ImageId
                            ) {
                                artifact["contentHex"] = serde_json::json!(hex::encode(bytes));
                            }
                            if *role == B4PositiveArtifactRole::ReceiptOracle {
                                artifact["codec"] = serde_json::json!(if index < 8 {
                                    "bincode-1.3.3-little-endian-fixed-int-reject-trailing"
                                } else {
                                    "eip0045-recursive-oracle-borsh-v1"
                                });
                            }
                            artifact
                        })
                        .collect::<Vec<_>>();
                    let manifest = &top_level.positive_exports[index].proof_output_manifest_jcs;
                    serde_json::json!({
                        "caseIndex": index,
                        "caseId": case.case_id,
                        "generation": compiled_positive_generation_recipe(index).unwrap(),
                        "proofOutputManifest": {
                            "fileName": if index < 8 {
                                "candidate-proof-output-manifest.json"
                            } else {
                                "candidate-recursive-output-manifest.json"
                            },
                            "byteLength": manifest.len(),
                            "sha256": digest(manifest),
                            "encoding": "rfc8785-jcs",
                        },
                        "artifacts": artifacts,
                    })
                })
                .collect::<Vec<_>>();
            let generation_jcs = canonical_json_bytes(&serde_json::json!({
                "format": "Eip0045B4PositiveGenerationSetV2",
                "formatVersion": 2,
                "inputSetCommitment": {
                    "format": "Eip0045B4PositiveInputSetV2",
                    "byteLength": input_jcs.len(),
                    "sha256": digest(&input_jcs),
                    "encoding": "rfc8785-jcs",
                },
                "proofGeneratorArtifact": {
                    "byteLength": generator.bytes.len(),
                    "sha256": digest(&generator.bytes),
                    "encoding": "raw-bytes",
                },
                "cases": cases,
            }))
            .unwrap();

            let case = &top_level.expanded_registry.positive_cases[0];
            let primary = case
                .artifacts
                .iter()
                .map(|identity| OwnedV2Source {
                    path: identity.path.clone(),
                    bytes: if identity.role == B4PositiveArtifactRole::RawSeal {
                        top_level.positive_exports[0].raw_seal.clone()
                    } else {
                        top_level.source_artifacts[&identity.path].clone()
                    },
                })
                .collect();
            let auxiliary = top_level.positive_exports[0]
                .auxiliary_artifacts
                .iter()
                .map(|identity| OwnedV2Source {
                    path: identity.path.clone(),
                    bytes: top_level.source_artifacts[&identity.path].clone(),
                })
                .collect();
            Self {
                input_jcs,
                generation_jcs,
                generator,
                nested,
                proof_output_manifest_jcs: top_level.positive_exports[0]
                    .proof_output_manifest_jcs
                    .clone(),
                primary,
                auxiliary,
            }
        }

        fn refresh_generation_input_commitment(&mut self) {
            let mut generation =
                crate::canonical::validate_canonical_json_source(&self.generation_jcs).unwrap();
            generation["inputSetCommitment"]["byteLength"] =
                serde_json::json!(self.input_jcs.len());
            generation["inputSetCommitment"]["sha256"] = serde_json::json!(digest(&self.input_jcs));
            self.generation_jcs = canonical_json_bytes(&generation).unwrap();
        }

        fn mutate_input(&mut self, mutation: impl FnOnce(&mut serde_json::Value)) {
            let mut input =
                crate::canonical::validate_canonical_json_source(&self.input_jcs).unwrap();
            mutation(&mut input);
            self.input_jcs = canonical_json_bytes(&input).unwrap();
            self.refresh_generation_input_commitment();
        }

        fn mutate_generation(&mut self, mutation: impl FnOnce(&mut serde_json::Value)) {
            let mut generation =
                crate::canonical::validate_canonical_json_source(&self.generation_jcs).unwrap();
            mutation(&mut generation);
            self.generation_jcs = canonical_json_bytes(&generation).unwrap();
        }

        fn resolver(&self) -> anyhow::Result<super::B4FixtureSourceResolverV2> {
            let nested = self
                .nested
                .iter()
                .map(OwnedV2Source::view)
                .collect::<Vec<_>>();
            super::B4FixtureSourceResolverV2::from_postproof_documents(
                &self.input_jcs,
                &self.generation_jcs,
                self.generator.view(),
                &nested,
            )
        }

        fn authenticate_case_zero<'a>(
            &'a self,
            resolver: &super::B4FixtureSourceResolverV2,
        ) -> anyhow::Result<crate::b4_positive_source_auth::B4AuthenticatedPositiveCaseSourceV2<'a>>
        {
            let primary = self
                .primary
                .iter()
                .map(OwnedV2Source::view)
                .collect::<Vec<_>>();
            let auxiliary = self
                .auxiliary
                .iter()
                .map(OwnedV2Source::view)
                .collect::<Vec<_>>();
            resolver.positive_case(
                0,
                B4PositiveCaseSourceV2 {
                    proof_output_manifest_jcs: &self.proof_output_manifest_jcs,
                    primary_artifacts: &primary,
                    auxiliary_artifacts: &auxiliary,
                },
            )
        }
    }

    fn refresh_positive_export_manifest(
        top_level: &mut crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1,
        case_index: usize,
    ) {
        let case = &top_level.expanded_registry.positive_cases[case_index];
        let mut manifest = positive_artifact_layout(case_index)
            .unwrap()
            .iter()
            .zip(&case.artifacts)
            .map(|((_, path), artifact)| ManifestEntry {
                path: (*path).to_owned(),
                length: artifact.byte_length.to_string(),
                sha256: artifact.sha256.clone(),
            })
            .collect::<Vec<_>>();
        manifest.extend(
            top_level.positive_exports[case_index]
                .auxiliary_artifacts
                .iter()
                .map(|artifact| ManifestEntry {
                    path: artifact.path.clone(),
                    length: artifact.byte_length.to_string(),
                    sha256: artifact.sha256.clone(),
                }),
        );
        manifest.sort_by(|left, right| left.path.cmp(&right.path));
        top_level.positive_exports[case_index].proof_output_manifest_jcs =
            canonical_json_bytes(&serde_json::to_value(manifest).unwrap()).unwrap();
    }

    pub(super) fn replace_positive_artifact(
        top_level: &mut crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1,
        case_index: usize,
        role: B4PositiveArtifactRole,
        bytes: Vec<u8>,
    ) {
        let artifact = top_level.expanded_registry.positive_cases[case_index]
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.role == role)
            .unwrap();
        artifact.byte_length = bytes.len() as u64;
        artifact.sha256 = digest(&bytes);
        top_level
            .source_artifacts
            .insert(artifact.path.clone(), bytes);
        refresh_positive_export_manifest(top_level, case_index);
    }

    fn replace_reference_statement_sha256(
        top_level: &mut crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1,
        statement_sha256: &str,
    ) {
        let mut input =
            crate::canonical::validate_canonical_json_source(&top_level.positive_input_set)
                .unwrap();
        input["referenceStatement"]["statementSha256"] = serde_json::json!(statement_sha256);
        top_level.positive_input_set = canonical_json_bytes(&input).unwrap();
        top_level
            .expanded_registry
            .bindings
            .reference_statement_bundle
            .statement_sha256 = statement_sha256.to_owned();
    }

    fn statement_bundle_artifact(path: &str, role: &str, bytes: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "length": bytes.len(),
            "path": path,
            "role": role,
            "sha256": digest(bytes),
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the test oracle makes each independently bound statement identity explicit"
    )]
    fn statement_bundle_manifest_jcs(
        statement: &[u8],
        chain_domain_id: [u8; 32],
        profile_id: [u8; 32],
        program_id: [u8; 32],
        contract_id: [u8; 32],
        application_payload: &[u8],
        proposition: &[u8],
        claim: ReceiptClaimDigests,
    ) -> Vec<u8> {
        canonical_json_bytes(&serde_json::json!({
            "artifacts": [
                statement_bundle_artifact(
                    "application-payload.bin",
                    "application-payload",
                    application_payload,
                ),
                statement_bundle_artifact(
                    "chain-domain-id.bin",
                    "chain-domain-id",
                    &chain_domain_id,
                ),
                statement_bundle_artifact(
                    "claim-digest.bin",
                    "expected-claim-digest",
                    &claim.expected_claim,
                ),
                statement_bundle_artifact("contract-id.bin", "contract-id", &contract_id),
                statement_bundle_artifact(
                    "journal-digest.bin",
                    "journal-digest",
                    &claim.journal_digest,
                ),
                statement_bundle_artifact(
                    "output-digest.bin",
                    "receipt-output-digest",
                    &claim.output,
                ),
                statement_bundle_artifact(
                    "post-digest.bin",
                    "receipt-post-digest",
                    &claim.post,
                ),
                statement_bundle_artifact("profile-id.bin", "stark-profile-id", &profile_id),
                statement_bundle_artifact("program-id.bin", "guest-program-id", &program_id),
                statement_bundle_artifact(
                    "proposition.bin",
                    "self-proposition-bytes",
                    proposition,
                ),
                statement_bundle_artifact("statement.bin", "ergo-statement-v1", statement),
            ],
            "claim": {
                "expectedClaim": hex::encode(claim.expected_claim),
                "journalDigest": hex::encode(claim.journal_digest),
                "output": hex::encode(claim.output),
                "post": hex::encode(claim.post),
            },
            "format": "ErgoStatementBundleV1",
            "formatVersion": 1,
            "statement": {
                "applicationPayloadLength": application_payload.len(),
                "chainDomainId": hex::encode(chain_domain_id),
                "contractId": hex::encode(contract_id),
                "domainHex": hex::encode(ERGO_STATEMENT_DOMAIN),
                "profileId": hex::encode(profile_id),
                "programId": hex::encode(program_id),
                "propositionBytesLength": proposition.len(),
                "statementLength": statement.len(),
                "statementSha256": digest(statement),
                "version": 1,
            },
        }))
        .unwrap()
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the synthetic authority fixture keeps every cross-bound input and registry field visible"
    )]
    fn populate_positive_input_sources(
        top_level: &mut crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1,
    ) -> (Vec<u8>, String, String) {
        let manifest = include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin").to_vec();
        let algorithm = include_bytes!("../../profiles/risc0-v3-succinct/algorithm.txt").to_vec();
        let constants = include_bytes!("../../profiles/risc0-v3-succinct/constants.bin").to_vec();
        let (guest_elf, image_id_bytes) = valid_program_fixture();
        let source_lock = b"{}".to_vec();
        let generator = b"authenticated-generator".to_vec();
        let profile_id = hex::encode(crate::profile::profile_id(&manifest).unwrap());
        let image_id = hex::encode(image_id_bytes);
        let profile_id_bytes: [u8; 32] = hex::decode(&profile_id).unwrap().try_into().unwrap();
        let contract_id_bytes = [0x22; 32];
        let chain_domain_id = [0x10; 32];
        let application_payload = b"fixture-payload";
        let proposition = b"fixture proposition bytes";
        let reference_statement = ErgoStatementV1::new(
            chain_domain_id,
            profile_id_bytes,
            image_id_bytes,
            contract_id_bytes,
            application_payload,
        )
        .unwrap()
        .encode()
        .unwrap();
        let reference_claim =
            ok_receipt_claim_digests(&image_id_bytes, &reference_statement).unwrap();
        let statement_manifest = statement_bundle_manifest_jcs(
            &reference_statement,
            chain_domain_id,
            profile_id_bytes,
            image_id_bytes,
            contract_id_bytes,
            application_payload,
            proposition,
            reference_claim,
        );
        let reference_statement_byte_length = reference_statement.len();
        let reference_statement_sha256 = digest(&reference_statement);
        replace_positive_artifact(
            top_level,
            0,
            B4PositiveArtifactRole::ImageId,
            image_id_bytes.to_vec(),
        );
        replace_positive_artifact(
            top_level,
            0,
            B4PositiveArtifactRole::Journal,
            reference_statement,
        );
        let manifest_path = "profiles/risc0-v3-succinct/manifest.bin";
        let algorithm_path = "profiles/risc0-v3-succinct/algorithm.txt";
        let constants_path = "profiles/risc0-v3-succinct/constants.bin";
        let guest_path = "methods/guest.elf";
        let guest_candidate_path = "reproduction/schema/b4-corpus-v1.candidate/bindings/guest.elf";
        let statement_path = "statement/bundle-manifest.json";
        let statement_candidate_path =
            "reproduction/schema/b4-corpus-v1.candidate/bindings/statement-manifest.json";
        let source_lock_path = "locks/source-lock.json";
        let generator_path = "generator/eip0045-candidate-generator";
        let input = serde_json::json!({
            "format": "Eip0045B4PositiveInputSetV1",
            "formatVersion": 1,
            "profile": {
                "profileId": profile_id,
                "manifest": input_identity(manifest_path, &manifest, "raw-bytes"),
                "algorithm": input_identity(algorithm_path, &algorithm, "raw-bytes"),
                "constants": input_identity(constants_path, &constants, "raw-bytes"),
            },
            "guest": {
                "elf": input_identity(guest_path, &guest_elf, "raw-bytes"),
                "imageId": image_id,
            },
            "referenceStatement": {
                "bundleManifest": input_identity(statement_path, &statement_manifest, "rfc8785-jcs"),
                "contractId": hex::encode(contract_id_bytes),
                "statementByteLength": reference_statement_byte_length,
                "statementSha256": reference_statement_sha256,
                "chainDomainId": hex::encode(chain_domain_id),
                "applicationPayloadByteLength": application_payload.len(),
                "applicationPayloadSha256": digest(application_payload),
            },
            "sourceLock": input_identity(source_lock_path, &source_lock, "rfc8785-jcs"),
            "proofGenerator": {"artifact": input_identity(generator_path, &generator, "raw-bytes")},
        });
        let input_jcs = canonical_json_bytes(&input).unwrap();
        for (path, bytes) in [
            (manifest_path, manifest.clone()),
            (algorithm_path, algorithm.clone()),
            (constants_path, constants.clone()),
            (guest_path, guest_elf.clone()),
            (guest_candidate_path, guest_elf.clone()),
            (statement_path, statement_manifest.clone()),
            (statement_candidate_path, statement_manifest.clone()),
            (source_lock_path, source_lock),
            (generator_path, generator),
        ] {
            top_level.source_artifacts.insert(path.to_owned(), bytes);
        }
        top_level.positive_input_set = input_jcs.clone();
        top_level.expanded_registry.profile.profile_id = profile_id.clone();
        top_level.expanded_registry.profile.manifest = B4ArtifactBinding {
            byte_length: manifest.len() as u64,
            encoding: B4ArtifactEncoding::RawBytes,
            path: manifest_path.to_owned(),
            sha256: digest(&manifest),
            state: B4BindingState::Bound,
        };
        top_level.expanded_registry.bindings.guest.elf = B4ArtifactBinding {
            byte_length: guest_elf.len() as u64,
            encoding: B4ArtifactEncoding::RawBytes,
            path: guest_candidate_path.to_owned(),
            sha256: digest(&guest_elf),
            state: B4BindingState::Bound,
        };
        top_level.expanded_registry.bindings.guest.image_id = image_id.clone();
        top_level.expanded_registry.bindings.guest.state = B4BindingState::Bound;
        top_level
            .expanded_registry
            .bindings
            .reference_statement_bundle
            .manifest = B4ArtifactBinding {
            byte_length: statement_manifest.len() as u64,
            encoding: B4ArtifactEncoding::Rfc8785Jcs,
            path: statement_candidate_path.to_owned(),
            sha256: digest(&statement_manifest),
            state: B4BindingState::Bound,
        };
        top_level
            .expanded_registry
            .bindings
            .reference_statement_bundle
            .contract_id = hex::encode(contract_id_bytes);
        top_level
            .expanded_registry
            .bindings
            .reference_statement_bundle
            .statement_sha256 = reference_statement_sha256;
        top_level
            .expanded_registry
            .bindings
            .reference_statement_bundle
            .state = B4BindingState::Bound;
        (input_jcs, profile_id, image_id)
    }

    fn populate_positive_sources()
    -> crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1 {
        let mut top_level = fixture_source_top_level();
        for case in &mut top_level.expanded_registry.positive_cases {
            let roles: &[B4PositiveArtifactRole] = if case.index < 8 {
                &[
                    B4PositiveArtifactRole::ClaimDigest,
                    B4PositiveArtifactRole::ControlId,
                    B4PositiveArtifactRole::ImageId,
                    B4PositiveArtifactRole::Journal,
                    B4PositiveArtifactRole::Metadata,
                    B4PositiveArtifactRole::RawSeal,
                    B4PositiveArtifactRole::ReceiptOracle,
                ]
            } else {
                &[
                    B4PositiveArtifactRole::Ancestry,
                    B4PositiveArtifactRole::Calibration,
                    B4PositiveArtifactRole::ClaimDigest,
                    B4PositiveArtifactRole::ControlId,
                    B4PositiveArtifactRole::ImageId,
                    B4PositiveArtifactRole::Journal,
                    B4PositiveArtifactRole::RawSeal,
                    B4PositiveArtifactRole::ReceiptOracle,
                ]
            };
            case.artifacts.clear();
            for role in roles {
                let bytes = role_bytes(*role, usize::from(case.index));
                let expected_file = positive_artifact_layout(usize::from(case.index))
                    .unwrap()
                    .iter()
                    .find_map(|(expected_role, expected_file)| {
                        (*expected_role == *role).then_some(*expected_file)
                    })
                    .unwrap();
                let path = format!(
                    "reproduction/schema/b4-corpus-v1.candidate/positive/{}/{}",
                    case.case_id, expected_file
                );
                if *role != B4PositiveArtifactRole::RawSeal {
                    top_level
                        .source_artifacts
                        .insert(path.clone(), bytes.clone());
                }
                case.artifacts.push(B4PositiveArtifact {
                    byte_length: bytes.len() as u64,
                    encoding: match role {
                        B4PositiveArtifactRole::Ancestry
                        | B4PositiveArtifactRole::Calibration
                        | B4PositiveArtifactRole::Metadata => B4ArtifactEncoding::Rfc8785Jcs,
                        _ => B4ArtifactEncoding::RawBytes,
                    },
                    path,
                    role: *role,
                    sha256: digest(&bytes),
                });
            }
        }
        top_level.positive_exports = top_level
            .expanded_registry
            .positive_cases
            .iter()
            .map(|case| {
                let mut manifest = positive_artifact_layout(usize::from(case.index))
                    .unwrap()
                    .iter()
                    .zip(&case.artifacts)
                    .map(|((_, path), artifact)| ManifestEntry {
                        path: (*path).to_owned(),
                        length: artifact.byte_length.to_string(),
                        sha256: artifact.sha256.clone(),
                    })
                    .collect::<Vec<_>>();
                manifest.sort_by(|left, right| left.path.cmp(&right.path));
                crate::b4_materialization_set::B4AuthenticatedPositiveExportV1 {
                    case_index: case.index,
                    proof_output_manifest_jcs: canonical_json_bytes(
                        &serde_json::to_value(manifest).unwrap(),
                    )
                    .unwrap(),
                    raw_seal: role_bytes(B4PositiveArtifactRole::RawSeal, usize::from(case.index)),
                    auxiliary_artifacts: Vec::new(),
                }
            })
            .collect();
        populate_recursive_auxiliary_sources(&mut top_level);
        top_level
    }

    fn populate_recursive_auxiliary_sources(
        top_level: &mut crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1,
    ) {
        for index in 8..=10 {
            if !top_level.positive_exports[index]
                .auxiliary_artifacts
                .is_empty()
            {
                continue;
            }
            let mut manifest: Vec<ManifestEntry> = serde_json::from_slice(
                &top_level.positive_exports[index].proof_output_manifest_jcs,
            )
            .unwrap();
            for (position, path) in
                crate::b4_positive_gate::positive_auxiliary_artifact_paths(index)
                    .unwrap()
                    .iter()
                    .copied()
                    .enumerate()
            {
                let bytes = vec![
                    0xa0_u8.wrapping_add(u8::try_from(index * 8 + position).unwrap(),);
                    PROOF_BYTES
                ];
                let identity =
                    crate::b4_materialization_set::B4AuthenticatedPositiveAuxiliaryArtifactV1 {
                        path: path.to_owned(),
                        byte_length: bytes.len() as u64,
                        sha256: digest(&bytes),
                    };
                manifest.push(ManifestEntry {
                    path: identity.path.clone(),
                    length: identity.byte_length.to_string(),
                    sha256: identity.sha256.clone(),
                });
                top_level
                    .source_artifacts
                    .insert(identity.path.clone(), bytes);
                top_level.positive_exports[index]
                    .auxiliary_artifacts
                    .push(identity);
            }
            manifest.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
            top_level.positive_exports[index].proof_output_manifest_jcs =
                canonical_json_bytes(&serde_json::to_value(manifest).unwrap()).unwrap();
        }
    }

    pub(super) fn populate_global_reference_statement_sources()
    -> crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1 {
        let mut top_level = populate_positive_sources();
        populate_positive_input_sources(&mut top_level);

        let case_zero = &top_level.expanded_registry.positive_cases[0];
        let journal_path = case_zero
            .artifacts
            .iter()
            .find(|artifact| artifact.role == B4PositiveArtifactRole::Journal)
            .unwrap()
            .path
            .clone();
        let image_id_path = case_zero
            .artifacts
            .iter()
            .find(|artifact| artifact.role == B4PositiveArtifactRole::ImageId)
            .unwrap()
            .path
            .clone();
        let statement = top_level.source_artifacts[&journal_path].clone();
        let program_id: [u8; 32] = top_level.source_artifacts[&image_id_path]
            .as_slice()
            .try_into()
            .unwrap();
        let claim = ok_receipt_claim_digests(&program_id, &statement).unwrap();
        for index in 0..11 {
            replace_positive_artifact(
                &mut top_level,
                index,
                B4PositiveArtifactRole::Journal,
                statement.clone(),
            );
            replace_positive_artifact(
                &mut top_level,
                index,
                B4PositiveArtifactRole::ImageId,
                program_id.to_vec(),
            );
            replace_positive_artifact(
                &mut top_level,
                index,
                B4PositiveArtifactRole::ClaimDigest,
                claim.expected_claim.to_vec(),
            );
        }
        let profile_manifest_path = top_level.expanded_registry.profile.manifest.path.clone();
        let profile_manifest =
            StarkProfileManifestV1::decode(&top_level.source_artifacts[&profile_manifest_path])
                .unwrap();
        let join_control_id = profile_manifest
            .terminal_controls()
            .iter()
            .find(|control| {
                control.control_kind() == crate::constants::TERMINAL_CONTROL_KIND_JOIN
                    && control.parameter() == 0
            })
            .unwrap()
            .control_id();
        replace_positive_artifact(
            &mut top_level,
            8,
            B4PositiveArtifactRole::ControlId,
            join_control_id.to_vec(),
        );

        let (catalogue_jcs, sources) =
            crate::b4_terminal::synthetic_terminal_fixture_catalog_source().unwrap();
        let mut catalogue =
            crate::b4_terminal::Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(
                &catalogue_jcs,
            )
            .unwrap();
        catalogue.program_id = hex::encode(program_id);
        top_level.terminal_fixture_catalog_jcs = catalogue.to_canonical_jcs().unwrap();
        top_level.source_artifacts.extend(sources);
        top_level
    }

    pub(super) fn populate_v2_materialization_fixture_sources()
    -> crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1 {
        let mut top_level = populate_global_reference_statement_sources();
        let parsed_v1 = parse_positive_input_sources(&top_level.positive_input_set).unwrap();
        for (source_path, candidate_path) in [
            (
                parsed_v1.guest_elf.path.as_str(),
                "reproduction/schema/b4-corpus-v1.candidate/bindings/guest.elf",
            ),
            (
                parsed_v1.reference_statement_manifest().path.as_str(),
                "reproduction/schema/b4-corpus-v1.candidate/bindings/statement-manifest.json",
            ),
        ] {
            let bytes = top_level.source_artifacts[source_path].clone();
            if let Some(previous) = top_level
                .source_artifacts
                .insert(candidate_path.to_owned(), bytes.clone())
            {
                assert_eq!(previous, bytes);
            }
        }
        top_level.expanded_registry.bindings.guest.elf.path =
            "reproduction/schema/b4-corpus-v1.candidate/bindings/guest.elf".to_owned();
        top_level
            .expanded_registry
            .bindings
            .reference_statement_bundle
            .manifest
            .path = "reproduction/schema/b4-corpus-v1.candidate/bindings/statement-manifest.json"
            .to_owned();
        let verifier_cli_path = "contracts/eip0045-verifier-cli-contract.json";
        let verifier_cli_jcs = b"{}".to_vec();
        top_level
            .source_artifacts
            .insert(verifier_cli_path.to_owned(), verifier_cli_jcs.clone());
        let mut input =
            crate::canonical::validate_canonical_json_source(&top_level.positive_input_set)
                .unwrap();
        input["format"] = serde_json::json!("Eip0045B4PositiveInputSetV2");
        input["formatVersion"] = serde_json::json!(2);
        input["verifierCliContract"] =
            input_identity(verifier_cli_path, &verifier_cli_jcs, "rfc8785-jcs");
        input["validators"] = serde_json::json!([]);
        input["runnerProfiles"] = serde_json::json!([]);
        input["recursiveCalibrations"] = serde_json::json!([]);
        input["positiveCases"] = serde_json::json!([]);
        top_level.positive_input_set = canonical_json_bytes(&input).unwrap();
        top_level
    }

    #[cfg(feature = "recursive-ancestry")]
    fn referenced_source(
        top_level: &crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1,
        path: &str,
    ) -> RecursiveAncestryArtifactReference {
        recursive_ancestry_artifact_reference(
            path.to_owned(),
            top_level.source_artifacts[path].as_slice(),
        )
        .unwrap()
    }

    #[cfg(feature = "recursive-ancestry")]
    fn final_control_id(projection: &RecursiveAncestryProjection) -> Vec<u8> {
        let control_id = match &projection.steps.last().unwrap().terminal {
            RecursiveAncestryTerminal::Lift { control_id, .. }
            | RecursiveAncestryTerminal::Join { control_id }
            | RecursiveAncestryTerminal::Resolve { control_id } => control_id,
        };
        hex::decode(control_id).unwrap()
    }

    #[cfg(feature = "recursive-ancestry")]
    fn rebind_recursive_projection_sources(
        top_level: &crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1,
        projection: &mut RecursiveAncestryProjection,
    ) {
        projection.statement = referenced_source(top_level, &projection.statement.path);
        if let Some(assumption) = &mut projection.assumption_receipt {
            assumption.raw_seal = referenced_source(top_level, &assumption.raw_seal.path);
        }
        let final_index = projection.steps.len() - 1;
        for step in &mut projection.steps[..final_index] {
            step.raw_seal = referenced_source(top_level, &step.raw_seal.path);
        }
        let final_path = projection.steps[final_index].raw_seal.path.clone();
        projection.steps[final_index].raw_seal = recursive_ancestry_artifact_reference(
            final_path,
            &top_level.positive_exports[projection.family.positive_case_index()].raw_seal,
        )
        .unwrap();
    }

    #[cfg(feature = "recursive-ancestry")]
    pub(super) fn populate_valid_recursive_ancestry_sources()
    -> crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1 {
        let mut top_level = populate_global_reference_statement_sources();
        let statement_path = top_level.expanded_registry.positive_cases[0]
            .artifacts
            .iter()
            .find(|artifact| artifact.role == B4PositiveArtifactRole::Journal)
            .unwrap()
            .path
            .clone();
        let statement = top_level.source_artifacts[&statement_path].clone();

        for family in [
            RecursiveAncestryFamily::TerminalJoin,
            RecursiveAncestryFamily::TerminalResolve,
            RecursiveAncestryFamily::ResolveThenJoin,
        ] {
            let mut projection = match family {
                RecursiveAncestryFamily::TerminalJoin => {
                    crate::recursive_ancestry::tests::synthetic_terminal_join(&statement)
                }
                RecursiveAncestryFamily::TerminalResolve => {
                    crate::recursive_ancestry::tests::synthetic_terminal_resolve(&statement)
                }
                RecursiveAncestryFamily::ResolveThenJoin => {
                    crate::recursive_ancestry::tests::synthetic_resolve_then_join(&statement)
                }
            };
            rebind_recursive_projection_sources(&top_level, &mut projection);
            let case_index = family.positive_case_index();
            replace_positive_artifact(
                &mut top_level,
                case_index,
                B4PositiveArtifactRole::Ancestry,
                recursive_ancestry_to_jcs(&projection).unwrap(),
            );
            replace_positive_artifact(
                &mut top_level,
                case_index,
                B4PositiveArtifactRole::ClaimDigest,
                recursive_ancestry_claim_digest(&projection.steps.last().unwrap().claim)
                    .unwrap()
                    .to_vec(),
            );
            replace_positive_artifact(
                &mut top_level,
                case_index,
                B4PositiveArtifactRole::ControlId,
                final_control_id(&projection),
            );
        }
        top_level
    }

    #[cfg(feature = "recursive-ancestry")]
    #[allow(
        clippy::too_many_lines,
        reason = "the test-only reseed keeps the statement, registry, export, terminal, and recursive-family rebinding in one auditable closure"
    )]
    pub(super) fn reseed_descriptor_rooted_recursive_sources_from_case9(
        top_level: &mut crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1,
        proposition: &[u8],
    ) -> anyhow::Result<()> {
        let case9_artifacts = top_level
            .expanded_registry
            .positive_cases
            .get(9)
            .context("descriptor-rooted fixture omits positive case 9")?
            .artifacts
            .clone();
        let case9_export = top_level
            .positive_exports
            .get(9)
            .context("descriptor-rooted fixture omits positive export 9")?
            .clone();
        let case9_journal_path = case9_artifacts
            .iter()
            .find(|artifact| artifact.role == B4PositiveArtifactRole::Journal)
            .context("descriptor-rooted fixture case 9 omits its Journal")?
            .path
            .clone();
        let statement = top_level
            .source_artifacts
            .get(&case9_journal_path)
            .context("descriptor-rooted fixture case-9 Journal source is missing")?
            .clone();
        let parsed = parse_ergo_statement_v1(&statement)
            .context("descriptor-rooted fixture case-9 Journal is not ErgoStatementV1")?;
        anyhow::ensure!(
            parsed.encode()?.as_slice() == statement,
            "descriptor-rooted fixture case-9 Journal does not re-encode exactly"
        );
        let program_id = parsed.program_id();
        let claim = ok_receipt_claim_digests(&program_id, &statement)?;
        for (role, expected) in [
            (B4PositiveArtifactRole::ImageId, program_id.as_slice()),
            (
                B4PositiveArtifactRole::ClaimDigest,
                claim.expected_claim.as_slice(),
            ),
        ] {
            let path = &case9_artifacts
                .iter()
                .find(|artifact| artifact.role == role)
                .with_context(|| format!("descriptor-rooted fixture case 9 omits {role:?}"))?
                .path;
            anyhow::ensure!(
                top_level
                    .source_artifacts
                    .get(path)
                    .is_some_and(|bytes| bytes.as_slice() == expected),
                "descriptor-rooted fixture case-9 {role:?} differs from its retained Journal"
            );
        }

        let manifest = statement_bundle_manifest_jcs(
            &statement,
            parsed.chain_domain_id(),
            parsed.profile_id(),
            program_id,
            parsed.contract_id(),
            parsed.application_payload(),
            proposition,
            claim,
        );
        replace_statement_manifest_source(top_level, &manifest);
        let mut input =
            crate::canonical::validate_canonical_json_source(&top_level.positive_input_set)?;
        input["profile"]["profileId"] = serde_json::json!(hex::encode(parsed.profile_id()));
        input["guest"]["imageId"] = serde_json::json!(hex::encode(program_id));
        input["referenceStatement"]["contractId"] =
            serde_json::json!(hex::encode(parsed.contract_id()));
        input["referenceStatement"]["statementByteLength"] = serde_json::json!(statement.len());
        input["referenceStatement"]["statementSha256"] = serde_json::json!(digest(&statement));
        input["referenceStatement"]["chainDomainId"] =
            serde_json::json!(hex::encode(parsed.chain_domain_id()));
        input["referenceStatement"]["applicationPayloadByteLength"] =
            serde_json::json!(parsed.application_payload().len());
        input["referenceStatement"]["applicationPayloadSha256"] =
            serde_json::json!(digest(parsed.application_payload()));
        top_level.positive_input_set = canonical_json_bytes(&input)?;
        top_level.expanded_registry.profile.profile_id = hex::encode(parsed.profile_id());
        top_level.expanded_registry.bindings.guest.image_id = hex::encode(program_id);
        top_level
            .expanded_registry
            .bindings
            .reference_statement_bundle
            .contract_id = hex::encode(parsed.contract_id());
        top_level
            .expanded_registry
            .bindings
            .reference_statement_bundle
            .statement_sha256 = digest(&statement);
        replace_terminal_catalogue_program_id(top_level, program_id);

        for index in (0..11).filter(|index| *index != 9) {
            replace_positive_artifact(
                top_level,
                index,
                B4PositiveArtifactRole::Journal,
                statement.clone(),
            );
            replace_positive_artifact(
                top_level,
                index,
                B4PositiveArtifactRole::ImageId,
                program_id.to_vec(),
            );
            replace_positive_artifact(
                top_level,
                index,
                B4PositiveArtifactRole::ClaimDigest,
                claim.expected_claim.to_vec(),
            );
        }
        for family in [
            RecursiveAncestryFamily::TerminalJoin,
            RecursiveAncestryFamily::ResolveThenJoin,
        ] {
            let mut projection = match family {
                RecursiveAncestryFamily::TerminalJoin => {
                    crate::recursive_ancestry::tests::synthetic_terminal_join(&statement)
                }
                RecursiveAncestryFamily::ResolveThenJoin => {
                    crate::recursive_ancestry::tests::synthetic_resolve_then_join(&statement)
                }
                RecursiveAncestryFamily::TerminalResolve => unreachable!(),
            };
            rebind_recursive_projection_sources(top_level, &mut projection);
            let case_index = family.positive_case_index();
            replace_positive_artifact(
                top_level,
                case_index,
                B4PositiveArtifactRole::Ancestry,
                recursive_ancestry_to_jcs(&projection)?,
            );
            replace_positive_artifact(
                top_level,
                case_index,
                B4PositiveArtifactRole::ClaimDigest,
                recursive_ancestry_claim_digest(
                    &projection
                        .steps
                        .last()
                        .context("synthetic recursive projection has no final step")?
                        .claim,
                )?
                .to_vec(),
            );
            replace_positive_artifact(
                top_level,
                case_index,
                B4PositiveArtifactRole::ControlId,
                final_control_id(&projection),
            );
        }

        anyhow::ensure!(
            top_level.expanded_registry.positive_cases[9].artifacts == case9_artifacts
                && top_level.positive_exports[9].case_index == case9_export.case_index
                && top_level.positive_exports[9].proof_output_manifest_jcs
                    == case9_export.proof_output_manifest_jcs
                && top_level.positive_exports[9].raw_seal == case9_export.raw_seal
                && top_level.positive_exports[9].auxiliary_artifacts
                    == case9_export.auxiliary_artifacts,
            "descriptor-rooted fixture reseed changed fixed case-9 primary or export authority"
        );
        Ok(())
    }

    fn replace_reference_statement_input_scalar(
        top_level: &mut crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1,
        field: &str,
        value: serde_json::Value,
    ) {
        let mut input =
            crate::canonical::validate_canonical_json_source(&top_level.positive_input_set)
                .unwrap();
        input["referenceStatement"][field] = value;
        if field == "contractId" {
            top_level
                .expanded_registry
                .bindings
                .reference_statement_bundle
                .contract_id = input["referenceStatement"][field]
                .as_str()
                .unwrap()
                .to_owned();
        }
        if field == "statementSha256" {
            top_level
                .expanded_registry
                .bindings
                .reference_statement_bundle
                .statement_sha256 = input["referenceStatement"][field]
                .as_str()
                .unwrap()
                .to_owned();
        }
        top_level.positive_input_set = canonical_json_bytes(&input).unwrap();
    }

    fn replace_guest_elf_source(
        top_level: &mut crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1,
        guest_elf: &[u8],
    ) {
        let mut input =
            crate::canonical::validate_canonical_json_source(&top_level.positive_input_set)
                .unwrap();
        let upstream_path = input["guest"]["elf"]["path"].as_str().unwrap().to_owned();
        let candidate_path = top_level.expanded_registry.bindings.guest.elf.path.clone();
        assert_ne!(candidate_path, upstream_path);
        assert!(candidate_path.starts_with("reproduction/schema/b4-corpus-v1.candidate/"));
        top_level
            .source_artifacts
            .insert(upstream_path.clone(), guest_elf.to_vec());
        top_level
            .source_artifacts
            .insert(candidate_path, guest_elf.to_vec());
        input["guest"]["elf"] = input_identity(&upstream_path, guest_elf, "raw-bytes");
        top_level.positive_input_set = canonical_json_bytes(&input).unwrap();
        top_level.expanded_registry.bindings.guest.elf.byte_length = guest_elf.len() as u64;
        top_level.expanded_registry.bindings.guest.elf.sha256 = digest(guest_elf);
    }

    fn replace_terminal_catalogue_program_id(
        top_level: &mut crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1,
        program_id: [u8; 32],
    ) {
        let mut catalogue =
            crate::b4_terminal::Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(
                &top_level.terminal_fixture_catalog_jcs,
            )
            .unwrap();
        catalogue.program_id = hex::encode(program_id);
        top_level.terminal_fixture_catalog_jcs = catalogue.to_canonical_jcs().unwrap();
    }

    fn replace_statement_manifest_source(
        top_level: &mut crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1,
        manifest: &[u8],
    ) {
        let mut input =
            crate::canonical::validate_canonical_json_source(&top_level.positive_input_set)
                .unwrap();
        let upstream_path = input["referenceStatement"]["bundleManifest"]["path"]
            .as_str()
            .unwrap()
            .to_owned();
        let candidate_path = top_level
            .expanded_registry
            .bindings
            .reference_statement_bundle
            .manifest
            .path
            .clone();
        assert_ne!(candidate_path, upstream_path);
        assert!(candidate_path.starts_with("reproduction/schema/b4-corpus-v1.candidate/"));
        top_level
            .source_artifacts
            .insert(upstream_path.clone(), manifest.to_vec());
        top_level
            .source_artifacts
            .insert(candidate_path, manifest.to_vec());
        input["referenceStatement"]["bundleManifest"] =
            input_identity(&upstream_path, manifest, "rfc8785-jcs");
        top_level.positive_input_set = canonical_json_bytes(&input).unwrap();
        top_level
            .expanded_registry
            .bindings
            .reference_statement_bundle
            .manifest
            .byte_length = manifest.len() as u64;
        top_level
            .expanded_registry
            .bindings
            .reference_statement_bundle
            .manifest
            .sha256 = digest(manifest);
    }

    fn coherently_rewrite_declared_program(
        top_level: &mut crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1,
        program_id: [u8; 32],
    ) {
        let case_zero = &top_level.expanded_registry.positive_cases[0];
        let journal_path = case_zero
            .artifacts
            .iter()
            .find(|artifact| artifact.role == B4PositiveArtifactRole::Journal)
            .unwrap()
            .path
            .clone();
        let original = top_level.source_artifacts[&journal_path].clone();
        let parsed = parse_ergo_statement_v1(&original).unwrap();
        let statement = ErgoStatementV1::new(
            parsed.chain_domain_id(),
            parsed.profile_id(),
            program_id,
            parsed.contract_id(),
            parsed.application_payload(),
        )
        .unwrap()
        .encode()
        .unwrap();
        let claim = ok_receipt_claim_digests(&program_id, &statement).unwrap();
        let manifest = statement_bundle_manifest_jcs(
            &statement,
            parsed.chain_domain_id(),
            parsed.profile_id(),
            program_id,
            parsed.contract_id(),
            parsed.application_payload(),
            b"fixture proposition bytes",
            claim,
        );
        replace_statement_manifest_source(top_level, &manifest);

        let mut input =
            crate::canonical::validate_canonical_json_source(&top_level.positive_input_set)
                .unwrap();
        input["guest"]["imageId"] = serde_json::json!(hex::encode(program_id));
        input["referenceStatement"]["statementByteLength"] = serde_json::json!(statement.len());
        input["referenceStatement"]["statementSha256"] = serde_json::json!(digest(&statement));
        top_level.positive_input_set = canonical_json_bytes(&input).unwrap();
        top_level.expanded_registry.bindings.guest.image_id = hex::encode(program_id);
        top_level
            .expanded_registry
            .bindings
            .reference_statement_bundle
            .statement_sha256 = digest(&statement);

        for index in 0..11 {
            replace_positive_artifact(
                top_level,
                index,
                B4PositiveArtifactRole::Journal,
                statement.clone(),
            );
            replace_positive_artifact(
                top_level,
                index,
                B4PositiveArtifactRole::ImageId,
                program_id.to_vec(),
            );
            replace_positive_artifact(
                top_level,
                index,
                B4PositiveArtifactRole::ClaimDigest,
                claim.expected_claim.to_vec(),
            );
        }
        replace_terminal_catalogue_program_id(top_level, program_id);
    }

    #[test]
    fn authenticated_positive_views_cover_lift_and_all_recursive_families() {
        let top_level = populate_positive_sources();
        let resolver = super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();

        for (index, case_id) in [
            (0, "lift-po2-15"),
            (8, "terminal-join"),
            (9, "terminal-resolve-explicit-root"),
            (10, "resolve-zero-root-then-join"),
        ] {
            let view = resolver.positive_case(index, case_id).unwrap();
            assert_eq!(
                view.raw_seal(),
                role_bytes(B4PositiveArtifactRole::RawSeal, index)
            );
            assert_eq!(
                view.artifact(B4PositiveArtifactRole::Journal).unwrap(),
                role_bytes(B4PositiveArtifactRole::Journal, index)
            );
        }
    }

    #[test]
    fn authenticated_positive_views_accept_full_recursive_manifest_custody() {
        let mut top_level = populate_positive_sources();
        populate_recursive_auxiliary_sources(&mut top_level);
        for (index, expected_count) in [(8, 10), (9, 10), (10, 12)] {
            assert_eq!(
                top_level.expanded_registry.positive_cases[index]
                    .artifacts
                    .len(),
                8
            );
            let manifest: ProofOutputManifest = serde_json::from_slice(
                &top_level.positive_exports[index].proof_output_manifest_jcs,
            )
            .unwrap();
            assert_eq!(manifest.len(), expected_count);
        }

        let resolver = super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();
        for (index, case_id) in [
            (8, "terminal-join"),
            (9, "terminal-resolve-explicit-root"),
            (10, "resolve-zero-root-then-join"),
        ] {
            resolver.positive_case(index, case_id).unwrap();
        }
    }

    #[cfg(feature = "recursive-ancestry")]
    #[test]
    fn typed_recursive_source_views_bind_all_three_positive_families() {
        let top_level = populate_valid_recursive_ancestry_sources();
        let resolver = super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();

        for family in [
            RecursiveAncestryFamily::TerminalJoin,
            RecursiveAncestryFamily::TerminalResolve,
            RecursiveAncestryFamily::ResolveThenJoin,
        ] {
            let view = resolver.recursive_ancestry_source(family).unwrap();
            assert_eq!(view.family(), family);
            assert_eq!(view.projection().family, family);
            assert_eq!(view.projection().case_id, family.case_id());
            assert_eq!(
                view.final_raw_seal(),
                top_level.positive_exports[family.positive_case_index()].raw_seal
            );
            assert_eq!(view.auxiliary_seals().len(), family.auxiliary_count());
            let encoded = view.encoded_auxiliary_map().unwrap();
            let decoded =
                crate::b4_recursive_auxiliary_map::decode_recursive_auxiliary_map(&encoded, family)
                    .unwrap();
            assert_eq!(decoded.len(), family.auxiliary_count());
        }
    }

    #[cfg(feature = "recursive-ancestry")]
    #[test]
    fn descriptor_rooted_reseed_closes_manifest_unanimity_and_all_recursive_families() {
        let mut top_level = populate_valid_recursive_ancestry_sources();
        let case9_journal_path = top_level.expanded_registry.positive_cases[9]
            .artifacts
            .iter()
            .find(|artifact| artifact.role == B4PositiveArtifactRole::Journal)
            .unwrap()
            .path
            .clone();
        let statement = top_level.source_artifacts[&case9_journal_path].clone();
        replace_statement_manifest_source(&mut top_level, b"{}");
        replace_positive_artifact(
            &mut top_level,
            0,
            B4PositiveArtifactRole::Journal,
            b"drifted-test-journal".to_vec(),
        );

        reseed_descriptor_rooted_recursive_sources_from_case9(
            &mut top_level,
            b"fixture proposition bytes",
        )
        .unwrap();

        let resolver = super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();
        let input = resolver.positive_input().unwrap();
        crate::b4_statement_bundle_manifest::StatementBundleManifestV1::from_canonical_jcs(
            input.reference_statement_manifest(),
        )
        .unwrap();
        assert_eq!(
            resolver
                .global_reference_statement()
                .unwrap()
                .statement_bytes(),
            statement
        );
        for index in 0..11 {
            let case_id = crate::b4_materialization_set::compiled_positive_case_id(index).unwrap();
            assert_eq!(
                resolver
                    .positive_case(index, &case_id)
                    .unwrap()
                    .artifact(B4PositiveArtifactRole::Journal)
                    .unwrap(),
                statement
            );
        }
        for family in [
            RecursiveAncestryFamily::TerminalJoin,
            RecursiveAncestryFamily::TerminalResolve,
            RecursiveAncestryFamily::ResolveThenJoin,
        ] {
            resolver.recursive_ancestry_source(family).unwrap();
        }
    }

    #[cfg(feature = "recursive-ancestry")]
    #[test]
    fn case9_conditional_accessor_exposes_step_zero_and_never_the_final_seal() {
        let top_level = populate_valid_recursive_ancestry_sources();
        let resolver = super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();
        let general = resolver
            .recursive_ancestry_source(RecursiveAncestryFamily::TerminalResolve)
            .unwrap();
        let step_zero_path = general.projection().steps[0].raw_seal.path.clone();
        let assumption_path = general
            .projection()
            .assumption_receipt
            .as_ref()
            .unwrap()
            .raw_seal
            .path
            .clone();
        let assumption_seal = general.auxiliary_seals().get(&assumption_path).unwrap();
        let restricted = resolver.case9_conditional_receipt_source().unwrap();

        assert_eq!(restricted.conditional_raw_seal_path(), step_zero_path);
        assert_eq!(
            restricted.conditional_raw_seal(),
            general.auxiliary_seals().get(&step_zero_path).unwrap()
        );
        assert_ne!(restricted.conditional_raw_seal(), assumption_seal);
        assert_ne!(restricted.conditional_raw_seal(), general.final_raw_seal());
        assert_eq!(
            restricted.profile_manifest_context(),
            general.profile_manifest_context()
        );
        assert_eq!(restricted.statement_context(), general.statement());
    }

    #[cfg(feature = "recursive-ancestry")]
    #[test]
    fn typed_recursive_source_view_rejects_family_profile_program_claim_and_control_drift() {
        let assert_rejected = |mutate: fn(
            &mut crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1,
        )| {
            let mut top_level = populate_valid_recursive_ancestry_sources();
            mutate(&mut top_level);
            let resolver =
                super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();
            assert!(
                resolver
                    .recursive_ancestry_source(RecursiveAncestryFamily::TerminalJoin)
                    .is_err()
            );
        };

        assert_rejected(|top_level| {
            let case9_ancestry_path = top_level.expanded_registry.positive_cases[9]
                .artifacts
                .iter()
                .find(|artifact| artifact.role == B4PositiveArtifactRole::Ancestry)
                .unwrap()
                .path
                .clone();
            let case9_ancestry = top_level.source_artifacts[&case9_ancestry_path].clone();
            replace_positive_artifact(
                top_level,
                8,
                B4PositiveArtifactRole::Ancestry,
                case9_ancestry,
            );
        });
        assert_rejected(|top_level| {
            let ancestry_path = top_level.expanded_registry.positive_cases[8]
                .artifacts
                .iter()
                .find(|artifact| artifact.role == B4PositiveArtifactRole::Ancestry)
                .unwrap()
                .path
                .clone();
            let mut projection: RecursiveAncestryProjection =
                serde_json::from_slice(&top_level.source_artifacts[&ancestry_path]).unwrap();
            projection.profile_id = "ff".repeat(32);
            replace_positive_artifact(
                top_level,
                8,
                B4PositiveArtifactRole::Ancestry,
                recursive_ancestry_to_jcs(&projection).unwrap(),
            );
        });
        assert_rejected(|top_level| {
            replace_positive_artifact(
                top_level,
                8,
                B4PositiveArtifactRole::ImageId,
                vec![0x81; 32],
            );
        });
        assert_rejected(|top_level| {
            replace_positive_artifact(
                top_level,
                8,
                B4PositiveArtifactRole::ClaimDigest,
                vec![0x82; 32],
            );
        });
        assert_rejected(|top_level| {
            replace_positive_artifact(
                top_level,
                8,
                B4PositiveArtifactRole::ControlId,
                vec![0x83; 32],
            );
        });
    }

    fn replace_recursive_export_manifest(
        top_level: &mut crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1,
        case_index: usize,
        manifest: ProofOutputManifest,
    ) {
        top_level.positive_exports[case_index].proof_output_manifest_jcs =
            canonical_json_bytes(&serde_json::to_value(manifest).unwrap()).unwrap();
    }

    fn assert_recursive_fixture_resolver_rejection(
        mutate: impl FnOnce(
            &mut crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1,
        ),
        expected_error: &str,
    ) {
        let mut top_level = populate_positive_sources();
        populate_recursive_auxiliary_sources(&mut top_level);
        mutate(&mut top_level);
        let Err(error) = super::B4FixtureSourceResolverV1::from_authenticated(&top_level) else {
            panic!("recursive auxiliary drift unexpectedly authenticated");
        };
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(expected_error),
            "expected {expected_error:?}, got {rendered:?}"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn authenticated_positive_views_reject_recursive_auxiliary_identity_manifest_and_content_drift()
    {
        let case_8_first =
            crate::b4_positive_gate::positive_auxiliary_artifact_paths(8).unwrap()[0];
        let case_8_second =
            crate::b4_positive_gate::positive_auxiliary_artifact_paths(8).unwrap()[1];
        let case_9_first =
            crate::b4_positive_gate::positive_auxiliary_artifact_paths(9).unwrap()[0];

        assert_recursive_fixture_resolver_rejection(
            |top_level| {
                top_level.positive_exports[8].auxiliary_artifacts.pop();
            },
            "auxiliary artifact cardinality",
        );
        assert_recursive_fixture_resolver_rejection(
            |top_level| {
                let extra = top_level.positive_exports[8].auxiliary_artifacts[0].clone();
                top_level.positive_exports[8]
                    .auxiliary_artifacts
                    .push(extra);
            },
            "auxiliary artifact cardinality",
        );
        assert_recursive_fixture_resolver_rejection(
            |top_level| {
                top_level.positive_exports[8].auxiliary_artifacts.swap(0, 1);
            },
            "auxiliary artifact path/order drift",
        );
        assert_recursive_fixture_resolver_rejection(
            |top_level| {
                let duplicate = top_level.positive_exports[8].auxiliary_artifacts[0].clone();
                top_level.positive_exports[8].auxiliary_artifacts[1] = duplicate;
            },
            "auxiliary artifact path/order drift",
        );
        assert_recursive_fixture_resolver_rejection(
            |top_level| {
                top_level.positive_exports[8].auxiliary_artifacts[0].path = case_9_first.to_owned();
            },
            "auxiliary artifact path/order drift",
        );
        assert_recursive_fixture_resolver_rejection(
            |top_level| {
                top_level.positive_exports[8].auxiliary_artifacts[0].path =
                    "wrong/recursive-auxiliary.bin".to_owned();
            },
            "auxiliary artifact path/order drift",
        );
        assert_recursive_fixture_resolver_rejection(
            |top_level| {
                top_level.positive_exports[8].auxiliary_artifacts[0].byte_length -= 1;
            },
            "auxiliary manifest path, length, or digest drift",
        );
        assert_recursive_fixture_resolver_rejection(
            |top_level| {
                top_level.positive_exports[8].auxiliary_artifacts[0].sha256 = "00".repeat(32);
            },
            "auxiliary manifest path, length, or digest drift",
        );
        assert_recursive_fixture_resolver_rejection(
            |top_level| {
                top_level.source_artifacts.remove(case_8_first);
            },
            "missing authenticated recursive auxiliary source",
        );
        assert_recursive_fixture_resolver_rejection(
            |top_level| {
                top_level.source_artifacts.get_mut(case_8_first).unwrap()[0] ^= 0xff;
            },
            "auxiliary source path, length, digest, or content drift",
        );
        assert_recursive_fixture_resolver_rejection(
            |top_level| {
                let left = top_level.source_artifacts[case_8_second].clone();
                let right = top_level.source_artifacts[case_9_first].clone();
                top_level
                    .source_artifacts
                    .insert(case_8_second.to_owned(), right);
                top_level
                    .source_artifacts
                    .insert(case_9_first.to_owned(), left);
            },
            "auxiliary source path, length, digest, or content drift",
        );
        assert_recursive_fixture_resolver_rejection(
            |top_level| {
                let mut manifest: ProofOutputManifest = serde_json::from_slice(
                    &top_level.positive_exports[8].proof_output_manifest_jcs,
                )
                .unwrap();
                manifest.retain(|entry| entry.path != case_8_first);
                replace_recursive_export_manifest(top_level, 8, manifest);
            },
            "wrong artifact cardinality",
        );
        assert_recursive_fixture_resolver_rejection(
            |top_level| {
                let mut manifest: ProofOutputManifest = serde_json::from_slice(
                    &top_level.positive_exports[8].proof_output_manifest_jcs,
                )
                .unwrap();
                manifest.push(ManifestEntry {
                    path: "unexpected-recursive-export-member.bin".to_owned(),
                    length: PROOF_BYTES.to_string(),
                    sha256: "00".repeat(32),
                });
                manifest.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
                replace_recursive_export_manifest(top_level, 8, manifest);
            },
            "wrong artifact cardinality",
        );
        assert_recursive_fixture_resolver_rejection(
            |top_level| {
                let mut manifest: ProofOutputManifest = serde_json::from_slice(
                    &top_level.positive_exports[8].proof_output_manifest_jcs,
                )
                .unwrap();
                manifest.swap(0, 1);
                replace_recursive_export_manifest(top_level, 8, manifest);
            },
            "invalid inventory",
        );
        assert_recursive_fixture_resolver_rejection(
            |top_level| {
                let mut manifest: ProofOutputManifest = serde_json::from_slice(
                    &top_level.positive_exports[8].proof_output_manifest_jcs,
                )
                .unwrap();
                let duplicate_path = manifest[0].path.clone();
                manifest[1].path = duplicate_path;
                manifest.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
                replace_recursive_export_manifest(top_level, 8, manifest);
            },
            "invalid inventory",
        );
        assert_recursive_fixture_resolver_rejection(
            |top_level| {
                let mut manifest: ProofOutputManifest = serde_json::from_slice(
                    &top_level.positive_exports[8].proof_output_manifest_jcs,
                )
                .unwrap();
                manifest
                    .iter_mut()
                    .find(|entry| entry.path == case_8_first)
                    .unwrap()
                    .path = case_9_first.to_owned();
                manifest.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
                replace_recursive_export_manifest(top_level, 8, manifest);
            },
            "auxiliary manifest path, length, or digest drift",
        );
        assert_recursive_fixture_resolver_rejection(
            |top_level| {
                let identity = &top_level.positive_exports[8].auxiliary_artifacts[0];
                top_level.expanded_registry.positive_cases[8]
                    .artifacts
                    .push(B4PositiveArtifact {
                        byte_length: identity.byte_length,
                        encoding: B4ArtifactEncoding::RawBytes,
                        path: identity.path.clone(),
                        role: B4PositiveArtifactRole::RawSeal,
                        sha256: identity.sha256.clone(),
                    });
            },
            "positive case artifact cardinality",
        );
    }

    #[test]
    fn authenticated_positive_view_exposes_the_exact_proof_output_manifest_jcs() {
        let top_level = populate_positive_sources();
        let resolver = super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();

        let view = resolver.positive_case(0, "lift-po2-15").unwrap();
        assert_eq!(
            view.proof_output_manifest_jcs(),
            top_level.positive_exports[0].proof_output_manifest_jcs
        );
    }

    #[test]
    fn authenticated_positive_input_view_reauthenticates_profile_and_guest_sources() {
        let mut top_level = populate_positive_sources();
        let (input_jcs, profile_id, image_id) = populate_positive_input_sources(&mut top_level);
        let parsed_input = parse_positive_input_sources(&top_level.positive_input_set).unwrap();
        let guest_candidate_path = top_level.expanded_registry.bindings.guest.elf.path.clone();
        let statement_candidate_path = top_level
            .expanded_registry
            .bindings
            .reference_statement_bundle
            .manifest
            .path
            .clone();
        let resolver = super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();

        let input = resolver.positive_input().unwrap();
        assert_eq!(input.positive_input_set(), input_jcs);
        assert_eq!(input.profile_id(), profile_id);
        assert_eq!(input.guest_image_id(), image_id);
        assert_eq!(
            input
                .initial_profile_manifest()
                .unwrap()
                .profile_id()
                .unwrap(),
            hex::decode(profile_id).unwrap().as_slice()
        );
        assert_eq!(
            input.profile_algorithm(),
            include_bytes!("../../profiles/risc0-v3-succinct/algorithm.txt")
        );
        assert_eq!(
            input.profile_constants(),
            include_bytes!("../../profiles/risc0-v3-succinct/constants.bin")
        );
        let (expected_elf, expected_image_id) = valid_program_fixture();
        assert_eq!(input.guest_elf(), expected_elf);
        assert_eq!(input.guest_image_id(), hex::encode(expected_image_id),);
        assert!(std::ptr::eq(
            input.guest_elf(),
            top_level.source_artifacts[&guest_candidate_path].as_slice()
        ));
        assert!(!std::ptr::eq(
            input.guest_elf(),
            top_level.source_artifacts[&parsed_input.guest_elf.path].as_slice()
        ));
        assert!(std::ptr::eq(
            input.reference_statement_manifest(),
            top_level.source_artifacts[&statement_candidate_path].as_slice()
        ));
        assert!(!std::ptr::eq(
            input.reference_statement_manifest(),
            top_level.source_artifacts[&parsed_input.reference_statement_manifest().path]
                .as_slice()
        ));
        crate::b4_statement_bundle_manifest::StatementBundleManifestV1::from_canonical_jcs(
            input.reference_statement_manifest(),
        )
        .unwrap();
        assert_eq!(input.reference_contract_id(), [0x22; 32]);
        assert_eq!(input.reference_chain_domain_id(), [0x10; 32]);
        assert_eq!(
            input.reference_application_payload_byte_length(),
            b"fixture-payload".len() as u64
        );
        assert_eq!(
            input.reference_application_payload_sha256(),
            Sha256::digest(b"fixture-payload").as_slice()
        );
        let journal = resolver
            .positive_case(0, "lift-po2-15")
            .unwrap()
            .artifact(B4PositiveArtifactRole::Journal)
            .unwrap();
        let expected_statement_sha256: [u8; 32] = Sha256::digest(journal).into();
        assert_eq!(
            input.reference_statement_sha256(),
            expected_statement_sha256
        );
        assert_eq!(
            input.reference_statement_byte_length(),
            journal.len() as u64
        );
    }

    #[test]
    fn authenticated_positive_input_view_rejects_missing_and_drifted_quarantine_copies() {
        for role in ["guest", "reference-statement"] {
            for mutation in ["missing", "byte-drift"] {
                let mut top_level = populate_positive_sources();
                populate_positive_input_sources(&mut top_level);
                let candidate_path = match role {
                    "guest" => top_level.expanded_registry.bindings.guest.elf.path.clone(),
                    "reference-statement" => top_level
                        .expanded_registry
                        .bindings
                        .reference_statement_bundle
                        .manifest
                        .path
                        .clone(),
                    _ => unreachable!(),
                };
                match mutation {
                    "missing" => {
                        top_level.source_artifacts.remove(&candidate_path).unwrap();
                    }
                    "byte-drift" => {
                        top_level.source_artifacts.get_mut(&candidate_path).unwrap()[0] ^= 1;
                    }
                    _ => unreachable!(),
                }
                let resolver =
                    super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();
                let message = format!(
                    "{:#}",
                    resolver
                        .positive_input()
                        .err()
                        .expect("V1 quarantine-copy mutant unexpectedly resolved")
                );
                let expected = if mutation == "missing" {
                    "lacks candidate"
                } else {
                    "authenticated candidate"
                };
                assert!(
                    message.contains(expected),
                    "{role} {mutation} failed outside candidate-copy authentication: {message}"
                );
            }
        }
    }

    #[test]
    fn case_zero_journal_cross_binds_profile_program_contract_and_exact_sha256() {
        let mut top_level = populate_positive_sources();
        populate_positive_input_sources(&mut top_level);
        let resolver = super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();

        let bound = resolver.case_zero_reference_statement().unwrap();
        assert_eq!(bound.statement_bytes(), bound.statement().encode().unwrap());
        assert_eq!(bound.statement().profile_id(), bound.profile_id());
        assert_eq!(bound.statement().program_id(), bound.program_id());
        assert_eq!(bound.statement().contract_id(), [0x22; 32]);
        assert_eq!(bound.statement().application_payload(), b"fixture-payload");
    }

    #[test]
    fn global_reference_statement_has_no_case_selector() {
        let top_level = populate_global_reference_statement_sources();
        let resolver = super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();

        let global = resolver.global_reference_statement().unwrap();
        let parsed = parse_ergo_statement_v1(global.statement_bytes()).unwrap();
        assert_eq!(global.statement(), parsed);
        assert_eq!(
            global.claim_digests(),
            ok_receipt_claim_digests(&parsed.program_id(), global.statement_bytes()).unwrap()
        );
        for case in &top_level.expanded_registry.positive_cases {
            let journal_path = &case
                .artifacts
                .iter()
                .find(|artifact| artifact.role == B4PositiveArtifactRole::Journal)
                .unwrap()
                .path;
            assert_eq!(
                top_level.source_artifacts[journal_path],
                global.statement_bytes()
            );
        }
    }

    fn changed_global_statement(
        top_level: &crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1,
    ) -> (Vec<u8>, ReceiptClaimDigests) {
        let journal_path = &top_level.expanded_registry.positive_cases[0]
            .artifacts
            .iter()
            .find(|artifact| artifact.role == B4PositiveArtifactRole::Journal)
            .unwrap()
            .path;
        let parsed = parse_ergo_statement_v1(&top_level.source_artifacts[journal_path]).unwrap();
        let mut payload = parsed.application_payload().to_vec();
        payload[0] ^= 1;
        let changed = ErgoStatementV1::new(
            parsed.chain_domain_id(),
            parsed.profile_id(),
            parsed.program_id(),
            parsed.contract_id(),
            &payload,
        )
        .unwrap()
        .encode()
        .unwrap();
        let claim = ok_receipt_claim_digests(&parsed.program_id(), &changed).unwrap();
        (changed, claim)
    }

    #[test]
    fn global_reference_statement_rejects_a_coherent_single_case_rewrite_at_every_ordinal() {
        for index in 0..11 {
            let mut top_level = populate_global_reference_statement_sources();
            let (changed, claim) = changed_global_statement(&top_level);
            replace_positive_artifact(
                &mut top_level,
                index,
                B4PositiveArtifactRole::Journal,
                changed,
            );
            replace_positive_artifact(
                &mut top_level,
                index,
                B4PositiveArtifactRole::ClaimDigest,
                claim.expected_claim.to_vec(),
            );

            let resolver =
                super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();
            let Err(error) = resolver.global_reference_statement() else {
                panic!("accepted a coherently rewritten Journal and ClaimDigest at case {index}");
            };
            assert!(
                format!("{error:#}").contains("not byte-identical"),
                "single-case rewrite at case {index} did not isolate physical unanimity: {error:#}"
            );
        }
    }

    #[test]
    fn global_reference_statement_requires_full_unanimity_for_every_partial_split() {
        for canonical_count in 1..11 {
            let mut top_level = populate_global_reference_statement_sources();
            let (changed, claim) = changed_global_statement(&top_level);
            for index in canonical_count..11 {
                replace_positive_artifact(
                    &mut top_level,
                    index,
                    B4PositiveArtifactRole::Journal,
                    changed.clone(),
                );
                replace_positive_artifact(
                    &mut top_level,
                    index,
                    B4PositiveArtifactRole::ClaimDigest,
                    claim.expected_claim.to_vec(),
                );
            }

            let resolver =
                super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();
            let Err(error) = resolver.global_reference_statement() else {
                panic!("accepted a {canonical_count}/11 partial Journal agreement");
            };
            assert!(
                format!("{error:#}").contains("not byte-identical"),
                "{canonical_count}/11 split did not isolate physical unanimity: {error:#}"
            );
        }
    }

    #[test]
    fn global_reference_statement_rejects_isolated_image_and_claim_artifact_drifts() {
        for (role, bytes) in [
            (B4PositiveArtifactRole::ImageId, vec![0x91; 32]),
            (B4PositiveArtifactRole::ClaimDigest, vec![0x92; 32]),
        ] {
            let mut top_level = populate_global_reference_statement_sources();
            replace_positive_artifact(&mut top_level, 7, role, bytes);
            let resolver =
                super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();
            assert!(
                resolver.global_reference_statement().is_err(),
                "accepted isolated {} drift",
                role_name(role)
            );
        }
    }

    #[test]
    fn global_reference_statement_rejects_manifest_physical_byte_drift() {
        let mut top_level = populate_global_reference_statement_sources();
        let input = crate::canonical::validate_canonical_json_source(&top_level.positive_input_set)
            .unwrap();
        let path = input["referenceStatement"]["bundleManifest"]["path"]
            .as_str()
            .unwrap()
            .to_owned();
        top_level.source_artifacts.get_mut(&path).unwrap()[0] ^= 1;
        let resolver = super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();

        assert!(resolver.global_reference_statement().is_err());
    }

    #[test]
    fn global_reference_statement_rejects_each_isolated_positive_input_scalar_drift() {
        for field in [
            "chainDomainId",
            "contractId",
            "statementByteLength",
            "statementSha256",
            "applicationPayloadByteLength",
            "applicationPayloadSha256",
        ] {
            let mut top_level = populate_global_reference_statement_sources();
            let value = match field {
                "chainDomainId" | "contractId" | "statementSha256" | "applicationPayloadSha256" => {
                    serde_json::json!("99".repeat(32))
                }
                "statementByteLength" | "applicationPayloadByteLength" => {
                    serde_json::json!(160)
                }
                _ => unreachable!(),
            };
            replace_reference_statement_input_scalar(&mut top_level, field, value);
            let resolver =
                super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();
            assert!(
                resolver.global_reference_statement().is_err(),
                "accepted isolated positive-input {field} drift"
            );
        }
    }

    #[test]
    fn global_reference_statement_recomputes_program_id_instead_of_trusting_coordinated_metadata() {
        let mut top_level = populate_global_reference_statement_sources();
        coherently_rewrite_declared_program(&mut top_level, [0xa3; 32]);
        let resolver = super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();

        let Err(error) = resolver.global_reference_statement() else {
            panic!("accepted coordinated declared-program drift against the guest ELF");
        };
        assert!(
            format!("{error:#}").contains("differs from the authenticated guest ELF"),
            "coordinated declared-program rewrite did not isolate ELF recomputation: {error:#}"
        );
    }

    #[test]
    fn global_reference_statement_rejects_a_coherently_rebound_malformed_guest_elf() {
        let mut top_level = populate_global_reference_statement_sources();
        replace_guest_elf_source(&mut top_level, b"not-a-risc-zero-program");
        let resolver = super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();

        let Err(error) = resolver.global_reference_statement() else {
            panic!("accepted a coherently rebound malformed guest ELF");
        };
        assert!(
            format!("{error:#}")
                .contains("authenticated guest ELF cannot produce a RISC Zero image ID"),
            "malformed guest ELF failed outside image-ID recomputation: {error:#}"
        );
    }

    #[test]
    fn global_reference_statement_rejects_terminal_catalogue_program_drift() {
        let mut top_level = populate_global_reference_statement_sources();
        replace_terminal_catalogue_program_id(&mut top_level, [0xa4; 32]);
        let resolver = super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();

        assert!(resolver.global_reference_statement().is_err());
    }

    #[test]
    fn case_zero_journal_cross_binding_rejects_isolated_profile_program_contract_and_sha_drifts() {
        for drift in ["profile", "program", "contract", "statement-sha256"] {
            let mut top_level = populate_positive_sources();
            populate_positive_input_sources(&mut top_level);
            let journal_path = top_level.expanded_registry.positive_cases[0]
                .artifacts
                .iter()
                .find(|artifact| artifact.role == B4PositiveArtifactRole::Journal)
                .unwrap()
                .path
                .clone();
            let original = top_level.source_artifacts[&journal_path].clone();
            let parsed = parse_ergo_statement_v1(&original).unwrap();

            if drift == "statement-sha256" {
                replace_reference_statement_sha256(&mut top_level, &"44".repeat(32));
            } else {
                let mut profile_id = parsed.profile_id();
                let mut program_id = parsed.program_id();
                let mut contract_id = parsed.contract_id();
                match drift {
                    "profile" => profile_id[0] ^= 1,
                    "program" => program_id[0] ^= 1,
                    "contract" => contract_id[0] ^= 1,
                    _ => unreachable!(),
                }
                let changed = ErgoStatementV1::new(
                    parsed.chain_domain_id(),
                    profile_id,
                    program_id,
                    contract_id,
                    parsed.application_payload(),
                )
                .unwrap()
                .encode()
                .unwrap();
                let changed_sha256 = digest(&changed);
                replace_positive_artifact(
                    &mut top_level,
                    0,
                    B4PositiveArtifactRole::Journal,
                    changed,
                );
                replace_reference_statement_sha256(&mut top_level, &changed_sha256);
            }

            let resolver =
                super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();
            assert!(
                resolver.case_zero_reference_statement().is_err(),
                "accepted isolated {drift} drift"
            );
        }
    }

    #[test]
    fn authenticated_positive_input_view_rejects_byte_drift() {
        let mut top_level = populate_positive_sources();
        populate_positive_input_sources(&mut top_level);
        let manifest_path = top_level.expanded_registry.profile.manifest.path.clone();
        top_level.source_artifacts.get_mut(&manifest_path).unwrap()[0] ^= 1;
        let resolver = super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();

        assert!(resolver.positive_input().is_err());
    }

    #[test]
    fn authenticated_positive_input_view_rejects_reference_manifest_registry_drift() {
        let mut top_level = populate_positive_sources();
        populate_positive_input_sources(&mut top_level);
        top_level
            .expanded_registry
            .bindings
            .reference_statement_bundle
            .manifest
            .sha256 = "aa".repeat(32);
        let resolver = super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();

        assert!(resolver.positive_input().is_err());
    }

    #[test]
    fn authenticated_positive_input_view_rejects_coordinated_arbitrary_profile_id() {
        let mut top_level = populate_positive_sources();
        populate_positive_input_sources(&mut top_level);
        let arbitrary_profile_id = "44".repeat(32);
        let mut input =
            crate::canonical::validate_canonical_json_source(&top_level.positive_input_set)
                .unwrap();
        input["profile"]["profileId"] = serde_json::json!(arbitrary_profile_id.clone());
        top_level.positive_input_set = canonical_json_bytes(&input).unwrap();
        top_level.expanded_registry.profile.profile_id = arbitrary_profile_id;
        let resolver = super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();

        assert!(resolver.positive_input().is_err());
    }

    #[test]
    fn authenticated_positive_input_view_rejects_coherent_manifest_b2_envelope_rewrite() {
        let mut top_level = populate_positive_sources();
        populate_positive_input_sources(&mut top_level);
        let manifest_path = top_level.expanded_registry.profile.manifest.path.clone();
        let original =
            StarkProfileManifestV1::decode(&top_level.source_artifacts[&manifest_path]).unwrap();
        let rewritten = StarkProfileManifestV1::new(
            original.exact_proof_bytes(),
            original.max_application_payload_bytes(),
            original.outer_po2(),
            original.inner_control_root(),
            *original.terminal_controls(),
            original.algorithm_artifact(),
            ProfileArtifactReference::from_artifact(
                original.binary_data_artifact().artifact_kind(),
                b"coherent-but-unselected-b2-envelope",
            )
            .unwrap(),
        )
        .unwrap();
        let rewritten_manifest = rewritten.encode().unwrap().to_vec();
        let rewritten_profile_id = hex::encode(rewritten.profile_id().unwrap());
        top_level
            .source_artifacts
            .insert(manifest_path.clone(), rewritten_manifest.clone());
        let mut input =
            crate::canonical::validate_canonical_json_source(&top_level.positive_input_set)
                .unwrap();
        input["profile"]["profileId"] = serde_json::json!(rewritten_profile_id.clone());
        input["profile"]["manifest"] =
            input_identity(&manifest_path, &rewritten_manifest, "raw-bytes");
        top_level.positive_input_set = canonical_json_bytes(&input).unwrap();
        top_level.expanded_registry.profile.profile_id = rewritten_profile_id;
        top_level.expanded_registry.profile.manifest.byte_length = rewritten_manifest.len() as u64;
        top_level.expanded_registry.profile.manifest.sha256 = digest(&rewritten_manifest);
        let resolver = super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();

        assert!(resolver.positive_input().is_err());
    }

    #[test]
    fn terminal_fixture_resolver_reauthenticates_a_valid_synthetic_catalogue() {
        let mut top_level = populate_positive_sources();
        let (catalogue_jcs, sources) =
            crate::b4_terminal::synthetic_terminal_fixture_catalog_source().unwrap();
        top_level.terminal_fixture_catalog_jcs = catalogue_jcs;
        top_level.source_artifacts.extend(sources);
        let resolver = super::B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();

        let fixture = resolver.terminal_fixture(0, "lift-po2-14").unwrap();
        assert_eq!(fixture.fixture_index(), 0);
        assert_eq!(fixture.fixture_id(), "lift-po2-14");
        assert_eq!(fixture.raw_seal().len(), PROOF_BYTES);
        assert_eq!(fixture.receipt_oracle(), [0]);
    }

    #[test]
    fn terminal_fixture_resolver_rejects_wrong_selector_missing_artifact_and_byte_drift() {
        let (catalogue_jcs, sources) =
            crate::b4_terminal::synthetic_terminal_fixture_catalog_source().unwrap();

        let mut wrong_selector = populate_positive_sources();
        wrong_selector.terminal_fixture_catalog_jcs = catalogue_jcs.clone();
        wrong_selector.source_artifacts.extend(sources.clone());
        let resolver =
            super::B4FixtureSourceResolverV1::from_authenticated(&wrong_selector).unwrap();
        assert!(resolver.terminal_fixture(0, "lift-po2-15").is_err());

        let raw_path = crate::b4_terminal::terminal_fixture_raw_seal_path("lift-po2-14").unwrap();
        let mut missing_artifact = populate_positive_sources();
        missing_artifact.terminal_fixture_catalog_jcs = catalogue_jcs.clone();
        missing_artifact.source_artifacts.extend(sources.clone());
        missing_artifact.source_artifacts.remove(&raw_path);
        let resolver =
            super::B4FixtureSourceResolverV1::from_authenticated(&missing_artifact).unwrap();
        assert!(resolver.terminal_fixture(0, "lift-po2-14").is_err());

        let mut byte_drift = populate_positive_sources();
        byte_drift.terminal_fixture_catalog_jcs = catalogue_jcs;
        byte_drift.source_artifacts.extend(sources);
        byte_drift.source_artifacts.get_mut(&raw_path).unwrap()[0] ^= 1;
        let resolver = super::B4FixtureSourceResolverV1::from_authenticated(&byte_drift).unwrap();
        assert!(resolver.terminal_fixture(0, "lift-po2-14").is_err());
    }

    #[test]
    fn authenticated_positive_views_reject_missing_role_inventory() {
        let mut top_level = populate_positive_sources();
        top_level.expanded_registry.positive_cases[0]
            .artifacts
            .pop();
        assert!(super::B4FixtureSourceResolverV1::from_authenticated(&top_level).is_err());
    }

    #[test]
    fn authenticated_positive_views_reject_channel_identity_and_order_drift() {
        let mut duplicate = populate_positive_sources();
        duplicate.expanded_registry.positive_cases[0].artifacts[1].role =
            B4PositiveArtifactRole::ClaimDigest;
        assert!(super::B4FixtureSourceResolverV1::from_authenticated(&duplicate).is_err());

        let mut reordered_exports = populate_positive_sources();
        reordered_exports.positive_exports.swap(0, 1);
        assert!(super::B4FixtureSourceResolverV1::from_authenticated(&reordered_exports).is_err());

        let mut raw_source = populate_positive_sources();
        let raw = &raw_source.expanded_registry.positive_cases[0].artifacts[5];
        raw_source.source_artifacts.insert(
            raw.path.clone(),
            role_bytes(B4PositiveArtifactRole::RawSeal, 0),
        );
        assert!(super::B4FixtureSourceResolverV1::from_authenticated(&raw_source).is_err());

        let mut digest_drift = populate_positive_sources();
        digest_drift.expanded_registry.positive_cases[8].artifacts[0].sha256 = "0".repeat(64);
        assert!(super::B4FixtureSourceResolverV1::from_authenticated(&digest_drift).is_err());

        let mut cross_case = populate_positive_sources();
        let source_path = cross_case.expanded_registry.positive_cases[0].artifacts[0]
            .path
            .clone();
        let target_path = cross_case.expanded_registry.positive_cases[1].artifacts[0]
            .path
            .clone();
        let source = cross_case.source_artifacts[&source_path].clone();
        cross_case.source_artifacts.insert(target_path, source);
        assert!(super::B4FixtureSourceResolverV1::from_authenticated(&cross_case).is_err());
    }

    #[test]
    fn authenticated_positive_views_reject_same_digest_cross_case_path_substitution() {
        let mut top_level = populate_positive_sources();
        let source = top_level.expanded_registry.positive_cases[0].artifacts[0].clone();
        let target = &mut top_level.expanded_registry.positive_cases[1].artifacts[0];
        top_level
            .source_artifacts
            .insert(source.path.clone(), role_bytes(source.role, 0));
        target.path = source.path;
        target.byte_length = source.byte_length;
        target.sha256 = source.sha256.clone();
        let manifest = top_level.positive_exports[1]
            .proof_output_manifest_jcs
            .clone();
        let mut entries: Vec<ManifestEntry> = serde_json::from_value(
            crate::canonical::validate_canonical_json_source(&manifest).unwrap(),
        )
        .unwrap();
        entries[0].length = source.byte_length.to_string();
        entries[0].sha256 = source.sha256;
        top_level.positive_exports[1].proof_output_manifest_jcs =
            canonical_json_bytes(&serde_json::to_value(entries).unwrap()).unwrap();

        assert!(super::B4FixtureSourceResolverV1::from_authenticated(&top_level).is_err());
    }

    #[test]
    fn authenticated_positive_views_reject_raw_seal_from_another_case_even_when_bytes_match() {
        let mut top_level = populate_positive_sources();
        let raw_position = top_level.expanded_registry.positive_cases[0]
            .artifacts
            .iter()
            .position(|artifact| artifact.role == B4PositiveArtifactRole::RawSeal)
            .unwrap();
        let case_one_raw = top_level.expanded_registry.positive_cases[1].artifacts[raw_position]
            .path
            .clone();
        top_level.positive_exports[1].raw_seal = top_level.positive_exports[0].raw_seal.clone();
        top_level.expanded_registry.positive_cases[1].artifacts[raw_position].sha256 =
            top_level.expanded_registry.positive_cases[0].artifacts[raw_position]
                .sha256
                .clone();
        top_level.expanded_registry.positive_cases[0].artifacts[raw_position].path = case_one_raw;

        assert!(super::B4FixtureSourceResolverV1::from_authenticated(&top_level).is_err());
    }

    #[test]
    fn v2_postproof_reparse_recomputes_each_document_nested_source_and_selected_export() {
        let exact = V2PostproofFixture::exact();
        let resolver = exact.resolver().unwrap();
        let authenticated = exact.authenticate_case_zero(&resolver).unwrap();
        assert_eq!(authenticated.case_index(), 0);
        assert_eq!(authenticated.primary_measurements().len(), 7);
        assert!(authenticated.auxiliary_measurements().is_empty());
        assert_eq!(
            resolver.postproof().input_set_measurement.byte_length,
            exact.input_jcs.len() as u64
        );
        assert_eq!(
            resolver.postproof().generation_set_measurement.byte_length,
            exact.generation_jcs.len() as u64
        );
        assert_eq!(
            resolver.postproof().proof_generator_measurement.byte_length,
            exact.generator.bytes.len() as u64
        );

        let mut input_v1 = exact.clone();
        input_v1.mutate_input(|input| {
            input["format"] = serde_json::json!("Eip0045B4PositiveInputSetV1");
        });
        assert!(input_v1.resolver().is_err());

        let mut generation_v1 = exact.clone();
        generation_v1.mutate_generation(|generation| {
            generation["format"] = serde_json::json!("Eip0045B4PositiveGenerationSetV1");
        });
        assert!(generation_v1.resolver().is_err());

        let mut generator_path = exact.clone();
        generator_path.mutate_input(|input| {
            input["proofGenerator"]["artifact"]["path"] =
                serde_json::json!("generator/substituted-eip0045-candidate-generator");
        });
        assert!(generator_path.resolver().is_err());

        let mut generator_length = exact.clone();
        generator_length.mutate_input(|input| {
            let length = input["proofGenerator"]["artifact"]["byteLength"]
                .as_u64()
                .unwrap();
            input["proofGenerator"]["artifact"]["byteLength"] = serde_json::json!(length + 1);
        });
        assert!(generator_length.resolver().is_err());

        let mut generator_digest = exact.clone();
        generator_digest.mutate_input(|input| {
            input["proofGenerator"]["artifact"]["sha256"] = serde_json::json!("00".repeat(32));
        });
        assert!(generator_digest.resolver().is_err());

        let mut noncanonical_nested_jcs = exact.clone();
        let cli_path = "contracts/eip0045-verifier-cli-contract.json";
        let cli = noncanonical_nested_jcs
            .nested
            .iter_mut()
            .find(|source| source.path == cli_path)
            .unwrap();
        cli.bytes = b"{} ".to_vec();
        noncanonical_nested_jcs.mutate_input(|input| {
            input["verifierCliContract"]["byteLength"] = serde_json::json!(3);
            input["verifierCliContract"]["sha256"] = serde_json::json!(digest(b"{} "));
        });
        assert!(noncanonical_nested_jcs.resolver().is_err());

        let mut role = exact.clone();
        role.mutate_generation(|generation| {
            generation["cases"][0]["artifacts"][0]["role"] = serde_json::json!("control-id");
        });
        let role_resolver = role.resolver().unwrap();
        assert!(role.authenticate_case_zero(&role_resolver).is_err());

        let mut artifact_length = exact.clone();
        artifact_length.mutate_generation(|generation| {
            let length = generation["cases"][0]["artifacts"][0]["byteLength"]
                .as_u64()
                .unwrap();
            generation["cases"][0]["artifacts"][0]["byteLength"] = serde_json::json!(length + 1);
        });
        let length_resolver = artifact_length.resolver().unwrap();
        assert!(
            artifact_length
                .authenticate_case_zero(&length_resolver)
                .is_err()
        );

        let mut artifact_digest = exact.clone();
        artifact_digest.mutate_generation(|generation| {
            generation["cases"][0]["artifacts"][0]["sha256"] = serde_json::json!("00".repeat(32));
        });
        let digest_resolver = artifact_digest.resolver().unwrap();
        assert!(
            artifact_digest
                .authenticate_case_zero(&digest_resolver)
                .is_err()
        );

        let mut manifest_jcs = exact;
        manifest_jcs.proof_output_manifest_jcs.push(b' ');
        let manifest_resolver = manifest_jcs.resolver().unwrap();
        assert!(
            manifest_jcs
                .authenticate_case_zero(&manifest_resolver)
                .is_err()
        );
    }

    #[test]
    fn materialization_v2_plan_accessor_is_sourced_only_from_its_authenticated_wrapper() {
        let source = include_str!("b4_fixture_sources.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let accessor = production
            .split("pub(crate) fn negative_plan_jcs(&self)")
            .nth(1)
            .unwrap()
            .split("pub(crate) fn positive_case(")
            .next()
            .unwrap();
        assert!(accessor.contains("&self.top_level.storage().negative_plan"));
        assert!(!accessor.contains("B4FixtureSourceResolverV1"));
        assert!(!accessor.contains("from_authenticated("));
        assert_eq!(
            production
                .matches("pub(crate) fn negative_plan_jcs(&self)")
                .count(),
            1
        );
    }
}
