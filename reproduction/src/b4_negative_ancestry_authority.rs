// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Derive-first authority for the closed B4 negative-ancestry witness catalogue.
//!
//! Candidate catalogue bytes never select a verifier, claim, recipe, path, or
//! dispatch branch. The source authority first reauthenticates the exact
//! upstream authorities and source-only byte closure before witness production;
//! finalization then derives the catalogue from seven receipts accepted by the
//! one compiled stock verifier.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail, ensure};
use risc0_binfmt::compute_image_id;
use risc0_zkvm::ReceiptClaim;
use sha2::{Digest as _, Sha256};

use crate::{
    b4_campaign_contract::{
        B4CampaignPrecommitAuthorityV1, B4ContractArtifactEncodingV1, B4ContractArtifactIdentityV1,
        B4PositiveGenerationAuthorityV2,
    },
    b4_materialization_set::{
        B4AuthenticatedPositiveInputSourcesV1, B4AuthenticatedPositiveInputSourcesV2,
        RECURSIVE_POSITIVE_ARTIFACT_LAYOUT, parse_positive_input_sources,
        parse_positive_input_sources_v2,
    },
    b4_negative_ancestry_source::{
        B4AuthenticatedCase9AssumptionSourceV1, B4AuthenticatedNegativeAncestryProducerSourceV1,
        B4AuthenticatedNegativeAncestryProducerSourceV2,
    },
    b4_negative_ancestry_witness::{
        B4_NEGATIVE_ANCESTRY_ALTERNATE_GUEST_ELF_PATH, B4_NEGATIVE_ANCESTRY_BINDING_COUNT,
        B4_NEGATIVE_ANCESTRY_PROFILE_MANIFEST_PATH, B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_FORMAT,
        B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_VERSION, B4NegativeAncestryWitnessCatalogStageV1,
        B4NegativeAncestryWitnessEntryV1, B4NegativeAncestryWitnessIdV1,
        Eip0045B4NegativeAncestryWitnessCatalogV1, compiled_negative_ancestry_witness_layout,
        expected_terminal,
    },
    b4_plan::Eip0045B4NegativePlanV1,
    b4_positive_gate::B4PositiveGenerationAuthorityV1,
    b4_positive_source_auth::{
        B4PositiveCaseSourceV1, B4PositiveCaseSourceV2, B4PositiveGenerationDocumentV1,
        B4PositiveGenerationDocumentV2, B4PositiveSourceBytesV1, B4PositiveSourceBytesV2,
        authenticate_external_identity, authenticate_external_identity_v2,
        authenticate_positive_case_source, authenticate_positive_case_source_v2,
        bind_external_path, merge_prior_paths,
    },
    b4_recursive_auxiliary_paths::compiled_positive_auxiliary_artifact_paths,
    constants::{DIGEST_BYTES, MANIFEST_BYTES, PROOF_BYTES, RISC0_INNER_CONTROL_ROOT_HEX},
    constants_artifact,
    ergo_statement::{ErgoStatementFieldV1, ErgoStatementV1, parse_ergo_statement_v1},
    profile_algorithm::authenticate_profile_algorithm,
    profile_manifest::{ProfileArtifacts, validate_profile_package_v1},
    receipt_oracle_codec::{RECEIPT_ORACLE_CODEC_V1, RECEIPT_ORACLE_MAX_BYTES},
    receipt_oracle_replay::{
        CompiledStockSuccinctReplayV1, StockReceiptReplayError, VerifiedStockSuccinctReceiptV1,
    },
    recursive_ancestry::{
        RecursiveAncestryClaim, RecursiveAncestryFamily, RecursiveAncestryInventoryEntry,
        RecursiveAncestryProjection, RecursiveAncestrySourceInventory, RecursiveAncestryTerminal,
        derive_empty_assumption_ok_recursive_ancestry_claim,
        derive_recursive_ancestry_claim_with_inventory, parse_recursive_ancestry_jcs,
        project_verified_receipt_claim, recursive_ancestry_claim_digest,
        recursive_ancestry_revealed_head_witness, recursive_ancestry_to_jcs,
        validate_canonical_recursive_ancestry, validate_recursive_ancestry_artifacts,
        validate_recursive_ancestry_structure,
    },
};

#[cfg(test)]
use serde_json::Value;

#[cfg(test)]
use crate::{
    b4::B4PositiveArtifactRole,
    b4_materialization_set::{
        positive_artifact_encoding, positive_artifact_role_name, validate_positive_artifact_length,
    },
    canonical::canonical_json_bytes,
    manifest::ProofOutputManifest,
};

const CASE_9_INDEX: usize = 9;
const MAX_ALTERNATE_GUEST_ELF_BYTES: usize = 4 * 1024 * 1024;

/// Exact externally held bytes and their independently selected physical path.
#[derive(Clone, Copy, Debug)]
pub struct B4NegativeAncestryExternalBytesV1<'a> {
    /// Safe repository/archive-relative physical path.
    pub path: &'a str,
    /// Exact bytes read independently from that path.
    pub bytes: &'a [u8],
}

/// Fixed four-artifact verifier profile package.
#[derive(Clone, Copy, Debug)]
pub struct B4NegativeAncestryProfilePackageExternalV1<'a> {
    /// Exact binary profile manifest.
    pub profile_manifest: B4NegativeAncestryExternalBytesV1<'a>,
    /// Exact B1 algorithm artifact.
    pub profile_algorithm: B4NegativeAncestryExternalBytesV1<'a>,
    /// Exact B2 verifier-data artifact.
    pub profile_constants: B4NegativeAncestryExternalBytesV1<'a>,
    /// Exact consumer guest ELF.
    pub consumer_guest_elf: B4NegativeAncestryExternalBytesV1<'a>,
}

/// Exact positive case-9 export in its two physical source orders.
#[derive(Clone, Copy, Debug)]
pub struct B4NegativeAncestryCase9ExportV1<'a> {
    /// Exact pathless proof-output-manifest JCS.
    pub proof_output_manifest_jcs: &'a [u8],
    /// Eight primary artifacts in compiled generation-role order.
    pub primary_artifacts: &'a [B4NegativeAncestryExternalBytesV1<'a>],
    /// Assumption receipt then conditional step-00 raw seal.
    pub auxiliary_artifacts: &'a [B4NegativeAncestryExternalBytesV1<'a>],
}

/// V2-only external bytes used after the central V2 semantic gate.
#[derive(Clone, Copy, Debug)]
pub struct B4NegativeAncestryExternalBytesV2<'a> {
    /// Safe repository/archive-relative physical path.
    pub path: &'a str,
    /// Exact bytes independently read from that path.
    pub bytes: &'a [u8],
}

/// Fixed V2 profile-package sources selected by the reparsed positive input.
#[derive(Clone, Copy, Debug)]
pub struct B4NegativeAncestryProfilePackageExternalV2<'a> {
    /// Exact binary profile manifest.
    pub profile_manifest: B4NegativeAncestryExternalBytesV2<'a>,
    /// Exact B1 algorithm artifact.
    pub profile_algorithm: B4NegativeAncestryExternalBytesV2<'a>,
    /// Exact B2 verifier-data artifact.
    pub profile_constants: B4NegativeAncestryExternalBytesV2<'a>,
    /// Exact consumer guest ELF.
    pub consumer_guest_elf: B4NegativeAncestryExternalBytesV2<'a>,
}

/// Exact V2 positive case-9 export in its two physical source orders.
#[derive(Clone, Copy, Debug)]
pub struct B4NegativeAncestryCase9ExportV2<'a> {
    /// Exact pathless proof-output-manifest JCS.
    pub proof_output_manifest_jcs: &'a [u8],
    /// Eight primary artifacts in compiled generation-role order.
    pub primary_artifacts: &'a [B4NegativeAncestryExternalBytesV2<'a>],
    /// Assumption receipt then conditional step-00 raw seal.
    pub auxiliary_artifacts: &'a [B4NegativeAncestryExternalBytesV2<'a>],
}

/// Independently supplied source-only closure for the affine V2 ancestry gate.
#[derive(Clone, Copy, Debug)]
pub struct B4NegativeAncestrySourceClosureV2<'a> {
    /// Exact pathless campaign-precommit JCS.
    pub campaign_precommit_jcs: &'a [u8],
    /// Exact V2 positive input-set JCS and physical path.
    pub positive_input_set: B4NegativeAncestryExternalBytesV2<'a>,
    /// Exact V2 positive generation-set JCS and physical path.
    pub positive_generation_set: B4NegativeAncestryExternalBytesV2<'a>,
    /// Exact fixed verifier profile package.
    pub profile_package: B4NegativeAncestryProfilePackageExternalV2<'a>,
    /// Exact V2 positive terminal-resolve case-9 export.
    pub case9: B4NegativeAncestryCase9ExportV2<'a>,
    /// Exact alternate guest ELF used only by the compiled alternate-program rows.
    pub alternate_guest_elf: B4NegativeAncestryExternalBytesV2<'a>,
}

/// One externally measured negative receipt binding.
#[derive(Clone, Copy, Debug)]
pub struct B4NegativeAncestryWitnessExternalEntryV1<'a> {
    /// Exact expanded-corpus row.
    pub expanded_row: u16,
    /// Exact create-only raw seal.
    pub raw_seal: B4NegativeAncestryExternalBytesV1<'a>,
    /// Exact direct receipt oracle.
    pub receipt_oracle: B4NegativeAncestryExternalBytesV1<'a>,
}

/// Complete external byte closure accepted by the derive-first constructor.
#[derive(Clone, Copy, Debug)]
pub struct B4NegativeAncestryExternalClosureV1<'a> {
    /// Exact pathless campaign-precommit JCS.
    pub campaign_precommit_jcs: &'a [u8],
    /// Exact positive input-set JCS and physical path.
    pub positive_input_set: B4NegativeAncestryExternalBytesV1<'a>,
    /// Exact positive generation-set JCS and physical path.
    pub positive_generation_set: B4NegativeAncestryExternalBytesV1<'a>,
    /// Exact fixed verifier profile package.
    pub profile_package: B4NegativeAncestryProfilePackageExternalV1<'a>,
    /// Exact positive terminal-resolve export.
    pub case9: B4NegativeAncestryCase9ExportV1<'a>,
    /// Exact alternate guest ELF used only by rows 147 and 151.
    pub alternate_guest_elf: B4NegativeAncestryExternalBytesV1<'a>,
    /// Eleven row bindings in compiled expanded-row order.
    pub entries: &'a [B4NegativeAncestryWitnessExternalEntryV1<'a>],
}

impl<'a> B4NegativeAncestryExternalClosureV1<'a> {
    /// Project the exact source-only closure required before witness production.
    #[must_use]
    pub const fn source_closure(self) -> B4NegativeAncestrySourceClosureV1<'a> {
        B4NegativeAncestrySourceClosureV1 {
            campaign_precommit_jcs: self.campaign_precommit_jcs,
            positive_input_set: self.positive_input_set,
            positive_generation_set: self.positive_generation_set,
            profile_package: self.profile_package,
            case9: self.case9,
            alternate_guest_elf: self.alternate_guest_elf,
        }
    }
}

/// Exact authenticated inputs required before any negative witness exists.
#[derive(Clone, Copy, Debug)]
pub struct B4NegativeAncestrySourceClosureV1<'a> {
    /// Exact pathless campaign-precommit JCS.
    pub campaign_precommit_jcs: &'a [u8],
    /// Exact positive input-set JCS and physical path.
    pub positive_input_set: B4NegativeAncestryExternalBytesV1<'a>,
    /// Exact positive generation-set JCS and physical path.
    pub positive_generation_set: B4NegativeAncestryExternalBytesV1<'a>,
    /// Exact fixed verifier profile package.
    pub profile_package: B4NegativeAncestryProfilePackageExternalV1<'a>,
    /// Exact positive terminal-resolve export.
    pub case9: B4NegativeAncestryCase9ExportV1<'a>,
    /// Exact alternate guest ELF used only by rows 147 and 151.
    pub alternate_guest_elf: B4NegativeAncestryExternalBytesV1<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct B4NegativeAncestryPriorCommitmentsV1 {
    campaign_precommit: PathlessByteIdentityV1,
    positive_input_set: PathlessByteIdentityV1,
    positive_generation_set: PathlessByteIdentityV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct B4NegativeAncestryPriorCommitmentsV2 {
    campaign_precommit: PathlessByteIdentityV1,
    positive_input_set: B4ContractArtifactIdentityV1,
    positive_generation_set: B4ContractArtifactIdentityV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PathlessByteIdentityV1 {
    byte_length: u64,
    sha256: [u8; DIGEST_BYTES],
}

#[derive(Clone, Debug)]
struct B4NegativeAncestryPriorAuthorityViewV1 {
    campaign_precommit_jcs: Vec<u8>,
    positive_input_set: B4ContractArtifactIdentityV1,
    positive_generation_set: B4ContractArtifactIdentityV1,
    negative_plan: B4ContractArtifactIdentityV1,
    case9: crate::b4_positive_gate::B4PositiveGenerationCaseAuthorityV1,
    provenance_paths: BTreeSet<String>,
    positive_provenance_sha256: BTreeMap<String, String>,
}

impl B4NegativeAncestryPriorAuthorityViewV1 {
    fn from_authorities(
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV1,
    ) -> Result<Self> {
        ensure!(
            campaign.precommit().input_set == *positive.input_set(),
            "prior authorities bind different positive input sets"
        );
        let campaign_precommit_jcs = campaign.to_canonical_precommit_jcs()?;
        ensure!(
            crate::b4_campaign_contract::Eip0045B4CampaignPrecommitV1::from_canonical_jcs(
                &campaign_precommit_jcs,
            )? == *campaign.precommit(),
            "campaign precommit authority does not round-trip to its exact JCS"
        );

        let verifier = campaign.verifier_authority();
        let negative_plan_jcs = verifier.negative_plan_jcs().to_vec();
        ensure!(
            B4ContractArtifactIdentityV1::from_bytes(
                &verifier.contract().negative_plan.path,
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &negative_plan_jcs,
            )? == verifier.contract().negative_plan,
            "verifier authority negative-plan bytes differ from its retained identity"
        );
        ensure!(
            Eip0045B4NegativePlanV1::from_canonical_jcs(&negative_plan_jcs)?
                == Eip0045B4NegativePlanV1::canonical()?,
            "verifier authority negative plan differs from the compiled closed plan"
        );

        let case9 = positive
            .cases()
            .get(CASE_9_INDEX)
            .context("positive generation authority has no case 9")?;
        ensure!(
            usize::from(case9.case_index()) == CASE_9_INDEX,
            "positive generation authority case-9 index drifted"
        );

        let mut provenance_paths = BTreeSet::new();
        merge_prior_paths(&mut provenance_paths, campaign.artifact_paths())?;
        merge_prior_paths(&mut provenance_paths, positive.provenance_paths())?;
        ensure!(
            provenance_paths.contains(&positive.input_set().path)
                && provenance_paths.contains(&positive.generation_set().path)
                && provenance_paths.contains(&verifier.contract().negative_plan.path),
            "prior path closure omits a directly retained authority document"
        );
        let positive_provenance_sha256 = positive.provenance_sha256().clone();
        ensure!(
            positive
                .provenance_paths()
                .iter()
                .eq(positive_provenance_sha256.keys()),
            "positive authority provenance paths and digests differ"
        );

        Ok(Self {
            campaign_precommit_jcs,
            positive_input_set: positive.input_set().clone(),
            positive_generation_set: positive.generation_set().clone(),
            negative_plan: verifier.contract().negative_plan.clone(),
            case9: *case9,
            provenance_paths,
            positive_provenance_sha256,
        })
    }
}

#[derive(Debug)]
struct B4NegativeAncestryPriorAuthorityViewV2 {
    campaign_precommit_jcs: Vec<u8>,
    positive_input_set: B4ContractArtifactIdentityV1,
    positive_generation_set: B4ContractArtifactIdentityV1,
    negative_plan: B4ContractArtifactIdentityV1,
    provenance_paths: BTreeSet<String>,
    positive_provenance_sha256: BTreeMap<String, [u8; DIGEST_BYTES]>,
}

impl B4NegativeAncestryPriorAuthorityViewV2 {
    fn from_authorities(
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV2,
    ) -> Result<Self> {
        ensure!(
            campaign.precommit().input_set == *positive.positive_input_set_identity(),
            "campaign and V2 positive authorities bind different positive input sets"
        );
        let campaign_precommit_jcs = campaign.to_canonical_precommit_jcs()?;
        ensure!(
            crate::b4_campaign_contract::Eip0045B4CampaignPrecommitV1::from_canonical_jcs(
                &campaign_precommit_jcs,
            )? == *campaign.precommit(),
            "campaign precommit authority does not round-trip before V2 ancestry"
        );

        let verifier = campaign.verifier_authority();
        let negative_plan_jcs = verifier.negative_plan_jcs();
        ensure!(
            B4ContractArtifactIdentityV1::from_bytes(
                &verifier.contract().negative_plan.path,
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                negative_plan_jcs,
            )? == verifier.contract().negative_plan,
            "V2 ancestry campaign negative-plan bytes differ from the retained identity"
        );
        ensure!(
            Eip0045B4NegativePlanV1::from_canonical_jcs(negative_plan_jcs)?
                == Eip0045B4NegativePlanV1::canonical()?,
            "V2 ancestry campaign negative plan differs from the compiled closed plan"
        );

        let mut provenance_paths = BTreeSet::new();
        merge_prior_paths(&mut provenance_paths, campaign.artifact_paths())?;
        merge_prior_paths(&mut provenance_paths, positive.provenance_paths())?;
        ensure!(
            provenance_paths.contains(&positive.positive_input_set_identity().path)
                && provenance_paths.contains(&positive.positive_generation_set_identity().path)
                && provenance_paths.contains(&verifier.contract().negative_plan.path),
            "V2 ancestry prior path closure omits a retained authority document"
        );
        let positive_provenance_sha256 = positive.provenance_sha256().clone();
        ensure!(
            positive
                .provenance_paths()
                .iter()
                .eq(positive_provenance_sha256.keys()),
            "V2 positive authority provenance paths and digests differ"
        );

        Ok(Self {
            campaign_precommit_jcs,
            positive_input_set: positive.positive_input_set_identity().clone(),
            positive_generation_set: positive.positive_generation_set_identity().clone(),
            negative_plan: verifier.contract().negative_plan.clone(),
            provenance_paths,
            positive_provenance_sha256,
        })
    }
}

#[derive(Clone, Debug)]
struct AuthenticatedProfileV1 {
    profile_manifest: B4ContractArtifactIdentityV1,
    consumer_program_id: [u8; DIGEST_BYTES],
    alternate_guest_elf: B4ContractArtifactIdentityV1,
    alternate_program_id: [u8; DIGEST_BYTES],
    profile_id: [u8; DIGEST_BYTES],
}

#[derive(Clone, Debug)]
struct AuthenticatedSourceClosureV1 {
    prior_commitments: B4NegativeAncestryPriorCommitmentsV1,
    profile: AuthenticatedProfileV1,
    case9: AuthenticatedCase9V1,
    provenance_paths: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct AuthenticatedProfileV2 {
    profile_manifest: B4ContractArtifactIdentityV1,
    consumer_program_id: [u8; DIGEST_BYTES],
    alternate_guest_elf: B4ContractArtifactIdentityV1,
    alternate_program_id: [u8; DIGEST_BYTES],
    profile_id: [u8; DIGEST_BYTES],
}

#[derive(Clone, Debug)]
struct B4RetainedPositiveCase9CustodyV2 {
    case_id: String,
    proof_output_manifest: crate::b4_positive_gate::FileMeasurement,
    primary_measurements: Vec<crate::b4_positive_gate::FileMeasurement>,
    auxiliary_measurements: Vec<crate::b4_positive_gate::FileMeasurement>,
}

#[derive(Clone, Debug)]
struct AuthenticatedSourceClosureV2 {
    prior_commitments: B4NegativeAncestryPriorCommitmentsV2,
    profile: AuthenticatedProfileV2,
    case9: AuthenticatedCase9V2,
    case9_custody: B4RetainedPositiveCase9CustodyV2,
    prior_provenance_paths: BTreeSet<String>,
    positive_provenance_sha256: BTreeMap<String, [u8; DIGEST_BYTES]>,
    provenance_paths: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct AuthenticatedCase9V1 {
    projection: RecursiveAncestryProjection,
    statement: Vec<u8>,
    final_raw_seal: Vec<u8>,
    assumption_raw_seal: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct AuthenticatedCase9V2 {
    pub(crate) projection: RecursiveAncestryProjection,
    pub(crate) statement: Vec<u8>,
    pub(crate) final_raw_seal: Vec<u8>,
    pub(crate) assumption_raw_seal: Vec<u8>,
}

#[derive(Clone, Debug)]
struct B4VerifiedDirectAncestryReceiptV1 {
    claim: RecursiveAncestryClaim,
    terminal: RecursiveAncestryTerminal,
    control_root: String,
}

trait B4NegativeAncestryWitnessReplayV1 {
    fn replay(
        &self,
        raw_seal: &[u8],
        receipt_oracle: &[u8],
    ) -> Result<B4VerifiedDirectAncestryReceiptV1>;
}

struct CompiledNegativeAncestryWitnessReplayV1 {
    stock: CompiledStockSuccinctReplayV1,
}

impl CompiledNegativeAncestryWitnessReplayV1 {
    fn from_compiled_profile() -> Result<Self> {
        Ok(Self {
            stock: CompiledStockSuccinctReplayV1::from_compiled_profile()
                .map_err(stock_replay_error)?,
        })
    }
}

impl B4NegativeAncestryWitnessReplayV1 for CompiledNegativeAncestryWitnessReplayV1 {
    fn replay(
        &self,
        raw_seal: &[u8],
        receipt_oracle: &[u8],
    ) -> Result<B4VerifiedDirectAncestryReceiptV1> {
        let decoded = self
            .stock
            .decode_direct(receipt_oracle)
            .map_err(stock_replay_error)?;
        let verified = self
            .stock
            .verify(decoded, raw_seal)
            .map_err(stock_replay_error)?;
        project_verified_direct_receipt(&verified)
    }
}

#[derive(Clone, Debug)]
#[allow(
    dead_code,
    reason = "exact row bytes are retained for the separately approved materialization tranche"
)]
pub(crate) struct B4RetainedNegativeAncestryWitnessEntryV1 {
    pub(crate) expanded_row: u16,
    pub(crate) raw_seal: Vec<u8>,
    pub(crate) receipt_oracle: Vec<u8>,
}

pub(crate) struct B4NegativeAncestryProducerSourceProjectionV1<'a> {
    pub(crate) case9_recursive_oracle_borsh: &'a [u8],
    pub(crate) case9_assumption_raw_seal: &'a [u8],
    pub(crate) case9_final_raw_seal: &'a [u8],
    pub(crate) canonical_statement: &'a [u8],
    pub(crate) consumer_guest_elf: &'a [u8],
    pub(crate) consumer_program_id: [u8; DIGEST_BYTES],
    pub(crate) alternate_guest_elf: &'a [u8],
    pub(crate) alternate_program_id: [u8; DIGEST_BYTES],
}

pub(crate) struct B4NegativeAncestryProducerSourceProjectionV2<'a> {
    pub(crate) case9_recursive_oracle_borsh: &'a [u8],
    pub(crate) case9_assumption_raw_seal: &'a [u8],
    pub(crate) case9_final_raw_seal: &'a [u8],
    pub(crate) canonical_statement: &'a [u8],
    pub(crate) consumer_guest_elf: &'a [u8],
    pub(crate) consumer_program_id: [u8; DIGEST_BYTES],
    pub(crate) alternate_guest_elf: &'a [u8],
    pub(crate) alternate_program_id: [u8; DIGEST_BYTES],
    pub(crate) prior_provenance_paths: &'a BTreeSet<String>,
    pub(crate) positive_provenance_sha256: &'a BTreeMap<String, [u8; DIGEST_BYTES]>,
}

/// Opaque authority for the complete pre-generation negative-ancestry source.
///
/// The type is intentionally non-serializable and has no public data
/// constructor. It authenticates all source bytes before any negative witness
/// exists, exposes only borrowed producer views, and finalizes the catalogue
/// only from a separately supplied closed eleven-entry inventory.
#[derive(Clone, Debug)]
pub struct B4NegativeAncestrySourceAuthorityV1 {
    prior: B4NegativeAncestryPriorAuthorityViewV1,
    authenticated: AuthenticatedSourceClosureV1,
    consumer_guest_elf: Vec<u8>,
    alternate_guest_elf: Vec<u8>,
    case9_recursive_oracle_borsh: Vec<u8>,
}

impl B4NegativeAncestrySourceAuthorityV1 {
    /// Authenticate the complete source-only closure before witness production.
    ///
    /// # Errors
    ///
    /// Returns an error for stale prior documents, profile drift, unsafe or
    /// aliased source paths, a malformed case-9 export, or any case-9 byte
    /// mismatch against the positive-generation authority.
    pub fn from_source_closure(
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV1,
        source: B4NegativeAncestrySourceClosureV1<'_>,
    ) -> Result<Self> {
        let prior = B4NegativeAncestryPriorAuthorityViewV1::from_authorities(campaign, positive)?;
        let authenticated = authenticate_source_closure(&prior, &source)?;
        Ok(Self {
            prior,
            authenticated,
            consumer_guest_elf: source.profile_package.consumer_guest_elf.bytes.to_vec(),
            alternate_guest_elf: source.alternate_guest_elf.bytes.to_vec(),
            case9_recursive_oracle_borsh: source.case9.primary_artifacts[7].bytes.to_vec(),
        })
    }

    /// Rebind this retained source to the exact campaign and positive authorities.
    ///
    /// This hidden integration seam returns no source projection and exposes no
    /// retained source bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if either supplied authority is internally inconsistent
    /// or differs from the construction-time precommit, positive identities,
    /// case-9 custody, or provenance closure.
    #[doc(hidden)]
    pub fn verify_authority_bindings(
        &self,
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV1,
    ) -> Result<()> {
        let supplied = B4NegativeAncestryPriorAuthorityViewV1::from_authorities(campaign, positive)
            .context("cannot reconstruct supplied negative-ancestry prior authorities")?;
        ensure!(
            supplied.campaign_precommit_jcs == self.prior.campaign_precommit_jcs,
            "supplied campaign precommit differs from retained negative-ancestry source authority"
        );
        ensure!(
            supplied.negative_plan == self.prior.negative_plan,
            "supplied campaign negative plan differs from retained negative-ancestry source authority"
        );
        ensure!(
            supplied.positive_input_set == self.prior.positive_input_set,
            "supplied positive input identity differs from retained negative-ancestry source authority"
        );
        ensure!(
            supplied.positive_generation_set == self.prior.positive_generation_set,
            "supplied positive generation identity differs from retained negative-ancestry source authority"
        );
        ensure!(
            supplied.case9 == self.prior.case9,
            "supplied positive case-9 custody differs from retained negative-ancestry source authority"
        );
        ensure!(
            supplied.provenance_paths == self.prior.provenance_paths
                && supplied
                    .provenance_paths
                    .is_subset(&self.authenticated.provenance_paths),
            "supplied authority provenance paths differ from retained negative-ancestry source authority"
        );
        ensure!(
            supplied.positive_provenance_sha256 == self.prior.positive_provenance_sha256,
            "supplied positive provenance digests differ from retained negative-ancestry source authority"
        );

        let supplied_commitments = B4NegativeAncestryPriorCommitmentsV1 {
            campaign_precommit: pathless_identity(&supplied.campaign_precommit_jcs)?,
            positive_input_set: pathless_identity_from_contract_identity(
                &supplied.positive_input_set,
                "positive input set",
            )?,
            positive_generation_set: pathless_identity_from_contract_identity(
                &supplied.positive_generation_set,
                "positive generation set",
            )?,
        };
        ensure!(
            supplied_commitments == self.authenticated.prior_commitments,
            "supplied prior commitments differ from retained negative-ancestry source authentication"
        );
        Ok(())
    }

    /// Borrow the exact authenticated case-9 assumption source.
    #[must_use]
    pub fn case9_assumption_source(&self) -> B4AuthenticatedCase9AssumptionSourceV1<'_> {
        B4AuthenticatedCase9AssumptionSourceV1::from_authority(self)
    }

    /// Borrow the complete authenticated source for the fixed seven-witness producer.
    #[must_use]
    pub fn producer_source(&self) -> B4AuthenticatedNegativeAncestryProducerSourceV1<'_> {
        B4AuthenticatedNegativeAncestryProducerSourceV1::from_authority(self)
    }

    pub(crate) fn case9_assumption_source_parts(
        &self,
    ) -> (&[u8], &[u8], &[u8], [u8; DIGEST_BYTES]) {
        (
            &self.case9_recursive_oracle_borsh,
            &self.authenticated.case9.assumption_raw_seal,
            &self.authenticated.case9.statement,
            self.authenticated.profile.consumer_program_id,
        )
    }

    pub(crate) fn producer_source_projection(
        &self,
    ) -> B4NegativeAncestryProducerSourceProjectionV1<'_> {
        B4NegativeAncestryProducerSourceProjectionV1 {
            case9_recursive_oracle_borsh: &self.case9_recursive_oracle_borsh,
            case9_assumption_raw_seal: &self.authenticated.case9.assumption_raw_seal,
            case9_final_raw_seal: &self.authenticated.case9.final_raw_seal,
            canonical_statement: &self.authenticated.case9.statement,
            consumer_guest_elf: &self.consumer_guest_elf,
            consumer_program_id: self.authenticated.profile.consumer_program_id,
            alternate_guest_elf: &self.alternate_guest_elf,
            alternate_program_id: self.authenticated.profile.alternate_program_id,
        }
    }

    /// Authenticate and derive the final catalogue from eleven generated rows.
    ///
    /// # Errors
    ///
    /// Returns an error before receipt replay for a missing, extra, reordered,
    /// duplicated, unsafe, or path-conflicting entry. Otherwise returns the
    /// first stock replay, claim, or derived-catalogue invariant failure.
    pub fn finalize(
        &self,
        entries: &[B4NegativeAncestryWitnessExternalEntryV1<'_>],
    ) -> Result<B4NegativeAncestryWitnessCatalogAuthorityV1> {
        let provenance_paths = validate_finalization_closure(
            entries,
            &self.authenticated.case9,
            &self.authenticated.provenance_paths,
        )?;
        let replay = CompiledNegativeAncestryWitnessReplayV1::from_compiled_profile()?;
        build_catalog_authority_from_entries(
            &self.prior,
            entries,
            &self.authenticated,
            &self.alternate_guest_elf,
            provenance_paths,
            &replay,
        )
    }

    #[cfg(test)]
    fn finalize_with_replay(
        &self,
        entries: &[B4NegativeAncestryWitnessExternalEntryV1<'_>],
        replay: &impl B4NegativeAncestryWitnessReplayV1,
    ) -> Result<B4NegativeAncestryWitnessCatalogAuthorityV1> {
        let provenance_paths = validate_finalization_closure(
            entries,
            &self.authenticated.case9,
            &self.authenticated.provenance_paths,
        )?;
        build_catalog_authority_from_entries(
            &self.prior,
            entries,
            &self.authenticated,
            &self.alternate_guest_elf,
            provenance_paths,
            replay,
        )
    }
}

/// Opaque affine authority for one fully authenticated V2 ancestry source.
///
/// It can be minted only by joining the campaign precommit, the consumed V2
/// positive-generation authority, and independently supplied source bytes.
/// It has no parser, deserializer, clone, default, or V1 conversion path.
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_negative_ancestry_authority::
///     B4NegativeAncestrySourceAuthorityV2;
/// fn require_clone<T: Clone>() {}
/// require_clone::<B4NegativeAncestrySourceAuthorityV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_negative_ancestry_authority::
///     B4NegativeAncestrySourceAuthorityV2;
/// fn require_default<T: Default>() {}
/// require_default::<B4NegativeAncestrySourceAuthorityV2>();
/// ```
pub struct B4NegativeAncestrySourceAuthorityV2 {
    prior: B4NegativeAncestryPriorAuthorityViewV2,
    authenticated: AuthenticatedSourceClosureV2,
    consumer_guest_elf: Vec<u8>,
    alternate_guest_elf: Vec<u8>,
    case9_recursive_oracle_borsh: Vec<u8>,
}

impl B4NegativeAncestrySourceAuthorityV2 {
    /// Authenticate the complete V2 source closure before witness production.
    ///
    /// # Errors
    ///
    /// Returns an error for authority drift, noncanonical V2 documents,
    /// profile or case-9 custody drift, path aliasing, or source mismatch.
    pub fn from_source_closure(
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV2,
        source: B4NegativeAncestrySourceClosureV2<'_>,
    ) -> Result<Self> {
        let prior = B4NegativeAncestryPriorAuthorityViewV2::from_authorities(campaign, positive)?;
        let authenticated = authenticate_source_closure_v2(&prior, positive, &source)?;
        Ok(Self {
            prior,
            authenticated,
            consumer_guest_elf: source.profile_package.consumer_guest_elf.bytes.to_vec(),
            alternate_guest_elf: source.alternate_guest_elf.bytes.to_vec(),
            case9_recursive_oracle_borsh: source.case9.primary_artifacts[7].bytes.to_vec(),
        })
    }

    /// Rebind the retained V2 source to the exact supplied affine authorities.
    ///
    /// # Errors
    ///
    /// Returns an error for campaign, V2 positive identity, provenance, or
    /// retained case-9 custody drift.
    #[doc(hidden)]
    pub fn verify_authority_bindings(
        &self,
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV2,
    ) -> Result<()> {
        let supplied = B4NegativeAncestryPriorAuthorityViewV2::from_authorities(campaign, positive)
            .context("cannot reconstruct supplied V2 ancestry prior authorities")?;
        ensure!(
            supplied.campaign_precommit_jcs == self.prior.campaign_precommit_jcs
                && supplied.negative_plan == self.prior.negative_plan,
            "supplied campaign differs from retained V2 ancestry source authority"
        );
        ensure!(
            supplied.positive_input_set == self.prior.positive_input_set
                && supplied.positive_generation_set == self.prior.positive_generation_set,
            "supplied positive identities differ from retained V2 ancestry source authority"
        );
        ensure!(
            supplied.provenance_paths == self.prior.provenance_paths
                && supplied.provenance_paths == self.authenticated.prior_provenance_paths,
            "supplied provenance differs from retained V2 ancestry source authority"
        );
        ensure!(
            supplied.positive_provenance_sha256 == self.prior.positive_provenance_sha256
                && supplied.positive_provenance_sha256
                    == self.authenticated.positive_provenance_sha256,
            "supplied positive provenance digests differ from retained V2 ancestry source authority"
        );
        ensure!(
            positive.case_custody_matches(
                CASE_9_INDEX,
                &self.authenticated.case9_custody.case_id,
                self.authenticated.case9_custody.proof_output_manifest,
                &self.authenticated.case9_custody.primary_measurements,
                &self.authenticated.case9_custody.auxiliary_measurements,
            ),
            "supplied V2 authority does not retain the authenticated case-9 custody"
        );
        let supplied_commitments = B4NegativeAncestryPriorCommitmentsV2 {
            campaign_precommit: pathless_identity(&supplied.campaign_precommit_jcs)?,
            positive_input_set: supplied.positive_input_set.clone(),
            positive_generation_set: supplied.positive_generation_set.clone(),
        };
        ensure!(
            supplied_commitments == self.authenticated.prior_commitments,
            "supplied commitments differ from retained V2 ancestry source authentication"
        );
        Ok(())
    }

    /// Borrow the complete authenticated source for the fixed V2 producer.
    #[must_use]
    pub fn producer_source(&self) -> B4AuthenticatedNegativeAncestryProducerSourceV2<'_> {
        B4AuthenticatedNegativeAncestryProducerSourceV2::from_authority(self)
    }

    pub(crate) fn producer_source_projection(
        &self,
    ) -> B4NegativeAncestryProducerSourceProjectionV2<'_> {
        B4NegativeAncestryProducerSourceProjectionV2 {
            case9_recursive_oracle_borsh: &self.case9_recursive_oracle_borsh,
            case9_assumption_raw_seal: &self.authenticated.case9.assumption_raw_seal,
            case9_final_raw_seal: &self.authenticated.case9.final_raw_seal,
            canonical_statement: &self.authenticated.case9.statement,
            consumer_guest_elf: &self.consumer_guest_elf,
            consumer_program_id: self.authenticated.profile.consumer_program_id,
            alternate_guest_elf: &self.alternate_guest_elf,
            alternate_program_id: self.authenticated.profile.alternate_program_id,
            prior_provenance_paths: &self.authenticated.prior_provenance_paths,
            positive_provenance_sha256: &self.authenticated.positive_provenance_sha256,
        }
    }

    /// Authenticate and derive a distinct V2 catalogue authority.
    ///
    /// # Errors
    ///
    /// Returns the first inventory, replay, claim, or catalogue invariant failure.
    pub fn finalize(
        &self,
        entries: &[B4NegativeAncestryWitnessExternalEntryV1<'_>],
    ) -> Result<B4NegativeAncestryWitnessCatalogAuthorityV2> {
        let provenance_paths = validate_finalization_closure(
            entries,
            &self.authenticated.case9,
            &self.authenticated.provenance_paths,
        )?;
        let replay = CompiledNegativeAncestryWitnessReplayV1::from_compiled_profile()?;
        build_catalog_authority_v2_from_entries(
            &self.prior,
            entries,
            &self.authenticated,
            &self.alternate_guest_elf,
            provenance_paths,
            &replay,
        )
    }

    #[cfg(test)]
    fn finalize_with_replay(
        &self,
        entries: &[B4NegativeAncestryWitnessExternalEntryV1<'_>],
        replay: &impl B4NegativeAncestryWitnessReplayV1,
    ) -> Result<B4NegativeAncestryWitnessCatalogAuthorityV2> {
        let provenance_paths = validate_finalization_closure(
            entries,
            &self.authenticated.case9,
            &self.authenticated.provenance_paths,
        )?;
        build_catalog_authority_v2_from_entries(
            &self.prior,
            entries,
            &self.authenticated,
            &self.alternate_guest_elf,
            provenance_paths,
            replay,
        )
    }
}

/// Opaque authority for one exact derive-first negative-ancestry catalogue.
///
/// The type is intentionally non-serializable and has no public data
/// constructor. Exact generated row bytes remain privately retained after
/// source authentication and stock replay.
#[derive(Clone, Debug)]
#[allow(
    dead_code,
    reason = "private closure fields are retained for the separately approved materialization tranche"
)]
pub struct B4NegativeAncestryWitnessCatalogAuthorityV1 {
    expected: Eip0045B4NegativeAncestryWitnessCatalogV1,
    canonical_jcs: Vec<u8>,
    prior_commitments: B4NegativeAncestryPriorCommitmentsV1,
    alternate_guest_elf: Vec<u8>,
    retained_entries: Vec<B4RetainedNegativeAncestryWitnessEntryV1>,
    provenance_paths: BTreeSet<String>,
}

impl B4NegativeAncestryWitnessCatalogAuthorityV1 {
    /// Derive authority from prior opaque authorities and exact external bytes.
    ///
    /// # Errors
    ///
    /// Returns an error before receipt replay for any stale prior document,
    /// profile drift, unsafe or aliased path, case-9 source defect, or witness
    /// inventory mismatch; otherwise returns the first stock replay, claim, or
    /// derived-catalogue invariant failure.
    pub fn from_external_closure(
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV1,
        external: B4NegativeAncestryExternalClosureV1<'_>,
    ) -> Result<Self> {
        B4NegativeAncestrySourceAuthorityV1::from_source_closure(
            campaign,
            positive,
            external.source_closure(),
        )?
        .finalize(external.entries)
    }

    /// Verify that this ancestry authority belongs to the supplied prior authorities.
    ///
    /// # Errors
    ///
    /// Returns an error if the prior authorities are inconsistent, retain an
    /// invalid artifact identity, or differ from any retained prior commitment.
    #[doc(hidden)]
    pub fn verify_prior_authority_lineage(
        &self,
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV1,
    ) -> Result<()> {
        let prior = B4NegativeAncestryPriorAuthorityViewV1::from_authorities(campaign, positive)?;
        let rederived = B4NegativeAncestryPriorCommitmentsV1 {
            campaign_precommit: pathless_identity(&prior.campaign_precommit_jcs)?,
            positive_input_set: pathless_identity_from_contract_identity(
                &prior.positive_input_set,
                "positive input set",
            )?,
            positive_generation_set: pathless_identity_from_contract_identity(
                &prior.positive_generation_set,
                "positive generation set",
            )?,
        };
        ensure!(
            rederived == self.prior_commitments,
            "negative-ancestry authority belongs to different prior authorities"
        );
        Ok(())
    }

    /// Require candidate bytes to equal the sole internally derived catalogue.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, structurally invalid,
    /// semantically different, or byte-different catalogue input.
    pub fn verify_candidate_jcs(&self, source: &[u8]) -> Result<()> {
        let candidate = Eip0045B4NegativeAncestryWitnessCatalogV1::from_canonical_jcs(source)?;
        ensure!(
            candidate == self.expected,
            "candidate negative ancestry catalogue differs from derived authority"
        );
        ensure!(
            source == self.canonical_jcs,
            "candidate negative ancestry catalogue bytes differ from derived authority"
        );
        Ok(())
    }

    /// Exact canonical catalogue bytes prescribed by this authority.
    #[must_use]
    pub fn canonical_catalog_jcs(&self) -> &[u8] {
        &self.canonical_jcs
    }

    /// Immutable derived catalogue prescribed by this authority.
    #[must_use]
    pub const fn catalog(&self) -> &Eip0045B4NegativeAncestryWitnessCatalogV1 {
        &self.expected
    }

    #[allow(
        dead_code,
        reason = "consumed by the separately approved materialization tranche"
    )]
    pub(crate) const fn prior_commitments(&self) -> &B4NegativeAncestryPriorCommitmentsV1 {
        &self.prior_commitments
    }

    #[allow(
        dead_code,
        reason = "consumed by the separately approved materialization tranche"
    )]
    pub(crate) fn alternate_guest_elf(&self) -> &[u8] {
        &self.alternate_guest_elf
    }

    #[allow(
        dead_code,
        reason = "consumed by the separately approved materialization tranche"
    )]
    pub(crate) fn retained_entries(&self) -> &[B4RetainedNegativeAncestryWitnessEntryV1] {
        &self.retained_entries
    }

    #[allow(
        dead_code,
        reason = "consumed by the separately approved materialization tranche"
    )]
    pub(crate) const fn provenance_paths(&self) -> &BTreeSet<String> {
        &self.provenance_paths
    }

    #[cfg(test)]
    pub(crate) fn synthetic_for_publication_tests() -> Self {
        tests::publication_authority_fixture()
    }
}

/// Opaque affine authority for one exact V2-derived ancestry catalogue.
///
/// The serialized catalogue remains the reviewed V1 wire. This distinct token
/// retains V2 positive identities and case-9 custody and has no V1 conversion,
/// parser, deserializer, clone, copy, or default constructor.
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_negative_ancestry_authority::
///     B4NegativeAncestryWitnessCatalogAuthorityV2;
/// fn require_clone<T: Clone>() {}
/// require_clone::<B4NegativeAncestryWitnessCatalogAuthorityV2>();
/// ```
pub struct B4NegativeAncestryWitnessCatalogAuthorityV2 {
    expected: Eip0045B4NegativeAncestryWitnessCatalogV1,
    canonical_jcs: Vec<u8>,
    prior_commitments: B4NegativeAncestryPriorCommitmentsV2,
    case9_custody: B4RetainedPositiveCase9CustodyV2,
    alternate_guest_elf: Vec<u8>,
    retained_entries: Vec<B4RetainedNegativeAncestryWitnessEntryV1>,
    prior_provenance_paths: BTreeSet<String>,
    positive_provenance_sha256: BTreeMap<String, [u8; DIGEST_BYTES]>,
    provenance_paths: BTreeSet<String>,
}

impl B4NegativeAncestryWitnessCatalogAuthorityV2 {
    /// Rebind this catalogue to its exact campaign and V2 positive authorities.
    ///
    /// # Errors
    ///
    /// Returns an error for campaign, positive identity, or case-9 custody drift.
    #[doc(hidden)]
    pub fn verify_prior_authority_lineage(
        &self,
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV2,
    ) -> Result<()> {
        let prior = B4NegativeAncestryPriorAuthorityViewV2::from_authorities(campaign, positive)?;
        let rederived = B4NegativeAncestryPriorCommitmentsV2 {
            campaign_precommit: pathless_identity(&prior.campaign_precommit_jcs)?,
            positive_input_set: prior.positive_input_set.clone(),
            positive_generation_set: prior.positive_generation_set.clone(),
        };
        ensure!(
            rederived == self.prior_commitments,
            "V2 ancestry catalogue belongs to different prior authorities"
        );
        ensure!(
            prior.provenance_paths == self.prior_provenance_paths,
            "V2 ancestry catalogue prior-authority provenance closure differs"
        );
        ensure!(
            prior.positive_provenance_sha256 == self.positive_provenance_sha256,
            "V2 ancestry catalogue positive provenance digests differ"
        );
        ensure!(
            positive.case_custody_matches(
                CASE_9_INDEX,
                &self.case9_custody.case_id,
                self.case9_custody.proof_output_manifest,
                &self.case9_custody.primary_measurements,
                &self.case9_custody.auxiliary_measurements,
            ),
            "V2 ancestry catalogue belongs to different positive case-9 custody"
        );
        Ok(())
    }

    /// Require candidate bytes to equal the sole internally derived catalogue.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, or byte-different input.
    pub fn verify_candidate_jcs(&self, source: &[u8]) -> Result<()> {
        let candidate = Eip0045B4NegativeAncestryWitnessCatalogV1::from_canonical_jcs(source)?;
        ensure!(
            candidate == self.expected && source == self.canonical_jcs,
            "candidate negative ancestry catalogue differs from V2-derived authority"
        );
        Ok(())
    }

    /// Exact canonical V1 wire bytes prescribed by this V2 authority.
    #[must_use]
    pub fn canonical_catalog_jcs(&self) -> &[u8] {
        &self.canonical_jcs
    }

    /// Immutable V1 wire catalogue prescribed by this V2 authority.
    #[must_use]
    pub const fn catalog(&self) -> &Eip0045B4NegativeAncestryWitnessCatalogV1 {
        &self.expected
    }

    pub(crate) fn alternate_guest_elf(&self) -> &[u8] {
        &self.alternate_guest_elf
    }

    pub(crate) fn retained_entries(&self) -> &[B4RetainedNegativeAncestryWitnessEntryV1] {
        &self.retained_entries
    }

    pub(crate) const fn provenance_paths(&self) -> &BTreeSet<String> {
        &self.provenance_paths
    }
}

fn stock_replay_error(error: StockReceiptReplayError) -> anyhow::Error {
    anyhow::Error::new(error)
}

/// Local test facts only: this does not construct campaign or publication authority.
#[cfg(test)]
pub(crate) fn replay_local_ancestry_receipt(
    raw_seal: &[u8],
    receipt_oracle: &[u8],
) -> Result<(RecursiveAncestryClaim, RecursiveAncestryTerminal, String)> {
    let verified = CompiledNegativeAncestryWitnessReplayV1::from_compiled_profile()?
        .replay(raw_seal, receipt_oracle)?;
    Ok((verified.claim, verified.terminal, verified.control_root))
}

fn project_verified_direct_receipt(
    verified: &VerifiedStockSuccinctReceiptV1<ReceiptClaim>,
) -> Result<B4VerifiedDirectAncestryReceiptV1> {
    let upstream_claim = verified
        .claim()
        .as_value()
        .map_err(|_| anyhow::anyhow!("verified direct receipt claim is pruned"))?;
    let claim = project_verified_receipt_claim(upstream_claim)?;
    ensure!(
        recursive_ancestry_claim_digest(&claim)?.as_slice() == verified.claim_digest().as_bytes(),
        "verified direct receipt claim digest differs from its ancestry projection"
    );
    ensure!(
        hex::encode(verified.control_id().as_bytes()) == verified.stock().control_id,
        "verified direct receipt control ID differs from its compiled stock row"
    );
    let terminal = project_verified_stock_terminal(verified.stock())?;
    Ok(B4VerifiedDirectAncestryReceiptV1 {
        claim,
        terminal,
        control_root: hex::encode(verified.control_root().as_bytes()),
    })
}

fn project_verified_stock_terminal(
    stock: &crate::b4_terminal::B4StockControlLayoutV1,
) -> Result<RecursiveAncestryTerminal> {
    let terminal = match stock.family {
        "lift-po2-15" => RecursiveAncestryTerminal::Lift {
            segment_po2: 15,
            control_id: stock.control_id.to_owned(),
        },
        "lift-po2-16" => RecursiveAncestryTerminal::Lift {
            segment_po2: 16,
            control_id: stock.control_id.to_owned(),
        },
        "join" => RecursiveAncestryTerminal::Join {
            control_id: stock.control_id.to_owned(),
        },
        "resolve" => RecursiveAncestryTerminal::Resolve {
            control_id: stock.control_id.to_owned(),
        },
        family => bail!("verified direct receipt uses inadmissible ancestry terminal {family}"),
    };
    Ok(terminal)
}

fn authenticate_source_closure(
    prior: &B4NegativeAncestryPriorAuthorityViewV1,
    external: &B4NegativeAncestrySourceClosureV1<'_>,
) -> Result<AuthenticatedSourceClosureV1> {
    require_closed_source_cardinalities(external)?;
    ensure!(
        external.campaign_precommit_jcs == prior.campaign_precommit_jcs,
        "campaign-precommit bytes differ from the opaque prior authority"
    );
    authenticate_external_identity(
        B4PositiveSourceBytesV1 {
            path: external.positive_input_set.path,
            bytes: external.positive_input_set.bytes,
        },
        &prior.positive_input_set,
        B4ContractArtifactEncodingV1::Rfc8785Jcs,
        "positive input set",
    )?;
    authenticate_external_identity(
        B4PositiveSourceBytesV1 {
            path: external.positive_generation_set.path,
            bytes: external.positive_generation_set.bytes,
        },
        &prior.positive_generation_set,
        B4ContractArtifactEncodingV1::Rfc8785Jcs,
        "positive generation set",
    )?;
    crate::canonical::validate_canonical_json_source(external.positive_input_set.bytes)
        .context("positive input set is not exact canonical JCS")?;
    crate::canonical::validate_canonical_json_source(external.positive_generation_set.bytes)
        .context("positive generation set is not exact canonical JCS")?;

    let input = parse_positive_input_sources(external.positive_input_set.bytes)?;
    let mut paths = prior.provenance_paths.clone();
    bind_external_path(
        &mut paths,
        external.positive_input_set.path,
        true,
        "positive input set",
    )?;
    bind_external_path(
        &mut paths,
        external.positive_generation_set.path,
        true,
        "positive generation set",
    )?;

    let profile = authenticate_profile(
        &input,
        external.profile_package,
        external.alternate_guest_elf,
    )?;
    let case9 = authenticate_case9(
        prior,
        external.positive_generation_set.bytes,
        external.case9,
        profile.profile_id,
        profile.consumer_program_id,
        &mut paths,
    )?;
    for source in [
        external.profile_package.profile_manifest,
        external.profile_package.profile_algorithm,
        external.profile_package.profile_constants,
        external.profile_package.consumer_guest_elf,
    ] {
        bind_external_path(
            &mut paths,
            source.path,
            true,
            "negative ancestry profile source",
        )?;
    }
    bind_external_path(
        &mut paths,
        external.alternate_guest_elf.path,
        false,
        "negative ancestry alternate guest ELF",
    )?;

    Ok(AuthenticatedSourceClosureV1 {
        prior_commitments: B4NegativeAncestryPriorCommitmentsV1 {
            campaign_precommit: pathless_identity(&prior.campaign_precommit_jcs)?,
            positive_input_set: pathless_identity(external.positive_input_set.bytes)?,
            positive_generation_set: pathless_identity(external.positive_generation_set.bytes)?,
        },
        profile,
        case9,
        provenance_paths: paths,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the V2 gate keeps document identities, profile bytes, case-9 custody, and path closure in one fail-closed transition"
)]
fn authenticate_source_closure_v2(
    prior: &B4NegativeAncestryPriorAuthorityViewV2,
    positive: &B4PositiveGenerationAuthorityV2,
    external: &B4NegativeAncestrySourceClosureV2<'_>,
) -> Result<AuthenticatedSourceClosureV2> {
    ensure!(
        positive.provenance_sha256() == &prior.positive_provenance_sha256,
        "V2 positive provenance digests differ from the retained prior view"
    );
    ensure!(
        external.campaign_precommit_jcs == prior.campaign_precommit_jcs,
        "campaign-precommit bytes differ from the V2 ancestry prior authority"
    );
    authenticate_external_identity_v2(
        B4PositiveSourceBytesV2 {
            path: external.positive_input_set.path,
            bytes: external.positive_input_set.bytes,
        },
        &prior.positive_input_set,
        B4ContractArtifactEncodingV1::Rfc8785Jcs,
        "V2 positive input set",
    )?;
    authenticate_external_identity_v2(
        B4PositiveSourceBytesV2 {
            path: external.positive_generation_set.path,
            bytes: external.positive_generation_set.bytes,
        },
        &prior.positive_generation_set,
        B4ContractArtifactEncodingV1::Rfc8785Jcs,
        "V2 positive generation set",
    )?;
    crate::canonical::validate_canonical_json_source(external.positive_input_set.bytes)
        .context("V2 positive input set is not exact canonical JCS")?;
    crate::canonical::validate_canonical_json_source(external.positive_generation_set.bytes)
        .context("V2 positive generation set is not exact canonical JCS")?;

    let mut paths = prior.provenance_paths.clone();
    bind_external_path(
        &mut paths,
        external.positive_input_set.path,
        true,
        "V2 positive input set",
    )?;
    bind_external_path(
        &mut paths,
        external.positive_generation_set.path,
        true,
        "V2 positive generation set",
    )?;

    let mut case_paths = BTreeSet::new();
    let case9 = authenticate_case9_v2(
        external.positive_input_set.bytes,
        external.positive_generation_set.bytes,
        external.profile_package,
        external.case9,
        &mut case_paths,
    )?;
    merge_prior_paths(&mut paths, &case_paths)?;

    let primary = external
        .case9
        .primary_artifacts
        .iter()
        .map(|source| B4PositiveSourceBytesV2 {
            path: source.path,
            bytes: source.bytes,
        })
        .collect::<Vec<_>>();
    let auxiliary = external
        .case9
        .auxiliary_artifacts
        .iter()
        .map(|source| B4PositiveSourceBytesV2 {
            path: source.path,
            bytes: source.bytes,
        })
        .collect::<Vec<_>>();
    let retained_case9 = positive
        .authenticate_case(
            CASE_9_INDEX,
            B4PositiveCaseSourceV2 {
                proof_output_manifest_jcs: external.case9.proof_output_manifest_jcs,
                primary_artifacts: &primary,
                auxiliary_artifacts: &auxiliary,
            },
        )
        .context("V2 positive authority rejects independently supplied case-9 custody")?;
    ensure!(
        retained_case9.case_index() == CASE_9_INDEX
            && retained_case9.journal() == case9.statement
            && retained_case9.raw_seal() == case9.final_raw_seal
            && retained_case9.auxiliary_artifacts()[0].bytes == case9.assumption_raw_seal,
        "V2 positive authority case-9 custody differs from semantic ancestry authentication"
    );
    let case9_custody = B4RetainedPositiveCase9CustodyV2 {
        case_id: retained_case9.case_id().to_owned(),
        proof_output_manifest: retained_case9.proof_output_manifest(),
        primary_measurements: retained_case9.primary_measurements().to_vec(),
        auxiliary_measurements: retained_case9.auxiliary_measurements().to_vec(),
    };

    let input = parse_positive_input_sources_v2(external.positive_input_set.bytes)?;
    let profile_id = decode_hex32(&input.profile_id, "V2 positive input profile ID")?;
    let consumer_program_id: [u8; DIGEST_BYTES] =
        compute_image_id(external.profile_package.consumer_guest_elf.bytes)
            .context("V2 consumer guest ELF is not a valid RISC Zero program")?
            .into();
    ensure!(
        hex::encode(consumer_program_id) == input.guest_image_id,
        "V2 consumer guest ELF differs from the positive input identity"
    );
    ensure!(
        external.alternate_guest_elf.path == B4_NEGATIVE_ANCESTRY_ALTERNATE_GUEST_ELF_PATH,
        "V2 alternate guest ELF path differs from the closed catalogue path"
    );
    ensure!(
        (1..=MAX_ALTERNATE_GUEST_ELF_BYTES).contains(&external.alternate_guest_elf.bytes.len()),
        "V2 alternate guest ELF is outside its closed byte bound"
    );
    let alternate_program_id: [u8; DIGEST_BYTES] =
        compute_image_id(external.alternate_guest_elf.bytes)
            .context("V2 alternate guest ELF is not a valid RISC Zero program")?
            .into();
    ensure!(
        alternate_program_id != consumer_program_id,
        "V2 alternate guest ELF computes to the consumer program ID"
    );
    bind_external_path(
        &mut paths,
        external.alternate_guest_elf.path,
        false,
        "V2 negative ancestry alternate guest ELF",
    )?;

    Ok(AuthenticatedSourceClosureV2 {
        prior_commitments: B4NegativeAncestryPriorCommitmentsV2 {
            campaign_precommit: pathless_identity(&prior.campaign_precommit_jcs)?,
            positive_input_set: B4ContractArtifactIdentityV1::from_bytes(
                external.positive_input_set.path,
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                external.positive_input_set.bytes,
            )?,
            positive_generation_set: B4ContractArtifactIdentityV1::from_bytes(
                external.positive_generation_set.path,
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                external.positive_generation_set.bytes,
            )?,
        },
        profile: AuthenticatedProfileV2 {
            profile_manifest: input.profile_manifest,
            consumer_program_id,
            alternate_guest_elf: B4ContractArtifactIdentityV1::from_bytes(
                external.alternate_guest_elf.path,
                B4ContractArtifactEncodingV1::RawBytes,
                external.alternate_guest_elf.bytes,
            )?,
            alternate_program_id,
            profile_id,
        },
        case9,
        case9_custody,
        prior_provenance_paths: prior.provenance_paths.clone(),
        positive_provenance_sha256: prior.positive_provenance_sha256.clone(),
        provenance_paths: paths,
    })
}

fn require_closed_source_cardinalities(
    external: &B4NegativeAncestrySourceClosureV1<'_>,
) -> Result<()> {
    ensure!(
        external.case9.primary_artifacts.len() == RECURSIVE_POSITIVE_ARTIFACT_LAYOUT.len(),
        "negative ancestry source closure must contain exactly eight case-9 primary artifacts"
    );
    ensure!(
        external.case9.auxiliary_artifacts.len()
            == compiled_positive_auxiliary_artifact_paths(CASE_9_INDEX)?.len(),
        "negative ancestry source closure must contain exactly two case-9 auxiliary artifacts"
    );
    Ok(())
}

fn authenticate_profile(
    input: &B4AuthenticatedPositiveInputSourcesV1,
    package: B4NegativeAncestryProfilePackageExternalV1<'_>,
    alternate_elf: B4NegativeAncestryExternalBytesV1<'_>,
) -> Result<AuthenticatedProfileV1> {
    for (external, expected, label) in [
        (
            package.profile_manifest,
            &input.profile_manifest,
            "profile manifest",
        ),
        (
            package.profile_algorithm,
            &input.profile_algorithm,
            "profile algorithm",
        ),
        (
            package.profile_constants,
            &input.profile_constants,
            "profile constants",
        ),
        (
            package.consumer_guest_elf,
            &input.guest_elf,
            "consumer guest ELF",
        ),
    ] {
        authenticate_external_identity(
            B4PositiveSourceBytesV1 {
                path: external.path,
                bytes: external.bytes,
            },
            expected,
            B4ContractArtifactEncodingV1::RawBytes,
            label,
        )?;
    }
    ensure!(
        package.profile_manifest.path == B4_NEGATIVE_ANCESTRY_PROFILE_MANIFEST_PATH,
        "profile-manifest path differs from the negative ancestry catalogue authority"
    );
    ensure!(
        package.profile_manifest.bytes.len() == MANIFEST_BYTES,
        "profile manifest has the wrong exact byte length"
    );

    let profile_id = decode_hex32(&input.profile_id, "positive input profile ID")?;
    let validated = validate_profile_package_v1(
        package.profile_manifest.bytes,
        ProfileArtifacts {
            algorithm: package.profile_algorithm.bytes,
            binary_data: package.profile_constants.bytes,
        },
        &profile_id,
    )
    .context("profile package differs from its authenticated Manifest V1")?;
    validated
        .manifest()
        .validate_initial_profile_target()
        .context("profile manifest differs from the frozen initial target")?;
    authenticate_profile_algorithm(package.profile_algorithm.bytes, validated.manifest())
        .context("B1 algorithm artifact differs from the frozen profile")?;
    constants_artifact::verify_canonical(package.profile_constants.bytes)
        .context("B2 constants artifact differs from its canonical frozen bytes")?;
    ensure!(
        hex::encode(validated.manifest().inner_control_root()) == RISC0_INNER_CONTROL_ROOT_HEX,
        "profile manifest inner control root differs from the compiled stock root"
    );

    let consumer_program_id: [u8; DIGEST_BYTES] =
        compute_image_id(package.consumer_guest_elf.bytes)
            .context("consumer guest ELF is not a valid RISC Zero program")?
            .into();
    ensure!(
        hex::encode(consumer_program_id) == input.guest_image_id,
        "consumer guest ELF image ID differs from the positive-input authority"
    );

    ensure!(
        alternate_elf.path == B4_NEGATIVE_ANCESTRY_ALTERNATE_GUEST_ELF_PATH,
        "alternate guest ELF path differs from the closed catalogue path"
    );
    ensure!(
        (1..=MAX_ALTERNATE_GUEST_ELF_BYTES).contains(&alternate_elf.bytes.len()),
        "alternate guest ELF is outside its closed byte bound"
    );
    let alternate_program_id: [u8; DIGEST_BYTES] = compute_image_id(alternate_elf.bytes)
        .context("alternate guest ELF is not a valid RISC Zero program")?
        .into();
    ensure!(
        alternate_program_id != consumer_program_id,
        "alternate guest ELF computes to the consumer program ID"
    );

    Ok(AuthenticatedProfileV1 {
        profile_manifest: input.profile_manifest.clone(),
        consumer_program_id,
        alternate_guest_elf: B4ContractArtifactIdentityV1::from_bytes(
            alternate_elf.path,
            B4ContractArtifactEncodingV1::RawBytes,
            alternate_elf.bytes,
        )?,
        alternate_program_id,
        profile_id,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the function authenticates each independently falsifiable case-9 source in one fail-closed order"
)]
fn authenticate_case9(
    prior: &B4NegativeAncestryPriorAuthorityViewV1,
    positive_generation_set_jcs: &[u8],
    case9: B4NegativeAncestryCase9ExportV1<'_>,
    profile_id: [u8; DIGEST_BYTES],
    consumer_program_id: [u8; DIGEST_BYTES],
    paths: &mut BTreeSet<String>,
) -> Result<AuthenticatedCase9V1> {
    let generation =
        B4PositiveGenerationDocumentV1::from_canonical_jcs(positive_generation_set_jcs)?;
    let primary = case9
        .primary_artifacts
        .iter()
        .map(|source| B4PositiveSourceBytesV1 {
            path: source.path,
            bytes: source.bytes,
        })
        .collect::<Vec<_>>();
    let auxiliary = case9
        .auxiliary_artifacts
        .iter()
        .map(|source| B4PositiveSourceBytesV1 {
            path: source.path,
            bytes: source.bytes,
        })
        .collect::<Vec<_>>();
    let authenticated = authenticate_positive_case_source(
        &generation,
        &prior.case9,
        CASE_9_INDEX,
        B4PositiveCaseSourceV1 {
            proof_output_manifest_jcs: case9.proof_output_manifest_jcs,
            primary_artifacts: &primary,
            auxiliary_artifacts: &auxiliary,
        },
        paths,
    )?;

    let ancestry = case9.primary_artifacts[0].bytes;
    let claim_digest = case9.primary_artifacts[2].bytes;
    let control_id = case9.primary_artifacts[3].bytes;
    let statement = authenticated.journal();
    let image_id = authenticated.image_id();
    let final_raw_seal = authenticated.raw_seal();
    let _receipt_oracle = authenticated.receipt_oracle();

    let projection = parse_recursive_ancestry_jcs(ancestry)?;
    ensure!(
        recursive_ancestry_to_jcs(&projection)? == ancestry,
        "positive case-9 ancestry projection does not round-trip byte-exactly"
    );
    ensure!(
        projection.family == RecursiveAncestryFamily::TerminalResolve,
        "positive case-9 ancestry projection is not terminal resolve"
    );
    validate_recursive_ancestry_structure(&projection, statement, profile_id)?;
    validate_canonical_recursive_ancestry(&projection, statement, profile_id)?;
    let authenticated_auxiliary = authenticated.auxiliary_artifacts();
    let auxiliary_map = BTreeMap::from([
        (
            authenticated_auxiliary[0].path.to_owned(),
            authenticated_auxiliary[0].bytes,
        ),
        (
            authenticated_auxiliary[1].path.to_owned(),
            authenticated_auxiliary[1].bytes,
        ),
    ]);
    validate_recursive_ancestry_artifacts(&projection, statement, final_raw_seal, &auxiliary_map)?;

    let final_step = projection
        .steps
        .last()
        .context("positive case-9 ancestry has no final step")?;
    ensure!(
        recursive_ancestry_claim_digest(&final_step.claim)? == claim_digest,
        "positive case-9 claim-digest artifact differs from the final receipt claim"
    );
    let crate::recursive_ancestry::RecursiveAncestryTerminal::Resolve {
        control_id: final_control_id,
    } = &final_step.terminal
    else {
        bail!("positive case-9 final terminal is not stock resolve");
    };
    ensure!(
        hex::decode(final_control_id)
            .context("positive case-9 final control ID is not hexadecimal")?
            == control_id,
        "positive case-9 control-ID artifact differs from the final terminal"
    );
    ensure!(
        image_id == consumer_program_id,
        "positive case-9 image-ID artifact differs from the consumer guest"
    );

    Ok(AuthenticatedCase9V1 {
        projection,
        statement: statement.to_vec(),
        final_raw_seal: final_raw_seal.to_vec(),
        assumption_raw_seal: authenticated_auxiliary[0].bytes.to_vec(),
    })
}

fn authenticate_v2_profile_package(
    input: &B4AuthenticatedPositiveInputSourcesV2,
    package: B4NegativeAncestryProfilePackageExternalV2<'_>,
    paths: &mut BTreeSet<String>,
) -> Result<([u8; DIGEST_BYTES], [u8; DIGEST_BYTES])> {
    for (external, expected, label) in [
        (
            package.profile_manifest,
            &input.profile_manifest,
            "V2 profile manifest",
        ),
        (
            package.profile_algorithm,
            &input.profile_algorithm,
            "V2 profile algorithm",
        ),
        (
            package.profile_constants,
            &input.profile_constants,
            "V2 profile constants",
        ),
        (
            package.consumer_guest_elf,
            &input.guest_elf,
            "V2 consumer guest ELF",
        ),
    ] {
        authenticate_external_identity_v2(
            B4PositiveSourceBytesV2 {
                path: external.path,
                bytes: external.bytes,
            },
            expected,
            B4ContractArtifactEncodingV1::RawBytes,
            label,
        )?;
        bind_external_path(paths, external.path, true, label)?;
    }
    ensure!(
        package.profile_manifest.path == B4_NEGATIVE_ANCESTRY_PROFILE_MANIFEST_PATH,
        "V2 profile-manifest path differs from the negative ancestry catalogue authority"
    );
    ensure!(
        package.profile_manifest.bytes.len() == MANIFEST_BYTES,
        "V2 profile manifest has the wrong exact byte length"
    );

    let profile_id = decode_hex32(&input.profile_id, "V2 positive input profile ID")?;
    let validated = validate_profile_package_v1(
        package.profile_manifest.bytes,
        ProfileArtifacts {
            algorithm: package.profile_algorithm.bytes,
            binary_data: package.profile_constants.bytes,
        },
        &profile_id,
    )
    .context("V2 profile package differs from its authenticated Manifest V1")?;
    validated
        .manifest()
        .validate_initial_profile_target()
        .context("V2 profile manifest differs from the frozen initial target")?;
    authenticate_profile_algorithm(package.profile_algorithm.bytes, validated.manifest())
        .context("V2 B1 algorithm artifact differs from the frozen profile")?;
    constants_artifact::verify_canonical(package.profile_constants.bytes)
        .context("V2 B2 constants artifact differs from its canonical frozen bytes")?;
    ensure!(
        hex::encode(validated.manifest().inner_control_root()) == RISC0_INNER_CONTROL_ROOT_HEX,
        "V2 profile manifest inner control root differs from the compiled stock root"
    );

    let consumer_program_id: [u8; DIGEST_BYTES] =
        compute_image_id(package.consumer_guest_elf.bytes)
            .context("V2 consumer guest ELF is not a valid RISC Zero program")?
            .into();
    ensure!(
        hex::encode(consumer_program_id) == input.guest_image_id,
        "V2 consumer guest ELF image ID differs from the positive input set"
    );
    Ok((profile_id, consumer_program_id))
}

#[allow(
    clippy::too_many_lines,
    reason = "the V2 last reparser keeps input, generation, case-9 physical identities, and ancestry semantics in one fail-closed branch"
)]
pub(crate) fn authenticate_case9_v2(
    positive_input_set_jcs: &[u8],
    positive_generation_set_jcs: &[u8],
    profile_package: B4NegativeAncestryProfilePackageExternalV2<'_>,
    case9: B4NegativeAncestryCase9ExportV2<'_>,
    paths: &mut BTreeSet<String>,
) -> Result<AuthenticatedCase9V2> {
    let input = parse_positive_input_sources_v2(positive_input_set_jcs)?;
    let generation =
        B4PositiveGenerationDocumentV2::from_canonical_jcs(positive_generation_set_jcs)?;
    generation.authenticate_input_set(positive_input_set_jcs)?;
    let (profile_id, consumer_program_id) =
        authenticate_v2_profile_package(&input, profile_package, paths)?;

    ensure!(
        case9.primary_artifacts.len() == RECURSIVE_POSITIVE_ARTIFACT_LAYOUT.len(),
        "V2 negative ancestry case-9 closure must contain exactly eight primary artifacts"
    );
    ensure!(
        case9.auxiliary_artifacts.len()
            == compiled_positive_auxiliary_artifact_paths(CASE_9_INDEX)?.len(),
        "V2 negative ancestry case-9 closure must contain exactly two auxiliary artifacts"
    );
    let primary = case9
        .primary_artifacts
        .iter()
        .map(|source| B4PositiveSourceBytesV2 {
            path: source.path,
            bytes: source.bytes,
        })
        .collect::<Vec<_>>();
    let auxiliary = case9
        .auxiliary_artifacts
        .iter()
        .map(|source| B4PositiveSourceBytesV2 {
            path: source.path,
            bytes: source.bytes,
        })
        .collect::<Vec<_>>();
    let authenticated = authenticate_positive_case_source_v2(
        &generation,
        CASE_9_INDEX,
        B4PositiveCaseSourceV2 {
            proof_output_manifest_jcs: case9.proof_output_manifest_jcs,
            primary_artifacts: &primary,
            auxiliary_artifacts: &auxiliary,
        },
        paths,
    )?;

    let ancestry = case9.primary_artifacts[0].bytes;
    let claim_digest = case9.primary_artifacts[2].bytes;
    let control_id = case9.primary_artifacts[3].bytes;
    let statement = authenticated.journal();
    let image_id = authenticated.image_id();
    let final_raw_seal = authenticated.raw_seal();
    let _receipt_oracle = authenticated.receipt_oracle();

    let projection = parse_recursive_ancestry_jcs(ancestry)?;
    ensure!(
        recursive_ancestry_to_jcs(&projection)? == ancestry,
        "V2 positive case-9 ancestry projection does not round-trip byte-exactly"
    );
    ensure!(
        projection.family == RecursiveAncestryFamily::TerminalResolve,
        "V2 positive case-9 ancestry projection is not terminal resolve"
    );
    validate_recursive_ancestry_structure(&projection, statement, profile_id)?;
    validate_canonical_recursive_ancestry(&projection, statement, profile_id)?;
    let authenticated_auxiliary = authenticated.auxiliary_artifacts();
    let auxiliary_map = BTreeMap::from([
        (
            authenticated_auxiliary[0].path.to_owned(),
            authenticated_auxiliary[0].bytes,
        ),
        (
            authenticated_auxiliary[1].path.to_owned(),
            authenticated_auxiliary[1].bytes,
        ),
    ]);
    validate_recursive_ancestry_artifacts(&projection, statement, final_raw_seal, &auxiliary_map)?;

    let final_step = projection
        .steps
        .last()
        .context("V2 positive case-9 ancestry has no final step")?;
    ensure!(
        recursive_ancestry_claim_digest(&final_step.claim)? == claim_digest,
        "V2 positive case-9 claim-digest artifact differs from the final receipt claim"
    );
    let RecursiveAncestryTerminal::Resolve {
        control_id: final_control_id,
    } = &final_step.terminal
    else {
        bail!("V2 positive case-9 final terminal is not stock resolve");
    };
    ensure!(
        hex::decode(final_control_id)
            .context("V2 positive case-9 final control ID is not hexadecimal")?
            == control_id,
        "V2 positive case-9 control-ID artifact differs from the final terminal"
    );
    ensure!(
        image_id == consumer_program_id,
        "V2 positive case-9 image-ID artifact differs from the consumer guest"
    );

    Ok(AuthenticatedCase9V2 {
        projection,
        statement: statement.to_vec(),
        final_raw_seal: final_raw_seal.to_vec(),
        assumption_raw_seal: authenticated_auxiliary[0].bytes.to_vec(),
    })
}
trait AuthenticatedProfileView {
    fn profile_id(&self) -> [u8; DIGEST_BYTES];
    fn consumer_program_id(&self) -> [u8; DIGEST_BYTES];
    fn alternate_program_id(&self) -> [u8; DIGEST_BYTES];
}

impl AuthenticatedProfileView for AuthenticatedProfileV1 {
    fn profile_id(&self) -> [u8; DIGEST_BYTES] {
        self.profile_id
    }

    fn consumer_program_id(&self) -> [u8; DIGEST_BYTES] {
        self.consumer_program_id
    }

    fn alternate_program_id(&self) -> [u8; DIGEST_BYTES] {
        self.alternate_program_id
    }
}

impl AuthenticatedProfileView for AuthenticatedProfileV2 {
    fn profile_id(&self) -> [u8; DIGEST_BYTES] {
        self.profile_id
    }

    fn consumer_program_id(&self) -> [u8; DIGEST_BYTES] {
        self.consumer_program_id
    }

    fn alternate_program_id(&self) -> [u8; DIGEST_BYTES] {
        self.alternate_program_id
    }
}

trait AuthenticatedCase9View {
    fn projection(&self) -> &RecursiveAncestryProjection;
    fn statement(&self) -> &[u8];
    fn final_raw_seal(&self) -> &[u8];
    fn assumption_raw_seal(&self) -> &[u8];
}

impl AuthenticatedCase9View for AuthenticatedCase9V1 {
    fn projection(&self) -> &RecursiveAncestryProjection {
        &self.projection
    }

    fn statement(&self) -> &[u8] {
        &self.statement
    }

    fn final_raw_seal(&self) -> &[u8] {
        &self.final_raw_seal
    }

    fn assumption_raw_seal(&self) -> &[u8] {
        &self.assumption_raw_seal
    }
}

impl AuthenticatedCase9View for AuthenticatedCase9V2 {
    fn projection(&self) -> &RecursiveAncestryProjection {
        &self.projection
    }

    fn statement(&self) -> &[u8] {
        &self.statement
    }

    fn final_raw_seal(&self) -> &[u8] {
        &self.final_raw_seal
    }

    fn assumption_raw_seal(&self) -> &[u8] {
        &self.assumption_raw_seal
    }
}

fn derive_expected_claims<P, C>(
    profile: &P,
    case9: &C,
) -> Result<BTreeMap<B4NegativeAncestryWitnessIdV1, RecursiveAncestryClaim>>
where
    P: AuthenticatedProfileView,
    C: AuthenticatedCase9View,
{
    let canonical = authenticate_canonical_case9_claim(profile, case9)?;
    let duplicate_claim = derive_duplicate_assumption_claim(&canonical, case9)?;
    let alternate_statement_claim = derive_alternate_statement_claim(profile, case9)?;
    let alternate_program_claim = derive_alternate_program_claim(profile, case9)?;

    let mut claims = BTreeMap::new();
    for witness in [
        B4NegativeAncestryWitnessIdV1::Case9AssumptionLift,
        B4NegativeAncestryWitnessIdV1::Case9FinalResolve,
    ] {
        ensure!(
            claims.insert(witness, canonical.clone()).is_none(),
            "duplicate canonical witness claim dispatch"
        );
    }
    for witness in [
        B4NegativeAncestryWitnessIdV1::AlternateStatementAssumptionLift,
        B4NegativeAncestryWitnessIdV1::AlternateStatementFinalResolve,
        B4NegativeAncestryWitnessIdV1::AlternateStatementFinalJoin,
    ] {
        ensure!(
            claims
                .insert(witness, alternate_statement_claim.clone())
                .is_none(),
            "duplicate alternate-statement witness claim dispatch"
        );
    }
    ensure!(
        claims
            .insert(
                B4NegativeAncestryWitnessIdV1::AlternateProgramLift,
                alternate_program_claim,
            )
            .is_none()
            && claims
                .insert(
                    B4NegativeAncestryWitnessIdV1::DuplicateAssumptionLift,
                    duplicate_claim,
                )
                .is_none(),
        "duplicate negative ancestry witness claim dispatch"
    );
    ensure!(
        claims.len() == 7,
        "negative ancestry claim derivation did not produce exactly seven witness classes"
    );
    Ok(claims)
}

fn authenticate_canonical_case9_claim(
    profile: &impl AuthenticatedProfileView,
    case9: &impl AuthenticatedCase9View,
) -> Result<RecursiveAncestryClaim> {
    let statement = case9.statement();
    let projection = case9.projection();
    let canonical_statement = parse_ergo_statement_v1(statement)?;
    ensure!(
        canonical_statement.profile_id() == profile.profile_id()
            && canonical_statement.program_id() == profile.consumer_program_id(),
        "positive case-9 statement differs from the authenticated profile or consumer program"
    );
    let canonical = derive_empty_assumption_ok_recursive_ancestry_claim(
        &profile.consumer_program_id(),
        statement,
    )?;
    let case9_assumption = &projection
        .assumption_receipt
        .as_ref()
        .context("positive case 9 has no assumption receipt")?
        .claim;
    let case9_final = &projection
        .steps
        .last()
        .context("positive case 9 has no final step")?
        .claim;
    ensure!(
        case9_assumption == &canonical && case9_final == &canonical,
        "positive case-9 assumption and final receipts do not authenticate the canonical OK claim"
    );
    Ok(canonical)
}

fn derive_duplicate_assumption_claim(
    canonical: &RecursiveAncestryClaim,
    case9: &impl AuthenticatedCase9View,
) -> Result<RecursiveAncestryClaim> {
    let projection = case9.projection();
    let statement = case9.statement();
    let head = recursive_ancestry_revealed_head_witness(projection)?;
    let revealed_head = RecursiveAncestryInventoryEntry::Revealed {
        claim_digest: hex::encode(head.claim_digest),
        control_root: hex::encode(head.control_root),
    };
    let one_head = RecursiveAncestrySourceInventory {
        entries: vec![revealed_head.clone()],
    };
    let conditional =
        derive_recursive_ancestry_claim_with_inventory(canonical, statement, &one_head)?;
    ensure!(
        projection
            .steps
            .first()
            .context("positive case 9 has no conditional step")?
            .claim
            == conditional,
        "positive case-9 conditional step differs from the independently reconstructed one-head claim"
    );

    let duplicated = RecursiveAncestrySourceInventory {
        entries: vec![revealed_head.clone(), revealed_head],
    };
    derive_recursive_ancestry_claim_with_inventory(canonical, statement, &duplicated)
}

fn derive_alternate_statement_claim(
    profile: &impl AuthenticatedProfileView,
    case9: &impl AuthenticatedCase9View,
) -> Result<RecursiveAncestryClaim> {
    let statement = case9.statement();
    let canonical_statement = parse_ergo_statement_v1(statement)?;
    let mut alternate_chain_domain = canonical_statement.chain_domain_id();
    alternate_chain_domain[0] ^= 0x01;
    let alternate_statement = ErgoStatementV1::new(
        alternate_chain_domain,
        canonical_statement.profile_id(),
        canonical_statement.program_id(),
        canonical_statement.contract_id(),
        canonical_statement.application_payload(),
    )?
    .encode()?;
    require_only_statement_field_changed(
        statement,
        &alternate_statement,
        ErgoStatementFieldV1::ChainDomainId,
        "alternate statement",
    )?;
    let reparsed_alternate_statement = parse_ergo_statement_v1(&alternate_statement)?;
    ensure!(
        reparsed_alternate_statement.chain_domain_id() == alternate_chain_domain
            && reparsed_alternate_statement.profile_id() == canonical_statement.profile_id()
            && reparsed_alternate_statement.program_id() == canonical_statement.program_id()
            && reparsed_alternate_statement.contract_id() == canonical_statement.contract_id()
            && reparsed_alternate_statement.application_payload()
                == canonical_statement.application_payload(),
        "alternate statement changed a field other than chain-domain byte zero"
    );
    derive_empty_assumption_ok_recursive_ancestry_claim(
        &profile.consumer_program_id(),
        &alternate_statement,
    )
}

fn derive_alternate_program_claim(
    profile: &impl AuthenticatedProfileView,
    case9: &impl AuthenticatedCase9View,
) -> Result<RecursiveAncestryClaim> {
    let statement = case9.statement();
    let canonical_statement = parse_ergo_statement_v1(statement)?;
    let alternate_program_statement = ErgoStatementV1::new(
        canonical_statement.chain_domain_id(),
        canonical_statement.profile_id(),
        profile.alternate_program_id(),
        canonical_statement.contract_id(),
        canonical_statement.application_payload(),
    )?
    .encode()?;
    require_only_statement_field_changed(
        statement,
        &alternate_program_statement,
        ErgoStatementFieldV1::ProgramId,
        "alternate-program statement",
    )?;
    let reparsed_alternate_program = parse_ergo_statement_v1(&alternate_program_statement)?;
    ensure!(
        reparsed_alternate_program.chain_domain_id() == canonical_statement.chain_domain_id()
            && reparsed_alternate_program.profile_id() == canonical_statement.profile_id()
            && reparsed_alternate_program.program_id() == profile.alternate_program_id()
            && reparsed_alternate_program.contract_id() == canonical_statement.contract_id()
            && reparsed_alternate_program.application_payload()
                == canonical_statement.application_payload(),
        "alternate-program statement changed a field other than program ID"
    );
    derive_empty_assumption_ok_recursive_ancestry_claim(
        &profile.alternate_program_id(),
        &alternate_program_statement,
    )
}

fn require_only_statement_field_changed(
    original: &[u8],
    changed: &[u8],
    field: ErgoStatementFieldV1,
    label: &str,
) -> Result<()> {
    let parsed = parse_ergo_statement_v1(original)?;
    let span = parsed.layout()?.span(field);
    ensure!(
        original.len() == changed.len()
            && original[..span.start()] == changed[..span.start()]
            && original[span.end()..] == changed[span.end()..]
            && original[span.start()..span.end()] != changed[span.start()..span.end()],
        "{label} did not change exactly its one authorized statement field"
    );
    Ok(())
}

fn pathless_identity(bytes: &[u8]) -> Result<PathlessByteIdentityV1> {
    ensure!(!bytes.is_empty(), "pathless authority bytes are empty");
    Ok(PathlessByteIdentityV1 {
        byte_length: u64::try_from(bytes.len())?,
        sha256: Sha256::digest(bytes).into(),
    })
}

#[allow(
    dead_code,
    reason = "consumed by the separately approved materialization tranche"
)]
fn pathless_identity_from_contract_identity(
    identity: &B4ContractArtifactIdentityV1,
    label: &str,
) -> Result<PathlessByteIdentityV1> {
    identity
        .validate()
        .with_context(|| format!("{label} has an invalid retained identity"))?;
    let sha256 = hex::decode(&identity.sha256)
        .with_context(|| format!("{label} SHA-256 is not hexadecimal"))?
        .try_into()
        .map_err(|digest: Vec<u8>| {
            anyhow::anyhow!(
                "{label} SHA-256 has {} bytes instead of {DIGEST_BYTES}",
                digest.len()
            )
        })?;
    Ok(PathlessByteIdentityV1 {
        byte_length: identity.byte_length,
        sha256,
    })
}

fn decode_hex32(value: &str, label: &str) -> Result<[u8; DIGEST_BYTES]> {
    let bytes = hex::decode(value).with_context(|| format!("{label} is not hexadecimal"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} is not exactly 32 bytes"))
}

fn validate_finalization_closure(
    entries: &[B4NegativeAncestryWitnessExternalEntryV1<'_>],
    case9: &impl AuthenticatedCase9View,
    source_paths: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    ensure!(
        entries.len() == B4_NEGATIVE_ANCESTRY_BINDING_COUNT,
        "negative ancestry finalization must contain exactly eleven witness entries"
    );
    let mut paths = source_paths.clone();
    for entry in entries {
        bind_external_path(
            &mut paths,
            entry.raw_seal.path,
            false,
            "negative ancestry raw seal",
        )?;
        bind_external_path(
            &mut paths,
            entry.receipt_oracle.path,
            false,
            "negative ancestry receipt oracle",
        )?;
    }
    validate_witness_inventory(entries, case9)?;
    Ok(paths)
}

fn validate_witness_inventory(
    entries: &[B4NegativeAncestryWitnessExternalEntryV1<'_>],
    case9: &impl AuthenticatedCase9View,
) -> Result<()> {
    let layout = compiled_negative_ancestry_witness_layout()?;
    ensure!(
        entries.len() == B4_NEGATIVE_ANCESTRY_BINDING_COUNT && entries.len() == layout.len(),
        "negative ancestry external closure must contain exactly eleven row bindings"
    );
    for (position, (entry, expected)) in entries.iter().zip(&layout).enumerate() {
        ensure!(
            entry.expanded_row == expected.expanded_row
                && entry.raw_seal.path == expected.raw_seal_path
                && entry.receipt_oracle.path == expected.receipt_oracle_path,
            "negative ancestry external row/path order drift at position {position}"
        );
        ensure!(
            entry.raw_seal.bytes.len() == PROOF_BYTES,
            "negative ancestry raw seal has the wrong exact byte length at position {position}"
        );
        ensure!(
            (1..=RECEIPT_ORACLE_MAX_BYTES).contains(&entry.receipt_oracle.bytes.len()),
            "negative ancestry receipt oracle is outside its closed byte bound at position {position}"
        );
    }

    for alias_rows in [
        [141_u16, 142, 153],
        [145, 150, u16::MAX],
        [147, 151, u16::MAX],
    ] {
        let first = entry_for_row(entries, alias_rows[0])?;
        for row in alias_rows[1..]
            .iter()
            .copied()
            .filter(|row| *row != u16::MAX)
        {
            let alias = entry_for_row(entries, row)?;
            ensure!(
                alias.raw_seal.bytes == first.raw_seal.bytes
                    && alias.receipt_oracle.bytes == first.receipt_oracle.bytes,
                "negative ancestry alias class does not contain byte-identical evidence"
            );
        }
    }

    let representatives = [141_u16, 143, 145, 147, 148, 152, 154]
        .map(|row| entry_for_row(entries, row))
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    for left in 0..representatives.len() {
        for right in left + 1..representatives.len() {
            ensure!(
                representatives[left].raw_seal.bytes != representatives[right].raw_seal.bytes
                    && representatives[left].receipt_oracle.bytes
                        != representatives[right].receipt_oracle.bytes,
                "two distinct negative ancestry witnesses alias exact evidence bytes"
            );
        }
    }

    ensure!(
        entry_for_row(entries, 141)?.raw_seal.bytes == case9.assumption_raw_seal(),
        "rows 141/142/153 do not copy the authenticated case-9 assumption receipt"
    );
    ensure!(
        entry_for_row(entries, 143)?.raw_seal.bytes == case9.final_raw_seal(),
        "row 143 does not copy the authenticated case-9 final resolve receipt"
    );
    Ok(())
}

fn entry_for_row<'entries, 'bytes>(
    entries: &'entries [B4NegativeAncestryWitnessExternalEntryV1<'bytes>],
    row: u16,
) -> Result<&'entries B4NegativeAncestryWitnessExternalEntryV1<'bytes>> {
    let mut matches = entries.iter().filter(|entry| entry.expanded_row == row);
    let entry = matches
        .next()
        .with_context(|| format!("negative ancestry external closure lacks row {row}"))?;
    ensure!(
        matches.next().is_none(),
        "negative ancestry external closure duplicates row {row}"
    );
    Ok(entry)
}

fn replay_distinct_witnesses(
    external: &[B4NegativeAncestryWitnessExternalEntryV1<'_>],
    expected_claims: &BTreeMap<B4NegativeAncestryWitnessIdV1, RecursiveAncestryClaim>,
    replay: &impl B4NegativeAncestryWitnessReplayV1,
) -> Result<BTreeMap<B4NegativeAncestryWitnessIdV1, B4VerifiedDirectAncestryReceiptV1>> {
    let layout = compiled_negative_ancestry_witness_layout()?;
    let mut verified = BTreeMap::new();
    for row in [141_u16, 143, 145, 147, 148, 152, 154] {
        let entry = entry_for_row(external, row)?;
        let slot = layout
            .iter()
            .find(|slot| slot.expanded_row == row)
            .with_context(|| format!("compiled ancestry layout lacks representative row {row}"))?;
        let receipt = replay
            .replay(entry.raw_seal.bytes, entry.receipt_oracle.bytes)
            .with_context(|| format!("stock receipt replay failed for representative row {row}"))?;
        let expected_claim = expected_claims
            .get(&slot.witness_id)
            .context("claim dispatch lacks a compiled witness ID")?;
        ensure!(
            &receipt.claim == expected_claim,
            "verified receipt authenticates a claim foreign to its compiled producer recipe at row {row}"
        );
        ensure!(
            receipt.terminal == expected_terminal(slot.witness_id, slot.producer_role)?,
            "verified receipt terminal differs from its compiled producer role at row {row}"
        );
        ensure!(
            receipt.control_root == RISC0_INNER_CONTROL_ROOT_HEX,
            "verified receipt control root differs from the stock profile at row {row}"
        );
        ensure!(
            verified.insert(slot.witness_id, receipt).is_none(),
            "representative replay duplicated a witness ID"
        );
    }
    ensure!(
        verified.len() == 7,
        "negative ancestry replay did not authenticate exactly seven distinct witnesses"
    );
    Ok(verified)
}

fn build_catalog_authority_from_entries(
    prior: &B4NegativeAncestryPriorAuthorityViewV1,
    external_entries: &[B4NegativeAncestryWitnessExternalEntryV1<'_>],
    authenticated: &AuthenticatedSourceClosureV1,
    alternate_guest_elf: &[u8],
    provenance_paths: BTreeSet<String>,
    replay: &impl B4NegativeAncestryWitnessReplayV1,
) -> Result<B4NegativeAncestryWitnessCatalogAuthorityV1> {
    let expected_claims = derive_expected_claims(&authenticated.profile, &authenticated.case9)?;
    let verified = replay_distinct_witnesses(external_entries, &expected_claims, replay)?;
    let layout = compiled_negative_ancestry_witness_layout()?;

    let mut entries = Vec::with_capacity(B4_NEGATIVE_ANCESTRY_BINDING_COUNT);
    let mut retained_entries = Vec::with_capacity(B4_NEGATIVE_ANCESTRY_BINDING_COUNT);
    for (slot, source) in layout.iter().zip(external_entries) {
        let receipt = verified
            .get(&slot.witness_id)
            .context("verified witness map lacks one compiled row binding")?;
        let claim_digest = hex::encode(recursive_ancestry_claim_digest(&receipt.claim)?);
        entries.push(B4NegativeAncestryWitnessEntryV1 {
            expanded_row: slot.expanded_row,
            execution_id: slot.execution_id.clone(),
            base_family: slot.base_family,
            witness_id: slot.witness_id,
            producer_role: slot.producer_role,
            logical_placement: slot.logical_placement,
            recipe: slot.recipe,
            logical_consumer_path: slot.logical_consumer_path.clone(),
            first_public_rejection: slot.first_public_rejection.clone(),
            claim: receipt.claim.clone(),
            claim_digest,
            producer_program_id: receipt.claim.pre_state_digest.clone(),
            terminal: receipt.terminal.clone(),
            control_root: receipt.control_root.clone(),
            raw_seal: B4ContractArtifactIdentityV1::from_bytes(
                source.raw_seal.path,
                B4ContractArtifactEncodingV1::RawBytes,
                source.raw_seal.bytes,
            )?,
            receipt_oracle: B4ContractArtifactIdentityV1::from_bytes(
                source.receipt_oracle.path,
                B4ContractArtifactEncodingV1::RawBytes,
                source.receipt_oracle.bytes,
            )?,
        });
        retained_entries.push(B4RetainedNegativeAncestryWitnessEntryV1 {
            expanded_row: slot.expanded_row,
            raw_seal: source.raw_seal.bytes.to_vec(),
            receipt_oracle: source.receipt_oracle.bytes.to_vec(),
        });
    }

    let expected = Eip0045B4NegativeAncestryWitnessCatalogV1 {
        format: B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_FORMAT.to_owned(),
        format_version: B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_VERSION,
        stage: B4NegativeAncestryWitnessCatalogStageV1::PostGenerationDerived,
        receipt_oracle_codec: RECEIPT_ORACLE_CODEC_V1.to_owned(),
        negative_plan: prior.negative_plan.clone(),
        profile_manifest: authenticated.profile.profile_manifest.clone(),
        alternate_guest_elf: authenticated.profile.alternate_guest_elf.clone(),
        consumer_program_id: hex::encode(authenticated.profile.consumer_program_id),
        alternate_program_id: hex::encode(authenticated.profile.alternate_program_id),
        inner_control_root: RISC0_INNER_CONTROL_ROOT_HEX.to_owned(),
        entries,
    };
    expected.validate()?;
    let canonical_jcs = expected.to_canonical_jcs()?;
    ensure!(
        Eip0045B4NegativeAncestryWitnessCatalogV1::from_canonical_jcs(&canonical_jcs)? == expected,
        "derived negative ancestry catalogue does not round-trip byte-exactly"
    );
    Ok(B4NegativeAncestryWitnessCatalogAuthorityV1 {
        expected,
        canonical_jcs,
        prior_commitments: authenticated.prior_commitments.clone(),
        alternate_guest_elf: alternate_guest_elf.to_vec(),
        retained_entries,
        provenance_paths,
    })
}

fn build_catalog_authority_v2_from_entries(
    prior: &B4NegativeAncestryPriorAuthorityViewV2,
    external_entries: &[B4NegativeAncestryWitnessExternalEntryV1<'_>],
    authenticated: &AuthenticatedSourceClosureV2,
    alternate_guest_elf: &[u8],
    provenance_paths: BTreeSet<String>,
    replay: &impl B4NegativeAncestryWitnessReplayV1,
) -> Result<B4NegativeAncestryWitnessCatalogAuthorityV2> {
    ensure!(
        authenticated.prior_commitments.positive_input_set == prior.positive_input_set
            && authenticated.prior_commitments.positive_generation_set
                == prior.positive_generation_set,
        "authenticated V2 source document identities drifted before finalization"
    );
    ensure!(
        authenticated.prior_provenance_paths == prior.provenance_paths,
        "authenticated V2 source prior provenance closure drifted before finalization"
    );
    ensure!(
        authenticated.positive_provenance_sha256 == prior.positive_provenance_sha256,
        "authenticated V2 source positive provenance digests drifted before finalization"
    );
    let expected_claims = derive_expected_claims(&authenticated.profile, &authenticated.case9)?;
    let verified = replay_distinct_witnesses(external_entries, &expected_claims, replay)?;
    let layout = compiled_negative_ancestry_witness_layout()?;

    let mut entries = Vec::with_capacity(B4_NEGATIVE_ANCESTRY_BINDING_COUNT);
    let mut retained_entries = Vec::with_capacity(B4_NEGATIVE_ANCESTRY_BINDING_COUNT);
    for (slot, source) in layout.iter().zip(external_entries) {
        let receipt = verified
            .get(&slot.witness_id)
            .context("verified V2 witness map lacks one compiled row binding")?;
        let claim_digest = hex::encode(recursive_ancestry_claim_digest(&receipt.claim)?);
        entries.push(B4NegativeAncestryWitnessEntryV1 {
            expanded_row: slot.expanded_row,
            execution_id: slot.execution_id.clone(),
            base_family: slot.base_family,
            witness_id: slot.witness_id,
            producer_role: slot.producer_role,
            logical_placement: slot.logical_placement,
            recipe: slot.recipe,
            logical_consumer_path: slot.logical_consumer_path.clone(),
            first_public_rejection: slot.first_public_rejection.clone(),
            claim: receipt.claim.clone(),
            claim_digest,
            producer_program_id: receipt.claim.pre_state_digest.clone(),
            terminal: receipt.terminal.clone(),
            control_root: receipt.control_root.clone(),
            raw_seal: B4ContractArtifactIdentityV1::from_bytes(
                source.raw_seal.path,
                B4ContractArtifactEncodingV1::RawBytes,
                source.raw_seal.bytes,
            )?,
            receipt_oracle: B4ContractArtifactIdentityV1::from_bytes(
                source.receipt_oracle.path,
                B4ContractArtifactEncodingV1::RawBytes,
                source.receipt_oracle.bytes,
            )?,
        });
        retained_entries.push(B4RetainedNegativeAncestryWitnessEntryV1 {
            expanded_row: slot.expanded_row,
            raw_seal: source.raw_seal.bytes.to_vec(),
            receipt_oracle: source.receipt_oracle.bytes.to_vec(),
        });
    }

    let expected = Eip0045B4NegativeAncestryWitnessCatalogV1 {
        format: B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_FORMAT.to_owned(),
        format_version: B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_VERSION,
        stage: B4NegativeAncestryWitnessCatalogStageV1::PostGenerationDerived,
        receipt_oracle_codec: RECEIPT_ORACLE_CODEC_V1.to_owned(),
        negative_plan: prior.negative_plan.clone(),
        profile_manifest: authenticated.profile.profile_manifest.clone(),
        alternate_guest_elf: authenticated.profile.alternate_guest_elf.clone(),
        consumer_program_id: hex::encode(authenticated.profile.consumer_program_id),
        alternate_program_id: hex::encode(authenticated.profile.alternate_program_id),
        inner_control_root: RISC0_INNER_CONTROL_ROOT_HEX.to_owned(),
        entries,
    };
    expected.validate()?;
    let canonical_jcs = expected.to_canonical_jcs()?;
    ensure!(
        Eip0045B4NegativeAncestryWitnessCatalogV1::from_canonical_jcs(&canonical_jcs)? == expected,
        "V2-derived negative ancestry catalogue does not round-trip byte-exactly"
    );
    Ok(B4NegativeAncestryWitnessCatalogAuthorityV2 {
        expected,
        canonical_jcs,
        prior_commitments: authenticated.prior_commitments.clone(),
        case9_custody: authenticated.case9_custody.clone(),
        alternate_guest_elf: alternate_guest_elf.to_vec(),
        retained_entries,
        prior_provenance_paths: authenticated.prior_provenance_paths.clone(),
        positive_provenance_sha256: authenticated.positive_provenance_sha256.clone(),
        provenance_paths,
    })
}

#[cfg(test)]
fn build_catalog_authority(
    prior: &B4NegativeAncestryPriorAuthorityViewV1,
    external: &B4NegativeAncestryExternalClosureV1<'_>,
    authenticated: &AuthenticatedSourceClosureV1,
    replay: &impl B4NegativeAncestryWitnessReplayV1,
) -> Result<B4NegativeAncestryWitnessCatalogAuthorityV1> {
    let provenance_paths = validate_finalization_closure(
        external.entries,
        &authenticated.case9,
        &authenticated.provenance_paths,
    )?;
    build_catalog_authority_from_entries(
        prior,
        external.entries,
        authenticated,
        external.alternate_guest_elf.bytes,
        provenance_paths,
        replay,
    )
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::cell::RefCell;

    use super::*;

    const HISTORICAL_REFERENCE_CHAIN_DOMAIN_ID: [u8; DIGEST_BYTES] = [0x71; DIGEST_BYTES];
    const HISTORICAL_REFERENCE_APPLICATION_PAYLOAD: &[u8] = b"";

    pub(super) struct OwnedWitnessEntry {
        pub(super) expanded_row: u16,
        pub(super) raw_path: String,
        pub(super) receipt_path: String,
        pub(super) raw_seal: Vec<u8>,
        pub(super) receipt_oracle: Vec<u8>,
    }

    impl OwnedWitnessEntry {
        pub(super) fn external(&self) -> B4NegativeAncestryWitnessExternalEntryV1<'_> {
            B4NegativeAncestryWitnessExternalEntryV1 {
                expanded_row: self.expanded_row,
                raw_seal: B4NegativeAncestryExternalBytesV1 {
                    path: &self.raw_path,
                    bytes: &self.raw_seal,
                },
                receipt_oracle: B4NegativeAncestryExternalBytesV1 {
                    path: &self.receipt_path,
                    bytes: &self.receipt_oracle,
                },
            }
        }
    }

    pub(super) struct FakeReplay {
        pub(super) expected: BTreeMap<(Vec<u8>, Vec<u8>), B4VerifiedDirectAncestryReceiptV1>,
        pub(super) calls: RefCell<Vec<u8>>,
    }

    impl B4NegativeAncestryWitnessReplayV1 for FakeReplay {
        fn replay(
            &self,
            raw_seal: &[u8],
            receipt_oracle: &[u8],
        ) -> Result<B4VerifiedDirectAncestryReceiptV1> {
            self.calls
                .borrow_mut()
                .push(raw_seal.first().copied().unwrap_or_default());
            self.expected
                .get(&(raw_seal.to_vec(), receipt_oracle.to_vec()))
                .cloned()
                .context("fake replay has no exact raw-seal/oracle pair")
        }
    }

    struct FixedNegativeAncestrySourceFixtureV1 {
        prior: crate::b4_campaign_contract::test_support::NegativeAncestryConstructorTestSupportV1,
        alternate_guest_elf: Vec<u8>,
        witnesses: Vec<OwnedWitnessEntry>,
        replay: FakeReplay,
    }

    impl FixedNegativeAncestrySourceFixtureV1 {
        fn exact() -> Result<Self> {
            Self::exact_with_reference_statement(
                HISTORICAL_REFERENCE_CHAIN_DOMAIN_ID,
                HISTORICAL_REFERENCE_APPLICATION_PAYLOAD,
            )
        }

        fn exact_with_reference_statement(
            chain_domain_id: [u8; DIGEST_BYTES],
            application_payload: &[u8],
        ) -> Result<Self> {
            let alternate_raw_seal =
                crate::receipt_oracle_replay::test_support::alternate_raw_seal_bytes();
            let prior = crate::b4_campaign_contract::test_support::
                build_negative_ancestry_constructor_test_support_with_reference_statement(
                    alternate_raw_seal,
                    chain_domain_id,
                    application_payload,
                )?;
            let alternate_receipt =
                crate::receipt_oracle_replay::test_support::alternate_direct_receipt_bytes();
            let final_raw_seal = prior
                .case9_primary_artifacts
                .iter()
                .find(|artifact| artifact.path.ends_with("/candidate-raw-seal.bin"))
                .context("case 9 must retain its final raw seal")?
                .bytes
                .clone();
            ensure!(
                alternate_raw_seal != final_raw_seal,
                "alternate and case-9 final raw seals must remain distinct"
            );

            let evidence = |row: u16| -> (Vec<u8>, Vec<u8>) {
                match row {
                    141 | 142 | 153 => (alternate_raw_seal.to_vec(), alternate_receipt.clone()),
                    143 => (final_raw_seal.clone(), vec![0xc3; 64]),
                    145 | 150 => (vec![0x45; PROOF_BYTES], vec![0xc5; 64]),
                    147 | 151 => (vec![0x47; PROOF_BYTES], vec![0xc7; 64]),
                    148 => (vec![0x48; PROOF_BYTES], vec![0xc8; 64]),
                    152 => (vec![0x52; PROOF_BYTES], vec![0xd2; 64]),
                    154 => (vec![0x54; PROOF_BYTES], vec![0xd4; 64]),
                    _ => unreachable!("unexpected negative-ancestry row {row}"),
                }
            };
            let witnesses = compiled_negative_ancestry_witness_layout()?
                .into_iter()
                .map(|slot| {
                    let (raw_seal, receipt_oracle) = evidence(slot.expanded_row);
                    OwnedWitnessEntry {
                        expanded_row: slot.expanded_row,
                        raw_path: slot.raw_seal_path,
                        receipt_path: slot.receipt_oracle_path,
                        raw_seal,
                        receipt_oracle,
                    }
                })
                .collect();
            let mut fixture = Self {
                prior,
                alternate_guest_elf: crate::test_support::program_binary(0x0000_0093, 0x0000_0013),
                witnesses,
                replay: FakeReplay {
                    expected: BTreeMap::new(),
                    calls: RefCell::new(Vec::new()),
                },
            };
            let source_authority = fixture.with_source_closure(|source| {
                B4NegativeAncestrySourceAuthorityV1::from_source_closure(
                    &fixture.prior.campaign_precommit_authority,
                    &fixture.prior.positive_generation_authority,
                    source,
                )
            })?;
            let claims = derive_expected_claims(
                &source_authority.authenticated.profile,
                &source_authority.authenticated.case9,
            )?;
            let layout = compiled_negative_ancestry_witness_layout()?;
            for row in [141_u16, 143, 145, 147, 148, 152, 154] {
                let slot = layout
                    .iter()
                    .find(|slot| slot.expanded_row == row)
                    .with_context(|| format!("compiled layout omits representative row {row}"))?;
                let source = fixture
                    .witnesses
                    .iter()
                    .find(|entry| entry.expanded_row == row)
                    .with_context(|| format!("fixed fixture omits representative row {row}"))?;
                fixture.replay.expected.insert(
                    (source.raw_seal.clone(), source.receipt_oracle.clone()),
                    B4VerifiedDirectAncestryReceiptV1 {
                        claim: claims
                            .get(&slot.witness_id)
                            .with_context(|| {
                                format!("real source authority omitted the claim for row {row}")
                            })?
                            .clone(),
                        terminal: expected_terminal(slot.witness_id, slot.producer_role)?,
                        control_root: RISC0_INNER_CONTROL_ROOT_HEX.to_owned(),
                    },
                );
            }
            Ok(fixture)
        }

        fn with_source_closure<T>(
            &self,
            use_source: impl FnOnce(B4NegativeAncestrySourceClosureV1<'_>) -> Result<T>,
        ) -> Result<T> {
            let primary_artifacts = self
                .prior
                .case9_primary_artifacts
                .iter()
                .map(|artifact| B4NegativeAncestryExternalBytesV1 {
                    path: &artifact.path,
                    bytes: &artifact.bytes,
                })
                .collect::<Vec<_>>();
            let auxiliary_artifacts = self
                .prior
                .case9_auxiliary_artifacts
                .iter()
                .map(|artifact| B4NegativeAncestryExternalBytesV1 {
                    path: &artifact.path,
                    bytes: &artifact.bytes,
                })
                .collect::<Vec<_>>();
            use_source(B4NegativeAncestrySourceClosureV1 {
                campaign_precommit_jcs: &self.prior.campaign_precommit_jcs,
                positive_input_set: B4NegativeAncestryExternalBytesV1 {
                    path: &self.prior.positive_input_set.path,
                    bytes: &self.prior.positive_input_set.bytes,
                },
                positive_generation_set: B4NegativeAncestryExternalBytesV1 {
                    path: &self.prior.positive_generation_set.path,
                    bytes: &self.prior.positive_generation_set.bytes,
                },
                profile_package: B4NegativeAncestryProfilePackageExternalV1 {
                    profile_manifest: B4NegativeAncestryExternalBytesV1 {
                        path: &self.prior.profile_manifest.path,
                        bytes: &self.prior.profile_manifest.bytes,
                    },
                    profile_algorithm: B4NegativeAncestryExternalBytesV1 {
                        path: &self.prior.profile_algorithm.path,
                        bytes: &self.prior.profile_algorithm.bytes,
                    },
                    profile_constants: B4NegativeAncestryExternalBytesV1 {
                        path: &self.prior.profile_constants.path,
                        bytes: &self.prior.profile_constants.bytes,
                    },
                    consumer_guest_elf: B4NegativeAncestryExternalBytesV1 {
                        path: &self.prior.consumer_guest_elf.path,
                        bytes: &self.prior.consumer_guest_elf.bytes,
                    },
                },
                case9: B4NegativeAncestryCase9ExportV1 {
                    proof_output_manifest_jcs: &self.prior.case9_proof_output_manifest_jcs,
                    primary_artifacts: &primary_artifacts,
                    auxiliary_artifacts: &auxiliary_artifacts,
                },
                alternate_guest_elf: B4NegativeAncestryExternalBytesV1 {
                    path: B4_NEGATIVE_ANCESTRY_ALTERNATE_GUEST_ELF_PATH,
                    bytes: &self.alternate_guest_elf,
                },
            })
        }

        fn with_external_closure<T>(
            &self,
            use_external: impl FnOnce(B4NegativeAncestryExternalClosureV1<'_>) -> Result<T>,
        ) -> Result<T> {
            self.with_source_closure(|source| {
                let entries = self.entries();
                use_external(B4NegativeAncestryExternalClosureV1 {
                    campaign_precommit_jcs: source.campaign_precommit_jcs,
                    positive_input_set: source.positive_input_set,
                    positive_generation_set: source.positive_generation_set,
                    profile_package: source.profile_package,
                    case9: source.case9,
                    alternate_guest_elf: source.alternate_guest_elf,
                    entries: &entries,
                })
            })
        }

        fn verify_public_constructor_routing(&self) -> Result<()> {
            let finalize_error = self.with_source_closure(|source| {
                let primary = source.case9.primary_artifacts;
                let auxiliary = source.case9.auxiliary_artifacts;
                let consumer_guest_elf = source.profile_package.consumer_guest_elf.bytes;
                let alternate_guest_elf = source.alternate_guest_elf.bytes;
                let consumer_program_id =
                    <[u8; DIGEST_BYTES]>::from(compute_image_id(consumer_guest_elf)?);
                let alternate_program_id =
                    <[u8; DIGEST_BYTES]>::from(compute_image_id(alternate_guest_elf)?);
                let source_authority = B4NegativeAncestrySourceAuthorityV1::from_source_closure(
                    &self.prior.campaign_precommit_authority,
                    &self.prior.positive_generation_authority,
                    source,
                )?;

                let case9_source = source_authority.case9_assumption_source();
                ensure!(
                    case9_source.recursive_oracle_borsh() == primary[7].bytes,
                    "case-9 assumption source recursive oracle drifted"
                );
                ensure!(
                    case9_source.assumption_raw_seal() == auxiliary[0].bytes,
                    "case-9 assumption source raw seal drifted"
                );
                ensure!(
                    case9_source.statement() == primary[5].bytes,
                    "case-9 assumption source statement drifted"
                );
                ensure!(
                    case9_source.consumer_program_id() == consumer_program_id,
                    "case-9 assumption source consumer program ID drifted"
                );

                let producer_source = source_authority.producer_source();
                ensure!(
                    producer_source.case9_recursive_oracle_borsh() == primary[7].bytes,
                    "producer source recursive oracle drifted"
                );
                ensure!(
                    producer_source.case9_assumption_raw_seal() == auxiliary[0].bytes,
                    "producer source case-9 assumption raw seal drifted"
                );
                ensure!(
                    producer_source.case9_final_raw_seal() == primary[6].bytes,
                    "producer source case-9 final raw seal drifted"
                );
                ensure!(
                    producer_source.canonical_statement() == primary[5].bytes,
                    "producer source canonical statement drifted"
                );
                ensure!(
                    producer_source.consumer_guest_elf() == consumer_guest_elf,
                    "producer source consumer guest ELF drifted"
                );
                ensure!(
                    producer_source.consumer_program_id() == consumer_program_id,
                    "producer source consumer program ID drifted"
                );
                ensure!(
                    producer_source.alternate_guest_elf() == alternate_guest_elf,
                    "producer source alternate guest ELF drifted"
                );
                ensure!(
                    producer_source.alternate_program_id() == alternate_program_id,
                    "producer source alternate program ID drifted"
                );

                let entries = self.entries();
                source_authority.finalize(&entries).map_or_else(Ok, |_| {
                    bail!("ordinary stock finalization unexpectedly authenticated")
                })
            })?;
            let wrapper_error = self.with_external_closure(|external| {
                B4NegativeAncestryWitnessCatalogAuthorityV1::from_external_closure(
                    &self.prior.campaign_precommit_authority,
                    &self.prior.positive_generation_authority,
                    external,
                )
                .map_or_else(Ok, |_| {
                    bail!("public external-closure constructor unexpectedly authenticated")
                })
            })?;
            let error_chain = format!("{finalize_error:#}");
            ensure!(
                error_chain == format!("{wrapper_error:#}"),
                "ordinary and public constructor error chains differ"
            );
            ensure!(
                error_chain.contains("stock receipt replay failed for representative row 141"),
                "public constructor failed before the first stock replay: {error_chain}"
            );
            ensure!(
                error_chain.contains("verifier-parameter digest differs from the pinned default"),
                "public constructor did not retain the compiled stock verifier boundary: {error_chain}"
            );
            Ok(())
        }

        fn entries(&self) -> Vec<B4NegativeAncestryWitnessExternalEntryV1<'_>> {
            self.witnesses
                .iter()
                .map(OwnedWitnessEntry::external)
                .collect()
        }

        fn derive_authority(&self) -> Result<B4NegativeAncestryWitnessCatalogAuthorityV1> {
            self.with_source_closure(|source| {
                let source_authority = B4NegativeAncestrySourceAuthorityV1::from_source_closure(
                    &self.prior.campaign_precommit_authority,
                    &self.prior.positive_generation_authority,
                    source,
                )?;
                let entries = self.entries();
                source_authority.finalize_with_replay(&entries, &self.replay)
            })
        }
    }

    struct FixedNegativeAncestrySourceFixtureV2 {
        prior: crate::b4_campaign_contract::test_support::TerminalLineageConstructorTestSupportV2,
        alternate_guest_elf: Vec<u8>,
        witnesses: Vec<OwnedWitnessEntry>,
        replay: FakeReplay,
    }

    impl FixedNegativeAncestrySourceFixtureV2 {
        fn exact() -> Result<Self> {
            let prior = crate::b4_campaign_contract::test_support::
                build_terminal_lineage_constructor_test_support_v2()?;
            let case9 = &prior.sources.cases[CASE_9_INDEX];
            let assumption_raw_seal = case9
                .auxiliary_artifacts
                .first()
                .context("V2 case 9 must retain its assumption raw seal")?
                .bytes
                .clone();
            let final_raw_seal = case9
                .primary_artifacts
                .iter()
                .find(|artifact| artifact.path.ends_with("/candidate-raw-seal.bin"))
                .context("V2 case 9 must retain its final raw seal")?
                .bytes
                .clone();
            ensure!(
                assumption_raw_seal != final_raw_seal,
                "V2 assumption and final case-9 raw seals must remain distinct"
            );
            let alternate_receipt =
                crate::receipt_oracle_replay::test_support::alternate_direct_receipt_bytes();
            let evidence = |row: u16| -> (Vec<u8>, Vec<u8>) {
                match row {
                    141 | 142 | 153 => (assumption_raw_seal.clone(), alternate_receipt.clone()),
                    143 => (final_raw_seal.clone(), vec![0xc3; 64]),
                    145 | 150 => (vec![0x45; PROOF_BYTES], vec![0xc5; 64]),
                    147 | 151 => (vec![0x47; PROOF_BYTES], vec![0xc7; 64]),
                    148 => (vec![0x48; PROOF_BYTES], vec![0xc8; 64]),
                    152 => (vec![0x52; PROOF_BYTES], vec![0xd2; 64]),
                    154 => (vec![0x54; PROOF_BYTES], vec![0xd4; 64]),
                    _ => unreachable!("unexpected V2 negative-ancestry row {row}"),
                }
            };
            let witnesses = compiled_negative_ancestry_witness_layout()?
                .into_iter()
                .map(|slot| {
                    let (raw_seal, receipt_oracle) = evidence(slot.expanded_row);
                    OwnedWitnessEntry {
                        expanded_row: slot.expanded_row,
                        raw_path: slot.raw_seal_path,
                        receipt_path: slot.receipt_oracle_path,
                        raw_seal,
                        receipt_oracle,
                    }
                })
                .collect();
            let mut fixture = Self {
                prior,
                alternate_guest_elf: crate::test_support::program_binary(0x0000_0093, 0x0000_0013),
                witnesses,
                replay: FakeReplay {
                    expected: BTreeMap::new(),
                    calls: RefCell::new(Vec::new()),
                },
            };
            let source_authority = fixture.derive_source_authority()?;
            let claims = derive_expected_claims(
                &source_authority.authenticated.profile,
                &source_authority.authenticated.case9,
            )?;
            let layout = compiled_negative_ancestry_witness_layout()?;
            for row in [141_u16, 143, 145, 147, 148, 152, 154] {
                let slot = layout
                    .iter()
                    .find(|slot| slot.expanded_row == row)
                    .with_context(|| {
                        format!("compiled V2 layout omits representative row {row}")
                    })?;
                let source = fixture
                    .witnesses
                    .iter()
                    .find(|entry| entry.expanded_row == row)
                    .with_context(|| format!("fixed V2 fixture omits representative row {row}"))?;
                fixture.replay.expected.insert(
                    (source.raw_seal.clone(), source.receipt_oracle.clone()),
                    B4VerifiedDirectAncestryReceiptV1 {
                        claim: claims
                            .get(&slot.witness_id)
                            .with_context(|| format!("V2 source omitted the claim for row {row}"))?
                            .clone(),
                        terminal: expected_terminal(slot.witness_id, slot.producer_role)?,
                        control_root: RISC0_INNER_CONTROL_ROOT_HEX.to_owned(),
                    },
                );
            }
            Ok(fixture)
        }

        fn source_artifact(
            &self,
            identity: &B4ContractArtifactIdentityV1,
        ) -> Result<&crate::b4_campaign_contract::test_support::OwnedPositiveAuthorityTestArtifactV2>
        {
            self.prior
                .sources
                .nested_input_sources
                .iter()
                .chain(std::iter::once(&self.prior.sources.proof_generator))
                .chain(self.prior.sources.runner_profiles.iter())
                .chain(self.prior.sources.validator_descriptors.iter())
                .find(|artifact| artifact.path == identity.path)
                .with_context(|| format!("V2 fixture lacks retained source {}", identity.path))
        }

        fn with_source_closure<T>(
            &self,
            use_source: impl FnOnce(B4NegativeAncestrySourceClosureV2<'_>) -> Result<T>,
        ) -> Result<T> {
            let campaign_precommit_jcs = self
                .prior
                .campaign_precommit_authority
                .to_canonical_precommit_jcs()?;
            let input =
                parse_positive_input_sources_v2(&self.prior.sources.positive_input_set.bytes)?;
            let profile_manifest = self.source_artifact(&input.profile_manifest)?;
            let profile_algorithm = self.source_artifact(&input.profile_algorithm)?;
            let profile_constants = self.source_artifact(&input.profile_constants)?;
            let consumer_guest_elf = self.source_artifact(&input.guest_elf)?;
            let case9 = &self.prior.sources.cases[CASE_9_INDEX];
            let primary_artifacts = case9
                .primary_artifacts
                .iter()
                .map(|artifact| B4NegativeAncestryExternalBytesV2 {
                    path: &artifact.path,
                    bytes: &artifact.bytes,
                })
                .collect::<Vec<_>>();
            let auxiliary_artifacts = case9
                .auxiliary_artifacts
                .iter()
                .map(|artifact| B4NegativeAncestryExternalBytesV2 {
                    path: &artifact.path,
                    bytes: &artifact.bytes,
                })
                .collect::<Vec<_>>();
            use_source(B4NegativeAncestrySourceClosureV2 {
                campaign_precommit_jcs: &campaign_precommit_jcs,
                positive_input_set: B4NegativeAncestryExternalBytesV2 {
                    path: &self.prior.sources.positive_input_set.path,
                    bytes: &self.prior.sources.positive_input_set.bytes,
                },
                positive_generation_set: B4NegativeAncestryExternalBytesV2 {
                    path: &self.prior.sources.positive_generation_set.path,
                    bytes: &self.prior.sources.positive_generation_set.bytes,
                },
                profile_package: B4NegativeAncestryProfilePackageExternalV2 {
                    profile_manifest: B4NegativeAncestryExternalBytesV2 {
                        path: &profile_manifest.path,
                        bytes: &profile_manifest.bytes,
                    },
                    profile_algorithm: B4NegativeAncestryExternalBytesV2 {
                        path: &profile_algorithm.path,
                        bytes: &profile_algorithm.bytes,
                    },
                    profile_constants: B4NegativeAncestryExternalBytesV2 {
                        path: &profile_constants.path,
                        bytes: &profile_constants.bytes,
                    },
                    consumer_guest_elf: B4NegativeAncestryExternalBytesV2 {
                        path: &consumer_guest_elf.path,
                        bytes: &consumer_guest_elf.bytes,
                    },
                },
                case9: B4NegativeAncestryCase9ExportV2 {
                    proof_output_manifest_jcs: &case9.proof_output_manifest.bytes,
                    primary_artifacts: &primary_artifacts,
                    auxiliary_artifacts: &auxiliary_artifacts,
                },
                alternate_guest_elf: B4NegativeAncestryExternalBytesV2 {
                    path: B4_NEGATIVE_ANCESTRY_ALTERNATE_GUEST_ELF_PATH,
                    bytes: &self.alternate_guest_elf,
                },
            })
        }

        fn derive_source_authority(&self) -> Result<B4NegativeAncestrySourceAuthorityV2> {
            self.with_source_closure(|source| {
                B4NegativeAncestrySourceAuthorityV2::from_source_closure(
                    &self.prior.campaign_precommit_authority,
                    &self.prior.positive_generation_authority,
                    source,
                )
            })
        }

        fn entries(&self) -> Vec<B4NegativeAncestryWitnessExternalEntryV1<'_>> {
            self.witnesses
                .iter()
                .map(OwnedWitnessEntry::external)
                .collect()
        }
    }

    pub(crate) struct B4NegativeAncestryLineageTestSupportV1 {
        pub(crate) prior:
            crate::b4_campaign_contract::test_support::NegativeAncestryConstructorTestSupportV1,
        pub(crate) ancestry: B4NegativeAncestryWitnessCatalogAuthorityV1,
    }

    pub(crate) struct B4NegativeAncestryLineageTestSupportV2 {
        pub(crate) prior:
            crate::b4_campaign_contract::test_support::TerminalLineageConstructorTestSupportV2,
        pub(crate) source: B4NegativeAncestrySourceAuthorityV2,
        pub(crate) ancestry: B4NegativeAncestryWitnessCatalogAuthorityV2,
    }

    pub(crate) fn fixed_negative_ancestry_lineage_test_support_v2()
    -> Result<B4NegativeAncestryLineageTestSupportV2> {
        let fixture = FixedNegativeAncestrySourceFixtureV2::exact()?;
        let source = fixture.derive_source_authority()?;
        source.verify_authority_bindings(
            &fixture.prior.campaign_precommit_authority,
            &fixture.prior.positive_generation_authority,
        )?;
        let entries = fixture.entries();
        let ancestry = source.finalize_with_replay(&entries, &fixture.replay)?;
        ancestry.verify_prior_authority_lineage(
            &fixture.prior.campaign_precommit_authority,
            &fixture.prior.positive_generation_authority,
        )?;
        Ok(B4NegativeAncestryLineageTestSupportV2 {
            prior: fixture.prior,
            source,
            ancestry,
        })
    }

    pub(super) struct B4NegativeAncestrySourceBindingTestSupportV1 {
        pub(super) prior:
            crate::b4_campaign_contract::test_support::NegativeAncestryConstructorTestSupportV1,
        pub(super) source: B4NegativeAncestrySourceAuthorityV1,
    }

    pub(super) fn fixed_negative_ancestry_source_binding_test_support()
    -> Result<B4NegativeAncestrySourceBindingTestSupportV1> {
        let fixture = FixedNegativeAncestrySourceFixtureV1::exact()?;
        let source = fixture.with_source_closure(|source| {
            B4NegativeAncestrySourceAuthorityV1::from_source_closure(
                &fixture.prior.campaign_precommit_authority,
                &fixture.prior.positive_generation_authority,
                source,
            )
        })?;
        Ok(B4NegativeAncestrySourceBindingTestSupportV1 {
            prior: fixture.prior,
            source,
        })
    }

    pub(crate) fn fixed_negative_ancestry_lineage_test_support()
    -> Result<B4NegativeAncestryLineageTestSupportV1> {
        let fixture = FixedNegativeAncestrySourceFixtureV1::exact()?;
        fixture.verify_public_constructor_routing()?;
        let ancestry = fixture.derive_authority()?;
        Ok(B4NegativeAncestryLineageTestSupportV1 {
            prior: fixture.prior,
            ancestry,
        })
    }

    pub(crate) fn fixed_negative_ancestry_lineage_test_support_with_reference_statement(
        chain_domain_id: [u8; DIGEST_BYTES],
        application_payload: &[u8],
    ) -> Result<B4NegativeAncestryLineageTestSupportV1> {
        let fixture = FixedNegativeAncestrySourceFixtureV1::exact_with_reference_statement(
            chain_domain_id,
            application_payload,
        )?;
        fixture.verify_public_constructor_routing()?;
        let ancestry = fixture.derive_authority()?;
        Ok(B4NegativeAncestryLineageTestSupportV1 {
            prior: fixture.prior,
            ancestry,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, sync::OnceLock};

    use serde_json::json;

    use super::{
        test_support::{
            B4NegativeAncestrySourceBindingTestSupportV1, FakeReplay, OwnedWitnessEntry,
            fixed_negative_ancestry_lineage_test_support,
            fixed_negative_ancestry_lineage_test_support_v2,
            fixed_negative_ancestry_source_binding_test_support,
        },
        *,
    };
    use crate::b4_campaign_contract::test_support::{
        NegativeAncestryConstructorTestSupportV1, TerminalLineageAlternateCampaignsV1,
        build_negative_ancestry_constructor_test_support,
        build_terminal_lineage_alternate_campaigns,
    };

    #[test]
    fn v2_postproof_reparse_last_reparser_rejects_only_the_v1_generation_literal() {
        let support = real_prior_support();
        let fixture = case9_source_fixture();
        let (input_jcs, generation_jcs) = promote_v2_postproof_documents(
            &support.positive_input_set.bytes,
            &support.positive_generation_set.bytes,
        );
        let mut substituted =
            crate::canonical::validate_canonical_json_source(&generation_jcs).unwrap();
        substituted["format"] = serde_json::json!("Eip0045B4PositiveGenerationSetV1");
        let substituted = canonical_json_bytes(&substituted).unwrap();

        let error = authenticate_case9_fixture_v2(&input_jcs, &substituted, &fixture)
            .unwrap_err()
            .to_string();
        assert!(error.contains("wrong format identity"), "{error}");
    }

    #[test]
    fn v2_postproof_reparse_case9_recomputes_every_consumed_document_and_physical_identity() {
        fn mutate_generation(source: &[u8], mutation: impl FnOnce(&mut Value)) -> Vec<u8> {
            let mut generation = crate::canonical::validate_canonical_json_source(source).unwrap();
            mutation(&mut generation);
            canonical_json_bytes(&generation).unwrap()
        }

        let support = real_prior_support();
        let exact_fixture = case9_source_fixture();
        let (input_jcs, generation_jcs) = promote_v2_postproof_documents(
            &support.positive_input_set.bytes,
            &support.positive_generation_set.bytes,
        );
        let authenticated =
            authenticate_case9_fixture_v2(&input_jcs, &generation_jcs, &exact_fixture).unwrap();
        assert!(!authenticated.projection.steps.is_empty());
        assert!(!authenticated.statement.is_empty());
        assert_eq!(authenticated.final_raw_seal.len(), PROOF_BYTES);
        assert_eq!(authenticated.assumption_raw_seal.len(), PROOF_BYTES);

        let mut noncanonical_input = input_jcs.clone();
        noncanonical_input.push(b' ');
        assert!(
            authenticate_case9_fixture_v2(&noncanonical_input, &generation_jcs, &exact_fixture)
                .is_err()
        );

        let mut noncanonical_generation = generation_jcs.clone();
        noncanonical_generation.push(b' ');
        assert!(
            authenticate_case9_fixture_v2(&input_jcs, &noncanonical_generation, &exact_fixture)
                .is_err()
        );

        for (field, replacement) in [
            (
                "path",
                serde_json::json!("profiles/risc0-v3-succinct/substituted-manifest.bin"),
            ),
            (
                "byteLength",
                serde_json::json!(support.profile_manifest.bytes.len() + 1),
            ),
            ("sha256", serde_json::json!("00".repeat(32))),
        ] {
            let (mutated_input, rebound_generation) =
                mutate_v2_input_and_rebind_generation(&input_jcs, &generation_jcs, |input| {
                    input["profile"]["manifest"][field] = replacement;
                });
            assert!(
                authenticate_case9_fixture_v2(&mutated_input, &rebound_generation, &exact_fixture)
                    .is_err(),
                "V2 case-9 reparser accepted profile-manifest {field} drift"
            );
        }

        let role_drift = mutate_generation(&generation_jcs, |generation| {
            generation["cases"][CASE_9_INDEX]["artifacts"][0]["role"] =
                serde_json::json!("calibration");
        });
        assert!(authenticate_case9_fixture_v2(&input_jcs, &role_drift, &exact_fixture).is_err());

        let path_drift = mutate_generation(&generation_jcs, |generation| {
            generation["cases"][CASE_9_INDEX]["artifacts"][0]["sourceFile"] =
                serde_json::json!("substituted-ancestry.json");
        });
        assert!(authenticate_case9_fixture_v2(&input_jcs, &path_drift, &exact_fixture).is_err());

        let length_drift = mutate_generation(&generation_jcs, |generation| {
            let length = generation["cases"][CASE_9_INDEX]["artifacts"][0]["byteLength"]
                .as_u64()
                .unwrap();
            generation["cases"][CASE_9_INDEX]["artifacts"][0]["byteLength"] =
                serde_json::json!(length + 1);
        });
        assert!(authenticate_case9_fixture_v2(&input_jcs, &length_drift, &exact_fixture).is_err());

        let digest_drift = mutate_generation(&generation_jcs, |generation| {
            generation["cases"][CASE_9_INDEX]["artifacts"][0]["sha256"] =
                serde_json::json!("00".repeat(32));
        });
        assert!(authenticate_case9_fixture_v2(&input_jcs, &digest_drift, &exact_fixture).is_err());

        let mut manifest_drift = exact_fixture;
        manifest_drift.manifest_jcs.push(b' ');
        assert!(
            authenticate_case9_fixture_v2(&input_jcs, &generation_jcs, &manifest_drift).is_err()
        );

        let mut physical_digest_drift = case9_source_fixture();
        physical_digest_drift.primary[0].bytes[0] ^= 1;
        assert!(
            authenticate_case9_fixture_v2(&input_jcs, &generation_jcs, &physical_digest_drift)
                .is_err()
        );
    }

    #[test]
    fn direct_ancestry_projection_admits_only_the_two_required_lift_exponents() {
        let lift_15 = &crate::b4_terminal::B4_STOCK_CONTROL_LAYOUT[5];
        let lift_16 = &crate::b4_terminal::B4_STOCK_CONTROL_LAYOUT[6];
        let lift_17 = &crate::b4_terminal::B4_STOCK_CONTROL_LAYOUT[7];

        assert_eq!(
            project_verified_stock_terminal(lift_15).unwrap(),
            RecursiveAncestryTerminal::Lift {
                segment_po2: 15,
                control_id: lift_15.control_id.to_owned(),
            }
        );
        assert_eq!(
            project_verified_stock_terminal(lift_16).unwrap(),
            RecursiveAncestryTerminal::Lift {
                segment_po2: 16,
                control_id: lift_16.control_id.to_owned(),
            }
        );
        assert_eq!(
            project_verified_stock_terminal(lift_17)
                .unwrap_err()
                .to_string(),
            "verified direct receipt uses inadmissible ancestry terminal lift-po2-17"
        );
    }

    struct DerivationFixture {
        prior: B4NegativeAncestryPriorAuthorityViewV1,
        authenticated: AuthenticatedSourceClosureV1,
        witnesses: Vec<OwnedWitnessEntry>,
        replay: FakeReplay,
        alternate_elf: Vec<u8>,
    }

    impl DerivationFixture {
        fn external_entries(&self) -> Vec<B4NegativeAncestryWitnessExternalEntryV1<'_>> {
            self.witnesses
                .iter()
                .map(OwnedWitnessEntry::external)
                .collect()
        }
    }

    #[derive(Clone)]
    struct OwnedExternalBytes {
        path: String,
        bytes: Vec<u8>,
    }

    impl OwnedExternalBytes {
        fn external(&self) -> B4NegativeAncestryExternalBytesV1<'_> {
            B4NegativeAncestryExternalBytesV1 {
                path: &self.path,
                bytes: &self.bytes,
            }
        }

        fn external_v2(&self) -> B4NegativeAncestryExternalBytesV2<'_> {
            B4NegativeAncestryExternalBytesV2 {
                path: &self.path,
                bytes: &self.bytes,
            }
        }
    }

    struct Case9SourceFixture {
        prior: B4NegativeAncestryPriorAuthorityViewV1,
        generation_jcs: Vec<u8>,
        manifest_jcs: Vec<u8>,
        primary: Vec<OwnedExternalBytes>,
        auxiliary: Vec<OwnedExternalBytes>,
        profile_id: [u8; DIGEST_BYTES],
        consumer_program_id: [u8; DIGEST_BYTES],
    }

    impl Case9SourceFixture {
        fn primary_views(&self) -> Vec<B4NegativeAncestryExternalBytesV1<'_>> {
            self.primary
                .iter()
                .map(OwnedExternalBytes::external)
                .collect()
        }

        fn auxiliary_views(&self) -> Vec<B4NegativeAncestryExternalBytesV1<'_>> {
            self.auxiliary
                .iter()
                .map(OwnedExternalBytes::external)
                .collect()
        }

        fn primary_views_v2(&self) -> Vec<B4NegativeAncestryExternalBytesV2<'_>> {
            self.primary
                .iter()
                .map(OwnedExternalBytes::external_v2)
                .collect()
        }

        fn auxiliary_views_v2(&self) -> Vec<B4NegativeAncestryExternalBytesV2<'_>> {
            self.auxiliary
                .iter()
                .map(OwnedExternalBytes::external_v2)
                .collect()
        }
    }

    fn real_prior_support()
    -> &'static crate::b4_campaign_contract::test_support::NegativeAncestryConstructorTestSupportV1
    {
        static SUPPORT: OnceLock<
            crate::b4_campaign_contract::test_support::NegativeAncestryConstructorTestSupportV1,
        > = OnceLock::new();
        SUPPORT.get_or_init(|| {
            crate::b4_campaign_contract::test_support::
                build_negative_ancestry_constructor_test_support(
                    crate::receipt_oracle_replay::test_support::alternate_raw_seal_bytes(),
                )
                .expect("real negative-ancestry constructor support")
        })
    }

    fn real_prior_view() -> B4NegativeAncestryPriorAuthorityViewV1 {
        let support = real_prior_support();
        B4NegativeAncestryPriorAuthorityViewV1::from_authorities(
            &support.campaign_precommit_authority,
            &support.positive_generation_authority,
        )
        .expect("real prior authorities must derive the case-9 view")
    }

    fn case9_source_fixture() -> Case9SourceFixture {
        let support = real_prior_support();
        let profile_id = crate::profile::profile_id(&support.profile_manifest.bytes).unwrap();
        let consumer_program_id: [u8; DIGEST_BYTES] =
            compute_image_id(&support.consumer_guest_elf.bytes)
                .unwrap()
                .into();
        Case9SourceFixture {
            prior: real_prior_view(),
            generation_jcs: support.positive_generation_set.bytes.clone(),
            manifest_jcs: support.case9_proof_output_manifest_jcs.clone(),
            primary: support
                .case9_primary_artifacts
                .iter()
                .map(|artifact| OwnedExternalBytes {
                    path: artifact.path.clone(),
                    bytes: artifact.bytes.clone(),
                })
                .collect(),
            auxiliary: support
                .case9_auxiliary_artifacts
                .iter()
                .map(|artifact| OwnedExternalBytes {
                    path: artifact.path.clone(),
                    bytes: artifact.bytes.clone(),
                })
                .collect(),
            profile_id,
            consumer_program_id,
        }
    }

    fn promote_v2_postproof_documents(input_v1: &[u8], generation_v1: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut input = crate::canonical::validate_canonical_json_source(input_v1).unwrap();
        input["format"] = serde_json::json!("Eip0045B4PositiveInputSetV2");
        input["formatVersion"] = serde_json::json!(2);
        let input_jcs = canonical_json_bytes(&input).unwrap();

        let mut generation =
            crate::canonical::validate_canonical_json_source(generation_v1).unwrap();
        generation["format"] = serde_json::json!("Eip0045B4PositiveGenerationSetV2");
        generation["formatVersion"] = serde_json::json!(2);
        generation["inputSetCommitment"]["format"] =
            serde_json::json!("Eip0045B4PositiveInputSetV2");
        generation["inputSetCommitment"]["byteLength"] = serde_json::json!(input_jcs.len());
        generation["inputSetCommitment"]["sha256"] =
            serde_json::json!(hex::encode(Sha256::digest(&input_jcs)));
        (input_jcs, canonical_json_bytes(&generation).unwrap())
    }

    fn authenticate_case9_fixture_v2(
        input_jcs: &[u8],
        generation_jcs: &[u8],
        fixture: &Case9SourceFixture,
    ) -> Result<AuthenticatedCase9V2> {
        let support = real_prior_support();
        let primary = fixture.primary_views_v2();
        let auxiliary = fixture.auxiliary_views_v2();
        let mut paths = BTreeSet::new();
        authenticate_case9_v2(
            input_jcs,
            generation_jcs,
            B4NegativeAncestryProfilePackageExternalV2 {
                profile_manifest: B4NegativeAncestryExternalBytesV2 {
                    path: &support.profile_manifest.path,
                    bytes: &support.profile_manifest.bytes,
                },
                profile_algorithm: B4NegativeAncestryExternalBytesV2 {
                    path: &support.profile_algorithm.path,
                    bytes: &support.profile_algorithm.bytes,
                },
                profile_constants: B4NegativeAncestryExternalBytesV2 {
                    path: &support.profile_constants.path,
                    bytes: &support.profile_constants.bytes,
                },
                consumer_guest_elf: B4NegativeAncestryExternalBytesV2 {
                    path: &support.consumer_guest_elf.path,
                    bytes: &support.consumer_guest_elf.bytes,
                },
            },
            B4NegativeAncestryCase9ExportV2 {
                proof_output_manifest_jcs: &fixture.manifest_jcs,
                primary_artifacts: &primary,
                auxiliary_artifacts: &auxiliary,
            },
            &mut paths,
        )
    }

    fn mutate_v2_input_and_rebind_generation(
        input_jcs: &[u8],
        generation_jcs: &[u8],
        mutation: impl FnOnce(&mut Value),
    ) -> (Vec<u8>, Vec<u8>) {
        let mut input = crate::canonical::validate_canonical_json_source(input_jcs).unwrap();
        mutation(&mut input);
        let input_jcs = canonical_json_bytes(&input).unwrap();
        let mut generation =
            crate::canonical::validate_canonical_json_source(generation_jcs).unwrap();
        generation["inputSetCommitment"]["byteLength"] = serde_json::json!(input_jcs.len());
        generation["inputSetCommitment"]["sha256"] =
            serde_json::json!(hex::encode(Sha256::digest(&input_jcs)));
        (input_jcs, canonical_json_bytes(&generation).unwrap())
    }

    fn authenticate_case9_fixture(fixture: &Case9SourceFixture) -> Result<AuthenticatedCase9V1> {
        let primary = fixture.primary_views();
        let auxiliary = fixture.auxiliary_views();
        let mut paths = fixture.prior.provenance_paths.clone();
        authenticate_case9(
            &fixture.prior,
            &fixture.generation_jcs,
            B4NegativeAncestryCase9ExportV1 {
                proof_output_manifest_jcs: &fixture.manifest_jcs,
                primary_artifacts: &primary,
                auxiliary_artifacts: &auxiliary,
            },
            fixture.profile_id,
            fixture.consumer_program_id,
            &mut paths,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture holds the complete external source closure in one lifetime and exposes twelve single-source mutations"
    )]
    fn authenticate_complete_source_fixture(
        mutation: Option<usize>,
    ) -> Result<AuthenticatedSourceClosureV1> {
        let support = real_prior_support();
        let prior = real_prior_view();
        let mut campaign_precommit_jcs = support.campaign_precommit_jcs.clone();
        let mut input_jcs = support.positive_input_set.bytes.clone();
        let mut generation_jcs = support.positive_generation_set.bytes.clone();
        let mut manifest = support.profile_manifest.bytes.clone();
        let mut algorithm = support.profile_algorithm.bytes.clone();
        let mut constants = support.profile_constants.bytes.clone();
        let mut consumer_elf = support.consumer_guest_elf.bytes.clone();
        let mut case9_manifest_jcs = support.case9_proof_output_manifest_jcs.clone();
        let mut primary = support
            .case9_primary_artifacts
            .iter()
            .map(|artifact| OwnedExternalBytes {
                path: artifact.path.clone(),
                bytes: artifact.bytes.clone(),
            })
            .collect::<Vec<_>>();
        let mut auxiliary = support
            .case9_auxiliary_artifacts
            .iter()
            .map(|artifact| OwnedExternalBytes {
                path: artifact.path.clone(),
                bytes: artifact.bytes.clone(),
            })
            .collect::<Vec<_>>();
        let mut alternate_elf = crate::test_support::program_binary(0x0000_0093, 0x0000_0013);
        ensure!(
            compute_image_id(&alternate_elf).unwrap() != compute_image_id(&consumer_elf).unwrap(),
            "test alternate program unexpectedly aliases consumer"
        );

        match mutation {
            None => {}
            Some(0) => campaign_precommit_jcs.push(b' '),
            Some(1) => input_jcs.push(b' '),
            Some(2) => generation_jcs.push(b' '),
            Some(3) => manifest[0] ^= 1,
            Some(4) => algorithm[0] ^= 1,
            Some(5) => constants[0] ^= 1,
            Some(6) => consumer_elf[0] ^= 1,
            Some(7) => alternate_elf[0] ^= 1,
            Some(8) => case9_manifest_jcs.push(b'\n'),
            Some(9) => primary[0].bytes[0] ^= 1,
            Some(10) => auxiliary[0].bytes[0] ^= 1,
            Some(11) => primary[7].path = primary[6].path.clone(),
            Some(other) => panic!("unknown source mutation {other}"),
        }

        let primary_views = primary
            .iter()
            .map(OwnedExternalBytes::external)
            .collect::<Vec<_>>();
        let auxiliary_views = auxiliary
            .iter()
            .map(OwnedExternalBytes::external)
            .collect::<Vec<_>>();
        let external = B4NegativeAncestrySourceClosureV1 {
            campaign_precommit_jcs: &campaign_precommit_jcs,
            positive_input_set: B4NegativeAncestryExternalBytesV1 {
                path: &support.positive_input_set.path,
                bytes: &input_jcs,
            },
            positive_generation_set: B4NegativeAncestryExternalBytesV1 {
                path: &support.positive_generation_set.path,
                bytes: &generation_jcs,
            },
            profile_package: B4NegativeAncestryProfilePackageExternalV1 {
                profile_manifest: B4NegativeAncestryExternalBytesV1 {
                    path: &support.profile_manifest.path,
                    bytes: &manifest,
                },
                profile_algorithm: B4NegativeAncestryExternalBytesV1 {
                    path: &support.profile_algorithm.path,
                    bytes: &algorithm,
                },
                profile_constants: B4NegativeAncestryExternalBytesV1 {
                    path: &support.profile_constants.path,
                    bytes: &constants,
                },
                consumer_guest_elf: B4NegativeAncestryExternalBytesV1 {
                    path: &support.consumer_guest_elf.path,
                    bytes: &consumer_elf,
                },
            },
            case9: B4NegativeAncestryCase9ExportV1 {
                proof_output_manifest_jcs: &case9_manifest_jcs,
                primary_artifacts: &primary_views,
                auxiliary_artifacts: &auxiliary_views,
            },
            alternate_guest_elf: B4NegativeAncestryExternalBytesV1 {
                path: B4_NEGATIVE_ANCESTRY_ALTERNATE_GUEST_ELF_PATH,
                bytes: &alternate_elf,
            },
        };
        authenticate_source_closure(&prior, &external)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture constructs all seven distinct claim classes and eleven exact row bindings together"
    )]
    fn derivation_fixture() -> DerivationFixture {
        let profile_id = [0x22; DIGEST_BYTES];
        let consumer_program_id = [0x44; DIGEST_BYTES];
        let alternate_program_id = [0x55; DIGEST_BYTES];
        let statement = ErgoStatementV1::new(
            [0x11; DIGEST_BYTES],
            profile_id,
            consumer_program_id,
            [0x33; DIGEST_BYTES],
            b"authority fixture payload",
        )
        .unwrap()
        .encode()
        .unwrap();
        let assumption_raw_seal = vec![0x11; PROOF_BYTES];
        let conditional_raw_seal = vec![0x22; PROOF_BYTES];
        let final_raw_seal = vec![0x33; PROOF_BYTES];
        let mut projection =
            crate::recursive_ancestry::tests::synthetic_terminal_resolve(&statement);
        projection
            .assumption_receipt
            .as_mut()
            .unwrap()
            .raw_seal
            .sha256 = hex::encode(Sha256::digest(&assumption_raw_seal));
        projection.steps[0].raw_seal.sha256 = hex::encode(Sha256::digest(&conditional_raw_seal));
        projection.steps[1].raw_seal.sha256 = hex::encode(Sha256::digest(&final_raw_seal));
        let case9 = AuthenticatedCase9V1 {
            projection,
            statement,
            final_raw_seal,
            assumption_raw_seal,
        };

        let manifest_bytes = include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin");
        let alternate_elf = b"synthetic alternate guest ELF".to_vec();
        let profile = AuthenticatedProfileV1 {
            profile_manifest: B4ContractArtifactIdentityV1::from_bytes(
                B4_NEGATIVE_ANCESTRY_PROFILE_MANIFEST_PATH,
                B4ContractArtifactEncodingV1::RawBytes,
                manifest_bytes,
            )
            .unwrap(),
            consumer_program_id,
            alternate_guest_elf: B4ContractArtifactIdentityV1::from_bytes(
                B4_NEGATIVE_ANCESTRY_ALTERNATE_GUEST_ELF_PATH,
                B4ContractArtifactEncodingV1::RawBytes,
                &alternate_elf,
            )
            .unwrap(),
            alternate_program_id,
            profile_id,
        };
        let claims = derive_expected_claims(&profile, &case9).unwrap();
        let layout = compiled_negative_ancestry_witness_layout().unwrap();
        let token_for_row = |row| match row {
            141 | 142 | 153 => 0x11,
            143 => 0x33,
            145 | 150 => 0x45,
            147 | 151 => 0x47,
            148 => 0x48,
            152 => 0x52,
            154 => 0x54,
            _ => unreachable!(),
        };
        let witnesses = layout
            .iter()
            .map(|slot| {
                let token = token_for_row(slot.expanded_row);
                OwnedWitnessEntry {
                    expanded_row: slot.expanded_row,
                    raw_path: slot.raw_seal_path.clone(),
                    receipt_path: slot.receipt_oracle_path.clone(),
                    raw_seal: vec![token; PROOF_BYTES],
                    receipt_oracle: vec![token ^ 0x80; 64],
                }
            })
            .collect::<Vec<_>>();
        let mut expected = BTreeMap::new();
        for row in [141_u16, 143, 145, 147, 148, 152, 154] {
            let slot = layout.iter().find(|slot| slot.expanded_row == row).unwrap();
            let source = witnesses
                .iter()
                .find(|entry| entry.expanded_row == row)
                .unwrap();
            expected.insert(
                (source.raw_seal.clone(), source.receipt_oracle.clone()),
                B4VerifiedDirectAncestryReceiptV1 {
                    claim: claims.get(&slot.witness_id).unwrap().clone(),
                    terminal: expected_terminal(slot.witness_id, slot.producer_role).unwrap(),
                    control_root: RISC0_INNER_CONTROL_ROOT_HEX.to_owned(),
                },
            );
        }

        let prior = real_prior_view();
        let authenticated = AuthenticatedSourceClosureV1 {
            prior_commitments: B4NegativeAncestryPriorCommitmentsV1 {
                campaign_precommit: pathless_identity(&prior.campaign_precommit_jcs).unwrap(),
                positive_input_set: pathless_identity_from_contract_identity(
                    &prior.positive_input_set,
                    "positive input set",
                )
                .unwrap(),
                positive_generation_set: pathless_identity_from_contract_identity(
                    &prior.positive_generation_set,
                    "positive generation set",
                )
                .unwrap(),
            },
            profile,
            case9,
            provenance_paths: BTreeSet::new(),
        };
        DerivationFixture {
            prior,
            authenticated,
            witnesses,
            replay: FakeReplay {
                expected,
                calls: RefCell::new(Vec::new()),
            },
            alternate_elf,
        }
    }

    fn dummy_external_closure<'a>(
        entries: &'a [B4NegativeAncestryWitnessExternalEntryV1<'a>],
        alternate_elf: &'a [u8],
    ) -> B4NegativeAncestryExternalClosureV1<'a> {
        let unused = B4NegativeAncestryExternalBytesV1 {
            path: "unused/source.bin",
            bytes: b"x",
        };
        B4NegativeAncestryExternalClosureV1 {
            campaign_precommit_jcs: b"{}",
            positive_input_set: unused,
            positive_generation_set: unused,
            profile_package: B4NegativeAncestryProfilePackageExternalV1 {
                profile_manifest: unused,
                profile_algorithm: unused,
                profile_constants: unused,
                consumer_guest_elf: unused,
            },
            case9: B4NegativeAncestryCase9ExportV1 {
                proof_output_manifest_jcs: b"{}",
                primary_artifacts: &[],
                auxiliary_artifacts: &[],
            },
            alternate_guest_elf: B4NegativeAncestryExternalBytesV1 {
                path: B4_NEGATIVE_ANCESTRY_ALTERNATE_GUEST_ELF_PATH,
                bytes: alternate_elf,
            },
            entries,
        }
    }

    fn source_authority_from_derivation_fixture(
        fixture: &DerivationFixture,
    ) -> B4NegativeAncestrySourceAuthorityV1 {
        B4NegativeAncestrySourceAuthorityV1 {
            prior: fixture.prior.clone(),
            authenticated: fixture.authenticated.clone(),
            consumer_guest_elf: b"synthetic consumer ELF".to_vec(),
            alternate_guest_elf: fixture.alternate_elf.clone(),
            case9_recursive_oracle_borsh: b"synthetic recursive oracle".to_vec(),
        }
    }

    pub(super) fn publication_authority_fixture() -> B4NegativeAncestryWitnessCatalogAuthorityV1 {
        let fixture = derivation_fixture();
        let entries = fixture.external_entries();
        source_authority_from_derivation_fixture(&fixture)
            .finalize_with_replay(&entries, &fixture.replay)
            .expect("publication authority fixture must authenticate")
    }

    #[test]
    fn public_constructor_requires_both_prior_authorities_and_external_closure() {
        let source_constructor: for<'a> fn(
            &'a B4CampaignPrecommitAuthorityV1,
            &'a B4PositiveGenerationAuthorityV1,
            B4NegativeAncestrySourceClosureV1<'a>,
        ) -> Result<B4NegativeAncestrySourceAuthorityV1> =
            B4NegativeAncestrySourceAuthorityV1::from_source_closure;
        let constructor: for<'a> fn(
            &'a B4CampaignPrecommitAuthorityV1,
            &'a B4PositiveGenerationAuthorityV1,
            B4NegativeAncestryExternalClosureV1<'a>,
        )
            -> Result<B4NegativeAncestryWitnessCatalogAuthorityV1> =
            B4NegativeAncestryWitnessCatalogAuthorityV1::from_external_closure;
        std::hint::black_box(source_constructor);
        std::hint::black_box(constructor);
    }

    fn source_binding_support() -> &'static B4NegativeAncestrySourceBindingTestSupportV1 {
        static SUPPORT: OnceLock<B4NegativeAncestrySourceBindingTestSupportV1> = OnceLock::new();
        SUPPORT.get_or_init(|| {
            fixed_negative_ancestry_source_binding_test_support()
                .expect("fixed negative-ancestry source binding support")
        })
    }

    fn source_binding_alternate_positive_support()
    -> &'static NegativeAncestryConstructorTestSupportV1 {
        static SUPPORT: OnceLock<NegativeAncestryConstructorTestSupportV1> = OnceLock::new();
        SUPPORT.get_or_init(|| {
            let mut distinct_case9_raw_seal =
                crate::receipt_oracle_replay::test_support::alternate_raw_seal_bytes().to_vec();
            distinct_case9_raw_seal[0] ^= 1;
            build_negative_ancestry_constructor_test_support(&distinct_case9_raw_seal)
                .expect("separately valid alternate negative-ancestry positive authority")
        })
    }

    fn source_binding_alternate_campaigns() -> &'static TerminalLineageAlternateCampaignsV1 {
        static SUPPORT: OnceLock<TerminalLineageAlternateCampaignsV1> = OnceLock::new();
        SUPPORT.get_or_init(|| {
            build_terminal_lineage_alternate_campaigns(
                crate::receipt_oracle_replay::test_support::alternate_raw_seal_bytes(),
            )
            .expect("separately valid alternate negative-ancestry campaigns")
        })
    }

    #[test]
    fn source_authority_binding_verifier_accepts_originating_authorities() {
        let support = source_binding_support();
        let verifier: fn(
            &B4NegativeAncestrySourceAuthorityV1,
            &B4CampaignPrecommitAuthorityV1,
            &B4PositiveGenerationAuthorityV1,
        ) -> Result<()> = B4NegativeAncestrySourceAuthorityV1::verify_authority_bindings;
        std::hint::black_box(verifier);

        support
            .source
            .verify_authority_bindings(
                &support.prior.campaign_precommit_authority,
                &support.prior.positive_generation_authority,
            )
            .expect("originating negative-ancestry source authorities must rebind");
    }

    #[test]
    fn source_authority_binding_verifier_rejects_each_isolated_foreign_authority_component() {
        let support = source_binding_support();
        let campaign = &support.prior.campaign_precommit_authority;
        let positive = &support.prior.positive_generation_authority;
        let alternate_campaigns = source_binding_alternate_campaigns();
        let alternate_positive =
            &source_binding_alternate_positive_support().positive_generation_authority;

        assert_eq!(
            alternate_campaigns.different_executor.precommit().input_set,
            *positive.input_set()
        );
        assert_eq!(alternate_positive.input_set(), positive.input_set());
        assert_ne!(
            alternate_positive.generation_set(),
            positive.generation_set()
        );
        assert_ne!(
            alternate_positive.cases()[CASE_9_INDEX],
            positive.cases()[CASE_9_INDEX]
        );
        assert_ne!(
            alternate_positive.provenance_sha256(),
            positive.provenance_sha256()
        );

        let error = support
            .source
            .verify_authority_bindings(&alternate_campaigns.different_executor, positive)
            .expect_err("foreign campaign precommit must not rebind");
        assert!(format!("{error:#}").contains("campaign precommit"));

        let mut foreign_input = support.source.clone();
        foreign_input.prior.positive_input_set = alternate_campaigns
            .different_input
            .precommit()
            .input_set
            .clone();
        assert_ne!(
            foreign_input.prior.positive_input_set,
            *positive.input_set()
        );
        let error = foreign_input
            .verify_authority_bindings(campaign, positive)
            .expect_err("foreign positive input must not rebind");
        assert!(format!("{error:#}").contains("positive input identity"));

        let error = support
            .source
            .verify_authority_bindings(campaign, alternate_positive)
            .expect_err("foreign positive generation must not rebind");
        assert!(format!("{error:#}").contains("positive generation identity"));

        let mut foreign_case9 = support.source.clone();
        foreign_case9.prior.case9 = alternate_positive.cases()[CASE_9_INDEX];
        let error = foreign_case9
            .verify_authority_bindings(campaign, positive)
            .expect_err("foreign positive case 9 must not rebind");
        assert!(format!("{error:#}").contains("positive case-9 custody"));

        let mut foreign_provenance = support.source.clone();
        foreign_provenance.prior.positive_provenance_sha256 =
            alternate_positive.provenance_sha256().clone();
        let error = foreign_provenance
            .verify_authority_bindings(campaign, positive)
            .expect_err("foreign positive provenance must not rebind");
        assert!(format!("{error:#}").contains("positive provenance digests"));
    }

    #[test]
    fn source_authority_binding_verifier_rejects_each_isolated_retained_binding_drift() {
        let support = source_binding_support();
        let campaign = &support.prior.campaign_precommit_authority;
        let positive = &support.prior.positive_generation_authority;

        let mut foreign_negative_plan = support.source.clone();
        foreign_negative_plan
            .prior
            .negative_plan
            .sha256
            .replace_range(0..1, "0");
        if foreign_negative_plan.prior.negative_plan.sha256
            == support.source.prior.negative_plan.sha256
        {
            foreign_negative_plan
                .prior
                .negative_plan
                .sha256
                .replace_range(0..1, "1");
        }
        let error = foreign_negative_plan
            .verify_authority_bindings(campaign, positive)
            .expect_err("foreign retained negative plan must not rebind");
        assert!(format!("{error:#}").contains("negative plan"));

        let mut foreign_prior_paths = support.source.clone();
        assert!(
            foreign_prior_paths
                .prior
                .provenance_paths
                .insert("foreign/retained-provenance.bin".to_owned())
        );
        let error = foreign_prior_paths
            .verify_authority_bindings(campaign, positive)
            .expect_err("foreign retained provenance paths must not rebind");
        assert!(format!("{error:#}").contains("provenance paths"));

        let mut incomplete_authenticated_paths = support.source.clone();
        let removed_path = incomplete_authenticated_paths
            .prior
            .provenance_paths
            .iter()
            .next()
            .cloned()
            .expect("retained prior provenance path");
        assert!(
            incomplete_authenticated_paths
                .authenticated
                .provenance_paths
                .remove(&removed_path)
        );
        let error = incomplete_authenticated_paths
            .verify_authority_bindings(campaign, positive)
            .expect_err("incomplete authenticated provenance closure must not rebind");
        assert!(format!("{error:#}").contains("provenance paths"));

        let mut foreign_commitments = support.source.clone();
        foreign_commitments
            .authenticated
            .prior_commitments
            .campaign_precommit
            .sha256[0] ^= 1;
        let error = foreign_commitments
            .verify_authority_bindings(campaign, positive)
            .expect_err("foreign authenticated prior commitments must not rebind");
        assert!(format!("{error:#}").contains("prior commitments"));
    }

    #[test]
    fn retained_prior_authority_lineage_accepts_originating_authorities_and_rejects_each_commitment_drift()
     {
        let support = fixed_negative_ancestry_lineage_test_support().unwrap();
        support
            .ancestry
            .verify_prior_authority_lineage(
                &support.prior.campaign_precommit_authority,
                &support.prior.positive_generation_authority,
            )
            .unwrap();

        let mutations: [fn(&mut B4NegativeAncestryPriorCommitmentsV1); 3] = [
            |commitments: &mut B4NegativeAncestryPriorCommitmentsV1| {
                commitments.campaign_precommit.byte_length += 1;
            },
            |commitments: &mut B4NegativeAncestryPriorCommitmentsV1| {
                commitments.positive_input_set.sha256[0] ^= 1;
            },
            |commitments: &mut B4NegativeAncestryPriorCommitmentsV1| {
                commitments.positive_generation_set.byte_length += 1;
            },
        ];
        for mutate in mutations {
            let mut drifted = support.ancestry.clone();
            mutate(&mut drifted.prior_commitments);
            assert!(
                drifted
                    .verify_prior_authority_lineage(
                        &support.prior.campaign_precommit_authority,
                        &support.prior.positive_generation_authority,
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn source_authority_then_finalization_routes_the_closed_real_prior_fixture() {
        let support = fixed_negative_ancestry_lineage_test_support().unwrap();
        support
            .ancestry
            .verify_prior_authority_lineage(
                &support.prior.campaign_precommit_authority,
                &support.prior.positive_generation_authority,
            )
            .unwrap();
        assert_eq!(
            support
                .ancestry
                .catalog()
                .entries
                .iter()
                .map(|entry| entry.expanded_row)
                .collect::<Vec<_>>(),
            compiled_negative_ancestry_witness_layout()
                .unwrap()
                .into_iter()
                .map(|slot| slot.expanded_row)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn candidate_is_only_a_comparison_input_after_authority_exists() {
        let verifier: fn(&B4NegativeAncestryWitnessCatalogAuthorityV1, &[u8]) -> Result<()> =
            B4NegativeAncestryWitnessCatalogAuthorityV1::verify_candidate_jcs;
        std::hint::black_box(verifier);
    }

    #[test]
    fn pathless_measurement_is_length_and_byte_sensitive() {
        let base = pathless_identity(b"authority").unwrap();
        assert_ne!(base, pathless_identity(b"authority!").unwrap());
        assert_ne!(base, pathless_identity(b"authoritx").unwrap());
        assert!(pathless_identity(b"").is_err());
    }

    #[test]
    fn physical_path_closure_rejects_duplicates_and_ancestry_aliases() {
        let mut paths = BTreeSet::from(["root/existing.bin".to_owned()]);
        assert!(bind_external_path(&mut paths, "root/existing.bin", false, "new source").is_err());
        assert!(bind_external_path(&mut paths, "root", false, "new source").is_err());
        assert!(
            bind_external_path(&mut paths, "root/existing.bin/child", false, "new source").is_err()
        );
        assert!(bind_external_path(&mut paths, "../escape", false, "new source").is_err());
        assert!(bind_external_path(&mut paths, "root/existing.bin", true, "prior replay").is_ok());
    }

    #[test]
    fn witness_cardinality_is_bounded_before_any_source_authentication_or_path_walk() {
        let fixture = derivation_fixture();
        for mutation in 0..2 {
            let mut entries = fixture.external_entries();
            if mutation == 0 {
                entries.pop();
            } else {
                entries.push(entries[0]);
            }
            let source = source_authority_from_derivation_fixture(&fixture);
            let error = source
                .finalize_with_replay(&entries, &fixture.replay)
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "negative ancestry finalization must contain exactly eleven witness entries"
            );
        }
        assert!(fixture.replay.calls.borrow().is_empty());
    }

    #[test]
    fn witness_duplicate_and_path_alias_fail_before_any_receipt_replay() {
        for mutation in 0..3 {
            let mut fixture = derivation_fixture();
            fixture
                .authenticated
                .provenance_paths
                .insert("retained/source.bin".to_owned());
            match mutation {
                0 => fixture.witnesses[1].expanded_row = fixture.witnesses[0].expanded_row,
                1 => fixture.witnesses[1].receipt_path = fixture.witnesses[0].raw_path.clone(),
                2 => fixture.witnesses[1].receipt_path = "retained/source.bin".to_owned(),
                _ => unreachable!(),
            }
            let entries = fixture.external_entries();
            let source = source_authority_from_derivation_fixture(&fixture);
            assert!(
                source
                    .finalize_with_replay(&entries, &fixture.replay)
                    .is_err(),
                "finalization mutation {mutation} unexpectedly authenticated"
            );
            assert!(fixture.replay.calls.borrow().is_empty());
        }
    }

    #[test]
    fn recursive_case9_layout_remains_exactly_eight_roles() {
        assert_eq!(RECURSIVE_POSITIVE_ARTIFACT_LAYOUT.len(), 8);
        assert_eq!(
            RECURSIVE_POSITIVE_ARTIFACT_LAYOUT[0],
            (B4PositiveArtifactRole::Ancestry, "candidate-ancestry.json")
        );
        assert_eq!(
            RECURSIVE_POSITIVE_ARTIFACT_LAYOUT[7],
            (
                B4PositiveArtifactRole::ReceiptOracle,
                "candidate-recursive-oracle.borsh"
            )
        );
        for (role, _) in RECURSIVE_POSITIVE_ARTIFACT_LAYOUT {
            let _ = positive_artifact_role_name(role);
            let _ = positive_artifact_encoding(role);
            validate_positive_artifact_length(
                CASE_9_INDEX,
                role,
                match role {
                    B4PositiveArtifactRole::Ancestry | B4PositiveArtifactRole::Calibration => 2,
                    B4PositiveArtifactRole::ClaimDigest
                    | B4PositiveArtifactRole::ControlId
                    | B4PositiveArtifactRole::ImageId => 32,
                    B4PositiveArtifactRole::Journal => 159,
                    B4PositiveArtifactRole::RawSeal => crate::constants::PROOF_BYTES as u64,
                    B4PositiveArtifactRole::ReceiptOracle => 1,
                    B4PositiveArtifactRole::Metadata => unreachable!(),
                },
            )
            .unwrap();
        }
    }

    #[test]
    fn opaque_authority_replays_exactly_seven_representatives_in_fixed_order() {
        let fixture = derivation_fixture();
        let entries = fixture.external_entries();
        let source = source_authority_from_derivation_fixture(&fixture);
        let authority = source
            .finalize_with_replay(&entries, &fixture.replay)
            .unwrap();

        assert_eq!(
            fixture.replay.calls.borrow().as_slice(),
            [0x11, 0x33, 0x45, 0x47, 0x48, 0x52, 0x54]
        );
        assert_eq!(authority.catalog().entries.len(), 11);
        assert_eq!(authority.retained_entries().len(), 11);
        authority
            .verify_candidate_jcs(authority.canonical_catalog_jcs())
            .unwrap();
    }

    #[test]
    fn alias_or_order_failure_happens_before_any_receipt_replay() {
        for mutation in 0..2 {
            let mut fixture = derivation_fixture();
            if mutation == 0 {
                fixture
                    .witnesses
                    .iter_mut()
                    .find(|entry| entry.expanded_row == 142)
                    .unwrap()
                    .raw_seal[0] ^= 1;
            } else {
                fixture.witnesses.swap(0, 1);
            }
            let entries = fixture.external_entries();
            let source = source_authority_from_derivation_fixture(&fixture);
            assert!(
                source
                    .finalize_with_replay(&entries, &fixture.replay)
                    .is_err()
            );
            assert!(fixture.replay.calls.borrow().is_empty());
        }
    }

    #[test]
    fn valid_receipt_from_a_foreign_claim_class_is_rejected() {
        let mut fixture = derivation_fixture();
        let canonical = fixture
            .replay
            .expected
            .values()
            .find(|receipt| {
                receipt.claim
                    == fixture
                        .authenticated
                        .case9
                        .projection
                        .steps
                        .last()
                        .unwrap()
                        .claim
            })
            .unwrap()
            .claim
            .clone();
        let foreign = fixture
            .replay
            .expected
            .iter_mut()
            .find(|((raw, _), _)| raw[0] == 0x45)
            .unwrap()
            .1;
        foreign.claim = canonical;
        let entries = fixture.external_entries();
        let source = source_authority_from_derivation_fixture(&fixture);

        assert!(
            source
                .finalize_with_replay(&entries, &fixture.replay)
                .is_err()
        );
        assert_eq!(fixture.replay.calls.borrow().as_slice(), [0x11, 0x33, 0x45]);
    }

    #[test]
    fn structurally_valid_coordinated_candidate_rewrite_cannot_replace_authority() {
        let fixture = derivation_fixture();
        let entries = fixture.external_entries();
        let source = source_authority_from_derivation_fixture(&fixture);
        let authority = source
            .finalize_with_replay(&entries, &fixture.replay)
            .unwrap();

        let mut candidate = authority.catalog().clone();
        for entry in candidate
            .entries
            .iter_mut()
            .filter(|entry| matches!(entry.expanded_row, 141 | 142 | 153))
        {
            entry.raw_seal.sha256 = "ab".repeat(DIGEST_BYTES);
            entry.receipt_oracle.sha256 = "ac".repeat(DIGEST_BYTES);
        }
        candidate.validate().unwrap();
        let rewritten = candidate.to_canonical_jcs().unwrap();
        assert!(authority.verify_candidate_jcs(&rewritten).is_err());

        let pretty = serde_json::to_vec_pretty(&json!(authority.catalog())).unwrap();
        assert!(authority.verify_candidate_jcs(&pretty).is_err());
        let mut trailing = authority.canonical_catalog_jcs().to_vec();
        trailing.push(b'\n');
        assert!(authority.verify_candidate_jcs(&trailing).is_err());
    }

    #[test]
    fn every_structurally_permitted_coordinated_rewrite_remains_non_authoritative() {
        let fixture = derivation_fixture();
        let entries = fixture.external_entries();
        let source = source_authority_from_derivation_fixture(&fixture);
        let authority = source
            .finalize_with_replay(&entries, &fixture.replay)
            .unwrap();
        let schema: Value = serde_json::from_str(include_str!(
            "../finalizer-schema/b4-negative-ancestry-witness-catalog-v1.schema.json"
        ))
        .unwrap();
        let schema = jsonschema::draft202012::options().build(&schema).unwrap();

        let mut consumer_program = authority.catalog().clone();
        consumer_program.consumer_program_id = "66".repeat(DIGEST_BYTES);
        for entry in &mut consumer_program.entries {
            if entry.witness_id != B4NegativeAncestryWitnessIdV1::AlternateProgramLift {
                entry.producer_program_id = consumer_program.consumer_program_id.clone();
                entry.claim.pre_state_digest = consumer_program.consumer_program_id.clone();
                entry.claim_digest =
                    hex::encode(recursive_ancestry_claim_digest(&entry.claim).unwrap());
            }
        }

        let mut alternate_program = authority.catalog().clone();
        alternate_program.alternate_program_id = "77".repeat(DIGEST_BYTES);
        for entry in &mut alternate_program.entries {
            if entry.witness_id == B4NegativeAncestryWitnessIdV1::AlternateProgramLift {
                entry.producer_program_id = alternate_program.alternate_program_id.clone();
                entry.claim.pre_state_digest = alternate_program.alternate_program_id.clone();
                entry.claim_digest =
                    hex::encode(recursive_ancestry_claim_digest(&entry.claim).unwrap());
            }
        }

        let mut canonical_claim = authority.catalog().clone();
        for entry in canonical_claim
            .entries
            .iter_mut()
            .filter(|entry| matches!(entry.expanded_row, 141 | 142 | 143 | 153))
        {
            entry.claim.output_digest = "91".repeat(DIGEST_BYTES);
            entry.claim_digest =
                hex::encode(recursive_ancestry_claim_digest(&entry.claim).unwrap());
        }

        let mut alias_artifacts = authority.catalog().clone();
        for entry in alias_artifacts
            .entries
            .iter_mut()
            .filter(|entry| matches!(entry.expanded_row, 141 | 142 | 153))
        {
            entry.raw_seal.sha256 = "ab".repeat(DIGEST_BYTES);
            entry.receipt_oracle.sha256 = "ac".repeat(DIGEST_BYTES);
        }

        for rewritten in [
            consumer_program,
            alternate_program,
            canonical_claim,
            alias_artifacts,
        ] {
            rewritten.validate().unwrap();
            let value = serde_json::to_value(&rewritten).unwrap();
            assert!(schema.validate(&value).is_ok());
            assert!(
                authority
                    .verify_candidate_jcs(&rewritten.to_canonical_jcs().unwrap())
                    .is_err()
            );
        }
    }

    #[test]
    fn authority_candidate_parser_rejects_every_noncanonical_or_open_shape() {
        let fixture = derivation_fixture();
        let entries = fixture.external_entries();
        let source = source_authority_from_derivation_fixture(&fixture);
        let authority = source
            .finalize_with_replay(&entries, &fixture.replay)
            .unwrap();
        let canonical = authority.canonical_catalog_jcs();
        let canonical_text = std::str::from_utf8(canonical).unwrap();

        let duplicate = format!(
            "{{\"format\":\"{B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_FORMAT}\",{}",
            &canonical_text[1..]
        );
        assert!(
            authority
                .verify_candidate_jcs(duplicate.as_bytes())
                .is_err()
        );

        for mutation in 0..4 {
            let mut value: Value = serde_json::from_slice(canonical).unwrap();
            match mutation {
                0 => {
                    value
                        .as_object_mut()
                        .unwrap()
                        .insert("unknown".to_owned(), Value::Bool(true));
                }
                1 => {
                    value.as_object_mut().unwrap().remove("receiptOracleCodec");
                }
                2 => {
                    value["receiptOracleCodec"] = json!("wrong-codec");
                }
                3 => {
                    value["entries"].as_array_mut().unwrap().swap(0, 1);
                }
                _ => unreachable!(),
            }
            let source = canonical_json_bytes(&value).unwrap();
            assert!(authority.verify_candidate_jcs(&source).is_err());
        }

        let pretty =
            serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(canonical).unwrap())
                .unwrap();
        assert!(authority.verify_candidate_jcs(&pretty).is_err());
        let mut trailing = canonical.to_vec();
        trailing.push(b'\n');
        assert!(authority.verify_candidate_jcs(&trailing).is_err());
        assert!(
            authority
                .verify_candidate_jcs(&vec![b' '; 128 * 1024 + 1])
                .is_err()
        );
    }

    #[test]
    fn four_claim_classes_have_the_exact_alias_partition() {
        let fixture = derivation_fixture();
        let claims =
            derive_expected_claims(&fixture.authenticated.profile, &fixture.authenticated.case9)
                .unwrap();
        assert_eq!(
            claims[&B4NegativeAncestryWitnessIdV1::Case9AssumptionLift],
            claims[&B4NegativeAncestryWitnessIdV1::Case9FinalResolve]
        );
        assert_eq!(
            claims[&B4NegativeAncestryWitnessIdV1::AlternateStatementAssumptionLift],
            claims[&B4NegativeAncestryWitnessIdV1::AlternateStatementFinalResolve]
        );
        assert_eq!(
            claims[&B4NegativeAncestryWitnessIdV1::AlternateStatementAssumptionLift],
            claims[&B4NegativeAncestryWitnessIdV1::AlternateStatementFinalJoin]
        );
        let distinct = claims
            .values()
            .map(|claim| recursive_ancestry_claim_digest(claim).unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(distinct.len(), 4);
    }

    #[test]
    fn case9_reconstructs_three_distinct_orders_and_authenticates_every_source() {
        let fixture = case9_source_fixture();
        let authenticated = authenticate_case9_fixture(&fixture).unwrap();

        assert_eq!(
            authenticated.projection.family,
            RecursiveAncestryFamily::TerminalResolve
        );
        assert_eq!(authenticated.statement, fixture.primary[5].bytes);
        assert_eq!(authenticated.final_raw_seal, fixture.primary[6].bytes);
        assert_eq!(
            authenticated.assumption_raw_seal,
            fixture.auxiliary[0].bytes
        );
        let parsed: ProofOutputManifest = serde_json::from_slice(&fixture.manifest_jcs).unwrap();
        assert!(
            parsed
                .windows(2)
                .all(|pair| pair[0].path.as_bytes() < pair[1].path.as_bytes())
        );
        assert_eq!(
            fixture
                .primary
                .iter()
                .map(|source| source.path.rsplit('/').next().unwrap())
                .collect::<Vec<_>>(),
            RECURSIVE_POSITIVE_ARTIFACT_LAYOUT
                .iter()
                .map(|(_, basename)| *basename)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn case9_rejects_manifest_primary_auxiliary_and_generation_drift() {
        for mutation in 0..9 {
            let mut fixture = case9_source_fixture();
            match mutation {
                0 => fixture.primary.swap(0, 1),
                1 => fixture.auxiliary.swap(0, 1),
                2 => fixture.manifest_jcs.push(b'\n'),
                3 => {
                    let mut value: Value = serde_json::from_slice(&fixture.generation_jcs).unwrap();
                    value["cases"][CASE_9_INDEX]["artifacts"][0]["sha256"] =
                        json!("aa".repeat(DIGEST_BYTES));
                    fixture.generation_jcs = canonical_json_bytes(&value).unwrap();
                }
                4 => fixture.auxiliary[0].bytes[0] ^= 1,
                5 => {
                    fixture.primary.pop();
                }
                6 => fixture.primary.push(fixture.primary[0].clone()),
                7 => {
                    fixture.auxiliary.pop();
                }
                8 => fixture.auxiliary.push(fixture.auxiliary[0].clone()),
                _ => unreachable!(),
            }
            assert!(
                authenticate_case9_fixture(&fixture).is_err(),
                "case-9 mutation {mutation} unexpectedly authenticated"
            );
        }
    }

    #[test]
    fn complete_source_closure_authenticates_profile_prior_documents_and_case9() {
        let authenticated = authenticate_complete_source_fixture(None).unwrap();
        assert_eq!(
            authenticated.profile.profile_manifest.path,
            B4_NEGATIVE_ANCESTRY_PROFILE_MANIFEST_PATH
        );
        assert_eq!(
            authenticated.case9.projection.family,
            RecursiveAncestryFamily::TerminalResolve
        );
        assert_eq!(
            authenticated
                .prior_commitments
                .campaign_precommit
                .byte_length,
            u64::try_from(real_prior_support().campaign_precommit_jcs.len()).unwrap()
        );
    }

    #[test]
    fn every_prior_profile_case9_and_path_mutation_fails_before_replay_exists() {
        for mutation in 0..12 {
            assert!(
                authenticate_complete_source_fixture(Some(mutation)).is_err(),
                "source-closure mutation {mutation} unexpectedly authenticated"
            );
        }
    }

    #[test]
    fn v2_source_constructor_has_the_affine_positive_authority_signature() {
        let _: for<'a> fn(
            &B4CampaignPrecommitAuthorityV1,
            &B4PositiveGenerationAuthorityV2,
            B4NegativeAncestrySourceClosureV2<'a>,
        ) -> Result<B4NegativeAncestrySourceAuthorityV2> =
            B4NegativeAncestrySourceAuthorityV2::from_source_closure;
    }

    #[test]
    fn v2_source_shape_has_no_v1_or_terminal_packet_mint_path() {
        let source = include_str!("b4_negative_ancestry_authority.rs");
        let start = source
            .find("impl B4NegativeAncestrySourceAuthorityV2")
            .unwrap();
        let end = source[start..]
            .find("/// Opaque authority for one exact derive-first")
            .map(|offset| start + offset)
            .unwrap();
        let implementation = &source[start..end];
        assert!(implementation.contains("B4PositiveGenerationAuthorityV2"));
        assert!(implementation.contains("authenticate_source_closure_v2"));
        assert!(implementation.contains("case_custody_matches"));
        for forbidden in [
            "B4PositiveGenerationAuthorityV1",
            "TerminalEvidencePacket",
            "CampaignReceipt",
            "from_v1",
            "into_v1",
        ] {
            assert!(!implementation.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn v2_catalog_shape_retains_full_lineage_without_subset_or_conversion_escape() {
        let source = include_str!("b4_negative_ancestry_authority.rs");
        let declaration = source
            .split("pub struct B4NegativeAncestryWitnessCatalogAuthorityV2 {")
            .nth(1)
            .unwrap()
            .split("\n}")
            .next()
            .unwrap();
        assert!(declaration.contains("prior_commitments: B4NegativeAncestryPriorCommitmentsV2"));
        assert!(declaration.contains("prior_provenance_paths: BTreeSet<String>"));
        assert!(
            declaration
                .contains("positive_provenance_sha256: BTreeMap<String, [u8; DIGEST_BYTES]>")
        );

        let commitments = source
            .split("pub(crate) struct B4NegativeAncestryPriorCommitmentsV2 {")
            .nth(1)
            .unwrap()
            .split("\n}")
            .next()
            .unwrap();
        assert!(commitments.contains("positive_input_set: B4ContractArtifactIdentityV1"));
        assert!(commitments.contains("positive_generation_set: B4ContractArtifactIdentityV1"));
        assert!(!commitments.contains("positive_input_set: PathlessByteIdentityV1"));
        assert!(!commitments.contains("positive_generation_set: PathlessByteIdentityV1"));

        let implementation = source
            .split("impl B4NegativeAncestryWitnessCatalogAuthorityV2 {")
            .nth(1)
            .unwrap()
            .split("fn stock_replay_error")
            .next()
            .unwrap();
        assert!(!implementation.contains("is_subset"));
        for forbidden in ["From<", "Into<", "from_v1", "into_v1"] {
            assert!(!implementation.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn v2_source_finalize_and_lineage_retain_exact_prior_and_digest_closures() {
        let support = fixed_negative_ancestry_lineage_test_support_v2().unwrap();
        let producer = support.source.producer_source();
        assert_eq!(
            producer.positive_provenance_sha256(),
            support
                .prior
                .positive_generation_authority
                .provenance_sha256()
        );
        assert!(
            support
                .prior
                .positive_generation_authority
                .provenance_paths()
                .iter()
                .eq(producer.positive_provenance_sha256().keys())
        );
        assert_eq!(
            producer.prior_provenance_paths(),
            &support.ancestry.prior_provenance_paths
        );
        support
            .ancestry
            .verify_prior_authority_lineage(
                &support.prior.campaign_precommit_authority,
                &support.prior.positive_generation_authority,
            )
            .unwrap();
    }

    #[test]
    fn v2_catalog_lineage_rejects_input_and_generation_relocation_even_with_union_paths() {
        let mut support = fixed_negative_ancestry_lineage_test_support_v2().unwrap();
        let original_input_path = support
            .ancestry
            .prior_commitments
            .positive_input_set
            .path
            .clone();
        support.ancestry.prior_commitments.positive_input_set.path =
            "reproduction/preproof/relocated-input-set.json".to_owned();
        let error = support
            .ancestry
            .verify_prior_authority_lineage(
                &support.prior.campaign_precommit_authority,
                &support.prior.positive_generation_authority,
            )
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("different prior authorities"),
            "unexpected input-relocation discriminator: {error:#}"
        );
        support.ancestry.prior_commitments.positive_input_set.path = original_input_path;

        let original_generation_path = support.prior.sources.positive_generation_set.path.clone();
        support.prior.sources.positive_generation_set.path =
            "reproduction/preproof/relocated-generation-set.json".to_owned();
        let relocated_generation_path = support.prior.sources.positive_generation_set.path.clone();
        let relocated_positive = B4PositiveGenerationAuthorityV2::from_validated(
            support.prior.sources.validate_preacceptance().unwrap(),
        );
        support
            .ancestry
            .provenance_paths
            .insert(relocated_generation_path);
        assert!(
            support
                .ancestry
                .provenance_paths
                .contains(&original_generation_path),
            "the mutant must retain the original path so only exact prior closure discriminates"
        );
        let error = support
            .ancestry
            .verify_prior_authority_lineage(
                &support.prior.campaign_precommit_authority,
                &relocated_positive,
            )
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("different prior authorities"),
            "unexpected generation-relocation discriminator: {error:#}"
        );
    }

    #[test]
    fn v2_source_and_catalog_reject_provenance_digest_and_case9_custody_mutants() {
        let mut support = fixed_negative_ancestry_lineage_test_support_v2().unwrap();
        let provenance_path = support
            .source
            .authenticated
            .positive_provenance_sha256
            .first_key_value()
            .expect("positive provenance map cannot be empty")
            .0
            .clone();
        support
            .source
            .authenticated
            .positive_provenance_sha256
            .get_mut(&provenance_path)
            .unwrap()[0] ^= 1;
        let error = support
            .source
            .verify_authority_bindings(
                &support.prior.campaign_precommit_authority,
                &support.prior.positive_generation_authority,
            )
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("positive provenance digests"),
            "unexpected source digest discriminator: {error:#}"
        );
        support
            .source
            .authenticated
            .positive_provenance_sha256
            .get_mut(&provenance_path)
            .unwrap()[0] ^= 1;

        support
            .ancestry
            .positive_provenance_sha256
            .get_mut(&provenance_path)
            .unwrap()[0] ^= 1;
        let error = support
            .ancestry
            .verify_prior_authority_lineage(
                &support.prior.campaign_precommit_authority,
                &support.prior.positive_generation_authority,
            )
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("positive provenance digests"),
            "unexpected catalogue digest discriminator: {error:#}"
        );
        support
            .ancestry
            .positive_provenance_sha256
            .get_mut(&provenance_path)
            .unwrap()[0] ^= 1;

        support.ancestry.case9_custody.case_id.push_str("-mutant");
        let error = support
            .ancestry
            .verify_prior_authority_lineage(
                &support.prior.campaign_precommit_authority,
                &support.prior.positive_generation_authority,
            )
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("case-9 custody"),
            "unexpected case-9 discriminator: {error:#}"
        );
    }

    mod independent_claim_tests {
        include!("b4_negative_ancestry_authority_independent_tests.rs");
    }
}
