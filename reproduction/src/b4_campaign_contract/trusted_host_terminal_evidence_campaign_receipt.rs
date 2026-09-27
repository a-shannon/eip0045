//! Closed trusted-host terminal-evidence campaign receipt candidate.

use std::ffi::{OsStr, OsString};

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    b4_terminal::{
        B4_TERMINAL_EVIDENCE_MANIFEST_MAX_BYTES, B4_TERMINAL_FIXTURE_COUNT,
        B4_TERMINAL_FIXTURE_LAYOUT,
    },
    canonical::{canonical_json_bytes, validate_lower_hex_exact},
};

use super::{
    B4ContractArtifactEncodingV1, B4ContractArtifactIdentityV1,
    B4PositiveGenerationAuthorityV2, B4TrustedHostCampaignPrecommitAuthorityV1,
    B4TrustedHostRequestV1, CanonicalContract, MAX_CAMPAIGN_PRECOMMIT_BYTES,
    MAX_DESCRIPTOR_BYTES, MAX_EXECUTOR_ARTIFACT_BYTES, MAX_EXECUTOR_CONTRACT_BYTES,
    MAX_INPUT_SET_BYTES, parse_contract, require_distinct_paths, require_identity,
    serialize_contract, sha256_hex, validate_digest,
};

/// Exact discriminator for the separately realized trusted-host receipt.
pub const B4_TRUSTED_HOST_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FORMAT: &str =
    "Eip0045B4TrustedHostTerminalEvidenceCampaignReceiptV1";
/// Maximum accepted canonical receipt length.
pub const MAX_TRUSTED_HOST_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES: usize = 64 * 1024;
/// Domain tag for the exact trusted-host `argv[1..]` vector.
pub const B4_TRUSTED_HOST_PUBLISH_TERMINAL_EVIDENCE_CANONICAL_ARGV_FORMAT: &str =
    "Eip0045B4TrustedHostPublishTerminalEvidenceCanonicalArgvV1";

const COMMAND: &str = "publish-terminal-evidence";
const REALIZATION: &str = "trusted-host-v1";
const FRESH_FIXTURE_RECEIPTS: usize = 8;
const REUSED_FIXTURE_RECEIPTS: usize = 1;
const DIRECT_PAIRS: usize = 1;
const TOP_LEVEL_PROVING_CALLS: usize = 12;

/// Independently retained values for one trusted-host receipt construction.
pub struct B4TrustedHostTerminalEvidenceCampaignReceiptInputsV1<'a> {
    /// Full-envelope campaign authority, never an H0 projection.
    pub campaign: &'a B4TrustedHostCampaignPrecommitAuthorityV1,
    /// Physical identity of the retained full-envelope precommit file.
    pub campaign_precommit_identity: &'a B4ContractArtifactIdentityV1,
    /// Affine post-proof authority over all eleven positive exports.
    pub positive: &'a B4PositiveGenerationAuthorityV2,
    /// Independently authenticated authoritative build-evidence root.
    pub build_evidence_root_sha256: &'a str,
    /// Unmodified process argv, including `argv[0]`.
    pub process_argv: &'a [OsString],
    /// Externally pinned current trusted-host request byte length.
    pub request_byte_length: u64,
    /// Externally pinned current trusted-host request SHA-256.
    pub request_sha256: &'a str,
    /// Parsed execution mode; receipt creation requires execute mode.
    pub parsed_preflight_only: bool,
    /// Observed development mode; receipt creation requires absence.
    pub risc0_dev_mode: Option<&'a OsStr>,
    /// Exact terminal packet manifest byte length.
    pub terminal_packet_manifest_byte_length: usize,
    /// Exact terminal packet identity.
    pub terminal_packet_id: &'a str,
}

/// Non-authorizing, closed candidate receipt for trusted-host publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Eip0045B4TrustedHostTerminalEvidenceCampaignReceiptV1 {
    wire: TrustedHostTerminalEvidenceCampaignReceiptWireV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustedHostTerminalEvidenceCampaignReceiptWireV1 {
    format: String,
    format_version: u8,
    realization: String,
    campaign_precommit: B4ContractArtifactIdentityV1,
    precommit_request: B4ContractArtifactIdentityV1,
    positive_input_set: B4ContractArtifactIdentityV1,
    positive_generation_set: B4ContractArtifactIdentityV1,
    build_evidence_root_sha256: String,
    executor: ExecutorWireV1,
    invocation: InvocationWireV1,
    workload: WorkloadWireV1,
    terminal_packet: PacketWireV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecutorWireV1 {
    artifact: B4ContractArtifactIdentityV1,
    build_descriptor: B4ContractArtifactIdentityV1,
    executor_contract: B4ContractArtifactIdentityV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InvocationWireV1 {
    command: String,
    canonical_argv_sha256: String,
    request_byte_length: u64,
    request_sha256: String,
    risc0_dev_mode: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WorkloadWireV1 {
    fixture_ids: [String; B4_TERMINAL_FIXTURE_COUNT],
    fixture_count: usize,
    freshly_generated_fixture_receipt_count: usize,
    reused_authenticated_fixture_receipt_count: usize,
    direct_pair_count: usize,
    top_level_proving_api_invocation_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PacketWireV1 {
    manifest_byte_length: u64,
    packet_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalArgvV1<'a> {
    format: &'static str,
    tokens: Vec<&'a str>,
}

/// Validate the exact trusted-host CLI shape and hash its domain-tagged argv.
///
/// This validates the externally pinned request and build root against the
/// unmodified process arguments, without treating argv as a source authority.
pub fn b4_trusted_host_publish_terminal_evidence_canonical_argv_sha256(
    process_argv: &[OsString],
    request_byte_length: u64,
    request_sha256: &str,
    build_evidence_root_sha256: &str,
    parsed_preflight_only: bool,
) -> Result<String> {
    ensure!((1..=65536).contains(&request_byte_length),
        "trusted-host terminal request byte length is outside its bound");
    validate_digest(request_sha256, "trusted-host terminal request SHA-256")?;
    validate_digest(build_evidence_root_sha256, "trusted-host terminal build root")?;
    let (_, tail) = process_argv.split_first().context("trusted-host argv lacks argv[0]")?;
    ensure!(tail.len() == 16 + usize::from(parsed_preflight_only),
        "trusted-host terminal argv has wrong cardinality");
    let tokens = tail.iter().map(|token| token.to_str()
        .context("trusted-host terminal argv contains non-UTF-8"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(tokens[0] == "b4-campaign" && tokens[1] == COMMAND
        && tokens[2] == "--realization" && tokens[3] == REALIZATION
        && tokens[4] == "--request" && tokens[6] == "--request-bytes"
        && tokens[8] == "--request-sha256"
        && tokens[10] == "--expected-source-commit"
        && tokens[12] == "--expected-source-tree"
        && tokens[14] == "--expected-build-evidence-root",
        "trusted-host terminal argv differs from its canonical command and flag order");
    B4TrustedHostRequestV1::validate_absolute_source_path(tokens[5], "request path")?;
    ensure!(tokens[7] == request_byte_length.to_string()
        && tokens[9] == request_sha256 && tokens[15] == build_evidence_root_sha256,
        "trusted-host terminal argv differs from its external request or build pin");
    validate_lower_hex_exact(tokens[11], 20)?;
    validate_lower_hex_exact(tokens[13], 20)?;
    if parsed_preflight_only {
        ensure!(tokens[16] == "--preflight-only",
            "trusted-host terminal argv lacks its parsed preflight token");
    }
    let value = serde_json::to_value(CanonicalArgvV1 {
        format: B4_TRUSTED_HOST_PUBLISH_TERMINAL_EVIDENCE_CANONICAL_ARGV_FORMAT,
        tokens,
    })?;
    Ok(sha256_hex(&canonical_json_bytes(&value)?))
}

impl Eip0045B4TrustedHostTerminalEvidenceCampaignReceiptV1 {
    /// Construct a candidate from the full-envelope and positive authorities.
    pub fn new(inputs: B4TrustedHostTerminalEvidenceCampaignReceiptInputsV1<'_>) -> Result<Self> {
        ensure!(!inputs.parsed_preflight_only,
            "preflight-only invocation cannot construct a trusted-host terminal receipt");
        ensure!(inputs.risc0_dev_mode.is_none(),
            "RISC0_DEV_MODE must be absent for a trusted-host terminal receipt");
        ensure!(inputs.campaign_precommit_identity == inputs.campaign.envelope_identity(),
            "retained full-envelope precommit differs from trusted-host authority");
        ensure!(inputs.positive.positive_input_set_identity()
            == &inputs.campaign.inner_precommit().input_set,
            "trusted-host campaign and positive-generation input identities differ");
        ensure!(inputs.build_evidence_root_sha256
            == inputs.campaign.envelope().build_evidence_root_sha256,
            "trusted-host receipt build root differs from the campaign envelope");
        let canonical_argv_sha256 = b4_trusted_host_publish_terminal_evidence_canonical_argv_sha256(
            inputs.process_argv, inputs.request_byte_length, inputs.request_sha256,
            inputs.build_evidence_root_sha256, inputs.parsed_preflight_only)?;
        let inner = inputs.campaign.inner_precommit();
        let receipt = Self { wire: TrustedHostTerminalEvidenceCampaignReceiptWireV1 {
            format: B4_TRUSTED_HOST_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FORMAT.to_owned(),
            format_version: 1,
            realization: REALIZATION.to_owned(),
            campaign_precommit: inputs.campaign_precommit_identity.clone(),
            precommit_request: inputs.campaign.request_identity().clone(),
            positive_input_set: inputs.positive.positive_input_set_identity().clone(),
            positive_generation_set: inputs.positive.positive_generation_set_identity().clone(),
            build_evidence_root_sha256: inputs.build_evidence_root_sha256.to_owned(),
            executor: ExecutorWireV1 {
                artifact: inner.campaign_executor.artifact.clone(),
                build_descriptor: inner.campaign_executor.build_descriptor.clone(),
                executor_contract: inner.executor_contract.clone(),
            },
            invocation: InvocationWireV1 {
                command: COMMAND.to_owned(), canonical_argv_sha256,
                request_byte_length: inputs.request_byte_length,
                request_sha256: inputs.request_sha256.to_owned(),
                risc0_dev_mode: "absent".to_owned(),
            },
            workload: WorkloadWireV1 {
                fixture_ids: B4_TERMINAL_FIXTURE_LAYOUT.map(|layout| layout.fixture_id.to_owned()),
                fixture_count: B4_TERMINAL_FIXTURE_COUNT,
                freshly_generated_fixture_receipt_count: FRESH_FIXTURE_RECEIPTS,
                reused_authenticated_fixture_receipt_count: REUSED_FIXTURE_RECEIPTS,
                direct_pair_count: DIRECT_PAIRS,
                top_level_proving_api_invocation_count: TOP_LEVEL_PROVING_CALLS,
            },
            terminal_packet: PacketWireV1 {
                manifest_byte_length: u64::try_from(inputs.terminal_packet_manifest_byte_length)
                    .context("terminal packet manifest length does not fit u64")?,
                packet_id: inputs.terminal_packet_id.to_owned(),
            },
        }};
        receipt.validate()?;
        Ok(receipt)
    }

    /// Parse exact canonical bytes under the closed trusted-host schema.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        #[cfg(feature = "positive-gate")]
        super::validate_trusted_host_schema(source,
            include_str!("../../finalizer-schema/b4-trusted-host-terminal-evidence-campaign-receipt-v1.schema.json"),
            "trusted-host terminal receipt")?;
        let wire = parse_contract(source,
            MAX_TRUSTED_HOST_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES,
            "trusted-host terminal receipt")?;
        Ok(Self { wire })
    }

    /// Serialize a validated candidate as exact RFC 8785 JCS.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        serialize_contract(&self.wire,
            MAX_TRUSTED_HOST_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES,
            "trusted-host terminal receipt")
    }

    /// Revalidate every document-local field and path relationship.
    pub fn validate(&self) -> Result<()> { self.wire.validate_contract() }

    /// Full-envelope campaign precommit identity.
    #[must_use]
    pub fn campaign_precommit(&self) -> &B4ContractArtifactIdentityV1 {
        &self.wire.campaign_precommit
    }

    /// Prior trusted-host precommit request identity.
    #[must_use]
    pub fn precommit_request(&self) -> &B4ContractArtifactIdentityV1 {
        &self.wire.precommit_request
    }

    /// Current trusted-host request pin.
    #[must_use]
    pub fn request_pin(&self) -> (u64, &str) {
        (self.wire.invocation.request_byte_length, &self.wire.invocation.request_sha256)
    }

    /// SHA-256 of the exact domain-tagged trusted-host argv vector.
    #[must_use]
    pub fn canonical_argv_sha256(&self) -> &str {
        &self.wire.invocation.canonical_argv_sha256
    }

    /// Bound authoritative build-evidence root.
    #[must_use]
    pub fn build_evidence_root_sha256(&self) -> &str {
        &self.wire.build_evidence_root_sha256
    }

    /// Bound terminal-packet manifest byte length.
    #[must_use]
    pub fn terminal_packet_manifest_byte_length(&self) -> u64 {
        self.wire.terminal_packet.manifest_byte_length
    }

    /// Bound terminal-packet ID.
    #[must_use]
    pub fn terminal_packet_id(&self) -> &str { &self.wire.terminal_packet.packet_id }
}

impl CanonicalContract for TrustedHostTerminalEvidenceCampaignReceiptWireV1 {
    fn validate_contract(&self) -> Result<()> {
        ensure!(self.format == B4_TRUSTED_HOST_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FORMAT
            && self.format_version == 1 && self.realization == REALIZATION,
            "wrong trusted-host terminal receipt discriminator");
        require_identity(&self.campaign_precommit,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            u64::try_from(MAX_CAMPAIGN_PRECOMMIT_BYTES + 4096)?,
            "trusted-host full-envelope precommit")?;
        ensure!(self.campaign_precommit.path.ends_with("/trusted-host/campaign-precommit.json"),
            "trusted-host terminal receipt names another precommit kind");
        require_identity(&self.precommit_request,
            B4ContractArtifactEncodingV1::Rfc8785Jcs, 65536,
            "trusted-host precommit request")?;
        require_identity(&self.positive_input_set,
            B4ContractArtifactEncodingV1::Rfc8785Jcs, MAX_INPUT_SET_BYTES,
            "trusted-host positive input set")?;
        require_identity(&self.positive_generation_set,
            B4ContractArtifactEncodingV1::Rfc8785Jcs, MAX_INPUT_SET_BYTES,
            "trusted-host positive generation set")?;
        require_identity(&self.executor.artifact,
            B4ContractArtifactEncodingV1::RawBytes, MAX_EXECUTOR_ARTIFACT_BYTES,
            "trusted-host executor artifact")?;
        require_identity(&self.executor.build_descriptor,
            B4ContractArtifactEncodingV1::Rfc8785Jcs, MAX_DESCRIPTOR_BYTES,
            "trusted-host executor build descriptor")?;
        require_identity(&self.executor.executor_contract,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            u64::try_from(MAX_EXECUTOR_CONTRACT_BYTES)?,
            "trusted-host executor contract")?;
        require_distinct_paths([
            &self.campaign_precommit, &self.precommit_request,
            &self.positive_input_set, &self.positive_generation_set,
            &self.executor.artifact, &self.executor.build_descriptor,
            &self.executor.executor_contract,
        ], "trusted-host terminal receipt")?;
        validate_digest(&self.build_evidence_root_sha256,
            "trusted-host terminal build evidence root")?;
        ensure!(self.invocation.command == COMMAND
            && self.invocation.risc0_dev_mode == "absent",
            "trusted-host terminal receipt has wrong invocation mode");
        validate_lower_hex_exact(&self.invocation.canonical_argv_sha256, 32)?;
        ensure!((1..=65536).contains(&self.invocation.request_byte_length),
            "trusted-host terminal request length is outside its bound");
        validate_digest(&self.invocation.request_sha256,
            "trusted-host terminal request SHA-256")?;
        ensure!(self.workload.fixture_ids.iter().map(String::as_str)
            .eq(B4_TERMINAL_FIXTURE_LAYOUT.iter().map(|layout| layout.fixture_id))
            && self.workload.fixture_count == B4_TERMINAL_FIXTURE_COUNT
            && self.workload.freshly_generated_fixture_receipt_count == FRESH_FIXTURE_RECEIPTS
            && self.workload.reused_authenticated_fixture_receipt_count == REUSED_FIXTURE_RECEIPTS
            && self.workload.direct_pair_count == DIRECT_PAIRS
            && self.workload.top_level_proving_api_invocation_count == TOP_LEVEL_PROVING_CALLS,
            "trusted-host terminal receipt workload differs from the fixed producer");
        ensure!((1..=u64::try_from(B4_TERMINAL_EVIDENCE_MANIFEST_MAX_BYTES)?)
            .contains(&self.terminal_packet.manifest_byte_length),
            "trusted-host terminal packet manifest length is outside its bound");
        validate_digest(&self.terminal_packet.packet_id,
            "trusted-host terminal packet ID")
    }
}

#[cfg(all(test, feature = "recursive-ancestry"))]
mod tests {
    use std::ffi::{OsStr, OsString};

    use serde_json::Value;

    use super::*;
    use crate::b4_campaign_contract::test_support::{
        TerminalLineageConstructorTestSupportV2,
        build_terminal_lineage_constructor_test_support_v2,
    };

    const BUILD_ROOT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const REQUEST_SHA: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const PACKET_ID: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn argv() -> Vec<OsString> {
        ["executor", "b4-campaign", COMMAND, "--realization", REALIZATION,
            "--request", "/campaign/request.json", "--request-bytes", "71",
            "--request-sha256", REQUEST_SHA, "--expected-source-commit",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "--expected-source-tree",
            "ffffffffffffffffffffffffffffffffffffffff", "--expected-build-evidence-root",
            BUILD_ROOT].into_iter().map(OsString::from).collect()
    }

    fn inputs<'a>(
        fixture: &'a TerminalLineageConstructorTestSupportV2,
        process_argv: &'a [OsString],
    ) -> B4TrustedHostTerminalEvidenceCampaignReceiptInputsV1<'a> {
        B4TrustedHostTerminalEvidenceCampaignReceiptInputsV1 {
            campaign: &fixture.trusted_host_campaign_precommit_authority,
            campaign_precommit_identity: fixture.trusted_host_campaign_precommit_authority
                .envelope_identity(),
            positive: &fixture.positive_generation_authority,
            build_evidence_root_sha256: BUILD_ROOT,
            process_argv,
            request_byte_length: 71,
            request_sha256: REQUEST_SHA,
            parsed_preflight_only: false,
            risc0_dev_mode: None,
            terminal_packet_manifest_byte_length: 1024,
            terminal_packet_id: PACKET_ID,
        }
    }

    #[test]
    fn production_authorities_construct_exact_trusted_host_receipt() {
        let fixture = build_terminal_lineage_constructor_test_support_v2().unwrap();
        let process_argv = argv();
        let receipt = Eip0045B4TrustedHostTerminalEvidenceCampaignReceiptV1::new(
            inputs(&fixture, &process_argv)).unwrap();
        assert_eq!(receipt.campaign_precommit(), fixture
            .trusted_host_campaign_precommit_authority.envelope_identity());
        assert_eq!(receipt.precommit_request(), fixture
            .trusted_host_campaign_precommit_authority.request_identity());
        assert_eq!(receipt.request_pin(), (71, REQUEST_SHA));
        assert_ne!(receipt.precommit_request().sha256, receipt.request_pin().1);
        assert_eq!(receipt.build_evidence_root_sha256(), BUILD_ROOT);
        assert_eq!(receipt.terminal_packet_manifest_byte_length(), 1024);
        assert_eq!(receipt.terminal_packet_id(), PACKET_ID);
        let bytes = receipt.to_canonical_jcs().unwrap();
        assert_eq!(Eip0045B4TrustedHostTerminalEvidenceCampaignReceiptV1::
            from_canonical_jcs(&bytes).unwrap(), receipt);
        assert_eq!(receipt.canonical_argv_sha256(),
            b4_trusted_host_publish_terminal_evidence_canonical_argv_sha256(
                &process_argv, 71, REQUEST_SHA, BUILD_ROOT, false).unwrap());
    }

    #[test]
    fn constructor_rejects_isolated_authority_request_build_and_mode_faults() {
        let fixture = build_terminal_lineage_constructor_test_support_v2().unwrap();
        let process_argv = argv();
        let mut altered_identity = fixture.trusted_host_campaign_precommit_authority
            .envelope_identity().clone();
        altered_identity.sha256 = "a".repeat(64);
        let mut candidate = inputs(&fixture, &process_argv);
        candidate.campaign_precommit_identity = &altered_identity;
        assert!(Eip0045B4TrustedHostTerminalEvidenceCampaignReceiptV1::new(candidate).is_err());
        let mut candidate = inputs(&fixture, &process_argv);
        candidate.build_evidence_root_sha256 = REQUEST_SHA;
        assert!(Eip0045B4TrustedHostTerminalEvidenceCampaignReceiptV1::new(candidate).is_err());
        let mut candidate = inputs(&fixture, &process_argv);
        candidate.request_byte_length = 72;
        assert!(Eip0045B4TrustedHostTerminalEvidenceCampaignReceiptV1::new(candidate).is_err());
        let mut candidate = inputs(&fixture, &process_argv);
        candidate.request_sha256 = PACKET_ID;
        assert!(Eip0045B4TrustedHostTerminalEvidenceCampaignReceiptV1::new(candidate).is_err());
        let mut candidate = inputs(&fixture, &process_argv);
        candidate.parsed_preflight_only = true;
        assert!(Eip0045B4TrustedHostTerminalEvidenceCampaignReceiptV1::new(candidate).is_err());
        let mut candidate = inputs(&fixture, &process_argv);
        candidate.risc0_dev_mode = Some(OsStr::new("1"));
        assert!(Eip0045B4TrustedHostTerminalEvidenceCampaignReceiptV1::new(candidate).is_err());
        let mut h0_argv = process_argv.clone();
        h0_argv[1] = OsString::from(COMMAND);
        assert!(Eip0045B4TrustedHostTerminalEvidenceCampaignReceiptV1::new(
            inputs(&fixture, &h0_argv)).is_err());
    }

    #[test]
    fn constructor_rejects_a_separately_valid_positive_input_identity() {
        let fixture = build_terminal_lineage_constructor_test_support_v2().unwrap();
        let process_argv = argv();
        Eip0045B4TrustedHostTerminalEvidenceCampaignReceiptV1::new(
            inputs(&fixture, &process_argv)).unwrap();

        let mut alternate_sources = fixture.sources.clone();
        alternate_sources.positive_input_set.path =
            "reproduction/preproof/relocated-input-set.json".to_owned();
        let alternate_positive = B4PositiveGenerationAuthorityV2::from_validated(
            alternate_sources.validate_preacceptance().unwrap());
        assert_ne!(alternate_positive.positive_input_set_identity(),
            &fixture.trusted_host_campaign_precommit_authority.inner_precommit().input_set);
        let mut candidate = inputs(&fixture, &process_argv);
        candidate.positive = &alternate_positive;
        let error = Eip0045B4TrustedHostTerminalEvidenceCampaignReceiptV1::new(candidate)
            .unwrap_err();
        assert!(error.to_string().contains(
            "trusted-host campaign and positive-generation input identities differ"));
    }

    #[test]
    fn exact_argv_and_closed_schema_reject_independent_substitutions() {
        let process_argv = argv();
        let canonical = b4_trusted_host_publish_terminal_evidence_canonical_argv_sha256(
            &process_argv, 71, REQUEST_SHA, BUILD_ROOT, false).unwrap();
        for (index, replacement) in [(5, "--other"), (6, "/campaign/../request.json"),
            (8, "071"), (10, PACKET_ID), (16, REQUEST_SHA)] {
            let mut altered = process_argv.clone();
            altered[index] = OsString::from(replacement);
            assert!(b4_trusted_host_publish_terminal_evidence_canonical_argv_sha256(
                &altered, 71, REQUEST_SHA, BUILD_ROOT, false).is_err(),
                "accepted argv substitution at {index}");
        }
        let mut changed_commit = process_argv.clone();
        changed_commit[12] = OsString::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_ne!(canonical,
            b4_trusted_host_publish_terminal_evidence_canonical_argv_sha256(
                &changed_commit, 71, REQUEST_SHA, BUILD_ROOT, false).unwrap());

        let fixture = build_terminal_lineage_constructor_test_support_v2().unwrap();
        let receipt = Eip0045B4TrustedHostTerminalEvidenceCampaignReceiptV1::new(
            inputs(&fixture, &process_argv)).unwrap();
        let original: Value = serde_json::from_slice(&receipt.to_canonical_jcs().unwrap()).unwrap();
        for (pointer, replacement) in [
            ("/format", Value::String("Eip0045B4TerminalEvidenceCampaignReceiptV1".to_owned())),
            ("/campaignPrecommit/path", Value::String("h0/precommit.json".to_owned())),
            ("/invocation/requestSha256", Value::String("0".repeat(64))),
            ("/workload/fixtureCount", Value::from(8)),
            ("/terminalPacket/packetId", Value::String("0".repeat(64))),
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            let bytes = canonical_json_bytes(&changed).unwrap();
            assert!(Eip0045B4TrustedHostTerminalEvidenceCampaignReceiptV1::
                from_canonical_jcs(&bytes).is_err(), "accepted {pointer} fault");
        }
        let mut extra = original;
        extra["unbound"] = Value::Bool(true);
        assert!(Eip0045B4TrustedHostTerminalEvidenceCampaignReceiptV1::
            from_canonical_jcs(&canonical_json_bytes(&extra).unwrap()).is_err());
    }
}
