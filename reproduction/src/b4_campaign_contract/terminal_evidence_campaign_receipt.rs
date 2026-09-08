//! Strict candidate codec for one terminal-evidence campaign receipt.

use std::ffi::{OsStr, OsString};

use anyhow::{ensure, Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::{
    b4_terminal::{
        B4_TERMINAL_EVIDENCE_MANIFEST_MAX_BYTES, B4_TERMINAL_FIXTURE_COUNT,
        B4_TERMINAL_FIXTURE_LAYOUT,
    },
    canonical::{canonical_json_bytes, validate_lower_hex_exact},
};

use super::{
    parse_contract, require_distinct_paths, require_identity, serialize_contract, sha256_hex,
    validate_digest, B4ContractArtifactEncodingV1, B4ContractArtifactIdentityV1, CanonicalContract,
    B4_CAMPAIGN_EXECUTOR_COMMANDS, MAX_CAMPAIGN_PRECOMMIT_BYTES, MAX_DESCRIPTOR_BYTES,
    MAX_EXECUTOR_ARTIFACT_BYTES, MAX_EXECUTOR_CONTRACT_BYTES, MAX_INPUT_SET_BYTES,
};

/// Exact terminal-evidence campaign-receipt format discriminator.
pub const B4_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FORMAT: &str =
    "Eip0045B4TerminalEvidenceCampaignReceiptV1";
/// Exact terminal-evidence campaign-receipt format version.
pub const B4_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FORMAT_VERSION: u8 = 1;
/// Maximum accepted or emitted canonical receipt length.
pub const MAX_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES: usize = 64 * 1024;
/// Exact domain tag for canonical publish-terminal-evidence argv.
pub const B4_PUBLISH_TERMINAL_EVIDENCE_CANONICAL_ARGV_FORMAT: &str =
    "Eip0045B4PublishTerminalEvidenceCanonicalArgvV1";

const PUBLISH_TERMINAL_EVIDENCE_COMMAND: &str = "publish-terminal-evidence";
const PREFLIGHT_ONLY_FLAG: &str = "--preflight-only";
const RISC0_DEV_MODE_ABSENT: &str = "absent";
const FRESHLY_GENERATED_FIXTURE_RECEIPT_COUNT: usize = 8;
const REUSED_AUTHENTICATED_FIXTURE_RECEIPT_COUNT: usize = 1;
const DIRECT_PAIR_COUNT: usize = 1;
const TOP_LEVEL_PROVING_API_INVOCATION_COUNT: usize = 12;

/// Borrowed, non-serializable inputs for one checked candidate receipt.
#[derive(Clone, Copy, Debug)]
pub struct B4TerminalEvidenceCampaignReceiptInputsV1<'a> {
    /// Exact campaign-precommit identity.
    pub campaign_precommit: &'a B4ContractArtifactIdentityV1,
    /// Exact positive-input-set identity.
    pub positive_input_set: &'a B4ContractArtifactIdentityV1,
    /// Exact positive-generation-set identity.
    pub positive_generation_set: &'a B4ContractArtifactIdentityV1,
    /// Exact running executor identity.
    pub executor_artifact: &'a B4ContractArtifactIdentityV1,
    /// Exact executor build-descriptor identity.
    pub executor_build_descriptor: &'a B4ContractArtifactIdentityV1,
    /// Exact executor command-contract identity.
    pub executor_contract: &'a B4ContractArtifactIdentityV1,
    /// Unmodified full process argv, including `argv[0]`.
    pub process_argv: &'a [OsString],
    /// Parsed execution-mode flag; receipt construction requires execute mode.
    pub parsed_preflight_only: bool,
    /// Observed `RISC0_DEV_MODE`; receipt construction requires absence.
    pub risc0_dev_mode: Option<&'a OsStr>,
    /// Exact terminal packet manifest byte length.
    pub terminal_packet_manifest_byte_length: usize,
    /// Exact terminal packet identity.
    pub terminal_packet_id: &'a str,
}

/// Closed, non-authorizing terminal-evidence campaign-receipt candidate.
///
/// The public type deliberately does not implement Serde. Canonical parsing is
/// available only through [`Self::from_canonical_jcs`].
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::
///     Eip0045B4TerminalEvidenceCampaignReceiptV1;
/// use serde::Serialize;
///
/// fn require_serialize<T: Serialize>() {}
/// require_serialize::<Eip0045B4TerminalEvidenceCampaignReceiptV1>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::
///     Eip0045B4TerminalEvidenceCampaignReceiptV1;
/// use serde::de::DeserializeOwned;
///
/// fn require_deserialize<T: DeserializeOwned>() {}
/// require_deserialize::<Eip0045B4TerminalEvidenceCampaignReceiptV1>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::
///     Eip0045B4TerminalEvidenceCampaignReceiptV1;
///
/// let _ = Eip0045B4TerminalEvidenceCampaignReceiptV1 {};
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Eip0045B4TerminalEvidenceCampaignReceiptV1 {
    wire: TerminalEvidenceCampaignReceiptWireV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalEvidenceCampaignReceiptWireV1 {
    format: String,
    format_version: u8,
    campaign_precommit: B4ContractArtifactIdentityV1,
    positive_input_set: B4ContractArtifactIdentityV1,
    positive_generation_set: B4ContractArtifactIdentityV1,
    executor: TerminalEvidenceCampaignReceiptExecutorWireV1,
    invocation: TerminalEvidenceCampaignReceiptInvocationWireV1,
    workload: TerminalEvidenceCampaignReceiptWorkloadWireV1,
    terminal_packet: TerminalEvidenceCampaignReceiptPacketWireV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalEvidenceCampaignReceiptExecutorWireV1 {
    artifact: B4ContractArtifactIdentityV1,
    build_descriptor: B4ContractArtifactIdentityV1,
    executor_contract: B4ContractArtifactIdentityV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalEvidenceCampaignReceiptInvocationWireV1 {
    command: String,
    canonical_argv_sha256: String,
    risc0_dev_mode: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalEvidenceCampaignReceiptWorkloadWireV1 {
    fixture_ids: [String; B4_TERMINAL_FIXTURE_COUNT],
    fixture_count: usize,
    freshly_generated_fixture_receipt_count: usize,
    reused_authenticated_fixture_receipt_count: usize,
    direct_pair_count: usize,
    top_level_proving_api_invocation_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalEvidenceCampaignReceiptPacketWireV1 {
    manifest_byte_length: u64,
    packet_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalArgvV1<'a> {
    format: &'static str,
    tokens: Vec<&'a str>,
}

impl Eip0045B4TerminalEvidenceCampaignReceiptV1 {
    /// Construct and validate one receipt candidate from exact measured inputs.
    ///
    /// # Errors
    ///
    /// Returns an error for preflight or development mode, invalid argv,
    /// malformed identities, a path conflict, or an invalid packet identity.
    pub fn new(inputs: B4TerminalEvidenceCampaignReceiptInputsV1<'_>) -> Result<Self> {
        ensure!(
            !inputs.parsed_preflight_only,
            "preflight-only invocation cannot construct a terminal evidence campaign receipt"
        );
        ensure!(
            inputs.risc0_dev_mode.is_none(),
            "RISC0_DEV_MODE must be absent for terminal evidence campaign receipt construction"
        );
        let canonical_argv_sha256 = b4_publish_terminal_evidence_canonical_argv_sha256(
            inputs.process_argv,
            inputs.parsed_preflight_only,
        )?;
        let manifest_byte_length = u64::try_from(inputs.terminal_packet_manifest_byte_length)
            .context("terminal packet manifest byte length does not fit u64")?;
        let receipt = Self {
            wire: TerminalEvidenceCampaignReceiptWireV1 {
                format: B4_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FORMAT.to_owned(),
                format_version: B4_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FORMAT_VERSION,
                campaign_precommit: inputs.campaign_precommit.clone(),
                positive_input_set: inputs.positive_input_set.clone(),
                positive_generation_set: inputs.positive_generation_set.clone(),
                executor: TerminalEvidenceCampaignReceiptExecutorWireV1 {
                    artifact: inputs.executor_artifact.clone(),
                    build_descriptor: inputs.executor_build_descriptor.clone(),
                    executor_contract: inputs.executor_contract.clone(),
                },
                invocation: TerminalEvidenceCampaignReceiptInvocationWireV1 {
                    command: PUBLISH_TERMINAL_EVIDENCE_COMMAND.to_owned(),
                    canonical_argv_sha256,
                    risc0_dev_mode: RISC0_DEV_MODE_ABSENT.to_owned(),
                },
                workload: TerminalEvidenceCampaignReceiptWorkloadWireV1 {
                    fixture_ids: B4_TERMINAL_FIXTURE_LAYOUT
                        .map(|layout| layout.fixture_id.to_owned()),
                    fixture_count: B4_TERMINAL_FIXTURE_COUNT,
                    freshly_generated_fixture_receipt_count:
                        FRESHLY_GENERATED_FIXTURE_RECEIPT_COUNT,
                    reused_authenticated_fixture_receipt_count:
                        REUSED_AUTHENTICATED_FIXTURE_RECEIPT_COUNT,
                    direct_pair_count: DIRECT_PAIR_COUNT,
                    top_level_proving_api_invocation_count: TOP_LEVEL_PROVING_API_INVOCATION_COUNT,
                },
                terminal_packet: TerminalEvidenceCampaignReceiptPacketWireV1 {
                    manifest_byte_length,
                    packet_id: inputs.terminal_packet_id.to_owned(),
                },
            },
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Parse exact RFC 8785 JCS under the global source-byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns an error before parsing for empty or oversized input, or for
    /// any malformed, noncanonical, open, or semantically invalid receipt.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            (1..=MAX_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES).contains(&source.len()),
            "terminal evidence campaign receipt source byte length is outside the V1 bound"
        );
        let wire = parse_contract(
            source,
            MAX_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES,
            "terminal evidence campaign receipt",
        )?;
        Ok(Self { wire })
    }

    /// Serialize this validated candidate as exact RFC 8785 JCS.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid candidate or oversized canonical bytes.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        serialize_contract(
            &self.wire,
            MAX_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES,
            "terminal evidence campaign receipt",
        )
    }

    /// Revalidate the complete document-local candidate contract.
    ///
    /// # Errors
    ///
    /// Returns an error for any fixed-value, identity, path, digest, workload,
    /// or packet-bound violation.
    pub fn validate(&self) -> Result<()> {
        self.wire.validate_contract()
    }

    /// Exact campaign-precommit identity.
    #[must_use]
    pub fn campaign_precommit(&self) -> &B4ContractArtifactIdentityV1 {
        &self.wire.campaign_precommit
    }

    /// Exact positive-input-set identity.
    #[must_use]
    pub fn positive_input_set(&self) -> &B4ContractArtifactIdentityV1 {
        &self.wire.positive_input_set
    }

    /// Exact positive-generation-set identity.
    #[must_use]
    pub fn positive_generation_set(&self) -> &B4ContractArtifactIdentityV1 {
        &self.wire.positive_generation_set
    }

    /// Exact executor artifact identity.
    #[must_use]
    pub fn executor_artifact(&self) -> &B4ContractArtifactIdentityV1 {
        &self.wire.executor.artifact
    }

    /// Exact executor build-descriptor identity.
    #[must_use]
    pub fn executor_build_descriptor(&self) -> &B4ContractArtifactIdentityV1 {
        &self.wire.executor.build_descriptor
    }

    /// Exact executor command-contract identity.
    #[must_use]
    pub fn executor_contract(&self) -> &B4ContractArtifactIdentityV1 {
        &self.wire.executor.executor_contract
    }

    /// SHA-256 of the exact domain-tagged retained argv token vector.
    #[must_use]
    pub fn canonical_argv_sha256(&self) -> &str {
        &self.wire.invocation.canonical_argv_sha256
    }

    /// Exact terminal packet manifest byte length.
    #[must_use]
    pub fn terminal_packet_manifest_byte_length(&self) -> u64 {
        self.wire.terminal_packet.manifest_byte_length
    }

    /// Exact terminal packet ID.
    #[must_use]
    pub fn terminal_packet_id(&self) -> &str {
        &self.wire.terminal_packet.packet_id
    }
}

impl CanonicalContract for TerminalEvidenceCampaignReceiptWireV1 {
    fn validate_contract(&self) -> Result<()> {
        ensure!(
            self.format == B4_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FORMAT,
            "wrong terminal evidence campaign receipt format"
        );
        ensure!(
            self.format_version == B4_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FORMAT_VERSION,
            "wrong terminal evidence campaign receipt version"
        );
        require_identity(
            &self.campaign_precommit,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            u64::try_from(MAX_CAMPAIGN_PRECOMMIT_BYTES)
                .context("campaign precommit maximum does not fit u64")?,
            "campaign precommit",
        )?;
        require_identity(
            &self.positive_input_set,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_INPUT_SET_BYTES,
            "positive input set",
        )?;
        require_identity(
            &self.positive_generation_set,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_INPUT_SET_BYTES,
            "positive generation set",
        )?;
        require_identity(
            &self.executor.artifact,
            B4ContractArtifactEncodingV1::RawBytes,
            MAX_EXECUTOR_ARTIFACT_BYTES,
            "campaign executor artifact",
        )?;
        require_identity(
            &self.executor.build_descriptor,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_DESCRIPTOR_BYTES,
            "campaign executor build descriptor",
        )?;
        require_identity(
            &self.executor.executor_contract,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            u64::try_from(MAX_EXECUTOR_CONTRACT_BYTES)
                .context("executor contract maximum does not fit u64")?,
            "campaign executor contract",
        )?;
        require_distinct_paths(
            [
                &self.campaign_precommit,
                &self.positive_input_set,
                &self.positive_generation_set,
                &self.executor.artifact,
                &self.executor.build_descriptor,
                &self.executor.executor_contract,
            ],
            "terminal evidence campaign receipt",
        )?;
        ensure!(
            self.invocation.command == PUBLISH_TERMINAL_EVIDENCE_COMMAND,
            "wrong terminal evidence campaign receipt command"
        );
        validate_lower_hex_exact(&self.invocation.canonical_argv_sha256, 32)
            .context("invalid canonical argv SHA-256")?;
        ensure!(
            self.invocation.risc0_dev_mode == RISC0_DEV_MODE_ABSENT,
            "terminal evidence campaign receipt must record absent RISC0_DEV_MODE"
        );
        ensure!(
            self.workload
                .fixture_ids
                .iter()
                .map(String::as_str)
                .eq(B4_TERMINAL_FIXTURE_LAYOUT
                    .iter()
                    .map(|layout| layout.fixture_id)),
            "terminal evidence campaign receipt fixture order drift"
        );
        ensure!(
            self.workload.fixture_count == B4_TERMINAL_FIXTURE_COUNT
                && self.workload.freshly_generated_fixture_receipt_count
                    == FRESHLY_GENERATED_FIXTURE_RECEIPT_COUNT
                && self.workload.reused_authenticated_fixture_receipt_count
                    == REUSED_AUTHENTICATED_FIXTURE_RECEIPT_COUNT
                && self.workload.direct_pair_count == DIRECT_PAIR_COUNT
                && self.workload.top_level_proving_api_invocation_count
                    == TOP_LEVEL_PROVING_API_INVOCATION_COUNT,
            "terminal evidence campaign receipt workload counters drift"
        );
        let manifest_maximum = u64::try_from(B4_TERMINAL_EVIDENCE_MANIFEST_MAX_BYTES)
            .context("terminal evidence manifest maximum does not fit u64")?;
        ensure!(
            (1..=manifest_maximum).contains(&self.terminal_packet.manifest_byte_length),
            "terminal evidence campaign receipt manifest byte length is outside the V1 bound"
        );
        validate_digest(
            &self.terminal_packet.packet_id,
            "terminal evidence campaign receipt packet ID",
        )
    }
}

/// Validate one retained campaign-executor invocation against its parsed mode.
///
/// The expected command must belong to the frozen eleven-command inventory.
/// Exactly one raw `--preflight-only` token is required in preflight mode and
/// forbidden in execute mode.
///
/// # Errors
///
/// Returns an error for a command outside the frozen inventory, missing or
/// non-UTF-8 retained tokens, a wrong command, or raw/parsed preflight-mode
/// disagreement.
#[doc(hidden)]
pub fn validate_b4_campaign_command_invocation(
    process_argv: &[OsString],
    expected_command: &str,
    parsed_preflight_only: bool,
) -> Result<()> {
    ensure!(
        B4_CAMPAIGN_EXECUTOR_COMMANDS.contains(&expected_command),
        "expected command is outside the frozen B4 campaign inventory"
    );
    let (_, retained) = process_argv
        .split_first()
        .context("process argv must contain argv[0]")?;
    let tokens = retained
        .iter()
        .map(|token| {
            token
                .to_str()
                .context("B4 campaign argv contains a non-UTF-8 token")
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        tokens.first().copied() == Some(expected_command),
        "retained argv begins with the wrong B4 campaign command"
    );
    let raw_preflight_count = tokens
        .iter()
        .filter(|token| **token == PREFLIGHT_ONLY_FLAG)
        .count();
    ensure!(
        raw_preflight_count == usize::from(parsed_preflight_only),
        "raw argv and parsed preflight mode disagree"
    );
    Ok(())
}

/// Validate retained `publish-terminal-evidence` argv in either parsed mode.
///
/// # Errors
///
/// Returns the first frozen-command or raw/parsed mode mismatch.
#[doc(hidden)]
pub fn validate_b4_publish_terminal_evidence_invocation(
    process_argv: &[OsString],
    parsed_preflight_only: bool,
) -> Result<()> {
    validate_b4_campaign_command_invocation(
        process_argv,
        PUBLISH_TERMINAL_EVIDENCE_COMMAND,
        parsed_preflight_only,
    )
}

/// Hash the exact domain-tagged `argv[1..]` token vector for receipt binding.
///
/// # Errors
///
/// Returns an error for preflight mode, missing or non-UTF-8 retained tokens,
/// a wrong command, or raw/parsed preflight-mode disagreement.
pub fn b4_publish_terminal_evidence_canonical_argv_sha256(
    process_argv: &[OsString],
    parsed_preflight_only: bool,
) -> Result<String> {
    ensure!(
        !parsed_preflight_only,
        "preflight-only invocation cannot construct a terminal evidence campaign receipt"
    );
    validate_b4_publish_terminal_evidence_invocation(process_argv, parsed_preflight_only)?;
    let (_, retained) = process_argv
        .split_first()
        .context("process argv must contain argv[0]")?;
    let tokens = retained
        .iter()
        .map(|token| {
            token
                .to_str()
                .context("publish-terminal-evidence argv contains a non-UTF-8 token")
        })
        .collect::<Result<Vec<_>>>()?;
    let value = serde_json::to_value(CanonicalArgvV1 {
        format: B4_PUBLISH_TERMINAL_EVIDENCE_CANONICAL_ARGV_FORMAT,
        tokens,
    })
    .context("cannot serialize canonical publish-terminal-evidence argv")?;
    Ok(sha256_hex(&canonical_json_bytes(&value)?))
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};

    use super::*;
    use serde_json::Value;

    fn identity(
        path: &str,
        encoding: B4ContractArtifactEncodingV1,
        seed: u8,
    ) -> B4ContractArtifactIdentityV1 {
        B4ContractArtifactIdentityV1 {
            path: path.to_owned(),
            byte_length: 1,
            sha256: format!("{seed:02x}").repeat(32),
            encoding,
        }
    }

    fn identities() -> [B4ContractArtifactIdentityV1; 6] {
        [
            identity(
                "campaign/precommit.json",
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                1,
            ),
            identity(
                "campaign/positive-input-set.json",
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                2,
            ),
            identity(
                "campaign/positive-generation-set.json",
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                3,
            ),
            identity(
                "executor/artifact",
                B4ContractArtifactEncodingV1::RawBytes,
                4,
            ),
            identity(
                "executor/build-descriptor.json",
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                5,
            ),
            identity(
                "executor/contract.json",
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                6,
            ),
        ]
    }

    fn valid_argv() -> [OsString; 4] {
        [
            OsString::from("ignored-bin"),
            OsString::from(PUBLISH_TERMINAL_EVIDENCE_COMMAND),
            OsString::from("--outer-root"),
            OsString::from("campaign/terminal"),
        ]
    }

    fn construct_with(
        argv: &[OsString],
        parsed_preflight_only: bool,
        risc0_dev_mode: Option<&OsStr>,
        manifest_byte_length: usize,
        packet_id: &str,
    ) -> Result<Eip0045B4TerminalEvidenceCampaignReceiptV1> {
        let identities = identities();
        Eip0045B4TerminalEvidenceCampaignReceiptV1::new(B4TerminalEvidenceCampaignReceiptInputsV1 {
            campaign_precommit: &identities[0],
            positive_input_set: &identities[1],
            positive_generation_set: &identities[2],
            executor_artifact: &identities[3],
            executor_build_descriptor: &identities[4],
            executor_contract: &identities[5],
            process_argv: argv,
            parsed_preflight_only,
            risc0_dev_mode,
            terminal_packet_manifest_byte_length: manifest_byte_length,
            terminal_packet_id: packet_id,
        })
    }

    fn valid_receipt() -> Eip0045B4TerminalEvidenceCampaignReceiptV1 {
        construct_with(&valid_argv(), false, None, 1, &"a7".repeat(32)).unwrap()
    }

    fn identity_mut(
        wire: &mut TerminalEvidenceCampaignReceiptWireV1,
        index: usize,
    ) -> &mut B4ContractArtifactIdentityV1 {
        match index {
            0 => &mut wire.campaign_precommit,
            1 => &mut wire.positive_input_set,
            2 => &mut wire.positive_generation_set,
            3 => &mut wire.executor.artifact,
            4 => &mut wire.executor.build_descriptor,
            5 => &mut wire.executor.executor_contract,
            _ => panic!("identity index outside fixed six-role receipt"),
        }
    }

    fn canonical_unchecked(wire: &TerminalEvidenceCampaignReceiptWireV1) -> Vec<u8> {
        canonical_json_bytes(&serde_json::to_value(wire).unwrap()).unwrap()
    }

    #[test]
    fn canonical_argv_digest_preserves_exact_retained_tokens() {
        let argv = valid_argv();

        assert_eq!(
            b4_publish_terminal_evidence_canonical_argv_sha256(&argv, false).unwrap(),
            "e1434876672a03766a93d0131193f0b10395725a1594c687232ffc43bb55a92a"
        );
        let changed_binary = [
            OsString::from("another-bin"),
            OsString::from(PUBLISH_TERMINAL_EVIDENCE_COMMAND),
            OsString::from("--outer-root"),
            OsString::from("campaign/terminal"),
        ];
        assert_eq!(
            b4_publish_terminal_evidence_canonical_argv_sha256(&changed_binary, false).unwrap(),
            b4_publish_terminal_evidence_canonical_argv_sha256(&argv, false).unwrap()
        );

        let mut changed_token = argv.clone();
        changed_token[3] = OsString::from("campaign/other");
        assert_ne!(
            b4_publish_terminal_evidence_canonical_argv_sha256(&changed_token, false).unwrap(),
            b4_publish_terminal_evidence_canonical_argv_sha256(&argv, false).unwrap()
        );
        let split_boundary = [
            OsString::from("ignored-bin"),
            OsString::from(PUBLISH_TERMINAL_EVIDENCE_COMMAND),
            OsString::from("--outer-root"),
            OsString::from("campaign"),
            OsString::from("/terminal"),
        ];
        assert_ne!(
            b4_publish_terminal_evidence_canonical_argv_sha256(&split_boundary, false).unwrap(),
            b4_publish_terminal_evidence_canonical_argv_sha256(&argv, false).unwrap()
        );
        let mut with_empty = argv.to_vec();
        with_empty.insert(3, OsString::new());
        assert_ne!(
            b4_publish_terminal_evidence_canonical_argv_sha256(&with_empty, false).unwrap(),
            b4_publish_terminal_evidence_canonical_argv_sha256(&argv, false).unwrap()
        );
        let mut reordered = argv.clone();
        reordered.swap(2, 3);
        assert_ne!(
            b4_publish_terminal_evidence_canonical_argv_sha256(&reordered, false).unwrap(),
            b4_publish_terminal_evidence_canonical_argv_sha256(&argv, false).unwrap()
        );
        let omitted = [
            OsString::from("ignored-bin"),
            OsString::from(PUBLISH_TERMINAL_EVIDENCE_COMMAND),
            OsString::from("--outer-root"),
        ];
        assert_ne!(
            b4_publish_terminal_evidence_canonical_argv_sha256(&omitted, false).unwrap(),
            b4_publish_terminal_evidence_canonical_argv_sha256(&argv, false).unwrap()
        );
    }

    #[test]
    fn canonical_argv_and_constructor_reject_non_execute_modes() {
        let argv = valid_argv();
        assert!(b4_publish_terminal_evidence_canonical_argv_sha256(&argv, true).is_err());
        assert!(construct_with(&argv, true, None, 1, &"a7".repeat(32)).is_err());
        assert!(construct_with(&argv, false, Some(OsStr::new("1")), 1, &"a7".repeat(32),).is_err());
        let raw_preflight = [
            OsString::from("ignored-bin"),
            OsString::from(PUBLISH_TERMINAL_EVIDENCE_COMMAND),
            OsString::from(PREFLIGHT_ONLY_FLAG),
        ];
        assert!(b4_publish_terminal_evidence_canonical_argv_sha256(&raw_preflight, false).is_err());
        assert!(b4_publish_terminal_evidence_canonical_argv_sha256(&[], false).is_err());
        assert!(b4_publish_terminal_evidence_canonical_argv_sha256(
            &[OsString::from("ignored-bin")],
            false,
        )
        .is_err());
        assert!(b4_publish_terminal_evidence_canonical_argv_sha256(
            &[
                OsString::from("ignored-bin"),
                OsString::from("wrong-command"),
            ],
            false,
        )
        .is_err());
    }

    #[test]
    fn shared_invocation_validator_accepts_exact_preflight_and_rejects_mode_drift() {
        let execute = valid_argv();
        validate_b4_campaign_command_invocation(&execute, PUBLISH_TERMINAL_EVIDENCE_COMMAND, false)
            .unwrap();

        let mut preflight = execute.to_vec();
        preflight.push(OsString::from(PREFLIGHT_ONLY_FLAG));
        validate_b4_campaign_command_invocation(
            &preflight,
            PUBLISH_TERMINAL_EVIDENCE_COMMAND,
            true,
        )
        .unwrap();
        validate_b4_publish_terminal_evidence_invocation(&preflight, true).unwrap();

        assert!(validate_b4_campaign_command_invocation(
            &preflight,
            PUBLISH_TERMINAL_EVIDENCE_COMMAND,
            false,
        )
        .is_err());
        assert!(validate_b4_campaign_command_invocation(
            &execute,
            PUBLISH_TERMINAL_EVIDENCE_COMMAND,
            true,
        )
        .is_err());
        assert!(validate_b4_publish_terminal_evidence_invocation(&execute, true).is_err());
        assert!(validate_b4_publish_terminal_evidence_invocation(&preflight, false).is_err());

        let mut duplicate_preflight = preflight.clone();
        duplicate_preflight.push(OsString::from(PREFLIGHT_ONLY_FLAG));
        assert!(validate_b4_campaign_command_invocation(
            &duplicate_preflight,
            PUBLISH_TERMINAL_EVIDENCE_COMMAND,
            true,
        )
        .is_err());

        let mut wrong_command = execute.clone();
        wrong_command[1] = OsString::from("generate-negative-ancestry-witness-catalog");
        assert!(validate_b4_campaign_command_invocation(
            &wrong_command,
            PUBLISH_TERMINAL_EVIDENCE_COMMAND,
            false,
        )
        .is_err());
        assert!(
            validate_b4_campaign_command_invocation(&execute, "not-a-frozen-command", false)
                .is_err()
        );
    }

    #[test]
    fn receipt_round_trips_with_fixed_workload_and_getters() {
        let receipt = valid_receipt();
        let source = receipt.to_canonical_jcs().unwrap();
        let reopened =
            Eip0045B4TerminalEvidenceCampaignReceiptV1::from_canonical_jcs(&source).unwrap();
        assert_eq!(reopened, receipt);
        assert_eq!(
            reopened.campaign_precommit().path,
            "campaign/precommit.json"
        );
        assert_eq!(
            reopened.positive_input_set().path,
            "campaign/positive-input-set.json"
        );
        assert_eq!(
            reopened.positive_generation_set().path,
            "campaign/positive-generation-set.json"
        );
        assert_eq!(reopened.executor_artifact().path, "executor/artifact");
        assert_eq!(
            reopened.executor_build_descriptor().path,
            "executor/build-descriptor.json"
        );
        assert_eq!(reopened.executor_contract().path, "executor/contract.json");
        assert_eq!(
            reopened.canonical_argv_sha256(),
            "e1434876672a03766a93d0131193f0b10395725a1594c687232ffc43bb55a92a"
        );
        assert_eq!(reopened.terminal_packet_manifest_byte_length(), 1);
        assert_eq!(reopened.terminal_packet_id(), "a7".repeat(32));
        assert_eq!(
            reopened
                .wire
                .workload
                .fixture_ids
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            B4_TERMINAL_FIXTURE_LAYOUT
                .iter()
                .map(|layout| layout.fixture_id)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            (
                reopened.wire.workload.fixture_count,
                reopened
                    .wire
                    .workload
                    .freshly_generated_fixture_receipt_count,
                reopened
                    .wire
                    .workload
                    .reused_authenticated_fixture_receipt_count,
                reopened.wire.workload.direct_pair_count,
                reopened
                    .wire
                    .workload
                    .top_level_proving_api_invocation_count,
            ),
            (9, 8, 1, 1, 12)
        );
    }

    #[test]
    fn source_bound_precedes_utf8_json_and_typed_parsing() {
        let empty =
            Eip0045B4TerminalEvidenceCampaignReceiptV1::from_canonical_jcs(&[]).unwrap_err();
        assert!(format!("{empty:#}").contains("source byte length"));

        let oversized = vec![0xff; MAX_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES + 1];
        let error =
            Eip0045B4TerminalEvidenceCampaignReceiptV1::from_canonical_jcs(&oversized).unwrap_err();
        assert!(format!("{error:#}").contains("source byte length"));

        let at_limit = vec![0xff; MAX_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES];
        let error =
            Eip0045B4TerminalEvidenceCampaignReceiptV1::from_canonical_jcs(&at_limit).unwrap_err();
        assert!(!format!("{error:#}").contains("source byte length"));
    }

    #[test]
    fn all_six_identity_roles_enforce_bounds_encodings_and_shape() {
        let maxima = [
            u64::try_from(MAX_CAMPAIGN_PRECOMMIT_BYTES).unwrap(),
            MAX_INPUT_SET_BYTES,
            MAX_INPUT_SET_BYTES,
            MAX_EXECUTOR_ARTIFACT_BYTES,
            MAX_DESCRIPTOR_BYTES,
            u64::try_from(MAX_EXECUTOR_CONTRACT_BYTES).unwrap(),
        ];
        let encodings = [
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            B4ContractArtifactEncodingV1::RawBytes,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
        ];
        for index in 0..6 {
            let mut receipt = valid_receipt();
            identity_mut(&mut receipt.wire, index).byte_length = maxima[index];
            assert!(receipt.validate().is_ok());

            identity_mut(&mut receipt.wire, index).byte_length =
                maxima[index].checked_add(1).unwrap();
            assert!(receipt.validate().is_err());

            let mut receipt = valid_receipt();
            identity_mut(&mut receipt.wire, index).encoding =
                if encodings[index] == B4ContractArtifactEncodingV1::RawBytes {
                    B4ContractArtifactEncodingV1::Rfc8785Jcs
                } else {
                    B4ContractArtifactEncodingV1::RawBytes
                };
            assert!(receipt.validate().is_err());

            let mut receipt = valid_receipt();
            identity_mut(&mut receipt.wire, index).byte_length = 0;
            assert!(receipt.validate().is_err());

            let mut receipt = valid_receipt();
            identity_mut(&mut receipt.wire, index).sha256 = "AA".repeat(32);
            assert!(receipt.validate().is_err());

            let mut receipt = valid_receipt();
            identity_mut(&mut receipt.wire, index).sha256 = "00".repeat(32);
            assert!(receipt.validate().is_err());

            let mut receipt = valid_receipt();
            identity_mut(&mut receipt.wire, index).path = "../escape".to_owned();
            assert!(receipt.validate().is_err());
        }
    }

    #[test]
    fn every_identity_pair_rejects_equality_and_component_ancestry() {
        for left in 0..6 {
            for right in (left + 1)..6 {
                for (left_path, right_path) in [
                    ("shared/path", "shared/path"),
                    ("shared/path", "shared/path/child"),
                    ("shared/path/child", "shared/path"),
                ] {
                    let mut receipt = valid_receipt();
                    identity_mut(&mut receipt.wire, left).path = left_path.to_owned();
                    identity_mut(&mut receipt.wire, right).path = right_path.to_owned();
                    assert!(
                        receipt.validate().is_err(),
                        "identity pair {left}/{right} admitted {left_path}/{right_path}"
                    );
                }
            }
        }
    }

    #[test]
    fn packet_bounds_digests_and_fixed_values_fail_closed() {
        let mut receipt = valid_receipt();
        receipt.wire.terminal_packet.manifest_byte_length =
            u64::try_from(B4_TERMINAL_EVIDENCE_MANIFEST_MAX_BYTES).unwrap();
        assert!(receipt.validate().is_ok());
        receipt.wire.terminal_packet.manifest_byte_length = 0;
        assert!(receipt.validate().is_err());
        receipt.wire.terminal_packet.manifest_byte_length =
            u64::try_from(B4_TERMINAL_EVIDENCE_MANIFEST_MAX_BYTES)
                .unwrap()
                .checked_add(1)
                .unwrap();
        assert!(receipt.validate().is_err());

        let mut receipt = valid_receipt();
        receipt.wire.terminal_packet.packet_id = "00".repeat(32);
        assert!(receipt.validate().is_err());
        let mut receipt = valid_receipt();
        receipt.wire.terminal_packet.packet_id = "AA".repeat(32);
        assert!(receipt.validate().is_err());

        let mut receipt = valid_receipt();
        receipt.wire.invocation.canonical_argv_sha256 = "0".repeat(64);
        assert!(receipt.validate().is_ok());
        receipt.wire.invocation.canonical_argv_sha256 = "AA".repeat(32);
        assert!(receipt.validate().is_err());

        let mut mutations = Vec::new();
        let mut receipt = valid_receipt();
        receipt.wire.format.push_str("-wrong");
        mutations.push(receipt);
        let mut receipt = valid_receipt();
        receipt.wire.format_version = 2;
        mutations.push(receipt);
        let mut receipt = valid_receipt();
        receipt.wire.invocation.command = "wrong".to_owned();
        mutations.push(receipt);
        let mut receipt = valid_receipt();
        receipt.wire.invocation.risc0_dev_mode = "present".to_owned();
        mutations.push(receipt);
        let mut receipt = valid_receipt();
        receipt.wire.workload.fixture_ids.swap(0, 1);
        mutations.push(receipt);
        let mut receipt = valid_receipt();
        receipt.wire.workload.fixture_count = 8;
        mutations.push(receipt);
        let mut receipt = valid_receipt();
        receipt
            .wire
            .workload
            .freshly_generated_fixture_receipt_count = 7;
        mutations.push(receipt);
        let mut receipt = valid_receipt();
        receipt
            .wire
            .workload
            .reused_authenticated_fixture_receipt_count = 2;
        mutations.push(receipt);
        let mut receipt = valid_receipt();
        receipt.wire.workload.direct_pair_count = 2;
        mutations.push(receipt);
        let mut receipt = valid_receipt();
        receipt.wire.workload.top_level_proving_api_invocation_count = 11;
        mutations.push(receipt);
        assert!(mutations.iter().all(|receipt| receipt.validate().is_err()));
    }

    #[test]
    fn parser_rejects_unknown_duplicate_noncanonical_and_alias_shapes() {
        let receipt = valid_receipt();
        let canonical = receipt.to_canonical_jcs().unwrap();
        let mut root: Value = serde_json::from_slice(&canonical).unwrap();
        root.as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), Value::Bool(true));
        assert!(
            Eip0045B4TerminalEvidenceCampaignReceiptV1::from_canonical_jcs(
                &canonical_json_bytes(&root).unwrap(),
            )
            .is_err()
        );

        let mut nested: Value = serde_json::from_slice(&canonical).unwrap();
        nested["executor"]
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), Value::Bool(true));
        assert!(
            Eip0045B4TerminalEvidenceCampaignReceiptV1::from_canonical_jcs(
                &canonical_json_bytes(&nested).unwrap(),
            )
            .is_err()
        );

        let mut alias: Value = serde_json::from_slice(&canonical).unwrap();
        let executor = alias["executor"].as_object_mut().unwrap();
        let contract = executor.remove("executorContract").unwrap();
        executor.insert("commandContract".to_owned(), contract);
        assert!(
            Eip0045B4TerminalEvidenceCampaignReceiptV1::from_canonical_jcs(
                &canonical_json_bytes(&alias).unwrap(),
            )
            .is_err()
        );

        let canonical_text = String::from_utf8(canonical.clone()).unwrap();
        let duplicate = format!(
            "{{\"format\":\"{B4_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FORMAT}\",{}",
            &canonical_text[1..]
        );
        assert!(
            Eip0045B4TerminalEvidenceCampaignReceiptV1::from_canonical_jcs(duplicate.as_bytes(),)
                .is_err()
        );
        let pretty =
            serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&canonical).unwrap())
                .unwrap();
        assert!(Eip0045B4TerminalEvidenceCampaignReceiptV1::from_canonical_jcs(&pretty).is_err());
        let mut trailing = canonical;
        trailing.extend_from_slice(b"{}");
        assert!(
            Eip0045B4TerminalEvidenceCampaignReceiptV1::from_canonical_jcs(&trailing,).is_err()
        );
    }

    #[test]
    fn parser_rejects_missing_extra_or_mutated_fixed_workload() {
        let receipt = valid_receipt();
        let source = receipt.to_canonical_jcs().unwrap();
        let mut missing: Value = serde_json::from_slice(&source).unwrap();
        missing["workload"]["fixtureIds"]
            .as_array_mut()
            .unwrap()
            .remove(0);
        assert!(
            Eip0045B4TerminalEvidenceCampaignReceiptV1::from_canonical_jcs(
                &canonical_json_bytes(&missing).unwrap(),
            )
            .is_err()
        );
        let mut extra: Value = serde_json::from_slice(&source).unwrap();
        extra["workload"]["fixtureIds"]
            .as_array_mut()
            .unwrap()
            .push(Value::String("extra".to_owned()));
        assert!(
            Eip0045B4TerminalEvidenceCampaignReceiptV1::from_canonical_jcs(
                &canonical_json_bytes(&extra).unwrap(),
            )
            .is_err()
        );
        let mut mutated = receipt.wire;
        mutated.workload.fixture_ids[0] = "wrong".to_owned();
        assert!(
            Eip0045B4TerminalEvidenceCampaignReceiptV1::from_canonical_jcs(&canonical_unchecked(
                &mutated
            ),)
            .is_err()
        );
    }

    #[test]
    fn schema_matches_compiled_receipt_constants_layout_and_bounds() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../finalizer-schema/b4-terminal-evidence-campaign-receipt-v1.schema.json"
        ))
        .unwrap();
        assert_eq!(
            schema["$id"],
            "urn:ergo:eip-0045:b4-terminal-evidence-campaign-receipt-v1"
        );
        assert_eq!(
            schema["x-eip0045-canonicalByteLengthMaximum"],
            MAX_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES
        );
        assert_eq!(
            schema["properties"]["format"]["const"],
            B4_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FORMAT
        );
        assert_eq!(
            schema["properties"]["formatVersion"]["const"],
            B4_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FORMAT_VERSION
        );
        assert_eq!(
            schema["properties"]["terminalPacket"]["properties"]["manifestByteLength"]["maximum"],
            B4_TERMINAL_EVIDENCE_MANIFEST_MAX_BYTES
        );
        assert_eq!(
            schema["properties"]["invocation"]["properties"]["command"]["const"],
            PUBLISH_TERMINAL_EVIDENCE_COMMAND
        );
        assert_eq!(
            schema["properties"]["invocation"]["properties"]["canonicalArgvSha256"]["$ref"],
            "#/$defs/LowerHex32"
        );
        assert_eq!(
            schema["properties"]["invocation"]["properties"]["risc0DevMode"]["const"],
            RISC0_DEV_MODE_ABSENT
        );
        assert_eq!(
            schema["properties"]["terminalPacket"]["properties"]["packetId"]["$ref"],
            "#/$defs/NonzeroHex32"
        );
        for (definition, maximum, encoding) in [
            (
                "CampaignPrecommitIdentity",
                u64::try_from(MAX_CAMPAIGN_PRECOMMIT_BYTES).unwrap(),
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
            ),
            (
                "PositiveInputSetIdentity",
                MAX_INPUT_SET_BYTES,
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
            ),
            (
                "PositiveGenerationSetIdentity",
                MAX_INPUT_SET_BYTES,
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
            ),
            (
                "ExecutorArtifactIdentity",
                MAX_EXECUTOR_ARTIFACT_BYTES,
                B4ContractArtifactEncodingV1::RawBytes,
            ),
            (
                "ExecutorBuildDescriptorIdentity",
                MAX_DESCRIPTOR_BYTES,
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
            ),
            (
                "ExecutorContractIdentity",
                u64::try_from(MAX_EXECUTOR_CONTRACT_BYTES).unwrap(),
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
            ),
        ] {
            assert_eq!(
                schema["$defs"][definition]["allOf"][1]["properties"]["byteLength"]["maximum"],
                maximum
            );
            assert_eq!(
                schema["$defs"][definition]["allOf"][1]["properties"]["encoding"]["const"],
                serde_json::to_value(encoding).unwrap()
            );
        }
        let schema_ids = schema["properties"]["workload"]["properties"]["fixtureIds"]
            ["prefixItems"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["const"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            schema_ids,
            B4_TERMINAL_FIXTURE_LAYOUT
                .iter()
                .map(|layout| layout.fixture_id)
                .collect::<Vec<_>>()
        );
        for (field, expected) in [
            ("fixtureCount", 9),
            ("freshlyGeneratedFixtureReceiptCount", 8),
            ("reusedAuthenticatedFixtureReceiptCount", 1),
            ("directPairCount", 1),
            ("topLevelProvingApiInvocationCount", 12),
        ] {
            assert_eq!(
                schema["properties"]["workload"]["properties"][field]["const"],
                expected
            );
        }

        fn require_closed_objects(value: &Value) {
            match value {
                Value::Object(object) => {
                    if object.get("type").and_then(Value::as_str) == Some("object") {
                        assert_eq!(
                            object.get("additionalProperties"),
                            Some(&Value::Bool(false))
                        );
                    }
                    for nested in object.values() {
                        require_closed_objects(nested);
                    }
                }
                Value::Array(values) => {
                    for nested in values {
                        require_closed_objects(nested);
                    }
                }
                _ => {}
            }
        }
        require_closed_objects(&schema);
    }

    #[cfg(feature = "positive-gate")]
    #[test]
    fn draft_2020_12_schema_accepts_rust_receipt_and_rejects_representative_drifts() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../finalizer-schema/b4-terminal-evidence-campaign-receipt-v1.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::draft202012::options().build(&schema).unwrap();
        // Draft 2020-12 cannot express the raw/JCS byte ceiling or the
        // cross-identity path antichain; sibling Rust tests bind both.
        let receipt = valid_receipt();
        let valid: Value = serde_json::from_slice(&receipt.to_canonical_jcs().unwrap()).unwrap();
        assert!(validator.validate(&valid).is_ok());

        let mut zero_argv_receipt = receipt.clone();
        zero_argv_receipt.wire.invocation.canonical_argv_sha256 = "00".repeat(32);
        zero_argv_receipt.validate().unwrap();
        let zero_argv: Value =
            serde_json::from_slice(&zero_argv_receipt.to_canonical_jcs().unwrap()).unwrap();
        assert!(validator.validate(&zero_argv).is_ok());

        let mut uppercase_argv = valid.clone();
        uppercase_argv["invocation"]["canonicalArgvSha256"] = Value::String("AA".repeat(32));
        let mut zero_packet = valid.clone();
        zero_packet["terminalPacket"]["packetId"] = Value::String("00".repeat(32));
        let mut wrong_executor_encoding = valid.clone();
        wrong_executor_encoding["executor"]["artifact"]["encoding"] =
            Value::String("rfc8785-jcs".to_owned());
        let mut wrong_fixture_order = valid.clone();
        wrong_fixture_order["workload"]["fixtureIds"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        let mut oversized_manifest = valid.clone();
        oversized_manifest["terminalPacket"]["manifestByteLength"] =
            Value::from(B4_TERMINAL_EVIDENCE_MANIFEST_MAX_BYTES + 1);
        let mut unknown_field = valid;
        unknown_field
            .as_object_mut()
            .unwrap()
            .insert("host".to_owned(), Value::String("forbidden".to_owned()));

        for drift in [
            uppercase_argv,
            zero_packet,
            wrong_executor_encoding,
            wrong_fixture_order,
            oversized_manifest,
            unknown_field,
        ] {
            assert!(validator.validate(&drift).is_err());
            assert!(
                Eip0045B4TerminalEvidenceCampaignReceiptV1::from_canonical_jcs(
                    &canonical_json_bytes(&drift).unwrap()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn maximal_shape_remains_bounded_and_generic_serializer_checks_post_jcs() {
        let mut receipt = valid_receipt();
        let maxima = [
            u64::try_from(MAX_CAMPAIGN_PRECOMMIT_BYTES).unwrap(),
            MAX_INPUT_SET_BYTES,
            MAX_INPUT_SET_BYTES,
            MAX_EXECUTOR_ARTIFACT_BYTES,
            MAX_DESCRIPTOR_BYTES,
            u64::try_from(MAX_EXECUTOR_CONTRACT_BYTES).unwrap(),
        ];
        for (index, maximum) in maxima.into_iter().enumerate() {
            let role = identity_mut(&mut receipt.wire, index);
            let fill = char::from(b'a' + u8::try_from(index).unwrap());
            role.path = std::iter::repeat_n(fill, 240).collect();
            role.byte_length = maximum;
            role.sha256 = "ff".repeat(32);
        }
        receipt.wire.invocation.canonical_argv_sha256 = "f".repeat(64);
        receipt.wire.terminal_packet.manifest_byte_length =
            u64::try_from(B4_TERMINAL_EVIDENCE_MANIFEST_MAX_BYTES).unwrap();
        receipt.wire.terminal_packet.packet_id = "ff".repeat(32);
        let source = receipt.to_canonical_jcs().unwrap();
        assert!(source.len() < MAX_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES);

        #[derive(Serialize, Deserialize)]
        struct SerializationBoundProbe {
            padding: String,
        }
        impl CanonicalContract for SerializationBoundProbe {
            fn validate_contract(&self) -> Result<()> {
                Ok(())
            }
        }
        assert!(serialize_contract(
            &SerializationBoundProbe {
                padding: "x".repeat(16),
            },
            MAX_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES,
            "serialization-bound probe",
        )
        .is_ok());
        assert!(serialize_contract(
            &SerializationBoundProbe {
                padding: "x".repeat(MAX_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES,),
            },
            MAX_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES,
            "serialization-bound probe",
        )
        .is_err());
    }

    #[test]
    fn constructor_accepts_manifest_endpoints_and_rejects_packet_drift() {
        assert!(construct_with(&valid_argv(), false, None, 1, &"a7".repeat(32)).is_ok());
        assert!(construct_with(
            &valid_argv(),
            false,
            None,
            B4_TERMINAL_EVIDENCE_MANIFEST_MAX_BYTES,
            &"a7".repeat(32),
        )
        .is_ok());
        assert!(construct_with(&valid_argv(), false, None, 0, &"a7".repeat(32)).is_err());
        assert!(construct_with(
            &valid_argv(),
            false,
            None,
            B4_TERMINAL_EVIDENCE_MANIFEST_MAX_BYTES + 1,
            &"a7".repeat(32),
        )
        .is_err());
        assert!(construct_with(&valid_argv(), false, None, 1, &"00".repeat(32)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_argv_rejects_before_hashing() {
        use std::os::unix::ffi::OsStringExt;

        let argv = [
            OsString::from("ignored-bin"),
            OsString::from(PUBLISH_TERMINAL_EVIDENCE_COMMAND),
            OsString::from_vec(vec![0xff]),
        ];
        assert!(b4_publish_terminal_evidence_canonical_argv_sha256(&argv, false).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn non_utf8_argv_rejects_before_hashing() {
        use std::os::windows::ffi::OsStringExt;

        let argv = [
            OsString::from("ignored-bin"),
            OsString::from(PUBLISH_TERMINAL_EVIDENCE_COMMAND),
            OsString::from_wide(&[0xd800]),
        ];
        assert!(b4_publish_terminal_evidence_canonical_argv_sha256(&argv, false).is_err());
    }
}
