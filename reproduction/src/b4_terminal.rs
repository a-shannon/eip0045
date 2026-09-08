//! Portable, closed catalogue for EIP-0045 B4 terminal fixtures.
//!
//! This module deliberately contains no RISC Zero verifier.  It defines the
//! byte-exact catalogue that independent implementations consume, validates
//! its closed RFC 8785 representation, authenticates the raw-seal artifacts,
//! and supports deterministic fixture selection by exact catalogue identity. The
//! generator-side replay must cryptographically verify every receipt before
//! constructing or accepting this catalogue.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    canonical::{canonical_json_bytes, validate_canonical_json_source, validate_lower_hex_exact},
    constants::{
        DIGEST_BYTES, PROOF_BYTES, RISC0_COMMIT, RISC0_INNER_CONTROL_ROOT_HEX, RISC0_REPOSITORY,
    },
    receipt_oracle_codec::{RECEIPT_ORACLE_CODEC_V1, RECEIPT_ORACLE_MAX_BYTES_U64},
};

/// Exact format discriminator for the terminal-fixture catalogue.
pub const B4_TERMINAL_FIXTURE_CATALOG_FORMAT: &str = "Eip0045B4TerminalFixtureCatalogV1";
/// Exact format version for the terminal-fixture catalogue.
pub const B4_TERMINAL_FIXTURE_CATALOG_FORMAT_VERSION: u8 = 1;
/// Non-promotional stage retained until the complete real-receipt corpus closes.
pub const B4_TERMINAL_FIXTURE_CATALOG_STAGE: &str = "candidate";
/// Exact pinned RISC Zero crate version represented by the catalogue.
pub const B4_TERMINAL_FIXTURE_RISC0_VERSION: &str = "3.0.5";
/// Exact non-consensus codec used for typed receipt-oracle replay.
pub const B4_TERMINAL_FIXTURE_RECEIPT_CODEC: &str = RECEIPT_ORACLE_CODEC_V1;
/// Repository-relative directory containing only terminal fixture artifacts.
pub const B4_TERMINAL_FIXTURE_DIRECTORY: &str =
    "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures";
/// Exact number of controls in RISC Zero v3.0.5's stock Poseidon2 root.
pub const B4_STOCK_CONTROL_COUNT: usize = 27;
/// Exact number of stock controls admitted by the initial EIP profile.
pub const B4_EIP_ALLOWED_CONTROL_COUNT: usize = 10;
/// Exact number of stock controls excluded by the initial EIP profile.
pub const B4_EIP_EXCLUDED_CONTROL_COUNT: usize = 17;
/// Exact number of cryptographically verified terminal fixtures.
pub const B4_TERMINAL_FIXTURE_COUNT: usize = 9;
/// Maximum canonical-byte length of a terminal-evidence packet manifest.
pub(crate) const B4_TERMINAL_EVIDENCE_MANIFEST_MAX_BYTES: usize = 65_536;

/// Maximum canonical-byte length of the terminal-fixture catalogue.
pub const B4_TERMINAL_FIXTURE_CATALOG_MAX_BYTES: usize = 256 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 96;

/// One immutable row in the pinned stock-control table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct B4StockControlLayoutV1 {
    /// Zero-based position in upstream `ALLOWED_CONTROL_IDS`.
    pub stock_index: u32,
    /// Stable catalogue family label.
    pub family: &'static str,
    /// Exact upstream recursion-program filename.
    pub upstream_program: &'static str,
    /// Exact Poseidon2 control ID from the pinned upstream source.
    pub control_id: &'static str,
    /// Whether the initial EIP profile admits this terminal.
    pub eip_allowed: bool,
}

/// Complete RISC Zero v3.0.5 Poseidon2 `ALLOWED_CONTROL_IDS` table.
///
/// These values are copied from commit [`RISC0_COMMIT`] and are independently
/// compared with the compiled upstream constants by the generator replay.
pub const B4_STOCK_CONTROL_LAYOUT: [B4StockControlLayoutV1; B4_STOCK_CONTROL_COUNT] = [
    stock(
        0,
        "identity",
        "identity.zkr",
        "0d79bc33b4760b4783cbb96fdc87724c7e0c463eb0ba1b2705d39f43c698bd2d",
        false,
    ),
    stock(
        1,
        "join",
        "join.zkr",
        "7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e",
        true,
    ),
    stock(
        2,
        "join-povw",
        "join_povw.zkr",
        "96cdf605f755f175a5661812810f2d491507c05f2ea4a83e4c3cad693d26651e",
        false,
    ),
    stock(
        3,
        "join-unwrap-povw",
        "join_unwrap_povw.zkr",
        "f74a894ff593584f65847630ead1a23af78c5f5fed2b61090866e01fa5767f12",
        false,
    ),
    stock(
        4,
        "lift-po2-14",
        "lift_rv32im_v2_14.zkr",
        "411fa636f2d364648f035174d3778d6340d9ae1dd648fc35657c173f01e27e5f",
        false,
    ),
    stock(
        5,
        "lift-po2-15",
        "lift_rv32im_v2_15.zkr",
        "1ca3ca03030719064ba61b3125bdd326fc57f74e799ef860bdea6f3227381e16",
        true,
    ),
    stock(
        6,
        "lift-po2-16",
        "lift_rv32im_v2_16.zkr",
        "c32b3627d2b3d60c64adf523a98bd16c0ff607471f3d6630d1f26d5e9406d841",
        true,
    ),
    stock(
        7,
        "lift-po2-17",
        "lift_rv32im_v2_17.zkr",
        "c9b08054994f542a6310b00d9b6fc6528ed7bb6f4ca5476a686847127cdfdc5b",
        true,
    ),
    stock(
        8,
        "lift-po2-18",
        "lift_rv32im_v2_18.zkr",
        "e7934a23ddce1423b425cf32aa23be29f48cd40e0b6ff9376dce6f3bf9d0bc35",
        true,
    ),
    stock(
        9,
        "lift-po2-19",
        "lift_rv32im_v2_19.zkr",
        "8c2fdd36ede09a4b9d316a43c51f1160cbd8876659c5f35810c3a119c60d3843",
        true,
    ),
    stock(
        10,
        "lift-po2-20",
        "lift_rv32im_v2_20.zkr",
        "34530b42028fb631c90e1226bb0e750d4b9b593840d45216f75dca449dac7734",
        true,
    ),
    stock(
        11,
        "lift-po2-21",
        "lift_rv32im_v2_21.zkr",
        "fd84d83092a1e1244d423a26d89c892ab098b467c6d82229912deb26e37d2562",
        true,
    ),
    stock(
        12,
        "lift-po2-22",
        "lift_rv32im_v2_22.zkr",
        "9d9dbf33535ab11f52a93839dfd23b352b7626009e81d9459fd04e488898ec6a",
        true,
    ),
    stock(
        13,
        "lift-povw-po2-14",
        "lift_rv32im_v2_povw_14.zkr",
        "c6972402cc81bc6c1122e65aa7cf463f3ac3f477c7dd860582ca7420fc7b8b02",
        false,
    ),
    stock(
        14,
        "lift-povw-po2-15",
        "lift_rv32im_v2_povw_15.zkr",
        "2f6ea1104bdd5955faa135611e8f803e7b4461703b937e704da70955ec115467",
        false,
    ),
    stock(
        15,
        "lift-povw-po2-16",
        "lift_rv32im_v2_povw_16.zkr",
        "a7b55654228123448cd67c400d9bf80b4e54eb3997ee92103e900903b6578862",
        false,
    ),
    stock(
        16,
        "lift-povw-po2-17",
        "lift_rv32im_v2_povw_17.zkr",
        "2adab2445391035b21f255606a1ba060a7d5a64db5cdf13d9fda7f22a2853270",
        false,
    ),
    stock(
        17,
        "lift-povw-po2-18",
        "lift_rv32im_v2_povw_18.zkr",
        "58b27422240db834c08b8e6c12000c093efce8613263f05825c380009c41da48",
        false,
    ),
    stock(
        18,
        "lift-povw-po2-19",
        "lift_rv32im_v2_povw_19.zkr",
        "26c84437d3e26875b259880d0f29da47ed5ca869133637701d33fb15a83dce4b",
        false,
    ),
    stock(
        19,
        "lift-povw-po2-20",
        "lift_rv32im_v2_povw_20.zkr",
        "177fde1441dc735dbd6a58245d82b2036623ac41547dc345f1fd7c486ac51462",
        false,
    ),
    stock(
        20,
        "lift-povw-po2-21",
        "lift_rv32im_v2_povw_21.zkr",
        "eac3fb487080a62e6ff85d331dd72a4706e50e55c9cb842dea48d71e3e119a04",
        false,
    ),
    stock(
        21,
        "lift-povw-po2-22",
        "lift_rv32im_v2_povw_22.zkr",
        "0344cd54d62d2a1b6538b674d5aa141250ff4c5be08c6e3d16cb5e1de632252d",
        false,
    ),
    stock(
        22,
        "resolve",
        "resolve.zkr",
        "53a7b23d07f99e5d5685e85874f5181e8486aa267a0ae607ffe9ba47c8bdda4a",
        true,
    ),
    stock(
        23,
        "resolve-povw",
        "resolve_povw.zkr",
        "20ac6e29b1806a143b508414140e2e15e461f93e04e3830af39cca362b8f005d",
        false,
    ),
    stock(
        24,
        "resolve-unwrap-povw",
        "resolve_unwrap_povw.zkr",
        "ba1d7275d5840e4f998e2c5120810c0eb197e90219696e2a64dec7662aa3cb06",
        false,
    ),
    stock(
        25,
        "union",
        "union.zkr",
        "7771415b778fea1923440e2eb22c4a1e1d7ada2d42cbe03d13402743c0988a31",
        false,
    ),
    stock(
        26,
        "unwrap-povw",
        "unwrap_povw.zkr",
        "1688f04cca489638862dba455c1d5c561513f975c885a3491f0fe12df761c847",
        false,
    ),
];

const fn stock(
    stock_index: u32,
    family: &'static str,
    upstream_program: &'static str,
    control_id: &'static str,
    eip_allowed: bool,
) -> B4StockControlLayoutV1 {
    B4StockControlLayoutV1 {
        stock_index,
        family,
        upstream_program,
        control_id,
        eip_allowed,
    }
}

/// Closed claim type used by one receipt oracle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4TerminalClaimKindV1 {
    /// `SuccinctReceipt<ReceiptClaim>`.
    ReceiptClaim,
    /// `SuccinctReceipt<WorkClaim<ReceiptClaim>>`.
    WorkReceiptClaim,
    /// `SuccinctReceipt<UnionClaim>`.
    UnionClaim,
}

/// Immutable fixture row expected by the catalogue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct B4TerminalFixtureLayoutV1 {
    /// Exact stable fixture ID.
    pub fixture_id: &'static str,
    /// Exact family, or `None` for the variable allowed/non-OK fixture.
    pub expected_family: Option<&'static str>,
    /// Exact typed receipt-oracle claim.
    pub claim_kind: B4TerminalClaimKindV1,
    /// Required EIP disposition.
    pub eip_allowed: bool,
    /// Required direct application status; absent only for `UnionClaim`.
    pub direct_ok: Option<bool>,
}

/// Eight excluded shipping families followed by one allowed/non-OK fixture.
pub const B4_TERMINAL_FIXTURE_LAYOUT: [B4TerminalFixtureLayoutV1; B4_TERMINAL_FIXTURE_COUNT] = [
    fixture(
        "lift-po2-14",
        Some("identity"),
        B4TerminalClaimKindV1::ReceiptClaim,
        false,
        Some(true),
    ),
    fixture(
        "lift-povw-po2-18",
        Some("lift-povw-po2-18"),
        B4TerminalClaimKindV1::WorkReceiptClaim,
        false,
        Some(true),
    ),
    fixture(
        "join-povw",
        Some("join-povw"),
        B4TerminalClaimKindV1::WorkReceiptClaim,
        false,
        Some(true),
    ),
    fixture(
        "join-unwrap-povw",
        Some("join-unwrap-povw"),
        B4TerminalClaimKindV1::ReceiptClaim,
        false,
        Some(true),
    ),
    fixture(
        "resolve-povw",
        Some("resolve-povw"),
        B4TerminalClaimKindV1::WorkReceiptClaim,
        false,
        Some(true),
    ),
    fixture(
        "resolve-unwrap-povw",
        Some("resolve-unwrap-povw"),
        B4TerminalClaimKindV1::ReceiptClaim,
        false,
        Some(true),
    ),
    fixture(
        "union",
        Some("union"),
        B4TerminalClaimKindV1::UnionClaim,
        false,
        None,
    ),
    fixture(
        "unwrap-povw",
        Some("unwrap-povw"),
        B4TerminalClaimKindV1::ReceiptClaim,
        false,
        Some(true),
    ),
    fixture(
        "allowed-terminal-non-ok",
        None,
        B4TerminalClaimKindV1::ReceiptClaim,
        true,
        Some(false),
    ),
];

const fn fixture(
    fixture_id: &'static str,
    expected_family: Option<&'static str>,
    claim_kind: B4TerminalClaimKindV1,
    eip_allowed: bool,
    direct_ok: Option<bool>,
) -> B4TerminalFixtureLayoutV1 {
    B4TerminalFixtureLayoutV1 {
        fixture_id,
        expected_family,
        claim_kind,
        eip_allowed,
        direct_ok,
    }
}

/// Return the exact repository path of one fixture's raw seal.
///
/// # Errors
///
/// Returns an error when `fixture_id` is outside the closed fixture layout.
pub fn terminal_fixture_raw_seal_path(fixture_id: &str) -> Result<String> {
    require_fixture_id(fixture_id)?;
    Ok(format!(
        "{B4_TERMINAL_FIXTURE_DIRECTORY}/{fixture_id}.raw-seal.bin"
    ))
}

/// Return the exact repository path of one typed receipt oracle.
///
/// # Errors
///
/// Returns an error when `fixture_id` is outside the closed fixture layout.
pub fn terminal_fixture_receipt_oracle_path(fixture_id: &str) -> Result<String> {
    require_fixture_id(fixture_id)?;
    Ok(format!(
        "{B4_TERMINAL_FIXTURE_DIRECTORY}/{fixture_id}.receipt-oracle.bincode"
    ))
}

fn require_fixture_id(fixture_id: &str) -> Result<()> {
    ensure!(
        B4_TERMINAL_FIXTURE_LAYOUT
            .iter()
            .any(|row| row.fixture_id == fixture_id),
        "terminal fixture ID is outside the closed V1 layout"
    );
    Ok(())
}

/// Pinned upstream identity recorded in the catalogue.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4TerminalUpstreamV1 {
    /// Exact upstream Git repository.
    pub repository: String,
    /// Exact upstream Git commit.
    pub commit: String,
    /// Exact `risc0-zkvm` crate version.
    pub risc0_zkvm_version: String,
    /// Exact bounded non-consensus receipt codec.
    pub receipt_oracle_codec: String,
}

/// One exact stock-control row serialized in the catalogue.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4StockControlV1 {
    /// Zero-based upstream table index.
    pub stock_index: u32,
    /// Stable catalogue family.
    pub family: String,
    /// Exact upstream recursion-program filename.
    pub upstream_program: String,
    /// Exact Poseidon2 control ID.
    pub control_id: String,
    /// Whether the initial EIP profile admits the terminal.
    pub eip_allowed: bool,
}

/// Exact identity of one repository artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4TerminalArtifactV1 {
    /// Repository-relative path.
    pub path: String,
    /// Exact artifact byte length.
    pub byte_length: u64,
    /// Lowercase SHA-256 of the exact bytes.
    pub sha256: String,
}

/// Exact terminal metadata proven by one succinct receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4TerminalBindingV1 {
    /// Zero-based stock table index, also bound by the inclusion proof.
    pub stock_index: u32,
    /// Exact receipt control ID.
    pub control_id: String,
    /// Exact inner and inclusion control root.
    pub control_root: String,
    /// Whether the initial EIP profile admits the terminal.
    pub eip_allowed: bool,
}

/// Exact zkVM exit status opened from a receipt claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4ExitStatusV1 {
    /// System exit component.
    pub system: u32,
    /// User exit component.
    pub user: u32,
    /// Derived `Halted(0)` predicate.
    pub ok: bool,
}

/// Exact assumption state opened from a receipt claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum B4AssumptionsBindingV1 {
    /// The exit status has no output and therefore no assumptions field.
    NoOutput,
    /// Exact digest of the assumptions list and its derived empty predicate.
    Commitment {
        /// SHA-256 typed digest of the assumptions list.
        digest: String,
        /// Whether the commitment represents the empty assumptions list.
        empty: bool,
    },
}

/// Direct application claim opened below a normal or `PoVW` receipt claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4DirectApplicationBindingV1 {
    /// Digest of the nested `ReceiptClaim`.
    pub application_claim_digest: String,
    /// Exact exit status.
    pub status: B4ExitStatusV1,
    /// Exact assumptions commitment or structurally absent output.
    pub assumptions: B4AssumptionsBindingV1,
}

/// One `UnionClaim` side plus every catalogue witness for its source claim.
///
/// A union proof authenticates an assumption digest, not the bytes or control
/// ID of the receipt used while proving.  `witness_fixture_ids` is therefore an
/// exhaustive evidence set, not a false provenance assertion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4UnionAssumptionBindingV1 {
    /// Exact `Assumption { claim, control_root }` digest.
    pub assumption_digest: String,
    /// Exact outer claim digest committed inside that assumption.
    pub source_claim_digest: String,
    /// Ordered exhaustive catalogue fixtures opening `source_claim_digest`.
    pub witness_fixture_ids: Vec<String>,
}

/// Honest application binding for a direct receipt or a union receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum B4ApplicationBindingV1 {
    /// The receipt directly opens a `ReceiptClaim` (possibly below `WorkClaim`).
    Direct {
        /// Exact opened application semantics.
        binding: B4DirectApplicationBindingV1,
    },
    /// The union binds two assumptions; application semantics are transitive
    /// through the listed, independently verified witnesses.
    Union {
        /// Left digest of the sorted `UnionClaim`.
        left: B4UnionAssumptionBindingV1,
        /// Right digest of the sorted `UnionClaim`.
        right: B4UnionAssumptionBindingV1,
    },
}

/// One cryptographically replayed terminal fixture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4TerminalFixtureV1 {
    /// Stable fixture ID.
    pub fixture_id: String,
    /// Stable terminal family.
    pub family: String,
    /// Typed receipt-oracle claim.
    pub claim_kind: B4TerminalClaimKindV1,
    /// Exact outer claim digest authenticated by the raw seal.
    pub claim_digest: String,
    /// Exact terminal/root/EIP-disposition binding.
    pub terminal: B4TerminalBindingV1,
    /// Direct or transitive application binding.
    pub application: B4ApplicationBindingV1,
    /// Byte-exact raw seal used by independent verifiers and mutations.
    pub raw_seal: B4TerminalArtifactV1,
    /// Bounded typed oracle used only for upstream replay.
    pub receipt_oracle: B4TerminalArtifactV1,
}

/// Complete portable terminal-fixture catalogue.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4TerminalFixtureCatalogV1 {
    /// Exact format discriminator.
    pub format: String,
    /// Exact format version.
    pub format_version: u8,
    /// Mandatory non-promotional stage.
    pub stage: String,
    /// Pinned upstream source and oracle codec.
    pub upstream: B4TerminalUpstreamV1,
    /// Exact expected guest image/program ID for every direct application claim.
    pub program_id: String,
    /// Exact stock Poseidon2 control root.
    pub inner_control_root: String,
    /// Complete ordered stock-control table.
    pub stock_controls: Vec<B4StockControlV1>,
    /// Eight excluded shipping families plus one allowed/non-OK fixture.
    pub fixtures: Vec<B4TerminalFixtureV1>,
}

impl Eip0045B4TerminalFixtureCatalogV1 {
    /// Parse exact RFC 8785 JCS and enforce every closed catalogue invariant.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, duplicate-key, noncanonical, unknown,
    /// reordered, incomplete, inconsistent, or non-exact catalogue data.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            source.len() <= B4_TERMINAL_FIXTURE_CATALOG_MAX_BYTES,
            "terminal-fixture catalogue exceeds its canonical-byte bound"
        );
        let value = validate_canonical_json_source(source)
            .context("terminal-fixture catalogue is not exact RFC 8785 JCS")?;
        let catalog: Self =
            serde_json::from_value(value).context("invalid terminal-fixture catalogue shape")?;
        catalog.validate()?;
        ensure!(
            catalog.to_canonical_jcs()? == source,
            "terminal-fixture catalogue does not round-trip byte-exactly"
        );
        Ok(catalog)
    }

    /// Serialize the validated catalogue as exact RFC 8785 JCS.
    ///
    /// # Errors
    ///
    /// Returns an error when validation, JSON conversion, or the byte bound
    /// fails.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value =
            serde_json::to_value(self).context("cannot serialize terminal-fixture catalogue")?;
        let bytes = canonical_json_bytes(&value)?;
        ensure!(
            bytes.len() <= B4_TERMINAL_FIXTURE_CATALOG_MAX_BYTES,
            "terminal-fixture catalogue exceeds its canonical-byte bound"
        );
        Ok(bytes)
    }

    /// Enforce the exact source table, fixture inventory, ordering, and links.
    ///
    /// This is a portable structural/authentication check.  Acceptance as B4
    /// evidence additionally requires generator-side upstream cryptographic
    /// replay of all receipt oracles.
    ///
    /// # Errors
    ///
    /// Returns an error for any closed-shape, identity, semantic, ordering,
    /// uniqueness, artifact, or transitive-union defect.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == B4_TERMINAL_FIXTURE_CATALOG_FORMAT
                && self.format_version == B4_TERMINAL_FIXTURE_CATALOG_FORMAT_VERSION
                && self.stage == B4_TERMINAL_FIXTURE_CATALOG_STAGE,
            "terminal-fixture catalogue format, version, or stage drift"
        );
        ensure!(
            self.upstream.repository == RISC0_REPOSITORY
                && self.upstream.commit == RISC0_COMMIT
                && self.upstream.risc0_zkvm_version == B4_TERMINAL_FIXTURE_RISC0_VERSION
                && self.upstream.receipt_oracle_codec == B4_TERMINAL_FIXTURE_RECEIPT_CODEC,
            "terminal-fixture upstream identity or codec drift"
        );
        validate_digest(&self.program_id, "terminal-fixture program ID")?;
        ensure!(
            self.inner_control_root == RISC0_INNER_CONTROL_ROOT_HEX,
            "terminal-fixture inner control root drift"
        );
        validate_stock_controls(&self.stock_controls)?;
        validate_fixtures(self)
    }

    /// Authenticate an exhaustive in-memory map of the nine raw seals.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing or extra path, wrong byte length, or
    /// SHA-256 mismatch.
    pub fn validate_raw_seal_artifacts(&self, raw_seals: &BTreeMap<String, Vec<u8>>) -> Result<()> {
        self.validate()?;
        ensure!(
            raw_seals.len() == self.fixtures.len(),
            "terminal raw-seal map is not exhaustive"
        );
        for fixture in &self.fixtures {
            let bytes = raw_seals
                .get(&fixture.raw_seal.path)
                .with_context(|| format!("missing raw seal for {}", fixture.fixture_id))?;
            authenticate_artifact(&fixture.raw_seal, bytes, PROOF_BYTES as u64)?;
        }
        let expected = self
            .fixtures
            .iter()
            .map(|fixture| fixture.raw_seal.path.as_str())
            .collect::<BTreeSet<_>>();
        ensure!(
            raw_seals
                .keys()
                .all(|path| expected.contains(path.as_str())),
            "terminal raw-seal map contains an extra path"
        );
        Ok(())
    }
}

fn validate_stock_controls(controls: &[B4StockControlV1]) -> Result<()> {
    ensure!(
        controls.len() == B4_STOCK_CONTROL_COUNT,
        "stock-control table does not contain exactly 27 rows"
    );
    let mut ids = BTreeSet::new();
    let mut allowed = 0_usize;
    for (actual, expected) in controls.iter().zip(B4_STOCK_CONTROL_LAYOUT) {
        ensure!(
            actual.stock_index == expected.stock_index
                && actual.family == expected.family
                && actual.upstream_program == expected.upstream_program
                && actual.control_id == expected.control_id
                && actual.eip_allowed == expected.eip_allowed,
            "stock-control row {} differs from the pinned v3.0.5 table",
            expected.stock_index
        );
        validate_semantic_id(&actual.family, "stock-control family")?;
        validate_digest(&actual.control_id, "stock control ID")?;
        ensure!(
            ids.insert(actual.control_id.as_str()),
            "duplicate stock control ID"
        );
        allowed += usize::from(actual.eip_allowed);
    }
    ensure!(
        allowed == B4_EIP_ALLOWED_CONTROL_COUNT
            && controls.len() - allowed == B4_EIP_EXCLUDED_CONTROL_COUNT,
        "stock-control EIP disposition is not exactly 10 allowed and 17 excluded"
    );
    Ok(())
}

fn validate_fixtures(catalog: &Eip0045B4TerminalFixtureCatalogV1) -> Result<()> {
    ensure!(
        catalog.fixtures.len() == B4_TERMINAL_FIXTURE_COUNT,
        "terminal-fixture catalogue does not contain exactly nine rows"
    );
    let mut fixture_ids = BTreeSet::new();
    let mut control_ids = BTreeSet::new();
    let mut artifact_paths = BTreeSet::new();
    let mut raw_digests = BTreeSet::new();

    for (fixture, layout) in catalog.fixtures.iter().zip(B4_TERMINAL_FIXTURE_LAYOUT) {
        ensure!(
            fixture.fixture_id == layout.fixture_id && fixture.claim_kind == layout.claim_kind,
            "terminal fixture order, ID, or claim kind drift"
        );
        validate_semantic_id(&fixture.fixture_id, "terminal fixture ID")?;
        validate_semantic_id(&fixture.family, "terminal fixture family")?;
        validate_digest(&fixture.claim_digest, "terminal fixture claim digest")?;
        ensure!(
            fixture_ids.insert(fixture.fixture_id.as_str()),
            "duplicate terminal fixture ID"
        );

        let stock_index = usize::try_from(fixture.terminal.stock_index)
            .context("terminal stock index does not fit usize")?;
        let stock = catalog
            .stock_controls
            .get(stock_index)
            .context("terminal stock index is outside the stock table")?;
        ensure!(
            stock.family == fixture.family
                && stock.control_id == fixture.terminal.control_id
                && stock.eip_allowed == fixture.terminal.eip_allowed
                && fixture.terminal.control_root == catalog.inner_control_root,
            "terminal fixture metadata does not match its exact stock row/root"
        );
        if let Some(expected_family) = layout.expected_family {
            ensure!(
                fixture.family == expected_family,
                "fixed terminal fixture family drift"
            );
        }
        ensure!(
            fixture.terminal.eip_allowed == layout.eip_allowed,
            "terminal fixture EIP disposition drift"
        );
        ensure!(
            control_ids.insert(fixture.terminal.control_id.as_str()),
            "duplicate terminal fixture control ID"
        );

        validate_artifact(
            &fixture.raw_seal,
            &terminal_fixture_raw_seal_path(layout.fixture_id)?,
            PROOF_BYTES as u64,
            PROOF_BYTES as u64,
            "raw seal",
        )?;
        validate_artifact(
            &fixture.receipt_oracle,
            &terminal_fixture_receipt_oracle_path(layout.fixture_id)?,
            1,
            RECEIPT_ORACLE_MAX_BYTES_U64,
            "receipt oracle",
        )?;
        ensure!(
            artifact_paths.insert(fixture.raw_seal.path.as_str())
                && artifact_paths.insert(fixture.receipt_oracle.path.as_str()),
            "duplicate terminal fixture artifact path"
        );
        ensure!(
            raw_digests.insert(fixture.raw_seal.sha256.as_str()),
            "duplicate terminal raw-seal SHA-256"
        );

        match (&fixture.application, layout.direct_ok) {
            (B4ApplicationBindingV1::Direct { binding }, Some(expected_ok)) => {
                validate_direct_binding(binding)?;
                ensure!(
                    binding.status.ok == expected_ok,
                    "terminal fixture direct status does not isolate its intended policy"
                );
                ensure!(
                    assumptions_are_empty_or_absent(&binding.assumptions),
                    "terminal fixture carries a non-empty assumptions list"
                );
            }
            (B4ApplicationBindingV1::Union { .. }, None) => {}
            _ => bail!("terminal fixture application binding kind drift"),
        }
    }

    let union = catalog
        .fixtures
        .iter()
        .find(|fixture| fixture.fixture_id == "union")
        .context("union fixture is missing")?;
    let B4ApplicationBindingV1::Union { left, right } = &union.application else {
        bail!("union fixture does not carry a union application binding");
    };
    validate_union_side(left, catalog)?;
    validate_union_side(right, catalog)?;
    Ok(())
}

fn validate_direct_binding(binding: &B4DirectApplicationBindingV1) -> Result<()> {
    validate_digest(
        &binding.application_claim_digest,
        "application claim digest",
    )?;
    ensure!(
        binding.status.ok == (binding.status.system == 0 && binding.status.user == 0),
        "application status ok flag is not derived from Halted(0)"
    );
    match &binding.assumptions {
        B4AssumptionsBindingV1::NoOutput => ensure!(
            binding.status.system == 2,
            "no-output assumptions state requires a system exit"
        ),
        B4AssumptionsBindingV1::Commitment { digest, .. } => {
            validate_digest(digest, "assumptions digest")?;
            ensure!(
                binding.status.system <= 1,
                "output assumptions commitment requires halted or paused status"
            );
        }
    }
    Ok(())
}

fn validate_union_side(
    side: &B4UnionAssumptionBindingV1,
    catalog: &Eip0045B4TerminalFixtureCatalogV1,
) -> Result<()> {
    validate_digest(&side.assumption_digest, "union assumption digest")?;
    validate_digest(&side.source_claim_digest, "union source claim digest")?;
    ensure!(
        !side.witness_fixture_ids.is_empty(),
        "union assumption has no verified catalogue witness"
    );

    let expected = catalog
        .fixtures
        .iter()
        .filter(|fixture| {
            fixture.fixture_id != "union"
                && fixture.fixture_id != "allowed-terminal-non-ok"
                && fixture.claim_digest == side.source_claim_digest
                && matches!(fixture.application, B4ApplicationBindingV1::Direct { .. })
        })
        .map(|fixture| fixture.fixture_id.clone())
        .collect::<Vec<_>>();
    ensure!(
        side.witness_fixture_ids == expected,
        "union witness fixture IDs are not the exhaustive catalogue-order set"
    );
    ensure!(
        !expected.is_empty(),
        "union source claim has no eligible direct shipping witness"
    );

    let mut first: Option<&B4DirectApplicationBindingV1> = None;
    for witness_id in &side.witness_fixture_ids {
        let witness = catalog
            .fixtures
            .iter()
            .find(|fixture| fixture.fixture_id == *witness_id)
            .context("union witness fixture disappeared")?;
        let B4ApplicationBindingV1::Direct { binding } = &witness.application else {
            bail!("union witness is not a direct application fixture");
        };
        ensure!(
            binding.status.ok && assumptions_are_empty_or_absent(&binding.assumptions),
            "union witness is not an otherwise-acceptable application claim"
        );
        if let Some(expected_binding) = first {
            ensure!(
                binding == expected_binding,
                "equal union source claims have inconsistent opened semantics"
            );
        } else {
            first = Some(binding);
        }
    }
    Ok(())
}

fn assumptions_are_empty_or_absent(binding: &B4AssumptionsBindingV1) -> bool {
    matches!(
        binding,
        B4AssumptionsBindingV1::NoOutput | B4AssumptionsBindingV1::Commitment { empty: true, .. }
    )
}

fn validate_artifact(
    artifact: &B4TerminalArtifactV1,
    expected_path: &str,
    minimum: u64,
    maximum: u64,
    label: &str,
) -> Result<()> {
    ensure!(artifact.path == expected_path, "{label} path drift");
    ensure!(
        (minimum..=maximum).contains(&artifact.byte_length),
        "{label} byte length is outside its closed bound"
    );
    validate_digest(&artifact.sha256, &format!("{label} SHA-256"))
}

fn authenticate_artifact(
    artifact: &B4TerminalArtifactV1,
    bytes: &[u8],
    exact_length: u64,
) -> Result<()> {
    ensure!(
        artifact.byte_length == exact_length && u64::try_from(bytes.len())? == artifact.byte_length,
        "terminal artifact byte length mismatch"
    );
    ensure!(
        sha256_hex(bytes) == artifact.sha256,
        "terminal artifact SHA-256 mismatch"
    );
    Ok(())
}

fn validate_semantic_id(value: &str, label: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= MAX_IDENTIFIER_BYTES,
        "{label} is empty or too long"
    );
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "{label} is not lower-kebab ASCII"
    );
    ensure!(
        !value.starts_with('-') && !value.ends_with('-') && !value.contains("--"),
        "{label} is not canonical lower-kebab ASCII"
    );
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    validate_lower_hex_exact(value, DIGEST_BYTES).with_context(|| format!("invalid {label}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Synthetic catalogue bytes and backing sources for resolver-only tests.
///
/// This helper is deliberately test-only and carries no cryptographic receipt
/// evidence. Production callers cannot select these sources.
#[cfg(test)]
pub(crate) type SyntheticTerminalFixtureSources = (Vec<u8>, BTreeMap<String, Vec<u8>>);

#[cfg(test)]
pub(crate) fn synthetic_terminal_fixture_catalog_source() -> Result<SyntheticTerminalFixtureSources>
{
    let (catalog, mut sources) = tests::synthetic_catalog();
    for (index, fixture) in catalog.fixtures.iter().enumerate() {
        sources.insert(
            fixture.receipt_oracle.path.clone(),
            vec![u8::try_from(index).context("synthetic terminal fixture index does not fit u8")?],
        );
    }
    Ok((catalog.to_canonical_jcs()?, sources))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_catalogue_uses_shared_receipt_oracle_codec_authority() {
        assert_eq!(
            B4_TERMINAL_FIXTURE_RECEIPT_CODEC,
            crate::receipt_oracle_codec::RECEIPT_ORACLE_CODEC_V1
        );
        let schema: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../finalizer-schema/b4-terminal-fixture-catalog-v1.schema.json"
        ))
        .unwrap();
        assert_eq!(
            schema["$defs"]["Upstream"]["properties"]["receiptOracleCodec"]["const"],
            crate::receipt_oracle_codec::RECEIPT_ORACLE_CODEC_V1
        );
    }
    use serde_json::json;

    // These fixtures exercise only portable grammar and authentication.  They
    // are deliberately synthetic and are never cryptographic receipt evidence.
    #[allow(clippy::too_many_lines)]
    pub(super) fn synthetic_catalog()
    -> (Eip0045B4TerminalFixtureCatalogV1, BTreeMap<String, Vec<u8>>) {
        let stock_controls = B4_STOCK_CONTROL_LAYOUT
            .iter()
            .map(|row| B4StockControlV1 {
                stock_index: row.stock_index,
                family: row.family.to_owned(),
                upstream_program: row.upstream_program.to_owned(),
                control_id: row.control_id.to_owned(),
                eip_allowed: row.eip_allowed,
            })
            .collect::<Vec<_>>();
        let mut raw_seals = BTreeMap::new();
        let mut fixtures = Vec::new();
        for (index, layout) in B4_TERMINAL_FIXTURE_LAYOUT.iter().enumerate() {
            let stock = match layout.expected_family {
                Some(family) => B4_STOCK_CONTROL_LAYOUT
                    .iter()
                    .find(|row| row.family == family)
                    .unwrap(),
                None => &B4_STOCK_CONTROL_LAYOUT[1],
            };
            let raw = vec![u8::try_from(index + 1).unwrap(); PROOF_BYTES];
            let raw_path = terminal_fixture_raw_seal_path(layout.fixture_id).unwrap();
            let receipt_path = terminal_fixture_receipt_oracle_path(layout.fixture_id).unwrap();
            raw_seals.insert(raw_path.clone(), raw.clone());
            let status = if layout.direct_ok == Some(false) {
                B4ExitStatusV1 {
                    system: 2,
                    user: 0,
                    ok: false,
                }
            } else {
                B4ExitStatusV1 {
                    system: 0,
                    user: 0,
                    ok: true,
                }
            };
            let application = if layout.claim_kind == B4TerminalClaimKindV1::UnionClaim {
                B4ApplicationBindingV1::Union {
                    left: B4UnionAssumptionBindingV1 {
                        assumption_digest: digest(90),
                        source_claim_digest: digest(1),
                        witness_fixture_ids: vec!["lift-po2-14".to_owned()],
                    },
                    right: B4UnionAssumptionBindingV1 {
                        assumption_digest: digest(91),
                        source_claim_digest: digest(2),
                        witness_fixture_ids: vec!["lift-povw-po2-18".to_owned()],
                    },
                }
            } else {
                B4ApplicationBindingV1::Direct {
                    binding: B4DirectApplicationBindingV1 {
                        application_claim_digest: digest(40 + index),
                        status,
                        assumptions: if layout.direct_ok == Some(false) {
                            B4AssumptionsBindingV1::NoOutput
                        } else {
                            B4AssumptionsBindingV1::Commitment {
                                digest: digest(0),
                                empty: true,
                            }
                        },
                    },
                }
            };
            fixtures.push(B4TerminalFixtureV1 {
                fixture_id: layout.fixture_id.to_owned(),
                family: stock.family.to_owned(),
                claim_kind: layout.claim_kind,
                claim_digest: digest(index + 1),
                terminal: B4TerminalBindingV1 {
                    stock_index: stock.stock_index,
                    control_id: stock.control_id.to_owned(),
                    control_root: RISC0_INNER_CONTROL_ROOT_HEX.to_owned(),
                    eip_allowed: stock.eip_allowed,
                },
                application,
                raw_seal: B4TerminalArtifactV1 {
                    path: raw_path,
                    byte_length: PROOF_BYTES as u64,
                    sha256: sha256_hex(&raw),
                },
                receipt_oracle: B4TerminalArtifactV1 {
                    path: receipt_path,
                    byte_length: 1,
                    sha256: sha256_hex(&[u8::try_from(index).unwrap()]),
                },
            });
        }
        let catalog = Eip0045B4TerminalFixtureCatalogV1 {
            format: B4_TERMINAL_FIXTURE_CATALOG_FORMAT.to_owned(),
            format_version: B4_TERMINAL_FIXTURE_CATALOG_FORMAT_VERSION,
            stage: B4_TERMINAL_FIXTURE_CATALOG_STAGE.to_owned(),
            upstream: B4TerminalUpstreamV1 {
                repository: RISC0_REPOSITORY.to_owned(),
                commit: RISC0_COMMIT.to_owned(),
                risc0_zkvm_version: B4_TERMINAL_FIXTURE_RISC0_VERSION.to_owned(),
                receipt_oracle_codec: B4_TERMINAL_FIXTURE_RECEIPT_CODEC.to_owned(),
            },
            program_id: digest(200),
            inner_control_root: RISC0_INNER_CONTROL_ROOT_HEX.to_owned(),
            stock_controls,
            fixtures,
        };
        (catalog, raw_seals)
    }

    fn digest(value: usize) -> String {
        format!("{value:064x}")
    }

    #[test]
    fn pinned_table_is_exactly_27_with_10_allowed_and_17_excluded() {
        assert_eq!(B4_STOCK_CONTROL_LAYOUT.len(), B4_STOCK_CONTROL_COUNT);
        assert_eq!(
            B4_STOCK_CONTROL_LAYOUT
                .iter()
                .filter(|row| row.eip_allowed)
                .count(),
            B4_EIP_ALLOWED_CONTROL_COUNT
        );
        assert_eq!(
            B4_STOCK_CONTROL_LAYOUT
                .iter()
                .filter(|row| !row.eip_allowed)
                .count(),
            B4_EIP_EXCLUDED_CONTROL_COUNT
        );
        let allowed = B4_STOCK_CONTROL_LAYOUT
            .iter()
            .filter(|row| row.eip_allowed)
            .map(|row| row.family)
            .collect::<Vec<_>>();
        assert_eq!(
            allowed,
            [
                "join",
                "lift-po2-15",
                "lift-po2-16",
                "lift-po2-17",
                "lift-po2-18",
                "lift-po2-19",
                "lift-po2-20",
                "lift-po2-21",
                "lift-po2-22",
                "resolve",
            ]
        );
    }

    #[test]
    fn real_terminal_layout_uses_identity_without_changing_the_stock_partition() {
        assert_eq!(B4_STOCK_CONTROL_LAYOUT.len(), 27);
        assert_eq!(
            B4_STOCK_CONTROL_LAYOUT
                .iter()
                .filter(|row| row.eip_allowed)
                .count(),
            10
        );
        assert_eq!(B4_STOCK_CONTROL_LAYOUT[0].family, "identity");
        assert_eq!(B4_STOCK_CONTROL_LAYOUT[4].family, "lift-po2-14");
        assert_eq!(B4_TERMINAL_FIXTURE_LAYOUT[0].fixture_id, "lift-po2-14");
        assert_eq!(
            B4_TERMINAL_FIXTURE_LAYOUT[0].expected_family,
            Some("identity")
        );
    }

    #[test]
    fn stable_terminal_abi_keeps_paths_schemas_and_negative_sweeps() {
        use crate::{
            b4_plan::Eip0045B4NegativePlanV1,
            b4_terminal_byte_map::{B4TerminalByteMapKind, terminal_byte_map_paths},
        };

        assert_eq!(
            terminal_byte_map_paths(B4TerminalByteMapKind::RawSeal),
            &[
                "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/allowed-terminal-non-ok.raw-seal.bin",
                "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/join-povw.raw-seal.bin",
                "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/join-unwrap-povw.raw-seal.bin",
                "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/lift-po2-14.raw-seal.bin",
                "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/lift-povw-po2-18.raw-seal.bin",
                "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/resolve-povw.raw-seal.bin",
                "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/resolve-unwrap-povw.raw-seal.bin",
                "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/union.raw-seal.bin",
                "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/unwrap-povw.raw-seal.bin",
            ]
        );
        assert_eq!(
            terminal_byte_map_paths(B4TerminalByteMapKind::ReceiptOracle),
            &[
                "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/allowed-terminal-non-ok.receipt-oracle.bincode",
                "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/join-povw.receipt-oracle.bincode",
                "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/join-unwrap-povw.receipt-oracle.bincode",
                "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/lift-po2-14.receipt-oracle.bincode",
                "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/lift-povw-po2-18.receipt-oracle.bincode",
                "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/resolve-povw.receipt-oracle.bincode",
                "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/resolve-unwrap-povw.receipt-oracle.bincode",
                "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/union.receipt-oracle.bincode",
                "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/unwrap-povw.receipt-oracle.bincode",
            ]
        );

        let terminal_schema: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../finalizer-schema/b4-terminal-fixture-catalog-v1.schema.json"
        ))
        .unwrap();
        assert_eq!(
            terminal_schema["$defs"]["FixtureId"]["enum"][0],
            "lift-po2-14"
        );

        let materialization_schema: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../finalizer-schema/b4-negative-materialization-set-v1.schema.json"
        ))
        .unwrap();
        let schema_execution_ids =
            materialization_schema["properties"]["executions"]["prefixItems"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|row| row["properties"]["executionId"]["const"].as_str())
                .filter(|execution_id| execution_id.ends_with("--lift-po2-14"))
                .collect::<Vec<_>>();
        assert_eq!(
            schema_execution_ids,
            [
                "terminal-excluded-control-id-sweep--lift-po2-14",
                "terminal-excluded-shipping-family-sweep--lift-po2-14",
            ]
        );

        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let control_sweep = plan
            .groups
            .iter()
            .find(|group| group.case_id == "terminal-excluded-control-id-sweep")
            .unwrap();
        assert_eq!(control_sweep.executions.len(), 17);
        assert_eq!(
            control_sweep
                .executions
                .iter()
                .map(|execution| execution.variant_id.as_str())
                .collect::<Vec<_>>(),
            [
                "identity",
                "join-povw",
                "join-unwrap-povw",
                "lift-po2-14",
                "lift-povw-po2-14",
                "lift-povw-po2-15",
                "lift-povw-po2-16",
                "lift-povw-po2-17",
                "lift-povw-po2-18",
                "lift-povw-po2-19",
                "lift-povw-po2-20",
                "lift-povw-po2-21",
                "lift-povw-po2-22",
                "resolve-povw",
                "resolve-unwrap-povw",
                "union",
                "unwrap-povw",
            ]
        );
        let shipping_sweep = plan
            .groups
            .iter()
            .find(|group| group.case_id == "terminal-excluded-shipping-family-sweep")
            .unwrap();
        assert_eq!(
            [
                &control_sweep.executions[3].execution_id,
                &shipping_sweep.executions[0].execution_id,
            ],
            [
                "terminal-excluded-control-id-sweep--lift-po2-14",
                "terminal-excluded-shipping-family-sweep--lift-po2-14",
            ]
        );
    }

    #[test]
    fn synthetic_grammar_only_catalog_round_trips_as_strict_jcs() {
        let (catalog, _) = synthetic_catalog();
        catalog.validate().unwrap();
        let bytes = catalog.to_canonical_jcs().unwrap();
        assert_eq!(
            Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(&bytes).unwrap(),
            catalog
        );

        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["unexpected"] = json!(true);
        assert!(
            Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(
                &canonical_json_bytes(&value).unwrap()
            )
            .is_err()
        );
        let pretty = serde_json::to_vec_pretty(
            &serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        )
        .unwrap();
        assert!(Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(&pretty).is_err());
        let duplicate = bytes
            .strip_suffix(b"}")
            .unwrap()
            .iter()
            .copied()
            .chain(br#",\"stage\":\"candidate\"}"#.iter().copied())
            .collect::<Vec<_>>();
        assert!(Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(&duplicate).is_err());
    }

    #[test]
    fn synthetic_grammar_only_order_status_paths_and_union_links_fail_closed() {
        let (catalog, _) = synthetic_catalog();

        let mut reordered = catalog.clone();
        reordered.fixtures.swap(0, 1);
        assert!(reordered.validate().is_err());

        let mut wrong_status = catalog.clone();
        let B4ApplicationBindingV1::Direct { binding } = &mut wrong_status.fixtures[0].application
        else {
            unreachable!()
        };
        binding.status.ok = false;
        assert!(wrong_status.validate().is_err());

        let mut wrong_path = catalog.clone();
        wrong_path.fixtures[0].raw_seal.path = "../seal.bin".to_owned();
        assert!(wrong_path.validate().is_err());

        let mut incomplete_union = catalog;
        let B4ApplicationBindingV1::Union { left, .. } =
            &mut incomplete_union.fixtures[6].application
        else {
            unreachable!()
        };
        left.witness_fixture_ids.clear();
        assert!(incomplete_union.validate().is_err());
    }
}
