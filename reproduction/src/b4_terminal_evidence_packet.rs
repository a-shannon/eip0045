//! Closed packet layout and canonical documents for terminal evidence export.

#![allow(
    dead_code,
    reason = "later packet tranches consume the crate-private layout and document codecs"
)]

#[cfg(feature = "negative-materialization-set")]
mod import;

#[cfg(all(feature = "negative-materialization-set", test))]
#[allow(
    unused_imports,
    reason = "crate-private projection fixture is consumed by sibling materialization tests"
)]
pub(crate) use import::B4TerminalEvidenceImportProjectionFixtureV1;
#[cfg(feature = "negative-materialization-set")]
pub use import::{B4TerminalEvidenceImportAuthorityV1, B4TerminalEvidenceImportAuthorityV2};
#[cfg(feature = "negative-materialization-set")]
#[allow(
    unused_imports,
    reason = "crate-private import projections are consumed only by enabled sibling producers"
)]
pub(crate) use import::{
    B4TerminalEvidenceImportByteIdentityV1, B4TerminalMaterializationProjectionV1,
};
#[cfg(all(feature = "negative-materialization-set", target_os = "linux"))]
pub use import::{
    authenticate_b4_terminal_evidence_import_from_directory_descriptor,
    authenticate_b4_terminal_evidence_import_from_directory_descriptor_v2,
};

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, ensure};
use risc0_binfmt::compute_image_id;
use risc0_zkvm::ReceiptClaim;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    b4_campaign_contract::{b4_paths_conflict, validate_safe_relative_path},
    b4_case8_terminal_join_root::{
        B4Case8TerminalJoinPacketSourcesV1, B4OwnedCase8TerminalJoinRootV1,
        B4VerifiedCase8TerminalJoinReplayV1,
    },
    b4_terminal::{
        B4_TERMINAL_FIXTURE_CATALOG_MAX_BYTES, B4_TERMINAL_FIXTURE_COUNT,
        B4_TERMINAL_FIXTURE_LAYOUT, Eip0045B4TerminalFixtureCatalogV1,
        terminal_fixture_raw_seal_path, terminal_fixture_receipt_oracle_path,
    },
    b4_terminal_oracle::{
        B4TerminalOracleReplayError, VerifiedB4TerminalOracleReplay, replay_fixed_terminal_oracles,
    },
    b4_validator::{B4PositiveTerminalKind, authenticate_initial_profile_package},
    canonical::{canonical_json_bytes, validate_canonical_json_source, validate_lower_hex_exact},
    constants::{DIGEST_BYTES, MAX_STATEMENT_BYTES, PROOF_BYTES},
    ergo_statement::parse_ergo_statement_v1,
    receipt_oracle_codec::RECEIPT_ORACLE_MAX_BYTES,
    receipt_oracle_replay::{
        CompiledStockSuccinctReplayV1, DecodedStockSuccinctReceiptV1, StockReceiptReplayError,
        VerifiedStockSuccinctReceiptV1,
    },
};

#[cfg(unix)]
pub use crate::b4_terminal_evidence_io::reopen_b4_terminal_evidence_packet_from_directory_descriptor;
pub use crate::b4_terminal_evidence_io::{
    B4TerminalEvidencePublicationLayoutV1, project_b4_terminal_evidence_publication_layout,
    reopen_b4_terminal_evidence_packet,
};
#[cfg(feature = "b4-terminal-evidence-publication")]
pub use crate::b4_terminal_evidence_io::{
    preflight_b4_terminal_evidence_publication, publish_b4_terminal_evidence_packet,
};
#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
pub use crate::b4_terminal_evidence_io::{
    preflight_b4_terminal_evidence_publication_from_directory_descriptor,
    publish_b4_terminal_evidence_packet_from_directory_descriptor,
};

/// Number of payload files in the closed terminal-evidence packet.
pub const B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT: usize = 29;
/// Number of regular files including the manifest and completion document.
pub const B4_TERMINAL_EVIDENCE_FILE_COUNT: usize = 31;
/// Canonical packet-relative manifest filename.
pub const B4_TERMINAL_EVIDENCE_MANIFEST_FILE: &str = "B4-TERMINAL-EVIDENCE-MANIFEST.json";
/// Canonical packet-relative completion filename.
pub const B4_TERMINAL_EVIDENCE_COMPLETION_FILE: &str = "B4-TERMINAL-EVIDENCE-COMPLETE.json";
/// Maximum byte length of either retained recursive source oracle.
pub const B4_TERMINAL_EVIDENCE_RECURSIVE_SOURCE_MAX_BYTES: usize = 32 * 1024 * 1024;

const MANIFEST_FORMAT: &str = "Eip0045B4TerminalEvidenceManifestV1";
const COMPLETION_FORMAT: &str = "Eip0045B4TerminalEvidenceCompletionV1";
const FORMAT_VERSION: u8 = 1;
pub(super) const MANIFEST_MAX_BYTES: usize =
    crate::b4_terminal::B4_TERMINAL_EVIDENCE_MANIFEST_MAX_BYTES;
pub(super) const COMPLETION_MAX_BYTES: usize = 4_096;
const GUEST_ELF_MAX_BYTES: usize = 4 * 1024 * 1024;
const PROFILE_MANIFEST_BYTES: usize = 458;
const PROFILE_ALGORITHM_BYTES: usize = 29_773;
const PROFILE_CONSTANTS_BYTES: usize = 65_119;

/// Borrowed exact three-file frozen-profile payload.
pub struct B4TerminalEvidenceProfilePayloadsV1<'a> {
    manifest: &'a [u8],
    algorithm: &'a [u8],
    constants: &'a [u8],
}

impl<'a> B4TerminalEvidenceProfilePayloadsV1<'a> {
    /// Construct the fixed profile view from bytes alone.
    ///
    /// # Errors
    ///
    /// Returns an error before decode when any file has the wrong compiled
    /// byte length.
    pub fn new(manifest: &'a [u8], algorithm: &'a [u8], constants: &'a [u8]) -> Result<Self> {
        require_exact_length("profile manifest", manifest.len(), PROFILE_MANIFEST_BYTES)?;
        require_exact_length(
            "profile algorithm",
            algorithm.len(),
            PROFILE_ALGORITHM_BYTES,
        )?;
        require_exact_length(
            "profile constants",
            constants.len(),
            PROFILE_CONSTANTS_BYTES,
        )?;
        Ok(Self {
            manifest,
            algorithm,
            constants,
        })
    }
}

/// Borrowed producer-source payloads retained for later source replay.
pub struct B4TerminalEvidenceProducerSourcesV1<'a> {
    guest_elf: &'a [u8],
    statement: &'a [u8],
    case0_lift15_receipt_oracle: &'a [u8],
    case8_terminal_join_recursive_oracle: &'a [u8],
    case9_terminal_resolve_recursive_oracle: &'a [u8],
}

impl<'a> B4TerminalEvidenceProducerSourcesV1<'a> {
    /// Construct the five fixed source roles from bytes alone.
    ///
    /// The three producer-oracle formats remain outside this consumer's
    /// semantic and lineage authority.
    ///
    /// # Errors
    ///
    /// Returns an error before decode or allocation when any source is outside
    /// its compiled role bound.
    pub fn new(
        guest_elf: &'a [u8],
        statement: &'a [u8],
        case0_lift15_receipt_oracle: &'a [u8],
        case8_terminal_join_recursive_oracle: &'a [u8],
        case9_terminal_resolve_recursive_oracle: &'a [u8],
    ) -> Result<Self> {
        require_bounded_length("guest.elf", guest_elf.len(), GUEST_ELF_MAX_BYTES)?;
        require_bounded_length("statement", statement.len(), MAX_STATEMENT_BYTES)?;
        require_bounded_length(
            "case-0 receipt oracle",
            case0_lift15_receipt_oracle.len(),
            RECEIPT_ORACLE_MAX_BYTES,
        )?;
        require_bounded_length(
            "case-8 recursive oracle",
            case8_terminal_join_recursive_oracle.len(),
            B4_TERMINAL_EVIDENCE_RECURSIVE_SOURCE_MAX_BYTES,
        )?;
        require_bounded_length(
            "case-9 recursive oracle",
            case9_terminal_resolve_recursive_oracle.len(),
            B4_TERMINAL_EVIDENCE_RECURSIVE_SOURCE_MAX_BYTES,
        )?;
        Ok(Self {
            guest_elf,
            statement,
            case0_lift15_receipt_oracle,
            case8_terminal_join_recursive_oracle,
            case9_terminal_resolve_recursive_oracle,
        })
    }
}

/// Borrowed fixed-position fixture seal/oracle pair.
#[derive(Clone, Copy)]
pub struct B4TerminalEvidenceFixturePairPayloadV1<'a> {
    raw_seal: &'a [u8],
    receipt_oracle: &'a [u8],
}

impl<'a> B4TerminalEvidenceFixturePairPayloadV1<'a> {
    /// Construct one array-position fixture pair from bytes alone.
    ///
    /// # Errors
    ///
    /// Returns an error before decode when either byte role is out of bounds.
    pub fn new(raw_seal: &'a [u8], receipt_oracle: &'a [u8]) -> Result<Self> {
        validate_pair_lengths(raw_seal, receipt_oracle)?;
        Ok(Self {
            raw_seal,
            receipt_oracle,
        })
    }

    /// Exact raw-seal bytes.
    #[must_use]
    pub const fn raw_seal(&self) -> &'a [u8] {
        self.raw_seal
    }

    /// Exact canonical typed-receipt bytes.
    #[must_use]
    pub const fn receipt_oracle(&self) -> &'a [u8] {
        self.receipt_oracle
    }
}

/// Borrowed final direct case-8 seal/oracle pair.
#[derive(Clone, Copy)]
pub struct B4TerminalEvidenceDirectPairPayloadV1<'a> {
    raw_seal: &'a [u8],
    receipt_oracle: &'a [u8],
}

impl<'a> B4TerminalEvidenceDirectPairPayloadV1<'a> {
    /// Construct the fixed direct pair from bytes alone.
    ///
    /// # Errors
    ///
    /// Returns an error before decode when either byte role is out of bounds.
    pub fn new(raw_seal: &'a [u8], receipt_oracle: &'a [u8]) -> Result<Self> {
        validate_pair_lengths(raw_seal, receipt_oracle)?;
        Ok(Self {
            raw_seal,
            receipt_oracle,
        })
    }

    /// Exact raw-seal bytes.
    #[must_use]
    pub const fn raw_seal(&self) -> &'a [u8] {
        self.raw_seal
    }

    /// Exact canonical typed-receipt bytes.
    #[must_use]
    pub const fn receipt_oracle(&self) -> &'a [u8] {
        self.receipt_oracle
    }
}

/// Selector-free borrowed view of all 29 packet payloads.
pub struct B4TerminalEvidencePacketPayloadsV1<'a> {
    profile: B4TerminalEvidenceProfilePayloadsV1<'a>,
    sources: B4TerminalEvidenceProducerSourcesV1<'a>,
    fixtures: [B4TerminalEvidenceFixturePairPayloadV1<'a>; B4_TERMINAL_FIXTURE_COUNT],
    catalogue: &'a [u8],
    case8_direct: B4TerminalEvidenceDirectPairPayloadV1<'a>,
}

impl<'a> B4TerminalEvidencePacketPayloadsV1<'a> {
    /// Construct the fixed packet payload view without any caller selector.
    ///
    /// # Errors
    ///
    /// Returns an error before allocation or semantic decode if the catalogue
    /// or checked aggregate length is outside compiled authority.
    pub fn new(
        profile: B4TerminalEvidenceProfilePayloadsV1<'a>,
        sources: B4TerminalEvidenceProducerSourcesV1<'a>,
        fixtures: [B4TerminalEvidenceFixturePairPayloadV1<'a>; B4_TERMINAL_FIXTURE_COUNT],
        catalogue: &'a [u8],
        case8_direct: B4TerminalEvidenceDirectPairPayloadV1<'a>,
    ) -> Result<Self> {
        require_bounded_length(
            "terminal fixture catalogue",
            catalogue.len(),
            B4_TERMINAL_FIXTURE_CATALOG_MAX_BYTES,
        )?;
        let packet = Self {
            profile,
            sources,
            fixtures,
            catalogue,
            case8_direct,
        };
        packet.validate_checked_aggregate()?;
        Ok(packet)
    }

    fn validate_checked_aggregate(&self) -> Result<()> {
        let lengths = [
            self.profile.manifest.len(),
            self.profile.algorithm.len(),
            self.profile.constants.len(),
            self.sources.guest_elf.len(),
            self.sources.statement.len(),
            self.sources.case0_lift15_receipt_oracle.len(),
            self.sources.case8_terminal_join_recursive_oracle.len(),
            self.sources.case9_terminal_resolve_recursive_oracle.len(),
            self.catalogue.len(),
            self.case8_direct.raw_seal.len(),
            self.case8_direct.receipt_oracle.len(),
        ]
        .into_iter()
        .chain(
            self.fixtures
                .iter()
                .flat_map(|pair| [pair.raw_seal.len(), pair.receipt_oracle.len()]),
        );
        let actual = checked_sum(lengths)?;
        let maximum = checked_role_maximum(&compiled_b4_terminal_evidence_role_table()?)?;
        ensure!(
            actual <= maximum,
            "terminal evidence payload aggregate exceeds its compiled maximum"
        );
        Ok(())
    }

    fn into_owned(self) -> Result<B4OwnedTerminalEvidencePacketPayloadsV1> {
        self.validate_checked_aggregate()?;
        let profile = B4OwnedTerminalEvidenceProfilePayloadsV1 {
            manifest: own_bytes(self.profile.manifest)?,
            algorithm: own_bytes(self.profile.algorithm)?,
            constants: own_bytes(self.profile.constants)?,
        };
        let sources = B4OwnedTerminalEvidenceProducerSourcesV1 {
            guest_elf: own_bytes(self.sources.guest_elf)?,
            statement: own_bytes(self.sources.statement)?,
            case0_lift15_receipt_oracle: own_bytes(self.sources.case0_lift15_receipt_oracle)?,
            case8_terminal_join_recursive_oracle: own_bytes(
                self.sources.case8_terminal_join_recursive_oracle,
            )?,
            case9_terminal_resolve_recursive_oracle: own_bytes(
                self.sources.case9_terminal_resolve_recursive_oracle,
            )?,
        };
        let mut owned_fixtures = Vec::new();
        owned_fixtures
            .try_reserve_exact(B4_TERMINAL_FIXTURE_COUNT)
            .context("cannot allocate the fixed terminal fixture array")?;
        for pair in self.fixtures {
            owned_fixtures.push(B4OwnedTerminalEvidencePairPayloadV1 {
                raw_seal: own_bytes(pair.raw_seal)?,
                receipt_oracle: own_bytes(pair.receipt_oracle)?,
            });
        }
        let fixtures = owned_fixtures
            .try_into()
            .map_err(|_| anyhow::anyhow!("owned terminal fixture count drift"))?;
        Ok(B4OwnedTerminalEvidencePacketPayloadsV1 {
            profile,
            sources,
            fixtures,
            catalogue: own_bytes(self.catalogue)?,
            case8_direct: B4OwnedTerminalEvidencePairPayloadV1 {
                raw_seal: own_bytes(self.case8_direct.raw_seal)?,
                receipt_oracle: own_bytes(self.case8_direct.receipt_oracle)?,
            },
        })
    }
}

struct B4OwnedTerminalEvidenceProfilePayloadsV1 {
    manifest: Vec<u8>,
    algorithm: Vec<u8>,
    constants: Vec<u8>,
}

struct B4OwnedTerminalEvidenceProducerSourcesV1 {
    guest_elf: Vec<u8>,
    statement: Vec<u8>,
    case0_lift15_receipt_oracle: Vec<u8>,
    case8_terminal_join_recursive_oracle: Vec<u8>,
    case9_terminal_resolve_recursive_oracle: Vec<u8>,
}

struct B4OwnedTerminalEvidencePairPayloadV1 {
    raw_seal: Vec<u8>,
    receipt_oracle: Vec<u8>,
}

struct B4OwnedTerminalEvidencePacketPayloadsV1 {
    profile: B4OwnedTerminalEvidenceProfilePayloadsV1,
    sources: B4OwnedTerminalEvidenceProducerSourcesV1,
    fixtures: [B4OwnedTerminalEvidencePairPayloadV1; B4_TERMINAL_FIXTURE_COUNT],
    catalogue: Vec<u8>,
    case8_direct: B4OwnedTerminalEvidencePairPayloadV1,
}

impl B4OwnedTerminalEvidencePacketPayloadsV1 {
    /// Visit the 29 fixed payload roles without exposing a path selector.
    fn visit_payloads(&self, mut visit: impl FnMut(&str, &[u8]) -> Result<()>) -> Result<()> {
        let mut payloads = BTreeMap::<String, &[u8]>::new();
        macro_rules! insert_fixed {
            ($path:expr, $bytes:expr) => {{
                ensure!(
                    payloads.insert($path.to_owned(), $bytes).is_none(),
                    "owned terminal evidence payload path is duplicated"
                );
            }};
        }
        insert_fixed!("sources/guest.elf", self.sources.guest_elf.as_slice());
        insert_fixed!("sources/statement.bin", self.sources.statement.as_slice());
        insert_fixed!(
            "sources/case-0-lift-15.receipt-oracle.bincode",
            self.sources.case0_lift15_receipt_oracle.as_slice()
        );
        insert_fixed!(
            "sources/case-8-terminal-join.recursive-oracle.borsh",
            self.sources.case8_terminal_join_recursive_oracle.as_slice()
        );
        insert_fixed!(
            "sources/case-9-terminal-resolve.recursive-oracle.borsh",
            self.sources
                .case9_terminal_resolve_recursive_oracle
                .as_slice()
        );
        insert_fixed!(
            "profiles/risc0-v3-succinct/manifest.bin",
            self.profile.manifest.as_slice()
        );
        insert_fixed!(
            "profiles/risc0-v3-succinct/algorithm.txt",
            self.profile.algorithm.as_slice()
        );
        insert_fixed!(
            "profiles/risc0-v3-succinct/constants.bin",
            self.profile.constants.as_slice()
        );
        for (pair, layout) in self.fixtures.iter().zip(B4_TERMINAL_FIXTURE_LAYOUT) {
            let raw_path = terminal_fixture_raw_seal_path(layout.fixture_id)?;
            insert_fixed!(&raw_path, pair.raw_seal.as_slice());
            let oracle_path = terminal_fixture_receipt_oracle_path(layout.fixture_id)?;
            insert_fixed!(&oracle_path, pair.receipt_oracle.as_slice());
        }
        insert_fixed!(
            "reproduction/schema/b4-corpus-v1.candidate/bindings/terminal-fixture-catalog.json",
            self.catalogue.as_slice()
        );
        insert_fixed!(
            "derived/case-8-terminal-join-final.raw-seal.bin",
            self.case8_direct.raw_seal.as_slice()
        );
        insert_fixed!(
            "derived/case-8-terminal-join-final.receipt-oracle.bincode",
            self.case8_direct.receipt_oracle.as_slice()
        );
        ensure!(
            payloads.len() == B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT,
            "owned terminal evidence payload map count drift"
        );
        for role in compiled_b4_terminal_evidence_role_table()? {
            let bytes = payloads
                .remove(&role.path)
                .context("owned terminal evidence payload is missing a compiled role")?;
            visit(&role.path, bytes)?;
        }
        ensure!(
            payloads.is_empty(),
            "owned terminal evidence payload map contains an unknown role"
        );
        Ok(())
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "the authenticated profile capability is consumed at the one-way semantic-state boundary"
    )]
    fn into_semantic_state(
        self,
        authenticated: B4AuthenticatedPacketProfileV1,
    ) -> B4TerminalEvidenceSemanticStateV1 {
        B4TerminalEvidenceSemanticStateV1 {
            profile_id: authenticated.profile_id,
            program_id: authenticated.program_id,
            statement_sha256: authenticated.statement_sha256,
            profile: self.profile,
            sources: self.sources,
            fixtures: self.fixtures,
            catalogue: self.catalogue,
            case8_direct: self.case8_direct,
        }
    }
}

/// Consumer-verified, byte-custodial image for create-only publication.
///
/// This crate-private type is not verified packet authority. It exposes only
/// fixed ordered visitation and its derived canonical documents to the sibling
/// I/O implementation.
pub(crate) struct B4PreparedTerminalEvidencePublicationV1 {
    payloads: B4OwnedTerminalEvidencePacketPayloadsV1,
    manifest: Vec<u8>,
    completion: Vec<u8>,
}

impl B4PreparedTerminalEvidencePublicationV1 {
    pub(crate) fn visit_payloads(
        &self,
        visit: impl FnMut(&str, &[u8]) -> Result<()>,
    ) -> Result<()> {
        self.payloads.visit_payloads(visit)
    }

    pub(crate) fn manifest_bytes(&self) -> &[u8] {
        &self.manifest
    }

    pub(crate) fn completion_bytes(&self) -> &[u8] {
        &self.completion
    }
}

#[cfg(test)]
pub(crate) struct B4MechanicalTerminalEvidencePublicationImageV1 {
    payloads: B4OwnedTerminalEvidencePacketPayloadsV1,
    manifest: Vec<u8>,
    completion: Vec<u8>,
}

#[cfg(test)]
impl B4MechanicalTerminalEvidencePublicationImageV1 {
    pub(crate) fn visit_payloads(
        &self,
        visit: impl FnMut(&str, &[u8]) -> Result<()>,
    ) -> Result<()> {
        self.payloads.visit_payloads(visit)
    }

    pub(crate) fn manifest_bytes(&self) -> &[u8] {
        &self.manifest
    }

    pub(crate) fn completion_bytes(&self) -> &[u8] {
        &self.completion
    }
}

struct B4AuthenticatedPacketProfileV1 {
    profile_id: [u8; DIGEST_BYTES],
    program_id: [u8; DIGEST_BYTES],
    statement_sha256: [u8; DIGEST_BYTES],
}

struct B4TerminalEvidenceSemanticStateV1 {
    profile_id: [u8; DIGEST_BYTES],
    program_id: [u8; DIGEST_BYTES],
    statement_sha256: [u8; DIGEST_BYTES],
    profile: B4OwnedTerminalEvidenceProfilePayloadsV1,
    sources: B4OwnedTerminalEvidenceProducerSourcesV1,
    fixtures: [B4OwnedTerminalEvidencePairPayloadV1; B4_TERMINAL_FIXTURE_COUNT],
    catalogue: Vec<u8>,
    case8_direct: B4OwnedTerminalEvidencePairPayloadV1,
}

/// Manifest-measured identity of one verified packet.
///
/// This value has no public constructor; Task 4 mints it only from a private
/// stable-filesystem token.
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4TerminalEvidencePacketIdentityV1;
/// fn forge() -> B4TerminalEvidencePacketIdentityV1 {
///     B4TerminalEvidencePacketIdentityV1 {
///         manifest_byte_length: 1,
///         packet_id: [0_u8; 32],
///     }
/// }
/// ```
pub struct B4TerminalEvidencePacketIdentityV1 {
    manifest_byte_length: u64,
    packet_id: [u8; DIGEST_BYTES],
}

impl B4TerminalEvidencePacketIdentityV1 {
    /// Exact canonical manifest byte length.
    #[must_use]
    pub const fn manifest_byte_length(self) -> u64 {
        self.manifest_byte_length
    }

    /// SHA-256 packet identity of the exact canonical manifest bytes.
    #[must_use]
    pub const fn packet_id(self) -> [u8; DIGEST_BYTES] {
        self.packet_id
    }
}

impl Copy for B4TerminalEvidencePacketIdentityV1 {}

impl Clone for B4TerminalEvidencePacketIdentityV1 {
    fn clone(&self) -> Self {
        *self
    }
}

/// Bytes-only view retained for later producer-source replay.
pub struct B4TerminalEvidenceSourceReplayViewV1<'a> {
    guest_elf: &'a [u8],
    statement: &'a [u8],
    case0_lift15_receipt_oracle: &'a [u8],
    case8_terminal_join_recursive_oracle: &'a [u8],
    case9_terminal_resolve_recursive_oracle: &'a [u8],
    case8_direct: B4TerminalEvidenceDirectPairPayloadV1<'a>,
}

impl<'a> B4TerminalEvidenceSourceReplayViewV1<'a> {
    /// Exact guest bytes; this getter makes no producer-lineage claim.
    #[must_use]
    pub const fn guest_elf(&self) -> &'a [u8] {
        self.guest_elf
    }

    /// Exact statement bytes; this getter makes no producer-lineage claim.
    #[must_use]
    pub const fn statement(&self) -> &'a [u8] {
        self.statement
    }

    /// Exact retained case-0 producer bytes without source-format approval.
    #[must_use]
    pub const fn case0_lift15_receipt_oracle(&self) -> &'a [u8] {
        self.case0_lift15_receipt_oracle
    }

    /// Exact retained case-8 recursive producer bytes without lineage approval.
    #[must_use]
    pub const fn case8_terminal_join_recursive_oracle(&self) -> &'a [u8] {
        self.case8_terminal_join_recursive_oracle
    }

    /// Exact retained case-9 recursive producer bytes without lineage approval.
    #[must_use]
    pub const fn case9_terminal_resolve_recursive_oracle(&self) -> &'a [u8] {
        self.case9_terminal_resolve_recursive_oracle
    }

    /// Exact semantically replayed direct case-8 pair.
    #[must_use]
    pub const fn case8_direct_pair(&self) -> B4TerminalEvidenceDirectPairPayloadV1<'a> {
        self.case8_direct
    }
}

/// Consumer-semantic packet authority.
///
/// The type path is public:
///
/// ```
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4VerifiedTerminalEvidencePacketV1;
/// fn accepts(_: Option<&B4VerifiedTerminalEvidencePacketV1>) {}
/// accepts(None);
/// fn assert_serde<T: serde::Serialize + serde::de::DeserializeOwned>() {}
/// assert_serde::<u8>();
/// ```
///
/// Its private state cannot be rebuilt with struct update syntax:
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4VerifiedTerminalEvidencePacketV1;
/// fn rebuild(value: B4VerifiedTerminalEvidencePacketV1)
///     -> B4VerifiedTerminalEvidencePacketV1
/// {
///     B4VerifiedTerminalEvidencePacketV1 { ..value }
/// }
/// ```
///
/// It implements none of the public minting or payload-revealing traits:
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4VerifiedTerminalEvidencePacketV1;
/// fn require<T: serde::Serialize>() {}
/// require::<B4VerifiedTerminalEvidencePacketV1>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4VerifiedTerminalEvidencePacketV1;
/// fn require<T: serde::de::DeserializeOwned>() {}
/// require::<B4VerifiedTerminalEvidencePacketV1>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4VerifiedTerminalEvidencePacketV1;
/// fn require<T: Default>() {}
/// require::<B4VerifiedTerminalEvidencePacketV1>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4VerifiedTerminalEvidencePacketV1;
/// fn require<T: core::fmt::Debug>() {}
/// require::<B4VerifiedTerminalEvidencePacketV1>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4VerifiedTerminalEvidencePacketV1;
/// fn require<T: Clone>() {}
/// require::<B4VerifiedTerminalEvidencePacketV1>();
/// ```
///
/// Fixture, catalogue, raw-payload, filesystem, importer, and lineage
/// projections do not exist:
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4VerifiedTerminalEvidencePacketV1;
/// fn project(value: &B4VerifiedTerminalEvidencePacketV1) { value.fixtures(); }
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4VerifiedTerminalEvidencePacketV1;
/// fn project(value: &B4VerifiedTerminalEvidencePacketV1) { value.catalogue(); }
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4VerifiedTerminalEvidencePacketV1;
/// fn project(value: &B4VerifiedTerminalEvidencePacketV1) { value.payloads(); }
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4VerifiedTerminalEvidencePacketV1;
/// fn project(value: B4VerifiedTerminalEvidencePacketV1) {
///     value.into_payloads();
/// }
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4VerifiedTerminalEvidencePacketV1;
/// fn project(value: &B4VerifiedTerminalEvidencePacketV1) { value.paths(); }
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4VerifiedTerminalEvidencePacketV1;
/// fn project(value: &B4VerifiedTerminalEvidencePacketV1) {
///     value.import_projection();
/// }
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4VerifiedTerminalEvidencePacketV1;
/// fn project(value: &B4VerifiedTerminalEvidencePacketV1) { value.lineage(); }
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4VerifiedTerminalEvidencePacketV1;
/// fn project(value: &B4VerifiedTerminalEvidencePacketV1) { value.profile(); }
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4VerifiedTerminalEvidencePacketV1;
/// fn project(value: &B4VerifiedTerminalEvidencePacketV1) { value.fixture(0); }
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4VerifiedTerminalEvidencePacketV1;
/// fn project(value: &B4VerifiedTerminalEvidencePacketV1) {
///     value.fixture("lift-po2-14");
/// }
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4VerifiedTerminalEvidencePacketV1;
/// fn project(value: &B4VerifiedTerminalEvidencePacketV1) {
///     value.prepare_terminal_materialization();
/// }
/// ```
pub struct B4VerifiedTerminalEvidencePacketV1 {
    identity: B4TerminalEvidencePacketIdentityV1,
    physical_closure_identity: crate::b4_terminal_evidence_io::B4PhysicalPacketClosureIdentityV1,
    semantic: B4TerminalEvidenceSemanticStateV1,
}

impl B4VerifiedTerminalEvidencePacketV1 {
    pub(super) const fn physical_closure_identity(
        &self,
    ) -> &crate::b4_terminal_evidence_io::B4PhysicalPacketClosureIdentityV1 {
        &self.physical_closure_identity
    }

    /// Return the measured packet identity.
    #[must_use]
    pub const fn identity(&self) -> B4TerminalEvidencePacketIdentityV1 {
        self.identity
    }

    /// Return the exact canonical manifest byte length.
    #[must_use]
    pub const fn manifest_byte_length(&self) -> u64 {
        self.identity.manifest_byte_length
    }

    /// Return the SHA-256 packet identity.
    #[must_use]
    pub const fn packet_id(&self) -> [u8; DIGEST_BYTES] {
        self.identity.packet_id
    }

    /// Return only the bytes required by later producer-source replay.
    #[must_use]
    pub fn source_replay_view(&self) -> B4TerminalEvidenceSourceReplayViewV1<'_> {
        B4TerminalEvidenceSourceReplayViewV1 {
            guest_elf: &self.semantic.sources.guest_elf,
            statement: &self.semantic.sources.statement,
            case0_lift15_receipt_oracle: &self.semantic.sources.case0_lift15_receipt_oracle,
            case8_terminal_join_recursive_oracle: &self
                .semantic
                .sources
                .case8_terminal_join_recursive_oracle,
            case9_terminal_resolve_recursive_oracle: &self
                .semantic
                .sources
                .case9_terminal_resolve_recursive_oracle,
            case8_direct: B4TerminalEvidenceDirectPairPayloadV1 {
                raw_seal: &self.semantic.case8_direct.raw_seal,
                receipt_oracle: &self.semantic.case8_direct.receipt_oracle,
            },
        }
    }
}

fn require_exact_length(role: &str, actual: usize, expected: usize) -> Result<()> {
    ensure!(
        actual == expected,
        "{role} has {actual} bytes, expected exactly {expected}"
    );
    Ok(())
}

fn require_bounded_length(role: &str, actual: usize, maximum: usize) -> Result<()> {
    ensure!(
        (1..=maximum).contains(&actual),
        "{role} has {actual} bytes, expected 1..={maximum}"
    );
    Ok(())
}

fn validate_pair_lengths(raw_seal: &[u8], receipt_oracle: &[u8]) -> Result<()> {
    require_exact_length("raw seal", raw_seal.len(), PROOF_BYTES)?;
    require_bounded_length(
        "receipt oracle",
        receipt_oracle.len(),
        RECEIPT_ORACLE_MAX_BYTES,
    )
}

fn own_bytes(source: &[u8]) -> Result<Vec<u8>> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(source.len())
        .context("cannot allocate a bounded terminal evidence payload")?;
    owned.extend_from_slice(source);
    Ok(owned)
}

fn authenticate_packet_profile_program_statement(
    manifest: &[u8],
    algorithm: &[u8],
    constants: &[u8],
    guest_elf: &[u8],
    statement: &[u8],
) -> Result<B4AuthenticatedPacketProfileV1> {
    let profile = authenticate_initial_profile_package(manifest, algorithm, constants)?;
    let profile_id = profile.profile_id()?;
    let program_id: [u8; DIGEST_BYTES] = compute_image_id(guest_elf)
        .context("packet guest.elf is not a valid encoded RISC Zero program")?
        .into();
    let decoded_statement =
        parse_ergo_statement_v1(statement).context("cannot decode packet ErgoStatementV1")?;
    ensure!(
        decoded_statement.encode()?.as_slice() == statement,
        "packet ErgoStatementV1 decode/re-encode changed bytes"
    );
    ensure!(
        decoded_statement.profile_id() == profile_id,
        "packet statement profile ID differs from the authenticated profile"
    );
    ensure!(
        decoded_statement.program_id() == program_id,
        "packet statement program ID differs from the derived guest image ID"
    );
    Ok(B4AuthenticatedPacketProfileV1 {
        profile_id,
        program_id,
        statement_sha256: Sha256::digest(statement).into(),
    })
}

fn packet_fixture_maps(
    fixtures: &[B4TerminalEvidenceFixturePairPayloadV1<'_>; B4_TERMINAL_FIXTURE_COUNT],
) -> Result<(BTreeMap<String, Vec<u8>>, BTreeMap<String, Vec<u8>>)> {
    let mut raw_seals = BTreeMap::new();
    let mut receipt_oracles = BTreeMap::new();
    for (pair, layout) in fixtures.iter().zip(B4_TERMINAL_FIXTURE_LAYOUT) {
        let raw_path = terminal_fixture_raw_seal_path(layout.fixture_id)?;
        let oracle_path = terminal_fixture_receipt_oracle_path(layout.fixture_id)?;
        ensure!(
            raw_seals
                .insert(raw_path, own_bytes(pair.raw_seal)?)
                .is_none()
                && receipt_oracles
                    .insert(oracle_path, own_bytes(pair.receipt_oracle)?)
                    .is_none(),
            "compiled terminal fixture layout contains a duplicate path"
        );
    }
    ensure!(
        raw_seals.len() == B4_TERMINAL_FIXTURE_COUNT
            && receipt_oracles.len() == B4_TERMINAL_FIXTURE_COUNT,
        "compiled terminal fixture map cardinality drift"
    );
    Ok((raw_seals, receipt_oracles))
}

fn replay_packet_fixture_pairs(
    fixtures: &[B4TerminalEvidenceFixturePairPayloadV1<'_>; B4_TERMINAL_FIXTURE_COUNT],
) -> Result<VerifiedB4TerminalOracleReplay> {
    let (raw_seals, receipt_oracles) = packet_fixture_maps(fixtures)?;
    replay_fixed_terminal_oracles(&raw_seals, &receipt_oracles).map_err(Into::into)
}

fn decode_packet_fixture_catalogue(source: &[u8]) -> Result<Eip0045B4TerminalFixtureCatalogV1> {
    Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(source)
        .context("cannot decode canonical terminal fixture catalogue")
}

fn bind_packet_fixture_catalogue(
    replay: &VerifiedB4TerminalOracleReplay,
    source: &[u8],
) -> std::result::Result<(), B4TerminalOracleReplayError> {
    replay.bind_candidate_catalogue_jcs(source)
}

fn decode_packet_direct_receipt(
    replay: &CompiledStockSuccinctReplayV1,
    source: &[u8],
) -> std::result::Result<DecodedStockSuccinctReceiptV1<ReceiptClaim>, StockReceiptReplayError> {
    replay.decode_direct(source)
}

fn replay_packet_direct_pair(
    pair: B4TerminalEvidenceDirectPairPayloadV1<'_>,
) -> std::result::Result<VerifiedStockSuccinctReceiptV1<ReceiptClaim>, StockReceiptReplayError> {
    let replay = CompiledStockSuccinctReplayV1::from_compiled_profile()?;
    let decoded = decode_packet_direct_receipt(&replay, pair.receipt_oracle)?;
    replay.verify(decoded, pair.raw_seal)
}

fn replay_packet_case8(
    payloads: &B4OwnedTerminalEvidencePacketPayloadsV1,
) -> Result<B4VerifiedCase8TerminalJoinReplayV1> {
    B4OwnedCase8TerminalJoinRootV1::from_packet_sources(B4Case8TerminalJoinPacketSourcesV1 {
        profile_manifest: &payloads.profile.manifest,
        profile_algorithm: &payloads.profile.algorithm,
        profile_constants: &payloads.profile.constants,
        guest_elf: &payloads.sources.guest_elf,
        statement: &payloads.sources.statement,
        raw_seal: &payloads.case8_direct.raw_seal,
    })?
    .replay()
}

fn decode_observation_digest(source: &str, role: &str) -> Result<[u8; DIGEST_BYTES]> {
    let bytes = hex::decode(source).with_context(|| format!("{role} is not hexadecimal"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{role} has the wrong digest width"))
}

fn verify_packet_semantics(
    payloads: B4TerminalEvidencePacketPayloadsV1<'_>,
) -> Result<B4TerminalEvidenceSemanticStateV1> {
    let owned = payloads.into_owned()?;
    let authenticated = verify_owned_packet_semantics(&owned)?;
    Ok(owned.into_semantic_state(authenticated))
}

fn verify_owned_packet_semantics(
    payloads: &B4OwnedTerminalEvidencePacketPayloadsV1,
) -> Result<B4AuthenticatedPacketProfileV1> {
    let authenticated = authenticate_packet_profile_program_statement(
        &payloads.profile.manifest,
        &payloads.profile.algorithm,
        &payloads.profile.constants,
        &payloads.sources.guest_elf,
        &payloads.sources.statement,
    )?;

    let fixture_views = std::array::from_fn(|index| {
        let pair = &payloads.fixtures[index];
        B4TerminalEvidenceFixturePairPayloadV1 {
            raw_seal: &pair.raw_seal,
            receipt_oracle: &pair.receipt_oracle,
        }
    });
    let fixture_replay = replay_packet_fixture_pairs(&fixture_views)?;
    bind_packet_fixture_catalogue(&fixture_replay, &payloads.catalogue)?;

    let case8 = replay_packet_case8(&payloads)?;
    let direct_pair = B4TerminalEvidenceDirectPairPayloadV1 {
        raw_seal: &payloads.case8_direct.raw_seal,
        receipt_oracle: &payloads.case8_direct.receipt_oracle,
    };
    let direct = replay_packet_direct_pair(direct_pair)
        .context("fixed case-8 direct stock receipt failed native replay")?;
    ensure!(
        case8.contexts()[6] == payloads.case8_direct.raw_seal,
        "case-8 direct replay did not consume the same raw-seal bytes"
    );
    let observation = case8.observation();
    ensure!(
        observation.terminal().kind == B4PositiveTerminalKind::Join
            && observation.terminal().parameter == 0,
        "case-8 observation is not the fixed Join/0 terminal"
    );
    let observation_claim =
        decode_observation_digest(observation.claim_digest(), "case-8 observation claim")?;
    ensure!(
        direct.claim_digest().as_bytes() == &observation_claim,
        "direct receipt claim digest differs from the case-8 observation claim digest"
    );
    let observation_control = decode_observation_digest(
        &observation.terminal().control_id,
        "case-8 observation control ID",
    )?;
    ensure!(
        direct.control_id().as_bytes() == &observation_control,
        "direct receipt control ID differs from the case-8 Join/0 observation control ID"
    );
    ensure!(
        &case8.terminal_metadata_record()[2..] == observation_control.as_slice(),
        "case-8 terminal metadata record differs from the observation control ID"
    );

    Ok(authenticated)
}

/// Own and consumer-verify one exact payload set for later publication.
///
/// This does not mint a verified terminal-evidence packet.
pub(crate) fn prepare_b4_terminal_evidence_publication(
    payloads: B4TerminalEvidencePacketPayloadsV1<'_>,
) -> Result<B4PreparedTerminalEvidencePublicationV1> {
    let owned = payloads.into_owned()?;
    let _authenticated = verify_owned_packet_semantics(&owned)?;
    let (manifest, completion) = derive_b4_terminal_evidence_publication_documents(&owned)?;
    Ok(B4PreparedTerminalEvidencePublicationV1 {
        payloads: owned,
        manifest,
        completion,
    })
}

fn derive_b4_terminal_evidence_publication_documents(
    owned: &B4OwnedTerminalEvidencePacketPayloadsV1,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut files = Vec::new();
    files
        .try_reserve_exact(B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT)
        .context("cannot allocate terminal evidence publication manifest rows")?;
    owned.visit_payloads(|path, bytes| {
        files.push(B4TerminalEvidenceFileIdentityV1 {
            path: path.to_owned(),
            byte_length: u64::try_from(bytes.len())?,
            sha256: hex::encode(Sha256::digest(bytes)),
        });
        Ok(())
    })?;
    ensure!(
        files.len() == B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT,
        "prepared terminal evidence manifest row count drift"
    );
    let manifest = Eip0045B4TerminalEvidenceManifestV1 {
        format: MANIFEST_FORMAT.to_owned(),
        format_version: FORMAT_VERSION,
        files,
    }
    .to_canonical_jcs()?;
    let completion =
        Eip0045B4TerminalEvidenceCompletionV1::for_manifest(&manifest)?.to_canonical_jcs()?;
    Ok((manifest, completion))
}

#[cfg(test)]
pub(crate) fn mechanical_b4_terminal_evidence_publication_for_test(
    seed: u8,
) -> Result<B4MechanicalTerminalEvidencePublicationImageV1> {
    let byte = |offset: u8| seed.wrapping_add(offset);
    let profile = B4OwnedTerminalEvidenceProfilePayloadsV1 {
        manifest: vec![byte(1); PROFILE_MANIFEST_BYTES],
        algorithm: vec![byte(2); PROFILE_ALGORITHM_BYTES],
        constants: vec![byte(3); PROFILE_CONSTANTS_BYTES],
    };
    let sources = B4OwnedTerminalEvidenceProducerSourcesV1 {
        guest_elf: vec![byte(4)],
        statement: vec![byte(5)],
        case0_lift15_receipt_oracle: vec![byte(6)],
        case8_terminal_join_recursive_oracle: vec![byte(7)],
        case9_terminal_resolve_recursive_oracle: vec![byte(8)],
    };
    let fixtures = std::array::from_fn(|index| B4OwnedTerminalEvidencePairPayloadV1 {
        raw_seal: vec![
            seed.wrapping_add(u8::try_from(index).expect("fixed fixture index fits u8"));
            PROOF_BYTES
        ],
        receipt_oracle: vec![seed.wrapping_add(
            u8::try_from(index + B4_TERMINAL_FIXTURE_COUNT).expect("fixed fixture index fits u8"),
        )],
    });
    let owned = B4OwnedTerminalEvidencePacketPayloadsV1 {
        profile,
        sources,
        fixtures,
        catalogue: vec![byte(27)],
        case8_direct: B4OwnedTerminalEvidencePairPayloadV1 {
            raw_seal: vec![byte(28); PROOF_BYTES],
            receipt_oracle: vec![byte(29)],
        },
    };
    let (manifest, completion) = derive_b4_terminal_evidence_publication_documents(&owned)?;
    Ok(B4MechanicalTerminalEvidencePublicationImageV1 {
        payloads: owned,
        manifest,
        completion,
    })
}

pub(super) fn mint_b4_verified_terminal_evidence_packet(
    mut measured: crate::b4_terminal_evidence_io::B4MeasuredTerminalEvidencePacketV1,
) -> Result<B4VerifiedTerminalEvidencePacketV1> {
    let physical_closure_identity = measured.take_physical_closure_identity()?;
    let manifest =
        Eip0045B4TerminalEvidenceManifestV1::from_canonical_jcs(measured.manifest_bytes())?;
    let roles = compiled_b4_terminal_evidence_role_table()?;
    ensure!(
        measured.payload_count() == B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT,
        "measured terminal evidence payload cardinality drift"
    );
    for (row, role) in manifest.files.iter().zip(&roles) {
        ensure!(
            row.path == role.path,
            "measured terminal evidence path order drift"
        );
        let (bytes, byte_length, sha256) = measured.measured_payload(&row.path)?;
        let rebound_sha256: [u8; DIGEST_BYTES] = Sha256::digest(bytes).into();
        ensure!(
            byte_length == row.byte_length
                && usize::try_from(byte_length)? == bytes.len()
                && hex::encode(sha256) == row.sha256
                && rebound_sha256 == sha256,
            "{} measured row does not rebind to its owned bytes",
            row.path
        );
    }

    let profile = B4TerminalEvidenceProfilePayloadsV1::new(
        measured
            .measured_payload("profiles/risc0-v3-succinct/manifest.bin")?
            .0,
        measured
            .measured_payload("profiles/risc0-v3-succinct/algorithm.txt")?
            .0,
        measured
            .measured_payload("profiles/risc0-v3-succinct/constants.bin")?
            .0,
    )?;
    let sources = B4TerminalEvidenceProducerSourcesV1::new(
        measured.measured_payload("sources/guest.elf")?.0,
        measured.measured_payload("sources/statement.bin")?.0,
        measured
            .measured_payload("sources/case-0-lift-15.receipt-oracle.bincode")?
            .0,
        measured
            .measured_payload("sources/case-8-terminal-join.recursive-oracle.borsh")?
            .0,
        measured
            .measured_payload("sources/case-9-terminal-resolve.recursive-oracle.borsh")?
            .0,
    )?;
    let mut fixture_views = Vec::new();
    fixture_views
        .try_reserve_exact(B4_TERMINAL_FIXTURE_COUNT)
        .context("cannot allocate fixed measured terminal fixture views")?;
    for layout in B4_TERMINAL_FIXTURE_LAYOUT {
        let raw_path = terminal_fixture_raw_seal_path(layout.fixture_id)?;
        let oracle_path = terminal_fixture_receipt_oracle_path(layout.fixture_id)?;
        fixture_views.push(B4TerminalEvidenceFixturePairPayloadV1::new(
            measured.measured_payload(&raw_path)?.0,
            measured.measured_payload(&oracle_path)?.0,
        )?);
    }
    let fixtures = fixture_views
        .try_into()
        .map_err(|_| anyhow::anyhow!("measured terminal fixture count drift"))?;
    let case8_direct = B4TerminalEvidenceDirectPairPayloadV1::new(
        measured
            .measured_payload("derived/case-8-terminal-join-final.raw-seal.bin")?
            .0,
        measured
            .measured_payload("derived/case-8-terminal-join-final.receipt-oracle.bincode")?
            .0,
    )?;
    let borrowed = B4TerminalEvidencePacketPayloadsV1::new(
        profile,
        sources,
        fixtures,
        measured
            .measured_payload(
                "reproduction/schema/b4-corpus-v1.candidate/bindings/terminal-fixture-catalog.json",
            )?
            .0,
        case8_direct,
    )?;
    let owned = borrowed.into_owned()?;
    let authenticated = verify_owned_packet_semantics(&owned)?;
    let semantic = owned.into_semantic_state(authenticated);
    let manifest_byte_length = u64::try_from(measured.manifest_bytes().len())?;
    let packet_id = Sha256::digest(measured.manifest_bytes()).into();
    Ok(B4VerifiedTerminalEvidencePacketV1 {
        identity: B4TerminalEvidencePacketIdentityV1 {
            manifest_byte_length,
            packet_id,
        },
        physical_closure_identity,
        semantic,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct B4TerminalEvidenceFileIdentityV1 {
    pub(super) path: String,
    pub(super) byte_length: u64,
    pub(super) sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Eip0045B4TerminalEvidenceManifestV1 {
    format: String,
    format_version: u8,
    pub(super) files: Vec<B4TerminalEvidenceFileIdentityV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Eip0045B4TerminalEvidenceCompletionV1 {
    format: String,
    format_version: u8,
    manifest_path: String,
    manifest_byte_length: u64,
    manifest_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct B4TerminalEvidenceRoleBoundsV1 {
    pub(super) path: String,
    minimum: usize,
    pub(super) maximum: usize,
}

impl Eip0045B4TerminalEvidenceManifestV1 {
    pub(super) fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            (1..=MANIFEST_MAX_BYTES).contains(&source.len()),
            "terminal evidence manifest is outside its byte bound"
        );
        let value = validate_canonical_json_source(source)?;
        let manifest: Self = serde_json::from_value(value.clone())
            .context("cannot decode terminal evidence manifest")?;
        ensure!(
            canonical_json_bytes(&serde_json::to_value(&manifest)?)? == source,
            "terminal evidence manifest does not reserialize byte-exactly"
        );
        manifest.validate()?;
        Ok(manifest)
    }

    fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = canonical_json_bytes(&serde_json::to_value(self)?)?;
        ensure!(
            (1..=MANIFEST_MAX_BYTES).contains(&bytes.len()),
            "terminal evidence manifest is outside its byte bound"
        );
        Ok(bytes)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.format == MANIFEST_FORMAT && self.format_version == FORMAT_VERSION,
            "terminal evidence manifest format drift"
        );
        let roles = compiled_b4_terminal_evidence_role_table()?;
        ensure!(
            self.files.len() == roles.len(),
            "terminal evidence manifest cardinality drift"
        );
        for (index, (file, role)) in self.files.iter().zip(&roles).enumerate() {
            ensure!(
                file.path == role.path,
                "terminal evidence manifest path or ordering drift at {index}"
            );
            let length = usize::try_from(file.byte_length)
                .context("terminal evidence manifest byte length overflows usize")?;
            ensure!(
                (role.minimum..=role.maximum).contains(&length),
                "terminal evidence manifest role length is outside its compiled bound at {index}"
            );
            validate_lower_hex_exact(&file.sha256, 32)?;
        }
        Ok(())
    }
}

impl Eip0045B4TerminalEvidenceCompletionV1 {
    fn for_manifest(manifest: &[u8]) -> Result<Self> {
        Eip0045B4TerminalEvidenceManifestV1::from_canonical_jcs(manifest)?;
        Ok(Self {
            format: COMPLETION_FORMAT.to_owned(),
            format_version: FORMAT_VERSION,
            manifest_path: B4_TERMINAL_EVIDENCE_MANIFEST_FILE.to_owned(),
            manifest_byte_length: u64::try_from(manifest.len())?,
            manifest_sha256: hex::encode(Sha256::digest(manifest)),
        })
    }

    pub(super) fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            (1..=COMPLETION_MAX_BYTES).contains(&source.len()),
            "terminal evidence completion is outside its byte bound"
        );
        let value = validate_canonical_json_source(source)?;
        let completion: Self = serde_json::from_value(value.clone())
            .context("cannot decode terminal evidence completion")?;
        ensure!(
            canonical_json_bytes(&serde_json::to_value(&completion)?)? == source,
            "terminal evidence completion does not reserialize byte-exactly"
        );
        completion.validate()?;
        Ok(completion)
    }

    fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = canonical_json_bytes(&serde_json::to_value(self)?)?;
        ensure!(
            (1..=COMPLETION_MAX_BYTES).contains(&bytes.len()),
            "terminal evidence completion is outside its byte bound"
        );
        Ok(bytes)
    }

    pub(super) fn bind_manifest(&self, manifest: &[u8]) -> Result<()> {
        self.validate()?;
        Eip0045B4TerminalEvidenceManifestV1::from_canonical_jcs(manifest)?;
        ensure!(
            self.manifest_byte_length == u64::try_from(manifest.len())?
                && self.manifest_sha256 == hex::encode(Sha256::digest(manifest)),
            "terminal evidence completion does not bind the exact manifest bytes"
        );
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.format == COMPLETION_FORMAT && self.format_version == FORMAT_VERSION,
            "terminal evidence completion format drift"
        );
        ensure!(
            self.manifest_path == B4_TERMINAL_EVIDENCE_MANIFEST_FILE,
            "terminal evidence completion manifest path drift"
        );
        ensure!(
            (1..=MANIFEST_MAX_BYTES as u64).contains(&self.manifest_byte_length),
            "terminal evidence completion manifest length is outside its bound"
        );
        validate_lower_hex_exact(&self.manifest_sha256, 32)
    }
}

fn compiled_b4_terminal_evidence_payload_paths()
-> Result<[String; B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT]> {
    compiled_b4_terminal_evidence_role_table().map(|roles| roles.map(|role| role.path))
}

pub(super) fn compiled_b4_terminal_evidence_role_table()
-> Result<[B4TerminalEvidenceRoleBoundsV1; B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT]> {
    let mut roles = vec![
        role("sources/guest.elf", 1, GUEST_ELF_MAX_BYTES),
        role("sources/statement.bin", 1, MAX_STATEMENT_BYTES),
        role(
            "sources/case-0-lift-15.receipt-oracle.bincode",
            1,
            RECEIPT_ORACLE_MAX_BYTES,
        ),
        role(
            "sources/case-8-terminal-join.recursive-oracle.borsh",
            1,
            B4_TERMINAL_EVIDENCE_RECURSIVE_SOURCE_MAX_BYTES,
        ),
        role(
            "sources/case-9-terminal-resolve.recursive-oracle.borsh",
            1,
            B4_TERMINAL_EVIDENCE_RECURSIVE_SOURCE_MAX_BYTES,
        ),
        role(
            "profiles/risc0-v3-succinct/manifest.bin",
            PROFILE_MANIFEST_BYTES,
            PROFILE_MANIFEST_BYTES,
        ),
        role(
            "profiles/risc0-v3-succinct/algorithm.txt",
            PROFILE_ALGORITHM_BYTES,
            PROFILE_ALGORITHM_BYTES,
        ),
        role(
            "profiles/risc0-v3-succinct/constants.bin",
            PROFILE_CONSTANTS_BYTES,
            PROFILE_CONSTANTS_BYTES,
        ),
    ];
    for layout in B4_TERMINAL_FIXTURE_LAYOUT {
        roles.push(role(
            &terminal_fixture_raw_seal_path(layout.fixture_id)?,
            PROOF_BYTES,
            PROOF_BYTES,
        ));
        roles.push(role(
            &terminal_fixture_receipt_oracle_path(layout.fixture_id)?,
            1,
            RECEIPT_ORACLE_MAX_BYTES,
        ));
    }
    roles.push(role(
        "reproduction/schema/b4-corpus-v1.candidate/bindings/terminal-fixture-catalog.json",
        1,
        B4_TERMINAL_FIXTURE_CATALOG_MAX_BYTES,
    ));
    roles.push(role(
        "derived/case-8-terminal-join-final.raw-seal.bin",
        PROOF_BYTES,
        PROOF_BYTES,
    ));
    roles.push(role(
        "derived/case-8-terminal-join-final.receipt-oracle.bincode",
        1,
        RECEIPT_ORACLE_MAX_BYTES,
    ));
    roles.sort_by(|left, right| left.path.cmp(&right.path));
    validate_compiled_roles(&roles)?;
    roles
        .try_into()
        .map_err(|_| anyhow::anyhow!("terminal evidence role count drift"))
}

fn role(path: &str, minimum: usize, maximum: usize) -> B4TerminalEvidenceRoleBoundsV1 {
    B4TerminalEvidenceRoleBoundsV1 {
        path: path.to_owned(),
        minimum,
        maximum,
    }
}

fn validate_compiled_roles(roles: &[B4TerminalEvidenceRoleBoundsV1]) -> Result<()> {
    ensure!(
        roles.len() == B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT,
        "terminal evidence role count drift"
    );
    for (index, role) in roles.iter().enumerate() {
        validate_safe_relative_path(&role.path)?;
        ensure!(
            role.minimum > 0 && role.minimum <= role.maximum,
            "terminal evidence role bound drift"
        );
        for other in &roles[index + 1..] {
            ensure!(
                role.path != other.path && !b4_paths_conflict(&role.path, &other.path),
                "terminal evidence paths are duplicate or conflicting"
            );
        }
    }
    Ok(())
}

fn checked_sum(values: impl IntoIterator<Item = usize>) -> Result<usize> {
    values.into_iter().try_fold(0usize, |sum, value| {
        sum.checked_add(value)
            .context("terminal evidence packet byte maximum overflows usize")
    })
}

fn checked_role_maximum(roles: &[B4TerminalEvidenceRoleBoundsV1]) -> Result<usize> {
    checked_sum(roles.iter().map(|role| role.maximum))
}

fn complete_packet_maximum(roles: &[B4TerminalEvidenceRoleBoundsV1]) -> Result<usize> {
    checked_sum([
        checked_role_maximum(roles)?,
        MANIFEST_MAX_BYTES,
        COMPLETION_MAX_BYTES,
    ])
}

fn compiled_b4_terminal_evidence_directories() -> Result<BTreeSet<String>> {
    let mut directories = BTreeSet::new();
    for path in compiled_b4_terminal_evidence_payload_paths()? {
        let mut components = path.split('/').collect::<Vec<_>>();
        components.pop();
        let mut directory = String::new();
        for component in components {
            if !directory.is_empty() {
                directory.push('/');
            }
            directory.push_str(component);
            directories.insert(directory.clone());
        }
    }
    Ok(directories)
}

fn synthetic_manifest() -> Eip0045B4TerminalEvidenceManifestV1 {
    let files = compiled_b4_terminal_evidence_role_table()
        .unwrap()
        .into_iter()
        .map(|role| B4TerminalEvidenceFileIdentityV1 {
            path: role.path,
            byte_length: role.minimum as u64,
            sha256: "00".repeat(32),
        })
        .collect();
    Eip0045B4TerminalEvidenceManifestV1 {
        format: MANIFEST_FORMAT.to_owned(),
        format_version: FORMAT_VERSION,
        files,
    }
}

fn canonical_synthetic_manifest_value_with_first_two_files_swapped() -> Vec<u8> {
    let mut manifest = synthetic_manifest();
    manifest.files.swap(0, 1);
    canonical_json_bytes(&serde_json::to_value(manifest).unwrap()).unwrap()
}

#[cfg(test)]
mod tests {
    include!("b4_terminal_evidence_packet_tests.rs");
}
