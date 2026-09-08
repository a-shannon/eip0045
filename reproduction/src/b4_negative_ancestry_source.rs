// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Opaque authenticated source views shared with B4 witness producers.

use std::collections::{BTreeMap, BTreeSet};

#[cfg(all(
    feature = "positive-gate",
    feature = "recursive-ancestry",
    feature = "receipt-oracle"
))]
use crate::b4_negative_ancestry_authority::{
    B4NegativeAncestrySourceAuthorityV1, B4NegativeAncestrySourceAuthorityV2,
};
use crate::constants::DIGEST_BYTES;

/// Borrowed, opaque view of the exact authenticated case-9 assumption source.
///
/// The source authority authenticates and retains these bytes but deliberately
/// leaves the generator-owned recursive-oracle wire format to the generator.
/// Private fields prevent external callers from fabricating this provenance
/// token through safe Rust.
pub struct B4AuthenticatedCase9AssumptionSourceV1<'a> {
    recursive_oracle_borsh: &'a [u8],
    assumption_raw_seal: &'a [u8],
    statement: &'a [u8],
    consumer_program_id: [u8; DIGEST_BYTES],
}

/// Complete authenticated byte source for the fixed seven-witness producer.
///
/// The token contains no family, workload, segment, terminal, row, path, or
/// count selector. Its private fields can be initialized only from an opaque
/// source authority, and all derived statements and proof parameters remain
/// the generator's responsibility.
pub struct B4AuthenticatedNegativeAncestryProducerSourceV1<'a> {
    case9_recursive_oracle_borsh: &'a [u8],
    case9_assumption_raw_seal: &'a [u8],
    case9_final_raw_seal: &'a [u8],
    canonical_statement: &'a [u8],
    consumer_guest_elf: &'a [u8],
    consumer_program_id: [u8; DIGEST_BYTES],
    alternate_guest_elf: &'a [u8],
    alternate_program_id: [u8; DIGEST_BYTES],
}

/// Complete authenticated byte source minted only from the affine V2 authority.
///
/// This is a distinct borrowed token, not a wrapper or conversion of the V1
/// producer source. Private fields prevent safe external fabrication.
pub struct B4AuthenticatedNegativeAncestryProducerSourceV2<'a> {
    case9_recursive_oracle_borsh: &'a [u8],
    case9_assumption_raw_seal: &'a [u8],
    case9_final_raw_seal: &'a [u8],
    canonical_statement: &'a [u8],
    consumer_guest_elf: &'a [u8],
    consumer_program_id: [u8; DIGEST_BYTES],
    alternate_guest_elf: &'a [u8],
    alternate_program_id: [u8; DIGEST_BYTES],
    prior_provenance_paths: &'a BTreeSet<String>,
    positive_provenance_sha256: &'a BTreeMap<String, [u8; DIGEST_BYTES]>,
}

impl<'a> B4AuthenticatedCase9AssumptionSourceV1<'a> {
    #[cfg(all(
        feature = "positive-gate",
        feature = "recursive-ancestry",
        feature = "receipt-oracle"
    ))]
    pub(crate) fn from_authority(authority: &'a B4NegativeAncestrySourceAuthorityV1) -> Self {
        let (recursive_oracle_borsh, assumption_raw_seal, statement, consumer_program_id) =
            authority.case9_assumption_source_parts();
        Self {
            recursive_oracle_borsh,
            assumption_raw_seal,
            statement,
            consumer_program_id,
        }
    }

    /// Exact authenticated `candidate-recursive-oracle.borsh` bytes.
    #[must_use]
    pub const fn recursive_oracle_borsh(&self) -> &[u8] {
        self.recursive_oracle_borsh
    }

    /// Exact authenticated case-9 assumption raw seal.
    #[must_use]
    pub const fn assumption_raw_seal(&self) -> &[u8] {
        self.assumption_raw_seal
    }

    /// Exact authenticated case-9 journal/statement bytes.
    #[must_use]
    pub const fn statement(&self) -> &[u8] {
        self.statement
    }

    /// Authenticated consumer program ID bound by the profile and case-9 export.
    #[must_use]
    pub const fn consumer_program_id(&self) -> [u8; DIGEST_BYTES] {
        self.consumer_program_id
    }
}

impl<'a> B4AuthenticatedNegativeAncestryProducerSourceV1<'a> {
    #[cfg(all(
        feature = "positive-gate",
        feature = "recursive-ancestry",
        feature = "receipt-oracle"
    ))]
    pub(crate) fn from_authority(authority: &'a B4NegativeAncestrySourceAuthorityV1) -> Self {
        let projection = authority.producer_source_projection();
        Self {
            case9_recursive_oracle_borsh: projection.case9_recursive_oracle_borsh,
            case9_assumption_raw_seal: projection.case9_assumption_raw_seal,
            case9_final_raw_seal: projection.case9_final_raw_seal,
            canonical_statement: projection.canonical_statement,
            consumer_guest_elf: projection.consumer_guest_elf,
            consumer_program_id: projection.consumer_program_id,
            alternate_guest_elf: projection.alternate_guest_elf,
            alternate_program_id: projection.alternate_program_id,
        }
    }

    /// Exact authenticated `candidate-recursive-oracle.borsh` bytes.
    #[must_use]
    pub const fn case9_recursive_oracle_borsh(&self) -> &[u8] {
        self.case9_recursive_oracle_borsh
    }

    /// Exact authenticated case-9 assumption raw seal.
    #[must_use]
    pub const fn case9_assumption_raw_seal(&self) -> &[u8] {
        self.case9_assumption_raw_seal
    }

    /// Exact authenticated case-9 final Resolve raw seal.
    #[must_use]
    pub const fn case9_final_raw_seal(&self) -> &[u8] {
        self.case9_final_raw_seal
    }

    /// Exact authenticated canonical statement.
    #[must_use]
    pub const fn canonical_statement(&self) -> &[u8] {
        self.canonical_statement
    }

    /// Exact authenticated consumer guest ELF.
    #[must_use]
    pub const fn consumer_guest_elf(&self) -> &[u8] {
        self.consumer_guest_elf
    }

    /// Authenticated consumer program ID derived by the source authority.
    #[must_use]
    pub const fn consumer_program_id(&self) -> [u8; DIGEST_BYTES] {
        self.consumer_program_id
    }

    /// Exact authenticated alternate guest ELF.
    #[must_use]
    pub const fn alternate_guest_elf(&self) -> &[u8] {
        self.alternate_guest_elf
    }

    /// Authenticated alternate program ID derived by the source authority.
    #[must_use]
    pub const fn alternate_program_id(&self) -> [u8; DIGEST_BYTES] {
        self.alternate_program_id
    }
}

impl<'a> B4AuthenticatedNegativeAncestryProducerSourceV2<'a> {
    #[cfg(all(
        feature = "positive-gate",
        feature = "recursive-ancestry",
        feature = "receipt-oracle"
    ))]
    pub(crate) fn from_authority(authority: &'a B4NegativeAncestrySourceAuthorityV2) -> Self {
        let projection = authority.producer_source_projection();
        Self {
            case9_recursive_oracle_borsh: projection.case9_recursive_oracle_borsh,
            case9_assumption_raw_seal: projection.case9_assumption_raw_seal,
            case9_final_raw_seal: projection.case9_final_raw_seal,
            canonical_statement: projection.canonical_statement,
            consumer_guest_elf: projection.consumer_guest_elf,
            consumer_program_id: projection.consumer_program_id,
            alternate_guest_elf: projection.alternate_guest_elf,
            alternate_program_id: projection.alternate_program_id,
            prior_provenance_paths: projection.prior_provenance_paths,
            positive_provenance_sha256: projection.positive_provenance_sha256,
        }
    }

    /// Exact authenticated `candidate-recursive-oracle.borsh` bytes.
    #[must_use]
    pub const fn case9_recursive_oracle_borsh(&self) -> &[u8] {
        self.case9_recursive_oracle_borsh
    }

    /// Exact authenticated case-9 assumption raw seal.
    #[must_use]
    pub const fn case9_assumption_raw_seal(&self) -> &[u8] {
        self.case9_assumption_raw_seal
    }

    /// Exact authenticated case-9 final Resolve raw seal.
    #[must_use]
    pub const fn case9_final_raw_seal(&self) -> &[u8] {
        self.case9_final_raw_seal
    }

    /// Exact authenticated canonical statement.
    #[must_use]
    pub const fn canonical_statement(&self) -> &[u8] {
        self.canonical_statement
    }

    /// Exact authenticated consumer guest ELF.
    #[must_use]
    pub const fn consumer_guest_elf(&self) -> &[u8] {
        self.consumer_guest_elf
    }

    /// Authenticated consumer program ID derived by the V2 source authority.
    #[must_use]
    pub const fn consumer_program_id(&self) -> [u8; DIGEST_BYTES] {
        self.consumer_program_id
    }

    /// Exact authenticated alternate guest ELF.
    #[must_use]
    pub const fn alternate_guest_elf(&self) -> &[u8] {
        self.alternate_guest_elf
    }

    /// Authenticated alternate program ID derived by the V2 source authority.
    #[must_use]
    pub const fn alternate_program_id(&self) -> [u8; DIGEST_BYTES] {
        self.alternate_program_id
    }

    /// Exact campaign-plus-positive provenance closure retained before V2 source expansion.
    #[must_use]
    pub const fn prior_provenance_paths(&self) -> &BTreeSet<String> {
        self.prior_provenance_paths
    }

    /// Exact path-to-SHA-256 closure retained by the V2 positive authority.
    #[must_use]
    pub const fn positive_provenance_sha256(&self) -> &BTreeMap<String, [u8; DIGEST_BYTES]> {
        self.positive_provenance_sha256
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn v2_producer_source_is_a_distinct_private_field_token() {
        let source = include_str!("b4_negative_ancestry_source.rs");
        let declaration = source
            .split("pub struct B4AuthenticatedNegativeAncestryProducerSourceV2")
            .nth(1)
            .unwrap()
            .split("impl<'a> B4AuthenticatedCase9AssumptionSourceV1")
            .next()
            .unwrap();
        assert!(declaration.contains("case9_recursive_oracle_borsh: &'a [u8]"));
        assert!(declaration.contains("prior_provenance_paths: &'a BTreeSet<String>"));
        assert!(
            declaration
                .contains("positive_provenance_sha256: &'a BTreeMap<String, [u8; DIGEST_BYTES]>")
        );
        assert!(!declaration.contains("pub case9_recursive_oracle_borsh"));
        let alias = ["type B4Authenticated", "NegativeAncestryProducerSourceV2"].concat();
        let conversion = ["From<B4Authenticated", "NegativeAncestryProducerSourceV2"].concat();
        assert!(!source.contains(&alias));
        assert!(!source.contains(&conversion));
    }
}
