//! Fixed owned evidence for the seven B4 negative-ancestry witnesses.
//!
//! Evidence bytes are stored exactly once under seven named identities. The
//! eleven physical row views are derived only from the reproduction crate's
//! compiled layout and borrow those owned bytes.

use anyhow::{Result, anyhow, ensure};
#[cfg(feature = "b4-negative-ancestry-finalization")]
use eip_0045_reproduction::b4_negative_ancestry_authority::{
    B4NegativeAncestryExternalBytesV1, B4NegativeAncestrySourceAuthorityV1,
    B4NegativeAncestrySourceAuthorityV2, B4NegativeAncestryWitnessCatalogAuthorityV1,
    B4NegativeAncestryWitnessCatalogAuthorityV2, B4NegativeAncestryWitnessExternalEntryV1,
};
use eip_0045_reproduction::{
    b4_negative_ancestry_witness::{
        B4_NEGATIVE_ANCESTRY_BINDING_COUNT, B4_NEGATIVE_ANCESTRY_DISTINCT_WITNESS_COUNT,
        B4NegativeAncestryWitnessIdV1, compiled_negative_ancestry_witness_layout,
    },
    constants::PROOF_BYTES,
    receipt_oracle_codec::RECEIPT_ORACLE_MAX_BYTES,
};

/// One exact direct-receipt evidence pair produced for a distinct witness.
#[derive(Debug, Eq, PartialEq)]
pub struct B4NegativeAncestryDirectEvidenceV1 {
    raw_seal: Vec<u8>,
    receipt_oracle: Vec<u8>,
}

impl B4NegativeAncestryDirectEvidenceV1 {
    fn from_verified_parts(raw_seal: Vec<u8>, receipt_oracle: Vec<u8>) -> Result<Self> {
        ensure!(
            raw_seal.len() == PROOF_BYTES,
            "negative ancestry raw seal must be exactly {PROOF_BYTES} bytes"
        );
        ensure!(
            (1..=RECEIPT_ORACLE_MAX_BYTES).contains(&receipt_oracle.len()),
            "negative ancestry receipt oracle is outside its closed byte bound"
        );
        Ok(Self {
            raw_seal,
            receipt_oracle,
        })
    }

    /// Exact little-endian raw succinct seal.
    #[must_use]
    pub fn raw_seal(&self) -> &[u8] {
        &self.raw_seal
    }

    /// Exact direct `SuccinctReceipt<ReceiptClaim>` bincode oracle.
    #[must_use]
    pub fn receipt_oracle(&self) -> &[u8] {
        &self.receipt_oracle
    }
}

/// Exact authenticated evidence for the case-9 assumption Lift identity.
#[derive(Debug)]
pub(crate) struct B4Case9AssumptionLiftEvidenceV1(B4NegativeAncestryDirectEvidenceV1);
/// Exact authenticated evidence for the case-9 final Resolve identity.
#[derive(Debug)]
pub(crate) struct B4Case9FinalResolveEvidenceV1(B4NegativeAncestryDirectEvidenceV1);
/// Exact authenticated evidence for the alternate-statement assumption Lift identity.
#[derive(Debug)]
pub(crate) struct B4AlternateStatementAssumptionLiftEvidenceV1(B4NegativeAncestryDirectEvidenceV1);
/// Exact authenticated evidence for the alternate-program Lift identity.
#[derive(Debug)]
pub(crate) struct B4AlternateProgramLiftEvidenceV1(B4NegativeAncestryDirectEvidenceV1);
/// Exact authenticated evidence for the alternate-statement final Resolve identity.
#[derive(Debug)]
pub(crate) struct B4AlternateStatementFinalResolveEvidenceV1(B4NegativeAncestryDirectEvidenceV1);
/// Exact authenticated evidence for the alternate-statement final Join identity.
#[derive(Debug)]
pub(crate) struct B4AlternateStatementFinalJoinEvidenceV1(B4NegativeAncestryDirectEvidenceV1);
/// Exact authenticated evidence for the duplicate-assumption Lift identity.
#[derive(Debug)]
pub(crate) struct B4DuplicateAssumptionLiftEvidenceV1(B4NegativeAncestryDirectEvidenceV1);

macro_rules! impl_verified_evidence_newtype {
    ($evidence_type:ident) => {
        impl $evidence_type {
            #[allow(
                dead_code,
                reason = "called by the separately approved proof-production integration tranche"
            )]
            pub(crate) fn from_verified_parts(
                raw_seal: Vec<u8>,
                receipt_oracle: Vec<u8>,
            ) -> Result<Self> {
                Ok(Self(
                    B4NegativeAncestryDirectEvidenceV1::from_verified_parts(
                        raw_seal,
                        receipt_oracle,
                    )?,
                ))
            }

            const fn evidence(&self) -> &B4NegativeAncestryDirectEvidenceV1 {
                &self.0
            }
        }
    };
}

impl_verified_evidence_newtype!(B4Case9AssumptionLiftEvidenceV1);
impl_verified_evidence_newtype!(B4Case9FinalResolveEvidenceV1);
impl_verified_evidence_newtype!(B4AlternateStatementAssumptionLiftEvidenceV1);
impl_verified_evidence_newtype!(B4AlternateProgramLiftEvidenceV1);
impl_verified_evidence_newtype!(B4AlternateStatementFinalResolveEvidenceV1);
impl_verified_evidence_newtype!(B4AlternateStatementFinalJoinEvidenceV1);
impl_verified_evidence_newtype!(B4DuplicateAssumptionLiftEvidenceV1);

/// Atomic owned set of exactly seven distinct negative-ancestry witnesses.
#[derive(Debug)]
pub struct B4ProducedNegativeAncestryWitnessSetV1 {
    case9_assumption_lift: B4Case9AssumptionLiftEvidenceV1,
    case9_final_resolve: B4Case9FinalResolveEvidenceV1,
    alternate_statement_assumption_lift: B4AlternateStatementAssumptionLiftEvidenceV1,
    alternate_program_lift: B4AlternateProgramLiftEvidenceV1,
    alternate_statement_final_resolve: B4AlternateStatementFinalResolveEvidenceV1,
    alternate_statement_final_join: B4AlternateStatementFinalJoinEvidenceV1,
    duplicate_assumption_lift: B4DuplicateAssumptionLiftEvidenceV1,
}

impl B4ProducedNegativeAncestryWitnessSetV1 {
    /// Construct the fixed seven-witness set after every producer has verified
    /// its own evidence.
    ///
    /// # Errors
    ///
    /// Returns an error if any two named identities reuse the same raw-seal
    /// bytes or the same receipt-oracle bytes.
    #[allow(
        dead_code,
        clippy::too_many_arguments,
        reason = "seven named arguments make the closed witness cardinality explicit"
    )]
    pub(crate) fn from_verified_distinct(
        case9_assumption_lift: B4Case9AssumptionLiftEvidenceV1,
        case9_final_resolve: B4Case9FinalResolveEvidenceV1,
        alternate_statement_assumption_lift: B4AlternateStatementAssumptionLiftEvidenceV1,
        alternate_program_lift: B4AlternateProgramLiftEvidenceV1,
        alternate_statement_final_resolve: B4AlternateStatementFinalResolveEvidenceV1,
        alternate_statement_final_join: B4AlternateStatementFinalJoinEvidenceV1,
        duplicate_assumption_lift: B4DuplicateAssumptionLiftEvidenceV1,
    ) -> Result<Self> {
        let set = Self {
            case9_assumption_lift,
            case9_final_resolve,
            alternate_statement_assumption_lift,
            alternate_program_lift,
            alternate_statement_final_resolve,
            alternate_statement_final_join,
            duplicate_assumption_lift,
        };
        let witnesses = set.distinct_witnesses();
        for (left_index, left) in witnesses.iter().enumerate() {
            for right in witnesses.iter().skip(left_index + 1) {
                ensure!(
                    left.1.raw_seal != right.1.raw_seal,
                    "negative ancestry witnesses {:?} and {:?} reuse raw-seal bytes",
                    left.0,
                    right.0
                );
                ensure!(
                    left.1.receipt_oracle != right.1.receipt_oracle,
                    "negative ancestry witnesses {:?} and {:?} reuse receipt-oracle bytes",
                    left.0,
                    right.0
                );
            }
        }
        Ok(set)
    }

    /// The exact seven witness identities and their owned evidence.
    #[must_use]
    pub const fn distinct_witnesses(
        &self,
    ) -> [(
        B4NegativeAncestryWitnessIdV1,
        &B4NegativeAncestryDirectEvidenceV1,
    ); B4_NEGATIVE_ANCESTRY_DISTINCT_WITNESS_COUNT] {
        [
            (
                B4NegativeAncestryWitnessIdV1::Case9AssumptionLift,
                self.case9_assumption_lift.evidence(),
            ),
            (
                B4NegativeAncestryWitnessIdV1::Case9FinalResolve,
                self.case9_final_resolve.evidence(),
            ),
            (
                B4NegativeAncestryWitnessIdV1::AlternateStatementAssumptionLift,
                self.alternate_statement_assumption_lift.evidence(),
            ),
            (
                B4NegativeAncestryWitnessIdV1::AlternateProgramLift,
                self.alternate_program_lift.evidence(),
            ),
            (
                B4NegativeAncestryWitnessIdV1::AlternateStatementFinalResolve,
                self.alternate_statement_final_resolve.evidence(),
            ),
            (
                B4NegativeAncestryWitnessIdV1::AlternateStatementFinalJoin,
                self.alternate_statement_final_join.evidence(),
            ),
            (
                B4NegativeAncestryWitnessIdV1::DuplicateAssumptionLift,
                self.duplicate_assumption_lift.evidence(),
            ),
        ]
    }

    /// Expand the seven stored identities into the exact eleven compiled rows.
    ///
    /// This method accepts no row, role, terminal, path, count, or recipe
    /// selectors. Every row and physical path comes from the compiled
    /// reproduction layout.
    ///
    /// # Errors
    ///
    /// Returns an error if the compiled layout cannot be derived or does not
    /// contain exactly eleven rows.
    pub fn expand_compiled_rows(
        &self,
    ) -> Result<[B4NegativeAncestryWitnessRowViewV1<'_>; B4_NEGATIVE_ANCESTRY_BINDING_COUNT]> {
        let layout = compiled_negative_ancestry_witness_layout()?;
        ensure!(
            layout.len() == B4_NEGATIVE_ANCESTRY_BINDING_COUNT,
            "compiled negative ancestry layout does not contain exactly eleven rows"
        );
        let rows = layout
            .into_iter()
            .map(|slot| B4NegativeAncestryWitnessRowViewV1 {
                expanded_row: slot.expanded_row,
                witness_id: slot.witness_id,
                raw_seal_path: slot.raw_seal_path,
                receipt_oracle_path: slot.receipt_oracle_path,
                evidence: self.evidence(slot.witness_id),
            })
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|rows: Vec<_>| {
                anyhow!(
                    "compiled negative ancestry expansion produced {} rows, expected {}",
                    rows.len(),
                    B4_NEGATIVE_ANCESTRY_BINDING_COUNT
                )
            })?;
        Ok(rows)
    }

    /// Project the exact compiled eleven-row fan-out by borrowing evidence
    /// bytes, then let the authenticated catalogue authority retain its own
    /// checked copies.
    ///
    /// # Errors
    ///
    /// Returns the reproduction authority's first closure, replay, claim, or
    /// derived-catalogue invariant failure.
    #[cfg(feature = "b4-negative-ancestry-finalization")]
    pub fn finalize_catalog(
        &self,
        authority: &B4NegativeAncestrySourceAuthorityV1,
    ) -> Result<B4NegativeAncestryWitnessCatalogAuthorityV1> {
        let rows = self.expand_compiled_rows()?;
        let entries = external_entries_for_rows(&rows);
        authority.finalize(&entries)
    }

    /// Project the same fixed eleven-row witness set into a V2-derived
    /// catalogue without converting or weakening the V2 source authority.
    ///
    /// # Errors
    ///
    /// Returns the V2 reproduction authority's first closure, replay, claim,
    /// or derived-catalogue invariant failure.
    #[cfg(feature = "b4-negative-ancestry-finalization")]
    pub fn finalize_catalog_v2(
        &self,
        authority: &B4NegativeAncestrySourceAuthorityV2,
    ) -> Result<B4NegativeAncestryWitnessCatalogAuthorityV2> {
        let rows = self.expand_compiled_rows()?;
        let entries = external_entries_for_rows(&rows);
        authority.finalize(&entries)
    }

    const fn evidence(
        &self,
        witness_id: B4NegativeAncestryWitnessIdV1,
    ) -> &B4NegativeAncestryDirectEvidenceV1 {
        match witness_id {
            B4NegativeAncestryWitnessIdV1::Case9AssumptionLift => {
                self.case9_assumption_lift.evidence()
            }
            B4NegativeAncestryWitnessIdV1::Case9FinalResolve => self.case9_final_resolve.evidence(),
            B4NegativeAncestryWitnessIdV1::AlternateStatementAssumptionLift => {
                self.alternate_statement_assumption_lift.evidence()
            }
            B4NegativeAncestryWitnessIdV1::AlternateProgramLift => {
                self.alternate_program_lift.evidence()
            }
            B4NegativeAncestryWitnessIdV1::AlternateStatementFinalResolve => {
                self.alternate_statement_final_resolve.evidence()
            }
            B4NegativeAncestryWitnessIdV1::AlternateStatementFinalJoin => {
                self.alternate_statement_final_join.evidence()
            }
            B4NegativeAncestryWitnessIdV1::DuplicateAssumptionLift => {
                self.duplicate_assumption_lift.evidence()
            }
        }
    }
}

/// Borrowed evidence view for one exact compiled physical row.
#[derive(Debug)]
pub struct B4NegativeAncestryWitnessRowViewV1<'a> {
    expanded_row: u16,
    witness_id: B4NegativeAncestryWitnessIdV1,
    raw_seal_path: String,
    receipt_oracle_path: String,
    evidence: &'a B4NegativeAncestryDirectEvidenceV1,
}

impl<'a> B4NegativeAncestryWitnessRowViewV1<'a> {
    /// Exact expanded-corpus row.
    #[must_use]
    pub const fn expanded_row(&self) -> u16 {
        self.expanded_row
    }

    /// Exact compiled witness identity selected by this row.
    #[must_use]
    pub const fn witness_id(&self) -> B4NegativeAncestryWitnessIdV1 {
        self.witness_id
    }

    /// Exact compiled create-only raw-seal path.
    #[must_use]
    pub fn raw_seal_path(&self) -> &str {
        &self.raw_seal_path
    }

    /// Exact compiled create-only direct-oracle path.
    #[must_use]
    pub fn receipt_oracle_path(&self) -> &str {
        &self.receipt_oracle_path
    }

    /// Borrow the one stored evidence identity selected by this row.
    #[must_use]
    pub const fn evidence(&self) -> &'a B4NegativeAncestryDirectEvidenceV1 {
        self.evidence
    }
}

#[cfg(feature = "b4-negative-ancestry-finalization")]
fn external_entries_for_rows<'rows, 'evidence>(
    rows: &'rows [B4NegativeAncestryWitnessRowViewV1<'evidence>;
               B4_NEGATIVE_ANCESTRY_BINDING_COUNT],
) -> [B4NegativeAncestryWitnessExternalEntryV1<'rows>; B4_NEGATIVE_ANCESTRY_BINDING_COUNT]
where
    'evidence: 'rows,
{
    std::array::from_fn(|index| {
        let row = &rows[index];
        B4NegativeAncestryWitnessExternalEntryV1 {
            expanded_row: row.expanded_row(),
            raw_seal: B4NegativeAncestryExternalBytesV1 {
                path: row.raw_seal_path(),
                bytes: row.evidence().raw_seal(),
            },
            receipt_oracle: B4NegativeAncestryExternalBytesV1 {
                path: row.receipt_oracle_path(),
                bytes: row.evidence().receipt_oracle(),
            },
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED_WITNESS_IDS: [B4NegativeAncestryWitnessIdV1; 7] = [
        B4NegativeAncestryWitnessIdV1::Case9AssumptionLift,
        B4NegativeAncestryWitnessIdV1::Case9FinalResolve,
        B4NegativeAncestryWitnessIdV1::AlternateStatementAssumptionLift,
        B4NegativeAncestryWitnessIdV1::AlternateProgramLift,
        B4NegativeAncestryWitnessIdV1::AlternateStatementFinalResolve,
        B4NegativeAncestryWitnessIdV1::AlternateStatementFinalJoin,
        B4NegativeAncestryWitnessIdV1::DuplicateAssumptionLift,
    ];

    #[test]
    fn constructor_positions_are_seven_distinct_identity_types() {
        type ExactConstructor = fn(
            B4Case9AssumptionLiftEvidenceV1,
            B4Case9FinalResolveEvidenceV1,
            B4AlternateStatementAssumptionLiftEvidenceV1,
            B4AlternateProgramLiftEvidenceV1,
            B4AlternateStatementFinalResolveEvidenceV1,
            B4AlternateStatementFinalJoinEvidenceV1,
            B4DuplicateAssumptionLiftEvidenceV1,
        ) -> Result<B4ProducedNegativeAncestryWitnessSetV1>;

        let constructor: ExactConstructor =
            B4ProducedNegativeAncestryWitnessSetV1::from_verified_distinct;
        let _ = constructor;

        let type_ids = [
            std::any::TypeId::of::<B4Case9AssumptionLiftEvidenceV1>(),
            std::any::TypeId::of::<B4Case9FinalResolveEvidenceV1>(),
            std::any::TypeId::of::<B4AlternateStatementAssumptionLiftEvidenceV1>(),
            std::any::TypeId::of::<B4AlternateProgramLiftEvidenceV1>(),
            std::any::TypeId::of::<B4AlternateStatementFinalResolveEvidenceV1>(),
            std::any::TypeId::of::<B4AlternateStatementFinalJoinEvidenceV1>(),
            std::any::TypeId::of::<B4DuplicateAssumptionLiftEvidenceV1>(),
        ];
        for (left_index, left) in type_ids.iter().enumerate() {
            for right in type_ids.iter().skip(left_index + 1) {
                assert_ne!(left, right);
            }
        }

        // The exact function-pointer binding names each positional type.
        // Swapping any two constructor arguments is therefore a compile error.
    }

    fn evidence_parts(raw_seed: u8, oracle_seed: u8) -> (Vec<u8>, Vec<u8>) {
        (
            vec![raw_seed; PROOF_BYTES],
            vec![0x80 | oracle_seed, oracle_seed],
        )
    }

    fn set_with_seeds(
        raw_seeds: [u8; 7],
        oracle_seeds: [u8; 7],
    ) -> Result<B4ProducedNegativeAncestryWitnessSetV1> {
        let (raw_0, oracle_0) = evidence_parts(raw_seeds[0], oracle_seeds[0]);
        let (raw_1, oracle_1) = evidence_parts(raw_seeds[1], oracle_seeds[1]);
        let (raw_2, oracle_2) = evidence_parts(raw_seeds[2], oracle_seeds[2]);
        let (raw_3, oracle_3) = evidence_parts(raw_seeds[3], oracle_seeds[3]);
        let (raw_4, oracle_4) = evidence_parts(raw_seeds[4], oracle_seeds[4]);
        let (raw_5, oracle_5) = evidence_parts(raw_seeds[5], oracle_seeds[5]);
        let (raw_6, oracle_6) = evidence_parts(raw_seeds[6], oracle_seeds[6]);
        B4ProducedNegativeAncestryWitnessSetV1::from_verified_distinct(
            B4Case9AssumptionLiftEvidenceV1::from_verified_parts(raw_0, oracle_0)?,
            B4Case9FinalResolveEvidenceV1::from_verified_parts(raw_1, oracle_1)?,
            B4AlternateStatementAssumptionLiftEvidenceV1::from_verified_parts(raw_2, oracle_2)?,
            B4AlternateProgramLiftEvidenceV1::from_verified_parts(raw_3, oracle_3)?,
            B4AlternateStatementFinalResolveEvidenceV1::from_verified_parts(raw_4, oracle_4)?,
            B4AlternateStatementFinalJoinEvidenceV1::from_verified_parts(raw_5, oracle_5)?,
            B4DuplicateAssumptionLiftEvidenceV1::from_verified_parts(raw_6, oracle_6)?,
        )
    }

    fn synthetic_verified_set() -> B4ProducedNegativeAncestryWitnessSetV1 {
        set_with_seeds([1, 2, 3, 4, 5, 6, 7], [11, 12, 13, 14, 15, 16, 17]).unwrap()
    }

    fn row<'rows, 'evidence>(
        rows: &'rows [B4NegativeAncestryWitnessRowViewV1<'evidence>;
                   B4_NEGATIVE_ANCESTRY_BINDING_COUNT],
        expanded_row: u16,
    ) -> &'rows B4NegativeAncestryWitnessRowViewV1<'evidence> {
        rows.iter()
            .find(|row| row.expanded_row() == expanded_row)
            .unwrap()
    }

    #[test]
    fn set_contains_exactly_seven_named_distinct_identities() {
        let set = synthetic_verified_set();
        let witnesses = set.distinct_witnesses();

        assert_eq!(witnesses.len(), B4_NEGATIVE_ANCESTRY_DISTINCT_WITNESS_COUNT);
        assert_eq!(
            witnesses.map(|(witness_id, _)| witness_id),
            EXPECTED_WITNESS_IDS
        );
        for (left_index, left) in witnesses.iter().enumerate() {
            for right in witnesses.iter().skip(left_index + 1) {
                assert!(!std::ptr::eq(left.1, right.1));
                assert_ne!(left.1.raw_seal(), right.1.raw_seal());
                assert_ne!(left.1.receipt_oracle(), right.1.receipt_oracle());
            }
        }
    }

    #[test]
    fn set_constructor_rejects_duplicate_raw_or_oracle_atomically() {
        assert!(set_with_seeds([1, 1, 3, 4, 5, 6, 7], [11, 12, 13, 14, 15, 16, 17]).is_err());
        assert!(set_with_seeds([1, 2, 3, 4, 5, 6, 7], [11, 11, 13, 14, 15, 16, 17]).is_err());
    }

    #[test]
    fn evidence_constructor_enforces_exact_length_bounds() {
        let maximum_oracle = B4Case9AssumptionLiftEvidenceV1::from_verified_parts(
            vec![1; PROOF_BYTES],
            vec![1; RECEIPT_ORACLE_MAX_BYTES],
        )
        .unwrap();
        assert_eq!(maximum_oracle.evidence().raw_seal().len(), PROOF_BYTES);
        assert_eq!(
            maximum_oracle.evidence().receipt_oracle().len(),
            RECEIPT_ORACLE_MAX_BYTES
        );
        assert!(
            B4Case9AssumptionLiftEvidenceV1::from_verified_parts(
                vec![1; PROOF_BYTES - 1],
                vec![1],
            )
            .is_err()
        );
        assert!(
            B4Case9AssumptionLiftEvidenceV1::from_verified_parts(
                vec![1; PROOF_BYTES + 1],
                vec![1],
            )
            .is_err()
        );
        assert!(
            B4Case9AssumptionLiftEvidenceV1::from_verified_parts(vec![1; PROOF_BYTES], Vec::new())
                .is_err()
        );
        assert!(
            B4Case9AssumptionLiftEvidenceV1::from_verified_parts(
                vec![1; PROOF_BYTES],
                vec![1; RECEIPT_ORACLE_MAX_BYTES + 1],
            )
            .is_err()
        );
    }

    #[test]
    fn fanout_is_exactly_the_eleven_compiled_rows() {
        let set = synthetic_verified_set();
        let rows = set.expand_compiled_rows().unwrap();
        let layout = compiled_negative_ancestry_witness_layout().unwrap();

        assert_eq!(rows.len(), B4_NEGATIVE_ANCESTRY_BINDING_COUNT);
        assert_eq!(
            std::array::from_fn(|index| rows[index].expanded_row()),
            [141, 142, 143, 145, 147, 148, 150, 151, 152, 153, 154]
        );
        for (actual, expected) in rows.iter().zip(layout) {
            assert_eq!(actual.expanded_row(), expected.expanded_row);
            assert_eq!(actual.witness_id(), expected.witness_id);
            assert_eq!(actual.raw_seal_path(), expected.raw_seal_path);
            assert_eq!(actual.receipt_oracle_path(), expected.receipt_oracle_path);
        }
    }

    #[cfg(feature = "b4-negative-ancestry-finalization")]
    #[test]
    fn finalization_projection_borrows_the_exact_compiled_rows() {
        let set = synthetic_verified_set();
        let rows = set.expand_compiled_rows().unwrap();
        let entries = external_entries_for_rows(&rows);

        for (entry, row) in entries.iter().zip(&rows) {
            assert_eq!(entry.expanded_row, row.expanded_row());
            assert_eq!(entry.raw_seal.path, row.raw_seal_path());
            assert_eq!(entry.receipt_oracle.path, row.receipt_oracle_path());
            assert_eq!(entry.raw_seal.bytes, row.evidence().raw_seal());
            assert_eq!(entry.receipt_oracle.bytes, row.evidence().receipt_oracle());
            assert!(std::ptr::eq(
                entry.raw_seal.bytes.as_ptr(),
                row.evidence().raw_seal().as_ptr()
            ));
            assert!(std::ptr::eq(
                entry.receipt_oracle.bytes.as_ptr(),
                row.evidence().receipt_oracle().as_ptr()
            ));
        }
    }

    #[cfg(feature = "b4-negative-ancestry-finalization")]
    #[test]
    fn v1_and_v2_finalization_signatures_remain_distinct() {
        let _: fn(
            &B4ProducedNegativeAncestryWitnessSetV1,
            &B4NegativeAncestrySourceAuthorityV1,
        ) -> Result<B4NegativeAncestryWitnessCatalogAuthorityV1> =
            B4ProducedNegativeAncestryWitnessSetV1::finalize_catalog;
        let _: fn(
            &B4ProducedNegativeAncestryWitnessSetV1,
            &B4NegativeAncestrySourceAuthorityV2,
        ) -> Result<B4NegativeAncestryWitnessCatalogAuthorityV2> =
            B4ProducedNegativeAncestryWitnessSetV1::finalize_catalog_v2;
    }

    #[test]
    fn fanout_reuses_exactly_the_three_compiled_alias_classes() {
        let set = synthetic_verified_set();
        let rows = set.expand_compiled_rows().unwrap();
        let mut actual_groups = Vec::<Vec<u16>>::new();

        for (index, candidate) in rows.iter().enumerate() {
            if rows[..index]
                .iter()
                .any(|earlier| std::ptr::eq(earlier.evidence(), candidate.evidence()))
            {
                continue;
            }
            let group = rows
                .iter()
                .filter(|other| std::ptr::eq(other.evidence(), candidate.evidence()))
                .map(B4NegativeAncestryWitnessRowViewV1::expanded_row)
                .collect::<Vec<_>>();
            actual_groups.push(group);
        }

        assert_eq!(
            actual_groups,
            vec![
                vec![141, 142, 153],
                vec![143],
                vec![145, 150],
                vec![147, 151],
                vec![148],
                vec![152],
                vec![154],
            ]
        );
        assert_eq!(
            actual_groups.iter().filter(|group| group.len() > 1).count(),
            3
        );
    }

    #[test]
    fn seven_representatives_are_pairwise_distinct() {
        let set = synthetic_verified_set();
        let rows = set.expand_compiled_rows().unwrap();
        let representatives =
            [141, 143, 145, 147, 148, 152, 154].map(|expanded_row| row(&rows, expanded_row));

        for (left_index, left) in representatives.iter().enumerate() {
            for right in representatives.iter().skip(left_index + 1) {
                assert!(!std::ptr::eq(left.evidence(), right.evidence()));
                assert_ne!(left.evidence().raw_seal(), right.evidence().raw_seal());
                assert_ne!(
                    left.evidence().receipt_oracle(),
                    right.evidence().receipt_oracle()
                );
            }
        }
    }

    #[test]
    fn row_154_is_distinct_from_the_case9_assumption_lift() {
        let set = synthetic_verified_set();
        let rows = set.expand_compiled_rows().unwrap();
        let duplicate = row(&rows, 154);

        assert_eq!(
            duplicate.witness_id(),
            B4NegativeAncestryWitnessIdV1::DuplicateAssumptionLift
        );
        for case9_row in [141, 142, 153] {
            let case9 = row(&rows, case9_row);
            assert_eq!(
                case9.witness_id(),
                B4NegativeAncestryWitnessIdV1::Case9AssumptionLift
            );
            assert!(!std::ptr::eq(case9.evidence(), duplicate.evidence()));
            assert_ne!(case9.evidence().raw_seal(), duplicate.evidence().raw_seal());
            assert_ne!(
                case9.evidence().receipt_oracle(),
                duplicate.evidence().receipt_oracle()
            );
        }
    }
}
