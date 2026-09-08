// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Exact shared wire codec for recursive positive auxiliary raw seals.

use anyhow::{Context as _, Result, ensure};

use crate::{
    b4_recursive_auxiliary_paths::{
        MAX_RECURSIVE_AUXILIARY_ARTIFACT_PATHS, compiled_positive_auxiliary_artifact_paths,
    },
    b4_terminal_byte_map::{
        B4ByteMapContract, B4ByteMapPayloadBounds, decode_byte_map,
        exact_byte_map_maximum_encoded_bytes,
    },
    constants::PROOF_BYTES,
    recursive_ancestry::RecursiveAncestryFamily,
};

#[cfg(any(feature = "positive-gate", test))]
use crate::b4_terminal_byte_map::{B4ByteMapEntry, encode_byte_map};

/// Maximum accepted encoded auxiliary-map size.
pub(crate) const B4_RECURSIVE_AUXILIARY_MAP_MAX_BYTES: usize =
    exact_byte_map_maximum_encoded_bytes(MAX_RECURSIVE_AUXILIARY_ARTIFACT_PATHS, PROOF_BYTES);

const TWO_AUXILIARY_PAYLOAD_BOUNDS: [B4ByteMapPayloadBounds; 2] =
    [B4ByteMapPayloadBounds::new(PROOF_BYTES, PROOF_BYTES); 2];
const FOUR_AUXILIARY_PAYLOAD_BOUNDS: [B4ByteMapPayloadBounds; 4] =
    [B4ByteMapPayloadBounds::new(PROOF_BYTES, PROOF_BYTES); 4];

fn recursive_auxiliary_contract(
    family: RecursiveAncestryFamily,
) -> Result<(B4ByteMapContract<'static>, &'static [&'static str])> {
    let expected = compiled_positive_auxiliary_artifact_paths(family.positive_case_index())?;
    let payload_bounds: &'static [B4ByteMapPayloadBounds] = match family {
        RecursiveAncestryFamily::TerminalJoin | RecursiveAncestryFamily::TerminalResolve => {
            &TWO_AUXILIARY_PAYLOAD_BOUNDS
        }
        RecursiveAncestryFamily::ResolveThenJoin => &FOUR_AUXILIARY_PAYLOAD_BOUNDS,
    };
    ensure!(
        expected.len() == payload_bounds.len() && expected.len() == family.auxiliary_count(),
        "compiled auxiliary path cardinality differs from the recursive family"
    );
    let family_maximum = exact_byte_map_maximum_encoded_bytes(expected, PROOF_BYTES);
    ensure!(
        family_maximum <= B4_RECURSIVE_AUXILIARY_MAP_MAX_BYTES,
        "compiled auxiliary family exceeds the enclosing subject byte bound"
    );
    Ok((
        B4ByteMapContract::exact(payload_bounds, expected, family_maximum),
        expected,
    ))
}

/// Borrowed, family-exact auxiliary raw-seal inventory.
///
/// Paths are normalized to the sole compiled path authority. Construction and
/// decoding both require exact path order, exact cardinality, and exact seal
/// lengths before this type can exist.
#[derive(Debug)]
pub(crate) struct B4RecursiveAuxiliaryMapV1<'a> {
    family: RecursiveAncestryFamily,
    entries: Vec<(&'static str, &'a [u8])>,
}

impl<'a> B4RecursiveAuxiliaryMapV1<'a> {
    /// Authenticate one already ordered source inventory.
    #[cfg(any(feature = "positive-gate", test))]
    pub(crate) fn from_exact_entries(
        family: RecursiveAncestryFamily,
        entries: &[(&str, &'a [u8])],
    ) -> Result<Self> {
        let expected = compiled_positive_auxiliary_artifact_paths(family.positive_case_index())?;
        ensure!(
            entries.len() == expected.len(),
            "auxiliary seal count differs from the parsed ancestry family"
        );

        let mut authenticated = Vec::with_capacity(expected.len());
        for ((path, payload), expected_path) in entries.iter().zip(expected) {
            ensure!(
                path.as_bytes() == expected_path.as_bytes(),
                "auxiliary path differs from the exact compiled family sequence"
            );
            ensure!(
                payload.len() == PROOF_BYTES,
                "auxiliary producer seal has the wrong exact byte length"
            );
            authenticated.push((*expected_path, *payload));
        }
        Ok(Self {
            family,
            entries: authenticated,
        })
    }

    /// Parsed recursive family.
    pub(crate) const fn family(&self) -> RecursiveAncestryFamily {
        self.family
    }

    /// Exact entry count.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Borrow one exact compiled-path payload.
    pub(crate) fn get(&self, path: &str) -> Option<&'a [u8]> {
        self.entries
            .iter()
            .find_map(|(candidate, payload)| (*candidate == path).then_some(*payload))
    }

    /// Iterate in exact compiled unsigned-byte path order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&'static str, &'a [u8])> + '_ {
        self.entries.iter().copied()
    }
}

/// Encode one authenticated auxiliary inventory using the shared exact wire.
#[cfg(any(feature = "positive-gate", test))]
pub(crate) fn encode_recursive_auxiliary_map(
    map: &B4RecursiveAuxiliaryMapV1<'_>,
) -> Result<Vec<u8>> {
    let (contract, _expected) = recursive_auxiliary_contract(map.family)?;
    let entries = map
        .entries
        .iter()
        .map(|(path, payload)| B4ByteMapEntry::new(path, payload))
        .collect::<Vec<_>>();
    encode_byte_map(contract, &entries).context("cannot encode exact recursive auxiliary map")
}

/// Decode an exact family-bound auxiliary inventory without copying payloads.
pub(crate) fn decode_recursive_auxiliary_map(
    source: &[u8],
    family: RecursiveAncestryFamily,
) -> Result<B4RecursiveAuxiliaryMapV1<'_>> {
    ensure!(
        source.len() <= B4_RECURSIVE_AUXILIARY_MAP_MAX_BYTES,
        "auxiliary seal map exceeds its byte bound"
    );
    let (contract, expected) = recursive_auxiliary_contract(family)?;
    let decoded =
        decode_byte_map(source, contract).context("cannot decode exact recursive auxiliary map")?;
    let entries = expected
        .iter()
        .zip(decoded.entries())
        .map(|(expected_path, entry)| (*expected_path, entry.payload()))
        .collect();
    Ok(B4RecursiveAuxiliaryMapV1 { family, entries })
}

// Keep the staged validator-facing decode API type-checked in the isolated
// negative-materialization feature before the remaining ancestry consumers
// land. This has no runtime or public API surface.
#[cfg(feature = "negative-materialization-set")]
const _: () = {
    let _ = B4RecursiveAuxiliaryMapV1::family;
    let _ = B4RecursiveAuxiliaryMapV1::len;
    let _ = B4RecursiveAuxiliaryMapV1::get;
    let _ = decode_recursive_auxiliary_map;
};

#[cfg(test)]
mod tests {
    use crate::{constants::PROOF_BYTES, recursive_ancestry::RecursiveAncestryFamily};

    use super::{
        B4_RECURSIVE_AUXILIARY_MAP_MAX_BYTES, B4RecursiveAuxiliaryMapV1,
        decode_recursive_auxiliary_map, encode_recursive_auxiliary_map,
    };

    fn exact_entries(
        family: RecursiveAncestryFamily,
        payloads: &[Vec<u8>],
    ) -> Vec<(&'static str, &[u8])> {
        crate::b4_recursive_auxiliary_paths::compiled_positive_auxiliary_artifact_paths(
            family.positive_case_index(),
        )
        .unwrap()
        .iter()
        .zip(payloads)
        .map(|(path, payload)| (*path, payload.as_slice()))
        .collect()
    }

    #[test]
    fn all_three_family_maps_round_trip_exactly() {
        for family in [
            RecursiveAncestryFamily::TerminalJoin,
            RecursiveAncestryFamily::TerminalResolve,
            RecursiveAncestryFamily::ResolveThenJoin,
        ] {
            let payloads = (0..family.auxiliary_count())
                .map(|index| vec![u8::try_from(index + 1).unwrap(); PROOF_BYTES])
                .collect::<Vec<_>>();
            let entries = exact_entries(family, &payloads);
            let authenticated =
                B4RecursiveAuxiliaryMapV1::from_exact_entries(family, &entries).unwrap();
            let encoded = encode_recursive_auxiliary_map(&authenticated).unwrap();
            let decoded = decode_recursive_auxiliary_map(&encoded, family).unwrap();

            assert_eq!(decoded.family(), family);
            assert_eq!(decoded.len(), family.auxiliary_count());
            assert_eq!(decoded.iter().collect::<Vec<_>>(), entries);
            assert_eq!(encode_recursive_auxiliary_map(&decoded).unwrap(), encoded);
        }
    }

    #[test]
    fn family_caps_are_exact_and_the_largest_is_the_envelope_cap() {
        let families = [
            RecursiveAncestryFamily::TerminalJoin,
            RecursiveAncestryFamily::TerminalResolve,
            RecursiveAncestryFamily::ResolveThenJoin,
        ];
        let exact_caps = families.map(|family| {
            let paths =
                crate::b4_recursive_auxiliary_paths::compiled_positive_auxiliary_artifact_paths(
                    family.positive_case_index(),
                )
                .unwrap();
            crate::b4_terminal_byte_map::exact_byte_map_maximum_encoded_bytes(paths, PROOF_BYTES)
        });
        assert_eq!(exact_caps, [445_560, 445_597, 891_177]);
        assert_eq!(
            B4_RECURSIVE_AUXILIARY_MAP_MAX_BYTES,
            *exact_caps.iter().max().unwrap()
        );
    }

    #[test]
    fn constructor_rejects_missing_extra_reordered_and_cross_family_entries() {
        let family = RecursiveAncestryFamily::TerminalResolve;
        let payloads = vec![vec![1; PROOF_BYTES], vec![2; PROOF_BYTES]];
        let entries = exact_entries(family, &payloads);

        assert!(B4RecursiveAuxiliaryMapV1::from_exact_entries(family, &entries[..1]).is_err());

        let mut extra = entries.clone();
        extra.push(entries[0]);
        assert!(B4RecursiveAuxiliaryMapV1::from_exact_entries(family, &extra).is_err());

        let mut reordered = entries.clone();
        reordered.swap(0, 1);
        assert!(B4RecursiveAuxiliaryMapV1::from_exact_entries(family, &reordered).is_err());

        assert!(
            B4RecursiveAuxiliaryMapV1::from_exact_entries(
                RecursiveAncestryFamily::TerminalJoin,
                &entries,
            )
            .is_err()
        );
    }

    #[test]
    fn decoder_rejects_truncation_trailing_bytes_and_wrong_family() {
        let family = RecursiveAncestryFamily::TerminalResolve;
        let payloads = vec![vec![1; PROOF_BYTES], vec![2; PROOF_BYTES]];
        let entries = exact_entries(family, &payloads);
        let authenticated =
            B4RecursiveAuxiliaryMapV1::from_exact_entries(family, &entries).unwrap();
        let encoded = encode_recursive_auxiliary_map(&authenticated).unwrap();

        assert!(decode_recursive_auxiliary_map(&encoded[..encoded.len() - 1], family).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_recursive_auxiliary_map(&trailing, family).is_err());
        assert!(
            decode_recursive_auxiliary_map(&encoded, RecursiveAncestryFamily::TerminalJoin,)
                .is_err()
        );
    }

    #[test]
    fn exact_payload_length_is_mandatory() {
        let family = RecursiveAncestryFamily::TerminalJoin;
        let payloads = vec![vec![1; PROOF_BYTES], vec![2; PROOF_BYTES - 1]];
        let entries = exact_entries(family, &payloads);
        assert!(B4RecursiveAuxiliaryMapV1::from_exact_entries(family, &entries).is_err());
    }
}
