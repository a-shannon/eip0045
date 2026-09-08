// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Feature-independent layout constants shared by B4 ancestry handoff formats.

/// Archive-relative path of the canonical negative-ancestry witness catalogue.
pub const B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_PATH: &str =
    "reproduction/negative-ancestry-witness-catalog.json";

/// Maximum canonical byte length of the committed witness catalogue.
pub(crate) const B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_MAX_BYTES: u64 = 131_072;
