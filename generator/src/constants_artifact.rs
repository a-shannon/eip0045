// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Canonical B2 verifier-data artifact for the RISC Zero v3 succinct profile.
//!
//! The source extractor is intentionally narrow: it accepts only the exact
//! pinned RISC Zero source files and then converts their numeric tables to the
//! fixed grammar documented by `profiles/risc0-v3-succinct/binary-format.md`.
//! The strict decoder is a separate path and must consume exactly 65,119 bytes.

use std::{collections::BTreeMap, fs, io::Write as _, path::Path};

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

pub const RISC0_COMMIT: &str = "8eb06ab020a92dc5b63ba6dd0836d432aba6d890";
pub const ARTIFACT_BYTES: usize = 65_119;
/// SHA-256 of the exact frozen `constants.bin` bytes.
pub const ARTIFACT_SHA256: &str =
    "8c4a92b7d354890481eefdef233d4ca43f6bcd9f7cb00e4dd9e709da47789ef3";
const HEADER_BYTES: usize = 87;
const ROOT_COUNT: usize = 28;
const POSEIDON_ROUND_CONSTANTS: usize = 213;
const POSEIDON_DIAGONAL_CONSTANTS: usize = 24;
const TAP_COUNT: usize = 643;
const TAP_BYTES: usize = 5;
const OP_COUNT: usize = 12_359;
const FIELD_VARS: usize = 11_130;
const MIX_VARS: usize = 1_229;
const RET_MIX_VAR: usize = 1_228;
const FIELD_VARS_U16: u16 = 11_130;
const MIX_VARS_U16: u16 = 1_229;
const RET_MIX_VAR_U16: u16 = 1_228;
const PROOF_SYSTEM_INFO: &[u8; 16] = b"RISC0_STARK:v1__";
const CIRCUIT_INFO: &[u8; 16] = b"RECURSION:rev1v1";

const SOURCE_LOCKS: &[(&str, &str)] = &[
    (
        "risc0/core/src/field/baby_bear.rs",
        "df3e77d606dd74d78fb6b6f3dbbe72455c5ed5b091f7a74de8c049e85b857ff3",
    ),
    (
        "risc0/zkp/src/core/hash/poseidon2/consts.rs",
        "5ee51bce046bce1306181a43136aa0731dcf976ab10e2e8d82db88711efdcc41",
    ),
    (
        "risc0/zkp/src/core/hash/poseidon2/mod.rs",
        "a2993a2e29fa33345a6a9ce0b4f192efe7412746b92b172b0eed8ce78ee8471f",
    ),
    (
        "risc0/zkp/src/adapter.rs",
        "1d1aca1dd7cc4c12477e0d887a3edfa0825b822efee671170ec667c7dd65ca1d",
    ),
    (
        "risc0/zkp/src/lib.rs",
        "107521d2426442fbc9358b7b9ae5650be92d670ea85e9a34aec7b9e9cc27dc6d",
    ),
    (
        "risc0/zkp/src/verify/mod.rs",
        "003a67af89a7cfaeac9ff23808225cdc4d81c41d64956f20243574531b166c4f",
    ),
    (
        "risc0/circuit/recursion/src/info.rs",
        "128c29a8ddf0560fb3a69c03fa1d959fab542d2fa09eae6794d28be871e345e9",
    ),
    (
        "risc0/circuit/recursion/src/lib.rs",
        "c967923d0d005474a1a75efbfed884fbb496a37bf387cef2b93c742f6c02e488",
    ),
    (
        "risc0/circuit/recursion/src/taps.rs",
        "d32cbf5350d6f724cf3582ef92fb6c392f993b51ee89c5384f7ad79bab43ce83",
    ),
    (
        "risc0/circuit/recursion/src/poly_ext.rs",
        "176f99041c0d3867ecd100b7292adbeb29294a0abe7a8f1f0a05807278da43b3",
    ),
];

const EXPECTED_HISTOGRAM: [(&str, usize); 10] = [
    ("Add", 4_061),
    ("AndCond", 152),
    ("AndEqz", 1_076),
    ("Const", 284),
    ("ConstExt", 0),
    ("Get", 669),
    ("GetGlobal", 52),
    ("Mul", 4_679),
    ("Sub", 1_385),
    ("True", 1),
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConstantsArtifact {
    pub upstream_commit: String,
    pub baby_bear: BabyBearData,
    pub poseidon2: Poseidon2Data,
    pub stark: StarkData,
    pub protocol_info: ProtocolInfoData,
    pub taps: TapDataSet,
    pub poly_ext: PolyExtData,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BabyBearData {
    pub modulus: u32,
    pub extension_degree: u8,
    pub extension_beta: u32,
    pub max_root_po2: u8,
    pub reverse_roots: Vec<u32>,
    pub extension_coefficient_remap: [u8; 4],
    pub extension_challenge_scale: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Poseidon2Data {
    pub cells: u8,
    pub rate: u8,
    pub output_cells: u8,
    pub rounds_half_full: u8,
    pub rounds_partial: u8,
    pub sbox_degree: u8,
    pub round_constants: Vec<u32>,
    pub internal_diagonal: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StarkData {
    pub queries: u8,
    pub inverse_rate: u8,
    pub fri_fold: u8,
    pub fri_fold_po2: u8,
    pub fri_min_degree: u16,
    pub output_size: u8,
    pub mix_size: u8,
    pub check_size: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolInfoData {
    pub proof_system: String,
    pub circuit: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TapDataSet {
    pub group_sizes: [u8; 3],
    pub combos_count: u8,
    pub total_combo_backs: u8,
    pub records: Vec<Tap>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Tap {
    pub group: u8,
    pub offset: u8,
    pub back: u8,
    pub combo: u8,
    pub skip: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolyExtData {
    pub field_variables: u16,
    pub mix_variables: u16,
    pub ret_mix_variable: u16,
    pub histogram: BTreeMap<String, usize>,
    pub operations: Vec<PolyExtOp>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "op", content = "args")]
pub enum PolyExtOp {
    Const(u32),
    ConstExt([u32; 4]),
    Get(u16),
    GetGlobal([u16; 2]),
    Add([u16; 2]),
    Sub([u16; 2]),
    Mul([u16; 2]),
    True,
    AndEqz([u16; 2]),
    AndCond([u16; 3]),
}

#[allow(clippy::too_many_lines)]
pub fn extract_from_pinned_sources(root: &Path) -> Result<ConstantsArtifact> {
    let mut source = BTreeMap::new();
    for &(relative, expected_hash) in SOURCE_LOCKS {
        let path = root.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR));
        let physical_bytes = fs::read(&path)
            .with_context(|| format!("cannot read pinned RISC Zero source {}", path.display()))?;
        let bytes = normalize_source_line_endings(&physical_bytes, relative)?;
        let actual = hex::encode(Sha256::digest(&bytes));
        ensure!(
            actual == expected_hash,
            "source lock mismatch for {relative}: expected {expected_hash}, got {actual}"
        );
        let text = String::from_utf8(bytes)
            .with_context(|| format!("pinned source is not UTF-8: {relative}"))?;
        source.insert(relative, text);
    }

    let baby = &source["risc0/core/src/field/baby_bear.rs"];
    require_all(
        baby,
        &[
            "pub const P: u32 = 15 * (1 << 27) + 1;",
            "const EXT_SIZE: usize = 4;",
            "const BETA: Elem = Elem::new(11);",
            "const MAX_ROU_PO2: usize = 27;",
        ],
    )?;
    let roots = parse_numeric_macro(baby, "const ROU_REV:", "rou_array![")?;
    ensure!(
        roots.len() == ROOT_COUNT,
        "expected {ROOT_COUNT} reverse roots, got {}",
        roots.len()
    );

    let poseidon_source = &source["risc0/zkp/src/core/hash/poseidon2/consts.rs"];
    require_all(
        poseidon_source,
        &[
            "pub const CELLS: usize = 24;",
            "pub const ROUNDS_HALF_FULL: usize = 4;",
            "pub const ROUNDS_PARTIAL: usize = 21;",
        ],
    )?;
    let full_round_constants = parse_numeric_macro(
        poseidon_source,
        "pub const ROUND_CONSTANTS:",
        "baby_bear_array![",
    )?;
    ensure!(
        full_round_constants.len() == 29 * 24,
        "expected 696 expanded Poseidon2 round constants, got {}",
        full_round_constants.len()
    );
    let mut round_constants = Vec::with_capacity(POSEIDON_ROUND_CONSTANTS);
    for round in 0..29 {
        if (4..25).contains(&round) {
            ensure!(
                full_round_constants[round * 24 + 1..(round + 1) * 24]
                    .iter()
                    .all(|&v| v == 0),
                "partial Poseidon2 round {round} has a nonzero unused slot"
            );
            round_constants.push(full_round_constants[round * 24]);
        } else {
            round_constants.extend_from_slice(&full_round_constants[round * 24..(round + 1) * 24]);
        }
    }
    ensure!(
        round_constants.len() == POSEIDON_ROUND_CONSTANTS,
        "sparse Poseidon2 constant count mismatch"
    );
    let internal_diagonal = parse_numeric_macro(
        poseidon_source,
        "pub const M_INT_DIAG_HZN:",
        "baby_bear_array![",
    )?;
    ensure!(
        internal_diagonal.len() == POSEIDON_DIAGONAL_CONSTANTS,
        "expected 24 Poseidon2 diagonal constants"
    );
    let poseidon_mod = &source["risc0/zkp/src/core/hash/poseidon2/mod.rs"];
    require_all(
        poseidon_mod,
        &[
            "pub const CELLS_RATE: usize = 16;",
            "pub const CELLS_OUT: usize = 8;",
            "let x2 = x * x;",
            "let x4 = x2 * x2;",
            "let x6 = x4 * x2;",
            "x6 * x",
        ],
    )?;

    let zkp = &source["risc0/zkp/src/lib.rs"];
    require_all(
        zkp,
        &[
            "pub const QUERIES: usize = 50;",
            "pub const INV_RATE: usize = 4;",
            "const FRI_FOLD_PO2: usize = 4;",
            "pub const FRI_FOLD: usize = 1 << FRI_FOLD_PO2;",
            "const FRI_MIN_DEGREE: usize = 256;",
        ],
    )?;
    let verifier = &source["risc0/zkp/src/verify/mod.rs"];
    require_all(
        verifier,
        &[
            "let remap = [0, 2, 1, 3];",
            "let three = F::Elem::from_u64(3);",
        ],
    )?;
    let adapter = &source["risc0/zkp/src/adapter.rs"];
    ensure!(
        adapter.contains("ProtocolInfo(*b\"RISC0_STARK:v1__\")"),
        "proof-system info string changed"
    );
    let recursion_info = &source["risc0/circuit/recursion/src/info.rs"];
    ensure!(
        recursion_info.contains("ProtocolInfo(*b\"RECURSION:rev1v1\")"),
        "recursion circuit info string changed"
    );
    let recursion_lib = &source["risc0/circuit/recursion/src/lib.rs"];
    require_all(
        recursion_lib,
        &[
            "pub const REGISTER_GROUP_ACCUM: usize = 0;",
            "pub const REGISTER_GROUP_CODE: usize = 1;",
            "pub const REGISTER_GROUP_DATA: usize = 2;",
        ],
    )?;
    require_all(
        recursion_info,
        &[
            "const OUTPUT_SIZE: usize = 32;",
            "const MIX_SIZE: usize = 20;",
        ],
    )?;

    let tap_source = &source["risc0/circuit/recursion/src/taps.rs"];
    require_all(
        tap_source,
        &[
            "combo_begin: &[0, 1, 3, 9, 15, 20]",
            "group_begin: &[0, 16, 39, 643]",
            "combos_count: 5",
            "reg_count: 163",
            "tot_combo_backs: 20",
        ],
    )?;
    let taps = parse_taps(tap_source)?;
    let operation_source = &source["risc0/circuit/recursion/src/poly_ext.rs"];
    ensure!(
        operation_source.contains("ret: 1228,"),
        "PolyExt return index changed"
    );
    let operations = parse_operations(operation_source)?;
    let artifact = ConstantsArtifact {
        upstream_commit: RISC0_COMMIT.to_owned(),
        baby_bear: BabyBearData {
            modulus: 2_013_265_921,
            extension_degree: 4,
            extension_beta: 11,
            max_root_po2: 27,
            reverse_roots: roots,
            extension_coefficient_remap: [0, 2, 1, 3],
            extension_challenge_scale: 3,
        },
        poseidon2: Poseidon2Data {
            cells: 24,
            rate: 16,
            output_cells: 8,
            rounds_half_full: 4,
            rounds_partial: 21,
            sbox_degree: 7,
            round_constants,
            internal_diagonal,
        },
        stark: StarkData {
            queries: 50,
            inverse_rate: 4,
            fri_fold: 16,
            fri_fold_po2: 4,
            fri_min_degree: 256,
            output_size: 32,
            mix_size: 20,
            check_size: 16,
        },
        protocol_info: ProtocolInfoData {
            proof_system: String::from_utf8(PROOF_SYSTEM_INFO.to_vec()).expect("ASCII constant"),
            circuit: String::from_utf8(CIRCUIT_INFO.to_vec()).expect("ASCII constant"),
        },
        taps: TapDataSet {
            group_sizes: [12, 23, 128],
            combos_count: 5,
            total_combo_backs: 20,
            records: taps,
        },
        poly_ext: PolyExtData {
            field_variables: FIELD_VARS_U16,
            mix_variables: MIX_VARS_U16,
            ret_mix_variable: RET_MIX_VAR_U16,
            histogram: histogram(&operations),
            operations,
        },
    };
    validate(&artifact)?;
    Ok(artifact)
}

pub fn encode(artifact: &ConstantsArtifact) -> Result<Vec<u8>> {
    validate(artifact)?;
    let mut out = Vec::with_capacity(ARTIFACT_BYTES);
    put_u32(&mut out, artifact.baby_bear.modulus);
    out.push(artifact.baby_bear.extension_degree);
    put_u32(&mut out, artifact.baby_bear.extension_beta);
    out.push(artifact.baby_bear.max_root_po2);
    out.extend_from_slice(&[
        artifact.poseidon2.cells,
        artifact.poseidon2.rate,
        artifact.poseidon2.output_cells,
        artifact.poseidon2.rounds_half_full,
        artifact.poseidon2.rounds_partial,
        artifact.poseidon2.sbox_degree,
    ]);
    put_u16(
        &mut out,
        u16::try_from(artifact.poseidon2.round_constants.len())
            .context("Poseidon2 round-constant count exceeds u16")?,
    );
    out.push(
        u8::try_from(artifact.poseidon2.internal_diagonal.len())
            .context("Poseidon2 diagonal count exceeds u8")?,
    );
    out.extend_from_slice(&[
        artifact.stark.queries,
        artifact.stark.inverse_rate,
        artifact.stark.fri_fold,
        artifact.stark.fri_fold_po2,
    ]);
    put_u16(&mut out, artifact.stark.fri_min_degree);
    out.extend_from_slice(&[
        artifact.stark.output_size,
        artifact.stark.mix_size,
        artifact.stark.check_size,
    ]);
    put_u16(
        &mut out,
        u16::try_from(artifact.taps.records.len()).context("tap count exceeds u16")?,
    );
    out.push(3);
    out.extend_from_slice(&artifact.taps.group_sizes);
    out.push(artifact.taps.combos_count);
    out.push(artifact.taps.total_combo_backs);
    put_u16(
        &mut out,
        u16::try_from(artifact.poly_ext.operations.len())
            .context("PolyExt operation count exceeds u16")?,
    );
    put_u16(&mut out, artifact.poly_ext.field_variables);
    put_u16(&mut out, artifact.poly_ext.mix_variables);
    put_u16(&mut out, artifact.poly_ext.ret_mix_variable);
    out.extend_from_slice(&artifact.baby_bear.extension_coefficient_remap);
    out.extend_from_slice(&[0, 1, 2]);
    out.push(16);
    out.push(16);
    out.push(5);
    out.push(artifact.baby_bear.extension_challenge_scale);
    out.extend_from_slice(artifact.protocol_info.proof_system.as_bytes());
    out.extend_from_slice(artifact.protocol_info.circuit.as_bytes());
    ensure!(
        out.len() == HEADER_BYTES,
        "internal header length is {}, expected {HEADER_BYTES}",
        out.len()
    );

    for &value in &artifact.baby_bear.reverse_roots {
        put_u32(&mut out, value);
    }
    for &value in &artifact.poseidon2.round_constants {
        put_u32(&mut out, value);
    }
    for &value in &artifact.poseidon2.internal_diagonal {
        put_u32(&mut out, value);
    }
    for tap in &artifact.taps.records {
        out.extend_from_slice(&[tap.group, tap.offset, tap.back, tap.combo, tap.skip]);
    }
    for op in &artifact.poly_ext.operations {
        encode_op(&mut out, op);
    }
    ensure!(
        out.len() == ARTIFACT_BYTES,
        "B2 encoding has {} bytes, expected {ARTIFACT_BYTES}",
        out.len()
    );
    Ok(out)
}

#[allow(clippy::too_many_lines)]
pub fn decode(bytes: &[u8]) -> Result<ConstantsArtifact> {
    ensure!(
        bytes.len() == ARTIFACT_BYTES,
        "B2 artifact has {} bytes, expected {ARTIFACT_BYTES}",
        bytes.len()
    );
    let mut cursor = Cursor::new(bytes);
    let modulus = cursor.u32()?;
    let extension_degree = cursor.u8()?;
    let extension_beta = cursor.u32()?;
    let max_root_po2 = cursor.u8()?;
    let cells = cursor.u8()?;
    let rate = cursor.u8()?;
    let output_cells = cursor.u8()?;
    let rounds_half_full = cursor.u8()?;
    let rounds_partial = cursor.u8()?;
    let sbox_degree = cursor.u8()?;
    let round_constant_count = usize::from(cursor.u16()?);
    let diagonal_count = usize::from(cursor.u8()?);
    let queries = cursor.u8()?;
    let inverse_rate = cursor.u8()?;
    let fri_fold = cursor.u8()?;
    let fri_fold_po2 = cursor.u8()?;
    let fri_min_degree = cursor.u16()?;
    let output_size = cursor.u8()?;
    let mix_size = cursor.u8()?;
    let check_size = cursor.u8()?;
    let tap_count = usize::from(cursor.u16()?);
    ensure!(cursor.u8()? == 3, "B2 group count is not 3");
    let group_sizes = [cursor.u8()?, cursor.u8()?, cursor.u8()?];
    let combos_count = cursor.u8()?;
    let total_combo_backs = cursor.u8()?;
    let op_count = usize::from(cursor.u16()?);
    let field_variables = cursor.u16()?;
    let mix_variables = cursor.u16()?;
    let ret_mix_variable = cursor.u16()?;
    let extension_coefficient_remap = [cursor.u8()?, cursor.u8()?, cursor.u8()?, cursor.u8()?];
    ensure!(
        [cursor.u8()?, cursor.u8()?, cursor.u8()?] == [0, 1, 2],
        "B2 group identifiers are not [0,1,2]"
    );
    let proof_info_len = usize::from(cursor.u8()?);
    let circuit_info_len = usize::from(cursor.u8()?);
    ensure!(cursor.u8()? == 5, "B2 tap record width is not {TAP_BYTES}");
    let extension_challenge_scale = cursor.u8()?;
    let proof_system = cursor.ascii(proof_info_len)?;
    let circuit = cursor.ascii(circuit_info_len)?;
    ensure!(
        cursor.position == HEADER_BYTES,
        "B2 header ended at {}, expected {HEADER_BYTES}",
        cursor.position
    );

    let reverse_roots = cursor.u32_vec(ROOT_COUNT)?;
    let round_constants = cursor.u32_vec(round_constant_count)?;
    let internal_diagonal = cursor.u32_vec(diagonal_count)?;
    let mut records = Vec::with_capacity(tap_count);
    for _ in 0..tap_count {
        records.push(Tap {
            group: cursor.u8()?,
            offset: cursor.u8()?,
            back: cursor.u8()?,
            combo: cursor.u8()?,
            skip: cursor.u8()?,
        });
    }
    let mut operations = Vec::with_capacity(op_count);
    let mut field_count = 0usize;
    let mut mix_count = 0usize;
    for _ in 0..op_count {
        let tag = cursor.u8()?;
        let op = match tag {
            0 => PolyExtOp::Const(cursor.u32()?),
            1 => PolyExtOp::ConstExt([cursor.u32()?, cursor.u32()?, cursor.u32()?, cursor.u32()?]),
            2 => PolyExtOp::Get(cursor.u16()?),
            3 => PolyExtOp::GetGlobal([cursor.u16()?, cursor.u16()?]),
            4 => PolyExtOp::Add([cursor.u16()?, cursor.u16()?]),
            5 => PolyExtOp::Sub([cursor.u16()?, cursor.u16()?]),
            6 => PolyExtOp::Mul([cursor.u16()?, cursor.u16()?]),
            7 => PolyExtOp::True,
            8 => PolyExtOp::AndEqz([cursor.u16()?, cursor.u16()?]),
            9 => PolyExtOp::AndCond([cursor.u16()?, cursor.u16()?, cursor.u16()?]),
            other => bail!("unknown B2 PolyExt opcode tag {other}"),
        };
        validate_op_references(&op, field_count, mix_count, tap_count, group_sizes)?;
        if is_mix(&op) {
            mix_count += 1;
        } else {
            field_count += 1;
        }
        operations.push(op);
    }
    ensure!(
        cursor.position == bytes.len(),
        "B2 decoder left {} trailing bytes",
        bytes.len() - cursor.position
    );
    let artifact = ConstantsArtifact {
        upstream_commit: RISC0_COMMIT.to_owned(),
        baby_bear: BabyBearData {
            modulus,
            extension_degree,
            extension_beta,
            max_root_po2,
            reverse_roots,
            extension_coefficient_remap,
            extension_challenge_scale,
        },
        poseidon2: Poseidon2Data {
            cells,
            rate,
            output_cells,
            rounds_half_full,
            rounds_partial,
            sbox_degree,
            round_constants,
            internal_diagonal,
        },
        stark: StarkData {
            queries,
            inverse_rate,
            fri_fold,
            fri_fold_po2,
            fri_min_degree,
            output_size,
            mix_size,
            check_size,
        },
        protocol_info: ProtocolInfoData {
            proof_system,
            circuit,
        },
        taps: TapDataSet {
            group_sizes,
            combos_count,
            total_combo_backs,
            records,
        },
        poly_ext: PolyExtData {
            field_variables,
            mix_variables,
            ret_mix_variable,
            histogram: histogram(&operations),
            operations,
        },
    };
    validate(&artifact)?;
    Ok(artifact)
}

/// Decode, re-encode, and authenticate the exact frozen B2 artifact bytes.
///
/// # Errors
///
/// Returns an error for any grammar violation, re-encoding mismatch, or
/// SHA-256 identity other than the frozen artifact.
pub fn verify_canonical(bytes: &[u8]) -> Result<ConstantsArtifact> {
    let decoded = decode(bytes)?;
    ensure!(
        encode(&decoded)? == bytes,
        "B2 decode/re-encode changed bytes"
    );
    let actual = hex::encode(Sha256::digest(bytes));
    ensure!(
        actual == ARTIFACT_SHA256,
        "B2 SHA-256 mismatch: expected {ARTIFACT_SHA256}, got {actual}"
    );
    Ok(decoded)
}

pub fn write_outputs(
    source_root: &Path,
    output_bin: &Path,
    output_json: &Path,
) -> Result<(String, String)> {
    let artifact = extract_from_pinned_sources(source_root)?;
    let bytes = encode(&artifact)?;
    let decoded = decode(&bytes)?;
    ensure!(
        decoded == artifact,
        "strict B2 decoder disagrees with source extraction"
    );
    ensure!(
        encode(&decoded)? == bytes,
        "strict B2 decode/re-encode changed bytes"
    );
    let binary_sha256 = hex::encode(Sha256::digest(&bytes));
    ensure!(
        binary_sha256 == ARTIFACT_SHA256,
        "generated B2 SHA-256 differs from the frozen artifact"
    );
    let json = serde_json::to_vec_pretty(&artifact).context("cannot serialize B2 JSON view")?;
    preflight_new_output(output_bin)?;
    preflight_new_output(output_json)?;
    write_new(output_bin, &bytes)?;
    write_new(output_json, &json)?;
    Ok((binary_sha256, hex::encode(Sha256::digest(&json))))
}

#[allow(clippy::too_many_lines)]
fn validate(artifact: &ConstantsArtifact) -> Result<()> {
    ensure!(
        artifact.upstream_commit == RISC0_COMMIT,
        "wrong upstream commit"
    );
    ensure!(
        artifact.baby_bear.modulus == 2_013_265_921,
        "wrong BabyBear modulus"
    );
    ensure!(
        artifact.baby_bear.extension_degree == 4 && artifact.baby_bear.extension_beta == 11,
        "wrong Ext4 definition"
    );
    ensure!(
        artifact.baby_bear.max_root_po2 == 27
            && artifact.baby_bear.reverse_roots.len() == ROOT_COUNT,
        "wrong reverse-root table shape"
    );
    ensure!(
        artifact
            .baby_bear
            .reverse_roots
            .iter()
            .all(|&v| v < artifact.baby_bear.modulus),
        "non-canonical BabyBear reverse root"
    );
    ensure!(
        artifact.baby_bear.extension_coefficient_remap == [0, 2, 1, 3],
        "wrong extension coefficient remap"
    );
    ensure!(
        artifact.baby_bear.extension_challenge_scale == 3,
        "wrong extension challenge scale"
    );
    ensure!(
        (
            artifact.poseidon2.cells,
            artifact.poseidon2.rate,
            artifact.poseidon2.output_cells
        ) == (24, 16, 8),
        "wrong Poseidon2 dimensions"
    );
    ensure!(
        (
            artifact.poseidon2.rounds_half_full,
            artifact.poseidon2.rounds_partial,
            artifact.poseidon2.sbox_degree
        ) == (4, 21, 7),
        "wrong Poseidon2 round parameters"
    );
    ensure!(
        artifact.poseidon2.round_constants.len() == POSEIDON_ROUND_CONSTANTS
            && artifact.poseidon2.internal_diagonal.len() == POSEIDON_DIAGONAL_CONSTANTS,
        "wrong Poseidon2 table shape"
    );
    ensure!(
        artifact
            .poseidon2
            .round_constants
            .iter()
            .chain(&artifact.poseidon2.internal_diagonal)
            .all(|&v| v < artifact.baby_bear.modulus),
        "non-canonical Poseidon2 field constant"
    );
    ensure!(
        (
            artifact.stark.queries,
            artifact.stark.inverse_rate,
            artifact.stark.fri_fold,
            artifact.stark.fri_fold_po2,
            artifact.stark.fri_min_degree
        ) == (50, 4, 16, 4, 256),
        "wrong FRI/STARK parameters"
    );
    ensure!(
        (
            artifact.stark.output_size,
            artifact.stark.mix_size,
            artifact.stark.check_size
        ) == (32, 20, 16),
        "wrong verifier dimensions"
    );
    ensure!(
        artifact.protocol_info.proof_system.as_bytes() == PROOF_SYSTEM_INFO
            && artifact.protocol_info.circuit.as_bytes() == CIRCUIT_INFO,
        "wrong protocol info preimage"
    );
    ensure!(
        artifact.taps.group_sizes == [12, 23, 128]
            && artifact.taps.combos_count == 5
            && artifact.taps.total_combo_backs == 20,
        "wrong TapSet metadata"
    );
    ensure!(artifact.taps.records.len() == TAP_COUNT, "wrong tap count");
    validate_taps(&artifact.taps)?;
    ensure!(
        artifact.poly_ext.operations.len() == OP_COUNT,
        "wrong PolyExt operation count"
    );
    ensure!(
        usize::from(artifact.poly_ext.field_variables) == FIELD_VARS
            && usize::from(artifact.poly_ext.mix_variables) == MIX_VARS
            && usize::from(artifact.poly_ext.ret_mix_variable) == RET_MIX_VAR,
        "wrong PolyExt variable census"
    );
    ensure!(
        artifact.poly_ext.mix_variables == artifact.poly_ext.ret_mix_variable + 1,
        "retMixVariable is not final mix variable"
    );
    let expected: BTreeMap<String, usize> = EXPECTED_HISTOGRAM
        .iter()
        .map(|(k, v)| ((*k).to_owned(), *v))
        .collect();
    let actual = histogram(&artifact.poly_ext.operations);
    ensure!(actual == expected, "wrong PolyExt opcode histogram");
    ensure!(
        artifact.poly_ext.histogram == actual,
        "stored PolyExt histogram differs from the instruction stream"
    );
    let mut fp = 0usize;
    let mut mix = 0usize;
    for op in &artifact.poly_ext.operations {
        validate_op_references(
            op,
            fp,
            mix,
            artifact.taps.records.len(),
            artifact.taps.group_sizes,
        )?;
        if is_mix(op) {
            mix += 1;
        } else {
            fp += 1;
        }
    }
    ensure!(
        fp == FIELD_VARS && mix == MIX_VARS,
        "PolyExt stack census differs from metadata"
    );
    Ok(())
}

fn validate_op_references(
    op: &PolyExtOp,
    fp: usize,
    mix: usize,
    taps: usize,
    groups: [u8; 3],
) -> Result<()> {
    let fp_ref = |v: u16| -> Result<()> {
        ensure!(
            usize::from(v) < fp,
            "PolyExt field reference {v} is not backward from {fp}"
        );
        Ok(())
    };
    let mix_ref = |v: u16| -> Result<()> {
        ensure!(
            usize::from(v) < mix,
            "PolyExt mix reference {v} is not backward from {mix}"
        );
        Ok(())
    };
    match op {
        PolyExtOp::Const(value) => ensure!(
            *value < 2_013_265_921,
            "PolyExt Const is not a reduced BabyBear value"
        ),
        PolyExtOp::ConstExt(values) => ensure!(
            values.iter().all(|value| *value < 2_013_265_921),
            "PolyExt ConstExt is not a reduced BabyBear value"
        ),
        PolyExtOp::True => {}
        PolyExtOp::Get(tap) => ensure!(
            usize::from(*tap) < taps,
            "PolyExt tap reference out of range"
        ),
        PolyExtOp::GetGlobal([group, offset]) => {
            ensure!(
                usize::from(*group) < 2,
                "PolyExt global group is not output or mix"
            );
            let bound = if *group == 0 { 32 } else { 20 };
            ensure!(
                usize::from(*offset) < bound,
                "PolyExt global offset out of range"
            );
            let _ = groups;
        }
        PolyExtOp::Add([a, b]) | PolyExtOp::Sub([a, b]) | PolyExtOp::Mul([a, b]) => {
            fp_ref(*a)?;
            fp_ref(*b)?;
        }
        PolyExtOp::AndEqz([chain, inner]) => {
            mix_ref(*chain)?;
            fp_ref(*inner)?;
        }
        PolyExtOp::AndCond([chain, cond, inner]) => {
            mix_ref(*chain)?;
            fp_ref(*cond)?;
            mix_ref(*inner)?;
        }
    }
    Ok(())
}

fn validate_taps(taps: &TapDataSet) -> Result<()> {
    let records = &taps.records;
    for (index, tap) in records.iter().enumerate() {
        ensure!(
            usize::from(tap.group) < taps.group_sizes.len(),
            "tap {index} group is out of range"
        );
        ensure!(
            tap.offset < taps.group_sizes[usize::from(tap.group)],
            "tap {index} offset is out of range"
        );
        ensure!(
            tap.combo < taps.combos_count,
            "tap {index} combo is out of range"
        );
        ensure!(tap.skip > 0, "tap {index} skip is zero");
    }

    let mut position = 0usize;
    let mut expected_registers = (0..taps.group_sizes.len()).flat_map(|group| {
        (0..taps.group_sizes[group])
            .map(move |offset| (u8::try_from(group).expect("three groups fit u8"), offset))
    });
    let mut combo_shapes = vec![None::<Vec<u8>>; usize::from(taps.combos_count)];
    while position < records.len() {
        let head = &records[position];
        let width = usize::from(head.skip);
        let end = position
            .checked_add(width)
            .context("tap register end overflows usize")?;
        ensure!(end <= records.len(), "tap register overruns the table");
        let expected = expected_registers
            .next()
            .context("tap table contains too many registers")?;
        ensure!(
            (head.group, head.offset) == expected,
            "tap register order differs at record {position}"
        );

        let mut backs = Vec::with_capacity(width);
        for tap in &records[position..end] {
            ensure!(
                tap.group == head.group
                    && tap.offset == head.offset
                    && tap.combo == head.combo
                    && tap.skip == head.skip,
                "tap register changes shape inside its skip run"
            );
            if let Some(previous) = backs.last() {
                ensure!(
                    tap.back > *previous,
                    "tap register backs are not strictly increasing"
                );
            }
            backs.push(tap.back);
        }
        let shape = &mut combo_shapes[usize::from(head.combo)];
        if let Some(previous) = shape {
            ensure!(
                *previous == backs,
                "tap registers disagree on one combo shape"
            );
        } else {
            *shape = Some(backs);
        }
        position = end;
    }
    ensure!(
        expected_registers.next().is_none(),
        "tap table omits one or more registers"
    );
    ensure!(
        position == records.len(),
        "tap register walk did not reach EOF"
    );
    ensure!(
        combo_shapes.iter().all(Option::is_some),
        "tap table omits one or more combos"
    );
    for right in 0..combo_shapes.len() {
        for left in 0..right {
            ensure!(
                combo_shapes[left] != combo_shapes[right],
                "two tap combos have the same back list"
            );
        }
    }
    let combo_back_count = combo_shapes
        .iter()
        .map(|shape| shape.as_ref().expect("all combo shapes checked").len())
        .sum::<usize>();
    ensure!(
        combo_back_count == usize::from(taps.total_combo_backs),
        "derived combo-back count differs from B2"
    );
    Ok(())
}

fn normalize_source_line_endings(bytes: &[u8], relative: &str) -> Result<Vec<u8>> {
    ensure!(
        !bytes.starts_with(&[0xef, 0xbb, 0xbf]),
        "pinned source has a UTF-8 BOM: {relative}"
    );
    ensure!(
        !bytes.contains(&0),
        "pinned source contains a NUL byte: {relative}"
    );
    let mut normalized = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'\r' {
            ensure!(
                bytes.get(index + 1) == Some(&b'\n'),
                "pinned source contains a lone CR byte: {relative}"
            );
            normalized.push(b'\n');
            index += 2;
        } else {
            normalized.push(bytes[index]);
            index += 1;
        }
    }
    Ok(normalized)
}

fn parse_taps(source: &str) -> Result<Vec<Tap>> {
    let block = between(source, "taps: &[", "    combo_taps:")?;
    let mut taps = Vec::new();
    for item in block.split("TapData {").skip(1) {
        let body = item
            .split_once('}')
            .context("unterminated TapData record")?
            .0;
        let mut values = BTreeMap::new();
        for line in body.lines() {
            if let Some((name, value)) = line.trim().trim_end_matches(',').split_once(':') {
                values.insert(name.trim(), parse_u8(value.trim())?);
            }
        }
        taps.push(Tap {
            group: required(&values, "group")?,
            offset: required(&values, "offset")?,
            back: required(&values, "back")?,
            combo: required(&values, "combo")?,
            skip: required(&values, "skip")?,
        });
    }
    ensure!(
        taps.len() == TAP_COUNT,
        "pinned TapSet has {} records, expected {TAP_COUNT}",
        taps.len()
    );
    Ok(taps)
}

fn parse_operations(source: &str) -> Result<Vec<PolyExtOp>> {
    let block = between(source, "block: &[", "],\n    ret:")?;
    let mut operations = Vec::new();
    for line in block.lines() {
        let code = line
            .split("//")
            .next()
            .unwrap_or("")
            .trim()
            .trim_end_matches(',')
            .trim();
        let Some(rest) = code.strip_prefix("PolyExtStep::") else {
            continue;
        };
        let (name, args) = if let Some((name, tail)) = rest.split_once('(') {
            (
                name,
                tail.strip_suffix(')')
                    .context("unterminated PolyExt operation")?,
            )
        } else {
            (rest, "")
        };
        let values: Vec<u32> = if args.is_empty() {
            Vec::new()
        } else {
            args.split(',')
                .map(|v| parse_u32(v.trim()))
                .collect::<Result<_>>()?
        };
        let u16v = |v: u32| u16::try_from(v).context("PolyExt reference exceeds u16");
        let op = match (name, values.as_slice()) {
            ("Const", [v]) => PolyExtOp::Const(*v),
            ("ConstExt", [a, b, c, d]) => PolyExtOp::ConstExt([*a, *b, *c, *d]),
            ("Get", [a]) => PolyExtOp::Get(u16v(*a)?),
            ("GetGlobal", [a, b]) => PolyExtOp::GetGlobal([u16v(*a)?, u16v(*b)?]),
            ("Add", [a, b]) => PolyExtOp::Add([u16v(*a)?, u16v(*b)?]),
            ("Sub", [a, b]) => PolyExtOp::Sub([u16v(*a)?, u16v(*b)?]),
            ("Mul", [a, b]) => PolyExtOp::Mul([u16v(*a)?, u16v(*b)?]),
            ("True", []) => PolyExtOp::True,
            ("AndEqz", [a, b]) => PolyExtOp::AndEqz([u16v(*a)?, u16v(*b)?]),
            ("AndCond", [a, b, c]) => PolyExtOp::AndCond([u16v(*a)?, u16v(*b)?, u16v(*c)?]),
            _ => bail!("unknown or malformed PolyExt operation: {code}"),
        };
        operations.push(op);
    }
    ensure!(
        operations.len() == OP_COUNT,
        "pinned PolyExt table has {} operations, expected {OP_COUNT}",
        operations.len()
    );
    Ok(operations)
}

fn parse_numeric_macro(source: &str, declaration: &str, macro_start: &str) -> Result<Vec<u32>> {
    let after_declaration = source
        .split_once(declaration)
        .with_context(|| format!("missing declaration {declaration}"))?
        .1;
    let after_macro = after_declaration
        .split_once(macro_start)
        .with_context(|| format!("missing macro {macro_start}"))?
        .1;
    let body = after_macro
        .split_once("];")
        .context("unterminated numeric macro")?
        .0;
    body.split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(parse_u32)
        .collect()
}

fn require_all(source: &str, needles: &[&str]) -> Result<()> {
    for needle in needles {
        ensure!(
            source.contains(needle),
            "pinned source no longer contains expected declaration: {needle}"
        );
    }
    Ok(())
}

fn between<'a>(source: &'a str, start: &str, end: &str) -> Result<&'a str> {
    let rest = source
        .split_once(start)
        .with_context(|| format!("missing source marker {start}"))?
        .1;
    Ok(rest
        .split_once(end)
        .with_context(|| format!("missing source marker {end}"))?
        .0)
}

fn parse_u32(value: &str) -> Result<u32> {
    let value = value.trim().replace('_', "");
    if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).context("invalid hex u32")
    } else {
        value.parse().context("invalid decimal u32")
    }
}

fn parse_u8(value: &str) -> Result<u8> {
    u8::try_from(parse_u32(value)?).context("value exceeds u8")
}

fn required(map: &BTreeMap<&str, u8>, name: &str) -> Result<u8> {
    map.get(name)
        .copied()
        .with_context(|| format!("missing TapData field {name}"))
}

fn histogram(operations: &[PolyExtOp]) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for op in operations {
        let name = match op {
            PolyExtOp::Const(_) => "Const",
            PolyExtOp::ConstExt(_) => "ConstExt",
            PolyExtOp::Get(_) => "Get",
            PolyExtOp::GetGlobal(_) => "GetGlobal",
            PolyExtOp::Add(_) => "Add",
            PolyExtOp::Sub(_) => "Sub",
            PolyExtOp::Mul(_) => "Mul",
            PolyExtOp::True => "True",
            PolyExtOp::AndEqz(_) => "AndEqz",
            PolyExtOp::AndCond(_) => "AndCond",
        };
        *out.entry(name.to_owned()).or_insert(0) += 1;
    }
    out.entry("ConstExt".to_owned()).or_insert(0);
    out
}

fn is_mix(op: &PolyExtOp) -> bool {
    matches!(
        op,
        PolyExtOp::True | PolyExtOp::AndEqz(_) | PolyExtOp::AndCond(_)
    )
}

fn encode_op(out: &mut Vec<u8>, op: &PolyExtOp) {
    match op {
        PolyExtOp::Const(v) => {
            out.push(0);
            put_u32(out, *v);
        }
        PolyExtOp::ConstExt(v) => {
            out.push(1);
            for x in v {
                put_u32(out, *x);
            }
        }
        PolyExtOp::Get(v) => {
            out.push(2);
            put_u16(out, *v);
        }
        PolyExtOp::GetGlobal(v) => {
            out.push(3);
            put_u16(out, v[0]);
            put_u16(out, v[1]);
        }
        PolyExtOp::Add(v) => {
            out.push(4);
            put_u16(out, v[0]);
            put_u16(out, v[1]);
        }
        PolyExtOp::Sub(v) => {
            out.push(5);
            put_u16(out, v[0]);
            put_u16(out, v[1]);
        }
        PolyExtOp::Mul(v) => {
            out.push(6);
            put_u16(out, v[0]);
            put_u16(out, v[1]);
        }
        PolyExtOp::True => out.push(7),
        PolyExtOp::AndEqz(v) => {
            out.push(8);
            put_u16(out, v[0]);
            put_u16(out, v[1]);
        }
        PolyExtOp::AndCond(v) => {
            out.push(9);
            put_u16(out, v[0]);
            put_u16(out, v[1]);
            put_u16(out, v[2]);
        }
    }
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options
        .open(path)
        .with_context(|| format!("refusing to overwrite {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("cannot write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("cannot sync {}", path.display()))?;
    Ok(())
}

fn preflight_new_output(path: &Path) -> Result<()> {
    ensure!(!path.exists(), "refusing to overwrite {}", path.display());
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
        let metadata =
            fs::metadata(parent).with_context(|| format!("cannot inspect {}", parent.display()))?;
        ensure!(
            metadata.is_dir(),
            "output parent is not a directory: {}",
            parent.display()
        );
    }
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(count)
            .context("B2 cursor overflow")?;
        ensure!(
            end <= self.bytes.len(),
            "unexpected EOF at byte {}",
            self.position
        );
        let out = &self.bytes[self.position..end];
        self.position = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("two bytes"),
        ))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }
    fn u32_vec(&mut self, count: usize) -> Result<Vec<u32>> {
        (0..count).map(|_| self.u32()).collect()
    }
    fn ascii(&mut self, count: usize) -> Result<String> {
        let bytes = self.take(count)?;
        ensure!(
            bytes.iter().all(u8::is_ascii),
            "non-ASCII protocol info at byte {}",
            self.position - count
        );
        String::from_utf8(bytes.to_vec()).context("invalid protocol info UTF-8")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const FROZEN_B2: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/constants.bin");

    fn source_root() -> Option<PathBuf> {
        std::env::var_os("EIP0045_RISC0_SOURCE").map(PathBuf::from)
    }

    #[test]
    fn fixed_layout_arithmetic_is_exact() {
        let op_bytes =
            284 * 5 + 669 * 3 + 52 * 5 + (4_061 + 1_385 + 4_679 + 1_076) * 5 + 1 + 152 * 7;
        assert_eq!(op_bytes, 60_757);
        assert_eq!(
            HEADER_BYTES
                + ROOT_COUNT * 4
                + POSEIDON_ROUND_CONSTANTS * 4
                + POSEIDON_DIAGONAL_CONSTANTS * 4
                + TAP_COUNT * TAP_BYTES
                + op_bytes,
            ARTIFACT_BYTES
        );
    }

    #[test]
    fn frozen_artifact_decodes_and_reserializes_without_source_access() {
        let decoded = verify_canonical(FROZEN_B2).unwrap();
        assert_eq!(encode(&decoded).unwrap(), FROZEN_B2);
        assert_eq!(FROZEN_B2.len(), ARTIFACT_BYTES);
        assert_eq!(hex::encode(Sha256::digest(FROZEN_B2)), ARTIFACT_SHA256);
    }

    #[test]
    fn pinned_sources_generate_decode_and_reserialize_exactly() {
        let Some(root) = source_root() else {
            return;
        };
        let extracted = extract_from_pinned_sources(&root).unwrap();
        let bytes = encode(&extracted).unwrap();
        assert_eq!(bytes.len(), ARTIFACT_BYTES);
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded, extracted);
        assert_eq!(encode(&decoded).unwrap(), bytes);
    }

    #[test]
    fn strict_decoder_rejects_length_and_reference_faults() {
        let mut bytes = FROZEN_B2.to_vec();
        assert!(decode(&bytes[..bytes.len() - 1]).is_err());
        bytes.push(0);
        assert!(decode(&bytes).is_err());

        let mut bytes = FROZEN_B2.to_vec();
        let operations_offset = HEADER_BYTES
            + ROOT_COUNT * 4
            + POSEIDON_ROUND_CONSTANTS * 4
            + POSEIDON_DIAGONAL_CONSTANTS * 4
            + TAP_COUNT * TAP_BYTES;
        assert_eq!(bytes[operations_offset], 0);
        let second_op = operations_offset + 5;
        bytes[second_op] = 4;
        bytes[second_op + 1..second_op + 5].copy_from_slice(&[1, 0, 0, 0]);
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn strict_decoder_rejects_noncanonical_constants_and_tap_shapes() {
        let operations_offset = HEADER_BYTES
            + ROOT_COUNT * 4
            + POSEIDON_ROUND_CONSTANTS * 4
            + POSEIDON_DIAGONAL_CONSTANTS * 4
            + TAP_COUNT * TAP_BYTES;
        assert_eq!(FROZEN_B2[operations_offset], 0);

        let mut noncanonical_const = FROZEN_B2.to_vec();
        noncanonical_const[operations_offset + 1..operations_offset + 5]
            .copy_from_slice(&2_013_265_921u32.to_le_bytes());
        assert!(decode(&noncanonical_const).is_err());

        let taps_offset = HEADER_BYTES
            + ROOT_COUNT * 4
            + POSEIDON_ROUND_CONSTANTS * 4
            + POSEIDON_DIAGONAL_CONSTANTS * 4;
        let mut malformed_taps = FROZEN_B2.to_vec();
        malformed_taps[taps_offset + 2] = 1;
        assert!(decode(&malformed_taps).is_err());
    }

    #[test]
    fn source_lock_normalizes_only_crlf_line_endings() {
        assert_eq!(
            normalize_source_line_endings(b"a\r\nb\n", "fixture").unwrap(),
            b"a\nb\n"
        );
        assert!(normalize_source_line_endings(b"a\rb", "fixture").is_err());
        assert!(normalize_source_line_endings(b"\xef\xbb\xbfsource", "fixture").is_err());
        assert!(normalize_source_line_endings(b"a\0b", "fixture").is_err());
    }
}
