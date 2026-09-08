//! Deterministic calibration records for the three recursive B4 families.
//!
//! Calibration is execution-only. The record binds one exact guest, statement,
//! family, workload, and source-segment sequence without claiming that the
//! monotone ranking convention proves a global minimum.

use std::{
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, Result, bail, ensure};
use eip_0045_reproduction::canonical::{
    canonical_json_bytes, validate_canonical_json_source, validate_lower_hex_exact,
};
use risc0_zkvm::compute_image_id;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Exact schema label for a recursive calibration report.
pub const RECURSIVE_CALIBRATION_SCHEMA: &str = "Eip0045B4RecursiveCalibrationV1";
/// Candidate-only lifecycle carried by every calibration report.
pub const RECURSIVE_CALIBRATION_LIFECYCLE: &str = "non-final-b4-recursive-candidate";
/// Fixed executor segment ceiling used to calibrate all recursive families.
pub const RECURSIVE_CALIBRATION_SEGMENT_LIMIT_PO2: u32 = 22;
/// Fixed workload used for the independent assumption receipt.
pub const RECURSIVE_ASSUMPTION_WORKLOAD_ITERATIONS: u32 = 0;
/// Maximum exact JCS byte length of one calibration report.
pub const RECURSIVE_CALIBRATION_MAX_BYTES: usize = 4096;

const MIN_SOURCE_SEGMENT_PO2: u32 = 15;
const MAX_SOURCE_SEGMENT_PO2: u32 = 22;
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Closed host execution recipes; neither variant changes the proof profile.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RecursiveCalibrationRecipe {
    /// Historical recipe and the default of every existing API.
    #[default]
    Fixed22,
    /// Lower execution ceiling for exactly the two two-segment Join families.
    Join21,
}

impl RecursiveCalibrationRecipe {
    /// Executor ceiling selected by this closed recipe.
    pub const fn segment_limit_po2(self) -> u32 {
        match self { Self::Fixed22 => RECURSIVE_CALIBRATION_SEGMENT_LIMIT_PO2, Self::Join21 => 21 }
    }

    /// Reject a recipe/family mismatch before observing or proving.
    pub fn validate_family(self, family: &str) -> Result<()> {
        expected_segment_count(family)?;
        ensure!(self == Self::Fixed22 || matches!(family, "terminal-join" | "resolve-then-join"),
            "Join21 permits only terminal-join and resolve-then-join");
        Ok(())
    }

    fn validate_ceiling(self, segments: &[u32]) -> Result<()> {
        ensure!(segments.iter().all(|po2| *po2 <= self.segment_limit_po2()),
            "recursive calibration source segment exceeds its declared recipe ceiling");
        Ok(())
    }
}

impl std::str::FromStr for RecursiveCalibrationRecipe {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "fixed22" => Ok(Self::Fixed22),
            "join21" => Ok(Self::Join21),
            _ => bail!("unknown recursive calibration recipe; expected fixed22 or join21"),
        }
    }
}

/// Exact canonical output of one deterministic recursive-family calibration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecursiveCalibrationReport {
    /// Closed report schema.
    pub schema: String,
    /// Candidate-only lifecycle; this report is not consensus provenance.
    pub lifecycle: String,
    /// SHA-256 of the exact guest ELF.
    pub elf_sha256: String,
    /// RISC Zero image ID recomputed and checked against that ELF by this module.
    pub image_id: String,
    /// SHA-256 of the exact `ErgoStatementV1` bytes.
    pub statement_sha256: String,
    /// One of the three closed recursive-family labels.
    pub family: String,
    /// Fixed family-calibration executor ceiling.
    pub segment_limit_po2: u32,
    /// Workload selected by canonical exponential bracketing and binary ranking.
    pub workload_iterations: u32,
    /// Fixed workload for an independent assumption receipt.
    pub assumption_workload_iterations: u32,
    /// Exact source-segment exponent sequence observed twice at the selected workload.
    pub segment_po2: Vec<u32>,
}

impl RecursiveCalibrationReport {
    /// Parse an exact RFC 8785 report and validate its closed static shape.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, non-canonical, trailing, duplicate, or
    /// unknown JSON, or for any invalid schema, identity, family, constant, or
    /// source-segment sequence.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        Self::from_canonical_jcs_with_recipe(source, RecursiveCalibrationRecipe::Fixed22)
    }

    /// Parse with an explicit closed recipe; the report cannot select it.
    pub fn from_canonical_jcs_with_recipe(source: &[u8], recipe: RecursiveCalibrationRecipe) -> Result<Self> {
        ensure!(
            source.len() <= RECURSIVE_CALIBRATION_MAX_BYTES,
            "recursive calibration report exceeds its byte limit"
        );
        let value = validate_canonical_json_source(source)
            .context("recursive calibration report is not exact RFC 8785 JCS")?;
        let report: Self =
            serde_json::from_value(value).context("invalid recursive calibration report shape")?;
        report.validate_static_with_recipe(recipe)?;
        ensure!(
            report.to_canonical_jcs_with_recipe(recipe)? == source,
            "recursive calibration report does not round-trip byte-exactly"
        );
        Ok(report)
    }

    /// Encode this report as exact RFC 8785 JCS.
    ///
    /// # Errors
    ///
    /// Returns an error if validation, serialization, or the byte bound fails.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.to_canonical_jcs_with_recipe(RecursiveCalibrationRecipe::Fixed22)
    }

    /// Encode using an explicitly selected recipe, retaining the V1 wire shape.
    pub fn to_canonical_jcs_with_recipe(&self, recipe: RecursiveCalibrationRecipe) -> Result<Vec<u8>> {
        self.validate_static_with_recipe(recipe)?;
        let value =
            serde_json::to_value(self).context("cannot serialize recursive calibration report")?;
        let bytes = canonical_json_bytes(&value)
            .context("cannot canonicalize recursive calibration report")?;
        ensure!(
            bytes.len() <= RECURSIVE_CALIBRATION_MAX_BYTES,
            "recursive calibration report exceeds its byte limit"
        );
        Ok(bytes)
    }

    fn validate_static_with_recipe(&self, recipe: RecursiveCalibrationRecipe) -> Result<()> {
        recipe.validate_family(&self.family)?;
        ensure!(
            self.schema == RECURSIVE_CALIBRATION_SCHEMA,
            "wrong recursive calibration schema"
        );
        ensure!(
            self.lifecycle == RECURSIVE_CALIBRATION_LIFECYCLE,
            "wrong recursive calibration lifecycle"
        );
        validate_lower_hex_exact(&self.elf_sha256, 32)
            .context("invalid recursive calibration ELF SHA-256")?;
        validate_lower_hex_exact(&self.image_id, 32)
            .context("invalid recursive calibration image ID")?;
        validate_lower_hex_exact(&self.statement_sha256, 32)
            .context("invalid recursive calibration statement SHA-256")?;
        let expected_count = expected_segment_count(&self.family)?;
        ensure!(
            self.segment_limit_po2 == recipe.segment_limit_po2(),
            "recursive calibration segment ceiling is not the fixed B4 value"
        );
        ensure!(
            self.assumption_workload_iterations == RECURSIVE_ASSUMPTION_WORKLOAD_ITERATIONS,
            "recursive calibration assumption workload is not fixed at zero"
        );
        recipe.validate_ceiling(&self.segment_po2)?;
        validate_exact_segment_sequence(&self.segment_po2, expected_count)
    }
}

/// Derive one report using the canonical family-cardinality ranking procedure.
///
/// The callback must execute the exact guest at the supplied workload and the
/// fixed [`RECURSIVE_CALIBRATION_SEGMENT_LIMIT_PO2`] ceiling. The selected
/// workload is executed once during ranking and once more; differing segment
/// sequences are rejected as nondeterministic.
///
/// # Errors
///
/// Returns an error for an unknown family, an invalid segment, a jump beyond
/// the family's exact cardinality, exhausted workload space, nondeterministic
/// replay, or any execution error returned by `observe`.
pub fn derive_recursive_calibration<F>(
    elf: &[u8],
    image_id: &[u8; 32],
    statement: &[u8],
    family: &str,
    observe: F,
) -> Result<RecursiveCalibrationReport>
where
    F: FnMut(u32) -> Result<Vec<u32>>,
{
    validate_image_id_binding(elf, image_id)?;
    derive_recursive_calibration_bound(elf, image_id, statement, family, observe)
}

/// Derive using an explicit recipe and the same complete ranking/replay algorithm.
pub fn derive_recursive_calibration_with_recipe<F>(
    elf: &[u8], image_id: &[u8; 32], statement: &[u8], family: &str,
    recipe: RecursiveCalibrationRecipe, observe: F,
) -> Result<RecursiveCalibrationReport>
where F: FnMut(u32) -> Result<Vec<u32>>,
{
    recipe.validate_family(family)?;
    validate_image_id_binding(elf, image_id)?;
    derive_recursive_calibration_bound_with_recipe(elf, image_id, statement, family, recipe, observe)
}

fn derive_recursive_calibration_bound<F>(
    elf: &[u8],
    image_id: &[u8; 32],
    statement: &[u8],
    family: &str,
    observe: F,
) -> Result<RecursiveCalibrationReport>
where
    F: FnMut(u32) -> Result<Vec<u32>>,
{
    derive_recursive_calibration_bound_with_recipe(elf, image_id, statement, family, RecursiveCalibrationRecipe::Fixed22, observe)
}

fn derive_recursive_calibration_bound_with_recipe<F>(
    elf: &[u8],
    image_id: &[u8; 32],
    statement: &[u8],
    family: &str,
    recipe: RecursiveCalibrationRecipe,
    mut observe: F,
) -> Result<RecursiveCalibrationReport>
where
    F: FnMut(u32) -> Result<Vec<u32>>,
{
    recipe.validate_family(family)?;
    let mut observe = |workload| {
        let segments = observe(workload)?;
        // This runs on every ranking observation and on the selected replay.
        if recipe == RecursiveCalibrationRecipe::Join21 { recipe.validate_ceiling(&segments)?; }
        Ok(segments)
    };
    let expected_count = expected_segment_count(family)?;
    let (workload_iterations, selected) = select_recursive_workload(expected_count, &mut observe)?;
    let replay = observe(workload_iterations).with_context(|| {
        format!("failed to replay selected recursive workload {workload_iterations}")
    })?;
    validate_exact_segment_sequence(&replay, expected_count)?;
    ensure!(
        replay == selected,
        "selected recursive workload produced a nondeterministic segment sequence"
    );

    let report = RecursiveCalibrationReport {
        schema: RECURSIVE_CALIBRATION_SCHEMA.to_owned(),
        lifecycle: RECURSIVE_CALIBRATION_LIFECYCLE.to_owned(),
        elf_sha256: sha256_hex(elf),
        image_id: hex::encode(image_id),
        statement_sha256: sha256_hex(statement),
        family: family.to_owned(),
        segment_limit_po2: recipe.segment_limit_po2(),
        workload_iterations,
        assumption_workload_iterations: RECURSIVE_ASSUMPTION_WORKLOAD_ITERATIONS,
        segment_po2: selected,
    };
    report.validate_static_with_recipe(recipe)?;
    Ok(report)
}

/// Authenticate and rederive a parsed report before recursive proving.
///
/// # Errors
///
/// Returns an error if any supplied identity or expected family differs, or if
/// a fresh complete calibration does not reproduce the report exactly.
pub fn verify_recursive_calibration<F>(
    report: &RecursiveCalibrationReport,
    elf: &[u8],
    image_id: &[u8; 32],
    statement: &[u8],
    expected_family: &str,
    observe: F,
) -> Result<()>
where
    F: FnMut(u32) -> Result<Vec<u32>>,
{
    validate_image_id_binding(elf, image_id)?;
    verify_recursive_calibration_bound(report, elf, image_id, statement, expected_family, observe)
}

/// Authenticate and fully rederive with an explicit closed recipe.
pub fn verify_recursive_calibration_with_recipe<F>(
    report: &RecursiveCalibrationReport, elf: &[u8], image_id: &[u8; 32],
    statement: &[u8], expected_family: &str, recipe: RecursiveCalibrationRecipe, observe: F,
) -> Result<()>
where F: FnMut(u32) -> Result<Vec<u32>>,
{
    recipe.validate_family(expected_family)?;
    validate_image_id_binding(elf, image_id)?;
    verify_recursive_calibration_bound_with_recipe(report, elf, image_id, statement, expected_family, recipe, observe)
}

fn verify_recursive_calibration_bound<F>(
    report: &RecursiveCalibrationReport,
    elf: &[u8],
    image_id: &[u8; 32],
    statement: &[u8],
    expected_family: &str,
    observe: F,
) -> Result<()>
where
    F: FnMut(u32) -> Result<Vec<u32>>,
{
    verify_recursive_calibration_bound_with_recipe(report, elf, image_id, statement, expected_family, RecursiveCalibrationRecipe::Fixed22, observe)
}

fn verify_recursive_calibration_bound_with_recipe<F>(
    report: &RecursiveCalibrationReport,
    elf: &[u8],
    image_id: &[u8; 32],
    statement: &[u8],
    expected_family: &str,
    recipe: RecursiveCalibrationRecipe,
    observe: F,
) -> Result<()>
where
    F: FnMut(u32) -> Result<Vec<u32>>,
{
    report.validate_static_with_recipe(recipe)?;
    ensure!(
        report.family == expected_family,
        "recursive calibration family differs from the requested proof family"
    );
    ensure!(
        report.elf_sha256 == sha256_hex(elf),
        "recursive calibration ELF SHA-256 differs"
    );
    ensure!(
        report.image_id == hex::encode(image_id),
        "recursive calibration image ID differs"
    );
    ensure!(
        report.statement_sha256 == sha256_hex(statement),
        "recursive calibration statement SHA-256 differs"
    );
    let derived =
        derive_recursive_calibration_bound_with_recipe(elf, image_id, statement, expected_family, recipe, observe)?;
    ensure!(
        &derived == report,
        "recursive calibration report differs from deterministic rederivation"
    );
    Ok(())
}

/// Create one calibration file without replacing any existing filesystem entry.
///
/// # Errors
///
/// Returns an error if the report is invalid, the path already exists, or the
/// new file cannot be written and synchronized.
pub fn create_recursive_calibration_file(
    path: &Path,
    report: &RecursiveCalibrationReport,
) -> Result<()> {
    create_recursive_calibration_file_with_recipe(path, report, RecursiveCalibrationRecipe::Fixed22)
}

/// Create a report using an explicit recipe without replacing any entry.
pub fn create_recursive_calibration_file_with_recipe(
    path: &Path, report: &RecursiveCalibrationReport, recipe: RecursiveCalibrationRecipe,
) -> Result<()> {
    let bytes = report.to_canonical_jcs_with_recipe(recipe)?;
    create_atomic_candidate_file(path, &bytes, "recursive calibration")
}

/// Publish exact candidate bytes without replacement through a synchronized
/// same-directory temporary file and an atomic create-only hard link.
///
/// If publication fails before the final link exists, the helper removes the
/// temporary file or returns a combined write/cleanup error. If a failure is
/// reported after the final link exists, the error explicitly identifies the
/// published final path and any remaining linked temporary path.
///
/// # Errors
///
/// Returns an error for an unsafe or occupied destination, write or sync
/// failure, failed atomic publication, or incomplete post-publication cleanup.
pub fn create_atomic_candidate_file(path: &Path, bytes: &[u8], label: &str) -> Result<()> {
    preflight_atomic_candidate_file(path, label)?;
    let parent = output_parent(path);
    let (temporary_path, mut file) = create_temporary_file(path)?;
    if let Err(error) = file.write_all(bytes) {
        drop(file);
        return remove_failed_temporary(&temporary_path, error).with_context(|| {
            format!(
                "cannot write temporary {label} file {}",
                temporary_path.display()
            )
        });
    }
    if let Err(error) = file.sync_all() {
        drop(file);
        return remove_failed_temporary(&temporary_path, error).with_context(|| {
            format!(
                "cannot sync temporary {label} file {}",
                temporary_path.display()
            )
        });
    }
    drop(file);
    if let Err(error) = fs::hard_link(&temporary_path, path) {
        return remove_failed_temporary(&temporary_path, error).with_context(|| {
            format!(
                "cannot atomically publish create-only {label} file {}",
                path.display()
            )
        });
    }
    sync_directory(parent).with_context(|| {
        format!(
            "{label} final link exists at {}, but its parent directory could not be synchronized",
            path.display()
        )
    })?;
    fs::remove_file(&temporary_path).with_context(|| {
        format!(
            "{label} final file is published at {}, but linked temporary file {} could not be removed",
            path.display(),
            temporary_path.display()
        )
    })?;
    sync_directory(parent).with_context(|| {
        format!(
            "{label} final file is published at {}, but temporary-link removal could not be synchronized",
            path.display()
        )
    })
}

fn remove_failed_temporary(path: &Path, source: std::io::Error) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Err(source.into()),
        Err(cleanup) => Err(anyhow::anyhow!(
            "{source}; additionally cannot remove temporary file {}: {cleanup}",
            path.display()
        )),
    }
}

/// Reject an occupied or structurally unsafe calibration destination before
/// performing any guest execution.
///
/// # Errors
///
/// Returns an error unless the parent is an ordinary directory and the final
/// path is absent, including as a dangling link.
pub fn preflight_recursive_calibration_file(path: &Path) -> Result<()> {
    preflight_atomic_candidate_file(path, "recursive calibration")
}

fn preflight_atomic_candidate_file(path: &Path, label: &str) -> Result<()> {
    let parent = output_parent(path);
    let parent_metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("cannot inspect {label} output parent {}", parent.display()))?;
    ensure!(
        parent_metadata.file_type().is_dir() && !is_reparse_point(&parent_metadata),
        "{label} output parent is not an ordinary directory: {}",
        parent.display()
    );
    match fs::symlink_metadata(path) {
        Ok(_) => bail!(
            "refusing to replace existing {label} path {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("cannot inspect {label} destination {}", path.display())),
    }
}

fn create_temporary_file(path: &Path) -> Result<(std::path::PathBuf, File)> {
    let parent = output_parent(path);
    let name = path
        .file_name()
        .context("recursive calibration output path has no file name")?;
    for _ in 0..128 {
        let ordinal = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = name.to_os_string();
        temporary_name.push(format!(".candidate-tmp-{}-{ordinal}", std::process::id()));
        let temporary_path = parent.join(temporary_name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
        {
            Ok(file) => return Ok((temporary_path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "cannot create recursive calibration temporary file {}",
                        temporary_path.display()
                    )
                });
            }
        }
    }
    bail!("cannot allocate a unique recursive calibration temporary file")
}

fn validate_image_id_binding(elf: &[u8], image_id: &[u8; 32]) -> Result<()> {
    let computed =
        compute_image_id(elf).context("cannot compute recursive calibration image ID")?;
    ensure!(
        computed.as_bytes() == image_id,
        "recursive calibration image ID does not match the supplied ELF"
    );
    Ok(())
}

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("cannot open calibration directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("cannot sync calibration directory {}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("cannot re-inspect calibration directory {}", path.display()))?;
    ensure!(
        metadata.is_dir(),
        "calibration output parent stopped being a directory: {}",
        path.display()
    );
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn select_recursive_workload<F>(expected_count: usize, observe: &mut F) -> Result<(u32, Vec<u32>)>
where
    F: FnMut(u32) -> Result<Vec<u32>>,
{
    let (zero, zero_rank) = observe_checked(observe, 0, expected_count)?;
    if zero_rank == CalibrationObservationRank::Exact {
        return Ok((0, zero));
    }

    let mut below = 0_u32;
    let mut high = 1_u32;
    let mut upper = loop {
        let (observation, rank) = observe_checked(observe, high, expected_count)?;
        if rank == CalibrationObservationRank::Exact {
            break observation;
        }
        below = high;
        if high == u32::MAX {
            bail!("u32 workload range exhausted below the required recursive segment count");
        }
        high = high.saturating_mul(2).max(high + 1);
    };

    while below + 1 < high {
        let middle = below + (high - below) / 2;
        let (observation, rank) = observe_checked(observe, middle, expected_count)?;
        match rank {
            CalibrationObservationRank::Below => below = middle,
            CalibrationObservationRank::Exact => {
                high = middle;
                upper = observation;
            }
        }
    }
    validate_exact_segment_sequence(&upper, expected_count)?;
    Ok((high, upper))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CalibrationObservationRank {
    Below,
    Exact,
}

fn observe_checked<F>(
    observe: &mut F,
    workload: u32,
    expected_count: usize,
) -> Result<(Vec<u32>, CalibrationObservationRank)>
where
    F: FnMut(u32) -> Result<Vec<u32>>,
{
    let observation = observe(workload)
        .with_context(|| format!("failed to observe recursive workload {workload}"))?;
    let rank = classify_observation(&observation, expected_count)?;
    Ok((observation, rank))
}

fn classify_observation(
    segment_po2: &[u32],
    expected_count: usize,
) -> Result<CalibrationObservationRank> {
    ensure!(
        !segment_po2.is_empty(),
        "recursive calibration execution emitted no source segments"
    );
    ensure!(
        segment_po2.len() <= expected_count,
        "recursive calibration jumped beyond the exact expected segment count"
    );
    for (index, po2) in segment_po2.iter().copied().enumerate() {
        ensure!(
            po2 <= MAX_SOURCE_SEGMENT_PO2,
            "recursive calibration emitted source segment po2 {po2} above 22"
        );
        if po2 < MIN_SOURCE_SEGMENT_PO2 {
            ensure!(
                index + 1 == segment_po2.len(),
                "recursive calibration emitted undersized non-final source segment po2 {po2}"
            );
            return Ok(CalibrationObservationRank::Below);
        }
    }
    Ok(if segment_po2.len() == expected_count {
        CalibrationObservationRank::Exact
    } else {
        CalibrationObservationRank::Below
    })
}

fn validate_exact_segment_sequence(segment_po2: &[u32], expected_count: usize) -> Result<()> {
    ensure!(
        classify_observation(segment_po2, expected_count)? == CalibrationObservationRank::Exact,
        "recursive calibration segment sequence has the wrong family cardinality"
    );
    Ok(())
}

fn expected_segment_count(family: &str) -> Result<usize> {
    match family {
        "terminal-resolve" => Ok(1),
        "terminal-join" | "resolve-then-join" => Ok(2),
        _ => bail!(
            "unknown recursive family {family:?}; expected terminal-join, terminal-resolve, or resolve-then-join"
        ),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use serde_json::json;

    use super::*;

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn derive_with<F>(family: &str, observe: F) -> Result<RecursiveCalibrationReport>
    where
        F: FnMut(u32) -> Result<Vec<u32>>,
    {
        derive_recursive_calibration_bound(b"elf", &[7; 32], b"statement", family, observe)
    }

    fn fixture() -> RecursiveCalibrationReport {
        derive_with("terminal-join", |workload| {
            Ok(if workload < 5 { vec![20] } else { vec![22, 19] })
        })
        .unwrap()
    }

    #[test]
    fn fixed22_jcs_and_legacy_api_remain_byte_exact() {
        let report = fixture();
        let expected = concat!(
            "{\"assumptionWorkloadIterations\":0,\"elfSha256\":\"780d84b20d7ae7e6292919399348bdbf96025270136198083fc8a4da398b5ca9\",",
            "\"family\":\"terminal-join\",\"imageId\":\"0707070707070707070707070707070707070707070707070707070707070707\",",
            "\"lifecycle\":\"non-final-b4-recursive-candidate\",\"schema\":\"Eip0045B4RecursiveCalibrationV1\",",
            "\"segmentLimitPo2\":22,\"segmentPo2\":[22,19],\"statementSha256\":\"b111c6e1d318f203063e5c16bab43c108326af0aa2f7b65760c95547a43dbe52\",\"workloadIterations\":5}"
        ).as_bytes();
        assert_eq!(report.to_canonical_jcs().unwrap(), expected);
        assert_eq!(report.to_canonical_jcs_with_recipe(RecursiveCalibrationRecipe::Fixed22).unwrap(), expected);
        assert_eq!(RecursiveCalibrationReport::from_canonical_jcs(expected).unwrap(), report);
        assert!(RecursiveCalibrationReport::from_canonical_jcs_with_recipe(expected, RecursiveCalibrationRecipe::Join21).is_err());
    }

    fn join21_fixture(family: &str) -> RecursiveCalibrationReport {
        derive_recursive_calibration_bound_with_recipe(b"elf", &[7; 32], b"statement", family,
            RecursiveCalibrationRecipe::Join21,
            |workload| Ok(if workload < 5 { vec![20] } else { vec![21, 19] })).unwrap()
    }

    #[test]
    fn join21_full_ranking_replay_and_explicit_codec_are_closed() {
        for family in ["terminal-join", "resolve-then-join"] {
            let mut calls = Vec::new();
            let report = derive_recursive_calibration_bound_with_recipe(b"elf", &[7; 32], b"statement", family,
                RecursiveCalibrationRecipe::Join21, |workload| {
                    calls.push(workload);
                    Ok(if workload < 5 { vec![20] } else { vec![21, 19] })
                }).unwrap();
            assert_eq!(calls, [0, 1, 2, 4, 8, 6, 5, 5]);
            assert_eq!(report.segment_limit_po2, 21);
            let bytes = report.to_canonical_jcs_with_recipe(RecursiveCalibrationRecipe::Join21).unwrap();
            assert_eq!(RecursiveCalibrationReport::from_canonical_jcs_with_recipe(&bytes, RecursiveCalibrationRecipe::Join21).unwrap(), report);
            assert!(report.to_canonical_jcs().is_err());
            assert!(RecursiveCalibrationReport::from_canonical_jcs(&bytes).is_err());
            calls.clear();
            verify_recursive_calibration_bound_with_recipe(&report, b"elf", &[7; 32], b"statement", family,
                RecursiveCalibrationRecipe::Join21, |workload| {
                    calls.push(workload);
                    Ok(if workload < 5 { vec![20] } else { vec![21, 19] })
                }).unwrap();
            assert_eq!(calls, [0, 1, 2, 4, 8, 6, 5, 5]);
        }
    }

    #[test]
    fn join21_rejects_wrong_family_and_every_over_ceiling_observation() {
        let mut calls = 0;
        assert!(derive_recursive_calibration_bound_with_recipe(b"elf", &[7; 32], b"statement", "terminal-resolve",
            RecursiveCalibrationRecipe::Join21, |_| { calls += 1; Ok(vec![21]) }).is_err());
        assert_eq!(calls, 0);
        for segments in [vec![22], vec![22, 14], vec![21, 22]] {
            let error = derive_recursive_calibration_bound_with_recipe(b"elf", &[7; 32], b"statement", "terminal-join",
                RecursiveCalibrationRecipe::Join21, |_| Ok(segments.clone())).unwrap_err();
            assert_eq!(error.root_cause().to_string(), "recursive calibration source segment exceeds its declared recipe ceiling");
        }
        let mut calls = 0;
        assert!(derive_recursive_calibration_bound_with_recipe(b"elf", &[7; 32], b"statement", "terminal-join",
            RecursiveCalibrationRecipe::Join21, |_| {
                calls += 1;
                Ok(if calls == 1 { vec![21, 19] } else { vec![21, 20] })
            }).unwrap_err().to_string().contains("nondeterministic"));
        assert_eq!(calls, 2);
    }

    #[test]
    fn join21_report_fields_are_bound_before_full_rederivation() {
        let positive = join21_fixture("terminal-join");
        for (field, replacement) in [
            ("segmentLimitPo2", json!(22)), ("segmentPo2", json!([22, 19])),
            ("family", json!("terminal-resolve")), ("assumptionWorkloadIterations", json!(1)),
            ("elfSha256", json!("00".repeat(32))), ("imageId", json!("00".repeat(32))),
            ("statementSha256", json!("00".repeat(32))), ("workloadIterations", json!(6)),
            ("segmentPo2", json!([21, 20])),
        ] {
            verify_recursive_calibration_bound_with_recipe(&positive, b"elf", &[7; 32], b"statement", "terminal-join",
                RecursiveCalibrationRecipe::Join21, |w| Ok(if w < 5 { vec![20] } else { vec![21, 19] })).unwrap();
            let mut value = serde_json::to_value(&positive).unwrap();
            value[field] = replacement;
            let altered: RecursiveCalibrationReport = serde_json::from_value(value).unwrap();
            assert!(verify_recursive_calibration_bound_with_recipe(&altered, b"elf", &[7; 32], b"statement", "terminal-join",
                RecursiveCalibrationRecipe::Join21, |w| Ok(if w < 5 { vec![20] } else { vec![21, 19] })).is_err(), "{field}");
        }
    }

    #[test]
    fn zero_workload_is_canonical_for_one_segment_family() {
        let mut calls = Vec::new();
        let report = derive_with("terminal-resolve", |workload| {
            calls.push(workload);
            Ok(vec![18])
        })
        .unwrap();
        assert_eq!(report.workload_iterations, 0);
        assert_eq!(report.segment_po2, vec![18]);
        assert_eq!(calls, vec![0, 0]);
    }

    #[test]
    fn exponential_bracket_and_binary_ranking_are_exact() {
        let mut calls = Vec::new();
        let report = derive_with("terminal-join", |workload| {
            calls.push(workload);
            Ok(if workload < 5 { vec![21] } else { vec![22, 19] })
        })
        .unwrap();
        assert_eq!(report.workload_iterations, 5);
        assert_eq!(report.segment_po2, vec![22, 19]);
        assert_eq!(calls, vec![0, 1, 2, 4, 8, 6, 5, 5]);
    }

    #[test]
    fn undersized_final_segment_is_ranked_below_the_first_valid_sequence() {
        let mut calls = Vec::new();
        let report = derive_with("terminal-join", |workload| {
            calls.push(workload);
            Ok(match workload {
                0..=4 => vec![22],
                5..=6 => vec![22, 14],
                _ => vec![22, 15],
            })
        })
        .unwrap();
        assert_eq!(report.workload_iterations, 7);
        assert_eq!(report.segment_po2, vec![22, 15]);
        assert_eq!(calls, vec![0, 1, 2, 4, 8, 6, 7, 7]);
    }

    #[test]
    fn selected_replay_must_remain_profile_valid() {
        let mut calls = 0;
        let error = derive_with("terminal-resolve", |_| {
            calls += 1;
            Ok(if calls == 1 { vec![15] } else { vec![14] })
        })
        .unwrap_err();
        assert!(
            error.to_string().contains("wrong family cardinality"),
            "{error:#}"
        );
        assert_eq!(calls, 2);
    }

    #[test]
    fn jumps_invalid_exponents_and_nondeterminism_are_rejected() {
        assert!(
            derive_with("terminal-join", |_| Ok(vec![20, 20, 20]))
                .unwrap_err()
                .to_string()
                .contains("jumped beyond")
        );
        assert!(
            derive_with("terminal-join", |_| Ok(vec![14, 15]))
                .unwrap_err()
                .to_string()
                .contains("undersized non-final")
        );
        assert!(
            derive_with("terminal-resolve", |_| Ok(vec![23]))
                .unwrap_err()
                .to_string()
                .contains("above 22")
        );
        assert!(
            derive_with("terminal-resolve", |_| Ok(vec![14]))
                .unwrap_err()
                .to_string()
                .contains("u32 workload range exhausted")
        );

        let mut calls = 0;
        assert!(
            derive_with("terminal-resolve", |_| {
                calls += 1;
                Ok(if calls == 1 { vec![18] } else { vec![19] })
            })
            .unwrap_err()
            .to_string()
            .contains("nondeterministic")
        );
    }

    #[test]
    fn canonical_report_rejects_altered_bindings_and_constants() {
        let report = fixture();
        let exact = report.to_canonical_jcs().unwrap();
        assert_eq!(
            RecursiveCalibrationReport::from_canonical_jcs(&exact).unwrap(),
            report
        );

        for (field, replacement) in [
            ("schema", json!("Eip0045B4RecursiveCalibrationV2")),
            ("lifecycle", json!("final")),
            ("family", json!("unknown-family")),
            ("segmentLimitPo2", json!(23)),
            ("assumptionWorkloadIterations", json!(1)),
        ] {
            let mut value = serde_json::to_value(&report).unwrap();
            value[field] = replacement;
            let source = canonical_json_bytes(&value).unwrap();
            assert!(
                RecursiveCalibrationReport::from_canonical_jcs(&source).is_err(),
                "field {field} was accepted"
            );
        }

        for (field, replacement) in [
            ("elfSha256", json!("00".repeat(32))),
            ("imageId", json!("00".repeat(32))),
            ("statementSha256", json!("00".repeat(32))),
            ("workloadIterations", json!(6)),
            ("segmentPo2", json!([22, 20])),
        ] {
            let mut value = serde_json::to_value(&report).unwrap();
            value[field] = replacement;
            let source = canonical_json_bytes(&value).unwrap();
            let altered = RecursiveCalibrationReport::from_canonical_jcs(&source).unwrap();
            assert!(
                verify_recursive_calibration_bound(
                    &altered,
                    b"elf",
                    &[7; 32],
                    b"statement",
                    "terminal-join",
                    |workload| Ok(if workload < 5 { vec![20] } else { vec![22, 19] })
                )
                .is_err(),
                "field {field} was not bound by rederivation"
            );
        }
    }

    #[test]
    fn family_mismatch_unknown_field_and_trailing_json_are_rejected() {
        let report = fixture();
        assert!(
            verify_recursive_calibration_bound(
                &report,
                b"elf",
                &[7; 32],
                b"statement",
                "resolve-then-join",
                |_| Ok(vec![22, 19])
            )
            .is_err()
        );

        let mut unknown = serde_json::to_value(&report).unwrap();
        unknown["unexpected"] = json!(true);
        assert!(
            RecursiveCalibrationReport::from_canonical_jcs(
                &canonical_json_bytes(&unknown).unwrap()
            )
            .is_err()
        );
        let mut trailing = report.to_canonical_jcs().unwrap();
        trailing.extend_from_slice(b"null");
        assert!(RecursiveCalibrationReport::from_canonical_jcs(&trailing).is_err());
    }

    #[test]
    fn calibration_file_is_create_only() {
        let report = fixture();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "eip0045-recursive-calibration-{}-{nonce}-{counter}.json",
            std::process::id()
        ));
        create_recursive_calibration_file(&path, &report).unwrap();
        assert_eq!(fs::read(&path).unwrap(), report.to_canonical_jcs().unwrap());
        assert!(create_recursive_calibration_file(&path, &report).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn exhaustion_nonmonotone_ranking_and_resolve_then_join_are_bounded() {
        let exhausted = derive_with("terminal-join", |_| Ok(vec![20])).unwrap_err();
        assert!(
            exhausted
                .to_string()
                .contains("u32 workload range exhausted")
        );

        let nonmonotone = derive_with("terminal-join", |workload| {
            Ok(if workload == 4 || workload >= 7 {
                vec![22, 18]
            } else {
                vec![20]
            })
        })
        .unwrap();
        assert_eq!(nonmonotone.workload_iterations, 4);

        let resolve_then_join = derive_with("resolve-then-join", |workload| {
            Ok(if workload < 3 { vec![19] } else { vec![21, 20] })
        })
        .unwrap();
        assert_eq!(resolve_then_join.workload_iterations, 3);
        assert_eq!(resolve_then_join.segment_po2, vec![21, 20]);
    }

    #[test]
    fn public_api_rejects_an_unbound_elf_and_image_id() {
        assert!(
            derive_recursive_calibration(
                b"not-an-elf",
                &[7; 32],
                b"statement",
                "terminal-resolve",
                |_| Ok(vec![18])
            )
            .is_err()
        );
    }

    #[test]
    fn duplicate_oversized_and_occupied_destinations_are_rejected() {
        let report = fixture();
        let exact = String::from_utf8(report.to_canonical_jcs().unwrap()).unwrap();
        let duplicate = exact.replacen(
            "\"family\":\"terminal-join\"",
            "\"family\":\"terminal-join\",\"family\":\"terminal-join\"",
            1,
        );
        assert!(RecursiveCalibrationReport::from_canonical_jcs(duplicate.as_bytes()).is_err());
        assert!(
            RecursiveCalibrationReport::from_canonical_jcs(&vec![
                b' ';
                RECURSIVE_CALIBRATION_MAX_BYTES
                    + 1
            ])
            .is_err()
        );

        let root = std::env::temp_dir().join(format!(
            "eip0045-recursive-calibration-preflight-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let occupied = root.join("occupied.json");
        fs::write(&occupied, b"occupied").unwrap();
        assert!(preflight_recursive_calibration_file(&occupied).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
