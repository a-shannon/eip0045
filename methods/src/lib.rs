//! Shared host/guest ABI and generated RISC Zero method constants.
//!
//! The private guest input is exactly:
//!
//! ```text
//! mode:u32le ||
//! statementLength:u32le ||
//! workloadIterations:u32le ||
//! workloadSeed:u64le ||
//! expectedWorkloadResult:u64le ||
//! assumptionImageId[32] ||
//! statementBytes[statementLength]
//! ```
//!
//! `mode = 0` requires an all-zero assumption image ID and performs no guest
//! verification. Modes `1`, `2`, and `3` require a nonzero assumption image ID.
//! Mode `1` creates exactly one same-program assumption using the zero
//! self-composition root. Modes `2` and `3` create, respectively, exactly one
//! and exactly two identical same-program assumptions using the pinned explicit
//! RISC Zero control root. Every mode commits only `statementBytes`; the mode
//! and assumption identifier remain private inputs used to construct the
//! candidate recursion ancestry.
//!
//! The host uses a fixed executor segmentation ceiling above the profile's
//! largest target, then calibrates `workloadIterations` so execution produces
//! exactly one final segment whose actual exponent is in `15..=22`. The guest
//! does not select a proving mode, ceiling, or target exponent. Only
//! `statementBytes` are committed to the receipt journal.

#![no_std]

use core::fmt;

/// Exact byte length of the fixed guest-input header.
pub const GUEST_INPUT_HEADER_BYTES: usize = 60;
/// Fixed stack buffer used to stream the statement into the journal.
pub const GUEST_STATEMENT_CHUNK_BYTES: usize = 256;
/// Maximum statement and journal length accepted by the guest.
pub const MAX_STATEMENT_BYTES: usize = 16_543;
/// Smallest supported final segment exponent targeted by calibration.
pub const MIN_CALIBRATION_PO2: u32 = 15;
/// Largest supported final segment exponent targeted by calibration.
pub const MAX_CALIBRATION_PO2: u32 = 22;

/// Private execution mode used by the shared candidate guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum GuestMode {
    /// Execute the deterministic workload and commit the statement directly.
    Plain = 0,
    /// Verify one same-program receipt using zero-root self-composition.
    VerifyAssumptionZeroRoot = 1,
    /// Verify one same-program receipt using the pinned explicit control root.
    VerifyAssumptionExplicitRoot = 2,
    /// Verify the same-program receipt exactly twice using the explicit root.
    VerifyAssumptionExplicitRootTwice = 3,
}

impl GuestMode {
    /// Decode the canonical little-endian numeric mode.
    fn from_u32(value: u32) -> Result<Self, InputAbiError> {
        match value {
            0 => Ok(Self::Plain),
            1 => Ok(Self::VerifyAssumptionZeroRoot),
            2 => Ok(Self::VerifyAssumptionExplicitRoot),
            3 => Ok(Self::VerifyAssumptionExplicitRootTwice),
            _ => Err(InputAbiError::InvalidMode(value)),
        }
    }

    /// Exact number of receipt assumptions recorded by this private mode.
    #[must_use]
    pub const fn assumption_count(self) -> usize {
        match self {
            Self::Plain => 0,
            Self::VerifyAssumptionZeroRoot | Self::VerifyAssumptionExplicitRoot => 1,
            Self::VerifyAssumptionExplicitRootTwice => 2,
        }
    }

    /// Whether this mode records one or more receipt assumptions.
    #[must_use]
    pub const fn verifies_assumption(self) -> bool {
        self.assumption_count() != 0
    }
}

/// Structurally decoded private input header for the calibration guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestInputHeader {
    mode: GuestMode,
    statement_length: u32,
    workload_iterations: u32,
    workload_seed: u64,
    expected_workload_result: u64,
    assumption_image_id: [u8; 32],
}

/// Failure returned while constructing or decoding the fixed input ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputAbiError {
    /// The supplied header slice is not exactly 60 bytes.
    InvalidHeaderLength {
        /// Supplied header length.
        actual: usize,
        /// Required header length.
        expected: usize,
    },
    /// The declared statement length exceeds the guest streaming bound.
    StatementTooLong {
        /// Declared statement length.
        actual: usize,
        /// Maximum accepted statement length.
        maximum: usize,
    },
    /// The numeric execution mode is not defined by this ABI.
    InvalidMode(u32),
    /// Plain mode carried a nonzero assumption image identifier.
    UnexpectedAssumptionImageId,
    /// Assumption-verification mode carried the all-zero image identifier.
    MissingAssumptionImageId,
}

impl fmt::Display for InputAbiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHeaderLength { actual, expected } => write!(
                formatter,
                "guest input header has {actual} bytes, expected exactly {expected}"
            ),
            Self::StatementTooLong { actual, maximum } => write!(
                formatter,
                "guest statement has {actual} bytes, maximum is {maximum}"
            ),
            Self::InvalidMode(value) => {
                write!(formatter, "guest input mode {value} is not defined")
            }
            Self::UnexpectedAssumptionImageId => {
                write!(
                    formatter,
                    "plain guest mode requires an all-zero assumption image ID"
                )
            }
            Self::MissingAssumptionImageId => write!(
                formatter,
                "assumption-verification guest mode requires a nonzero assumption image ID"
            ),
        }
    }
}

impl GuestInputHeader {
    /// Construct a canonical header and its deterministic expected workload result.
    ///
    /// # Errors
    ///
    /// Returns [`InputAbiError::StatementTooLong`] when `statement_length`
    /// exceeds 16,543 bytes.
    pub fn new(
        statement_length: usize,
        workload_iterations: u32,
        workload_seed: u64,
    ) -> Result<Self, InputAbiError> {
        Self::new_for_mode(
            GuestMode::Plain,
            statement_length,
            workload_iterations,
            workload_seed,
            [0; 32],
        )
    }

    /// Construct a header which creates one zero-root self-composition assumption.
    ///
    /// # Errors
    ///
    /// Returns [`InputAbiError::StatementTooLong`] for an oversized statement,
    /// or [`InputAbiError::MissingAssumptionImageId`] for the all-zero image ID.
    pub fn new_verifying_zero_root(
        statement_length: usize,
        workload_iterations: u32,
        workload_seed: u64,
        assumption_image_id: [u8; 32],
    ) -> Result<Self, InputAbiError> {
        Self::new_for_mode(
            GuestMode::VerifyAssumptionZeroRoot,
            statement_length,
            workload_iterations,
            workload_seed,
            assumption_image_id,
        )
    }

    /// Construct a header which creates one assumption under the pinned explicit root.
    ///
    /// # Errors
    ///
    /// Returns [`InputAbiError::StatementTooLong`] for an oversized statement,
    /// or [`InputAbiError::MissingAssumptionImageId`] for the all-zero image ID.
    pub fn new_verifying_explicit_root(
        statement_length: usize,
        workload_iterations: u32,
        workload_seed: u64,
        assumption_image_id: [u8; 32],
    ) -> Result<Self, InputAbiError> {
        Self::new_for_mode(
            GuestMode::VerifyAssumptionExplicitRoot,
            statement_length,
            workload_iterations,
            workload_seed,
            assumption_image_id,
        )
    }

    /// Construct a header which creates two identical assumptions under the pinned explicit root.
    ///
    /// # Errors
    ///
    /// Returns [`InputAbiError::StatementTooLong`] for an oversized statement,
    /// or [`InputAbiError::MissingAssumptionImageId`] for the all-zero image ID.
    pub fn new_verifying_explicit_root_twice(
        statement_length: usize,
        workload_iterations: u32,
        workload_seed: u64,
        assumption_image_id: [u8; 32],
    ) -> Result<Self, InputAbiError> {
        Self::new_for_mode(
            GuestMode::VerifyAssumptionExplicitRootTwice,
            statement_length,
            workload_iterations,
            workload_seed,
            assumption_image_id,
        )
    }

    fn new_for_mode(
        mode: GuestMode,
        statement_length: usize,
        workload_iterations: u32,
        workload_seed: u64,
        assumption_image_id: [u8; 32],
    ) -> Result<Self, InputAbiError> {
        validate_statement_length(statement_length)?;
        validate_mode_image_id(mode, &assumption_image_id)?;
        let statement_length =
            u32::try_from(statement_length).map_err(|_| InputAbiError::StatementTooLong {
                actual: statement_length,
                maximum: MAX_STATEMENT_BYTES,
            })?;

        Ok(Self {
            mode,
            statement_length,
            workload_iterations,
            workload_seed,
            expected_workload_result: workload_result(workload_seed, workload_iterations),
            assumption_image_id,
        })
    }

    /// Decode and structurally validate an exact 60-byte header.
    ///
    /// This does not precompute the workload result. The guest performs that
    /// work before reading and committing statement chunks, and gates every
    /// journal commit on the result matching
    /// [`Self::expected_workload_result`].
    ///
    /// # Errors
    ///
    /// Returns [`InputAbiError::InvalidHeaderLength`] for any non-exact header
    /// slice or [`InputAbiError::StatementTooLong`] for an oversized declared
    /// statement.
    pub fn decode(bytes: &[u8]) -> Result<Self, InputAbiError> {
        if bytes.len() != GUEST_INPUT_HEADER_BYTES {
            return Err(InputAbiError::InvalidHeaderLength {
                actual: bytes.len(),
                expected: GUEST_INPUT_HEADER_BYTES,
            });
        }

        let invalid_header = InputAbiError::InvalidHeaderLength {
            actual: bytes.len(),
            expected: GUEST_INPUT_HEADER_BYTES,
        };
        let (mode_bytes, remaining) = bytes.split_first_chunk::<4>().ok_or(invalid_header)?;
        let (statement_length_bytes, remaining) =
            remaining.split_first_chunk::<4>().ok_or(invalid_header)?;
        let (workload_iterations_bytes, remaining) =
            remaining.split_first_chunk::<4>().ok_or(invalid_header)?;
        let (workload_seed_bytes, remaining) =
            remaining.split_first_chunk::<8>().ok_or(invalid_header)?;
        let (expected_workload_result_bytes, assumption_image_id_bytes) =
            remaining.split_first_chunk::<8>().ok_or(invalid_header)?;
        let assumption_image_id: [u8; 32] = assumption_image_id_bytes
            .try_into()
            .map_err(|_| invalid_header)?;

        let mode = GuestMode::from_u32(u32::from_le_bytes(*mode_bytes))?;
        let statement_length = u32::from_le_bytes(*statement_length_bytes);
        let statement_length_usize = statement_length as usize;
        validate_statement_length(statement_length_usize)?;
        validate_mode_image_id(mode, &assumption_image_id)?;

        Ok(Self {
            mode,
            statement_length,
            workload_iterations: u32::from_le_bytes(*workload_iterations_bytes),
            workload_seed: u64::from_le_bytes(*workload_seed_bytes),
            expected_workload_result: u64::from_le_bytes(*expected_workload_result_bytes),
            assumption_image_id,
        })
    }

    /// Encode the canonical fixed-width little-endian header.
    #[must_use]
    pub fn encode(self) -> [u8; GUEST_INPUT_HEADER_BYTES] {
        let mut output = [0u8; GUEST_INPUT_HEADER_BYTES];
        output[0..4].copy_from_slice(&(self.mode as u32).to_le_bytes());
        output[4..8].copy_from_slice(&self.statement_length.to_le_bytes());
        output[8..12].copy_from_slice(&self.workload_iterations.to_le_bytes());
        output[12..20].copy_from_slice(&self.workload_seed.to_le_bytes());
        output[20..28].copy_from_slice(&self.expected_workload_result.to_le_bytes());
        output[28..60].copy_from_slice(&self.assumption_image_id);
        output
    }

    /// Private execution mode selected by this header.
    #[must_use]
    pub const fn mode(self) -> GuestMode {
        self.mode
    }

    /// Declared statement byte length following the header.
    #[must_use]
    pub const fn statement_length(self) -> u32 {
        self.statement_length
    }

    /// Number of deterministic mixing iterations the guest must execute.
    #[must_use]
    pub const fn workload_iterations(self) -> u32 {
        self.workload_iterations
    }

    /// Initial state for the deterministic workload.
    #[must_use]
    pub const fn workload_seed(self) -> u64 {
        self.workload_seed
    }

    /// Result that must match before the guest commits its journal.
    #[must_use]
    pub const fn expected_workload_result(self) -> u64 {
        self.expected_workload_result
    }

    /// Image ID used by the optional assumption-verification call or calls.
    #[must_use]
    pub const fn assumption_image_id(self) -> [u8; 32] {
        self.assumption_image_id
    }

    /// Exact total private-input length implied by this header.
    #[must_use]
    pub fn encoded_input_length(self) -> usize {
        GUEST_INPUT_HEADER_BYTES + self.statement_length as usize
    }

    /// Recompute and compare the deterministic workload result.
    #[must_use]
    pub fn workload_matches(self) -> bool {
        workload_result(self.workload_seed, self.workload_iterations)
            == self.expected_workload_result
    }
}

/// Return the next fixed-buffer statement chunk length.
///
/// The guest repeatedly applies this function until no bytes remain. Multiple
/// journal writes concatenate exactly, so the committed journal remains the
/// original statement byte string rather than a chunked serialization.
#[must_use]
pub const fn next_statement_chunk_length(remaining: usize) -> usize {
    if remaining < GUEST_STATEMENT_CHUNK_BYTES {
        remaining
    } else {
        GUEST_STATEMENT_CHUNK_BYTES
    }
}

/// Execute the deterministic, architecture-independent calibration workload.
///
/// The loop count and seed are private guest inputs. Wrapping integer
/// operations make the result identical on host and RV32IM targets. The guest
/// additionally treats the inputs and result as optimization barriers and
/// exits nonzero without committing unless this result matches the header.
#[must_use]
#[inline(never)]
pub fn workload_result(mut state: u64, iterations: u32) -> u64 {
    for round in 0..iterations {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15 ^ u64::from(round));
        state = (state ^ (state >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        state = (state ^ (state >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        state ^= state >> 31;
    }
    state
}

fn validate_statement_length(statement_length: usize) -> Result<(), InputAbiError> {
    if statement_length <= MAX_STATEMENT_BYTES {
        Ok(())
    } else {
        Err(InputAbiError::StatementTooLong {
            actual: statement_length,
            maximum: MAX_STATEMENT_BYTES,
        })
    }
}

fn validate_mode_image_id(
    mode: GuestMode,
    assumption_image_id: &[u8; 32],
) -> Result<(), InputAbiError> {
    let is_zero = assumption_image_id.iter().all(|byte| *byte == 0);
    match (mode, is_zero) {
        (GuestMode::Plain, true)
        | (
            GuestMode::VerifyAssumptionZeroRoot
            | GuestMode::VerifyAssumptionExplicitRoot
            | GuestMode::VerifyAssumptionExplicitRootTwice,
            false,
        ) => Ok(()),
        (GuestMode::Plain, false) => Err(InputAbiError::UnexpectedAssumptionImageId),
        (
            GuestMode::VerifyAssumptionZeroRoot
            | GuestMode::VerifyAssumptionExplicitRoot
            | GuestMode::VerifyAssumptionExplicitRootTwice,
            true,
        ) => Err(InputAbiError::MissingAssumptionImageId),
    }
}

#[cfg(all(not(target_os = "zkvm"), feature = "embed-methods"))]
#[allow(missing_docs)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/methods.rs"));
}

#[cfg(all(not(target_os = "zkvm"), feature = "embed-methods"))]
pub use generated::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_encoding_is_exact_little_endian() {
        let header = GuestInputHeader {
            mode: GuestMode::Plain,
            statement_length: 0x1234,
            workload_iterations: 0x0102_0304,
            workload_seed: 0x0102_0304_0506_0708,
            expected_workload_result: 0x1112_1314_1516_1718,
            assumption_image_id: [0; 32],
        };
        let mut expected = [0_u8; GUEST_INPUT_HEADER_BYTES];
        expected[0..4].copy_from_slice(&0_u32.to_le_bytes());
        expected[4..8].copy_from_slice(&0x1234_u32.to_le_bytes());
        expected[8..12].copy_from_slice(&0x0102_0304_u32.to_le_bytes());
        expected[12..20].copy_from_slice(&0x0102_0304_0506_0708_u64.to_le_bytes());
        expected[20..28].copy_from_slice(&0x1112_1314_1516_1718_u64.to_le_bytes());

        assert_eq!(header.encode(), expected);
        assert_eq!(GuestInputHeader::decode(&expected).unwrap(), header);
        assert_eq!(header.encoded_input_length(), 60 + 0x1234);
    }

    #[test]
    fn constructor_and_workload_match_an_independent_known_answer() {
        let header = GuestInputHeader::new(159, 7, 0x0123_4567_89ab_cdef).unwrap();
        assert_eq!(header.expected_workload_result(), 0xf782_1190_bc33_202f);
        assert!(header.workload_matches());

        let mut tampered = header.encode();
        tampered[16] ^= 1;
        assert!(!GuestInputHeader::decode(&tampered)
            .unwrap()
            .workload_matches());
    }

    #[test]
    fn statement_limit_is_exact() {
        assert!(GuestInputHeader::new(16_543, 0, 0).is_ok());
        assert_eq!(
            GuestInputHeader::new(16_544, 0, 0),
            Err(InputAbiError::StatementTooLong {
                actual: 16_544,
                maximum: 16_543,
            })
        );
    }

    #[test]
    fn header_length_is_exact() {
        for actual in [59, 61] {
            let bytes = [0u8; 61];
            assert_eq!(
                GuestInputHeader::decode(&bytes[..actual]),
                Err(InputAbiError::InvalidHeaderLength {
                    actual,
                    expected: 60,
                })
            );
        }
    }

    #[test]
    fn modes_and_assumption_image_id_are_canonical() {
        let assumption_image_id = [0x5a; 32];
        let zero_root =
            GuestInputHeader::new_verifying_zero_root(159, 3, 4, assumption_image_id).unwrap();
        let explicit_root =
            GuestInputHeader::new_verifying_explicit_root(159, 3, 4, assumption_image_id).unwrap();
        for (header, expected_mode) in [
            (zero_root, GuestMode::VerifyAssumptionZeroRoot),
            (explicit_root, GuestMode::VerifyAssumptionExplicitRoot),
        ] {
            assert_eq!(header.mode(), expected_mode);
            assert!(header.mode().verifies_assumption());
            assert_eq!(header.assumption_image_id(), assumption_image_id);
            assert_eq!(GuestInputHeader::decode(&header.encode()).unwrap(), header);
        }
        assert!(!GuestMode::Plain.verifies_assumption());

        for constructor in [
            GuestInputHeader::new_verifying_zero_root,
            GuestInputHeader::new_verifying_explicit_root,
        ] {
            assert_eq!(
                constructor(159, 3, 4, [0; 32]),
                Err(InputAbiError::MissingAssumptionImageId)
            );
        }

        let mut invalid_plain = GuestInputHeader::new(159, 3, 4).unwrap().encode();
        invalid_plain[28] = 1;
        assert_eq!(
            GuestInputHeader::decode(&invalid_plain),
            Err(InputAbiError::UnexpectedAssumptionImageId)
        );

        let mut invalid_mode = GuestInputHeader::new(159, 3, 4).unwrap().encode();
        invalid_mode[0..4].copy_from_slice(&4_u32.to_le_bytes());
        assert_eq!(
            GuestInputHeader::decode(&invalid_mode),
            Err(InputAbiError::InvalidMode(4))
        );
    }

    #[test]
    fn explicit_root_twice_mode_is_append_only_and_round_trips() {
        let assumption_image_id = [0x5a; 32];
        let once =
            GuestInputHeader::new_verifying_explicit_root(159, 3, 4, assumption_image_id).unwrap();
        let twice =
            GuestInputHeader::new_verifying_explicit_root_twice(159, 3, 4, assumption_image_id)
                .unwrap();

        assert_eq!(GuestMode::Plain.assumption_count(), 0);
        assert_eq!(GuestMode::VerifyAssumptionZeroRoot.assumption_count(), 1);
        assert_eq!(
            GuestMode::VerifyAssumptionExplicitRoot.assumption_count(),
            1
        );
        assert_eq!(
            GuestMode::VerifyAssumptionExplicitRootTwice.assumption_count(),
            2
        );
        assert_eq!(GuestMode::VerifyAssumptionExplicitRootTwice as u32, 3);

        let once_bytes = once.encode();
        let twice_bytes = twice.encode();
        assert_eq!(&twice_bytes[0..4], &3_u32.to_le_bytes());
        assert_eq!(&twice_bytes[4..], &once_bytes[4..]);
        assert_eq!(GuestInputHeader::decode(&twice_bytes).unwrap(), twice);
        assert_eq!(
            GuestInputHeader::new_verifying_explicit_root_twice(159, 3, 4, [0; 32]),
            Err(InputAbiError::MissingAssumptionImageId)
        );
    }

    #[test]
    fn statement_chunking_is_bounded_and_exact() {
        assert_eq!(next_statement_chunk_length(0), 0);
        assert_eq!(next_statement_chunk_length(1), 1);
        assert_eq!(next_statement_chunk_length(255), 255);
        assert_eq!(next_statement_chunk_length(256), 256);
        assert_eq!(next_statement_chunk_length(257), 256);

        let mut remaining = MAX_STATEMENT_BYTES;
        let mut total = 0;
        while remaining != 0 {
            let chunk = next_statement_chunk_length(remaining);
            assert!((1..=GUEST_STATEMENT_CHUNK_BYTES).contains(&chunk));
            remaining -= chunk;
            total += chunk;
        }
        assert_eq!(total, MAX_STATEMENT_BYTES);
    }
}
