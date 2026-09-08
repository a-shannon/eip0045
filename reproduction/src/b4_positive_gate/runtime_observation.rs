//! Pure, bounded parsers for the first two B4 runtime-observation contracts.
//!
//! The values in this module describe only the structure of caller-supplied
//! bytes. They do not attest that `runc` executed, that `/proc` was read, that
//! two inputs were captured together, or that a process is still alive.

use super::PositiveRunnerRole;
use crate::canonical::{parse_json_strict, validate_canonical_json_source};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    fmt::Write as _,
    num::{NonZeroU32, NonZeroU64},
};

pub(super) const RUNTIME_STATE_CONTRACT_ID: &str =
    "eip0045-b4-runtime-observation-runc-state-json-v1";
pub(super) const RUNTIME_PROCESS_IDENTITY_CONTRACT_ID: &str =
    "eip0045-b4-runtime-observation-linux-boot-id-pid-starttime-jcs-v1";

const RUNC_STATE_MAX_SOURCE_BYTES: usize = 16_384;
const PROCESS_IDENTITY_MAX_SOURCE_BYTES: usize = 128;
const RUNC_CONTAINER_ID_MAX_BYTES: usize = 128;
const RUNTIME_PATH_MAX_BYTES: usize = 4_096;
const RUNTIME_PATH_MAX_COMPONENTS: usize = 64;
const RUNTIME_PATH_COMPONENT_MAX_BYTES: usize = 128;
const RUNC_CREATED_TIMESTAMP_MAX_BYTES: usize = 30;
const LINUX_PID_MAX: u32 = 4_194_303;
const OCI_VERSION: &str = "1.3.0";

/// Opaque, role-bound parser contract for exact `runc state` JSON bytes.
///
/// This token is created only by the complete positive runner-profile
/// projection. Parsing with it establishes byte and semantic shape, not the
/// provenance, freshness, or runtime truth of the supplied bytes.
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_positive_gate::{
///     B4PositiveRuncStateContractV1, PositiveRunnerRole,
/// };
/// let _ = B4PositiveRuncStateContractV1 {
///     role: PositiveRunnerRole::RustVerifier,
/// };
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct B4PositiveRuncStateContractV1 {
    role: PositiveRunnerRole,
}

impl B4PositiveRuncStateContractV1 {
    pub(super) const fn new(role: PositiveRunnerRole) -> Self {
        Self { role }
    }

    /// Exact identifier of the accepted state-byte contract.
    #[must_use]
    pub const fn contract_id(&self) -> &'static str {
        RUNTIME_STATE_CONTRACT_ID
    }

    /// Maximum accepted source length, checked before JSON parsing.
    #[must_use]
    pub const fn maximum_source_bytes(&self) -> usize {
        RUNC_STATE_MAX_SOURCE_BYTES
    }

    /// Positive runner role to which this parser contract remains attached.
    #[must_use]
    pub const fn role(&self) -> PositiveRunnerRole {
        self.role
    }

    /// Parse one exact, complete `runc state` JSON document.
    ///
    /// # Errors
    ///
    /// Returns an error for a limit excess, malformed or duplicate-key JSON,
    /// any byte-level deviation from the fixed Go `MarshalIndent` form, an
    /// unknown or missing field, or an invalid state semantic.
    pub fn parse(&self, source: &[u8]) -> Result<B4ParsedRuncStateV1> {
        ensure!(
            source.len() <= RUNC_STATE_MAX_SOURCE_BYTES,
            "runc state source exceeds {RUNC_STATE_MAX_SOURCE_BYTES} bytes"
        );

        let value = parse_json_strict(source).context("invalid strict runc state JSON")?;
        let wire: RuncStateWire =
            serde_json::from_value(value).context("invalid closed runc state object")?;
        let expected = encode_exact_runc_state(&wire, source.len());
        ensure!(
            expected.as_bytes() == source,
            "runc state source is not the exact Go MarshalIndent byte form"
        );

        ensure!(
            wire.oci_version == OCI_VERSION,
            "runc state ociVersion differs from {OCI_VERSION}"
        );
        validate_runc_container_id(&wire.id)?;
        validate_runtime_path(&wire.bundle, "runc state bundle")?;
        validate_runtime_path(&wire.rootfs, "runc state rootfs")?;
        validate_rfc3339_nano_utc(&wire.created)?;
        ensure!(wire.owner.is_empty(), "runc state owner is not empty");
        ensure!(
            wire.pid <= u64::from(LINUX_PID_MAX),
            "runc state PID exceeds {LINUX_PID_MAX}"
        );
        let pid = u32::try_from(wire.pid).context("runc state PID does not fit u32")?;
        let status = match wire.status.as_str() {
            "created" => {
                ensure!(pid != 0, "created runc state has PID zero");
                B4ParsedRuncStateStatusV1::Created
            }
            "stopped" => {
                ensure!(pid == 0, "stopped runc state has a live PID");
                B4ParsedRuncStateStatusV1::Stopped
            }
            _ => anyhow::bail!("unsupported runc state status {:?}", wire.status),
        };

        Ok(B4ParsedRuncStateV1 {
            role: self.role,
            oci_version: wire.oci_version,
            container_id: wire.id,
            pid,
            status,
            bundle: wire.bundle,
            rootfs: wire.rootfs,
            created: wire.created,
            owner: wire.owner,
        })
    }
}

/// Opaque, role-bound parser contract for the canonical process-identity record.
///
/// The parser accepts a structural tuple containing a boot discriminator, PID,
/// and process start tick. It does not establish that a trusted producer read
/// either Linux source or that those source reads were contemporaneous.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct B4PositiveProcessIdentityContractV1 {
    role: PositiveRunnerRole,
}

impl B4PositiveProcessIdentityContractV1 {
    pub(super) const fn new(role: PositiveRunnerRole) -> Self {
        Self { role }
    }

    /// Exact identifier of the accepted process-identity record contract.
    #[must_use]
    pub const fn contract_id(&self) -> &'static str {
        RUNTIME_PROCESS_IDENTITY_CONTRACT_ID
    }

    /// Maximum accepted source length, checked before JSON parsing.
    #[must_use]
    pub const fn maximum_source_bytes(&self) -> usize {
        PROCESS_IDENTITY_MAX_SOURCE_BYTES
    }

    /// Positive runner role to which this parser contract remains attached.
    #[must_use]
    pub const fn role(&self) -> PositiveRunnerRole {
        self.role
    }

    /// Parse one exact RFC 8785 process-identity record.
    ///
    /// # Errors
    ///
    /// Returns an error for a limit excess, malformed, duplicate, unknown, or
    /// missing JSON member, non-JCS bytes, a noncanonical UUID, an out-of-range
    /// PID, or a noncanonical/nonzero-overflowing start-tick value.
    pub fn parse(&self, source: &[u8]) -> Result<B4ParsedProcessIdentityRecordV1> {
        ensure!(
            source.len() <= PROCESS_IDENTITY_MAX_SOURCE_BYTES,
            "process-identity source exceeds {PROCESS_IDENTITY_MAX_SOURCE_BYTES} bytes"
        );

        let value = validate_canonical_json_source(source)
            .context("invalid canonical process-identity JSON")?;
        let wire: ProcessIdentityWire =
            serde_json::from_value(value).context("invalid closed process-identity object")?;

        let boot_id = decode_canonical_boot_uuid(&wire.boot_id)?;
        ensure!(
            wire.pid <= u64::from(LINUX_PID_MAX),
            "process-identity PID exceeds {LINUX_PID_MAX}"
        );
        let pid = u32::try_from(wire.pid).context("process-identity PID does not fit u32")?;
        let pid = NonZeroU32::new(pid).context("process-identity PID is zero")?;
        let start_time_ticks =
            parse_nonzero_canonical_u64(&wire.start_time_ticks, "process-identity startTimeTicks")?;

        Ok(B4ParsedProcessIdentityRecordV1 {
            role: self.role,
            boot_id,
            pid,
            start_time_ticks,
        })
    }
}

/// Closed status accepted from exact `runc state` output in this tranche.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum B4ParsedRuncStateStatusV1 {
    /// `runc create` completed and returned a nonzero init PID.
    Created,
    /// The container stopped and `runc state` returned PID zero.
    Stopped,
}

impl B4ParsedRuncStateStatusV1 {
    /// Exact lowercase state spelling carried in the parsed JSON.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Stopped => "stopped",
        }
    }
}

/// Parsed structure of one exact, bounded `runc state` source.
///
/// This is a non-serializable structural value, not a runtime observation or
/// evidence that the named container or process exists.
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_positive_gate::B4ParsedRuncStateV1;
/// let _: B4ParsedRuncStateV1 = serde_json::from_slice(b"{}").unwrap();
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B4ParsedRuncStateV1 {
    role: PositiveRunnerRole,
    oci_version: String,
    container_id: String,
    pid: u32,
    status: B4ParsedRuncStateStatusV1,
    bundle: String,
    rootfs: String,
    created: String,
    owner: String,
}

impl B4ParsedRuncStateV1 {
    /// Positive runner role retained from the parser contract.
    #[must_use]
    pub const fn role(&self) -> PositiveRunnerRole {
        self.role
    }

    /// Exact OCI version parsed from the state document.
    #[must_use]
    pub fn oci_version(&self) -> &str {
        &self.oci_version
    }

    /// Exact `runc` container identifier.
    #[must_use]
    pub fn container_id(&self) -> &str {
        &self.container_id
    }

    /// Parsed init PID; it is zero exactly for `Stopped`.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Closed parsed state.
    #[must_use]
    pub const fn status(&self) -> B4ParsedRuncStateStatusV1 {
        self.status
    }

    /// Exact portable absolute bundle path carried by the state document.
    #[must_use]
    pub fn bundle(&self) -> &str {
        &self.bundle
    }

    /// Exact portable absolute rootfs path carried by the state document.
    #[must_use]
    pub fn rootfs(&self) -> &str {
        &self.rootfs
    }

    /// Exact canonical UTC `RFC3339Nano` creation timestamp.
    #[must_use]
    pub fn created(&self) -> &str {
        &self.created
    }

    /// Exact owner field, required by this contract to be empty.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Structurally match this created-state value with a parsed identity tuple.
    ///
    /// The result means only that both parsers carried the same role, this
    /// state was `created`, and the PID numbers matched. It does not establish
    /// capture order, atomicity, same-boot provenance, process liveness, or
    /// resistance to an exit/reuse race between source reads.
    ///
    /// # Errors
    ///
    /// Returns an error unless the roles match, the state is `Created`, and
    /// both parsed inputs carry the same nonzero PID.
    pub fn match_created_process_identity(
        &self,
        identity: &B4ParsedProcessIdentityRecordV1,
    ) -> Result<B4StructuralCreatedProcessMatchV1> {
        ensure!(
            self.role == identity.role,
            "runtime state and process identity roles differ"
        );
        ensure!(
            self.status == B4ParsedRuncStateStatusV1::Created,
            "only a created runc state can be structurally matched"
        );
        ensure!(
            self.pid == identity.pid.get(),
            "runtime state and process identity PIDs differ"
        );

        Ok(B4StructuralCreatedProcessMatchV1 {
            state: self.clone(),
            process_identity: *identity,
        })
    }
}

/// Parsed structure of one exact process-identity JCS record.
///
/// Its boot ID prevents ordinary cross-boot tuple collision only when a future
/// trusted producer establishes the provenance of the record. This pure value
/// makes no such claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct B4ParsedProcessIdentityRecordV1 {
    role: PositiveRunnerRole,
    boot_id: [u8; 16],
    pid: NonZeroU32,
    start_time_ticks: NonZeroU64,
}

impl B4ParsedProcessIdentityRecordV1 {
    /// Positive runner role retained from the parser contract.
    #[must_use]
    pub const fn role(&self) -> PositiveRunnerRole {
        self.role
    }

    /// Canonical UUID bytes parsed from the boot discriminator.
    #[must_use]
    pub const fn boot_id(&self) -> &[u8; 16] {
        &self.boot_id
    }

    /// Nonzero Linux PID from the structural record.
    #[must_use]
    pub const fn pid(&self) -> NonZeroU32 {
        self.pid
    }

    /// Nonzero process start time in Linux clock ticks since boot.
    #[must_use]
    pub const fn start_time_ticks(&self) -> NonZeroU64 {
        self.start_time_ticks
    }
}

/// Non-authorizing structural match between parsed created-state and identity values.
///
/// This type carries no filesystem, `/proc`, `runc`, liveness, completion, or
/// publication authority. A future effectful producer must separately close
/// source custody and the temporal exit/reuse boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B4StructuralCreatedProcessMatchV1 {
    state: B4ParsedRuncStateV1,
    process_identity: B4ParsedProcessIdentityRecordV1,
}

impl B4StructuralCreatedProcessMatchV1 {
    /// Positive runner role shared by both parsed inputs.
    #[must_use]
    pub const fn role(&self) -> PositiveRunnerRole {
        self.state.role
    }

    /// Parsed created-state side of the structural match.
    #[must_use]
    pub const fn state(&self) -> &B4ParsedRuncStateV1 {
        &self.state
    }

    /// Parsed process-identity side of the structural match.
    #[must_use]
    pub const fn process_identity(&self) -> &B4ParsedProcessIdentityRecordV1 {
        &self.process_identity
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuncStateWire {
    #[serde(rename = "ociVersion")]
    oci_version: String,
    id: String,
    pid: u64,
    status: String,
    bundle: String,
    rootfs: String,
    created: String,
    owner: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProcessIdentityWire {
    boot_id: String,
    pid: u64,
    start_time_ticks: String,
}

fn encode_exact_runc_state(wire: &RuncStateWire, source_length: usize) -> String {
    let mut output = String::with_capacity(source_length);
    output.push_str("{\n  \"ociVersion\": ");
    push_go_json_string(&mut output, &wire.oci_version);
    output.push_str(",\n  \"id\": ");
    push_go_json_string(&mut output, &wire.id);
    output.push_str(",\n  \"pid\": ");
    write!(&mut output, "{}", wire.pid).expect("writing to a String cannot fail");
    output.push_str(",\n  \"status\": ");
    push_go_json_string(&mut output, &wire.status);
    output.push_str(",\n  \"bundle\": ");
    push_go_json_string(&mut output, &wire.bundle);
    output.push_str(",\n  \"rootfs\": ");
    push_go_json_string(&mut output, &wire.rootfs);
    output.push_str(",\n  \"created\": ");
    push_go_json_string(&mut output, &wire.created);
    output.push_str(",\n  \"owner\": ");
    push_go_json_string(&mut output, &wire.owner);
    output.push_str("\n}");
    output
}

fn push_go_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '<' => output.push_str("\\u003c"),
            '>' => output.push_str("\\u003e"),
            '&' => output.push_str("\\u0026"),
            '\u{2028}' => output.push_str("\\u2028"),
            '\u{2029}' => output.push_str("\\u2029"),
            character if character <= '\u{001f}' => {
                let code = u32::from(character);
                write!(output, "\\u{code:04x}").expect("writing to a String cannot fail");
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

fn validate_runc_container_id(value: &str) -> Result<()> {
    ensure!(
        (1..=RUNC_CONTAINER_ID_MAX_BYTES).contains(&value.len()),
        "runc state ID is empty or exceeds {RUNC_CONTAINER_ID_MAX_BYTES} bytes"
    );
    ensure!(value != "." && value != "..", "runc state ID is a dot path");
    ensure!(
        value.bytes().all(|byte| matches!(
            byte,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'+' | b'-'
        )),
        "runc state ID contains a non-runc character"
    );
    Ok(())
}

fn validate_runtime_path(value: &str, label: &str) -> Result<()> {
    ensure!(
        (2..=RUNTIME_PATH_MAX_BYTES).contains(&value.len()),
        "{label} path is outside 2..={RUNTIME_PATH_MAX_BYTES} bytes"
    );
    ensure!(value.starts_with('/'), "{label} path is not absolute");
    ensure!(!value.ends_with('/'), "{label} path has a trailing slash");
    ensure!(!value.contains("//"), "{label} path has an empty component");

    let mut component_count = 0_usize;
    for component in value[1..].split('/') {
        component_count = component_count
            .checked_add(1)
            .context("runtime path component count overflowed")?;
        ensure!(
            component_count <= RUNTIME_PATH_MAX_COMPONENTS,
            "{label} path exceeds {RUNTIME_PATH_MAX_COMPONENTS} components"
        );
        ensure!(
            (1..=RUNTIME_PATH_COMPONENT_MAX_BYTES).contains(&component.len()),
            "{label} component is empty or exceeds {RUNTIME_PATH_COMPONENT_MAX_BYTES} bytes"
        );
        ensure!(
            component != "." && component != "..",
            "{label} path contains a dot component"
        );
        ensure!(
            component.bytes().all(|byte| matches!(
                byte,
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'+' | b'-'
            )),
            "{label} component is outside the portable ASCII subset"
        );
    }
    Ok(())
}

fn validate_rfc3339_nano_utc(value: &str) -> Result<()> {
    ensure!(
        value.len() <= RUNC_CREATED_TIMESTAMP_MAX_BYTES,
        "runc state created timestamp exceeds {RUNC_CREATED_TIMESTAMP_MAX_BYTES} bytes"
    );
    let bytes = value.as_bytes();
    let has_fraction = (22..=RUNC_CREATED_TIMESTAMP_MAX_BYTES).contains(&bytes.len());
    ensure!(
        bytes.len() == 20 || has_fraction,
        "runc state created timestamp has a noncanonical length"
    );
    ensure!(
        bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes[10] == b'T'
            && bytes[13] == b':'
            && bytes[16] == b':',
        "runc state created timestamp has invalid separators"
    );

    let year = decimal_digits(&bytes[0..4]).context("invalid timestamp year")?;
    let month = decimal_digits(&bytes[5..7]).context("invalid timestamp month")?;
    let day = decimal_digits(&bytes[8..10]).context("invalid timestamp day")?;
    let hour = decimal_digits(&bytes[11..13]).context("invalid timestamp hour")?;
    let minute = decimal_digits(&bytes[14..16]).context("invalid timestamp minute")?;
    let second = decimal_digits(&bytes[17..19]).context("invalid timestamp second")?;
    ensure!((1..=12).contains(&month), "timestamp month is invalid");
    ensure!(
        (1..=days_in_month(year, month)).contains(&day),
        "timestamp day is invalid"
    );
    ensure!(hour <= 23, "timestamp hour is invalid");
    ensure!(minute <= 59, "timestamp minute is invalid");
    ensure!(second <= 59, "timestamp second is invalid");

    if has_fraction {
        ensure!(
            bytes[19] == b'.' && bytes[bytes.len() - 1] == b'Z',
            "timestamp fraction is not UTC RFC3339Nano"
        );
        let fraction = &bytes[20..bytes.len() - 1];
        ensure!(
            fraction.iter().all(u8::is_ascii_digit),
            "timestamp fraction is not decimal"
        );
        ensure!(
            fraction.last() != Some(&b'0'),
            "timestamp fraction has a noncanonical trailing zero"
        );
    } else {
        ensure!(bytes[19] == b'Z', "timestamp is not canonical UTC");
    }
    Ok(())
}

fn decimal_digits(bytes: &[u8]) -> Option<u32> {
    let mut value = 0_u32;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add(u32::from(*byte - b'0'))?;
    }
    Some(value)
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn decode_canonical_boot_uuid(value: &str) -> Result<[u8; 16]> {
    let bytes = value.as_bytes();
    ensure!(bytes.len() == 36, "bootId is not a 36-byte UUID");
    for index in [8, 13, 18, 23] {
        ensure!(
            bytes[index] == b'-',
            "bootId has a misplaced UUID separator"
        );
    }
    ensure!(bytes[14] == b'4', "bootId is not a version-4 UUID");
    ensure!(
        matches!(bytes[19], b'8' | b'9' | b'a' | b'b'),
        "bootId does not have the RFC 4122 variant"
    );

    let mut decoded = [0_u8; 16];
    let mut output_index = 0_usize;
    let mut input_index = 0_usize;
    while input_index < bytes.len() {
        if matches!(input_index, 8 | 13 | 18 | 23) {
            input_index += 1;
            continue;
        }
        let high =
            lowercase_hex_nibble(bytes[input_index]).context("bootId is not lowercase hex")?;
        let low =
            lowercase_hex_nibble(bytes[input_index + 1]).context("bootId is not lowercase hex")?;
        decoded[output_index] = (high << 4) | low;
        output_index += 1;
        input_index += 2;
    }
    Ok(decoded)
}

const fn lowercase_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn parse_nonzero_canonical_u64(value: &str, label: &str) -> Result<NonZeroU64> {
    ensure!(
        !value.is_empty()
            && value.len() <= 20
            && value.as_bytes()[0].is_ascii_digit()
            && value.as_bytes()[0] != b'0'
            && value.as_bytes().iter().all(u8::is_ascii_digit),
        "{label} is not a canonical nonzero decimal u64"
    );
    let value = value
        .parse::<u64>()
        .with_context(|| format!("{label} exceeds u64"))?;
    NonZeroU64::new(value).with_context(|| format!("{label} is zero"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREATED_STATE: &str = "{\n  \"ociVersion\": \"1.3.0\",\n  \"id\": \"runner-0\",\n  \"pid\": 123,\n  \"status\": \"created\",\n  \"bundle\": \"/b4/bundle-0\",\n  \"rootfs\": \"/b4/rootfs-0\",\n  \"created\": \"2026-08-08T12:34:56.123456789Z\",\n  \"owner\": \"\"\n}";
    const STOPPED_STATE: &str = "{\n  \"ociVersion\": \"1.3.0\",\n  \"id\": \"runner-0\",\n  \"pid\": 0,\n  \"status\": \"stopped\",\n  \"bundle\": \"/b4/bundle-0\",\n  \"rootfs\": \"/b4/rootfs-0\",\n  \"created\": \"2026-08-08T12:34:56Z\",\n  \"owner\": \"\"\n}";
    const BOOT_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const PROCESS_IDENTITY: &str = "{\"bootId\":\"550e8400-e29b-41d4-a716-446655440000\",\"pid\":123,\"startTimeTicks\":\"456\"}";

    fn state_contract(role: PositiveRunnerRole) -> B4PositiveRuncStateContractV1 {
        B4PositiveRuncStateContractV1::new(role)
    }

    fn identity_contract(role: PositiveRunnerRole) -> B4PositiveProcessIdentityContractV1 {
        B4PositiveProcessIdentityContractV1::new(role)
    }

    fn identity_source(boot_id: &str, pid: u64, ticks: &str) -> String {
        format!("{{\"bootId\":\"{boot_id}\",\"pid\":{pid},\"startTimeTicks\":\"{ticks}\"}}")
    }

    fn state_without_member(source: &str, key: &str) -> String {
        let prefix = format!("  \"{key}\":");
        let mut lines = source
            .lines()
            .filter(|line| !line.starts_with(&prefix))
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let last_member = lines.len() - 2;
        if lines[last_member].ends_with(',') {
            lines[last_member].pop();
        }
        lines.join("\n")
    }

    fn assert_state_rejects(label: &str, source: &[u8]) {
        assert!(
            state_contract(PositiveRunnerRole::RustVerifier)
                .parse(source)
                .is_err(),
            "accepted invalid runc state mutant: {label}"
        );
    }

    fn assert_identity_rejects(label: &str, source: &[u8]) {
        assert!(
            identity_contract(PositiveRunnerRole::RustVerifier)
                .parse(source)
                .is_err(),
            "accepted invalid process-identity mutant: {label}"
        );
    }

    #[test]
    fn parses_exact_created_and_stopped_runc_states() {
        let contract = state_contract(PositiveRunnerRole::RustVerifier);
        assert_eq!(contract.contract_id(), RUNTIME_STATE_CONTRACT_ID);
        assert_eq!(contract.maximum_source_bytes(), RUNC_STATE_MAX_SOURCE_BYTES);
        assert_eq!(contract.role(), PositiveRunnerRole::RustVerifier);

        let created = contract.parse(CREATED_STATE.as_bytes()).unwrap();
        assert_eq!(created.role(), PositiveRunnerRole::RustVerifier);
        assert_eq!(created.oci_version(), "1.3.0");
        assert_eq!(created.container_id(), "runner-0");
        assert_eq!(created.pid(), 123);
        assert_eq!(created.status(), B4ParsedRuncStateStatusV1::Created);
        assert_eq!(created.status().as_str(), "created");
        assert_eq!(created.bundle(), "/b4/bundle-0");
        assert_eq!(created.rootfs(), "/b4/rootfs-0");
        assert_eq!(created.created(), "2026-08-08T12:34:56.123456789Z");
        assert_eq!(created.owner(), "");

        let stopped = contract.parse(STOPPED_STATE.as_bytes()).unwrap();
        assert_eq!(stopped.pid(), 0);
        assert_eq!(stopped.status(), B4ParsedRuncStateStatusV1::Stopped);
        assert_eq!(stopped.status().as_str(), "stopped");

        let live_pid_boundary_source = CREATED_STATE.replace("\"pid\": 123", "\"pid\": 4194303");
        assert_eq!(
            contract
                .parse(live_pid_boundary_source.as_bytes())
                .unwrap()
                .pid(),
            LINUX_PID_MAX
        );
        for timestamp in ["0000-01-01T00:00:00Z", "2000-02-29T23:59:59.1Z"] {
            let source = CREATED_STATE.replace("2026-08-08T12:34:56.123456789Z", timestamp);
            assert_eq!(
                contract.parse(source.as_bytes()).unwrap().created(),
                timestamp
            );
        }

        let full_length_container_id = "a".repeat(RUNC_CONTAINER_ID_MAX_BYTES);
        assert_eq!(full_length_container_id.len(), 128);
        let full_length_id_source = CREATED_STATE.replace("runner-0", &full_length_container_id);
        assert_eq!(
            contract
                .parse(full_length_id_source.as_bytes())
                .unwrap()
                .container_id(),
            full_length_container_id
        );

        let maximum_component_path = format!("/{}", "a".repeat(128));
        assert_eq!(maximum_component_path[1..].len(), 128);
        let maximum_component_source =
            CREATED_STATE.replace("/b4/bundle-0", &maximum_component_path);
        assert_eq!(
            contract
                .parse(maximum_component_source.as_bytes())
                .unwrap()
                .bundle(),
            maximum_component_path
        );

        let maximum_component_count_path = format!("/{}", vec!["a"; 64].join("/"));
        assert_eq!(maximum_component_count_path[1..].split('/').count(), 64);
        let maximum_component_count_source =
            CREATED_STATE.replace("/b4/bundle-0", &maximum_component_count_path);
        assert_eq!(
            contract
                .parse(maximum_component_count_source.as_bytes())
                .unwrap()
                .bundle(),
            maximum_component_count_path
        );

        let mut maximum_path_components = vec!["a".repeat(128); 31];
        maximum_path_components.push("a".repeat(96));
        let maximum_path = format!("/{}", maximum_path_components.join("/"));
        assert_eq!(maximum_path.len(), RUNTIME_PATH_MAX_BYTES);
        let maximum_path_source = CREATED_STATE.replace("/b4/bundle-0", &maximum_path);
        assert_eq!(
            contract
                .parse(maximum_path_source.as_bytes())
                .unwrap()
                .bundle(),
            maximum_path
        );
    }

    #[test]
    fn rejects_runc_state_json_shape_and_exact_byte_mutants() {
        let duplicate_escaped = CREATED_STATE.replacen(
            "  \"id\": \"runner-0\",",
            "  \"i\\u0064\": \"shadow\",\n  \"id\": \"runner-0\",",
            1,
        );
        let unknown = CREATED_STATE.replacen(
            "  \"owner\": \"\"",
            "  \"extension\": 1,\n  \"owner\": \"\"",
            1,
        );
        let trailing = format!("{CREATED_STATE}\n");
        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend_from_slice(CREATED_STATE.as_bytes());
        let order = CREATED_STATE.replacen(
            "  \"id\": \"runner-0\",\n  \"pid\": 123,",
            "  \"pid\": 123,\n  \"id\": \"runner-0\",",
            1,
        );
        let whitespace = CREATED_STATE.replacen("  \"id\"", "    \"id\"", 1);
        let escaped = CREATED_STATE.replacen("runner-0", "runner\\u002d0", 1);

        for (label, source) in [
            ("escaped duplicate key", duplicate_escaped.as_bytes()),
            ("unknown key", unknown.as_bytes()),
            ("trailing newline", trailing.as_bytes()),
            ("BOM", bom.as_slice()),
            ("member order", order.as_bytes()),
            ("indentation", whitespace.as_bytes()),
            ("equivalent escape", escaped.as_bytes()),
        ] {
            assert_state_rejects(label, source);
        }
        for key in [
            "ociVersion",
            "id",
            "pid",
            "status",
            "bundle",
            "rootfs",
            "created",
            "owner",
        ] {
            let missing = state_without_member(CREATED_STATE, key);
            assert_state_rejects(&format!("missing {key}"), missing.as_bytes());
        }
        assert_state_rejects("byte limit", &vec![b' '; RUNC_STATE_MAX_SOURCE_BYTES + 1]);
    }

    #[test]
    fn rejects_runc_state_status_pid_and_id_mutants() {
        let overlong_id = "a".repeat(RUNC_CONTAINER_ID_MAX_BYTES + 1);
        let mutants = [
            (
                "status",
                CREATED_STATE.replace("\"created\"", "\"running\""),
            ),
            (
                "created PID zero",
                CREATED_STATE.replace("\"pid\": 123", "\"pid\": 0"),
            ),
            (
                "stopped live PID",
                CREATED_STATE.replace("\"status\": \"created\"", "\"status\": \"stopped\""),
            ),
            (
                "PID maximum plus one",
                CREATED_STATE.replace("\"pid\": 123", "\"pid\": 4194304"),
            ),
            (
                "negative PID",
                CREATED_STATE.replace("\"pid\": 123", "\"pid\": -1"),
            ),
            (
                "fractional PID",
                CREATED_STATE.replace("\"pid\": 123", "\"pid\": 1.5"),
            ),
            (
                "string PID",
                CREATED_STATE.replace("\"pid\": 123", "\"pid\": \"123\""),
            ),
            (
                "exponent PID",
                CREATED_STATE.replace("\"pid\": 123", "\"pid\": 1e2"),
            ),
            (
                "OCI version",
                CREATED_STATE.replace("\"1.3.0\"", "\"1.2.1\""),
            ),
            (
                "owner",
                CREATED_STATE.replace("\"owner\": \"\"", "\"owner\": \"root\""),
            ),
            ("empty ID", CREATED_STATE.replace("\"runner-0\"", "\"\"")),
            ("dot ID", CREATED_STATE.replace("\"runner-0\"", "\".\"")),
            (
                "ID byte bound",
                CREATED_STATE.replace("runner-0", &overlong_id),
            ),
            (
                "ID character",
                CREATED_STATE.replace("\"runner-0\"", "\"runner/0\""),
            ),
        ];
        for (label, source) in mutants {
            assert_state_rejects(label, source.as_bytes());
        }

        let annotations = CREATED_STATE.replacen(
            "  \"owner\": \"\"",
            "  \"annotations\": {},\n  \"owner\": \"\"",
            1,
        );
        assert_state_rejects("annotations", annotations.as_bytes());
    }

    #[test]
    fn rejects_runc_state_path_and_timestamp_mutants() {
        let overlong_component = format!("/b4/{}", "a".repeat(129));
        let too_many_components = format!("/{}", vec!["a"; 65].join("/"));
        let mut overlong_path_components = vec!["a".repeat(128); 31];
        overlong_path_components.push("a".repeat(97));
        let overlong_path = format!("/{}", overlong_path_components.join("/"));
        assert_eq!(overlong_path.len(), RUNTIME_PATH_MAX_BYTES + 1);
        assert_eq!(overlong_path[1..].split('/').count(), 32);
        assert!(
            overlong_path[1..]
                .split('/')
                .all(|component| component.len() <= RUNTIME_PATH_COMPONENT_MAX_BYTES)
        );
        let mutants = [
            (
                "trailing slash",
                CREATED_STATE.replace("/b4/bundle-0", "/b4/bundle-0/"),
            ),
            (
                "relative bundle",
                CREATED_STATE.replace("/b4/bundle-0", "b4/bundle-0"),
            ),
            ("root path", CREATED_STATE.replace("/b4/bundle-0", "/")),
            (
                "double slash",
                CREATED_STATE.replace("/b4/bundle-0", "/b4//bundle-0"),
            ),
            (
                "dot component",
                CREATED_STATE.replace("/b4/bundle-0", "/b4/../bundle-0"),
            ),
            (
                "path space",
                CREATED_STATE.replace("/b4/bundle-0", "/b4/bundle 0"),
            ),
            (
                "component bound",
                CREATED_STATE.replace("/b4/bundle-0", &overlong_component),
            ),
            (
                "component count",
                CREATED_STATE.replace("/b4/bundle-0", &too_many_components),
            ),
            (
                "total path byte bound",
                CREATED_STATE.replace("/b4/bundle-0", &overlong_path),
            ),
            (
                "invalid rootfs",
                CREATED_STATE.replace("/b4/rootfs-0", "/b4/../rootfs-0"),
            ),
            (
                "calendar date",
                CREATED_STATE.replace("2026-08-08T12:34:56.123456789Z", "2026-02-30T12:34:56Z"),
            ),
            (
                "non-UTC timestamp",
                CREATED_STATE.replace(
                    "2026-08-08T12:34:56.123456789Z",
                    "2026-08-08T12:34:56+00:00",
                ),
            ),
            (
                "fraction trailing zero",
                CREATED_STATE.replace("2026-08-08T12:34:56.123456789Z", "2026-08-08T12:34:56.120Z"),
            ),
            (
                "fraction digit bound",
                CREATED_STATE.replace(
                    "2026-08-08T12:34:56.123456789Z",
                    "2026-08-08T12:34:56.1234567891Z",
                ),
            ),
        ];
        for (label, source) in mutants {
            assert_state_rejects(label, source.as_bytes());
        }
    }

    #[test]
    fn parses_exact_process_identity_and_structurally_matches_created_state() {
        let state_contract = state_contract(PositiveRunnerRole::RustVerifier);
        let identity_contract = identity_contract(PositiveRunnerRole::RustVerifier);
        assert_eq!(
            identity_contract.contract_id(),
            RUNTIME_PROCESS_IDENTITY_CONTRACT_ID
        );
        assert_eq!(
            identity_contract.maximum_source_bytes(),
            PROCESS_IDENTITY_MAX_SOURCE_BYTES
        );
        assert_eq!(identity_contract.role(), PositiveRunnerRole::RustVerifier);

        let state = state_contract.parse(CREATED_STATE.as_bytes()).unwrap();
        let identity = identity_contract
            .parse(PROCESS_IDENTITY.as_bytes())
            .unwrap();
        assert_eq!(identity.role(), PositiveRunnerRole::RustVerifier);
        assert_eq!(
            identity.boot_id(),
            &[
                0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
                0x00, 0x00
            ]
        );
        assert_eq!(identity.pid().get(), 123);
        assert_eq!(identity.start_time_ticks().get(), 456);

        let matched = state.match_created_process_identity(&identity).unwrap();
        assert_eq!(matched.role(), PositiveRunnerRole::RustVerifier);
        assert_eq!(matched.state(), &state);
        assert_eq!(matched.process_identity(), &identity);

        let boundary_source =
            identity_source(BOOT_ID, u64::from(LINUX_PID_MAX), &u64::MAX.to_string());
        let boundary = identity_contract.parse(boundary_source.as_bytes()).unwrap();
        assert_eq!(boundary.pid().get(), LINUX_PID_MAX);
        assert_eq!(boundary.start_time_ticks().get(), u64::MAX);
    }

    #[test]
    fn rejects_process_identity_shape_jcs_and_uuid_mutants() {
        let duplicate_escaped = format!(
            "{{\"bootId\":\"{BOOT_ID}\",\"p\\u0069d\":123,\"pid\":123,\"startTimeTicks\":\"456\"}}"
        );
        let sources = [
            ("escaped duplicate", duplicate_escaped),
            (
                "unknown",
                format!(
                    "{{\"bootId\":\"{BOOT_ID}\",\"extension\":0,\"pid\":123,\"startTimeTicks\":\"456\"}}"
                ),
            ),
            ("trailing", format!("{PROCESS_IDENTITY}\n")),
            (
                "whitespace",
                format!(" {{\"bootId\":\"{BOOT_ID}\",\"pid\":123,\"startTimeTicks\":\"456\"}}"),
            ),
            (
                "order",
                format!("{{\"pid\":123,\"bootId\":\"{BOOT_ID}\",\"startTimeTicks\":\"456\"}}"),
            ),
            ("escape", PROCESS_IDENTITY.replace('-', "\\u002d")),
            (
                "UUID uppercase",
                identity_source(&BOOT_ID.to_ascii_uppercase(), 123, "456"),
            ),
            (
                "UUID version",
                identity_source("550e8400-e29b-31d4-a716-446655440000", 123, "456"),
            ),
            (
                "UUID variant",
                identity_source("550e8400-e29b-41d4-7716-446655440000", 123, "456"),
            ),
            (
                "UUID separator",
                identity_source("550e8400xe29b-41d4-a716-446655440000", 123, "456"),
            ),
            (
                "bootId wrong type",
                "{\"bootId\":1,\"pid\":123,\"startTimeTicks\":\"456\"}".to_owned(),
            ),
        ];

        for (label, source) in sources {
            assert_identity_rejects(label, source.as_bytes());
        }

        for (key, source) in [
            (
                "bootId",
                "{\"pid\":123,\"startTimeTicks\":\"456\"}".to_owned(),
            ),
            (
                "pid",
                format!("{{\"bootId\":\"{BOOT_ID}\",\"startTimeTicks\":\"456\"}}"),
            ),
            (
                "startTimeTicks",
                format!("{{\"bootId\":\"{BOOT_ID}\",\"pid\":123}}"),
            ),
        ] {
            assert_identity_rejects(&format!("missing {key}"), source.as_bytes());
        }

        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend_from_slice(PROCESS_IDENTITY.as_bytes());
        assert_identity_rejects("BOM", &bom);
        let oversized_source = [b' '; PROCESS_IDENTITY_MAX_SOURCE_BYTES + 1];
        assert_identity_rejects("byte limit", &oversized_source);
    }

    #[test]
    fn rejects_process_identity_pid_and_tick_mutants() {
        let sources = [
            (
                "PID wrong type",
                format!("{{\"bootId\":\"{BOOT_ID}\",\"pid\":true,\"startTimeTicks\":\"456\"}}"),
            ),
            (
                "ticks wrong type",
                format!("{{\"bootId\":\"{BOOT_ID}\",\"pid\":123,\"startTimeTicks\":false}}"),
            ),
            ("PID zero", identity_source(BOOT_ID, 0, "456")),
            (
                "PID maximum plus one",
                identity_source(BOOT_ID, u64::from(LINUX_PID_MAX) + 1, "456"),
            ),
            (
                "PID negative",
                format!("{{\"bootId\":\"{BOOT_ID}\",\"pid\":-1,\"startTimeTicks\":\"456\"}}"),
            ),
            (
                "PID fraction",
                format!("{{\"bootId\":\"{BOOT_ID}\",\"pid\":1.5,\"startTimeTicks\":\"456\"}}"),
            ),
            (
                "PID exponent",
                format!("{{\"bootId\":\"{BOOT_ID}\",\"pid\":1e2,\"startTimeTicks\":\"456\"}}"),
            ),
            (
                "PID string",
                format!("{{\"bootId\":\"{BOOT_ID}\",\"pid\":\"123\",\"startTimeTicks\":\"456\"}}"),
            ),
            (
                "ticks JSON number",
                format!("{{\"bootId\":\"{BOOT_ID}\",\"pid\":123,\"startTimeTicks\":456}}"),
            ),
            ("ticks empty", identity_source(BOOT_ID, 123, "")),
            ("ticks nondecimal", identity_source(BOOT_ID, 123, "4x6")),
            ("ticks zero", identity_source(BOOT_ID, 123, "0")),
            ("ticks leading zero", identity_source(BOOT_ID, 123, "0456")),
            ("ticks sign", identity_source(BOOT_ID, 123, "-1")),
            (
                "ticks overflow",
                identity_source(BOOT_ID, 123, "18446744073709551616"),
            ),
        ];
        for (label, source) in sources {
            assert_identity_rejects(label, source.as_bytes());
        }
    }

    #[test]
    fn structural_match_rejects_role_status_and_pid_mismatch() {
        let rust_state_contract = state_contract(PositiveRunnerRole::RustVerifier);
        let rust_identity_contract = identity_contract(PositiveRunnerRole::RustVerifier);
        let jvm_identity_contract = identity_contract(PositiveRunnerRole::JvmVerifier);
        let created = rust_state_contract.parse(CREATED_STATE.as_bytes()).unwrap();
        let stopped = rust_state_contract.parse(STOPPED_STATE.as_bytes()).unwrap();
        let rust_identity = rust_identity_contract
            .parse(PROCESS_IDENTITY.as_bytes())
            .unwrap();
        let jvm_identity = jvm_identity_contract
            .parse(PROCESS_IDENTITY.as_bytes())
            .unwrap();
        let other_pid = rust_identity_contract
            .parse(identity_source(BOOT_ID, 124, "456").as_bytes())
            .unwrap();

        assert!(
            created
                .match_created_process_identity(&jvm_identity)
                .is_err()
        );
        assert!(
            stopped
                .match_created_process_identity(&rust_identity)
                .is_err()
        );
        assert!(created.match_created_process_identity(&other_pid).is_err());
    }
}
