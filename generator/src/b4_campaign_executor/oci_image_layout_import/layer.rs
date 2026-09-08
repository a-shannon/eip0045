//! Streaming, bounded structural validation for one OCI gzip-compressed ustar layer.

use std::{
    collections::BTreeSet,
    io::{self, BufReader, Read},
};

use anyhow::{Context as _, Result, bail, ensure};
use crc32fast::Hasher as Crc32Hasher;
use flate2::bufread::DeflateDecoder;
use sha2::{Digest as _, Sha256};

use super::super::artifact_import_contract::{B4ImmutableArtifactRoleV1, OciLayerStreamLimitsV1};
use super::json::OciExpectedLayerV1;

const GZIP_HEADER: [u8; 10] = [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];
const GZIP_TRAILER_BYTES: usize = 8;
const USTAR_BLOCK_BYTES: usize = 512;
const USTAR_PATH_MAX_BYTES: usize = 240;
const IO_BUFFER_BYTES: usize = 16 * 1024;
const OCI_LAYER_MIN_COMPRESSED_BYTES: u64 = 20;
const OCI_LAYER_MIN_UNCOMPRESSED_BYTES: u64 = 1_024;
const OCI_LAYER_UID_GID: u64 = 65_532;
const CHANGESET_TRANSCRIPT_DOMAIN_V1: &[u8] = b"EIP-0045 OCI layer changeset transcript v1\0";

/// Inert structural receipt for one authenticated OCI layer.
///
/// No source bytes, path, descriptor, reader or payload crosses this boundary.
#[derive(Debug)]
pub(super) struct ImportedOciLayerReceiptV1 {
    compressed_byte_length: u64,
    compressed_sha256: [u8; 32],
    uncompressed_byte_length: u64,
    observed_uncompressed_sha256: [u8; 32],
    entry_count: u64,
    regular_file_count: u64,
    directory_count: u64,
    symbolic_link_count: u64,
    whiteout_count: u64,
    regular_file_bytes: u64,
    changeset_transcript_sha256: [u8; 32],
}

impl ImportedOciLayerReceiptV1 {
    pub(super) const fn compressed_byte_length(&self) -> u64 {
        self.compressed_byte_length
    }

    pub(super) const fn compressed_sha256(&self) -> [u8; 32] {
        self.compressed_sha256
    }

    pub(super) const fn uncompressed_byte_length(&self) -> u64 {
        self.uncompressed_byte_length
    }

    pub(super) const fn observed_uncompressed_sha256(&self) -> [u8; 32] {
        self.observed_uncompressed_sha256
    }

    pub(super) const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    pub(super) const fn regular_file_count(&self) -> u64 {
        self.regular_file_count
    }

    pub(super) const fn directory_count(&self) -> u64 {
        self.directory_count
    }

    pub(super) const fn symbolic_link_count(&self) -> u64 {
        self.symbolic_link_count
    }

    pub(super) const fn whiteout_count(&self) -> u64 {
        self.whiteout_count
    }

    pub(super) const fn regular_file_bytes(&self) -> u64 {
        self.regular_file_bytes
    }

    pub(super) const fn changeset_transcript_sha256(&self) -> [u8; 32] {
        self.changeset_transcript_sha256
    }
}

pub(super) struct OciLayerReplayEntryV1<'entry> {
    path: &'entry str,
    kind: OciLayerReplayEntryKindV1<'entry>,
}

impl<'entry> OciLayerReplayEntryV1<'entry> {
    pub(super) const fn regular_file(path: &'entry str, mode: u64, byte_length: u64) -> Self {
        Self {
            path,
            kind: OciLayerReplayEntryKindV1::RegularFile { mode, byte_length },
        }
    }

    pub(super) const fn directory(path: &'entry str, mode: u64, byte_length: u64) -> Self {
        Self {
            path,
            kind: OciLayerReplayEntryKindV1::Directory { mode, byte_length },
        }
    }

    pub(super) const fn symbolic_link(
        path: &'entry str,
        mode: u64,
        byte_length: u64,
        target: &'entry str,
    ) -> Self {
        Self {
            path,
            kind: OciLayerReplayEntryKindV1::SymbolicLink {
                mode,
                byte_length,
                target,
            },
        }
    }

    pub(super) const fn remove(
        path: &'entry str,
        mode: u64,
        byte_length: u64,
        target: &'entry str,
    ) -> Self {
        Self {
            path,
            kind: OciLayerReplayEntryKindV1::Whiteout {
                mode,
                byte_length,
                operation: OciLayerReplayWhiteoutV1::Remove { target },
            },
        }
    }

    pub(super) const fn opaque_directory(
        path: &'entry str,
        mode: u64,
        byte_length: u64,
        subject: &'entry str,
    ) -> Self {
        Self {
            path,
            kind: OciLayerReplayEntryKindV1::Whiteout {
                mode,
                byte_length,
                operation: OciLayerReplayWhiteoutV1::OpaqueDirectory { path: subject },
            },
        }
    }

    pub(super) const fn path(&self) -> &str {
        self.path
    }

    pub(super) const fn kind(&self) -> &OciLayerReplayEntryKindV1<'entry> {
        &self.kind
    }
}

pub(super) enum OciLayerReplayEntryKindV1<'entry> {
    RegularFile {
        mode: u64,
        byte_length: u64,
    },
    Directory {
        mode: u64,
        byte_length: u64,
    },
    SymbolicLink {
        mode: u64,
        byte_length: u64,
        target: &'entry str,
    },
    Whiteout {
        mode: u64,
        byte_length: u64,
        operation: OciLayerReplayWhiteoutV1<'entry>,
    },
}

pub(super) enum OciLayerReplayWhiteoutV1<'entry> {
    Remove { target: &'entry str },
    OpaqueDirectory { path: &'entry str },
}

pub(super) trait OciLayerReplaySinkV1 {
    fn begin_entry(&mut self, entry: &OciLayerReplayEntryV1<'_>) -> Result<()>;

    fn write_regular_file_chunk(&mut self, chunk: &[u8]) -> Result<()>;

    fn finish_entry(&mut self) -> Result<()>;
}

#[derive(Clone)]
pub(super) struct ChangesetTranscriptV1 {
    sha256: Sha256,
    entry_open: bool,
    regular_bytes_remaining: Option<u64>,
}

impl ChangesetTranscriptV1 {
    pub(super) fn new() -> Self {
        let mut sha256 = Sha256::new();
        sha256.update(CHANGESET_TRANSCRIPT_DOMAIN_V1);
        Self {
            sha256,
            entry_open: false,
            regular_bytes_remaining: None,
        }
    }

    pub(super) fn begin_entry(&mut self, entry: &OciLayerReplayEntryV1<'_>) -> Result<()> {
        ensure!(
            !self.entry_open,
            "OCI layer changeset transcript entry is already open"
        );
        self.sha256.update([0x01]);
        match entry.kind() {
            OciLayerReplayEntryKindV1::RegularFile { mode, byte_length } => {
                self.sha256.update([0x10]);
                self.update_entry_identity(entry.path(), *mode, *byte_length);
                self.regular_bytes_remaining = Some(*byte_length);
            }
            OciLayerReplayEntryKindV1::Directory { mode, byte_length } => {
                self.sha256.update([0x11]);
                self.update_entry_identity(entry.path(), *mode, *byte_length);
                self.regular_bytes_remaining = None;
            }
            OciLayerReplayEntryKindV1::SymbolicLink {
                mode,
                byte_length,
                target,
            } => {
                self.sha256.update([0x12]);
                self.update_entry_identity(entry.path(), *mode, *byte_length);
                self.update_string(target);
                self.regular_bytes_remaining = None;
            }
            OciLayerReplayEntryKindV1::Whiteout {
                mode,
                byte_length,
                operation,
            } => {
                match operation {
                    OciLayerReplayWhiteoutV1::Remove { target } => {
                        self.sha256.update([0x13]);
                        self.update_entry_identity(entry.path(), *mode, *byte_length);
                        self.update_string(target);
                    }
                    OciLayerReplayWhiteoutV1::OpaqueDirectory { path } => {
                        self.sha256.update([0x14]);
                        self.update_entry_identity(entry.path(), *mode, *byte_length);
                        self.update_string(path);
                    }
                }
                self.regular_bytes_remaining = None;
            }
        }
        self.entry_open = true;
        Ok(())
    }

    pub(super) fn write_regular_file_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        ensure!(
            self.entry_open,
            "OCI layer changeset transcript has no open entry"
        );
        ensure!(
            !chunk.is_empty() && chunk.len() <= IO_BUFFER_BYTES,
            "OCI layer replay chunk is outside its fixed streaming range"
        );
        let remaining = self
            .regular_bytes_remaining
            .as_mut()
            .context("OCI layer replay emitted payload for a non-regular entry")?;
        let chunk_bytes = u64::try_from(chunk.len()).expect("replay chunk length fits in u64");
        ensure!(
            chunk_bytes <= *remaining,
            "OCI layer replay emitted more regular-file bytes than declared"
        );
        *remaining -= chunk_bytes;
        self.sha256.update(chunk);
        Ok(())
    }

    pub(super) fn finish_entry(&mut self) -> Result<()> {
        ensure!(
            self.entry_open,
            "OCI layer changeset transcript has no open entry"
        );
        ensure!(
            self.regular_bytes_remaining.unwrap_or(0) == 0,
            "OCI layer replay ended before its regular-file payload"
        );
        self.sha256.update([0xff]);
        self.entry_open = false;
        self.regular_bytes_remaining = None;
        Ok(())
    }

    pub(super) fn finish(self) -> Result<[u8; 32]> {
        ensure!(
            !self.entry_open,
            "OCI layer changeset transcript ended with an open entry"
        );
        Ok(self.sha256.finalize().into())
    }

    fn update_entry_identity(&mut self, path: &str, mode: u64, byte_length: u64) {
        self.update_string(path);
        self.sha256.update(mode.to_le_bytes());
        self.sha256.update(byte_length.to_le_bytes());
    }

    fn update_string(&mut self, value: &str) {
        self.sha256.update(
            u64::try_from(value.len())
                .expect("bounded OCI layer string length fits in u64")
                .to_le_bytes(),
        );
        self.sha256.update(value.as_bytes());
    }
}

struct TranscriptReplaySinkV1 {
    transcript: ChangesetTranscriptV1,
}

impl TranscriptReplaySinkV1 {
    fn new() -> Self {
        Self {
            transcript: ChangesetTranscriptV1::new(),
        }
    }

    fn finish(self) -> Result<[u8; 32]> {
        self.transcript.finish()
    }
}

impl OciLayerReplaySinkV1 for TranscriptReplaySinkV1 {
    fn begin_entry(&mut self, entry: &OciLayerReplayEntryV1<'_>) -> Result<()> {
        self.transcript.begin_entry(entry)
    }

    fn write_regular_file_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        self.transcript.write_regular_file_chunk(chunk)
    }

    fn finish_entry(&mut self) -> Result<()> {
        self.transcript.finish_entry()
    }
}

struct AuthenticatedReplaySinkV1<'sink> {
    transcript: TranscriptReplaySinkV1,
    downstream: &'sink mut dyn OciLayerReplaySinkV1,
}

impl OciLayerReplaySinkV1 for AuthenticatedReplaySinkV1<'_> {
    fn begin_entry(&mut self, entry: &OciLayerReplayEntryV1<'_>) -> Result<()> {
        self.transcript.begin_entry(entry)?;
        self.downstream.begin_entry(entry)
    }

    fn write_regular_file_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        self.transcript.write_regular_file_chunk(chunk)?;
        self.downstream.write_regular_file_chunk(chunk)
    }

    fn finish_entry(&mut self) -> Result<()> {
        self.transcript.finish_entry()?;
        self.downstream.finish_entry()
    }
}

/// Validate one authenticated gzip member and its exact ustar payload.
///
/// The compressed reader is hard-limited by the authenticated descriptor. All
/// decompressed ceilings are selected internally from the closed OCI role.
pub(super) fn inspect_authenticated_oci_layer(
    source: &mut dyn Read,
    expectation: &OciExpectedLayerV1,
) -> Result<ImportedOciLayerReceiptV1> {
    inspect_authenticated_oci_layer_inner(source, expectation, None)
}

/// Revalidate one authenticated layer through the closed replay transcript.
///
/// The callback surface and concrete sink remain private to this module. A
/// caller receives a receipt only when the parser transcript and replay
/// transcript agree after complete gzip and descriptor authentication.
pub(super) fn replay_authenticated_oci_layer(
    source: &mut dyn Read,
    expectation: &OciExpectedLayerV1,
) -> Result<ImportedOciLayerReceiptV1> {
    let mut sink = TranscriptReplaySinkV1::new();
    let receipt = inspect_authenticated_oci_layer_inner(source, expectation, Some(&mut sink))?;
    let replay_transcript = sink.finish()?;
    ensure!(
        replay_transcript == receipt.changeset_transcript_sha256(),
        "OCI layer replay transcript differs from its parser transcript"
    );
    Ok(receipt)
}

/// Revalidate one authenticated layer while driving one private downstream sink.
///
/// The independent transcript sink remains in front of the downstream effect;
/// the caller receives no receipt unless the complete parser and replay
/// transcripts agree after gzip and descriptor authentication.
pub(super) fn replay_authenticated_oci_layer_with_sink(
    source: &mut dyn Read,
    expectation: &OciExpectedLayerV1,
    downstream: &mut dyn OciLayerReplaySinkV1,
) -> Result<ImportedOciLayerReceiptV1> {
    let mut sink = AuthenticatedReplaySinkV1 {
        transcript: TranscriptReplaySinkV1::new(),
        downstream,
    };
    let receipt = inspect_authenticated_oci_layer_inner(source, expectation, Some(&mut sink))?;
    let replay_transcript = sink.transcript.finish()?;
    ensure!(
        replay_transcript == receipt.changeset_transcript_sha256(),
        "OCI layer replay transcript differs from its parser transcript"
    );
    Ok(receipt)
}

fn inspect_authenticated_oci_layer_inner(
    source: &mut dyn Read,
    expectation: &OciExpectedLayerV1,
    sink: Option<&mut dyn OciLayerReplaySinkV1>,
) -> Result<ImportedOciLayerReceiptV1> {
    let oci_limits = B4ImmutableArtifactRoleV1::OciImageLayoutUstar
        .limits()
        .require_oci("OCI layer stream")?;
    let limits = oci_limits.layer_stream();
    let expected_compressed = expectation.compressed().byte_length();
    let expected_uncompressed = expectation.uncompressed_byte_length();
    ensure!(
        (OCI_LAYER_MIN_COMPRESSED_BYTES..=oci_limits.maximum_outer_ustar_member_payload_bytes())
            .contains(&expected_compressed),
        "OCI compressed layer length is outside its closed role range"
    );
    ensure!(
        (OCI_LAYER_MIN_UNCOMPRESSED_BYTES..=limits.maximum_uncompressed_tar_bytes())
            .contains(&expected_uncompressed)
            && expected_uncompressed % USTAR_BLOCK_BYTES as u64 == 0,
        "OCI declared uncompressed layer length is outside its closed ustar range"
    );

    let bounded = source.take(expected_compressed);
    let observed_compressed = ObservedCompressedReader::new(bounded);
    let mut buffered = BufReader::with_capacity(IO_BUFFER_BYTES, observed_compressed);
    let mut header = [0_u8; GZIP_HEADER.len()];
    buffered
        .read_exact(&mut header)
        .context("OCI gzip header is truncated")?;
    ensure!(header == GZIP_HEADER, "OCI gzip header is not canonical");

    let deflate_decoder = DeflateDecoder::new(buffered);
    let mut observed_ustar = ObservedUncompressedReader::new(
        deflate_decoder,
        expected_uncompressed,
        limits.maximum_uncompressed_tar_bytes(),
    );
    let inspection = inspect_exact_ustar(&mut observed_ustar, limits, sink)?;
    let mut decoded_probe = [0_u8; 1];
    ensure!(
        observed_ustar
            .read(&mut decoded_probe)
            .context("cannot probe OCI layer Deflate EOF")?
            == 0,
        "OCI layer has decompressed bytes after its exact ustar terminator"
    );
    let (deflate_decoder, observed_uncompressed, uncompressed_sha256, crc32) =
        observed_ustar.finish();
    ensure!(
        observed_uncompressed == expected_uncompressed,
        "OCI layer uncompressed length differs from its authenticated declaration"
    );

    let mut buffered = deflate_decoder.into_inner();
    let mut trailer = [0_u8; GZIP_TRAILER_BYTES];
    buffered
        .read_exact(&mut trailer)
        .context("OCI gzip trailer is truncated by its authenticated compressed length")?;
    ensure!(
        u32::from_le_bytes(trailer[..4].try_into().expect("fixed CRC32 slice")) == crc32,
        "OCI gzip CRC32 differs from the decompressed ustar bytes"
    );
    let expected_isize = u32::try_from(observed_uncompressed % (u64::from(u32::MAX) + 1))
        .context("OCI gzip ISIZE modulo does not fit in u32")?;
    ensure!(
        u32::from_le_bytes(trailer[4..].try_into().expect("fixed ISIZE slice")) == expected_isize,
        "OCI gzip ISIZE differs from the decompressed ustar length"
    );

    let mut trailing = [0_u8; 2];
    let trailing_count = buffered
        .read(&mut trailing[..1])
        .context("cannot probe OCI gzip member EOF")?;
    if trailing_count != 0 {
        if trailing[0] == 0x1f {
            let second = buffered
                .read(&mut trailing[1..])
                .context("cannot classify OCI gzip trailing bytes")?;
            if second == 1 && trailing[1] == 0x8b {
                bail!("OCI gzip stream contains a second member");
            }
        }
        bail!("OCI gzip stream has trailing bytes");
    }

    let observed_compressed = buffered.into_inner().finish();
    ensure!(
        observed_compressed.byte_length == expected_compressed,
        "OCI layer compressed length differs from its authenticated declaration"
    );
    ensure!(
        observed_compressed.sha256 == expectation.compressed().digest(),
        "OCI layer compressed SHA-256 differs from its authenticated descriptor"
    );

    Ok(ImportedOciLayerReceiptV1 {
        compressed_byte_length: observed_compressed.byte_length,
        compressed_sha256: observed_compressed.sha256,
        uncompressed_byte_length: observed_uncompressed,
        observed_uncompressed_sha256: uncompressed_sha256,
        entry_count: inspection.counters.entry_count,
        regular_file_count: inspection.counters.regular_file_count,
        directory_count: inspection.counters.directory_count,
        symbolic_link_count: inspection.counters.symbolic_link_count,
        whiteout_count: inspection.counters.whiteout_count,
        regular_file_bytes: inspection.counters.regular_file_bytes,
        changeset_transcript_sha256: inspection.changeset_transcript_sha256,
    })
}

struct ObservedCompressedReader<R> {
    inner: R,
    byte_length: u64,
    sha256: Sha256,
}

struct ObservedCompressedIdentityV1 {
    byte_length: u64,
    sha256: [u8; 32],
}

impl<R> ObservedCompressedReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            byte_length: 0,
            sha256: Sha256::new(),
        }
    }

    fn finish(self) -> ObservedCompressedIdentityV1 {
        ObservedCompressedIdentityV1 {
            byte_length: self.byte_length,
            sha256: self.sha256.finalize().into(),
        }
    }
}

impl<R: Read> Read for ObservedCompressedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.byte_length = self
            .byte_length
            .checked_add(u64::try_from(read).expect("read length fits in u64"))
            .ok_or_else(|| io::Error::other("OCI compressed byte count overflowed"))?;
        self.sha256.update(&buffer[..read]);
        Ok(read)
    }
}

struct ObservedUncompressedReader<R> {
    inner: R,
    byte_length: u64,
    declared_maximum: u64,
    role_maximum: u64,
    sha256: Sha256,
    crc32: Crc32Hasher,
}

impl<R> ObservedUncompressedReader<R> {
    fn new(inner: R, declared_maximum: u64, role_maximum: u64) -> Self {
        Self {
            inner,
            byte_length: 0,
            declared_maximum,
            role_maximum,
            sha256: Sha256::new(),
            crc32: Crc32Hasher::new(),
        }
    }

    fn finish(self) -> (R, u64, [u8; 32], u32) {
        (
            self.inner,
            self.byte_length,
            self.sha256.finalize().into(),
            self.crc32.finalize(),
        )
    }
}

impl<R: Read> Read for ObservedUncompressedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let maximum = self.declared_maximum.min(self.role_maximum);
        if self.byte_length == maximum {
            let mut probe = [0_u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::other(
                    "OCI layer exceeds its declared or role-specific uncompressed length",
                )),
            };
        }
        let remaining = maximum - self.byte_length;
        let request = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let read = self.inner.read(&mut buffer[..request])?;
        self.byte_length = self
            .byte_length
            .checked_add(u64::try_from(read).expect("read length fits in u64"))
            .ok_or_else(|| io::Error::other("OCI uncompressed byte count overflowed"))?;
        self.sha256.update(&buffer[..read]);
        self.crc32.update(&buffer[..read]);
        Ok(read)
    }
}

#[derive(Default)]
struct LayerCountersV1 {
    entry_count: u64,
    regular_file_count: u64,
    directory_count: u64,
    symbolic_link_count: u64,
    whiteout_count: u64,
    regular_file_bytes: u64,
}

impl LayerCountersV1 {
    fn add_entry(&mut self, limits: OciLayerStreamLimitsV1) -> Result<()> {
        self.entry_count =
            limits.checked_add_tar_entries(self.entry_count, 1, "OCI layer ustar")?;
        Ok(())
    }

    fn add_regular(&mut self, byte_length: u64, limits: OciLayerStreamLimitsV1) -> Result<()> {
        limits.validate_regular_file_payload_bytes(byte_length, "OCI layer ustar")?;
        self.regular_file_count = self
            .regular_file_count
            .checked_add(1)
            .context("OCI layer regular-file count overflowed")?;
        self.regular_file_bytes = self
            .regular_file_bytes
            .checked_add(byte_length)
            .context("OCI layer regular-file byte count overflowed")?;
        ensure!(
            self.regular_file_bytes <= limits.maximum_uncompressed_tar_bytes(),
            "OCI layer aggregate regular-file bytes exceed the closed layer-stream budget"
        );
        Ok(())
    }

    fn add_directory(&mut self) -> Result<()> {
        self.directory_count = self
            .directory_count
            .checked_add(1)
            .context("OCI layer directory count overflowed")?;
        Ok(())
    }

    fn add_symbolic_link(&mut self) -> Result<()> {
        self.symbolic_link_count = self
            .symbolic_link_count
            .checked_add(1)
            .context("OCI layer symbolic-link count overflowed")?;
        Ok(())
    }

    fn add_whiteout(&mut self) -> Result<()> {
        self.whiteout_count = self
            .whiteout_count
            .checked_add(1)
            .context("OCI layer whiteout count overflowed")?;
        Ok(())
    }
}

struct ParsedUstarHeaderV1<'header> {
    path: String,
    typeflag: u8,
    mode: u64,
    payload_bytes: u64,
    linkname: &'header str,
    whiteout_target: Option<String>,
}

struct LayerInspectionV1 {
    counters: LayerCountersV1,
    changeset_transcript_sha256: [u8; 32],
}

fn inspect_exact_ustar(
    source: &mut dyn Read,
    limits: OciLayerStreamLimitsV1,
    mut sink: Option<&mut dyn OciLayerReplaySinkV1>,
) -> Result<LayerInspectionV1> {
    let mut counters = LayerCountersV1::default();
    let mut previous_path: Option<String> = None;
    let mut whiteout_targets = BTreeSet::new();
    let mut transcript = ChangesetTranscriptV1::new();

    loop {
        let mut header = [0_u8; USTAR_BLOCK_BYTES];
        source
            .read_exact(&mut header)
            .context("OCI ustar header or terminator is truncated")?;
        if header.iter().all(|byte| *byte == 0) {
            let mut second = [0_u8; USTAR_BLOCK_BYTES];
            source
                .read_exact(&mut second)
                .context("OCI ustar second terminator block is truncated")?;
            ensure!(
                second.iter().all(|byte| *byte == 0),
                "OCI ustar second terminator block is not zero"
            );
            return Ok(LayerInspectionV1 {
                counters,
                changeset_transcript_sha256: transcript.finish()?,
            });
        }

        let parsed = parse_ustar_header(&header, previous_path.as_deref())?;
        previous_path = Some(parsed.path.clone());
        let payload_bytes =
            validate_and_count_ustar_entry(&parsed, &mut counters, &mut whiteout_targets, limits)?;
        let entry = replay_entry(&parsed);
        transcript.begin_entry(&entry)?;
        if let Some(replay_sink) = sink.as_deref_mut() {
            replay_sink
                .begin_entry(&entry)
                .context("OCI layer replay sink rejected a validated entry")?;
        }
        consume_payload_and_padding(source, payload_bytes, &mut transcript, &mut sink)?;
        transcript.finish_entry()?;
        if let Some(replay_sink) = sink.as_deref_mut() {
            replay_sink
                .finish_entry()
                .context("OCI layer replay sink rejected a completed entry")?;
        }
    }
}

fn replay_entry<'entry>(
    parsed: &'entry ParsedUstarHeaderV1<'entry>,
) -> OciLayerReplayEntryV1<'entry> {
    let kind = if let Some(target) = parsed.whiteout_target.as_deref() {
        let operation = if parsed
            .path
            .rsplit_once('/')
            .map_or(parsed.path.as_str(), |(_, basename)| basename)
            == ".wh..wh..opq"
        {
            OciLayerReplayWhiteoutV1::OpaqueDirectory { path: target }
        } else {
            OciLayerReplayWhiteoutV1::Remove { target }
        };
        OciLayerReplayEntryKindV1::Whiteout {
            mode: parsed.mode,
            byte_length: parsed.payload_bytes,
            operation,
        }
    } else {
        match parsed.typeflag {
            b'0' => OciLayerReplayEntryKindV1::RegularFile {
                mode: parsed.mode,
                byte_length: parsed.payload_bytes,
            },
            b'5' => OciLayerReplayEntryKindV1::Directory {
                mode: parsed.mode,
                byte_length: parsed.payload_bytes,
            },
            b'2' => OciLayerReplayEntryKindV1::SymbolicLink {
                mode: parsed.mode,
                byte_length: parsed.payload_bytes,
                target: parsed.linkname,
            },
            _ => unreachable!("validated OCI ustar entry type is closed"),
        }
    };
    OciLayerReplayEntryV1 {
        path: &parsed.path,
        kind,
    }
}

fn parse_ustar_header<'header>(
    header: &'header [u8; USTAR_BLOCK_BYTES],
    previous_path: Option<&str>,
) -> Result<ParsedUstarHeaderV1<'header>> {
    validate_ustar_checksum(header)?;
    ensure!(
        &header[257..263] == b"ustar\0",
        "OCI ustar magic is not exact"
    );
    ensure!(&header[263..265] == b"00", "OCI ustar version is not exact");
    ensure!(
        header[500..].iter().all(|byte| *byte == 0),
        "OCI ustar reserved header bytes are not zero"
    );

    let name = canonical_field_string(&header[..100], "OCI ustar name", false)?;
    let prefix = canonical_field_string(&header[345..500], "OCI ustar prefix", true)?;
    let header_path = if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    };
    let typeflag = header[156];
    let path = normalize_ustar_header_path(&header_path, typeflag)?;
    let (canonical_prefix, canonical_name) = canonical_ustar_split(&header_path)?;
    ensure!(
        prefix == canonical_prefix && name == canonical_name,
        "OCI ustar name/prefix split is not canonical"
    );
    if let Some(previous) = previous_path {
        ensure!(
            path.as_str() > previous,
            "OCI ustar member order is not canonical"
        );
    }

    let mode = canonical_octal(&header[100..108], "OCI ustar mode")?;
    ensure!(
        canonical_octal(&header[108..116], "OCI ustar uid")? == OCI_LAYER_UID_GID,
        "OCI ustar uid is not the fixed layer identity"
    );
    ensure!(
        canonical_octal(&header[116..124], "OCI ustar gid")? == OCI_LAYER_UID_GID,
        "OCI ustar gid is not the fixed layer identity"
    );
    let payload_bytes = canonical_octal(&header[124..136], "OCI ustar size")?;
    ensure!(
        canonical_octal(&header[136..148], "OCI ustar mtime")? == 0,
        "OCI ustar mtime is not zero"
    );
    ensure!(
        canonical_field_string(&header[265..297], "OCI ustar uname", true)?.is_empty()
            && canonical_field_string(&header[297..329], "OCI ustar gname", true)?.is_empty(),
        "OCI ustar uname/gname are not empty"
    );
    ensure!(
        canonical_octal(&header[329..337], "OCI ustar devmajor")? == 0
            && canonical_octal(&header[337..345], "OCI ustar devminor")? == 0,
        "OCI ustar device numbers are not zero"
    );
    let linkname = canonical_field_string(&header[157..257], "OCI ustar linkname", true)?;
    let whiteout_target = whiteout_target(&path)?;

    Ok(ParsedUstarHeaderV1 {
        path,
        typeflag,
        mode,
        payload_bytes,
        linkname,
        whiteout_target,
    })
}

fn validate_and_count_ustar_entry(
    parsed: &ParsedUstarHeaderV1<'_>,
    counters: &mut LayerCountersV1,
    whiteout_targets: &mut BTreeSet<String>,
    limits: OciLayerStreamLimitsV1,
) -> Result<u64> {
    counters.add_entry(limits)?;
    if let Some(target) = parsed.whiteout_target.as_deref() {
        ensure!(
            parsed.typeflag == b'0',
            "OCI whiteout is not a regular ustar entry"
        );
        ensure!(parsed.mode == 0, "OCI whiteout mode is not 0000");
        ensure!(
            parsed.payload_bytes == 0,
            "OCI whiteout payload is not empty"
        );
        ensure!(
            parsed.linkname.is_empty(),
            "OCI whiteout linkname is not empty"
        );
        insert_nonoverlapping_whiteout(whiteout_targets, target.to_owned())?;
        counters.add_whiteout()?;
    } else {
        match parsed.typeflag {
            b'0' => {
                ensure!(
                    parsed.mode == 0o444 || parsed.mode == 0o555,
                    "OCI regular-file mode is not 0444 or 0555"
                );
                ensure!(
                    parsed.linkname.is_empty(),
                    "OCI regular-file linkname is not empty"
                );
                counters.add_regular(parsed.payload_bytes, limits)?;
            }
            b'5' => {
                ensure!(parsed.mode == 0o555, "OCI directory mode is not 0555");
                ensure!(
                    parsed.payload_bytes == 0,
                    "OCI directory payload is not empty"
                );
                ensure!(
                    parsed.linkname.is_empty(),
                    "OCI directory linkname is not empty"
                );
                counters.add_directory()?;
            }
            b'2' => {
                ensure!(parsed.mode == 0o777, "OCI symbolic-link mode is not 0777");
                ensure!(
                    parsed.payload_bytes == 0,
                    "OCI symbolic-link payload is not empty"
                );
                validate_symlink_target(&parsed.path, parsed.linkname)?;
                counters.add_symbolic_link()?;
            }
            _ => bail!("OCI ustar entry type is outside 0/5/2"),
        }
    }
    Ok(parsed.payload_bytes)
}

fn validate_ustar_checksum(header: &[u8; USTAR_BLOCK_BYTES]) -> Result<()> {
    ensure!(
        header[154] == 0 && header[155] == b' ',
        "OCI ustar checksum encoding is not canonical"
    );
    let declared = octal_digits(&header[148..154], "OCI ustar checksum")?;
    let mut checksum_header = *header;
    checksum_header[148..156].fill(b' ');
    let observed: u64 = checksum_header.iter().map(|byte| u64::from(*byte)).sum();
    ensure!(
        declared == observed,
        "OCI ustar checksum differs from its header"
    );
    Ok(())
}

fn canonical_octal(field: &[u8], label: &str) -> Result<u64> {
    let (&terminator, digits) = field
        .split_last()
        .context("OCI ustar numeric field is empty")?;
    ensure!(terminator == 0, "{label} terminator is not canonical");
    octal_digits(digits, label)
}

fn octal_digits(digits: &[u8], label: &str) -> Result<u64> {
    ensure!(
        !digits.is_empty() && digits.iter().all(|byte| (b'0'..=b'7').contains(byte)),
        "{label} digits are not canonical octal"
    );
    digits.iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(8)
            .and_then(|value| value.checked_add(u64::from(*byte - b'0')))
            .with_context(|| format!("{label} value overflowed"))
    })
}

fn canonical_field_string<'field>(
    field: &'field [u8],
    label: &str,
    allow_empty: bool,
) -> Result<&'field str> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    ensure!(
        field[end..].iter().all(|byte| *byte == 0),
        "{label} has bytes after its first NUL"
    );
    ensure!(allow_empty || end != 0, "{label} is empty");
    std::str::from_utf8(&field[..end]).with_context(|| format!("{label} is not UTF-8"))
}

fn normalize_ustar_header_path(path: &str, typeflag: u8) -> Result<String> {
    ensure!(
        !path.is_empty() && path.len() <= USTAR_PATH_MAX_BYTES,
        "OCI ustar path length is outside its closed range"
    );
    ensure!(
        !path.starts_with('/'),
        "OCI ustar path is not relative POSIX"
    );
    let normalized = if typeflag == b'5' {
        ensure!(
            path.ends_with('/') && !path.ends_with("//"),
            "OCI directory header path does not have exactly one trailing slash"
        );
        &path[..path.len() - 1]
    } else {
        ensure!(
            !path.ends_with('/'),
            "OCI non-directory header path has a trailing slash"
        );
        path
    };
    validate_normalized_layer_path(normalized)?;
    Ok(normalized.to_owned())
}

fn validate_normalized_layer_path(path: &str) -> Result<()> {
    ensure!(!path.is_empty(), "OCI ustar normalized path is empty");
    ensure!(
        path.split('/')
            .all(|component| !component.is_empty() && component != "." && component != ".."),
        "OCI ustar path is not lexically root-contained and canonical"
    );
    Ok(())
}

fn canonical_ustar_split(path: &str) -> Result<(&str, &str)> {
    if path.len() <= 100 {
        return Ok(("", path));
    }
    for (separator, _) in path.rmatch_indices('/') {
        let prefix = &path[..separator];
        let name = &path[separator + 1..];
        if !name.is_empty() && prefix.len() <= 155 && name.len() <= 100 {
            return Ok((prefix, name));
        }
    }
    bail!("OCI ustar path cannot use the canonical name/prefix split")
}

fn validate_symlink_target(entry_path: &str, target: &str) -> Result<()> {
    ensure!(!target.is_empty(), "OCI symbolic-link target is empty");
    let mut resolved: Vec<&str> = if target.starts_with('/') {
        Vec::new()
    } else {
        let mut parent: Vec<&str> = entry_path.split('/').collect();
        parent.pop();
        parent
    };
    for component in target.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            ensure!(
                resolved.pop().is_some(),
                "OCI symbolic-link target escapes the layer root"
            );
        } else {
            resolved.push(component);
        }
    }
    Ok(())
}

fn whiteout_target(path: &str) -> Result<Option<String>> {
    let (parent, basename) = path.rsplit_once('/').unwrap_or(("", path));
    if !basename.starts_with(".wh.") {
        return Ok(None);
    }
    if basename == ".wh..wh..opq" {
        return Ok(Some(parent.to_owned()));
    }
    let target_name = &basename[4..];
    ensure!(
        !target_name.is_empty(),
        "OCI whiteout basename is outside the closed syntax"
    );
    let target = if parent.is_empty() {
        target_name.to_owned()
    } else {
        format!("{parent}/{target_name}")
    };
    validate_normalized_layer_path(&target)?;
    Ok(Some(target))
}

fn insert_nonoverlapping_whiteout(
    existing: &mut BTreeSet<String>,
    candidate: String,
) -> Result<()> {
    ensure!(
        !existing.contains(&candidate),
        "OCI whiteout conflicts with an intra-layer whiteout subtree"
    );
    if candidate.is_empty() {
        ensure!(
            existing.is_empty(),
            "OCI whiteout conflicts with an intra-layer whiteout subtree"
        );
    } else {
        ensure!(
            !existing.contains(""),
            "OCI whiteout conflicts with an intra-layer whiteout subtree"
        );
        for (separator, _) in candidate.match_indices('/') {
            ensure!(
                !existing.contains(&candidate[..separator]),
                "OCI whiteout conflicts with an intra-layer whiteout subtree"
            );
        }
        let descendant_prefix = format!("{candidate}/");
        if let Some(descendant) = existing.range(descendant_prefix.clone()..).next() {
            ensure!(
                !descendant.starts_with(&descendant_prefix),
                "OCI whiteout conflicts with an intra-layer whiteout subtree"
            );
        }
    }
    existing.insert(candidate);
    Ok(())
}

fn consume_payload_and_padding(
    source: &mut dyn Read,
    payload_bytes: u64,
    transcript: &mut ChangesetTranscriptV1,
    sink: &mut Option<&mut dyn OciLayerReplaySinkV1>,
) -> Result<()> {
    let mut remaining = payload_bytes;
    let mut buffer = [0_u8; IO_BUFFER_BYTES];
    while remaining != 0 {
        let request = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        source
            .read_exact(&mut buffer[..request])
            .context("OCI ustar member payload is truncated")?;
        transcript.write_regular_file_chunk(&buffer[..request])?;
        if let Some(replay_sink) = sink.as_deref_mut() {
            replay_sink
                .write_regular_file_chunk(&buffer[..request])
                .context("OCI layer replay sink rejected a regular-file chunk")?;
        }
        remaining -= u64::try_from(request).expect("buffer request fits in u64");
    }
    let padding = (USTAR_BLOCK_BYTES as u64 - payload_bytes % USTAR_BLOCK_BYTES as u64)
        % USTAR_BLOCK_BYTES as u64;
    let padding = usize::try_from(padding).expect("ustar padding fits in usize");
    source
        .read_exact(&mut buffer[..padding])
        .context("OCI ustar member padding is truncated")?;
    ensure!(
        buffer[..padding].iter().all(|byte| *byte == 0),
        "OCI ustar member padding is not zero"
    );
    Ok(())
}

#[cfg(test)]
fn test_only_replay_authenticated_oci_layer_with_sink(
    source: &mut dyn Read,
    expectation: &OciExpectedLayerV1,
    sink: &mut dyn OciLayerReplaySinkV1,
) -> Result<ImportedOciLayerReceiptV1> {
    inspect_authenticated_oci_layer_inner(source, expectation, Some(sink))
}

#[cfg(test)]
pub(super) fn test_only_authenticated_regular_layer_seal(
    semantic_layer_index: u64,
    path: &str,
    mode: u64,
    payload: &[u8],
) -> Result<super::AuthenticatedOciLayerSealV1> {
    let entry = OciLayerReplayEntryV1 {
        path,
        kind: OciLayerReplayEntryKindV1::RegularFile {
            mode,
            byte_length: u64::try_from(payload.len())?,
        },
    };
    let mut transcript = ChangesetTranscriptV1::new();
    transcript.begin_entry(&entry)?;
    for chunk in payload.chunks(IO_BUFFER_BYTES) {
        transcript.write_regular_file_chunk(chunk)?;
    }
    transcript.finish_entry()?;
    Ok(super::AuthenticatedOciLayerSealV1 {
        semantic_layer_index,
        authenticated_entry_count: 1,
        changeset_transcript_sha256: transcript.finish()?,
        _private: (),
    })
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum TestEntryKind<'entry> {
    Regular(&'entry [u8], u64),
    Directory,
    SymbolicLink(&'entry str),
    Whiteout,
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct TestEntry<'entry> {
    path: &'entry str,
    kind: TestEntryKind<'entry>,
}

/// Build a canonical one-regular-file fixture for parent importer tests.
///
/// Stored Deflate blocks are split at 65,535 bytes, so payloads above one MiB
/// remain bounded and do not require a second gzip member.
#[cfg(test)]
pub(super) fn test_only_canonical_one_regular_file_layer(
    path: &str,
    payload: &[u8],
    executable: bool,
) -> Result<(Vec<u8>, OciExpectedLayerV1)> {
    let entries = [TestEntry {
        path,
        kind: TestEntryKind::Regular(payload, if executable { 0o555 } else { 0o444 }),
    }];
    let ustar = test_only_ustar(&entries)?;
    let gzip = test_only_gzip_stored(&ustar);
    let expectation = test_only_expectation(&gzip, &ustar);
    Ok((gzip, expectation))
}

#[cfg(test)]
fn test_only_expectation(gzip: &[u8], ustar: &[u8]) -> OciExpectedLayerV1 {
    use super::json::OciBlobIdentityV1;

    OciExpectedLayerV1::test_only(
        OciBlobIdentityV1::test_only(
            Sha256::digest(gzip).into(),
            u64::try_from(gzip.len()).expect("fixture gzip length fits in u64"),
        ),
        u64::try_from(ustar.len()).expect("fixture ustar length fits in u64"),
        Sha256::digest(ustar).into(),
    )
}

#[cfg(test)]
fn test_only_ustar(entries: &[TestEntry<'_>]) -> Result<Vec<u8>> {
    let payload_blocks = entries.iter().try_fold(0_usize, |total, entry| {
        let payload = match entry.kind {
            TestEntryKind::Regular(payload, _) => payload.len(),
            TestEntryKind::Directory | TestEntryKind::SymbolicLink(_) | TestEntryKind::Whiteout => {
                0
            }
        };
        let padded = payload
            .checked_add(USTAR_BLOCK_BYTES - 1)
            .context("fixture payload rounding overflowed")?
            / USTAR_BLOCK_BYTES;
        total
            .checked_add(1 + padded)
            .context("fixture ustar block count overflowed")
    })?;
    let total_blocks = payload_blocks
        .checked_add(2)
        .context("fixture terminator block count overflowed")?;
    let mut source = Vec::new();
    source
        .try_reserve_exact(total_blocks * USTAR_BLOCK_BYTES)
        .context("cannot reserve bounded fixture ustar")?;
    for entry in entries {
        let mut header = [0_u8; USTAR_BLOCK_BYTES];
        let (prefix, name) = canonical_ustar_split(entry.path)?;
        write_test_field(&mut header[..100], name.as_bytes())?;
        write_test_field(&mut header[345..500], prefix.as_bytes())?;
        let (typeflag, mode, payload, linkname) = match entry.kind {
            TestEntryKind::Regular(payload, mode) => (b'0', mode, payload, ""),
            TestEntryKind::Directory => (b'5', 0o555, &[][..], ""),
            TestEntryKind::SymbolicLink(target) => (b'2', 0o777, &[][..], target),
            TestEntryKind::Whiteout => (b'0', 0, &[][..], ""),
        };
        write_test_octal(&mut header[100..108], mode)?;
        write_test_octal(&mut header[108..116], OCI_LAYER_UID_GID)?;
        write_test_octal(&mut header[116..124], OCI_LAYER_UID_GID)?;
        write_test_octal(
            &mut header[124..136],
            u64::try_from(payload.len()).expect("fixture payload length fits in u64"),
        )?;
        write_test_octal(&mut header[136..148], 0)?;
        header[156] = typeflag;
        write_test_field(&mut header[157..257], linkname.as_bytes())?;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        write_test_octal(&mut header[329..337], 0)?;
        write_test_octal(&mut header[337..345], 0)?;
        refresh_test_checksum(&mut header)?;
        source.extend_from_slice(&header);
        source.extend_from_slice(payload);
        let padding = (USTAR_BLOCK_BYTES - payload.len() % USTAR_BLOCK_BYTES) % USTAR_BLOCK_BYTES;
        source.resize(source.len() + padding, 0);
    }
    source.resize(source.len() + 2 * USTAR_BLOCK_BYTES, 0);
    Ok(source)
}

#[cfg(test)]
fn write_test_field(field: &mut [u8], value: &[u8]) -> Result<()> {
    ensure!(
        value.len() <= field.len(),
        "fixture field exceeds its ustar width"
    );
    field[..value.len()].copy_from_slice(value);
    Ok(())
}

#[cfg(test)]
fn write_test_octal(field: &mut [u8], value: u64) -> Result<()> {
    let terminator = field.len() - 1;
    let encoded = format!("{value:0terminator$o}");
    ensure!(
        encoded.len() == terminator,
        "fixture octal value exceeds its field"
    );
    field[..terminator].copy_from_slice(encoded.as_bytes());
    field[terminator] = 0;
    Ok(())
}

#[cfg(test)]
fn refresh_test_checksum(header: &mut [u8; USTAR_BLOCK_BYTES]) -> Result<()> {
    header[148..156].fill(b' ');
    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    let encoded = format!("{checksum:06o}\0 ");
    ensure!(encoded.len() == 8, "fixture checksum exceeds its field");
    header[148..156].copy_from_slice(encoded.as_bytes());
    Ok(())
}

#[cfg(test)]
fn test_only_gzip_stored(payload: &[u8]) -> Vec<u8> {
    let mut source = Vec::with_capacity(GZIP_HEADER.len() + payload.len() + 64);
    source.extend_from_slice(&GZIP_HEADER);
    let mut chunks = payload.chunks(u16::MAX as usize).peekable();
    while let Some(chunk) = chunks.next() {
        source.push(u8::from(chunks.peek().is_none()));
        let length = u16::try_from(chunk.len()).expect("stored block length fits in u16");
        source.extend_from_slice(&length.to_le_bytes());
        source.extend_from_slice(&(!length).to_le_bytes());
        source.extend_from_slice(chunk);
    }
    source.extend_from_slice(&crc32fast::hash(payload).to_le_bytes());
    source.extend_from_slice(
        &u32::try_from(payload.len() % (u32::MAX as usize + 1))
            .expect("fixture ISIZE modulo fits in u32")
            .to_le_bytes(),
    );
    source
}

#[cfg(test)]
fn test_only_gzip_compressed(payload: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write as _;

    use flate2::{Compression, write::DeflateEncoder};

    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(payload)
        .context("cannot encode compressed fixture Deflate stream")?;
    let deflate = encoder
        .finish()
        .context("cannot finish fixture Deflate stream")?;
    let mut source = Vec::with_capacity(GZIP_HEADER.len() + deflate.len() + GZIP_TRAILER_BYTES);
    source.extend_from_slice(&GZIP_HEADER);
    source.extend_from_slice(&deflate);
    source.extend_from_slice(&crc32fast::hash(payload).to_le_bytes());
    source.extend_from_slice(
        &u32::try_from(payload.len() % (u32::MAX as usize + 1))
            .expect("fixture ISIZE modulo fits in u32")
            .to_le_bytes(),
    );
    Ok(source)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const MEMBER_PATH: &str = "usr/bin/validator";

    #[derive(Debug, PartialEq, Eq)]
    enum RecordedReplayEntry {
        RegularFile {
            path: String,
            mode: u64,
            byte_length: u64,
        },
        WhiteoutRemove {
            path: String,
            target: String,
        },
        WhiteoutOpaque {
            path: String,
            directory: String,
        },
    }

    #[derive(Default)]
    struct RecordingReplaySink {
        entries: Vec<RecordedReplayEntry>,
        regular_payload: Vec<u8>,
        maximum_chunk: usize,
        finished_entries: usize,
    }

    impl OciLayerReplaySinkV1 for RecordingReplaySink {
        fn begin_entry(&mut self, entry: &OciLayerReplayEntryV1<'_>) -> Result<()> {
            let recorded = match entry.kind() {
                OciLayerReplayEntryKindV1::RegularFile { mode, byte_length } => {
                    RecordedReplayEntry::RegularFile {
                        path: entry.path().to_owned(),
                        mode: *mode,
                        byte_length: *byte_length,
                    }
                }
                OciLayerReplayEntryKindV1::Whiteout {
                    operation: OciLayerReplayWhiteoutV1::Remove { target },
                    ..
                } => RecordedReplayEntry::WhiteoutRemove {
                    path: entry.path().to_owned(),
                    target: (*target).to_owned(),
                },
                OciLayerReplayEntryKindV1::Whiteout {
                    operation: OciLayerReplayWhiteoutV1::OpaqueDirectory { path },
                    ..
                } => RecordedReplayEntry::WhiteoutOpaque {
                    path: entry.path().to_owned(),
                    directory: (*path).to_owned(),
                },
                OciLayerReplayEntryKindV1::Directory { .. }
                | OciLayerReplayEntryKindV1::SymbolicLink { .. } => {
                    panic!("fixture must contain only regular files and whiteouts")
                }
            };
            self.entries.push(recorded);
            Ok(())
        }

        fn write_regular_file_chunk(&mut self, chunk: &[u8]) -> Result<()> {
            assert!(!chunk.is_empty(), "replay must not emit empty chunks");
            assert!(
                chunk.len() <= IO_BUFFER_BYTES,
                "replay chunk exceeded its fixed streaming buffer"
            );
            self.maximum_chunk = self.maximum_chunk.max(chunk.len());
            self.regular_payload.extend_from_slice(chunk);
            Ok(())
        }

        fn finish_entry(&mut self) -> Result<()> {
            self.finished_entries += 1;
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    enum SinkFailurePoint {
        Begin,
        Chunk,
        Finish,
    }

    struct FailingReplaySink {
        failure: SinkFailurePoint,
        begin_calls: usize,
        chunk_calls: usize,
        finish_calls: usize,
    }

    impl FailingReplaySink {
        const fn new(failure: SinkFailurePoint) -> Self {
            Self {
                failure,
                begin_calls: 0,
                chunk_calls: 0,
                finish_calls: 0,
            }
        }
    }

    impl OciLayerReplaySinkV1 for FailingReplaySink {
        fn begin_entry(&mut self, _entry: &OciLayerReplayEntryV1<'_>) -> Result<()> {
            self.begin_calls += 1;
            if matches!(self.failure, SinkFailurePoint::Begin) {
                anyhow::bail!("injected begin failure");
            }
            Ok(())
        }

        fn write_regular_file_chunk(&mut self, _chunk: &[u8]) -> Result<()> {
            self.chunk_calls += 1;
            if matches!(self.failure, SinkFailurePoint::Chunk) {
                anyhow::bail!("injected chunk failure");
            }
            Ok(())
        }

        fn finish_entry(&mut self) -> Result<()> {
            self.finish_calls += 1;
            if matches!(self.failure, SinkFailurePoint::Finish) {
                anyhow::bail!("injected finish failure");
            }
            Ok(())
        }
    }

    fn one_entry_transcript(
        entry: &OciLayerReplayEntryV1<'_>,
        payload: &[u8],
        chunk_bytes: usize,
    ) -> [u8; 32] {
        let mut transcript = ChangesetTranscriptV1::new();
        transcript
            .begin_entry(entry)
            .expect("begin transcript entry");
        for chunk in payload.chunks(chunk_bytes) {
            transcript
                .write_regular_file_chunk(chunk)
                .expect("bounded transcript chunk");
        }
        transcript.finish_entry().expect("finish transcript entry");
        transcript.finish().expect("finish changeset transcript")
    }

    fn regular_transcript(path_order: &[&str], payload: &[u8], chunk_bytes: usize) -> [u8; 32] {
        let mut transcript = ChangesetTranscriptV1::new();
        for path in path_order {
            let entry = OciLayerReplayEntryV1 {
                path,
                kind: OciLayerReplayEntryKindV1::RegularFile {
                    mode: 0o444,
                    byte_length: payload.len() as u64,
                },
            };
            transcript
                .begin_entry(&entry)
                .expect("begin transcript entry");
            for chunk in payload.chunks(chunk_bytes) {
                transcript
                    .write_regular_file_chunk(chunk)
                    .expect("bounded transcript chunk");
            }
            transcript.finish_entry().expect("finish transcript entry");
        }
        transcript.finish().expect("finish changeset transcript")
    }

    fn canonical_fixture() -> (Vec<u8>, OciExpectedLayerV1) {
        test_only_canonical_one_regular_file_layer(MEMBER_PATH, b"ok\n", true)
            .expect("canonical layer fixture")
    }

    fn inspect(
        source: &[u8],
        expectation: &OciExpectedLayerV1,
    ) -> Result<ImportedOciLayerReceiptV1> {
        inspect_authenticated_oci_layer(&mut Cursor::new(source), expectation)
    }

    fn expectation_for(
        source: &[u8],
        uncompressed_byte_length: u64,
        diff_id: [u8; 32],
    ) -> OciExpectedLayerV1 {
        OciExpectedLayerV1::test_only(
            super::super::json::OciBlobIdentityV1::test_only(
                Sha256::digest(source).into(),
                source.len() as u64,
            ),
            uncompressed_byte_length,
            diff_id,
        )
    }

    fn assert_rejected(source: &[u8], expectation: &OciExpectedLayerV1, message: &str) {
        let error = inspect(source, expectation).expect_err("single-fault layer fixture must fail");
        let error_chain = format!("{error:#}");
        assert!(
            error_chain.contains(message),
            "unexpected rejection for {message:?}: {error:#}"
        );
    }

    fn assert_error_contains<T>(result: Result<T>, message: &str) {
        let Err(error) = result else {
            panic!("single-fault fixture must fail for {message:?}");
        };
        assert!(
            format!("{error:#}").contains(message),
            "unexpected rejection for {message:?}: {error:#}"
        );
    }

    fn mutated_ustar_fixture(mutator: impl FnOnce(&mut Vec<u8>)) -> (Vec<u8>, OciExpectedLayerV1) {
        let entries = [TestEntry {
            path: MEMBER_PATH,
            kind: TestEntryKind::Regular(b"ok\n", 0o555),
        }];
        mutated_entries_fixture(&entries, mutator)
    }

    fn mutated_entries_fixture(
        entries: &[TestEntry<'_>],
        mutator: impl FnOnce(&mut Vec<u8>),
    ) -> (Vec<u8>, OciExpectedLayerV1) {
        let mut ustar = test_only_ustar(entries).expect("canonical ustar fixture");
        mutator(&mut ustar);
        let gzip = test_only_gzip_stored(&ustar);
        let expectation = test_only_expectation(&gzip, &ustar);
        (gzip, expectation)
    }

    fn refresh_first_header(ustar: &mut [u8]) {
        let header: &mut [u8; USTAR_BLOCK_BYTES] = (&mut ustar[..USTAR_BLOCK_BYTES])
            .try_into()
            .expect("fixture has one complete ustar header");
        refresh_test_checksum(header).expect("fixture checksum fits its field");
    }

    #[test]
    fn canonical_exact_layer_is_accepted_with_inert_observations() {
        let (source, expectation) = canonical_fixture();
        let receipt = inspect(&source, &expectation).expect("canonical layer must pass");
        assert_eq!(receipt.compressed_byte_length(), source.len() as u64);
        let compressed_sha256: [u8; 32] = Sha256::digest(&source).into();
        assert_eq!(receipt.compressed_sha256(), compressed_sha256);
        assert_eq!(receipt.uncompressed_byte_length(), 2_048);
        assert_ne!(receipt.observed_uncompressed_sha256(), [0_u8; 32]);
        assert_eq!(receipt.entry_count(), 1);
        assert_eq!(receipt.regular_file_count(), 1);
        assert_eq!(receipt.directory_count(), 0);
        assert_eq!(receipt.symbolic_link_count(), 0);
        assert_eq!(receipt.whiteout_count(), 0);
        assert_eq!(receipt.regular_file_bytes(), 3);
    }

    #[test]
    fn replay_streams_bounded_regular_chunks_and_distinguishes_whiteouts() {
        let payload = vec![0x5a; 40_000];
        let entries = [
            TestEntry {
                path: ".wh.old",
                kind: TestEntryKind::Whiteout,
            },
            TestEntry {
                path: "payload",
                kind: TestEntryKind::Regular(&payload, 0o444),
            },
        ];
        let ustar = test_only_ustar(&entries).expect("named-whiteout replay fixture");
        let gzip = test_only_gzip_stored(&ustar);
        let expectation = test_only_expectation(&gzip, &ustar);
        let mut sink = RecordingReplaySink::default();
        let receipt = test_only_replay_authenticated_oci_layer_with_sink(
            &mut Cursor::new(&gzip),
            &expectation,
            &mut sink,
        )
        .expect("validated layer replay must complete");
        let closed_receipt = replay_authenticated_oci_layer(&mut Cursor::new(&gzip), &expectation)
            .expect("closed validated layer replay must complete");

        assert_eq!(receipt.entry_count(), 2);
        assert_eq!(
            receipt.changeset_transcript_sha256(),
            closed_receipt.changeset_transcript_sha256()
        );
        assert_eq!(sink.maximum_chunk, IO_BUFFER_BYTES);
        assert_eq!(sink.regular_payload, payload);
        assert_eq!(sink.finished_entries, 2);
        assert_eq!(
            sink.entries,
            [
                RecordedReplayEntry::WhiteoutRemove {
                    path: ".wh.old".to_owned(),
                    target: "old".to_owned(),
                },
                RecordedReplayEntry::RegularFile {
                    path: "payload".to_owned(),
                    mode: 0o444,
                    byte_length: 40_000,
                },
            ]
        );

        let opaque_entries = [TestEntry {
            path: ".wh..wh..opq",
            kind: TestEntryKind::Whiteout,
        }];
        let opaque_ustar = test_only_ustar(&opaque_entries).expect("opaque replay fixture");
        let opaque_gzip = test_only_gzip_stored(&opaque_ustar);
        let opaque_expectation = test_only_expectation(&opaque_gzip, &opaque_ustar);
        let mut opaque_sink = RecordingReplaySink::default();
        test_only_replay_authenticated_oci_layer_with_sink(
            &mut Cursor::new(&opaque_gzip),
            &opaque_expectation,
            &mut opaque_sink,
        )
        .expect("validated opaque layer replay must complete");
        assert_eq!(
            opaque_sink.entries,
            [RecordedReplayEntry::WhiteoutOpaque {
                path: ".wh..wh..opq".to_owned(),
                directory: String::new(),
            }]
        );
        assert_eq!(opaque_sink.finished_entries, 1);
    }

    #[test]
    fn changeset_transcript_binds_order_kind_and_content_but_not_chunk_boundaries() {
        let payload = vec![0x42; 40_000];
        let canonical = regular_transcript(&["a", "b"], &payload, IO_BUFFER_BYTES);
        assert_eq!(
            canonical,
            regular_transcript(&["a", "b"], &payload, 1_000),
            "regular-file transcript must be invariant under bounded chunking"
        );
        assert_ne!(
            canonical,
            regular_transcript(&["b", "a"], &payload, IO_BUFFER_BYTES),
            "entry permutation must change the transcript"
        );
        assert_ne!(
            canonical,
            regular_transcript(&["a"], &payload, IO_BUFFER_BYTES),
            "entry omission must change the transcript"
        );
        let mut changed_payload = payload;
        changed_payload[20_000] ^= 1;
        assert_ne!(
            canonical,
            regular_transcript(&["a", "b"], &changed_payload, IO_BUFFER_BYTES),
            "regular-file content must change the transcript"
        );

        let mut remove = ChangesetTranscriptV1::new();
        let remove_entry = OciLayerReplayEntryV1 {
            path: ".wh.old",
            kind: OciLayerReplayEntryKindV1::Whiteout {
                mode: 0,
                byte_length: 0,
                operation: OciLayerReplayWhiteoutV1::Remove { target: "old" },
            },
        };
        remove.begin_entry(&remove_entry).expect("remove whiteout");
        remove.finish_entry().expect("finish remove whiteout");
        let remove = remove.finish().expect("remove transcript");

        let mut opaque = ChangesetTranscriptV1::new();
        let opaque_entry = OciLayerReplayEntryV1 {
            path: ".wh.old",
            kind: OciLayerReplayEntryKindV1::Whiteout {
                mode: 0,
                byte_length: 0,
                operation: OciLayerReplayWhiteoutV1::OpaqueDirectory { path: "old" },
            },
        };
        opaque.begin_entry(&opaque_entry).expect("opaque whiteout");
        opaque.finish_entry().expect("finish opaque whiteout");
        let opaque = opaque.finish().expect("opaque transcript");
        assert_ne!(
            remove, opaque,
            "Remove and Opaque operations must have distinct transcript tags"
        );
    }

    #[test]
    fn changeset_transcript_isolates_path_mode_length_kind_and_symlink_target() {
        let payload = b"payload";
        let regular = |path, mode| OciLayerReplayEntryV1 {
            path,
            kind: OciLayerReplayEntryKindV1::RegularFile {
                mode,
                byte_length: payload.len() as u64,
            },
        };
        let canonical = one_entry_transcript(&regular("bin/tool", 0o555), payload, 3);
        assert_ne!(
            canonical,
            one_entry_transcript(&regular("bin/other", 0o555), payload, 3),
            "path must change the transcript"
        );
        assert_ne!(
            canonical,
            one_entry_transcript(&regular("bin/tool", 0o444), payload, 3),
            "mode must change the transcript"
        );

        let empty_regular = OciLayerReplayEntryV1 {
            path: "empty",
            kind: OciLayerReplayEntryKindV1::RegularFile {
                mode: 0o444,
                byte_length: 0,
            },
        };
        let empty_directory = OciLayerReplayEntryV1 {
            path: "empty",
            kind: OciLayerReplayEntryKindV1::Directory {
                mode: 0o444,
                byte_length: 0,
            },
        };
        assert_ne!(
            one_entry_transcript(&empty_regular, &[], 1),
            one_entry_transcript(&empty_directory, &[], 1),
            "entry kind must change the transcript"
        );

        let directory_zero = OciLayerReplayEntryV1 {
            path: "dir",
            kind: OciLayerReplayEntryKindV1::Directory {
                mode: 0o555,
                byte_length: 0,
            },
        };
        let directory_one = OciLayerReplayEntryV1 {
            path: "dir",
            kind: OciLayerReplayEntryKindV1::Directory {
                mode: 0o555,
                byte_length: 1,
            },
        };
        assert_ne!(
            one_entry_transcript(&directory_zero, &[], 1),
            one_entry_transcript(&directory_one, &[], 1),
            "declared length must change the transcript"
        );

        let symlink = |target| OciLayerReplayEntryV1 {
            path: "bin/link",
            kind: OciLayerReplayEntryKindV1::SymbolicLink {
                mode: 0o777,
                byte_length: 0,
                target,
            },
        };
        assert_ne!(
            one_entry_transcript(&symlink("tool-a"), &[], 1),
            one_entry_transcript(&symlink("tool-b"), &[], 1),
            "symlink target must change the transcript"
        );
    }

    #[test]
    fn sink_and_late_authentication_failures_never_return_completion() {
        let (source, expectation) = canonical_fixture();
        for (failure, expected_context, expected_calls) in [
            (
                SinkFailurePoint::Begin,
                "rejected a validated entry",
                (1, 0, 0),
            ),
            (
                SinkFailurePoint::Chunk,
                "rejected a regular-file chunk",
                (1, 1, 0),
            ),
            (
                SinkFailurePoint::Finish,
                "rejected a completed entry",
                (1, 1, 1),
            ),
        ] {
            let mut sink = FailingReplaySink::new(failure);
            let error = test_only_replay_authenticated_oci_layer_with_sink(
                &mut Cursor::new(&source),
                &expectation,
                &mut sink,
            )
            .expect_err("sink failure must prevent a completion receipt");
            assert!(
                format!("{error:#}").contains(expected_context),
                "unexpected sink failure: {error:#}"
            );
            assert_eq!(
                (sink.begin_calls, sink.chunk_calls, sink.finish_calls),
                expected_calls
            );
        }

        let mut late_crc_failure = source;
        let crc_offset = late_crc_failure.len() - GZIP_TRAILER_BYTES;
        late_crc_failure[crc_offset] ^= 1;
        let late_expectation = expectation_for(
            &late_crc_failure,
            expectation.uncompressed_byte_length(),
            [0x77; 32],
        );
        let mut sink = RecordingReplaySink::default();
        let error = test_only_replay_authenticated_oci_layer_with_sink(
            &mut Cursor::new(&late_crc_failure),
            &late_expectation,
            &mut sink,
        )
        .expect_err("late CRC failure must prevent a completion receipt");
        assert!(
            format!("{error:#}").contains("gzip CRC32 differs"),
            "unexpected late failure: {error:#}"
        );
        assert_eq!(
            sink.finished_entries, 1,
            "late failure fixture must reach the completed entry callback"
        );
    }

    #[test]
    fn empty_layer_and_mismatching_future_diff_id_are_accepted_at_this_boundary() {
        let empty_ustar = test_only_ustar(&[]).expect("empty canonical layer");
        let empty_gzip = test_only_gzip_stored(&empty_ustar);
        let empty_receipt = inspect(
            &empty_gzip,
            &expectation_for(&empty_gzip, empty_ustar.len() as u64, [0x41; 32]),
        )
        .expect("empty layer must pass");
        assert_eq!(empty_receipt.entry_count(), 0);

        let (source, expectation) = canonical_fixture();
        let mismatching_diff_id =
            expectation_for(&source, expectation.uncompressed_byte_length(), [0x99; 32]);
        let receipt = inspect(&source, &mismatching_diff_id)
            .expect("structural boundary must not compare the future DiffID");
        assert_ne!(receipt.observed_uncompressed_sha256(), [0x99; 32]);
    }

    #[test]
    fn strongly_compressible_layer_has_no_ratio_rejection() {
        let payload = vec![b'x'; 2 * 1024 * 1024];
        let entries = [TestEntry {
            path: MEMBER_PATH,
            kind: TestEntryKind::Regular(&payload, 0o444),
        }];
        let ustar = test_only_ustar(&entries).expect("large canonical ustar");
        let gzip = test_only_gzip_compressed(&ustar).expect("compressed gzip fixture");
        assert!(gzip.len() * 100 < ustar.len());
        let expectation = test_only_expectation(&gzip, &ustar);
        let receipt = inspect(&gzip, &expectation).expect("compression ratio is not normative");
        assert_eq!(receipt.regular_file_bytes(), payload.len() as u64);
    }

    #[test]
    fn test_helper_splits_large_payload_across_stored_deflate_blocks() {
        let payload = vec![0x5a; 1_100_000];
        let (gzip, expectation) =
            test_only_canonical_one_regular_file_layer("artifact", &payload, false)
                .expect("large stored fixture");
        let receipt = inspect(&gzip, &expectation).expect("multi-block stored Deflate must pass");
        assert_eq!(receipt.regular_file_bytes(), payload.len() as u64);
    }

    #[test]
    fn gzip_header_crc_isize_member_and_digest_are_exact() {
        let (source, expectation) = canonical_fixture();
        let mut header = source.clone();
        header[9] = 3;
        assert_rejected(&header, &expectation, "gzip header is not canonical");

        let mut crc = source.clone();
        let crc_offset = crc.len() - 8;
        crc[crc_offset] ^= 1;
        assert_rejected(&crc, &expectation, "gzip CRC32 differs");

        let mut isize = source.clone();
        let isize_offset = isize.len() - 4;
        isize[isize_offset] ^= 1;
        assert_rejected(&isize, &expectation, "gzip ISIZE differs");

        let mut second = source.clone();
        second.extend_from_slice(&source);
        let second_expectation = test_only_expectation(
            &second,
            &test_only_ustar(&[TestEntry {
                path: MEMBER_PATH,
                kind: TestEntryKind::Regular(b"ok\n", 0o555),
            }])
            .expect("ustar"),
        );
        assert_rejected(&second, &second_expectation, "second member");

        let mut trailing = source.clone();
        trailing.push(0);
        let trailing_expectation = OciExpectedLayerV1::test_only(
            super::super::json::OciBlobIdentityV1::test_only(
                Sha256::digest(&trailing).into(),
                trailing.len() as u64,
            ),
            expectation.uncompressed_byte_length(),
            [0_u8; 32],
        );
        assert_rejected(&trailing, &trailing_expectation, "trailing bytes");

        let wrong_digest = OciExpectedLayerV1::test_only(
            super::super::json::OciBlobIdentityV1::test_only([0x7f; 32], source.len() as u64),
            expectation.uncompressed_byte_length(),
            [0_u8; 32],
        );
        assert_rejected(&source, &wrong_digest, "compressed SHA-256 differs");
    }

    #[test]
    fn every_gzip_header_field_and_flag_value_is_exact() {
        let (source, expectation) = canonical_fixture();
        let uncompressed_byte_length = expectation.uncompressed_byte_length();

        for offset in [0_usize, 1, 2, 4, 5, 6, 7, 8, 9] {
            let mut mutated = source.clone();
            mutated[offset] = mutated[offset].wrapping_add(1);
            assert_rejected(
                &mutated,
                &expectation_for(&mutated, uncompressed_byte_length, [0_u8; 32]),
                "gzip header is not canonical",
            );
        }

        for flags in 1..=u8::MAX {
            let mut mutated = source.clone();
            mutated[3] = flags;
            assert_rejected(
                &mutated,
                &expectation_for(&mutated, uncompressed_byte_length, [0_u8; 32]),
                "gzip header is not canonical",
            );
        }
    }

    #[test]
    fn gzip_deflate_and_trailer_truncations_invalid_stream_and_output_overrun_fail() {
        let (source, expectation) = canonical_fixture();
        assert_rejected(&source[..5], &expectation, "OCI gzip header is truncated");

        let mut deflate_truncated = source.clone();
        deflate_truncated.truncate(deflate_truncated.len() - GZIP_TRAILER_BYTES - 1);
        assert_rejected(
            &deflate_truncated,
            &expectation_for(
                &deflate_truncated,
                expectation.uncompressed_byte_length(),
                [0_u8; 32],
            ),
            "OCI ustar second terminator block is truncated",
        );

        let trailer_truncated = &source[..source.len() - 4];
        assert_rejected(
            trailer_truncated,
            &expectation_for(
                trailer_truncated,
                expectation.uncompressed_byte_length(),
                [0_u8; 32],
            ),
            "OCI gzip trailer is truncated by its authenticated compressed length",
        );

        let mut invalid_deflate = source.clone();
        invalid_deflate[GZIP_HEADER.len()] = 0x07;
        assert_rejected(
            &invalid_deflate,
            &expectation_for(
                &invalid_deflate,
                expectation.uncompressed_byte_length(),
                [0_u8; 32],
            ),
            "corrupt deflate stream",
        );

        let output_overrun = expectation_for(&source, 1_536, [0_u8; 32]);
        assert_rejected(
            &source,
            &output_overrun,
            "exceeds its declared or role-specific uncompressed length",
        );
    }

    #[test]
    fn authenticated_lengths_reject_under_and_over_without_large_allocations() {
        let (source, expectation) = canonical_fixture();
        let declared_short = OciExpectedLayerV1::test_only(
            super::super::json::OciBlobIdentityV1::test_only(
                Sha256::digest(&source).into(),
                source.len() as u64 - 1,
            ),
            expectation.uncompressed_byte_length(),
            [0_u8; 32],
        );
        assert_rejected(
            &source,
            &declared_short,
            "OCI gzip trailer is truncated by its authenticated compressed length",
        );

        let declared_long = OciExpectedLayerV1::test_only(
            super::super::json::OciBlobIdentityV1::test_only(
                Sha256::digest(&source).into(),
                source.len() as u64 + 1,
            ),
            expectation.uncompressed_byte_length(),
            [0_u8; 32],
        );
        assert_rejected(
            &source,
            &declared_long,
            "compressed length differs from its authenticated declaration",
        );

        let declared_uncompressed_short = expectation_for(&source, 1_536, [0_u8; 32]);
        assert_rejected(
            &source,
            &declared_uncompressed_short,
            "exceeds its declared or role-specific uncompressed length",
        );

        let declared_uncompressed_long = expectation_for(&source, 2_560, [0_u8; 32]);
        assert_rejected(
            &source,
            &declared_uncompressed_long,
            "uncompressed length differs from its authenticated declaration",
        );
    }

    #[test]
    fn ustar_checksum_octal_metadata_and_padding_are_exact() {
        let (bad_checksum, checksum_expectation) = mutated_ustar_fixture(|ustar| ustar[0] ^= 1);
        assert_rejected(&bad_checksum, &checksum_expectation, "checksum differs");

        let (bad_octal, octal_expectation) = mutated_ustar_fixture(|ustar| {
            ustar[100] = b' ';
            refresh_first_header(ustar);
        });
        assert_rejected(&bad_octal, &octal_expectation, "canonical octal");

        let (bad_uid, uid_expectation) = mutated_ustar_fixture(|ustar| {
            write_test_octal(&mut ustar[108..116], 0).expect("uid");
            refresh_first_header(ustar);
        });
        assert_rejected(&bad_uid, &uid_expectation, "uid is not");

        let (bad_padding, padding_expectation) = mutated_ustar_fixture(|ustar| {
            ustar[USTAR_BLOCK_BYTES + 3] = 1;
        });
        assert_rejected(&bad_padding, &padding_expectation, "padding is not zero");
    }

    #[test]
    fn payload_and_padding_truncations_reach_their_exact_parser_predicates() {
        let entries = [TestEntry {
            path: "file",
            kind: TestEntryKind::Regular(b"abc", 0o444),
        }];
        let ustar = test_only_ustar(&entries).expect("payload truncation fixture");
        let limits = B4ImmutableArtifactRoleV1::OciImageLayoutUstar
            .limits()
            .require_oci("test")
            .expect("OCI limits")
            .layer_stream();

        let mut payload_truncated = Cursor::new(&ustar[..USTAR_BLOCK_BYTES + 2]);
        assert_error_contains(
            inspect_exact_ustar(&mut payload_truncated, limits, None),
            "OCI ustar member payload is truncated",
        );

        let padding_bytes = USTAR_BLOCK_BYTES - 3;
        let mut padding_truncated =
            Cursor::new(&ustar[..USTAR_BLOCK_BYTES + 3 + padding_bytes - 1]);
        assert_error_contains(
            inspect_exact_ustar(&mut padding_truncated, limits, None),
            "OCI ustar member padding is truncated",
        );
    }

    #[test]
    fn semantically_correct_noncanonical_ustar_checksum_encodings_are_rejected() {
        let (space_padded, expectation) = mutated_ustar_fixture(|ustar| {
            let header = &mut ustar[..USTAR_BLOCK_BYTES];
            header[148..156].fill(b' ');
            let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
            let encoded = format!("{checksum:>6o}\0 ");
            assert_eq!(encoded.len(), 8);
            header[148..156].copy_from_slice(encoded.as_bytes());
        });
        assert_rejected(
            &space_padded,
            &expectation,
            "digits are not canonical octal",
        );

        let (base_256, expectation) = mutated_ustar_fixture(|ustar| {
            let header = &mut ustar[..USTAR_BLOCK_BYTES];
            header[148..156].fill(b' ');
            let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
            let mut encoded = checksum.to_be_bytes();
            encoded[0] |= 0x80;
            header[148..156].copy_from_slice(&encoded);
        });
        assert_rejected(&base_256, &expectation, "encoding is not canonical");
    }

    #[test]
    fn nul_tail_and_linkname_utf8_are_canonical() {
        let (source, expectation) = mutated_ustar_fixture(|ustar| {
            ustar[MEMBER_PATH.len() + 1] = b'x';
            refresh_first_header(ustar);
        });
        assert_rejected(
            &source,
            &expectation,
            "OCI ustar name has bytes after its first NUL",
        );

        let symlink = [TestEntry {
            path: "link",
            kind: TestEntryKind::SymbolicLink("target"),
        }];
        let (source, expectation) = mutated_entries_fixture(&symlink, |ustar| {
            ustar[157] = 0xff;
            refresh_first_header(ustar);
        });
        assert_rejected(&source, &expectation, "OCI ustar linkname is not UTF-8");
    }

    #[test]
    fn every_fixed_ustar_metadata_group_is_causally_rejected() {
        let mutations: &[(usize, u8, &str)] = &[
            (257, b'v', "magic is not exact"),
            (263, b'1', "version is not exact"),
            (265, b'u', "uname/gname are not empty"),
            (297, b'g', "uname/gname are not empty"),
            (500, 1, "reserved header bytes are not zero"),
        ];
        for &(offset, value, message) in mutations {
            let (source, expectation) = mutated_ustar_fixture(|ustar| {
                ustar[offset] = value;
                refresh_first_header(ustar);
            });
            assert_rejected(&source, &expectation, message);
        }

        for (range, value, message) in [
            (116..124, 0, "gid is not"),
            (136..148, 1, "mtime is not zero"),
            (329..337, 1, "device numbers are not zero"),
            (337..345, 1, "device numbers are not zero"),
        ] {
            let (source, expectation) = mutated_ustar_fixture(|ustar| {
                write_test_octal(&mut ustar[range], value).expect("metadata octal fixture");
                refresh_first_header(ustar);
            });
            assert_rejected(&source, &expectation, message);
        }
    }

    #[test]
    fn ustar_path_order_unique_type_and_mode_are_closed() {
        let entries = [
            TestEntry {
                path: "b/",
                kind: TestEntryKind::Directory,
            },
            TestEntry {
                path: "a/",
                kind: TestEntryKind::Directory,
            },
        ];
        let ustar = test_only_ustar(&entries).expect("reordered ustar");
        let gzip = test_only_gzip_stored(&ustar);
        assert_rejected(
            &gzip,
            &test_only_expectation(&gzip, &ustar),
            "order is not canonical",
        );

        let (bad_type, type_expectation) = mutated_ustar_fixture(|ustar| {
            ustar[156] = b'x';
            refresh_first_header(ustar);
        });
        assert_rejected(&bad_type, &type_expectation, "outside 0/5/2");

        let (bad_mode, mode_expectation) = mutated_ustar_fixture(|ustar| {
            write_test_octal(&mut ustar[100..108], 0o644).expect("mode");
            refresh_first_header(ustar);
        });
        assert_rejected(&bad_mode, &mode_expectation, "mode is not 0444 or 0555");
    }

    #[test]
    fn path_lexical_utf8_length_and_name_prefix_boundaries_are_exact() {
        for (path, message) in [
            ("/absolute", "path is not relative POSIX"),
            (
                "a/./b",
                "path is not lexically root-contained and canonical",
            ),
            (
                "a/../b",
                "path is not lexically root-contained and canonical",
            ),
            ("a//b", "path is not lexically root-contained and canonical"),
        ] {
            let entries = [TestEntry {
                path,
                kind: TestEntryKind::Regular(b"x", 0o444),
            }];
            let ustar = test_only_ustar(&entries).expect("lexical path fixture");
            let gzip = test_only_gzip_stored(&ustar);
            assert_rejected(&gzip, &test_only_expectation(&gzip, &ustar), message);
        }

        let backslash = [TestEntry {
            path: "literal\\backslash",
            kind: TestEntryKind::Regular(b"x", 0o444),
        }];
        let ustar = test_only_ustar(&backslash).expect("backslash fixture");
        let gzip = test_only_gzip_stored(&ustar);
        inspect(&gzip, &test_only_expectation(&gzip, &ustar))
            .expect("backslash is not a POSIX separator");

        let (invalid_utf8, invalid_utf8_expectation) = mutated_ustar_fixture(|ustar| {
            ustar[0] = 0xff;
            refresh_first_header(ustar);
        });
        assert_rejected(&invalid_utf8, &invalid_utf8_expectation, "not UTF-8");
        assert_error_contains(
            normalize_ustar_header_path(&"x".repeat(241), b'0'),
            "path length is outside its closed range",
        );

        let entries = [TestEntry {
            path: "a/b",
            kind: TestEntryKind::Regular(b"x", 0o444),
        }];
        let mut ustar = test_only_ustar(&entries).expect("split fixture");
        ustar[..100].fill(0);
        ustar[345..500].fill(0);
        write_test_field(&mut ustar[..100], b"b").expect("name");
        write_test_field(&mut ustar[345..500], b"a").expect("prefix");
        refresh_first_header(&mut ustar);
        let gzip = test_only_gzip_stored(&ustar);
        assert_rejected(
            &gzip,
            &test_only_expectation(&gzip, &ustar),
            "name/prefix split is not canonical",
        );

        let long_file = format!("{}/{}", "p".repeat(140), "n".repeat(99));
        let long_directory = format!("{}/{}", "p".repeat(140), "d".repeat(98)) + "/";
        for entry in [
            TestEntry {
                path: &long_file,
                kind: TestEntryKind::Regular(b"x", 0o444),
            },
            TestEntry {
                path: &long_directory,
                kind: TestEntryKind::Directory,
            },
        ] {
            let ustar = test_only_ustar(&[entry]).expect("240-byte long-path boundary");
            let gzip = test_only_gzip_stored(&ustar);
            inspect(&gzip, &test_only_expectation(&gzip, &ustar))
                .expect("canonical long path must pass");
        }
    }

    #[test]
    fn name_and_linkname_field_width_boundaries_are_exact() {
        let name_100 = "n".repeat(100);
        let entries = [TestEntry {
            path: &name_100,
            kind: TestEntryKind::Regular(b"", 0o444),
        }];
        let ustar = test_only_ustar(&entries).expect("100-byte name fixture");
        let gzip = test_only_gzip_stored(&ustar);
        inspect(&gzip, &test_only_expectation(&gzip, &ustar))
            .expect("100-byte name field must pass");

        let split_path = format!("p/{}", "n".repeat(100));
        let entries = [TestEntry {
            path: &split_path,
            kind: TestEntryKind::Regular(b"", 0o444),
        }];
        let ustar = test_only_ustar(&entries).expect("split path fixture");
        let gzip = test_only_gzip_stored(&ustar);
        inspect(&gzip, &test_only_expectation(&gzip, &ustar))
            .expect("path above 100 bytes must pass through its canonical prefix split");

        let name_101 = "n".repeat(101);
        let entries = [TestEntry {
            path: &name_101,
            kind: TestEntryKind::Regular(b"", 0o444),
        }];
        assert!(
            test_only_ustar(&entries)
                .expect_err("unsplittable 101-byte name must fail")
                .to_string()
                .contains("cannot use the canonical name/prefix split")
        );

        let linkname_100 = "t".repeat(100);
        let entries = [TestEntry {
            path: "link",
            kind: TestEntryKind::SymbolicLink(&linkname_100),
        }];
        let ustar = test_only_ustar(&entries).expect("100-byte linkname fixture");
        let gzip = test_only_gzip_stored(&ustar);
        inspect(&gzip, &test_only_expectation(&gzip, &ustar))
            .expect("100-byte linkname field must pass");

        let linkname_101 = "t".repeat(101);
        let entries = [TestEntry {
            path: "link",
            kind: TestEntryKind::SymbolicLink(&linkname_101),
        }];
        assert!(
            test_only_ustar(&entries)
                .expect_err("101-byte linkname must fail")
                .to_string()
                .contains("fixture field exceeds its ustar width")
        );

        let prefix_155_path = format!("{}/n", "p".repeat(155));
        let entries = [TestEntry {
            path: &prefix_155_path,
            kind: TestEntryKind::Regular(b"", 0o444),
        }];
        let ustar = test_only_ustar(&entries).expect("155-byte prefix fixture");
        let gzip = test_only_gzip_stored(&ustar);
        inspect(&gzip, &test_only_expectation(&gzip, &ustar))
            .expect("155-byte prefix field must pass");

        let prefix_156_path = format!("{}/n", "p".repeat(156));
        assert_error_contains(
            canonical_ustar_split(&prefix_156_path),
            "cannot use the canonical name/prefix split",
        );

        let impossible_split = format!("p/{}", "n".repeat(101));
        assert_error_contains(
            canonical_ustar_split(&impossible_split),
            "cannot use the canonical name/prefix split",
        );
    }

    #[test]
    fn path_order_uses_unsigned_utf8_bytes() {
        let canonical = [
            TestEntry {
                path: "z",
                kind: TestEntryKind::Regular(b"", 0o444),
            },
            TestEntry {
                path: "é",
                kind: TestEntryKind::Regular(b"", 0o444),
            },
        ];
        let ustar = test_only_ustar(&canonical).expect("unsigned UTF-8 order fixture");
        let gzip = test_only_gzip_stored(&ustar);
        inspect(&gzip, &test_only_expectation(&gzip, &ustar))
            .expect("ASCII must sort before non-ASCII by unsigned UTF-8 bytes");

        let reversed = [canonical[1], canonical[0]];
        let ustar = test_only_ustar(&reversed).expect("reversed unsigned UTF-8 fixture");
        let gzip = test_only_gzip_stored(&ustar);
        assert_rejected(
            &gzip,
            &test_only_expectation(&gzip, &ustar),
            "member order is not canonical",
        );
    }

    #[test]
    fn normalized_order_rejects_duplicates_and_directory_file_aliases() {
        let duplicates = [
            TestEntry {
                path: "same",
                kind: TestEntryKind::Regular(b"a", 0o444),
            },
            TestEntry {
                path: "same",
                kind: TestEntryKind::Regular(b"b", 0o444),
            },
        ];
        let ustar = test_only_ustar(&duplicates).expect("duplicate fixture");
        let gzip = test_only_gzip_stored(&ustar);
        assert_rejected(&gzip, &test_only_expectation(&gzip, &ustar), "order");

        let aliases = [
            TestEntry {
                path: "same",
                kind: TestEntryKind::Regular(b"a", 0o444),
            },
            TestEntry {
                path: "same/",
                kind: TestEntryKind::Directory,
            },
        ];
        let ustar = test_only_ustar(&aliases).expect("directory/file alias fixture");
        let gzip = test_only_gzip_stored(&ustar);
        assert_rejected(&gzip, &test_only_expectation(&gzip, &ustar), "order");
    }

    #[test]
    fn directories_symlinks_and_whiteouts_are_counted_and_root_contained() {
        let entries = [
            TestEntry {
                path: ".wh.old",
                kind: TestEntryKind::Whiteout,
            },
            TestEntry {
                path: "bin/",
                kind: TestEntryKind::Directory,
            },
            TestEntry {
                path: "bin/app",
                kind: TestEntryKind::Regular(b"a", 0o555),
            },
            TestEntry {
                path: "bin/link",
                kind: TestEntryKind::SymbolicLink("app"),
            },
        ];
        let ustar = test_only_ustar(&entries).expect("mixed ustar");
        let gzip = test_only_gzip_stored(&ustar);
        let receipt = inspect(&gzip, &test_only_expectation(&gzip, &ustar)).expect("mixed layer");
        assert_eq!(
            (
                receipt.entry_count(),
                receipt.regular_file_count(),
                receipt.directory_count(),
                receipt.symbolic_link_count(),
                receipt.whiteout_count()
            ),
            (4, 1, 1, 1, 1)
        );

        let escaping = [TestEntry {
            path: "link",
            kind: TestEntryKind::SymbolicLink("../escape"),
        }];
        let ustar = test_only_ustar(&escaping).expect("escaping link fixture");
        let gzip = test_only_gzip_stored(&ustar);
        assert_rejected(
            &gzip,
            &test_only_expectation(&gzip, &ustar),
            "escapes the layer root",
        );
    }

    #[test]
    fn directory_symlink_and_special_type_fields_are_exact() {
        for directory_path in ["bin", "bin//"] {
            let entries = [TestEntry {
                path: directory_path,
                kind: TestEntryKind::Directory,
            }];
            let ustar = test_only_ustar(&entries).expect("noncanonical directory fixture");
            let gzip = test_only_gzip_stored(&ustar);
            assert_rejected(
                &gzip,
                &test_only_expectation(&gzip, &ustar),
                "directory header path does not have exactly one trailing slash",
            );
        }

        let directory = [TestEntry {
            path: "bin/",
            kind: TestEntryKind::Directory,
        }];
        let mut ustar = test_only_ustar(&directory).expect("directory fixture");
        write_test_octal(&mut ustar[124..136], 1).expect("directory size");
        refresh_first_header(&mut ustar);
        let gzip = test_only_gzip_stored(&ustar);
        assert_rejected(
            &gzip,
            &test_only_expectation(&gzip, &ustar),
            "directory payload is not empty",
        );

        let symlink = [TestEntry {
            path: "link",
            kind: TestEntryKind::SymbolicLink("target"),
        }];
        let mut ustar = test_only_ustar(&symlink).expect("symlink fixture");
        ustar[157..257].fill(0);
        refresh_first_header(&mut ustar);
        let gzip = test_only_gzip_stored(&ustar);
        assert_rejected(
            &gzip,
            &test_only_expectation(&gzip, &ustar),
            "target is empty",
        );

        let normalized_target = [TestEntry {
            path: "a/link",
            kind: TestEntryKind::SymbolicLink("./b//../target"),
        }];
        let ustar = test_only_ustar(&normalized_target).expect("normalized target fixture");
        let gzip = test_only_gzip_stored(&ustar);
        inspect(&gzip, &test_only_expectation(&gzip, &ustar))
            .expect("dot and repeated-slash symlink target must normalize");

        for typeflag in [b'1', b'3', b'4', b'6'] {
            let (source, expectation) = mutated_ustar_fixture(|ustar| {
                ustar[156] = typeflag;
                refresh_first_header(ustar);
            });
            assert_rejected(&source, &expectation, "outside 0/5/2");
        }
    }

    #[test]
    fn entry_type_specific_fields_are_causally_rejected() {
        let directory = [TestEntry {
            path: "bin/",
            kind: TestEntryKind::Directory,
        }];
        let (source, expectation) = mutated_entries_fixture(&directory, |ustar| {
            write_test_octal(&mut ustar[100..108], 0o444).expect("directory mode");
            refresh_first_header(ustar);
        });
        assert_rejected(&source, &expectation, "directory mode is not 0555");
        let (source, expectation) = mutated_entries_fixture(&directory, |ustar| {
            write_test_field(&mut ustar[157..257], b"target").expect("directory linkname");
            refresh_first_header(ustar);
        });
        assert_rejected(&source, &expectation, "directory linkname is not empty");

        let symlink = [TestEntry {
            path: "link",
            kind: TestEntryKind::SymbolicLink("target"),
        }];
        let (source, expectation) = mutated_entries_fixture(&symlink, |ustar| {
            write_test_octal(&mut ustar[100..108], 0o555).expect("symbolic-link mode");
            refresh_first_header(ustar);
        });
        assert_rejected(&source, &expectation, "symbolic-link mode is not 0777");
        let (source, expectation) = mutated_entries_fixture(&symlink, |ustar| {
            write_test_octal(&mut ustar[124..136], 1).expect("symbolic-link size");
            refresh_first_header(ustar);
        });
        assert_rejected(&source, &expectation, "symbolic-link payload is not empty");

        let regular = [TestEntry {
            path: "file",
            kind: TestEntryKind::Regular(b"", 0o444),
        }];
        let (source, expectation) = mutated_entries_fixture(&regular, |ustar| {
            write_test_field(&mut ustar[157..257], b"target").expect("regular linkname");
            refresh_first_header(ustar);
        });
        assert_rejected(&source, &expectation, "regular-file linkname is not empty");

        let whiteout = [TestEntry {
            path: ".wh.old",
            kind: TestEntryKind::Whiteout,
        }];
        let (source, expectation) = mutated_entries_fixture(&whiteout, |ustar| {
            ustar[156] = b'2';
            refresh_first_header(ustar);
        });
        assert_rejected(&source, &expectation, "whiteout is not a regular");
        let (source, expectation) = mutated_entries_fixture(&whiteout, |ustar| {
            write_test_octal(&mut ustar[124..136], 1).expect("whiteout size");
            refresh_first_header(ustar);
        });
        assert_rejected(&source, &expectation, "whiteout payload is not empty");
        let (source, expectation) = mutated_entries_fixture(&whiteout, |ustar| {
            write_test_field(&mut ustar[157..257], b"target").expect("whiteout linkname");
            refresh_first_header(ustar);
        });
        assert_rejected(&source, &expectation, "whiteout linkname is not empty");
    }

    #[test]
    fn whiteout_syntax_mode_and_subtree_conflicts_fail_closed() {
        let malformed = [TestEntry {
            path: ".wh.",
            kind: TestEntryKind::Whiteout,
        }];
        let ustar = test_only_ustar(&malformed).expect("malformed whiteout fixture");
        let gzip = test_only_gzip_stored(&ustar);
        assert_rejected(
            &gzip,
            &test_only_expectation(&gzip, &ustar),
            "whiteout basename",
        );

        let wrong_mode = [TestEntry {
            path: ".wh.old",
            kind: TestEntryKind::Whiteout,
        }];
        let mut ustar = test_only_ustar(&wrong_mode).expect("whiteout mode fixture");
        write_test_octal(&mut ustar[100..108], 0o444).expect("nonzero whiteout mode");
        refresh_first_header(&mut ustar);
        let gzip = test_only_gzip_stored(&ustar);
        assert_rejected(
            &gzip,
            &test_only_expectation(&gzip, &ustar),
            "whiteout mode is not 0000",
        );

        let conflict = [
            TestEntry {
                path: ".wh.tree",
                kind: TestEntryKind::Whiteout,
            },
            TestEntry {
                path: "tree/.wh.file",
                kind: TestEntryKind::Whiteout,
            },
        ];
        let ustar = test_only_ustar(&conflict).expect("whiteout conflict fixture");
        let gzip = test_only_gzip_stored(&ustar);
        assert_rejected(&gzip, &test_only_expectation(&gzip, &ustar), "subtree");

        let root_conflict = [
            TestEntry {
                path: ".wh..wh..opq",
                kind: TestEntryKind::Whiteout,
            },
            TestEntry {
                path: ".wh.file",
                kind: TestEntryKind::Whiteout,
            },
        ];
        let ustar = test_only_ustar(&root_conflict).expect("root whiteout conflict fixture");
        let gzip = test_only_gzip_stored(&ustar);
        assert_rejected(&gzip, &test_only_expectation(&gzip, &ustar), "subtree");
    }

    #[test]
    fn nonadjacent_lexical_predecessor_cannot_hide_a_whiteout_ancestor() {
        let entries = [
            TestEntry {
                path: ".wh.a",
                kind: TestEntryKind::Whiteout,
            },
            TestEntry {
                path: ".wh.a-b",
                kind: TestEntryKind::Whiteout,
            },
            TestEntry {
                path: "a/.wh.b",
                kind: TestEntryKind::Whiteout,
            },
        ];
        let ustar = test_only_ustar(&entries).expect("nonadjacent whiteout ancestor fixture");
        let gzip = test_only_gzip_stored(&ustar);
        assert_rejected(&gzip, &test_only_expectation(&gzip, &ustar), "subtree");
    }

    #[test]
    fn delete_opaque_and_nested_opaque_whiteout_subjects_conflict() {
        for (entries, fixture_name) in [
            (
                [
                    TestEntry {
                        path: ".wh.tree",
                        kind: TestEntryKind::Whiteout,
                    },
                    TestEntry {
                        path: "tree/.wh..wh..opq",
                        kind: TestEntryKind::Whiteout,
                    },
                ],
                "delete plus opaque same subject",
            ),
            (
                [
                    TestEntry {
                        path: "a/.wh..wh..opq",
                        kind: TestEntryKind::Whiteout,
                    },
                    TestEntry {
                        path: "a/b/.wh..wh..opq",
                        kind: TestEntryKind::Whiteout,
                    },
                ],
                "nested opaque subjects",
            ),
        ] {
            let ustar = test_only_ustar(&entries).expect(fixture_name);
            let gzip = test_only_gzip_stored(&ustar);
            assert_rejected(&gzip, &test_only_expectation(&gzip, &ustar), "subtree");
        }
    }

    #[test]
    fn sibling_whiteout_subtrees_are_disjoint() {
        let entries = [
            TestEntry {
                path: "a/.wh.left",
                kind: TestEntryKind::Whiteout,
            },
            TestEntry {
                path: "a/.wh.right",
                kind: TestEntryKind::Whiteout,
            },
        ];
        let ustar = test_only_ustar(&entries).expect("sibling whiteout fixture");
        let gzip = test_only_gzip_stored(&ustar);
        let receipt = inspect(&gzip, &test_only_expectation(&gzip, &ustar))
            .expect("disjoint sibling whiteout subtrees must pass");
        assert_eq!(receipt.whiteout_count(), 2);
    }

    #[test]
    fn directory_header_requires_one_trailing_slash_and_normalizes_for_counts() {
        let entries = [TestEntry {
            path: "bin/",
            kind: TestEntryKind::Directory,
        }];
        let ustar = test_only_ustar(&entries).expect("canonical directory fixture");
        let gzip = test_only_gzip_stored(&ustar);
        let receipt = inspect(&gzip, &test_only_expectation(&gzip, &ustar))
            .expect("one-slash directory header must pass");
        assert_eq!(receipt.directory_count(), 1);
    }

    #[test]
    fn same_layer_recreation_after_whiteout_and_root_opaque_is_allowed() {
        let entries = [
            TestEntry {
                path: ".wh..wh..opq",
                kind: TestEntryKind::Whiteout,
            },
            TestEntry {
                path: "bin/",
                kind: TestEntryKind::Directory,
            },
            TestEntry {
                path: "bin/app",
                kind: TestEntryKind::Regular(b"new", 0o555),
            },
        ];
        let ustar = test_only_ustar(&entries).expect("opaque recreation fixture");
        let gzip = test_only_gzip_stored(&ustar);
        let receipt = inspect(&gzip, &test_only_expectation(&gzip, &ustar))
            .expect("same-layer recreation after opaque must pass");
        assert_eq!((receipt.whiteout_count(), receipt.entry_count()), (1, 3));

        let entries = [
            TestEntry {
                path: ".wh.old",
                kind: TestEntryKind::Whiteout,
            },
            TestEntry {
                path: "old",
                kind: TestEntryKind::Regular(b"replacement", 0o444),
            },
        ];
        let ustar = test_only_ustar(&entries).expect("named recreation fixture");
        let gzip = test_only_gzip_stored(&ustar);
        let receipt = inspect(&gzip, &test_only_expectation(&gzip, &ustar))
            .expect("same-layer recreation after named whiteout must pass");
        assert_eq!(
            (receipt.whiteout_count(), receipt.regular_file_count()),
            (1, 1)
        );
    }

    #[test]
    fn absolute_root_anchored_symlink_target_is_allowed() {
        let entries = [TestEntry {
            path: "bin-link",
            kind: TestEntryKind::SymbolicLink("/usr/bin/validator"),
        }];
        let ustar = test_only_ustar(&entries).expect("absolute symlink fixture");
        let gzip = test_only_gzip_stored(&ustar);
        let receipt = inspect(&gzip, &test_only_expectation(&gzip, &ustar))
            .expect("absolute root-anchored target must pass");
        assert_eq!(receipt.symbolic_link_count(), 1);
    }

    #[test]
    fn whiteout_may_target_a_basename_starting_with_whiteout_prefix() {
        let entries = [TestEntry {
            path: ".wh..wh.hidden",
            kind: TestEntryKind::Whiteout,
        }];
        let ustar = test_only_ustar(&entries).expect("nested whiteout-name fixture");
        let gzip = test_only_gzip_stored(&ustar);
        let receipt = inspect(&gzip, &test_only_expectation(&gzip, &ustar))
            .expect("whiteout target beginning .wh. must pass");
        assert_eq!(receipt.whiteout_count(), 1);
    }

    #[test]
    fn terminator_and_counter_arithmetic_fail_without_gib_allocations() {
        let entries = [TestEntry {
            path: MEMBER_PATH,
            kind: TestEntryKind::Regular(b"ok\n", 0o555),
        }];
        let canonical = test_only_ustar(&entries).expect("canonical terminator fixture");

        let one_terminator = &canonical[..canonical.len() - USTAR_BLOCK_BYTES];
        let gzip = test_only_gzip_stored(one_terminator);
        assert_rejected(
            &gzip,
            &test_only_expectation(&gzip, one_terminator),
            "OCI ustar second terminator block is truncated",
        );

        let no_terminator = &canonical[..canonical.len() - 2 * USTAR_BLOCK_BYTES];
        let gzip = test_only_gzip_stored(no_terminator);
        assert_rejected(
            &gzip,
            &test_only_expectation(&gzip, no_terminator),
            "OCI ustar header or terminator is truncated",
        );

        let mut decompressed_suffix = canonical.clone();
        decompressed_suffix.extend_from_slice(&[1_u8; USTAR_BLOCK_BYTES]);
        let gzip = test_only_gzip_stored(&decompressed_suffix);
        assert_rejected(
            &gzip,
            &test_only_expectation(&gzip, &decompressed_suffix),
            "decompressed bytes after",
        );

        let (bad_terminator, expectation) = mutated_ustar_fixture(|ustar| {
            let last = ustar.len() - 1;
            ustar[last] = 1;
        });
        assert_rejected(
            &bad_terminator,
            &expectation,
            "second terminator block is not zero",
        );

        let limits = B4ImmutableArtifactRoleV1::OciImageLayoutUstar
            .limits()
            .require_oci("test")
            .expect("OCI limits")
            .layer_stream();
        let mut counters = LayerCountersV1 {
            entry_count: limits.maximum_tar_entries(),
            ..LayerCountersV1::default()
        };
        assert_error_contains(
            counters.add_entry(limits),
            "exceeds its role-specific layer-tar entry budget",
        );
        counters.regular_file_bytes = limits.maximum_uncompressed_tar_bytes();
        assert_error_contains(
            counters.add_regular(1, limits),
            "aggregate regular-file bytes exceed the closed layer-stream budget",
        );

        let mut maximum_payload = LayerCountersV1::default();
        maximum_payload
            .add_regular(1_073_741_824, limits)
            .expect("maximum regular payload must pass without allocation");
        assert_eq!(maximum_payload.regular_file_bytes, 1_073_741_824);
        assert_error_contains(
            LayerCountersV1::default().add_regular(1_073_741_825, limits),
            "exceeds its role-specific layer regular-file payload byte budget",
        );
    }
}
