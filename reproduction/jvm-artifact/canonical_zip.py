"""Bounded classic-ZIP codec for the EIP-0045 B4 artifact gate.

This module implements only archive grammar and canonical STORED output.  It
does not inspect JVM class files, interpret manifest contents, select COPY
inputs, validate an inclusion-manifest wire format, execute a JAR, or make a
static/runtime reachability claim.

Author: A. Shannon
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
from typing import BinaryIO, Iterable, Iterator
import zlib


MAX_ARCHIVE_BYTES = 1_073_741_824
MAX_ENTRY_COUNT = 65_534
MAX_WRITE_ENTRY_COUNT = 4_096
MAX_NAME_BYTES = 240
MAX_CHUNK_BYTES = 65_536

_LOCAL_SIGNATURE = 0x04034B50
_CENTRAL_SIGNATURE = 0x02014B50
_DESCRIPTOR_SIGNATURE = 0x08074B50
_EOCD_SIGNATURE = 0x06054B50
_JAR_MARKER = b"\xfe\xca\x00\x00"
_MANIFEST = b"META-INF/MANIFEST.MF"

_LOCAL = struct.Struct("<IHHHHHIIIHH")
_CENTRAL = struct.Struct("<IHHHHHHIIIHHHHHII")
_DESCRIPTOR = struct.Struct("<IIII")
_EOCD = struct.Struct("<IHHHHIIH")


class ZipRejection(ValueError):
    """A closed-language ZIP rejection with a stable machine-readable code."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        message = code if not detail else f"{code}: {detail}"
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class EntryReport:
    name: str
    compressed_size: int
    uncompressed_size: int
    crc32: int


@dataclass(frozen=True, slots=True)
class ArchiveReport:
    artifact_sha256: str
    entry_count: int
    total_uncompressed_size: int
    entries_aggregate_sha256: str
    entries: tuple[EntryReport, ...]


@dataclass(frozen=True, slots=True)
class WriteReport:
    artifact_sha256: str
    byte_size: int
    entry_count: int
    total_uncompressed_size: int
    entries_aggregate_sha256: str


@dataclass(frozen=True, slots=True)
class Entry:
    index: int
    name: str
    raw_name: bytes
    method: int
    flags: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    dos_time: int
    dos_date: int
    local_header_offset: int
    data_offset: int
    data_descriptor_offset: int | None
    is_directory: bool
    extra: bytes

    @property
    def size(self) -> int:
        return self.uncompressed_size

    def iter_bytes(
        self, archive: "Archive", chunk_size: int = MAX_CHUNK_BYTES
    ) -> Iterator[bytes]:
        return archive.iter_entry_chunks(self, chunk_size)


@dataclass(frozen=True, slots=True)
class Archive:
    raw: bytes
    entries: tuple[Entry, ...]
    canonical: bool
    artifact_sha256: str
    total_uncompressed_size: int

    def entry(self, name: str | bytes) -> Entry:
        raw_name = _coerce_lookup_name(name)
        for candidate in self.entries:
            if candidate.raw_name == raw_name:
                return candidate
        raise KeyError(name)

    def iter_entry_chunks(
        self,
        entry: Entry | str | bytes,
        chunk_size: int = MAX_CHUNK_BYTES,
    ) -> Iterator[bytes]:
        if not isinstance(chunk_size, int) or isinstance(chunk_size, bool):
            raise TypeError("chunk_size must be an integer")
        if chunk_size < 1 or chunk_size > MAX_CHUNK_BYTES:
            raise ValueError("chunk_size must be between 1 and 65536")
        selected = self.entry(entry) if isinstance(entry, (str, bytes)) else entry
        if not isinstance(selected, Entry):
            raise TypeError("entry must be an Entry, str, or bytes")
        if selected.index >= len(self.entries) or selected.index < 0:
            raise ValueError("entry does not belong to this archive")
        if self.entries[selected.index] != selected:
            raise ValueError("entry does not belong to this archive")
        return _iter_validated_entry(self.raw, selected, chunk_size)

    def report(self) -> ArchiveReport:
        reports = tuple(
            EntryReport(
                entry.name,
                entry.compressed_size,
                entry.uncompressed_size,
                entry.crc32,
            )
            for entry in self.entries
        )
        return ArchiveReport(
            artifact_sha256=self.artifact_sha256,
            entry_count=len(self.entries),
            total_uncompressed_size=self.total_uncompressed_size,
            entries_aggregate_sha256=_entries_aggregate(self.entries),
            entries=reports,
        )


@dataclass(frozen=True, slots=True)
class _CentralEntry:
    index: int
    made_by: int
    needed: int
    flags: int
    method: int
    dos_time: int
    dos_date: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    raw_name: bytes
    extra: bytes
    local_header_offset: int
    is_directory: bool


@dataclass(frozen=True, slots=True)
class _WriteEntry:
    raw_name: bytes
    name: str
    data: bytes
    crc32: int
    local_header_offset: int


def _reject(code: str, detail: str = "") -> None:
    raise ZipRejection(code, detail)


def _require_range(raw_size: int, offset: int, length: int, code: str) -> None:
    if offset < 0 or length < 0 or offset > raw_size - length:
        _reject(code)


def _ascii_fold(raw_name: bytes) -> bytes:
    return bytes(value + 32 if 65 <= value <= 90 else value for value in raw_name)


def _validate_name(raw_name: bytes) -> tuple[str, bool]:
    if not 1 <= len(raw_name) <= MAX_NAME_BYTES:
        _reject("invalid_name_length")
    if any(value < 0x20 or value > 0x7E for value in raw_name):
        _reject("non_printable_or_non_ascii_name")
    if raw_name.startswith(b"/") or b"\\" in raw_name or b":" in raw_name:
        _reject("non_canonical_name")
    is_directory = raw_name.endswith(b"/")
    body = raw_name[:-1] if is_directory else raw_name
    if not body or raw_name.endswith(b"//"):
        _reject("non_canonical_name")
    segments = body.split(b"/")
    if any(segment in (b"", b".", b"..") for segment in segments):
        _reject("non_canonical_name")
    return raw_name.decode("ascii"), is_directory


def _coerce_lookup_name(name: str | bytes) -> bytes:
    if isinstance(name, bytes):
        return name
    if isinstance(name, str):
        try:
            return name.encode("ascii")
        except UnicodeEncodeError as exc:
            raise KeyError(name) from exc
    raise TypeError("name must be str or bytes")


def _expected_tuple(method: int) -> tuple[int, int, int]:
    if method == 0:
        return 0x000A, 10, 0x0800
    if method == 8:
        return 0x0014, 20, 0x0808
    _reject("unsupported_compression_method")
    raise AssertionError("unreachable")


def _validate_extra(extra: bytes, index: int) -> None:
    if extra and not (index == 0 and extra == _JAR_MARKER):
        _reject("unsupported_extra_field")


def _parse_central(
    raw: bytes, cd_offset: int, cd_size: int, entry_count: int
) -> tuple[_CentralEntry, ...]:
    cursor = cd_offset
    cd_end = cd_offset + cd_size
    entries: list[_CentralEntry] = []
    exact_names: set[bytes] = set()
    folded_names: set[bytes] = set()

    for index in range(entry_count):
        _require_range(cd_end, cursor, _CENTRAL.size, "truncated_central_header")
        fields = _CENTRAL.unpack_from(raw, cursor)
        (
            signature,
            made_by,
            needed,
            flags,
            method,
            dos_time,
            dos_date,
            crc32_value,
            compressed_size,
            uncompressed_size,
            name_length,
            extra_length,
            comment_length,
            disk_start,
            internal_attributes,
            external_attributes,
            local_header_offset,
        ) = fields
        if signature != _CENTRAL_SIGNATURE:
            _reject("invalid_central_signature")
        if 0xFFFF in (disk_start, name_length, extra_length, comment_length):
            _reject("zip64_sentinel")
        if 0xFFFFFFFF in (
            compressed_size,
            uncompressed_size,
            local_header_offset,
        ):
            _reject("zip64_sentinel")
        if crc32_value == 0xFFFFFFFF:
            _reject("crc32_all_ones")
        expected_made_by, expected_needed, expected_flags = _expected_tuple(method)
        if made_by != expected_made_by or needed != expected_needed:
            _reject("unsupported_version_tuple")
        if flags != expected_flags:
            _reject("unsupported_flags")
        if disk_start != 0:
            _reject("multi_disk")
        if internal_attributes != 0 or external_attributes != 0:
            _reject("non_zero_attributes")
        if comment_length != 0:
            _reject("entry_comment")
        record_size = _CENTRAL.size + name_length + extra_length
        _require_range(cd_end, cursor, record_size, "truncated_central_record")
        name_start = cursor + _CENTRAL.size
        raw_name = raw[name_start : name_start + name_length]
        extra = raw[name_start + name_length : cursor + record_size]
        name, is_directory = _validate_name(raw_name)
        del name
        _validate_extra(extra, index)
        if raw_name in exact_names:
            _reject("duplicate_entry_name")
        folded = _ascii_fold(raw_name)
        if folded in folded_names:
            _reject("ascii_casefold_collision")
        exact_names.add(raw_name)
        folded_names.add(folded)
        if compressed_size == 0 and uncompressed_size != 0:
            _reject("zero_compressed_size_mismatch")
        if method == 0 and compressed_size != uncompressed_size:
            _reject("stored_size_mismatch")
        if is_directory and (
            uncompressed_size != 0
            or crc32_value != 0
            or (method == 0 and compressed_size != 0)
        ):
            _reject("invalid_directory_marker")
        entries.append(
            _CentralEntry(
                index=index,
                made_by=made_by,
                needed=needed,
                flags=flags,
                method=method,
                dos_time=dos_time,
                dos_date=dos_date,
                crc32=crc32_value,
                compressed_size=compressed_size,
                uncompressed_size=uncompressed_size,
                raw_name=raw_name,
                extra=extra,
                local_header_offset=local_header_offset,
                is_directory=is_directory,
            )
        )
        cursor += record_size

    if cursor != cd_end:
        _reject("central_directory_size_mismatch")
    return tuple(entries)


def _parse_locals(
    raw: bytes,
    central_entries: tuple[_CentralEntry, ...],
    cd_offset: int,
    canonical: bool,
) -> tuple[Entry, ...]:
    cursor = 0
    entries: list[Entry] = []
    for central in central_entries:
        if central.local_header_offset != cursor:
            _reject("local_record_coverage_or_order")
        _require_range(cd_offset, cursor, _LOCAL.size, "truncated_local_header")
        (
            signature,
            needed,
            flags,
            method,
            dos_time,
            dos_date,
            local_crc32,
            local_compressed_size,
            local_uncompressed_size,
            name_length,
            extra_length,
        ) = _LOCAL.unpack_from(raw, cursor)
        if signature != _LOCAL_SIGNATURE:
            _reject("invalid_local_signature")
        if 0xFFFF in (name_length, extra_length):
            _reject("zip64_sentinel")
        if 0xFFFFFFFF in (local_compressed_size, local_uncompressed_size):
            _reject("zip64_sentinel")
        header_size = _LOCAL.size + name_length + extra_length
        _require_range(cd_offset, cursor, header_size, "truncated_local_record")
        name_start = cursor + _LOCAL.size
        raw_name = raw[name_start : name_start + name_length]
        extra = raw[name_start + name_length : cursor + header_size]
        if (
            needed != central.needed
            or flags != central.flags
            or method != central.method
            or dos_time != central.dos_time
            or dos_date != central.dos_date
            or raw_name != central.raw_name
            or extra != central.extra
        ):
            _reject("local_central_header_mismatch")
        if canonical and (dos_time != 0x0000 or dos_date != 0x0021):
            _reject("non_canonical_timestamp")
        data_offset = cursor + header_size
        _require_range(
            cd_offset,
            data_offset,
            central.compressed_size,
            "truncated_compressed_payload",
        )
        data_end = data_offset + central.compressed_size
        descriptor_offset: int | None = None
        if method == 0:
            if (
                local_crc32 != central.crc32
                or local_compressed_size != central.compressed_size
                or local_uncompressed_size != central.uncompressed_size
            ):
                _reject("stored_local_central_mismatch")
            cursor = data_end
        else:
            if local_crc32 != 0 or local_compressed_size != 0 or local_uncompressed_size != 0:
                _reject("deflate_local_fields_nonzero")
            _require_range(cd_offset, data_end, _DESCRIPTOR.size, "missing_data_descriptor")
            descriptor = _DESCRIPTOR.unpack_from(raw, data_end)
            if descriptor[0] != _DESCRIPTOR_SIGNATURE:
                _reject("unsigned_or_invalid_data_descriptor")
            if descriptor[1:] != (
                central.crc32,
                central.compressed_size,
                central.uncompressed_size,
            ):
                _reject("data_descriptor_mismatch")
            descriptor_offset = data_end
            cursor = data_end + _DESCRIPTOR.size
        entries.append(
            Entry(
                index=central.index,
                name=central.raw_name.decode("ascii"),
                raw_name=central.raw_name,
                method=central.method,
                flags=central.flags,
                crc32=central.crc32,
                compressed_size=central.compressed_size,
                uncompressed_size=central.uncompressed_size,
                dos_time=central.dos_time,
                dos_date=central.dos_date,
                local_header_offset=central.local_header_offset,
                data_offset=data_offset,
                data_descriptor_offset=descriptor_offset,
                is_directory=central.is_directory,
                extra=central.extra,
            )
        )
    if cursor != cd_offset:
        _reject("local_record_coverage_or_order")
    return tuple(entries)


def _iter_validated_entry(
    raw: bytes, entry: Entry, chunk_size: int
) -> Iterator[bytes]:
    start = entry.data_offset
    end = start + entry.compressed_size
    produced = 0
    crc = 0

    if entry.method == 0:
        cursor = start
        while cursor < end:
            next_cursor = min(cursor + chunk_size, end)
            chunk = raw[cursor:next_cursor]
            cursor = next_cursor
            produced += len(chunk)
            if produced > entry.uncompressed_size or produced > MAX_ARCHIVE_BYTES:
                _reject("decompressed_size_exceeded")
            crc = zlib.crc32(chunk, crc)
            yield chunk
    else:
        decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
        cursor = start
        while cursor < end:
            next_cursor = min(cursor + MAX_CHUNK_BYTES, end)
            pending = raw[cursor:next_cursor]
            cursor = next_cursor
            while pending:
                try:
                    chunk = decompressor.decompress(pending, chunk_size)
                except zlib.error as exc:
                    raise ZipRejection("deflate_error", str(exc)) from exc
                pending = decompressor.unconsumed_tail
                if decompressor.unused_data:
                    _reject("trailing_compressed_data")
                if chunk:
                    produced += len(chunk)
                    if produced > entry.uncompressed_size or produced > MAX_ARCHIVE_BYTES:
                        _reject("decompressed_size_exceeded")
                    crc = zlib.crc32(chunk, crc)
                    yield chunk
                if not chunk and pending:
                    _reject("deflate_no_progress")
        while True:
            try:
                chunk = decompressor.decompress(b"", chunk_size)
            except zlib.error as exc:
                raise ZipRejection("deflate_error", str(exc)) from exc
            if not chunk:
                break
            produced += len(chunk)
            if produced > entry.uncompressed_size or produced > MAX_ARCHIVE_BYTES:
                _reject("decompressed_size_exceeded")
            crc = zlib.crc32(chunk, crc)
            yield chunk
        if not decompressor.eof:
            _reject("truncated_deflate_stream")
        if decompressor.unused_data or decompressor.unconsumed_tail:
            _reject("trailing_compressed_data")

    if produced != entry.uncompressed_size:
        _reject("uncompressed_size_mismatch")
    if (crc & 0xFFFFFFFF) != entry.crc32:
        _reject("crc32_mismatch")
    if entry.is_directory and produced != 0:
        _reject("invalid_directory_marker")


def _entries_aggregate(entries: Iterable[Entry | _WriteEntry]) -> str:
    digest = hashlib.sha256()
    for entry in entries:
        if isinstance(entry, Entry):
            compressed_size = entry.compressed_size
            uncompressed_size = entry.uncompressed_size
        else:
            compressed_size = len(entry.data)
            uncompressed_size = len(entry.data)
        digest.update(struct.pack("<H", len(entry.raw_name)))
        digest.update(entry.raw_name)
        digest.update(
            struct.pack("<III", compressed_size, uncompressed_size, entry.crc32)
        )
    return digest.hexdigest()


def inspect_archive(raw: bytes, canonical: bool = False) -> Archive:
    """Parse and fully validate a bounded source or canonical archive.

    Source mode permits only the source policy's ordering and opaque timestamp
    allowances.  It does not normalize a rejected source archive.
    """

    if not isinstance(raw, bytes):
        raise TypeError("raw must be bytes")
    if not isinstance(canonical, bool):
        raise TypeError("canonical must be bool")
    raw_size = len(raw)
    if raw_size > MAX_ARCHIVE_BYTES:
        _reject("archive_too_large")
    if raw_size < _EOCD.size:
        _reject("missing_eocd")
    eocd_offset = raw_size - _EOCD.size
    (
        signature,
        disk_number,
        central_disk,
        entries_on_disk,
        entry_count,
        cd_size,
        cd_offset,
        comment_length,
    ) = _EOCD.unpack_from(raw, eocd_offset)
    if signature != _EOCD_SIGNATURE:
        _reject("eocd_not_final_22_bytes")
    if disk_number != 0 or central_disk != 0:
        _reject("multi_disk")
    if entries_on_disk == 0xFFFF or entry_count == 0xFFFF:
        _reject("zip64_sentinel")
    if entries_on_disk != entry_count or not 1 <= entry_count <= MAX_ENTRY_COUNT:
        _reject("invalid_entry_count")
    if cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF:
        _reject("zip64_sentinel")
    if comment_length != 0:
        _reject("archive_comment")
    if cd_offset + cd_size != eocd_offset:
        _reject("central_directory_coverage")

    central_entries = _parse_central(raw, cd_offset, cd_size, entry_count)
    entries = _parse_locals(raw, central_entries, cd_offset, canonical)

    if canonical:
        if entries[0].raw_name != _MANIFEST:
            _reject("manifest_not_first")
        for previous, current in zip(entries[1:], entries[2:]):
            if previous.raw_name >= current.raw_name:
                _reject("non_canonical_entry_order")

    total_uncompressed = 0
    for entry in entries:
        if entry.uncompressed_size > MAX_ARCHIVE_BYTES:
            _reject("entry_too_large")
        if not entry.is_directory:
            total_uncompressed += entry.uncompressed_size
            if total_uncompressed > MAX_ARCHIVE_BYTES:
                _reject("total_uncompressed_size_exceeded")
        for _ in _iter_validated_entry(raw, entry, MAX_CHUNK_BYTES):
            pass

    return Archive(
        raw=raw,
        entries=entries,
        canonical=canonical,
        artifact_sha256=hashlib.sha256(raw).hexdigest(),
        total_uncompressed_size=total_uncompressed,
    )


def _coerce_write_name(name: str | bytes) -> tuple[bytes, str]:
    if isinstance(name, str):
        try:
            raw_name = name.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ZipRejection("non_printable_or_non_ascii_name") from exc
    elif isinstance(name, bytes):
        raw_name = name
    else:
        raise TypeError("entry name must be str or bytes")
    decoded, is_directory = _validate_name(raw_name)
    if is_directory:
        _reject("writer_directory_not_allowed")
    return raw_name, decoded


def _prepare_write_entries(
    source_entries: Iterable[tuple[str | bytes, bytes]],
) -> tuple[tuple[_WriteEntry, ...], int, int, int]:
    prepared_without_offsets: list[tuple[bytes, str, bytes, int]] = []
    exact_names: set[bytes] = set()
    folded_names: set[bytes] = set()
    total_uncompressed = 0

    for item in source_entries:
        try:
            name, data = item
        except (TypeError, ValueError) as exc:
            raise TypeError("each entry must be a (name, bytes) pair") from exc
        raw_name, decoded = _coerce_write_name(name)
        if not isinstance(data, bytes):
            raise TypeError("entry content must be bytes")
        if raw_name in exact_names:
            _reject("duplicate_entry_name")
        folded = _ascii_fold(raw_name)
        if folded in folded_names:
            _reject("ascii_casefold_collision")
        exact_names.add(raw_name)
        folded_names.add(folded)
        total_uncompressed += len(data)
        if len(data) > MAX_ARCHIVE_BYTES:
            _reject("entry_too_large")
        if total_uncompressed > MAX_ARCHIVE_BYTES:
            _reject("total_uncompressed_size_exceeded")
        crc32_value = zlib.crc32(data) & 0xFFFFFFFF
        if crc32_value == 0xFFFFFFFF:
            _reject("crc32_all_ones")
        prepared_without_offsets.append((raw_name, decoded, data, crc32_value))
        if len(prepared_without_offsets) > MAX_WRITE_ENTRY_COUNT:
            _reject("writer_entry_count_exceeded")

    count = len(prepared_without_offsets)
    if not 1 <= count <= MAX_WRITE_ENTRY_COUNT:
        _reject("invalid_writer_entry_count")
    if prepared_without_offsets[0][0] != _MANIFEST:
        _reject("manifest_not_first")
    previous: bytes | None = None
    for raw_name, _, _, _ in prepared_without_offsets[1:]:
        if previous is not None and previous >= raw_name:
            _reject("non_canonical_entry_order")
        previous = raw_name

    local_cursor = 0
    prepared: list[_WriteEntry] = []
    for raw_name, decoded, data, crc32_value in prepared_without_offsets:
        if local_cursor == 0xFFFFFFFF or len(data) == 0xFFFFFFFF:
            _reject("zip64_sentinel")
        prepared.append(
            _WriteEntry(raw_name, decoded, data, crc32_value, local_cursor)
        )
        local_cursor += _LOCAL.size + len(raw_name) + len(data)

    cd_offset = local_cursor
    cd_size = sum(_CENTRAL.size + len(entry.raw_name) for entry in prepared)
    output_size = cd_offset + cd_size + _EOCD.size
    if 0xFFFFFFFF in (cd_offset, cd_size) or output_size > MAX_ARCHIVE_BYTES:
        _reject("canonical_output_too_large")
    return tuple(prepared), cd_offset, cd_size, output_size


def _write_exact(output: BinaryIO, data: bytes | memoryview, digest: object) -> None:
    view = memoryview(data)
    while view:
        try:
            written = output.write(view)
        except TypeError as exc:
            raise TypeError("output must be a binary stream") from exc
        if written is None:
            raise OSError("binary output stream made no write progress")
        if not isinstance(written, int) or written <= 0 or written > len(view):
            raise OSError("binary output stream made no valid write progress")
        digest.update(view[:written])
        view = view[written:]


def write_canonical(
    output: BinaryIO,
    entries: Iterable[tuple[str | bytes, bytes]],
) -> WriteReport:
    """Write a canonical STORED archive to a caller-owned exclusive stream.

    The caller must open ``output`` as a new exclusive binary stream.  The
    function verifies that its current position is zero and performs all input
    and output-size checks before the first write.  It never closes the stream.
    """

    prepared, cd_offset, cd_size, output_size = _prepare_write_entries(entries)
    try:
        position = output.tell()
    except (AttributeError, OSError) as exc:
        raise TypeError("output must expose tell() and start at position zero") from exc
    if position != 0:
        _reject("output_not_empty")

    digest = hashlib.sha256()
    for entry in prepared:
        header = _LOCAL.pack(
            _LOCAL_SIGNATURE,
            10,
            0x0800,
            0,
            0x0000,
            0x0021,
            entry.crc32,
            len(entry.data),
            len(entry.data),
            len(entry.raw_name),
            0,
        )
        _write_exact(output, header, digest)
        _write_exact(output, entry.raw_name, digest)
        data_view = memoryview(entry.data)
        for offset in range(0, len(data_view), MAX_CHUNK_BYTES):
            _write_exact(output, data_view[offset : offset + MAX_CHUNK_BYTES], digest)

    for entry in prepared:
        header = _CENTRAL.pack(
            _CENTRAL_SIGNATURE,
            0x000A,
            10,
            0x0800,
            0,
            0x0000,
            0x0021,
            entry.crc32,
            len(entry.data),
            len(entry.data),
            len(entry.raw_name),
            0,
            0,
            0,
            0,
            0,
            entry.local_header_offset,
        )
        _write_exact(output, header, digest)
        _write_exact(output, entry.raw_name, digest)

    eocd = _EOCD.pack(
        _EOCD_SIGNATURE,
        0,
        0,
        len(prepared),
        len(prepared),
        cd_size,
        cd_offset,
        0,
    )
    _write_exact(output, eocd, digest)
    return WriteReport(
        artifact_sha256=digest.hexdigest(),
        byte_size=output_size,
        entry_count=len(prepared),
        total_uncompressed_size=sum(len(entry.data) for entry in prepared),
        entries_aggregate_sha256=_entries_aggregate(prepared),
    )


__all__ = [
    "Archive",
    "ArchiveReport",
    "Entry",
    "EntryReport",
    "WriteReport",
    "ZipRejection",
    "inspect_archive",
    "write_canonical",
]
