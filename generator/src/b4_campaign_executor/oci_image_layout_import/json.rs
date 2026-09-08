//! Pure RFC 8785 and closed-graph validation for OCI image-layout JSON.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, ensure};
use eip_0045_reproduction::b4_positive_gate::B4PositiveOciImageLayoutV1;
use eip_0045_reproduction::canonical::{canonical_json_bytes, validate_canonical_json_source};
use serde_json::{Map, Number, Value};
use sha2::{Digest as _, Sha256};

const OCI_JSON_MIN_BYTES: u64 = 2;
const OCI_JSON_MAX_BYTES: u64 = 1_048_576;
const OCI_LAYER_MIN_BYTES: u64 = 20;
const OCI_LAYER_MAX_BYTES: u64 = 8_589_934_591;
const OCI_LAYER_MIN_UNCOMPRESSED_BYTES: u64 = 1_024;
const OCI_LAYER_MAX_UNCOMPRESSED_BYTES: u64 = 34_359_738_368;
const OCI_MAX_AGGREGATE_UNCOMPRESSED_BYTES: u64 = 34_359_738_368;
const OCI_MAX_ROOTFS_ENTRIES: u64 = 1_000_000;
const OCI_MIN_LAYERS: usize = 1;
const OCI_MAX_LAYERS: usize = 128;

const OCI_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const OCI_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

/// One expected content-addressed OCI blob identity.
pub(super) struct OciBlobIdentityV1 {
    digest: [u8; 32],
    byte_length: u64,
}

impl OciBlobIdentityV1 {
    #[cfg(test)]
    pub(super) const fn test_only(digest: [u8; 32], byte_length: u64) -> Self {
        Self {
            digest,
            byte_length,
        }
    }

    pub(super) const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(super) const fn byte_length(&self) -> u64 {
        self.byte_length
    }
}

/// One ordered profile layer tuple before gzip or rootfs inspection.
pub(super) struct OciExpectedLayerV1 {
    compressed: OciBlobIdentityV1,
    uncompressed_bytes: u64,
    diff_id: [u8; 32],
}

impl OciExpectedLayerV1 {
    #[cfg(test)]
    pub(super) const fn test_only(
        compressed: OciBlobIdentityV1,
        uncompressed_bytes: u64,
        diff_id: [u8; 32],
    ) -> Self {
        Self {
            compressed,
            uncompressed_bytes,
            diff_id,
        }
    }

    pub(super) const fn compressed(&self) -> &OciBlobIdentityV1 {
        &self.compressed
    }

    pub(super) const fn uncompressed_byte_length(&self) -> u64 {
        self.uncompressed_bytes
    }

    pub(super) const fn diff_id(&self) -> [u8; 32] {
        self.diff_id
    }
}

/// Closed post-changeset rootfs counts retained for the future layer gate.
#[derive(Clone, Copy)]
pub(super) struct OciExpectedRootfsV1 {
    entry_count: u64,
    regular_file_count: u64,
    directory_count: u64,
    symbolic_link_count: u64,
    regular_file_bytes: u64,
}

impl OciExpectedRootfsV1 {
    #[cfg(test)]
    pub(super) const fn test_only(
        entry_count: u64,
        regular_file_count: u64,
        directory_count: u64,
        symbolic_link_count: u64,
        regular_file_bytes: u64,
    ) -> Self {
        Self {
            entry_count,
            regular_file_count,
            directory_count,
            symbolic_link_count,
            regular_file_bytes,
        }
    }

    pub(super) const fn entry_count(self) -> u64 {
        self.entry_count
    }

    pub(super) const fn regular_file_count(self) -> u64 {
        self.regular_file_count
    }

    pub(super) const fn directory_count(self) -> u64 {
        self.directory_count
    }

    pub(super) const fn symbolic_link_count(self) -> u64 {
        self.symbolic_link_count
    }

    pub(super) const fn regular_file_bytes(self) -> u64 {
        self.regular_file_bytes
    }
}

/// Closed JSON expectation derived from one authenticated runner profile.
pub(super) struct OciImageExpectationV1 {
    manifest: OciBlobIdentityV1,
    config: OciBlobIdentityV1,
    layers: Vec<OciExpectedLayerV1>,
    post_changeset_rootfs: OciExpectedRootfsV1,
}

impl OciImageExpectationV1 {
    #[cfg(test)]
    pub(super) fn test_only(
        manifest: OciBlobIdentityV1,
        config: OciBlobIdentityV1,
        layers: Vec<OciExpectedLayerV1>,
    ) -> Self {
        Self {
            manifest,
            config,
            layers,
            post_changeset_rootfs: OciExpectedRootfsV1 {
                entry_count: 0,
                regular_file_count: 0,
                directory_count: 0,
                symbolic_link_count: 0,
                regular_file_bytes: 0,
            },
        }
    }

    #[cfg(test)]
    pub(super) fn test_only_with_post_changeset_rootfs(
        mut self,
        post_changeset_rootfs: OciExpectedRootfsV1,
    ) -> Self {
        self.post_changeset_rootfs = post_changeset_rootfs;
        self
    }

    pub(super) const fn manifest(&self) -> &OciBlobIdentityV1 {
        &self.manifest
    }

    pub(super) const fn config(&self) -> &OciBlobIdentityV1 {
        &self.config
    }

    pub(super) fn layers(&self) -> &[OciExpectedLayerV1] {
        &self.layers
    }

    pub(super) const fn post_changeset_rootfs(&self) -> OciExpectedRootfsV1 {
        self.post_changeset_rootfs
    }
}

/// Project the exact descriptor graph from one already-authenticated positive
/// runner profile. No path, role or descriptor value can be supplied
/// independently at this boundary.
pub(super) fn project_authenticated_oci_image_expectation(
    profile: &B4PositiveOciImageLayoutV1,
) -> Result<OciImageExpectationV1> {
    let mut layers = Vec::new();
    layers
        .try_reserve_exact(profile.layers().len())
        .context("cannot retain authenticated OCI profile layers")?;
    for layer in profile.layers() {
        layers.push(OciExpectedLayerV1 {
            compressed: OciBlobIdentityV1 {
                digest: layer.compressed_digest(),
                byte_length: layer.compressed_byte_length(),
            },
            uncompressed_bytes: layer.uncompressed_byte_length(),
            diff_id: layer.diff_id(),
        });
    }
    let expectation = OciImageExpectationV1 {
        manifest: OciBlobIdentityV1 {
            digest: profile.manifest().digest(),
            byte_length: profile.manifest().byte_length(),
        },
        config: OciBlobIdentityV1 {
            digest: profile.config().digest(),
            byte_length: profile.config().byte_length(),
        },
        layers,
        post_changeset_rootfs: OciExpectedRootfsV1 {
            entry_count: profile.post_changeset_rootfs().entry_count(),
            regular_file_count: profile.post_changeset_rootfs().regular_file_count(),
            directory_count: profile.post_changeset_rootfs().directory_count(),
            symbolic_link_count: profile.post_changeset_rootfs().symbolic_link_count(),
            regular_file_bytes: profile.post_changeset_rootfs().regular_file_bytes(),
        },
    };
    validate_oci_image_expectation(&expectation)?;
    Ok(expectation)
}

/// Validate all profile-declared bounds and non-alias invariants needed by the
/// JSON graph. This does not validate gzip, uncompressed `DiffIDs` or rootfs state.
pub(super) fn validate_oci_image_expectation(expectation: &OciImageExpectationV1) -> Result<()> {
    validate_inclusive_range(
        expectation.manifest.byte_length,
        OCI_JSON_MIN_BYTES,
        OCI_JSON_MAX_BYTES,
        "OCI manifest JSON byte length",
    )?;
    validate_inclusive_range(
        expectation.config.byte_length,
        OCI_JSON_MIN_BYTES,
        OCI_JSON_MAX_BYTES,
        "OCI config JSON byte length",
    )?;
    ensure!(
        (OCI_MIN_LAYERS..=OCI_MAX_LAYERS).contains(&expectation.layers.len()),
        "OCI expected layer cardinality is outside the closed range"
    );

    let mut compressed_digests = BTreeSet::<[u8; 32]>::new();
    ensure!(
        compressed_digests.insert(expectation.manifest.digest),
        "OCI manifest compressed identity is duplicated"
    );
    ensure!(
        compressed_digests.insert(expectation.config.digest),
        "OCI config digest aliases the manifest digest"
    );
    let mut diff_ids = BTreeSet::<[u8; 32]>::new();
    let mut aggregate_uncompressed_bytes = 0_u64;

    for (index, layer) in expectation.layers.iter().enumerate() {
        validate_inclusive_range(
            layer.compressed.byte_length,
            OCI_LAYER_MIN_BYTES,
            OCI_LAYER_MAX_BYTES,
            "OCI compressed layer byte length",
        )
        .with_context(|| format!("OCI layer {index} compressed length is invalid"))?;
        validate_inclusive_range(
            layer.uncompressed_bytes,
            OCI_LAYER_MIN_UNCOMPRESSED_BYTES,
            OCI_LAYER_MAX_UNCOMPRESSED_BYTES,
            "OCI declared uncompressed layer byte length",
        )
        .with_context(|| format!("OCI layer {index} uncompressed length is invalid"))?;
        ensure!(
            layer.uncompressed_bytes % 512 == 0,
            "OCI layer {index} uncompressed byte length is not a multiple of 512"
        );
        ensure!(
            compressed_digests.insert(layer.compressed.digest),
            "OCI layer {index} compressed digest is reused"
        );
        ensure!(
            diff_ids.insert(layer.diff_id),
            "OCI layer {index} DiffID is reused"
        );
        aggregate_uncompressed_bytes = aggregate_uncompressed_bytes
            .checked_add(layer.uncompressed_bytes)
            .context("OCI aggregate declared uncompressed layer bytes overflowed")?;
        ensure!(
            aggregate_uncompressed_bytes <= OCI_MAX_AGGREGATE_UNCOMPRESSED_BYTES,
            "OCI aggregate declared uncompressed layer bytes exceed the closed bound"
        );
    }
    for (value, label) in [
        (
            expectation.post_changeset_rootfs.entry_count,
            "OCI post-changeset rootfs entry count",
        ),
        (
            expectation.post_changeset_rootfs.regular_file_count,
            "OCI post-changeset rootfs regular-file count",
        ),
        (
            expectation.post_changeset_rootfs.directory_count,
            "OCI post-changeset rootfs directory count",
        ),
        (
            expectation.post_changeset_rootfs.symbolic_link_count,
            "OCI post-changeset rootfs symbolic-link count",
        ),
    ] {
        ensure!(
            value <= OCI_MAX_ROOTFS_ENTRIES,
            "{label} exceeds its closed bound"
        );
    }
    let typed_entry_count = expectation
        .post_changeset_rootfs
        .regular_file_count
        .checked_add(expectation.post_changeset_rootfs.directory_count)
        .and_then(|count| count.checked_add(expectation.post_changeset_rootfs.symbolic_link_count))
        .context("OCI post-changeset rootfs typed entry count overflowed")?;
    ensure!(
        expectation.post_changeset_rootfs.entry_count == typed_entry_count,
        "OCI post-changeset rootfs entry count differs from its typed counts"
    );
    ensure!(
        expectation.post_changeset_rootfs.regular_file_bytes <= aggregate_uncompressed_bytes,
        "OCI post-changeset rootfs regular-file bytes exceed the layer stream"
    );
    Ok(())
}

/// Derive the exact RFC 8785 `index.json` byte length from the closed profile
/// projection. No archive bytes or path authority are consumed.
pub(super) fn expected_index_json_byte_length(expectation: &OciImageExpectationV1) -> Result<u64> {
    validate_oci_image_expectation(expectation)?;
    let bytes = canonical_json_bytes(&expected_index_value(expectation))
        .context("cannot derive canonical OCI index JSON")?;
    let byte_length = u64::try_from(bytes.len()).context("OCI index JSON length exceeds u64")?;
    validate_inclusive_range(
        byte_length,
        OCI_JSON_MIN_BYTES,
        OCI_JSON_MAX_BYTES,
        "derived OCI index JSON byte length",
    )?;
    Ok(byte_length)
}

/// Validate the sole image-layout index against one closed profile projection.
pub(super) fn validate_index_json_source(
    source: &[u8],
    expectation: &OciImageExpectationV1,
) -> Result<()> {
    validate_oci_image_expectation(expectation)?;
    validate_json_source_bound(source, "OCI index JSON")?;
    let value = validate_canonical_json_source(source)
        .context("OCI index JSON is not strict RFC 8785 canonical JSON")?;
    let root = require_exact_object(
        &value,
        &["schemaVersion", "mediaType", "manifests"],
        "OCI index JSON",
    )?;
    require_u64_eq(root, "schemaVersion", 2, "OCI index JSON")?;
    require_string_eq(root, "mediaType", OCI_INDEX_MEDIA_TYPE, "OCI index JSON")?;
    let manifests = require_array(root, "manifests", "OCI index JSON")?;
    ensure!(
        manifests.len() == 1,
        "OCI index JSON must contain exactly one manifest descriptor"
    );
    let descriptor = require_exact_object(
        &manifests[0],
        &["mediaType", "digest", "size", "platform"],
        "OCI index manifest descriptor",
    )?;
    validate_descriptor_fields(
        descriptor,
        OCI_MANIFEST_MEDIA_TYPE,
        OCI_JSON_MIN_BYTES,
        OCI_JSON_MAX_BYTES,
        &expectation.manifest,
        "OCI index manifest descriptor",
    )?;
    validate_linux_amd64_platform(required(descriptor, "platform", "OCI index descriptor")?)?;

    let expected = canonical_json_bytes(&expected_index_value(expectation))
        .context("cannot derive expected canonical OCI index JSON")?;
    ensure!(
        source == expected.as_slice(),
        "OCI index JSON differs from the exact profile-derived canonical document"
    );
    Ok(())
}

/// Validate the selected manifest and its ordered compressed layer descriptors.
pub(super) fn validate_manifest_json_source(
    source: &[u8],
    expectation: &OciImageExpectationV1,
) -> Result<()> {
    validate_oci_image_expectation(expectation)?;
    validate_json_blob_source_identity(source, &expectation.manifest, "OCI manifest JSON")?;
    let value = validate_canonical_json_source(source)
        .context("OCI manifest JSON is not strict RFC 8785 canonical JSON")?;
    let root = require_exact_object(
        &value,
        &["schemaVersion", "mediaType", "config", "layers"],
        "OCI manifest JSON",
    )?;
    require_u64_eq(root, "schemaVersion", 2, "OCI manifest JSON")?;
    require_string_eq(
        root,
        "mediaType",
        OCI_MANIFEST_MEDIA_TYPE,
        "OCI manifest JSON",
    )?;

    let config = require_exact_object(
        required(root, "config", "OCI manifest JSON")?,
        &["mediaType", "digest", "size"],
        "OCI manifest config descriptor",
    )?;
    validate_descriptor_fields(
        config,
        OCI_CONFIG_MEDIA_TYPE,
        OCI_JSON_MIN_BYTES,
        OCI_JSON_MAX_BYTES,
        &expectation.config,
        "OCI manifest config descriptor",
    )?;

    let layers = require_array(root, "layers", "OCI manifest JSON")?;
    ensure!(
        layers.len() == expectation.layers.len(),
        "OCI manifest layer cardinality differs from the ordered profile tuples"
    );
    for (index, (descriptor, expected)) in layers.iter().zip(&expectation.layers).enumerate() {
        let descriptor = require_exact_object(
            descriptor,
            &["mediaType", "digest", "size"],
            "OCI manifest layer descriptor",
        )?;
        validate_descriptor_fields(
            descriptor,
            OCI_LAYER_MEDIA_TYPE,
            OCI_LAYER_MIN_BYTES,
            OCI_LAYER_MAX_BYTES,
            &expected.compressed,
            "OCI manifest layer descriptor",
        )
        .with_context(|| format!("OCI manifest layer descriptor {index} is invalid"))?;
    }
    Ok(())
}

/// Validate the selected config and its positionally bound rootfs `DiffIDs`.
pub(super) fn validate_config_json_source(
    source: &[u8],
    expectation: &OciImageExpectationV1,
) -> Result<()> {
    validate_oci_image_expectation(expectation)?;
    validate_json_blob_source_identity(source, &expectation.config, "OCI config JSON")?;
    let value = validate_canonical_json_source(source)
        .context("OCI config JSON is not strict RFC 8785 canonical JSON")?;
    let root = require_exact_object(&value, &["architecture", "os", "rootfs"], "OCI config JSON")?;
    require_string_eq(root, "architecture", "amd64", "OCI config JSON")?;
    require_string_eq(root, "os", "linux", "OCI config JSON")?;

    let rootfs = require_exact_object(
        required(root, "rootfs", "OCI config JSON")?,
        &["type", "diff_ids"],
        "OCI config rootfs",
    )?;
    require_string_eq(rootfs, "type", "layers", "OCI config rootfs")?;
    let diff_ids = require_array(rootfs, "diff_ids", "OCI config rootfs")?;
    ensure!(
        diff_ids.len() == expectation.layers.len(),
        "OCI config DiffID cardinality differs from the ordered profile tuples"
    );
    for (index, (actual, expected)) in diff_ids.iter().zip(&expectation.layers).enumerate() {
        let actual = parse_sha256_digest(actual, "OCI config DiffID")?;
        ensure!(
            actual == expected.diff_id,
            "OCI config DiffID {index} differs from its ordered profile tuple"
        );
    }
    Ok(())
}

fn expected_index_value(expectation: &OciImageExpectationV1) -> Value {
    let mut platform = Map::new();
    platform.insert("architecture".to_owned(), Value::String("amd64".to_owned()));
    platform.insert("os".to_owned(), Value::String("linux".to_owned()));

    let mut descriptor = Map::new();
    descriptor.insert(
        "mediaType".to_owned(),
        Value::String(OCI_MANIFEST_MEDIA_TYPE.to_owned()),
    );
    descriptor.insert(
        "digest".to_owned(),
        Value::String(format_sha256_digest(expectation.manifest.digest())),
    );
    descriptor.insert(
        "size".to_owned(),
        Value::Number(Number::from(expectation.manifest.byte_length())),
    );
    descriptor.insert("platform".to_owned(), Value::Object(platform));

    let mut index = Map::new();
    index.insert(
        "schemaVersion".to_owned(),
        Value::Number(Number::from(2_u64)),
    );
    index.insert(
        "mediaType".to_owned(),
        Value::String(OCI_INDEX_MEDIA_TYPE.to_owned()),
    );
    index.insert(
        "manifests".to_owned(),
        Value::Array(vec![Value::Object(descriptor)]),
    );
    Value::Object(index)
}

fn validate_json_blob_source_identity(
    source: &[u8],
    expected: &OciBlobIdentityV1,
    label: &str,
) -> Result<()> {
    validate_json_source_bound(source, label)?;
    let byte_length = u64::try_from(source.len()).context("JSON source length exceeds u64")?;
    ensure!(
        byte_length == expected.byte_length,
        "{label} byte length differs from its profile descriptor"
    );
    let digest: [u8; 32] = Sha256::digest(source).into();
    ensure!(
        digest == expected.digest,
        "{label} SHA-256 differs from its profile descriptor"
    );
    Ok(())
}

fn validate_json_source_bound(source: &[u8], label: &str) -> Result<()> {
    let byte_length = u64::try_from(source.len()).context("JSON source length exceeds u64")?;
    validate_inclusive_range(
        byte_length,
        OCI_JSON_MIN_BYTES,
        OCI_JSON_MAX_BYTES,
        &format!("{label} byte length"),
    )
}

fn validate_descriptor_fields(
    descriptor: &Map<String, Value>,
    expected_media_type: &str,
    minimum_size: u64,
    maximum_size: u64,
    expected: &OciBlobIdentityV1,
    label: &str,
) -> Result<()> {
    require_string_eq(descriptor, "mediaType", expected_media_type, label)?;
    let digest = parse_sha256_digest(required(descriptor, "digest", label)?, label)?;
    let size = require_u64(descriptor, "size", label)?;
    validate_inclusive_range(size, minimum_size, maximum_size, &format!("{label} size"))?;
    ensure!(
        digest == expected.digest,
        "{label} digest differs from its profile identity"
    );
    ensure!(
        size == expected.byte_length,
        "{label} size differs from its profile identity"
    );
    Ok(())
}

fn validate_linux_amd64_platform(value: &Value) -> Result<()> {
    let platform = require_exact_object(
        value,
        &["os", "architecture"],
        "OCI index manifest platform",
    )?;
    require_string_eq(
        platform,
        "architecture",
        "amd64",
        "OCI index manifest platform",
    )?;
    require_string_eq(platform, "os", "linux", "OCI index manifest platform")
}

fn require_exact_object<'value>(
    value: &'value Value,
    expected_keys: &[&str],
    label: &str,
) -> Result<&'value Map<String, Value>> {
    let object = value
        .as_object()
        .with_context(|| format!("{label} is not a JSON object"))?;
    ensure!(
        object.len() == expected_keys.len()
            && expected_keys.iter().all(|key| object.contains_key(*key)),
        "{label} does not have its exact closed key set"
    );
    Ok(object)
}

fn required<'value>(
    object: &'value Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<&'value Value> {
    object
        .get(key)
        .with_context(|| format!("{label} is missing required field {key}"))
}

fn require_array<'value>(
    object: &'value Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<&'value [Value]> {
    required(object, key, label)?
        .as_array()
        .map(Vec::as_slice)
        .with_context(|| format!("{label} field {key} is not an array"))
}

fn require_string_eq(
    object: &Map<String, Value>,
    key: &str,
    expected: &str,
    label: &str,
) -> Result<()> {
    let actual = required(object, key, label)?
        .as_str()
        .with_context(|| format!("{label} field {key} is not a string"))?;
    ensure!(actual == expected, "{label} field {key} is not exact");
    Ok(())
}

fn require_u64(object: &Map<String, Value>, key: &str, label: &str) -> Result<u64> {
    required(object, key, label)?
        .as_u64()
        .with_context(|| format!("{label} field {key} is not an unsigned integer"))
}

fn require_u64_eq(
    object: &Map<String, Value>,
    key: &str,
    expected: u64,
    label: &str,
) -> Result<()> {
    ensure!(
        require_u64(object, key, label)? == expected,
        "{label} field {key} is not exact"
    );
    Ok(())
}

fn parse_sha256_digest(value: &Value, label: &str) -> Result<[u8; 32]> {
    let digest = value
        .as_str()
        .with_context(|| format!("{label} digest is not a string"))?;
    let encoded = digest
        .strip_prefix("sha256:")
        .with_context(|| format!("{label} digest algorithm is not exact sha256"))?;
    ensure!(
        encoded.len() == 64
            && encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} digest is not exactly 64 lowercase hexadecimal characters"
    );
    let mut decoded = [0_u8; 32];
    hex::decode_to_slice(encoded, &mut decoded)
        .with_context(|| format!("cannot decode {label} SHA-256 digest"))?;
    Ok(decoded)
}

fn format_sha256_digest(digest: [u8; 32]) -> String {
    format!("sha256:{}", hex::encode(digest))
}

fn validate_inclusive_range(value: u64, minimum: u64, maximum: u64, label: &str) -> Result<()> {
    ensure!(
        (minimum..=maximum).contains(&value),
        "{label} is outside the closed range {minimum}..={maximum}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct JsonFixture {
        expectation: OciImageExpectationV1,
        index: Vec<u8>,
        manifest: Vec<u8>,
        config: Vec<u8>,
    }

    fn identity(seed: u8, byte_length: u64) -> OciBlobIdentityV1 {
        OciBlobIdentityV1::test_only([seed; 32], byte_length)
    }

    fn identity_from_source(source: &[u8]) -> OciBlobIdentityV1 {
        OciBlobIdentityV1::test_only(Sha256::digest(source).into(), source.len() as u64)
    }

    fn layer(
        compressed_seed: u8,
        compressed_bytes: u64,
        uncompressed_bytes: u64,
        diff_id_seed: u8,
    ) -> OciExpectedLayerV1 {
        OciExpectedLayerV1::test_only(
            identity(compressed_seed, compressed_bytes),
            uncompressed_bytes,
            [diff_id_seed; 32],
        )
    }

    fn one_layer() -> Vec<OciExpectedLayerV1> {
        vec![layer(0x90, 20, 1_024, 0xa0)]
    }

    fn opposite_digest_order_layers() -> Vec<OciExpectedLayerV1> {
        vec![layer(0xf0, 20, 1_024, 0xd0), layer(0x10, 21, 1_536, 0x20)]
    }

    fn config_value(layers: &[OciExpectedLayerV1]) -> Value {
        let diff_ids = layers
            .iter()
            .map(|layer| Value::String(format_sha256_digest(layer.diff_id())))
            .collect::<Vec<_>>();
        json!({
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {
                "type": "layers",
                "diff_ids": diff_ids
            }
        })
    }

    fn manifest_value(config: &OciBlobIdentityV1, layers: &[OciExpectedLayerV1]) -> Value {
        let layers = layers
            .iter()
            .map(|layer| {
                json!({
                    "mediaType": OCI_LAYER_MEDIA_TYPE,
                    "digest": format_sha256_digest(layer.compressed().digest()),
                    "size": layer.compressed().byte_length()
                })
            })
            .collect::<Vec<_>>();
        json!({
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST_MEDIA_TYPE,
            "config": {
                "mediaType": OCI_CONFIG_MEDIA_TYPE,
                "digest": format_sha256_digest(config.digest()),
                "size": config.byte_length()
            },
            "layers": layers
        })
    }

    fn fixture_with_layers(layers: Vec<OciExpectedLayerV1>) -> JsonFixture {
        let config = canonical_json_bytes(&config_value(&layers)).unwrap();
        let config_identity = identity_from_source(&config);
        let manifest = canonical_json_bytes(&manifest_value(&config_identity, &layers)).unwrap();
        let manifest_identity = identity_from_source(&manifest);
        let expectation =
            OciImageExpectationV1::test_only(manifest_identity, config_identity, layers);
        let index = canonical_json_bytes(&expected_index_value(&expectation)).unwrap();
        JsonFixture {
            expectation,
            index,
            manifest,
            config,
        }
    }

    fn canonical_one_layer_fixture() -> JsonFixture {
        fixture_with_layers(one_layer())
    }

    fn expectation_for_config_source(
        source: &[u8],
        layers: Vec<OciExpectedLayerV1>,
    ) -> OciImageExpectationV1 {
        OciImageExpectationV1::test_only(identity(0xee, 128), identity_from_source(source), layers)
    }

    fn declared_fn_names(source: &str) -> Vec<&str> {
        source
            .match_indices("fn ")
            .map(|(offset, _)| {
                let tail = &source[offset + 3..];
                let end = tail.find(['(', '<']).unwrap();
                &tail[..end]
            })
            .collect()
    }

    #[test]
    fn canonical_closed_json_graph_is_accepted() {
        let fixture = canonical_one_layer_fixture();
        validate_oci_image_expectation(&fixture.expectation).unwrap();
        validate_index_json_source(&fixture.index, &fixture.expectation).unwrap();
        validate_manifest_json_source(&fixture.manifest, &fixture.expectation).unwrap();
        validate_config_json_source(&fixture.config, &fixture.expectation).unwrap();
        assert_eq!(
            expected_index_json_byte_length(&fixture.expectation).unwrap(),
            fixture.index.len() as u64
        );
        assert_eq!(fixture.expectation.layers().len(), 1);
        assert_eq!(
            fixture.expectation.layers()[0].uncompressed_byte_length(),
            1_024
        );
        assert_eq!(fixture.expectation.layers()[0].diff_id(), [0xa0; 32]);
        assert_eq!(
            fixture.expectation.manifest().byte_length(),
            fixture.manifest.len() as u64
        );
        assert_eq!(
            fixture.expectation.config().byte_length(),
            fixture.config.len() as u64
        );
    }

    #[test]
    fn physical_digest_order_is_independent_from_layers_and_diff_ids_order() {
        let fixture = fixture_with_layers(opposite_digest_order_layers());
        let semantic_order = fixture
            .expectation
            .layers()
            .iter()
            .map(|layer| layer.compressed().digest())
            .collect::<Vec<_>>();
        let mut physical_order = semantic_order.clone();
        physical_order.sort_unstable();
        assert_eq!(semantic_order, vec![[0xf0; 32], [0x10; 32]]);
        assert_eq!(physical_order, vec![[0x10; 32], [0xf0; 32]]);
        validate_manifest_json_source(&fixture.manifest, &fixture.expectation).unwrap();
        validate_config_json_source(&fixture.config, &fixture.expectation).unwrap();
    }

    #[test]
    fn duplicate_trailing_and_noncanonical_index_sources_reject_causally() {
        let fixture = canonical_one_layer_fixture();

        let mut duplicate = String::from_utf8(fixture.index.clone()).unwrap();
        let end = duplicate.pop().unwrap();
        assert_eq!(end, '}');
        duplicate.push_str(",\"schemaVersion\":2}");
        let message = format!(
            "{:#}",
            validate_index_json_source(duplicate.as_bytes(), &fixture.expectation).unwrap_err()
        );
        assert!(message.contains("duplicate object key"), "{message}");

        let mut trailing = fixture.index.clone();
        trailing.push(b'x');
        let message = format!(
            "{:#}",
            validate_index_json_source(&trailing, &fixture.expectation).unwrap_err()
        );
        assert!(message.contains("unexpected data"), "{message}");

        let mut noncanonical = fixture.index.clone();
        noncanonical.insert(1, b' ');
        let message = format!(
            "{:#}",
            validate_index_json_source(&noncanonical, &fixture.expectation).unwrap_err()
        );
        assert!(message.contains("exact RFC 8785"), "{message}");
    }

    #[test]
    fn every_json_object_rejects_an_extra_key_after_valid_jcs() {
        let fixture = canonical_one_layer_fixture();
        let mut index = validate_canonical_json_source(&fixture.index).unwrap();
        index["extra"] = json!(true);
        let source = canonical_json_bytes(&index).unwrap();
        let message = format!(
            "{:#}",
            validate_index_json_source(&source, &fixture.expectation).unwrap_err()
        );
        assert!(message.contains("exact closed key set"), "{message}");

        let layers = one_layer();
        let config = canonical_json_bytes(&config_value(&layers)).unwrap();
        let config_identity = identity_from_source(&config);
        let mut manifest = manifest_value(&config_identity, &layers);
        manifest["subject"] = json!({});
        let manifest_source = canonical_json_bytes(&manifest).unwrap();
        let expectation = OciImageExpectationV1::test_only(
            identity_from_source(&manifest_source),
            config_identity,
            layers,
        );
        let message = format!(
            "{:#}",
            validate_manifest_json_source(&manifest_source, &expectation).unwrap_err()
        );
        assert!(message.contains("exact closed key set"), "{message}");

        let layers = one_layer();
        let mut config = config_value(&layers);
        config["config"] = json!({});
        let config_source = canonical_json_bytes(&config).unwrap();
        let expectation = expectation_for_config_source(&config_source, layers);
        let message = format!(
            "{:#}",
            validate_config_json_source(&config_source, &expectation).unwrap_err()
        );
        assert!(message.contains("exact closed key set"), "{message}");

        for pointer in ["/manifests/0", "/manifests/0/platform"] {
            let fixture = canonical_one_layer_fixture();
            let mut index = validate_canonical_json_source(&fixture.index).unwrap();
            index
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("extra".to_owned(), json!(true));
            let source = canonical_json_bytes(&index).unwrap();
            let message = format!(
                "{:#}",
                validate_index_json_source(&source, &fixture.expectation).unwrap_err()
            );
            assert!(
                message.contains("exact closed key set"),
                "{pointer}: {message}"
            );
        }

        for pointer in ["/config", "/layers/0"] {
            let fixture = canonical_one_layer_fixture();
            let mut manifest = validate_canonical_json_source(&fixture.manifest).unwrap();
            manifest
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("extra".to_owned(), json!(true));
            let source = canonical_json_bytes(&manifest).unwrap();
            let expectation = OciImageExpectationV1::test_only(
                identity_from_source(&source),
                identity_from_source(&fixture.config),
                one_layer(),
            );
            let message = format!(
                "{:#}",
                validate_manifest_json_source(&source, &expectation).unwrap_err()
            );
            assert!(
                message.contains("exact closed key set"),
                "{pointer}: {message}"
            );
        }

        let layers = one_layer();
        let mut config = config_value(&layers);
        config["rootfs"]["extra"] = json!(true);
        let source = canonical_json_bytes(&config).unwrap();
        let expectation = expectation_for_config_source(&source, layers);
        let message = format!(
            "{:#}",
            validate_config_json_source(&source, &expectation).unwrap_err()
        );
        assert!(message.contains("exact closed key set"), "{message}");
    }

    #[test]
    fn index_fields_platform_and_cardinality_are_exact() {
        for (pointer, replacement, expected) in [
            ("/schemaVersion", json!(3), "schemaVersion"),
            ("/mediaType", json!(OCI_MANIFEST_MEDIA_TYPE), "mediaType"),
            ("/manifests/0/platform/os", json!("windows"), "field os"),
            (
                "/manifests/0/platform/architecture",
                json!("arm64"),
                "field architecture",
            ),
        ] {
            let fixture = canonical_one_layer_fixture();
            let mut value = validate_canonical_json_source(&fixture.index).unwrap();
            *value.pointer_mut(pointer).unwrap() = replacement;
            let source = canonical_json_bytes(&value).unwrap();
            let message = format!(
                "{:#}",
                validate_index_json_source(&source, &fixture.expectation).unwrap_err()
            );
            assert!(message.contains(expected), "{pointer}: {message}");
        }

        for (pointer, replacement, expected) in [
            (
                "/manifests/0/mediaType",
                json!(OCI_INDEX_MEDIA_TYPE),
                "mediaType",
            ),
            (
                "/manifests/0/digest",
                json!(format_sha256_digest([0x77; 32])),
                "digest differs",
            ),
            (
                "/manifests/0/size",
                json!(
                    canonical_one_layer_fixture()
                        .expectation
                        .manifest()
                        .byte_length()
                        + 1
                ),
                "size differs",
            ),
        ] {
            let fixture = canonical_one_layer_fixture();
            let mut value = validate_canonical_json_source(&fixture.index).unwrap();
            *value.pointer_mut(pointer).unwrap() = replacement;
            let source = canonical_json_bytes(&value).unwrap();
            let message = format!(
                "{:#}",
                validate_index_json_source(&source, &fixture.expectation).unwrap_err()
            );
            assert!(message.contains(expected), "{pointer}: {message}");
        }

        for manifests in [json!([]), json!([{}, {}])] {
            let fixture = canonical_one_layer_fixture();
            let mut value = validate_canonical_json_source(&fixture.index).unwrap();
            value["manifests"] = manifests;
            let source = canonical_json_bytes(&value).unwrap();
            let message = format!(
                "{:#}",
                validate_index_json_source(&source, &fixture.expectation).unwrap_err()
            );
            assert!(message.contains("exactly one manifest"), "{message}");
        }
    }

    #[test]
    fn manifest_descriptor_fields_and_layer_cardinality_are_exact() {
        for (pointer, replacement, expected) in [
            ("/schemaVersion", json!(3), "schemaVersion"),
            ("/mediaType", json!(OCI_INDEX_MEDIA_TYPE), "mediaType"),
            (
                "/config/digest",
                json!(format_sha256_digest([0x77; 32])),
                "digest differs",
            ),
            (
                "/config/size",
                json!(
                    canonical_one_layer_fixture()
                        .expectation
                        .config()
                        .byte_length()
                        + 1
                ),
                "size differs",
            ),
            (
                "/layers/0/mediaType",
                json!(OCI_CONFIG_MEDIA_TYPE),
                "mediaType",
            ),
            ("/layers/0/size", json!(21), "size differs"),
            (
                "/layers/0/digest",
                json!(format_sha256_digest([0x78; 32])),
                "digest differs",
            ),
        ] {
            let fixture = canonical_one_layer_fixture();
            let mut value = validate_canonical_json_source(&fixture.manifest).unwrap();
            *value.pointer_mut(pointer).unwrap() = replacement;
            let source = canonical_json_bytes(&value).unwrap();
            let expectation = OciImageExpectationV1::test_only(
                identity_from_source(&source),
                identity_from_source(&fixture.config),
                one_layer(),
            );
            let message = format!(
                "{:#}",
                validate_manifest_json_source(&source, &expectation).unwrap_err()
            );
            assert!(message.contains(expected), "{pointer}: {message}");
        }

        let fixture = canonical_one_layer_fixture();
        let mut wrong_config = validate_canonical_json_source(&fixture.manifest).unwrap();
        wrong_config["config"]["mediaType"] = json!(OCI_MANIFEST_MEDIA_TYPE);
        let source = canonical_json_bytes(&wrong_config).unwrap();
        let layers = one_layer();
        let config = identity_from_source(&fixture.config);
        let expectation =
            OciImageExpectationV1::test_only(identity_from_source(&source), config, layers);
        let message = format!(
            "{:#}",
            validate_manifest_json_source(&source, &expectation).unwrap_err()
        );
        assert!(message.contains("mediaType"), "{message}");

        let fixture = canonical_one_layer_fixture();
        let mut no_layers = validate_canonical_json_source(&fixture.manifest).unwrap();
        no_layers["layers"] = json!([]);
        let source = canonical_json_bytes(&no_layers).unwrap();
        let expectation = OciImageExpectationV1::test_only(
            identity_from_source(&source),
            identity_from_source(&fixture.config),
            one_layer(),
        );
        let message = format!(
            "{:#}",
            validate_manifest_json_source(&source, &expectation).unwrap_err()
        );
        assert!(message.contains("cardinality"), "{message}");

        let fixture = fixture_with_layers(opposite_digest_order_layers());
        let mut swapped = validate_canonical_json_source(&fixture.manifest).unwrap();
        swapped["layers"].as_array_mut().unwrap().swap(0, 1);
        let source = canonical_json_bytes(&swapped).unwrap();
        let expectation = OciImageExpectationV1::test_only(
            identity_from_source(&source),
            identity_from_source(&fixture.config),
            opposite_digest_order_layers(),
        );
        let message = format!(
            "{:#}",
            validate_manifest_json_source(&source, &expectation).unwrap_err()
        );
        assert!(message.contains("digest differs"), "{message}");
    }

    #[test]
    fn config_platform_rootfs_and_diff_id_order_are_exact() {
        for (pointer, replacement, expected) in [
            ("/architecture", json!("arm64"), "architecture"),
            ("/os", json!("windows"), "field os"),
            ("/rootfs/type", json!("other"), "field type"),
        ] {
            let layers = one_layer();
            let mut value = config_value(&layers);
            *value.pointer_mut(pointer).unwrap() = replacement;
            let source = canonical_json_bytes(&value).unwrap();
            let expectation = expectation_for_config_source(&source, layers);
            let message = format!(
                "{:#}",
                validate_config_json_source(&source, &expectation).unwrap_err()
            );
            assert!(message.contains(expected), "{pointer}: {message}");
        }

        let layers = opposite_digest_order_layers();
        let mut value = config_value(&layers);
        value["rootfs"]["diff_ids"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        let source = canonical_json_bytes(&value).unwrap();
        let expectation = expectation_for_config_source(&source, opposite_digest_order_layers());
        let message = format!(
            "{:#}",
            validate_config_json_source(&source, &expectation).unwrap_err()
        );
        assert!(message.contains("DiffID 0 differs"), "{message}");

        let layers = one_layer();
        let mut value = config_value(&layers);
        value["rootfs"]["diff_ids"] = json!([]);
        let source = canonical_json_bytes(&value).unwrap();
        let expectation = expectation_for_config_source(&source, layers);
        let message = format!(
            "{:#}",
            validate_config_json_source(&source, &expectation).unwrap_err()
        );
        assert!(message.contains("cardinality"), "{message}");
    }

    #[test]
    fn expectation_cardinality_and_all_numeric_boundaries_are_closed() {
        let no_layers = OciImageExpectationV1::test_only(identity(1, 2), identity(2, 2), vec![]);
        assert!(
            validate_oci_image_expectation(&no_layers)
                .unwrap_err()
                .to_string()
                .contains("cardinality")
        );

        let too_many = (0..=OCI_MAX_LAYERS)
            .map(|index| {
                let seed =
                    u8::try_from(index + 3).expect("closed OCI layer-count test seed fits in u8");
                layer(seed, 20, 1_024, seed)
            })
            .collect::<Vec<_>>();
        let too_many = OciImageExpectationV1::test_only(identity(1, 2), identity(2, 2), too_many);
        assert!(
            validate_oci_image_expectation(&too_many)
                .unwrap_err()
                .to_string()
                .contains("cardinality")
        );

        for expectation in [
            OciImageExpectationV1::test_only(identity(1, 1), identity(2, 2), one_layer()),
            OciImageExpectationV1::test_only(
                identity(1, 2),
                identity(2, OCI_JSON_MAX_BYTES + 1),
                one_layer(),
            ),
            OciImageExpectationV1::test_only(
                identity(1, 2),
                identity(2, 2),
                vec![layer(3, OCI_LAYER_MIN_BYTES - 1, 1_024, 4)],
            ),
            OciImageExpectationV1::test_only(
                identity(1, 2),
                identity(2, 2),
                vec![layer(3, OCI_LAYER_MAX_BYTES + 1, 1_024, 4)],
            ),
            OciImageExpectationV1::test_only(
                identity(1, 2),
                identity(2, 2),
                vec![layer(3, 20, OCI_LAYER_MIN_UNCOMPRESSED_BYTES - 1, 4)],
            ),
            OciImageExpectationV1::test_only(
                identity(1, 2),
                identity(2, 2),
                vec![layer(3, 20, OCI_LAYER_MIN_UNCOMPRESSED_BYTES + 1, 4)],
            ),
            OciImageExpectationV1::test_only(
                identity(1, 2),
                identity(2, 2),
                vec![layer(3, 20, OCI_LAYER_MAX_UNCOMPRESSED_BYTES + 512, 4)],
            ),
        ] {
            assert!(validate_oci_image_expectation(&expectation).is_err());
        }

        let aggregate = OciImageExpectationV1::test_only(
            identity(1, 2),
            identity(2, 2),
            vec![
                layer(3, 20, OCI_LAYER_MAX_UNCOMPRESSED_BYTES, 4),
                layer(5, 20, 1_024, 6),
            ],
        );
        assert!(
            validate_oci_image_expectation(&aggregate)
                .unwrap_err()
                .to_string()
                .contains("aggregate")
        );

        let exact_maxima = OciImageExpectationV1::test_only(
            identity(1, OCI_JSON_MAX_BYTES),
            identity(2, OCI_JSON_MAX_BYTES),
            vec![layer(
                3,
                OCI_LAYER_MAX_BYTES,
                OCI_LAYER_MAX_UNCOMPRESSED_BYTES,
                4,
            )],
        );
        validate_oci_image_expectation(&exact_maxima).unwrap();
    }

    #[test]
    fn post_changeset_rootfs_counts_and_bytes_are_closed() {
        let mut expectation =
            OciImageExpectationV1::test_only(identity(1, 2), identity(2, 2), one_layer());
        expectation.post_changeset_rootfs = OciExpectedRootfsV1 {
            entry_count: 3,
            regular_file_count: 1,
            directory_count: 1,
            symbolic_link_count: 1,
            regular_file_bytes: 1_024,
        };
        validate_oci_image_expectation(&expectation).unwrap();

        expectation.post_changeset_rootfs.entry_count = 2;
        assert!(
            validate_oci_image_expectation(&expectation)
                .unwrap_err()
                .to_string()
                .contains("differs from its typed counts")
        );

        expectation.post_changeset_rootfs.entry_count = 3;
        expectation.post_changeset_rootfs.regular_file_count = OCI_MAX_ROOTFS_ENTRIES + 1;
        assert!(
            validate_oci_image_expectation(&expectation)
                .unwrap_err()
                .to_string()
                .contains("exceeds its closed bound")
        );

        expectation.post_changeset_rootfs.regular_file_count = 1;
        expectation.post_changeset_rootfs.regular_file_bytes = 1_025;
        assert!(
            validate_oci_image_expectation(&expectation)
                .unwrap_err()
                .to_string()
                .contains("regular-file bytes exceed the layer stream")
        );
    }

    #[test]
    fn compressed_digests_and_diff_ids_are_globally_unique() {
        for expectation in [
            OciImageExpectationV1::test_only(
                identity(1, 2),
                identity(1, 2),
                vec![layer(3, 20, 1_024, 4)],
            ),
            OciImageExpectationV1::test_only(
                identity(1, 2),
                identity(2, 2),
                vec![layer(1, 20, 1_024, 4)],
            ),
            OciImageExpectationV1::test_only(
                identity(1, 2),
                identity(2, 2),
                vec![layer(3, 20, 1_024, 4), layer(5, 20, 1_024, 4)],
            ),
            OciImageExpectationV1::test_only(
                identity(1, 2),
                identity(2, 2),
                vec![layer(3, 20, 1_024, 4), layer(3, 21, 1_536, 5)],
            ),
        ] {
            assert!(validate_oci_image_expectation(&expectation).is_err());
        }
    }

    #[test]
    fn digest_grammar_descriptor_sizes_and_source_identity_are_exact() {
        let fixture = canonical_one_layer_fixture();
        let mut index = validate_canonical_json_source(&fixture.index).unwrap();
        index["manifests"][0]["digest"] = json!(format!("sha256:{}", "A".repeat(64)));
        let source = canonical_json_bytes(&index).unwrap();
        let message = format!(
            "{:#}",
            validate_index_json_source(&source, &fixture.expectation).unwrap_err()
        );
        assert!(message.contains("lowercase hexadecimal"), "{message}");

        let fixture = canonical_one_layer_fixture();
        let mut index = validate_canonical_json_source(&fixture.index).unwrap();
        index["manifests"][0]["size"] = json!(1);
        let source = canonical_json_bytes(&index).unwrap();
        let message = format!(
            "{:#}",
            validate_index_json_source(&source, &fixture.expectation).unwrap_err()
        );
        assert!(message.contains("closed range"), "{message}");

        let fixture = canonical_one_layer_fixture();
        let wrong_length = OciImageExpectationV1::test_only(
            OciBlobIdentityV1::test_only(
                fixture.expectation.manifest().digest(),
                fixture.expectation.manifest().byte_length() + 1,
            ),
            identity_from_source(&fixture.config),
            one_layer(),
        );
        let message = format!(
            "{:#}",
            validate_manifest_json_source(&fixture.manifest, &wrong_length).unwrap_err()
        );
        assert!(message.contains("byte length differs"), "{message}");

        let fixture = canonical_one_layer_fixture();
        let wrong_digest = OciImageExpectationV1::test_only(
            identity(0xff, fixture.manifest.len() as u64),
            identity_from_source(&fixture.config),
            one_layer(),
        );
        let message = format!(
            "{:#}",
            validate_manifest_json_source(&fixture.manifest, &wrong_digest).unwrap_err()
        );
        assert!(message.contains("SHA-256 differs"), "{message}");
    }

    #[test]
    fn codec_types_are_non_cloneable_non_copyable_and_have_no_ambient_authority() {
        trait AmbiguousIfClone<Marker> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfClone<()> for T {}
        impl<T: Clone> AmbiguousIfClone<u8> for T {}

        trait AmbiguousIfCopy<Marker> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfCopy<()> for T {}
        impl<T: Copy> AmbiguousIfCopy<u8> for T {}

        <OciBlobIdentityV1 as AmbiguousIfClone<_>>::marker();
        <OciBlobIdentityV1 as AmbiguousIfCopy<_>>::marker();
        <OciExpectedLayerV1 as AmbiguousIfClone<_>>::marker();
        <OciExpectedLayerV1 as AmbiguousIfCopy<_>>::marker();
        <OciImageExpectationV1 as AmbiguousIfClone<_>>::marker();
        <OciImageExpectationV1 as AmbiguousIfCopy<_>>::marker();

        let source = include_str!("json.rs");
        let normalized = source.replace("\r\n", "\n");
        let production = normalized
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .unwrap();
        for forbidden in [
            "std::fs",
            "File::",
            "OpenOptions",
            "BorrowedFd",
            "OwnedFd",
            "AsFd",
            "AsRawFd",
            "Seek",
            "Command::new",
            "Serialize",
            "Deserialize",
            "include_bytes!",
        ] {
            assert!(!production.contains(forbidden), "forbidden {forbidden}");
        }
        let const_constructor = ["#[cfg(test)]\n    pub(super) const fn test_", "only("].concat();
        let constructor = ["#[cfg(test)]\n    pub(super) fn test_", "only("].concat();
        let constructor_name = ["fn test_", "only("].concat();
        assert_eq!(production.matches(&const_constructor).count(), 3);
        assert_eq!(production.matches(&constructor).count(), 1);
        assert_eq!(normalized.matches(&constructor_name).count(), 4);
        assert_eq!(production.matches("\n        Self {").count(), 4);

        for (type_name, methods, expected_occurrences) in [
            (
                "OciBlobIdentityV1",
                ["test_only", "digest", "byte_length"].as_slice(),
                16,
            ),
            (
                "OciExpectedLayerV1",
                [
                    "test_only",
                    "compressed",
                    "uncompressed_byte_length",
                    "diff_id",
                ]
                .as_slice(),
                6,
            ),
            (
                "OciExpectedRootfsV1",
                [
                    "test_only",
                    "entry_count",
                    "regular_file_count",
                    "directory_count",
                    "symbolic_link_count",
                    "regular_file_bytes",
                ]
                .as_slice(),
                7,
            ),
            (
                "OciImageExpectationV1",
                [
                    "test_only",
                    "test_only_with_post_changeset_rootfs",
                    "manifest",
                    "config",
                    "layers",
                    "post_changeset_rootfs",
                ]
                .as_slice(),
                10,
            ),
        ] {
            let implementation = production
                .split(&format!("impl {type_name} {{"))
                .nth(1)
                .unwrap()
                .split("\n}")
                .next()
                .unwrap();
            assert_eq!(declared_fn_names(implementation), methods, "{type_name}");
            assert_eq!(
                production.matches(type_name).count(),
                expected_occurrences,
                "unexpected production authority for {type_name}"
            );
        }
    }

    #[test]
    fn authenticated_profile_projection_copies_the_exact_closed_graph() {
        let source = include_str!("json.rs");
        let production = source.split("\n#[cfg(test)]\nmod tests").next().unwrap();

        assert!(production.contains("pub(super) fn project_authenticated_oci_image_expectation("));
        for field_projection in [
            "profile.manifest().digest()",
            "profile.manifest().byte_length()",
            "profile.config().digest()",
            "profile.config().byte_length()",
            "profile.layers().len()",
            "layer.compressed_digest()",
            "layer.compressed_byte_length()",
            "layer.uncompressed_byte_length()",
            "layer.diff_id()",
            "profile.post_changeset_rootfs().entry_count()",
            "profile.post_changeset_rootfs().regular_file_count()",
            "profile.post_changeset_rootfs().directory_count()",
            "profile.post_changeset_rootfs().symbolic_link_count()",
            "profile.post_changeset_rootfs().regular_file_bytes()",
        ] {
            assert!(
                production.contains(field_projection),
                "missing authenticated profile projection for {field_projection}"
            );
        }
        assert!(production.contains("validate_oci_image_expectation(&expectation)?;"));
    }
}
