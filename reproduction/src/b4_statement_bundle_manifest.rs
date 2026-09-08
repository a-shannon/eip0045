// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Strict decode-only authentication of one `ErgoStatementBundleV1` manifest.

use anyhow::{Context as _, Result, ensure};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::{
    canonical::{validate_canonical_json_source, validate_lower_hex_exact},
    claim::{ReceiptClaimDigests, ok_receipt_claim_digests},
    constants::{
        DIGEST_BYTES, ERGO_STATEMENT_DOMAIN, MAX_APPLICATION_PAYLOAD_BYTES, MAX_STATEMENT_BYTES,
        STATEMENT_PREFIX_BYTES,
    },
    ergo_statement::{ErgoStatementV1, parse_ergo_statement_v1},
};

const STATEMENT_BUNDLE_FORMAT: &str = "ErgoStatementBundleV1";
const STATEMENT_BUNDLE_FORMAT_VERSION: u8 = 1;
const STATEMENT_VERSION: u8 = 1;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_PROPOSITION_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArtifactBindingV1 {
    length: usize,
    sha256: [u8; DIGEST_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StatementBundleManifestV1 {
    application_payload: ArtifactBindingV1,
    chain_domain_id: [u8; DIGEST_BYTES],
    profile_id: [u8; DIGEST_BYTES],
    program_id: [u8; DIGEST_BYTES],
    contract_id: [u8; DIGEST_BYTES],
    proposition: ArtifactBindingV1,
    statement: ArtifactBindingV1,
    claim: ReceiptClaimDigests,
}

impl StatementBundleManifestV1 {
    /// Decode and authenticate the closed statement-bundle manifest grammar.
    ///
    /// This codec deliberately authenticates only identities derivable from
    /// the manifest itself. Proposition bytes are not an input here, so their
    /// artifact length and SHA-256 remain typed custody identities rather than
    /// a rederived contract-ID claim.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized or non-canonical source, a duplicate
    /// or unknown field, any inventory/order/type/bound mismatch, non-lowercase
    /// digest, or any inconsistent repeated identity.
    pub(crate) fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            source.len() <= MAX_MANIFEST_BYTES,
            "statement-bundle manifest has {} bytes, maximum is {MAX_MANIFEST_BYTES}",
            source.len()
        );
        let value = validate_canonical_json_source(source)
            .context("statement-bundle manifest is not exact RFC 8785 JCS")?;
        let raw: RawStatementManifestV1 = serde_json::from_value(value)
            .context("statement-bundle manifest has an invalid closed shape")?;

        ensure!(
            raw.format == STATEMENT_BUNDLE_FORMAT,
            "statement-bundle manifest format is not exact"
        );
        ensure!(
            raw.format_version == STATEMENT_BUNDLE_FORMAT_VERSION,
            "statement-bundle manifest format version is not V1"
        );
        ensure!(
            raw.statement.domain_hex == hex::encode(ERGO_STATEMENT_DOMAIN),
            "statement-bundle statement domain is not exact"
        );
        ensure!(
            raw.statement.version == STATEMENT_VERSION,
            "statement-bundle statement version is not V1"
        );

        let artifacts = authenticate_artifact_inventory(&raw.artifacts)?;

        let chain_domain_id = decode_digest(
            &raw.statement.chain_domain_id,
            "statement-bundle chain-domain ID",
        )?;
        let profile_id = decode_digest(&raw.statement.profile_id, "statement-bundle profile ID")?;
        let program_id = decode_digest(&raw.statement.program_id, "statement-bundle program ID")?;
        let contract_id =
            decode_digest(&raw.statement.contract_id, "statement-bundle contract ID")?;
        let claim = ReceiptClaimDigests {
            expected_claim: decode_digest(
                &raw.claim.expected_claim,
                "statement-bundle expected claim",
            )?,
            journal_digest: decode_digest(
                &raw.claim.journal_digest,
                "statement-bundle journal digest",
            )?,
            output: decode_digest(&raw.claim.output, "statement-bundle output digest")?,
            post: decode_digest(&raw.claim.post, "statement-bundle post digest")?,
        };
        let statement_sha256 = decode_digest(
            &raw.statement.statement_sha256,
            "statement-bundle statement SHA-256",
        )?;

        ensure!(
            artifacts.application_payload.length == raw.statement.application_payload_length,
            "application-payload artifact length differs from the statement scalar"
        );
        ensure!(
            artifacts.proposition.length == raw.statement.proposition_bytes_length,
            "proposition artifact length differs from the statement scalar"
        );
        ensure!(
            artifacts.statement.length == raw.statement.statement_length,
            "statement artifact length differs from the statement scalar"
        );
        ensure!(
            artifacts.statement.sha256 == statement_sha256,
            "statement artifact SHA-256 differs from the statement scalar"
        );
        let derived_statement_length = STATEMENT_PREFIX_BYTES
            .checked_add(raw.statement.application_payload_length)
            .context("statement length arithmetic overflowed")?;
        ensure!(
            raw.statement.statement_length == derived_statement_length,
            "statement length is inconsistent with its application-payload length"
        );
        ensure!(
            claim.journal_digest == statement_sha256,
            "journal digest differs from the exact statement SHA-256"
        );

        bind_raw_digest_artifacts(
            &artifacts,
            &chain_domain_id,
            &profile_id,
            &program_id,
            &contract_id,
            &claim,
        )?;

        Ok(Self {
            application_payload: artifacts.application_payload,
            chain_domain_id,
            profile_id,
            program_id,
            contract_id,
            proposition: artifacts.proposition,
            statement: artifacts.statement,
            claim,
        })
    }

    /// Chain-domain ID decoded from the exact manifest scalar.
    pub(crate) const fn chain_domain_id(&self) -> [u8; DIGEST_BYTES] {
        self.chain_domain_id
    }

    /// Immutable verifier-profile ID decoded from the exact manifest scalar.
    pub(crate) const fn profile_id(&self) -> [u8; DIGEST_BYTES] {
        self.profile_id
    }

    /// Guest-program ID decoded from the exact manifest scalar.
    pub(crate) const fn program_id(&self) -> [u8; DIGEST_BYTES] {
        self.program_id
    }

    /// Bound contract ID decoded from the exact manifest scalar.
    pub(crate) const fn contract_id(&self) -> [u8; DIGEST_BYTES] {
        self.contract_id
    }

    /// Declared application-payload artifact length.
    pub(crate) const fn application_payload_length(&self) -> usize {
        self.application_payload.length
    }

    /// Declared application-payload artifact SHA-256.
    pub(crate) const fn application_payload_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.application_payload.sha256
    }

    /// Declared proposition artifact length.
    #[allow(
        dead_code,
        reason = "proposition bytes remain a later physical-custody input, not a manifest-only derivation"
    )]
    pub(crate) const fn proposition_length(&self) -> usize {
        self.proposition.length
    }

    /// Declared proposition artifact SHA-256 custody identity.
    #[allow(
        dead_code,
        reason = "proposition bytes remain a later physical-custody input, not a manifest-only derivation"
    )]
    pub(crate) const fn proposition_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.proposition.sha256
    }

    /// Declared statement artifact length.
    pub(crate) const fn statement_length(&self) -> usize {
        self.statement.length
    }

    /// Declared statement artifact SHA-256.
    pub(crate) const fn statement_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.statement.sha256
    }

    /// Authenticate exact statement bytes against every derivable manifest
    /// identity and independently rebuild the successful receipt claim.
    ///
    /// # Errors
    ///
    /// Returns an error unless the bytes are a strict round-tripping
    /// `ErgoStatementV1`, match every statement and payload identity, and
    /// rederive all four manifest claim digests.
    pub(crate) fn authenticate_statement<'a>(
        &self,
        source: &'a [u8],
    ) -> Result<AuthenticatedStatementV1<'a>> {
        let statement = parse_ergo_statement_v1(source)
            .context("statement-bundle statement is not strict ErgoStatementV1")?;
        ensure!(
            statement.encode()? == source,
            "statement-bundle statement decode/re-encode changed bytes"
        );
        ensure!(
            source.len() == self.statement.length,
            "statement bytes differ from the manifest length"
        );
        ensure!(
            sha256(source) == self.statement.sha256,
            "statement bytes differ from the manifest SHA-256"
        );
        ensure!(
            statement.chain_domain_id() == self.chain_domain_id,
            "statement chain-domain ID differs from the manifest"
        );
        ensure!(
            statement.profile_id() == self.profile_id,
            "statement profile ID differs from the manifest"
        );
        ensure!(
            statement.program_id() == self.program_id,
            "statement program ID differs from the manifest"
        );
        ensure!(
            statement.contract_id() == self.contract_id,
            "statement contract ID differs from the manifest"
        );
        ensure!(
            statement.application_payload().len() == self.application_payload.length,
            "statement application-payload length differs from the manifest"
        );
        ensure!(
            statement.application_payload_sha256() == self.application_payload.sha256,
            "statement application-payload SHA-256 differs from the manifest"
        );
        let claim = ok_receipt_claim_digests(&statement.program_id(), source)
            .context("cannot derive the statement-bundle successful receipt claim")?;
        ensure!(
            claim == self.claim,
            "statement-derived receipt claim differs from the manifest"
        );
        Ok(AuthenticatedStatementV1 { statement, claim })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Strict statement value paired with its independently reconstructed claim.
pub(crate) struct AuthenticatedStatementV1<'a> {
    statement: ErgoStatementV1<'a>,
    claim: ReceiptClaimDigests,
}

impl<'a> AuthenticatedStatementV1<'a> {
    /// Strictly parsed statement borrowing the exact authenticated source.
    pub(crate) const fn statement(&self) -> ErgoStatementV1<'a> {
        self.statement
    }

    /// All four independently reconstructed successful-claim digests.
    pub(crate) const fn claim_digests(&self) -> ReceiptClaimDigests {
        self.claim
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawStatementManifestV1 {
    artifacts: [RawArtifactIdentityV1; 11],
    claim: RawClaimIdentityV1,
    format: String,
    format_version: u8,
    statement: RawStatementIdentityV1,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawArtifactIdentityV1 {
    length: usize,
    path: String,
    role: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawClaimIdentityV1 {
    expected_claim: String,
    journal_digest: String,
    output: String,
    post: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawStatementIdentityV1 {
    application_payload_length: usize,
    chain_domain_id: String,
    contract_id: String,
    domain_hex: String,
    profile_id: String,
    program_id: String,
    proposition_bytes_length: usize,
    statement_length: usize,
    statement_sha256: String,
    version: u8,
}

#[derive(Clone, Copy)]
struct ArtifactSpec {
    path: &'static str,
    role: &'static str,
    minimum_length: usize,
    maximum_length: usize,
}

const ARTIFACT_SPECS: [ArtifactSpec; 11] = [
    ArtifactSpec {
        path: "application-payload.bin",
        role: "application-payload",
        minimum_length: 0,
        maximum_length: MAX_APPLICATION_PAYLOAD_BYTES,
    },
    ArtifactSpec {
        path: "chain-domain-id.bin",
        role: "chain-domain-id",
        minimum_length: DIGEST_BYTES,
        maximum_length: DIGEST_BYTES,
    },
    ArtifactSpec {
        path: "claim-digest.bin",
        role: "expected-claim-digest",
        minimum_length: DIGEST_BYTES,
        maximum_length: DIGEST_BYTES,
    },
    ArtifactSpec {
        path: "contract-id.bin",
        role: "contract-id",
        minimum_length: DIGEST_BYTES,
        maximum_length: DIGEST_BYTES,
    },
    ArtifactSpec {
        path: "journal-digest.bin",
        role: "journal-digest",
        minimum_length: DIGEST_BYTES,
        maximum_length: DIGEST_BYTES,
    },
    ArtifactSpec {
        path: "output-digest.bin",
        role: "receipt-output-digest",
        minimum_length: DIGEST_BYTES,
        maximum_length: DIGEST_BYTES,
    },
    ArtifactSpec {
        path: "post-digest.bin",
        role: "receipt-post-digest",
        minimum_length: DIGEST_BYTES,
        maximum_length: DIGEST_BYTES,
    },
    ArtifactSpec {
        path: "profile-id.bin",
        role: "stark-profile-id",
        minimum_length: DIGEST_BYTES,
        maximum_length: DIGEST_BYTES,
    },
    ArtifactSpec {
        path: "program-id.bin",
        role: "guest-program-id",
        minimum_length: DIGEST_BYTES,
        maximum_length: DIGEST_BYTES,
    },
    ArtifactSpec {
        path: "proposition.bin",
        role: "self-proposition-bytes",
        minimum_length: 1,
        maximum_length: MAX_PROPOSITION_BYTES,
    },
    ArtifactSpec {
        path: "statement.bin",
        role: "ergo-statement-v1",
        minimum_length: STATEMENT_PREFIX_BYTES,
        maximum_length: MAX_STATEMENT_BYTES,
    },
];

struct AuthenticatedArtifactInventoryV1 {
    application_payload: ArtifactBindingV1,
    chain_domain_id: ArtifactBindingV1,
    expected_claim: ArtifactBindingV1,
    contract_id: ArtifactBindingV1,
    journal_digest: ArtifactBindingV1,
    output_digest: ArtifactBindingV1,
    post_digest: ArtifactBindingV1,
    profile_id: ArtifactBindingV1,
    program_id: ArtifactBindingV1,
    proposition: ArtifactBindingV1,
    statement: ArtifactBindingV1,
}

fn authenticate_artifact_inventory(
    raw: &[RawArtifactIdentityV1; 11],
) -> Result<AuthenticatedArtifactInventoryV1> {
    let [
        application_payload,
        chain_domain_id,
        expected_claim,
        contract_id,
        journal_digest,
        output_digest,
        post_digest,
        profile_id,
        program_id,
        proposition,
        statement,
    ] = raw;
    Ok(AuthenticatedArtifactInventoryV1 {
        application_payload: authenticate_artifact(application_payload, ARTIFACT_SPECS[0])?,
        chain_domain_id: authenticate_artifact(chain_domain_id, ARTIFACT_SPECS[1])?,
        expected_claim: authenticate_artifact(expected_claim, ARTIFACT_SPECS[2])?,
        contract_id: authenticate_artifact(contract_id, ARTIFACT_SPECS[3])?,
        journal_digest: authenticate_artifact(journal_digest, ARTIFACT_SPECS[4])?,
        output_digest: authenticate_artifact(output_digest, ARTIFACT_SPECS[5])?,
        post_digest: authenticate_artifact(post_digest, ARTIFACT_SPECS[6])?,
        profile_id: authenticate_artifact(profile_id, ARTIFACT_SPECS[7])?,
        program_id: authenticate_artifact(program_id, ARTIFACT_SPECS[8])?,
        proposition: authenticate_artifact(proposition, ARTIFACT_SPECS[9])?,
        statement: authenticate_artifact(statement, ARTIFACT_SPECS[10])?,
    })
}

fn authenticate_artifact(
    raw: &RawArtifactIdentityV1,
    spec: ArtifactSpec,
) -> Result<ArtifactBindingV1> {
    ensure!(
        raw.path == spec.path,
        "statement-bundle artifact path differs from exact generator order: expected {}, found {}",
        spec.path,
        raw.path
    );
    ensure!(
        raw.role == spec.role,
        "{} role differs from exact generator role {}",
        spec.path,
        spec.role
    );
    ensure!(
        (spec.minimum_length..=spec.maximum_length).contains(&raw.length),
        "{} has declared length {}, expected {}..={}",
        spec.path,
        raw.length,
        spec.minimum_length,
        spec.maximum_length
    );
    let sha256 = decode_digest(&raw.sha256, &format!("{} SHA-256", spec.path))?;
    Ok(ArtifactBindingV1 {
        length: raw.length,
        sha256,
    })
}

fn decode_digest(value: &str, label: &str) -> Result<[u8; DIGEST_BYTES]> {
    validate_lower_hex_exact(value, DIGEST_BYTES)
        .with_context(|| format!("{label} is not exact lowercase hex"))?;
    hex::decode(value)?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("{label} has {} decoded bytes", bytes.len()))
}

fn bind_raw_digest_artifact(
    artifact: ArtifactBindingV1,
    digest: &[u8; DIGEST_BYTES],
    label: &str,
) -> Result<()> {
    ensure!(
        artifact.sha256 == sha256(digest),
        "{label} raw digest artifact SHA-256 differs from its decoded scalar"
    );
    Ok(())
}

fn bind_raw_digest_artifacts(
    artifacts: &AuthenticatedArtifactInventoryV1,
    chain_domain_id: &[u8; DIGEST_BYTES],
    profile_id: &[u8; DIGEST_BYTES],
    program_id: &[u8; DIGEST_BYTES],
    contract_id: &[u8; DIGEST_BYTES],
    claim: &ReceiptClaimDigests,
) -> Result<()> {
    for (artifact, digest, label) in [
        (
            artifacts.chain_domain_id,
            chain_domain_id,
            "chain-domain ID",
        ),
        (artifacts.profile_id, profile_id, "profile ID"),
        (artifacts.program_id, program_id, "program ID"),
        (artifacts.contract_id, contract_id, "contract ID"),
        (
            artifacts.expected_claim,
            &claim.expected_claim,
            "expected claim",
        ),
        (
            artifacts.journal_digest,
            &claim.journal_digest,
            "journal digest",
        ),
        (artifacts.output_digest, &claim.output, "output digest"),
        (artifacts.post_digest, &claim.post, "post digest"),
    ] {
        bind_raw_digest_artifact(artifact, digest, label)?;
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> [u8; DIGEST_BYTES] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::{
        canonical::canonical_json_bytes,
        claim::{ReceiptClaimDigests, ok_receipt_claim_digests},
        constants::{
            ERGO_STATEMENT_DOMAIN, MAX_APPLICATION_PAYLOAD_BYTES, MAX_STATEMENT_BYTES,
            STATEMENT_PREFIX_BYTES,
        },
        ergo_statement::ErgoStatementV1,
    };

    struct Fixture {
        value: Value,
        manifest: Vec<u8>,
        statement: Vec<u8>,
        chain_domain_id: [u8; 32],
        profile_id: [u8; 32],
        program_id: [u8; 32],
        contract_id: [u8; 32],
        proposition: Vec<u8>,
        application_payload: Vec<u8>,
        claim: ReceiptClaimDigests,
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn artifact(path: &str, role: &str, bytes: &[u8]) -> Value {
        json!({
            "length": bytes.len(),
            "path": path,
            "role": role,
            "sha256": sha256_hex(bytes),
        })
    }

    fn fixture() -> Fixture {
        build_fixture(
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
            vec![0x55; 85],
            b"statement payload".to_vec(),
        )
    }

    fn build_fixture(
        chain_domain_id: [u8; 32],
        profile_id: [u8; 32],
        program_id: [u8; 32],
        contract_id: [u8; 32],
        proposition: Vec<u8>,
        application_payload: Vec<u8>,
    ) -> Fixture {
        let statement = ErgoStatementV1::new(
            chain_domain_id,
            profile_id,
            program_id,
            contract_id,
            &application_payload,
        )
        .unwrap()
        .encode()
        .unwrap();
        let claim = ok_receipt_claim_digests(&program_id, &statement).unwrap();
        let value = json!({
            "artifacts": [
                artifact("application-payload.bin", "application-payload", &application_payload),
                artifact("chain-domain-id.bin", "chain-domain-id", &chain_domain_id),
                artifact("claim-digest.bin", "expected-claim-digest", &claim.expected_claim),
                artifact("contract-id.bin", "contract-id", &contract_id),
                artifact("journal-digest.bin", "journal-digest", &claim.journal_digest),
                artifact("output-digest.bin", "receipt-output-digest", &claim.output),
                artifact("post-digest.bin", "receipt-post-digest", &claim.post),
                artifact("profile-id.bin", "stark-profile-id", &profile_id),
                artifact("program-id.bin", "guest-program-id", &program_id),
                artifact("proposition.bin", "self-proposition-bytes", &proposition),
                artifact("statement.bin", "ergo-statement-v1", &statement),
            ],
            "claim": {
                "expectedClaim": hex::encode(claim.expected_claim),
                "journalDigest": hex::encode(claim.journal_digest),
                "output": hex::encode(claim.output),
                "post": hex::encode(claim.post),
            },
            "format": "ErgoStatementBundleV1",
            "formatVersion": 1,
            "statement": {
                "applicationPayloadLength": application_payload.len(),
                "chainDomainId": hex::encode(chain_domain_id),
                "contractId": hex::encode(contract_id),
                "domainHex": hex::encode(ERGO_STATEMENT_DOMAIN),
                "profileId": hex::encode(profile_id),
                "programId": hex::encode(program_id),
                "propositionBytesLength": proposition.len(),
                "statementLength": statement.len(),
                "statementSha256": sha256_hex(&statement),
                "version": 1,
            },
        });
        Fixture {
            manifest: canonical_json_bytes(&value).unwrap(),
            value,
            statement,
            chain_domain_id,
            profile_id,
            program_id,
            contract_id,
            proposition,
            application_payload,
            claim,
        }
    }

    fn decode32(value: &str) -> [u8; 32] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    fn source(value: &Value) -> Vec<u8> {
        canonical_json_bytes(value).unwrap()
    }

    fn assert_rejected(value: &Value, label: &str) {
        assert!(
            StatementBundleManifestV1::from_canonical_jcs(&source(value)).is_err(),
            "accepted {label}"
        );
    }

    fn artifacts_mut(value: &mut Value) -> &mut Vec<Value> {
        value["artifacts"].as_array_mut().unwrap()
    }

    fn changed_digest_hex() -> String {
        "ee".repeat(32)
    }

    fn changed_digest() -> [u8; 32] {
        [0xee; 32]
    }

    fn bind_raw_digest_artifact(value: &mut Value, index: usize, digest: &[u8; 32]) {
        value["artifacts"][index]["sha256"] = json!(sha256_hex(digest));
    }

    fn rebind_claim(value: &mut Value, claim: ReceiptClaimDigests) {
        for (pointer, artifact_index, digest) in [
            ("/claim/expectedClaim", 2, claim.expected_claim),
            ("/claim/journalDigest", 4, claim.journal_digest),
            ("/claim/output", 5, claim.output),
            ("/claim/post", 6, claim.post),
        ] {
            *value.pointer_mut(pointer).unwrap() = json!(hex::encode(digest));
            bind_raw_digest_artifact(value, artifact_index, &digest);
        }
    }

    fn rebind_statement_transport_and_claim(
        value: &mut Value,
        statement: &[u8],
        program_id: &[u8; 32],
    ) {
        value["statement"]["statementLength"] = json!(statement.len());
        value["statement"]["statementSha256"] = json!(sha256_hex(statement));
        value["artifacts"][10]["length"] = json!(statement.len());
        value["artifacts"][10]["sha256"] = json!(sha256_hex(statement));
        rebind_claim(
            value,
            ok_receipt_claim_digests(program_id, statement).unwrap(),
        );
    }

    #[test]
    fn canonical_generator_shape_is_accepted() {
        let fixture = fixture();
        let manifest = StatementBundleManifestV1::from_canonical_jcs(&fixture.manifest).unwrap();
        assert_eq!(manifest.chain_domain_id(), fixture.chain_domain_id);
        assert_eq!(manifest.profile_id(), fixture.profile_id);
        assert_eq!(manifest.program_id(), fixture.program_id);
        assert_eq!(manifest.contract_id(), fixture.contract_id);
        assert_eq!(
            manifest.application_payload_length(),
            fixture.application_payload.len()
        );
        assert_eq!(
            manifest.application_payload_sha256(),
            Sha256::digest(&fixture.application_payload).as_slice()
        );
        assert_eq!(manifest.proposition_length(), fixture.proposition.len());
        assert_eq!(
            manifest.proposition_sha256(),
            Sha256::digest(&fixture.proposition).as_slice()
        );
        assert_eq!(manifest.statement_length(), fixture.statement.len());
        assert_eq!(
            manifest.statement_sha256(),
            Sha256::digest(&fixture.statement).as_slice()
        );
    }

    #[test]
    fn frozen_generator_reference_manifest_known_answer_is_accepted() {
        let fixture = build_fixture(
            decode32("b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b"),
            decode32("23c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383"),
            decode32("9490a07414919c7eca0176d4ff9614523beecc8746ae7ffd4916f29b2edb9fe5"),
            decode32("f3582418f41ba6920c83758e56ac4475bf6084a039f91a762388e774258a6c61"),
            hex::decode(concat!(
                "1c53020e209490a07414919c7eca0176d4ff9614523beecc8746ae7ffd4916f29b2edb9fe5",
                "0e2023c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383",
                "d1b9e4e3001ae4e3010e73007301"
            ))
            .unwrap(),
            (0_u8..32).collect(),
        );
        assert_eq!(
            sha256_hex(&fixture.manifest),
            "83a2c75473d4d048cdf66d922a4f9ab6909d46025ce94c3a3793e1348c388123"
        );
        let manifest = StatementBundleManifestV1::from_canonical_jcs(&fixture.manifest).unwrap();
        manifest.authenticate_statement(&fixture.statement).unwrap();
    }

    #[test]
    fn exact_statement_is_strictly_authenticated_and_claim_is_rederived() {
        let fixture = fixture();
        let manifest = StatementBundleManifestV1::from_canonical_jcs(&fixture.manifest).unwrap();
        let authenticated = manifest.authenticate_statement(&fixture.statement).unwrap();
        assert_eq!(
            authenticated.statement().encode().unwrap(),
            fixture.statement
        );
        assert_eq!(authenticated.claim_digests(), fixture.claim);
    }

    #[test]
    fn source_must_be_canonical_unique_and_bounded() {
        let fixture = fixture();

        let mut noncanonical = fixture.manifest.clone();
        noncanonical.push(b'\n');
        assert!(StatementBundleManifestV1::from_canonical_jcs(&noncanonical).is_err());

        let duplicate = br#"{"format":"ErgoStatementBundleV1","format":"ErgoStatementBundleV1"}"#;
        let duplicate_error = StatementBundleManifestV1::from_canonical_jcs(duplicate)
            .err()
            .unwrap();
        assert!(format!("{duplicate_error:#}").contains("duplicate object key"));

        let mut unknown = fixture.value.clone();
        unknown["unknown"] = json!(true);
        assert_rejected(&unknown, "unknown top-level field");

        let mut oversized = fixture.value;
        oversized["unknown"] = json!("x".repeat(64 * 1024));
        let oversized = source(&oversized);
        assert!(oversized.len() > 64 * 1024);
        assert!(StatementBundleManifestV1::from_canonical_jcs(&oversized).is_err());
    }

    #[test]
    fn unknown_fields_are_rejected_at_every_object_layer() {
        let fixture = fixture();
        for (label, pointer) in [
            ("artifact", "/artifacts/0"),
            ("claim", "/claim"),
            ("statement", "/statement"),
        ] {
            let mut value = fixture.value.clone();
            value
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("unknown".to_owned(), json!(true));
            assert_rejected(&value, &format!("{label} unknown field"));
        }
    }

    #[test]
    fn format_and_versions_are_exact() {
        let fixture = fixture();
        for (label, pointer, replacement) in [
            ("format", "/format", json!("ErgoStatementBundleV2")),
            ("format version", "/formatVersion", json!(2)),
            ("statement domain", "/statement/domainHex", json!("00")),
            ("statement version", "/statement/version", json!(2)),
        ] {
            let mut value = fixture.value.clone();
            *value.pointer_mut(pointer).unwrap() = replacement;
            assert_rejected(&value, label);
        }
    }

    #[test]
    fn artifact_inventory_is_exact_ordered_and_typed() {
        let fixture = fixture();

        let mut missing = fixture.value.clone();
        artifacts_mut(&mut missing).remove(3);
        assert_rejected(&missing, "missing artifact");

        let mut extra = fixture.value.clone();
        let duplicate = artifacts_mut(&mut extra)[3].clone();
        artifacts_mut(&mut extra).push(duplicate);
        assert_rejected(&extra, "extra artifact");

        let mut reordered = fixture.value.clone();
        artifacts_mut(&mut reordered).swap(0, 1);
        assert_rejected(&reordered, "reordered artifacts");

        let mut duplicated = fixture.value.clone();
        let first = artifacts_mut(&mut duplicated)[0].clone();
        artifacts_mut(&mut duplicated)[1] = first;
        assert_rejected(&duplicated, "duplicate artifact");

        let mut path = fixture.value.clone();
        path["artifacts"][0]["path"] = json!("payload.bin");
        assert_rejected(&path, "artifact path");

        let mut role = fixture.value;
        role["artifacts"][0]["role"] = json!("payload");
        assert_rejected(&role, "artifact role");
    }

    #[test]
    fn every_artifact_role_has_its_exact_length_bound() {
        let fixture = fixture();
        let invalid_lengths = [
            (0, MAX_APPLICATION_PAYLOAD_BYTES + 1),
            (1, 31),
            (2, 31),
            (3, 31),
            (4, 31),
            (5, 31),
            (6, 31),
            (7, 31),
            (8, 31),
            (9, 0),
            (9, 4097),
            (10, STATEMENT_PREFIX_BYTES - 1),
            (10, MAX_STATEMENT_BYTES + 1),
        ];
        for (index, length) in invalid_lengths {
            let mut value = fixture.value.clone();
            value["artifacts"][index]["length"] = json!(length);
            assert_rejected(&value, &format!("artifact {index} length {length}"));
        }
    }

    #[test]
    fn every_artifact_sha_is_lowercase_hex32() {
        let fixture = fixture();
        for index in 0..11 {
            let mut value = fixture.value.clone();
            value["artifacts"][index]["sha256"] = json!("A".repeat(64));
            assert_rejected(&value, &format!("artifact {index} uppercase SHA-256"));
        }
    }

    #[test]
    fn every_digest_scalar_is_lowercase_hex32() {
        let fixture = fixture();
        for pointer in [
            "/statement/chainDomainId",
            "/statement/contractId",
            "/statement/profileId",
            "/statement/programId",
            "/statement/statementSha256",
            "/claim/expectedClaim",
            "/claim/journalDigest",
            "/claim/output",
            "/claim/post",
        ] {
            let mut value = fixture.value.clone();
            *value.pointer_mut(pointer).unwrap() = json!("A".repeat(64));
            assert_rejected(&value, pointer);
        }
    }

    #[test]
    fn every_statement_scalar_is_bound_to_its_typed_artifact_or_constant() {
        let fixture = fixture();
        let mutations = [
            (
                "application payload length",
                "/statement/applicationPayloadLength",
                json!(fixture.application_payload.len() + 1),
            ),
            (
                "chain domain ID",
                "/statement/chainDomainId",
                json!(changed_digest_hex()),
            ),
            (
                "contract ID",
                "/statement/contractId",
                json!(changed_digest_hex()),
            ),
            (
                "profile ID",
                "/statement/profileId",
                json!(changed_digest_hex()),
            ),
            (
                "program ID",
                "/statement/programId",
                json!(changed_digest_hex()),
            ),
            (
                "proposition length",
                "/statement/propositionBytesLength",
                json!(fixture.proposition.len() + 1),
            ),
            (
                "statement length",
                "/statement/statementLength",
                json!(fixture.statement.len() + 1),
            ),
            (
                "statement SHA-256",
                "/statement/statementSha256",
                json!(changed_digest_hex()),
            ),
        ];
        for (label, pointer, replacement) in mutations {
            let mut value = fixture.value.clone();
            *value.pointer_mut(pointer).unwrap() = replacement;
            assert_rejected(&value, label);
        }
    }

    #[test]
    fn derivable_statement_length_and_journal_sha_relations_are_exact() {
        let fixture = fixture();

        let mut impossible_lengths = fixture.value.clone();
        let changed_statement_length = fixture.statement.len() + 1;
        impossible_lengths["statement"]["statementLength"] = json!(changed_statement_length);
        impossible_lengths["artifacts"][10]["length"] = json!(changed_statement_length);
        assert_rejected(
            &impossible_lengths,
            "statement length inconsistent with payload length",
        );

        let mut journal_sha = fixture.value;
        journal_sha["claim"]["journalDigest"] = json!(changed_digest_hex());
        bind_raw_digest_artifact(&mut journal_sha, 4, &changed_digest());
        assert_rejected(
            &journal_sha,
            "journal digest inconsistent with statement SHA-256",
        );
    }

    #[test]
    fn every_raw_identity_digest_is_bound_to_its_artifact_sha() {
        let fixture = fixture();
        for (label, artifact_index) in [
            ("chain domain ID", 1),
            ("contract ID", 3),
            ("profile ID", 7),
            ("program ID", 8),
        ] {
            let mut value = fixture.value.clone();
            value["artifacts"][artifact_index]["sha256"] = json!(changed_digest_hex());
            assert_rejected(&value, label);
        }
    }

    #[test]
    fn every_claim_scalar_and_raw_digest_artifact_are_cross_bound() {
        let fixture = fixture();
        for (label, pointer, artifact_index) in [
            ("expected claim", "/claim/expectedClaim", 2),
            ("journal digest", "/claim/journalDigest", 4),
            ("output digest", "/claim/output", 5),
            ("post digest", "/claim/post", 6),
        ] {
            let mut scalar = fixture.value.clone();
            *scalar.pointer_mut(pointer).unwrap() = json!(changed_digest_hex());
            assert_rejected(&scalar, &format!("{label} scalar"));

            let mut artifact = fixture.value.clone();
            artifact["artifacts"][artifact_index]["sha256"] = json!(changed_digest_hex());
            assert_rejected(&artifact, &format!("{label} artifact SHA-256"));
        }
    }

    #[test]
    fn coordinated_manifest_identity_drift_is_rejected_by_exact_statement_bytes() {
        let fixture = fixture();
        let changed = changed_digest();
        for (label, pointer, artifact_index) in [
            ("chain domain ID", "/statement/chainDomainId", 1),
            ("contract ID", "/statement/contractId", 3),
            ("profile ID", "/statement/profileId", 7),
            ("program ID", "/statement/programId", 8),
        ] {
            let mut value = fixture.value.clone();
            *value.pointer_mut(pointer).unwrap() = json!(hex::encode(changed));
            bind_raw_digest_artifact(&mut value, artifact_index, &changed);
            let manifest = StatementBundleManifestV1::from_canonical_jcs(&source(&value)).unwrap();
            assert!(
                manifest.authenticate_statement(&fixture.statement).is_err(),
                "accepted coordinated {label} drift"
            );
        }
    }

    #[test]
    fn coordinated_payload_and_statement_identity_drift_is_rejected() {
        let fixture = fixture();

        let mut payload_length = fixture.value.clone();
        let changed_payload_length = fixture.application_payload.len() + 1;
        payload_length["statement"]["applicationPayloadLength"] = json!(changed_payload_length);
        payload_length["artifacts"][0]["length"] = json!(changed_payload_length);
        let changed_statement_length = fixture.statement.len() + 1;
        payload_length["statement"]["statementLength"] = json!(changed_statement_length);
        payload_length["artifacts"][10]["length"] = json!(changed_statement_length);

        let mut payload_sha = fixture.value.clone();
        payload_sha["artifacts"][0]["sha256"] = json!(changed_digest_hex());

        let mut statement_sha = fixture.value.clone();
        statement_sha["statement"]["statementSha256"] = json!(changed_digest_hex());
        statement_sha["artifacts"][10]["sha256"] = json!(changed_digest_hex());
        statement_sha["claim"]["journalDigest"] = json!(changed_digest_hex());
        bind_raw_digest_artifact(&mut statement_sha, 4, &changed_digest());

        for (label, value) in [
            ("payload and statement lengths", payload_length),
            ("payload SHA-256", payload_sha),
            ("statement SHA-256", statement_sha),
        ] {
            let manifest = StatementBundleManifestV1::from_canonical_jcs(&source(&value)).unwrap();
            assert!(
                manifest.authenticate_statement(&fixture.statement).is_err(),
                "accepted coordinated {label} drift"
            );
        }
    }

    #[test]
    fn every_coordinated_claim_digest_drift_is_rejected() {
        let fixture = fixture();
        let changed = changed_digest();
        for (label, pointer, artifact_index) in [
            ("expected claim", "/claim/expectedClaim", 2),
            ("journal digest", "/claim/journalDigest", 4),
            ("output digest", "/claim/output", 5),
            ("post digest", "/claim/post", 6),
        ] {
            let mut value = fixture.value.clone();
            *value.pointer_mut(pointer).unwrap() = json!(hex::encode(changed));
            bind_raw_digest_artifact(&mut value, artifact_index, &changed);
            if label == "journal digest" {
                value["statement"]["statementSha256"] = json!(hex::encode(changed));
                value["artifacts"][10]["sha256"] = json!(hex::encode(changed));
            }
            let manifest = StatementBundleManifestV1::from_canonical_jcs(&source(&value)).unwrap();
            assert!(
                manifest.authenticate_statement(&fixture.statement).is_err(),
                "accepted coordinated {label} drift"
            );
        }
    }

    #[test]
    fn fully_rebound_malformed_statement_is_rejected_by_the_strict_codec() {
        let fixture = fixture();
        let mut malformed = fixture.statement.clone();
        malformed[0] ^= 1;
        let mut value = fixture.value.clone();
        rebind_statement_transport_and_claim(&mut value, &malformed, &fixture.program_id);
        let manifest = StatementBundleManifestV1::from_canonical_jcs(&source(&value)).unwrap();
        let error = manifest.authenticate_statement(&malformed).err().unwrap();
        assert!(format!("{error:#}").contains("ErgoStatementV1"));
    }

    #[test]
    fn proposition_identity_remains_typed_custody_not_a_false_rederivation() {
        let fixture = fixture();
        let mut value = fixture.value.clone();
        let changed_length = fixture.proposition.len() + 1;
        value["statement"]["propositionBytesLength"] = json!(changed_length);
        value["artifacts"][9]["length"] = json!(changed_length);
        value["artifacts"][9]["sha256"] = json!(changed_digest_hex());

        let manifest = StatementBundleManifestV1::from_canonical_jcs(&source(&value)).unwrap();
        assert_eq!(manifest.proposition_length(), changed_length);
        assert_eq!(manifest.proposition_sha256(), changed_digest());
        manifest.authenticate_statement(&fixture.statement).unwrap();
    }
}
