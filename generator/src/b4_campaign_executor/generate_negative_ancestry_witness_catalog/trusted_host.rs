//! Trusted-host negative-ancestry publication from separately replayed authorities.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsString,
    fs::File,
    io::Read as _,
    os::fd::BorrowedFd,
    os::unix::fs::MetadataExt as _,
    path::Path,
};

use anyhow::{ensure, Context as _, Result};
use eip_0045_reproduction::{
    b4_build_check::{AuthoritativeB4BuildProjection, B4BuildExpectations},
    b4_campaign_contract::{
        B4ContractArtifactEncodingV1, B4ContractArtifactIdentityV1, B4ExternalArtifactV1,
        B4PositiveGenerationAuthorityV2, B4TrustedHostCampaignPrecommitAuthorityV1,
        B4TrustedHostRequestV1, B4VerifierContractAuthorityV1,
        Eip0045B4TrustedHostCampaignPrecommitV1, MAX_CAMPAIGN_PRECOMMIT_BYTES,
    },
    b4_negative_ancestry_authority::{
        B4NegativeAncestryExternalBytesV2, B4NegativeAncestryProfilePackageExternalV2,
        B4NegativeAncestrySourceAuthorityV2,
    },
    b4_negative_ancestry_publication::{
        materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor_v2,
        validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor_v2,
    },
    canonical::canonical_json_bytes,
};
use risc0_zkvm::LocalProver;
use sha2::{Digest as _, Sha256};

use super::{
    project_generate_negative_ancestry_witness_catalog_layout,
    ProjectedSingleSubtreeCampaignLayout, REPRODUCTION_SUBTREE,
};
use crate::{
    b4_campaign_executor::{
        authenticated_preflight::derive_campaign_relative_artifact_path,
        custody::CurrentExecutableObservation,
        finalize_generation_set_handler::replay_published_generation_for_terminal,
        prepare_campaign_precommit::replay_trusted_host_authorities_for_negative_ancestry,
        typestate::{ExecutorExecuteContext, ExecutorPreflightContext},
    },
    locked_negative_ancestry_guest::require_locked_negative_ancestry_source_v2,
    recursive::prove_and_finalize_b4_negative_ancestry_witness_catalog_v2,
};

const COMMAND: &str = "generate-negative-ancestry-witness-catalog";
const MAX_RETAINED_ARTIFACT_BYTES: usize = 512 * 1024 * 1024;
const MAX_PRECOMMIT_BYTES: usize = MAX_CAMPAIGN_PRECOMMIT_BYTES + 4096;

#[derive(Debug, Eq, PartialEq)]
struct PhaseIdentity {
    envelope: B4ContractArtifactIdentityV1,
    request: B4ContractArtifactIdentityV1,
    input: B4ContractArtifactIdentityV1,
    generation: B4ContractArtifactIdentityV1,
    verifier: B4ContractArtifactIdentityV1,
    additional_sources: BTreeMap<&'static str, B4ContractArtifactIdentityV1>,
    campaign_paths: BTreeSet<String>,
}

struct AuthenticatedPhase {
    identity: PhaseIdentity,
    campaign: B4TrustedHostCampaignPrecommitAuthorityV1,
    verifier: B4VerifierContractAuthorityV1,
    positive: B4PositiveGenerationAuthorityV2,
    source: B4NegativeAncestrySourceAuthorityV2,
}

struct RetainedRole {
    path: String,
    bytes: Vec<u8>,
}

impl RetainedRole {
    fn external(&self) -> B4NegativeAncestryExternalBytesV2<'_> {
        B4NegativeAncestryExternalBytesV2 {
            path: &self.path,
            bytes: &self.bytes,
        }
    }

    fn identity(&self) -> Result<B4ContractArtifactIdentityV1> {
        B4ContractArtifactIdentityV1::from_bytes(
            &self.path,
            B4ContractArtifactEncodingV1::RawBytes,
            &self.bytes,
        )
    }
}

fn global_path<const ROOTS: usize>(
    request: &B4TrustedHostRequestV1,
    role: &str,
    campaign_root: &Path,
    roots: [&Path; ROOTS],
) -> Result<String> {
    let selected = request.locator(role)?;
    let root = roots
        .get(selected.root_index)
        .context("ancestry role root index is invalid")?;
    derive_campaign_relative_artifact_path(campaign_root, root, &selected.relative_path)
}

fn retain_role<const ROOTS: usize, F>(
    request: &B4TrustedHostRequestV1,
    role: &str,
    campaign_root: &Path,
    roots: [&Path; ROOTS],
    read: &mut F,
) -> Result<RetainedRole>
where
    F: FnMut(usize, &str, usize, u64) -> Result<Vec<u8>>,
{
    let selected = request.locator(role)?;
    Ok(RetainedRole {
        path: global_path(request, role, campaign_root, roots)?,
        bytes: read(
            selected.root_index,
            &selected.relative_path,
            MAX_RETAINED_ARTIFACT_BYTES,
            MAX_RETAINED_ARTIFACT_BYTES as u64,
        )?,
    })
}

fn require_request_pin(bytes: &[u8], length: u64, digest: &str) -> Result<()> {
    ensure!(
        (1..=65536).contains(&length)
            && bytes.len() as u64 == length
            && hex::encode(Sha256::digest(bytes)) == digest,
        "trusted-host ancestry request differs from its external pin"
    );
    Ok(())
}

fn require_prior_selection(
    current: &B4TrustedHostRequestV1,
    previous: &B4TrustedHostRequestV1,
    precommit_root: &str,
) -> Result<()> {
    ensure!(
        previous.command == "prepare-campaign-precommit"
            && previous.campaign_root == current.campaign_root
            && previous.configured_executor_artifact == current.configured_executor_artifact
            && previous.outer_final_root == precommit_root,
        "ancestry prior request belongs to another command, executor or campaign root"
    );
    let old_build = previous
        .prior_roots
        .get(previous.build_evidence_root_index)
        .context("ancestry prior request build root index is invalid")?;
    let current_build = current
        .prior_roots
        .get(current.build_evidence_root_index)
        .context("ancestry current request build root index is invalid")?;
    ensure!(
        old_build == current_build,
        "ancestry prior and current requests selected different build roots"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn authenticate_phase<const ROOTS: usize, F>(
    request: &B4TrustedHostRequestV1,
    campaign_root: &Path,
    roots: [&Path; ROOTS],
    build: &AuthoritativeB4BuildProjection,
    observed: &CurrentExecutableObservation,
    mut read: F,
) -> Result<AuthenticatedPhase>
where
    F: FnMut(usize, &str, usize, u64) -> Result<Vec<u8>>,
{
    let precommit_loc = request.locator("campaignPrecommit")?;
    ensure!(
        precommit_loc.relative_path == "trusted-host/campaign-precommit.json",
        "ancestry precommit locator is not the published trusted-host envelope"
    );
    let prior_loc = request.locator("precommitRequest")?;
    let precommit = read(
        precommit_loc.root_index,
        &precommit_loc.relative_path,
        MAX_PRECOMMIT_BYTES,
        MAX_PRECOMMIT_BYTES as u64,
    )?;
    let prior_bytes = read(prior_loc.root_index, &prior_loc.relative_path, 65536, 65536)?;
    let envelope = Eip0045B4TrustedHostCampaignPrecommitV1::from_canonical_jcs(&precommit)?;
    require_request_pin(
        &prior_bytes,
        envelope.request_byte_length,
        &envelope.request_sha256,
    )?;
    let previous = B4TrustedHostRequestV1::from_canonical_jcs(&prior_bytes)?;
    let precommit_root = request
        .prior_roots
        .get(precommit_loc.root_index)
        .context("ancestry precommit root index is invalid")?;
    require_prior_selection(request, &previous, precommit_root)?;
    ensure!(
        envelope.build_evidence_root_sha256 == build.evidence_root_sha256(),
        "ancestry precommit differs from the authenticated build root"
    );
    let prior_path = global_path(request, "precommitRequest", campaign_root, roots)?;
    let (campaign, verifier) = replay_trusted_host_authorities_for_negative_ancestry(
        &previous,
        B4ExternalArtifactV1 {
            path: &prior_path,
            bytes: &prior_bytes,
            encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
        },
        campaign_root,
        roots,
        build,
        envelope.request_byte_length,
        &envelope.request_sha256,
        |index, path, limit, remaining| read(index, path, limit.max_bytes(), remaining),
    )?;
    campaign.verify_candidate_jcs(&precommit)?;
    let precommit_path = global_path(request, "campaignPrecommit", campaign_root, roots)?;
    let measured = B4ContractArtifactIdentityV1::from_bytes(
        &precommit_path,
        B4ContractArtifactEncodingV1::Rfc8785Jcs,
        &precommit,
    )?;
    ensure!(
        &measured == campaign.envelope_identity(),
        "ancestry retained precommit path or bytes differ from replayed authority"
    );
    observed.require_artifact_identity(&campaign.inner_precommit().campaign_executor.artifact)?;
    let generation = replay_published_generation_for_terminal(
        request,
        campaign_root,
        roots,
        build,
        &campaign,
        |index, path| {
            read(
                index,
                path,
                MAX_RETAINED_ARTIFACT_BYTES,
                MAX_RETAINED_ARTIFACT_BYTES as u64,
            )
        },
    )?;
    let profile_manifest =
        retain_role(request, "profileManifest", campaign_root, roots, &mut read)?;
    let profile_algorithm =
        retain_role(request, "profileAlgorithm", campaign_root, roots, &mut read)?;
    let profile_constants =
        retain_role(request, "profileConstants", campaign_root, roots, &mut read)?;
    let guest_elf = retain_role(request, "guestElf", campaign_root, roots, &mut read)?;
    let alternate_guest_elf = retain_role(
        request,
        "alternateGuestElf",
        campaign_root,
        roots,
        &mut read,
    )?;
    let source = generation.with_negative_ancestry_source_closure(
        &precommit,
        B4NegativeAncestryProfilePackageExternalV2 {
            profile_manifest: profile_manifest.external(),
            profile_algorithm: profile_algorithm.external(),
            profile_constants: profile_constants.external(),
            consumer_guest_elf: guest_elf.external(),
        },
        alternate_guest_elf.external(),
        |positive, sources| {
            B4NegativeAncestrySourceAuthorityV2::from_source_closure_trusted_host(
                &campaign, positive, &verifier, sources,
            )
        },
    )?;
    source.verify_authority_bindings_trusted_host(&campaign, generation.authority(), &verifier)?;
    require_locked_negative_ancestry_source_v2(&source)?;
    let additional_sources = [
        ("profileManifest", profile_manifest.identity()?),
        ("profileAlgorithm", profile_algorithm.identity()?),
        ("profileConstants", profile_constants.identity()?),
        ("guestElf", guest_elf.identity()?),
        ("alternateGuestElf", alternate_guest_elf.identity()?),
    ]
    .into_iter()
    .collect();
    let identity = PhaseIdentity {
        envelope: measured,
        request: campaign.request_identity().clone(),
        input: generation.authority().positive_input_set_identity().clone(),
        generation: generation
            .authority()
            .positive_generation_set_identity()
            .clone(),
        verifier: campaign.inner_precommit().verifier_contract.clone(),
        additional_sources,
        campaign_paths: campaign.artifact_paths().clone(),
    };
    Ok(AuthenticatedPhase {
        identity,
        campaign,
        verifier,
        positive: generation.into_authority(),
        source,
    })
}

fn require_rebound_phase_identity(
    expected: &PhaseIdentity,
    observed: &PhaseIdentity,
) -> Result<()> {
    ensure!(
        observed == expected,
        "ancestry authority identities changed between preflight and execute"
    );
    Ok(())
}

/// Keep the cross-phase join before both the proof and physical transaction.
/// Production and the fault harness call this same one-way boundary.
fn execute_rebound_catalog_pipeline<const ROOTS: usize, Prepared, Output>(
    execute: &mut ExecutorExecuteContext<ROOTS, ProjectedSingleSubtreeCampaignLayout<ROOTS>>,
    expected: &PhaseIdentity,
    observed: &PhaseIdentity,
    prove_and_finalize: impl FnOnce() -> Result<Prepared>,
    materialize: impl for<'descriptor> FnOnce(BorrowedFd<'descriptor>, &Prepared) -> Result<()>,
    validate_and_rebind_postcommit: impl for<'descriptor> FnOnce(
        BorrowedFd<'descriptor>,
        Prepared,
    ) -> Result<Output>,
) -> Result<Output> {
    require_rebound_phase_identity(expected, observed)?;
    let prepared = execute.with_proof(|_capability| prove_and_finalize())?;
    execute.with_mutation(|capability| {
        let mut transaction = capability.begin_create_only_directory()?;
        transaction.publish_and_adopt_directory_tree(REPRODUCTION_SUBTREE, |root| {
            materialize(root, &prepared)
        })?;
        transaction.commit_with_postcommit_validation(|committed| {
            validate_and_rebind_postcommit(committed.root_directory_descriptor()?, prepared)
        })
    })
}

fn lower_hex(value: &str, digits: usize) -> bool {
    value.len() == digits
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_invocation(
    raw: &[OsString],
    request_bytes: u64,
    request_sha256: &str,
    expected_commit: &str,
    expected_tree: &str,
    expected_root: &str,
    preflight_only: bool,
) -> Result<String> {
    let argv = raw
        .iter()
        .map(|part| part.to_str().context("ancestry argv is not UTF-8"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        argv.len() == 17 + usize::from(preflight_only)
            && argv[1] == "b4-campaign"
            && argv[2] == COMMAND
            && argv[3] == "--realization"
            && argv[4] == "trusted-host-v1"
            && argv[5] == "--request"
            && argv[7] == "--request-bytes"
            && argv[9] == "--request-sha256"
            && argv[11] == "--expected-source-commit"
            && argv[13] == "--expected-source-tree"
            && argv[15] == "--expected-build-evidence-root",
        "ancestry argv differs from its canonical command and flag order"
    );
    let request_path = argv[6];
    ensure!(
        request_path.starts_with('/')
            && !request_path.contains('\\')
            && request_path
                .split('/')
                .skip(1)
                .all(|part| !part.is_empty() && part != "." && part != ".."),
        "ancestry request path is not normalized and absolute"
    );
    ensure!(
        argv[8] == request_bytes.to_string()
            && argv[10] == request_sha256
            && argv[12] == expected_commit
            && argv[14] == expected_tree
            && argv[16] == expected_root
            && lower_hex(request_sha256, 64)
            && lower_hex(expected_commit, 40)
            && lower_hex(expected_tree, 40)
            && lower_hex(expected_root, 64),
        "ancestry argv differs from the independent request or build pins"
    );
    if preflight_only {
        ensure!(
            argv[17] == "--preflight-only",
            "ancestry argv lacks preflight token"
        );
    }
    Ok(request_path.to_owned())
}

struct PinnedCurrentRequest {
    held: File,
    path: String,
    bytes: Vec<u8>,
    device: u64,
    inode: u64,
}

impl PinnedCurrentRequest {
    fn open(path: &str, length: u64, sha256: &str) -> Result<Self> {
        let descriptor = rustix::fs::openat2(
            rustix::fs::CWD,
            Path::new(path),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )
        .context("cannot pin ancestry request without symlinks")?;
        let mut held = File::from(descriptor);
        let metadata = held
            .metadata()
            .context("cannot stat pinned ancestry request")?;
        ensure!(
            metadata.is_file() && metadata.nlink() == 1 && metadata.len() == length,
            "ancestry request is not one regular file of pinned length"
        );
        let mut bytes = Vec::new();
        held.by_ref()
            .take(65537)
            .read_to_end(&mut bytes)
            .context("cannot read pinned ancestry request")?;
        require_request_pin(&bytes, length, sha256)?;
        Ok(Self {
            held,
            path: path.to_owned(),
            bytes,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn recheck(&self, length: u64, sha256: &str) -> Result<()> {
        let metadata = self
            .held
            .metadata()
            .context("cannot restat held ancestry request")?;
        ensure!(
            metadata.is_file()
                && metadata.nlink() == 1
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
                && metadata.len() == length,
            "held ancestry request identity changed"
        );
        let observed = Self::open(&self.path, length, sha256)?;
        ensure!(
            observed.device == self.device
                && observed.inode == self.inode
                && observed.bytes == self.bytes,
            "ancestry request path was replaced during the command"
        );
        Ok(())
    }
}

/// Derive a fresh TH source authority in each phase and publish only after
/// descriptor-rooted postcommit validation. The CLI performs one final request
/// recheck after this handler returns.
#[allow(clippy::too_many_lines)]
pub(in crate::b4_campaign_executor) fn handle<const ROOTS: usize>(
    request: &B4TrustedHostRequestV1,
    request_byte_length: u64,
    request_sha256: &str,
    expectations: &B4BuildExpectations<'_>,
    preflight_only: bool,
) -> Result<()> {
    let request_jcs = canonical_json_bytes(&serde_json::to_value(request)?)?;
    require_request_pin(&request_jcs, request_byte_length, request_sha256)?;
    ensure!(
        B4TrustedHostRequestV1::from_canonical_jcs(&request_jcs)? == *request
            && request.command == COMMAND
            && request.prior_roots.len() == ROOTS
            && (1..=16).contains(&ROOTS),
        "ancestry trusted-host request shape drift"
    );
    let expected_root = expectations
        .expected_evidence_root
        .context("ancestry trusted-host build root anchor is absent")?;
    let expected_commit = expectations
        .expected_source_commit
        .context("ancestry trusted-host source commit anchor is absent")?;
    let expected_tree = expectations
        .expected_source_tree
        .context("ancestry trusted-host source tree anchor is absent")?;
    let argv = env::args_os().collect::<Vec<_>>();
    let request_path = validate_invocation(
        &argv,
        request_byte_length,
        request_sha256,
        expected_commit,
        expected_tree,
        expected_root,
        preflight_only,
    )?;
    ensure!(
        env::var_os("RISC0_DEV_MODE").is_none(),
        "RISC0_DEV_MODE must be absent before trusted-host ancestry proof work"
    );
    let current_request =
        PinnedCurrentRequest::open(&request_path, request_byte_length, request_sha256)?;
    ensure!(
        current_request.bytes == request_jcs,
        "ancestry parsed request differs from its pinned physical source"
    );
    let campaign_root = Path::new(&request.campaign_root);
    let roots: [&Path; ROOTS] = std::array::from_fn(|i| Path::new(&request.prior_roots[i]));
    let layout = project_generate_negative_ancestry_witness_catalog_layout(
        campaign_root,
        roots,
        Path::new(&request.outer_final_root),
    )?;
    let preflight = ExecutorPreflightContext::capture(
        Path::new(&request.configured_executor_artifact),
        layout,
    )?;
    let build = preflight.authenticate_authoritative_b4_build_projection(
        request.build_evidence_root_index,
        expectations,
    )?;
    let phase = authenticate_phase(
        request,
        campaign_root,
        roots,
        &build,
        preflight.executable(),
        |index, path, limit, remaining| {
            preflight.read_immutable_file_with_length_validation::<MAX_RETAINED_ARTIFACT_BYTES>(
                index,
                path,
                |length| {
                    ensure!(
                        length <= limit as u64 && length <= remaining,
                        "ancestry retained source exceeds its role or aggregate bound"
                    );
                    Ok(())
                },
            )
        },
    )?;
    let expected_identity = phase.identity;
    drop((phase.campaign, phase.verifier, phase.positive, phase.source));
    current_request.recheck(request_byte_length, request_sha256)?;
    if preflight_only {
        return preflight.finish_preflight();
    }
    preflight.execute(|execute| {
        current_request.recheck(request_byte_length, request_sha256)?;
        ensure!(env::var_os("RISC0_DEV_MODE").is_none(),
            "RISC0_DEV_MODE appeared before ancestry execute replay");
        let rebound_build = execute.authenticate_authoritative_b4_build_projection(
            request.build_evidence_root_index, expectations)?;
        ensure!(rebound_build == build, "ancestry build changed between preflight and execute");
        let AuthenticatedPhase { identity, campaign, verifier, positive, source } =
            authenticate_phase(request, campaign_root, roots, &rebound_build,
                execute.executable(), |index, path, limit, remaining| {
                    execute.read_immutable_file_with_length_validation::<MAX_RETAINED_ARTIFACT_BYTES>(
                        index, path, |length| {
                            ensure!(length <= limit as u64 && length <= remaining,
                                "ancestry retained source exceeds its role or aggregate bound");
                            Ok(())
                        })
                })?;
        current_request.recheck(request_byte_length, request_sha256)?;
        execute_rebound_catalog_pipeline(
            execute, &expected_identity, &identity,
            || {
                ensure!(env::var_os("RISC0_DEV_MODE").is_none(),
                    "RISC0_DEV_MODE appeared before trusted-host ancestry proof work");
                source.verify_authority_bindings_trusted_host(&campaign, &positive, &verifier)?;
                require_locked_negative_ancestry_source_v2(&source)?;
                let prover = LocalProver::new("eip-0045-b4-campaign-generate-negative-ancestry-catalog");
                prove_and_finalize_b4_negative_ancestry_witness_catalog_v2(&prover, &source)
            },
            |root, authority| {
                materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor_v2(
                    root, authority)
            },
            |root, authority| {
                validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor_v2(
                    root, &authority)
                    .context("cannot semantically reopen committed TH ancestry catalogue")?;
                authority.verify_prior_authority_lineage_trusted_host(
                    &campaign, &positive, &verifier)?;
                source.verify_authority_bindings_trusted_host(&campaign, &positive, &verifier)?;
                require_locked_negative_ancestry_source_v2(&source)?;
                current_request.recheck(request_byte_length, request_sha256)?;
                ensure!(env::var_os("RISC0_DEV_MODE").is_none(),
                    "RISC0_DEV_MODE appeared before ancestry postcommit authority release");
                Ok(authority)
            },
        )?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use eip_0045_reproduction::b4_campaign_contract::B4TrustedHostArtifactLocatorV1;
    use std::{
        cell::Cell,
        fs,
        io::{Read as _, Write as _},
        os::fd::AsFd as _,
        rc::Rc,
    };

    const TEST_CATALOG_FILE: &str = "catalog.jcs";
    const TEST_CATALOG_BYTES: &[u8] = br#"{"fixture":"trusted-host-negative-ancestry"}"#;

    fn physical_test_identity() -> PhaseIdentity {
        let identity = |path: &str, bytes: &[u8]| {
            B4ContractArtifactIdentityV1::from_bytes(
                path,
                B4ContractArtifactEncodingV1::RawBytes,
                bytes,
            )
            .unwrap()
        };
        PhaseIdentity {
            envelope: identity("precommit", b"a"),
            request: identity("request", b"b"),
            input: identity("input", b"c"),
            generation: identity("generation", b"d"),
            verifier: identity("verifier", b"e"),
            additional_sources: BTreeMap::from([("profileManifest", identity("profile", b"f"))]),
            campaign_paths: BTreeSet::from(["precommit".to_owned()]),
        }
    }

    fn materialize_test_catalog(root: BorrowedFd<'_>, bytes: &[u8]) -> Result<()> {
        let resolve = rustix::fs::ResolveFlags::BENEATH
            | rustix::fs::ResolveFlags::NO_SYMLINKS
            | rustix::fs::ResolveFlags::NO_MAGICLINKS
            | rustix::fs::ResolveFlags::NO_XDEV;
        rustix::fs::mkdirat(root, REPRODUCTION_SUBTREE, rustix::fs::Mode::RWXU)
            .context("cannot create TH test reproduction subtree")?;
        let subtree = rustix::fs::openat2(
            root,
            REPRODUCTION_SUBTREE,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            resolve,
        )?;
        let descriptor = rustix::fs::openat2(
            subtree.as_fd(),
            TEST_CATALOG_FILE,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            resolve,
        )?;
        let mut file = File::from(descriptor);
        file.write_all(bytes)?;
        file.sync_all()?;
        rustix::fs::fsync(subtree.as_fd())?;
        rustix::fs::fsync(root)?;
        Ok(())
    }

    fn reopen_test_catalog(root: BorrowedFd<'_>) -> Result<Vec<u8>> {
        let resolve = rustix::fs::ResolveFlags::BENEATH
            | rustix::fs::ResolveFlags::NO_SYMLINKS
            | rustix::fs::ResolveFlags::NO_MAGICLINKS
            | rustix::fs::ResolveFlags::NO_XDEV;
        let subtree = rustix::fs::openat2(
            root,
            REPRODUCTION_SUBTREE,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            resolve,
        )?;
        let descriptor = rustix::fs::openat2(
            subtree.as_fd(),
            TEST_CATALOG_FILE,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            resolve,
        )?;
        let mut bytes = Vec::new();
        File::from(descriptor).take(1025).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 1024,
            "TH test catalogue exceeds reopen bound"
        );
        Ok(bytes)
    }

    #[test]
    fn real_th_pipeline_blocks_interphase_substitution_and_retains_postcommit_hold() {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum Fault {
            None,
            InterphaseIdentity,
            PostcommitReopen,
        }
        for fault in [
            Fault::None,
            Fault::InterphaseIdentity,
            Fault::PostcommitReopen,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let campaign = temp.path().join("campaign");
            let prior = campaign.join("prior");
            let outer_parent = campaign.join("runs");
            let outer = outer_parent.join("negative-ancestry");
            fs::create_dir_all(&prior).unwrap();
            fs::create_dir_all(&outer_parent).unwrap();
            let projected = project_generate_negative_ancestry_witness_catalog_layout(
                &campaign,
                [&prior],
                &outer,
            )
            .unwrap();
            let staging = projected.outer_staging_root().to_path_buf();
            let preflight =
                ExecutorPreflightContext::capture(&env::current_exe().unwrap(), projected).unwrap();
            let expected = physical_test_identity();
            let mut observed = physical_test_identity();
            if fault == Fault::InterphaseIdentity {
                observed.request = B4ContractArtifactIdentityV1::from_bytes(
                    "request",
                    B4ContractArtifactEncodingV1::RawBytes,
                    b"substituted",
                )
                .unwrap();
            }
            let proof_calls = Rc::new(Cell::new(0));
            let materialize_calls = Rc::new(Cell::new(0));
            let reopen_calls = Rc::new(Cell::new(0));
            let proof_count = Rc::clone(&proof_calls);
            let materialize_count = Rc::clone(&materialize_calls);
            let reopen_count = Rc::clone(&reopen_calls);
            let result = preflight.execute(|execute| {
                execute_rebound_catalog_pipeline(
                    execute,
                    &expected,
                    &observed,
                    move || {
                        proof_count.set(proof_count.get() + 1);
                        Ok(TEST_CATALOG_BYTES.to_vec())
                    },
                    move |root, authority| {
                        materialize_count.set(materialize_count.get() + 1);
                        let bytes = if fault == Fault::PostcommitReopen {
                            b"substituted catalogue".as_slice()
                        } else {
                            authority.as_slice()
                        };
                        materialize_test_catalog(root, bytes)
                    },
                    move |root, authority| {
                        reopen_count.set(reopen_count.get() + 1);
                        let reopened = reopen_test_catalog(root)?;
                        ensure!(
                            reopened == authority,
                            "TH postcommit semantic reopen differs from proof authority"
                        );
                        Ok(authority)
                    },
                )
            });
            assert_eq!(
                proof_calls.get(),
                usize::from(fault != Fault::InterphaseIdentity)
            );
            assert_eq!(
                materialize_calls.get(),
                usize::from(fault != Fault::InterphaseIdentity)
            );
            assert_eq!(
                reopen_calls.get(),
                usize::from(fault != Fault::InterphaseIdentity)
            );
            assert_eq!(
                result.is_ok(),
                fault == Fault::None,
                "TH pipeline returned wrong authority state for {fault:?}: {result:?}"
            );
            if fault == Fault::InterphaseIdentity {
                assert!(
                    !outer.exists() && !staging.exists(),
                    "interphase substitution reached filesystem mutation"
                );
            } else {
                assert!(
                    outer.exists() && !staging.exists(),
                    "TH commit did not retain the expected final/recovery state"
                );
                let retained =
                    fs::read(outer.join(REPRODUCTION_SUBTREE).join(TEST_CATALOG_FILE)).unwrap();
                assert_eq!(
                    retained.as_slice(),
                    if fault == Fault::None {
                        TEST_CATALOG_BYTES
                    } else {
                        b"substituted catalogue".as_slice()
                    }
                );
            }
            if fault == Fault::PostcommitReopen {
                assert!(format!("{:#}", result.unwrap_err())
                    .contains("TH postcommit semantic reopen differs from proof authority"));
            }
        }
    }

    fn prior_request() -> B4TrustedHostRequestV1 {
        B4TrustedHostRequestV1 {
            format: "Eip0045B4TrustedHostRequestV1".to_owned(),
            format_version: 1,
            realization: "trusted-host-v1".to_owned(),
            command: "prepare-campaign-precommit".to_owned(),
            campaign_root: "/campaign".to_owned(),
            prior_roots: vec!["/campaign/build".to_owned()],
            outer_final_root: "/campaign/precommit".to_owned(),
            configured_executor_artifact: "/campaign/executor".to_owned(),
            build_evidence_root_index: 0,
            input_set_path: None,
            guest_elf_path: None,
            proof_generator_path: None,
            input_set_request_byte_length: Some(1),
            input_set_request_sha256: Some("a".repeat(64)),
            sources: BTreeMap::from([(
                "inputSet".to_owned(),
                B4TrustedHostArtifactLocatorV1 {
                    root_index: 0,
                    relative_path: "positive-input-set.json".to_owned(),
                },
            )]),
        }
    }

    #[test]
    fn ancestry_prior_selection_rejects_isolated_command_root_executor_and_build_faults() {
        let previous = prior_request();
        let mut current = prior_request();
        current.command = COMMAND.to_owned();
        current.prior_roots.push("/campaign/precommit".to_owned());
        assert!(require_prior_selection(&current, &previous, "/campaign/precommit").is_ok());
        let mut changed = previous.clone();
        changed.command = "publish-terminal-evidence".to_owned();
        assert!(require_prior_selection(&current, &changed, "/campaign/precommit").is_err());
        changed = previous.clone();
        changed.campaign_root = "/other".to_owned();
        assert!(require_prior_selection(&current, &changed, "/campaign/precommit").is_err());
        changed = previous.clone();
        changed.configured_executor_artifact = "/other/executor".to_owned();
        assert!(require_prior_selection(&current, &changed, "/campaign/precommit").is_err());
        changed = previous.clone();
        changed.outer_final_root = "/other/precommit".to_owned();
        assert!(require_prior_selection(&current, &changed, "/campaign/precommit").is_err());
        changed = previous.clone();
        changed.prior_roots[0] = "/other/build".to_owned();
        assert!(require_prior_selection(&current, &changed, "/campaign/precommit").is_err());
    }

    #[test]
    fn ancestry_current_request_pin_rejects_byte_and_inode_substitution() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("request.json");
        std::fs::write(&path, b"original").unwrap();
        let digest = hex::encode(Sha256::digest(b"original"));
        let pinned = PinnedCurrentRequest::open(path.to_str().unwrap(), 8, &digest).unwrap();
        assert!(pinned.recheck(8, &digest).is_ok());
        std::fs::write(&path, b"replaced").unwrap();
        assert!(pinned.recheck(8, &digest).is_err());
        std::fs::write(&path, b"original").unwrap();
        std::fs::rename(&path, temp.path().join("former.json")).unwrap();
        std::fs::write(&path, b"original").unwrap();
        assert!(pinned.recheck(8, &digest).is_err());
    }

    #[test]
    fn phase_identity_rejects_isolated_envelope_request_and_source_substitutions() {
        fn identity(path: &str, bytes: &[u8]) -> B4ContractArtifactIdentityV1 {
            B4ContractArtifactIdentityV1::from_bytes(
                path,
                B4ContractArtifactEncodingV1::RawBytes,
                bytes,
            )
            .unwrap()
        }
        let initial = PhaseIdentity {
            envelope: identity("precommit", b"a"),
            request: identity("request", b"b"),
            input: identity("input", b"c"),
            generation: identity("generation", b"d"),
            verifier: identity("verifier", b"e"),
            additional_sources: BTreeMap::from([("profileManifest", identity("profile", b"f"))]),
            campaign_paths: BTreeSet::from(["precommit".to_owned()]),
        };
        assert!(require_rebound_phase_identity(&initial, &initial).is_ok());
        let mutations: [fn(&mut PhaseIdentity); 7] = [
            |value| value.envelope = identity("precommit", b"other"),
            |value| value.request = identity("request", b"other"),
            |value| value.input = identity("input", b"other"),
            |value| value.generation = identity("generation", b"other"),
            |value| value.verifier = identity("verifier", b"other"),
            |value| {
                value
                    .additional_sources
                    .insert("profileManifest", identity("profile", b"other"));
            },
            |value| {
                value.campaign_paths.insert("other".to_owned());
            },
        ];
        for mutate in mutations {
            let mut observed = PhaseIdentity {
                envelope: initial.envelope.clone(),
                request: initial.request.clone(),
                input: initial.input.clone(),
                generation: initial.generation.clone(),
                verifier: initial.verifier.clone(),
                additional_sources: initial.additional_sources.clone(),
                campaign_paths: initial.campaign_paths.clone(),
            };
            mutate(&mut observed);
            assert!(require_rebound_phase_identity(&initial, &observed).is_err());
        }
    }

    #[test]
    fn ancestry_invocation_rejects_single_faults_and_historical_command() {
        let request_sha = "a".repeat(64);
        let commit = "b".repeat(40);
        let tree = "c".repeat(40);
        let root = "d".repeat(64);
        let raw = [
            "executor",
            "b4-campaign",
            COMMAND,
            "--realization",
            "trusted-host-v1",
            "--request",
            "/request.json",
            "--request-bytes",
            "71",
            "--request-sha256",
            &request_sha,
            "--expected-source-commit",
            &commit,
            "--expected-source-tree",
            &tree,
            "--expected-build-evidence-root",
            &root,
        ]
        .map(OsString::from)
        .to_vec();
        assert!(validate_invocation(&raw, 71, &request_sha, &commit, &tree, &root, false).is_ok());
        for (index, replacement) in [
            (2, "publish-terminal-evidence"),
            (4, "historical-v1"),
            (6, "../request.json"),
            (8, "071"),
            (10, "bad"),
            (12, "bad"),
            (14, "bad"),
            (16, "bad"),
        ] {
            let mut changed = raw.clone();
            changed[index] = OsString::from(replacement);
            assert!(
                validate_invocation(&changed, 71, &request_sha, &commit, &tree, &root, false)
                    .is_err(),
                "accepted mutation at argv[{index}]"
            );
        }
        let mut trailing = raw;
        trailing.push(OsString::from("--preflight-only"));
        assert!(
            validate_invocation(&trailing, 71, &request_sha, &commit, &tree, &root, false).is_err()
        );
        assert!(
            validate_invocation(&trailing, 71, &request_sha, &commit, &tree, &root, true).is_ok()
        );
    }
}
