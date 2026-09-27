//! Trusted-host publication from descriptor-reopened predecessor authorities.

use std::{collections::BTreeSet, env, ffi::OsString, path::Path};

use anyhow::{Context as _, Result, ensure};
use eip_0045_reproduction::{
    b4_build_check::{AuthoritativeB4BuildProjection, B4BuildExpectations},
    b4_campaign_contract::{
        B4ContractArtifactEncodingV1, B4ContractArtifactIdentityV1, B4ExternalArtifactV1,
        B4PositiveGenerationAuthorityV2, B4TrustedHostCampaignPrecommitAuthorityV1,
        B4TrustedHostRequestV1, B4TrustedHostTerminalEvidenceCampaignReceiptInputsV1,
        Eip0045B4TrustedHostCampaignPrecommitV1,
        Eip0045B4TrustedHostTerminalEvidenceCampaignReceiptV1,
        MAX_CAMPAIGN_PRECOMMIT_BYTES, MAX_TRUSTED_HOST_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES,
        b4_trusted_host_publish_terminal_evidence_canonical_argv_sha256,
    },
    b4_terminal_evidence_packet::reopen_b4_terminal_evidence_packet_from_directory_descriptor,
    b4_terminal_source_lineage::{B4TerminalSourceExternalBytesV2, B4TerminalSourceLineageAuthorityV2},
    canonical::canonical_json_bytes,
};
use risc0_zkvm::LocalProver;
use sha2::{Digest as _, Sha256};

use super::{
    execute::{NoopPublishTerminalEvidenceTransitionObserver, ProjectedPublishLeaves,
        coordinate_publish_terminal_evidence, coordinate_publish_terminal_evidence_mutation},
    project_publish_terminal_evidence_layout,
};
use crate::{
    b4_campaign_executor::{
        authenticated_preflight::derive_campaign_relative_artifact_path,
        custody::CurrentExecutableObservation,
        finalize_generation_set_handler::replay_published_generation_for_terminal,
        prepare_campaign_precommit::replay_trusted_host_precommit_for_terminal,
        typestate::ExecutorPreflightContext,
    },
    terminal_evidence_export::{
        prepare_lineaged_b4_terminal_evidence_packet_trusted_host,
        publish_prepared_lineaged_b4_terminal_evidence_packet_from_directory_descriptor_trusted_host,
        require_terminal_packet_identity_binding,
    },
};

const COMMAND: &str = "publish-terminal-evidence";
const MAX_RETAINED_ARTIFACT_BYTES: usize = 512 * 1024 * 1024;
const MAX_PRECOMMIT_BYTES: usize = MAX_CAMPAIGN_PRECOMMIT_BYTES + 4096;

#[derive(Debug, Eq, PartialEq)]
struct PhaseIdentity {
    envelope: B4ContractArtifactIdentityV1,
    request: B4ContractArtifactIdentityV1,
    input: B4ContractArtifactIdentityV1,
    generation: B4ContractArtifactIdentityV1,
    guest: B4ContractArtifactIdentityV1,
    campaign_paths: BTreeSet<String>,
}

struct AuthenticatedPhase {
    identity: PhaseIdentity,
    campaign: B4TrustedHostCampaignPrecommitAuthorityV1,
    positive: B4PositiveGenerationAuthorityV2,
    lineage: B4TerminalSourceLineageAuthorityV2,
}

fn require_rebound_phase_identity(expected: &PhaseIdentity, observed: &PhaseIdentity) -> Result<()> {
    ensure!(observed == expected,
        "terminal authority identities changed between preflight and execute");
    Ok(())
}

fn require_request_pin(bytes: &[u8], length: u64, digest: &str) -> Result<()> {
    ensure!((1..=65536).contains(&length) && bytes.len() as u64 == length
        && hex::encode(Sha256::digest(bytes)) == digest,
        "trusted-host terminal request differs from its external pin");
    Ok(())
}

fn require_prior_selection(
    current: &B4TrustedHostRequestV1,
    previous: &B4TrustedHostRequestV1,
    precommit_root: &str,
) -> Result<()> {
    ensure!(previous.command == "prepare-campaign-precommit"
        && previous.campaign_root == current.campaign_root
        && previous.configured_executor_artifact == current.configured_executor_artifact
        && previous.outer_final_root == precommit_root,
        "terminal prior request belongs to another command, executor or campaign root");
    let old_build = previous.prior_roots.get(previous.build_evidence_root_index)
        .context("terminal prior request build root index is invalid")?;
    let current_build = current.prior_roots.get(current.build_evidence_root_index)
        .context("terminal current request build root index is invalid")?;
    ensure!(old_build == current_build,
        "terminal prior and current requests selected different build roots");
    Ok(())
}

fn global_path<const ROOTS: usize>(
    request: &B4TrustedHostRequestV1, role: &str,
    campaign_root: &Path, roots: [&Path; ROOTS],
) -> Result<String> {
    let selected = request.locator(role)?;
    let root = roots.get(selected.root_index).context("terminal role root index is invalid")?;
    derive_campaign_relative_artifact_path(campaign_root, root, &selected.relative_path)
}

/// Both phases call this with their own retained descriptor reader and build.
/// The size callback is applied by custody before allocating any file buffer.
#[allow(clippy::too_many_arguments)]
fn authenticate_phase<const ROOTS: usize, F>(
    request: &B4TrustedHostRequestV1,
    campaign_root: &Path,
    roots: [&Path; ROOTS],
    build: &AuthoritativeB4BuildProjection,
    observed: &CurrentExecutableObservation,
    mut read: F,
) -> Result<AuthenticatedPhase>
where F: FnMut(usize, &str, usize, u64) -> Result<Vec<u8>>,
{
    let precommit_loc = request.locator("campaignPrecommit")?;
    ensure!(precommit_loc.relative_path == "trusted-host/campaign-precommit.json",
        "terminal precommit locator is not the published trusted-host envelope");
    let prior_loc = request.locator("precommitRequest")?;
    let precommit = read(precommit_loc.root_index, &precommit_loc.relative_path,
        MAX_PRECOMMIT_BYTES, MAX_PRECOMMIT_BYTES as u64)?;
    let prior_bytes = read(prior_loc.root_index, &prior_loc.relative_path, 65536, 65536)?;
    let envelope = Eip0045B4TrustedHostCampaignPrecommitV1::from_canonical_jcs(&precommit)?;
    require_request_pin(&prior_bytes, envelope.request_byte_length, &envelope.request_sha256)?;
    let previous = B4TrustedHostRequestV1::from_canonical_jcs(&prior_bytes)?;
    let precommit_root = request.prior_roots.get(precommit_loc.root_index)
        .context("terminal precommit root index is invalid")?;
    require_prior_selection(request, &previous, precommit_root)?;
    ensure!(envelope.build_evidence_root_sha256 == build.evidence_root_sha256(),
        "terminal precommit differs from the authenticated build root");
    let prior_path = global_path(request, "precommitRequest", campaign_root, roots)?;
    let campaign = replay_trusted_host_precommit_for_terminal(
        &previous,
        B4ExternalArtifactV1 { path: &prior_path, bytes: &prior_bytes,
            encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs },
        campaign_root, roots, build, envelope.request_byte_length, &envelope.request_sha256,
        |index, path, limit, remaining| read(index, path, limit.max_bytes(), remaining),
    )?;
    campaign.verify_candidate_jcs(&precommit)?;
    let precommit_path = global_path(request, "campaignPrecommit", campaign_root, roots)?;
    let measured = B4ContractArtifactIdentityV1::from_bytes(&precommit_path,
        B4ContractArtifactEncodingV1::Rfc8785Jcs, &precommit)?;
    ensure!(&measured == campaign.envelope_identity(),
        "terminal retained precommit path or bytes differ from replayed authority");
    observed.require_artifact_identity(&campaign.inner_precommit().campaign_executor.artifact)?;
    let generation = replay_published_generation_for_terminal(
        request, campaign_root, roots, build, &campaign,
        |index, path| read(index, path, MAX_RETAINED_ARTIFACT_BYTES,
            MAX_RETAINED_ARTIFACT_BYTES as u64),
    )?;
    let guest_loc = request.locator("guestElf")?;
    let guest = read(guest_loc.root_index, &guest_loc.relative_path,
        MAX_RETAINED_ARTIFACT_BYTES, MAX_RETAINED_ARTIFACT_BYTES as u64)?;
    let guest_path = global_path(request, "guestElf", campaign_root, roots)?;
    let lineage = generation.with_terminal_source_closure(
        B4TerminalSourceExternalBytesV2 { path: &guest_path, bytes: &guest },
        |positive, sources| B4TerminalSourceLineageAuthorityV2::from_external_closure_trusted_host(
            &campaign, positive, sources),
    )?;
    lineage.verify_authority_bindings_trusted_host(&campaign, generation.authority())?;
    let identity = PhaseIdentity {
        envelope: measured,
        request: campaign.request_identity().clone(),
        input: generation.authority().positive_input_set_identity().clone(),
        generation: generation.authority().positive_generation_set_identity().clone(),
        guest: B4ContractArtifactIdentityV1::from_bytes(&guest_path,
            B4ContractArtifactEncodingV1::RawBytes, &guest)?,
        campaign_paths: campaign.artifact_paths().clone(),
    };
    Ok(AuthenticatedPhase { identity, campaign, positive: generation.into_authority(), lineage })
}

/// The CLI retains and rechecks the current request descriptor around this call.
/// This entry also binds its parsed value and process argv to the same pin.
pub(in crate::b4_campaign_executor) fn handle<const ROOTS: usize>(
    request: &B4TrustedHostRequestV1,
    request_byte_length: u64,
    request_sha256: &str,
    expectations: &B4BuildExpectations<'_>,
    preflight_only: bool,
) -> Result<()> {
    let request_jcs = canonical_json_bytes(&serde_json::to_value(request)?)?;
    require_request_pin(&request_jcs, request_byte_length, request_sha256)?;
    ensure!(B4TrustedHostRequestV1::from_canonical_jcs(&request_jcs)? == *request
        && request.command == COMMAND && request.prior_roots.len() == ROOTS
        && (1..=16).contains(&ROOTS), "terminal trusted-host request shape drift");
    let process_argv = env::args_os().collect::<Vec<OsString>>();
    let expected_root = expectations.expected_evidence_root
        .context("terminal trusted-host build root anchor is absent")?;
    let expected_commit = expectations.expected_source_commit
        .context("terminal trusted-host source commit anchor is absent")?;
    let expected_tree = expectations.expected_source_tree
        .context("terminal trusted-host source tree anchor is absent")?;
    ensure!(env::var_os("RISC0_DEV_MODE").is_none(),
        "RISC0_DEV_MODE must be absent before trusted-host terminal proof work");
    b4_trusted_host_publish_terminal_evidence_canonical_argv_sha256(
        &process_argv, request_byte_length, request_sha256,
        expected_root, preflight_only)?;
    ensure!(process_argv.get(12).and_then(|value| value.to_str()) == Some(expected_commit)
        && process_argv.get(14).and_then(|value| value.to_str()) == Some(expected_tree),
        "terminal argv source anchors differ from the independent build expectations");
    let campaign_root = Path::new(&request.campaign_root);
    let roots: [&Path; ROOTS] = std::array::from_fn(|i| Path::new(&request.prior_roots[i]));
    let layout = project_publish_terminal_evidence_layout(
        campaign_root, roots, Path::new(&request.outer_final_root))?;
    let preflight = ExecutorPreflightContext::capture(
        Path::new(&request.configured_executor_artifact), layout)?;
    let build = preflight.authenticate_authoritative_b4_build_projection(
        request.build_evidence_root_index, expectations)?;
    let phase = authenticate_phase(request, campaign_root, roots, &build, preflight.executable(),
        |index, path, limit, remaining| {
            preflight.read_immutable_file_with_length_validation::<MAX_RETAINED_ARTIFACT_BYTES>(
                index, path, |length| {
                    ensure!(length <= limit as u64 && length <= remaining,
                        "terminal retained source exceeds its role or aggregate bound");
                    Ok(())
                })
        })?;
    let expected_identity = phase.identity;
    drop((phase.campaign, phase.positive, phase.lineage));
    if preflight_only { return preflight.finish_preflight(); }
    preflight.execute(|execute| {
        let rebound_build = execute.authenticate_authoritative_b4_build_projection(
            request.build_evidence_root_index, expectations)?;
        ensure!(rebound_build == build, "terminal build changed between preflight and execute");
        let AuthenticatedPhase { identity, campaign, positive, lineage } = authenticate_phase(
            request, campaign_root, roots, &rebound_build, execute.executable(),
            |index, path, limit, remaining| {
                execute.read_immutable_file_with_length_validation::<MAX_RETAINED_ARTIFACT_BYTES>(
                    index, path, |length| {
                        ensure!(length <= limit as u64 && length <= remaining,
                            "terminal retained source exceeds its role or aggregate bound");
                        Ok(())
                    })
            })?;
        require_rebound_phase_identity(&expected_identity, &identity)?;
        let mut observer = NoopPublishTerminalEvidenceTransitionObserver;
        coordinate_publish_terminal_evidence(execute, &mut observer,
            |execute| execute.with_proof(|_capability| {
                ensure!(env::var_os("RISC0_DEV_MODE").is_none(),
                    "RISC0_DEV_MODE appeared before trusted-host proof work");
                let prover = LocalProver::new("eip-0045-b4-campaign-publish-terminal-evidence");
                prepare_lineaged_b4_terminal_evidence_packet_trusted_host(
                    &prover, &campaign, positive, lineage)
            }),
            |execute, prepared, observer| execute.with_mutation(|capability| {
                let leaves = ProjectedPublishLeaves::from_layout(capability.projected_layout())?;
                let publish_leaves = leaves.clone();
                let receipt_leaves = leaves.clone();
                coordinate_publish_terminal_evidence_mutation(observer, prepared,
                    || capability.begin_create_only_directory(),
                    |transaction, prepared| transaction.publish_and_adopt_directory_tree(
                        &publish_leaves.packet_relative,
                        |root| publish_prepared_lineaged_b4_terminal_evidence_packet_from_directory_descriptor_trusted_host(
                            root, &publish_leaves.packet_relative, &campaign, prepared)),
                    |transaction, published| {
                        let packet = published.identity();
                        let packet_id = hex::encode(packet.packet_id());
                        let observed_dev_mode = env::var_os("RISC0_DEV_MODE");
                        let receipt = Eip0045B4TrustedHostTerminalEvidenceCampaignReceiptV1::new(
                            B4TrustedHostTerminalEvidenceCampaignReceiptInputsV1 {
                                campaign: &campaign, campaign_precommit_identity: &identity.envelope,
                                positive: published.positive_authority(),
                                build_evidence_root_sha256: rebound_build.evidence_root_sha256(),
                                process_argv: &process_argv, request_byte_length, request_sha256,
                                parsed_preflight_only: false,
                                risc0_dev_mode: observed_dev_mode.as_deref(),
                                terminal_packet_manifest_byte_length: usize::try_from(packet.manifest_byte_length())?,
                                terminal_packet_id: &packet_id,
                            })?;
                        transaction.create_file(&receipt_leaves.receipt_relative,
                            &receipt.to_canonical_jcs()?,
                            MAX_TRUSTED_HOST_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES)?;
                        Ok((receipt, packet))
                    },
                    |transaction, published, (receipt, packet)| {
                        transaction.commit_with_postcommit_validation(|committed| {
                            leaves.revalidate_published_projection()?;
                            committed.require_projected_reserved_staging_absent(
                                &leaves.packet_relative,
                                &leaves.reserved_inner_relative,
                            )?;
                            let reopened = reopen_b4_terminal_evidence_packet_from_directory_descriptor(
                                committed.directory_descriptor(&leaves.packet_relative)?)?;
                            let authority = published.rebind_postcommit_semantically_reopened_packet_trusted_host(
                                &campaign, reopened)?;
                            let reopened_receipt = Eip0045B4TrustedHostTerminalEvidenceCampaignReceiptV1::from_canonical_jcs(
                                &committed.read_file(&leaves.receipt_relative,
                                    MAX_TRUSTED_HOST_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES)?)?;
                            ensure!(reopened_receipt == receipt,
                                "trusted-host postcommit receipt differs from retained candidate");
                            require_terminal_packet_identity_binding(
                                reopened_receipt.terminal_packet_manifest_byte_length(),
                                reopened_receipt.terminal_packet_id(), packet.manifest_byte_length(),
                                &hex::encode(packet.packet_id()))?;
                            Ok((authority, reopened_receipt))
                        })
                    })
            }))?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn selected(command: &str) -> B4TrustedHostRequestV1 {
        B4TrustedHostRequestV1 {
            format: "Eip0045B4TrustedHostRequestV1".to_owned(), format_version: 1,
            realization: "trusted-host-v1".to_owned(), command: command.to_owned(),
            campaign_root: "/campaign".to_owned(), prior_roots: vec!["/campaign/build".to_owned()],
            outer_final_root: "/campaign/precommit".to_owned(),
            configured_executor_artifact: "/campaign/executor".to_owned(),
            build_evidence_root_index: 0, input_set_path: None, guest_elf_path: None,
            proof_generator_path: None, input_set_request_byte_length: None,
            input_set_request_sha256: None, sources: BTreeMap::new(),
        }
    }

    #[test]
    fn retained_request_pin_rejects_independent_length_and_digest_substitutions() {
        let bytes = b"{\"selected\":true}";
        let digest = hex::encode(Sha256::digest(bytes));
        require_request_pin(bytes, bytes.len() as u64, &digest).unwrap();
        assert!(require_request_pin(bytes, bytes.len() as u64 + 1, &digest).is_err());
        assert!(require_request_pin(bytes, bytes.len() as u64, &"a".repeat(64)).is_err());
        assert!(require_request_pin(&[], 0, &hex::encode(Sha256::digest([]))).is_err());
    }

    #[test]
    fn prior_request_selection_rejects_each_independent_route_substitution() {
        let current = selected(COMMAND);
        let previous = selected("prepare-campaign-precommit");
        require_prior_selection(&current, &previous, "/campaign/precommit").unwrap();
        for fault in 0..6 {
            let mut changed = previous.clone();
            match fault {
                0 => changed.command = COMMAND.to_owned(),
                1 => changed.campaign_root = "/other".to_owned(),
                2 => changed.configured_executor_artifact = "/campaign/other-executor".to_owned(),
                3 => changed.outer_final_root = "/campaign/other-precommit".to_owned(),
                4 => changed.prior_roots[0] = "/campaign/other-build".to_owned(),
                5 => changed.build_evidence_root_index = 1,
                _ => unreachable!(),
            }
            assert!(require_prior_selection(&current, &changed, "/campaign/precommit").is_err(),
                "accepted prior request substitution {fault}");
        }
    }

    #[test]
    fn execute_rejects_each_isolated_preflight_authority_identity_change() {
        let artifact = |path: &str| B4ContractArtifactIdentityV1::from_bytes(
            path, B4ContractArtifactEncodingV1::RawBytes, path.as_bytes()).unwrap();
        let expected = PhaseIdentity {
            envelope: artifact("phase/envelope"),
            request: artifact("phase/request"),
            input: artifact("phase/input"),
            generation: artifact("phase/generation"),
            guest: artifact("phase/guest"),
            campaign_paths: BTreeSet::from(["phase/source".to_owned()]),
        };
        require_rebound_phase_identity(&expected, &expected).unwrap();
        for fault in 0..6 {
            let mut observed = PhaseIdentity {
                envelope: expected.envelope.clone(),
                request: expected.request.clone(),
                input: expected.input.clone(),
                generation: expected.generation.clone(),
                guest: expected.guest.clone(),
                campaign_paths: expected.campaign_paths.clone(),
            };
            match fault {
                0 => observed.envelope = artifact("phase/other-envelope"),
                1 => observed.request = artifact("phase/other-request"),
                2 => observed.input = artifact("phase/other-input"),
                3 => observed.generation = artifact("phase/other-generation"),
                4 => observed.guest = artifact("phase/other-guest"),
                5 => { observed.campaign_paths.insert("phase/other-source".to_owned()); }
                _ => unreachable!(),
            }
            assert!(require_rebound_phase_identity(&expected, &observed).is_err(),
                "accepted changed authority identity {fault}");
        }
    }
}

#[cfg(test)]
#[path = "trusted_host_fault_tests.rs"]
mod fault_tests;
