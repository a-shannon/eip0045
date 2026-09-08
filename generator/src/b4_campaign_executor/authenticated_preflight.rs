//! Shared authenticated preflight bindings for private B4 campaign handlers.

use std::path::{Component, Path};

use anyhow::{Context as _, Result, ensure};
use eip_0045_reproduction::b4_campaign_contract::{
    B4CampaignPrecommitAuthorityV1, B4CampaignPrecommitAuthorityV2, B4ContractArtifactEncodingV1,
    B4ContractArtifactIdentityV1, Eip0045B4CampaignPrecommitV1,
};

use super::custody::CurrentExecutableObservation;

pub(super) fn derive_campaign_relative_artifact_path(
    campaign_root: &Path,
    prior_root: &Path,
    root_relative_path: &str,
) -> Result<String> {
    let root_relative = prior_root
        .strip_prefix(campaign_root)
        .context("campaign-precommit root is outside the retained campaign root")?;
    let root_components = portable_relative_components(root_relative, true)?;
    let file_components = portable_relative_components(Path::new(root_relative_path), true)?;
    let mut components = root_components;
    components.extend(file_components);
    Ok(components.join("/"))
}

fn portable_relative_components(path: &Path, require_nonempty: bool) -> Result<Vec<String>> {
    ensure!(!path.is_absolute(), "artifact locator must be relative");
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => components.push(
                value
                    .to_str()
                    .context("artifact locator component is not UTF-8")?
                    .to_owned(),
            ),
            Component::CurDir | Component::ParentDir | Component::RootDir => {
                anyhow::bail!("artifact locator is not a normalized relative path");
            }
            Component::Prefix(_) => {
                anyhow::bail!("artifact locator has an unsupported prefix");
            }
        }
    }
    ensure!(
        !require_nonempty || !components.is_empty(),
        "artifact locator is empty"
    );
    let canonical = components.join("/");
    ensure!(
        path.as_os_str().is_empty() || path.to_str() == Some(canonical.as_str()),
        "artifact locator is not in portable canonical form"
    );
    Ok(components)
}

pub(super) fn authenticate_campaign_precommit_file(
    campaign_relative_path: &str,
    campaign: &B4CampaignPrecommitAuthorityV1,
    retained_bytes: &[u8],
) -> Result<B4ContractArtifactIdentityV1> {
    let expected_bytes = campaign.to_canonical_precommit_jcs()?;
    ensure!(
        retained_bytes == expected_bytes,
        "retained campaign precommit bytes differ from their authority"
    );
    let parsed = Eip0045B4CampaignPrecommitV1::from_canonical_jcs(retained_bytes)
        .context("retained campaign precommit is not exact canonical JCS")?;
    parsed
        .verify_against(campaign)
        .context("retained campaign precommit differs from its authority")?;
    B4ContractArtifactIdentityV1::from_bytes(
        campaign_relative_path,
        B4ContractArtifactEncodingV1::Rfc8785Jcs,
        retained_bytes,
    )
    .context("cannot derive the pathful campaign precommit identity from retained bytes")
}

pub(super) fn require_current_executable_binding(
    observed: &CurrentExecutableObservation,
    campaign: &B4CampaignPrecommitAuthorityV1,
) -> Result<()> {
    observed
        .require_artifact_identity(&campaign.precommit().campaign_executor.artifact)
        .context("running executor bytes differ from the campaign-precommitted artifact")
}

pub(super) fn authenticate_campaign_precommit_file_v2(
    campaign_relative_path: &str,
    campaign: &B4CampaignPrecommitAuthorityV2,
    retained_bytes: &[u8],
) -> Result<B4ContractArtifactIdentityV1> {
    campaign
        .verify_candidate_jcs(retained_bytes)
        .context("retained campaign precommit differs from its V2-derived authority")?;
    B4ContractArtifactIdentityV1::from_bytes(
        campaign_relative_path,
        B4ContractArtifactEncodingV1::Rfc8785Jcs,
        retained_bytes,
    )
    .context("cannot derive the pathful V2-derived campaign precommit identity")
}

pub(super) fn require_current_executable_binding_v2(
    observed: &CurrentExecutableObservation,
    campaign: &B4CampaignPrecommitAuthorityV2,
) -> Result<()> {
    observed
        .require_artifact_identity(&campaign.precommit().campaign_executor.artifact)
        .context("running executor bytes differ from the V2-derived campaign-precommitted artifact")
}
