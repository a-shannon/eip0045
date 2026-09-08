//! Pure projected-layout validation for a future campaign transaction.

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use eip_0045_reproduction::b4_positive_gate::{
    B4PositiveOciImageLayoutV1, PositiveGateBindings, PositiveRunnerRole,
};
use eip_0045_reproduction::b4_positive_input_set::{
    B4PositiveInputSetLayoutV1, B4PositiveInputSetLayoutV2, B4PositiveInputSetPublicationPathsV1,
    B4PositiveInputSetPublicationPathsV2, project_b4_positive_input_set_publication_paths_v1,
    project_b4_positive_input_set_publication_paths_v2,
};
use eip_0045_reproduction::b4_terminal_evidence_packet::project_b4_terminal_evidence_publication_layout;

use super::{
    create_only::project_create_only_directory_layout,
    oci_image_layout_import::{
        AuthenticatedOciOuterUstarInventoryV1, project_authenticated_oci_outer_ustar_inventory,
    },
    typestate::OciTopologyCustodyBridgePermitV1,
};

const MAX_CAMPAIGN_RELATIVE_PATH_BYTES: usize = 240;
const MAX_PROJECTED_PRIOR_ROOTS: usize = 16;
const MAX_PROJECTED_ADDITIONAL_LEAVES: usize = 16;
pub(super) const MAX_PROJECTED_OCI_IMAGE_LAYOUT_CAPTURE_SLOTS: usize = 4;
const INNER_PACKET_COMPONENT: &str = "terminal-evidence-packet";

#[derive(Debug)]
struct ProjectedCampaignRootClosure<const ROOTS: usize> {
    campaign_root: PathBuf,
    prior_roots: [PathBuf; ROOTS],
    outer_create_only: super::create_only::CreateOnlyDirectoryLayout,
    outer_final_root: PathBuf,
    outer_staging_root: PathBuf,
}

/// Filesystem-free projection of the two-level campaign publication layout.
#[derive(Debug)]
pub(super) struct ProjectedOuterCampaignLayout<const ROOTS: usize> {
    campaign_root: PathBuf,
    prior_roots: [PathBuf; ROOTS],
    outer_create_only: super::create_only::CreateOnlyDirectoryLayout,
    outer_final_root: PathBuf,
    outer_staging_root: PathBuf,
    staged_inner_final_path: PathBuf,
    staged_inner_staging_path: PathBuf,
    projected_inner_final_path: PathBuf,
    projected_inner_staging_path: PathBuf,
    required_outer_top_level_entries: Vec<String>,
    required_outer_top_level_directories: Vec<String>,
    staged_additional_top_level_leaves: Vec<PathBuf>,
    projected_additional_top_level_leaves: Vec<PathBuf>,
}

/// Filesystem-free projection of one direct create-only directory subtree.
#[derive(Debug)]
pub(super) struct ProjectedSingleSubtreeCampaignLayout<const ROOTS: usize> {
    campaign_root: PathBuf,
    prior_roots: [PathBuf; ROOTS],
    outer_create_only: super::create_only::CreateOnlyDirectoryLayout,
    outer_final_root: PathBuf,
    outer_staging_root: PathBuf,
    staged_subtree_path: PathBuf,
    projected_subtree_path: PathBuf,
    required_outer_top_level_entries: Vec<String>,
    required_outer_top_level_directories: Vec<String>,
}

/// Filesystem-free projection of one direct create-only file.
#[derive(Debug)]
pub(super) struct ProjectedSingleFileCampaignLayout<const ROOTS: usize> {
    campaign_root: PathBuf,
    prior_roots: [PathBuf; ROOTS],
    outer_create_only: super::create_only::CreateOnlyDirectoryLayout,
    outer_final_root: PathBuf,
    outer_staging_root: PathBuf,
    staged_file_path: PathBuf,
    projected_file_path: PathBuf,
    required_outer_top_level_entries: Vec<String>,
    required_outer_top_level_directories: Vec<String>,
}

/// Filesystem-free projection of the closed two-file H0 publication root.
#[derive(Debug)]
pub(super) struct ProjectedPrepareInputSetCampaignLayout<const ROOTS: usize> {
    campaign_root: PathBuf,
    prior_roots: [PathBuf; ROOTS],
    outer_create_only: super::create_only::CreateOnlyDirectoryLayout,
    outer_final_root: PathBuf,
    outer_staging_root: PathBuf,
    staged_input_set_path: PathBuf,
    staged_completion_path: PathBuf,
    projected_input_set_path: PathBuf,
    projected_completion_path: PathBuf,
    publication_paths: B4PositiveInputSetPublicationPathsV1,
    required_outer_top_level_entries: Vec<String>,
    required_outer_top_level_directories: Vec<String>,
}

/// Filesystem-free projection of the closed two-file H0 V2 publication root.
#[derive(Debug)]
pub(super) struct ProjectedPrepareInputSetCampaignLayoutV2<const ROOTS: usize> {
    campaign_root: PathBuf,
    prior_roots: [PathBuf; ROOTS],
    outer_create_only: super::create_only::CreateOnlyDirectoryLayout,
    outer_final_root: PathBuf,
    outer_staging_root: PathBuf,
    staged_input_set_path: PathBuf,
    staged_completion_path: PathBuf,
    projected_input_set_path: PathBuf,
    projected_completion_path: PathBuf,
    publication_paths: B4PositiveInputSetPublicationPathsV2,
    required_outer_top_level_entries: Vec<String>,
    required_outer_top_level_directories: Vec<String>,
}

/// One descriptor-relative OCI image-layout location projected before custody.
///
/// Fields remain private so no sibling can independently label an ambient path
/// as the large OCI role. [`AuthenticatedPrepareInputSetOciTopologyV1`] owns
/// the production constructor after deriving all four physical slots.
#[derive(Debug)]
pub(super) struct ProjectedOciImageLayoutCaptureSlotV1 {
    root_index: usize,
    relative_path: String,
}

impl ProjectedOciImageLayoutCaptureSlotV1 {
    pub(super) const fn root_index(&self) -> usize {
        self.root_index
    }

    pub(super) fn relative_path(&self) -> &str {
        &self.relative_path
    }
}

/// Affine pre-custody projection of one H0 layout and its closed OCI slots.
///
/// No production constructor exists yet. This wrapper can only be obtained by
/// the explicit test projection below until H0 derives the exact slot set.
#[derive(Debug)]
#[must_use = "the projected H0 layout and OCI capture slots must enter custody together"]
pub(super) struct ProjectedPrepareInputSetOciCaptureV1<const ROOTS: usize> {
    layout: ProjectedPrepareInputSetCampaignLayout<ROOTS>,
    slots: Vec<ProjectedOciImageLayoutCaptureSlotV1>,
}

impl<const ROOTS: usize> ProjectedPrepareInputSetOciCaptureV1<ROOTS> {
    pub(super) fn into_parts(
        self,
    ) -> (
        ProjectedPrepareInputSetCampaignLayout<ROOTS>,
        Vec<ProjectedOciImageLayoutCaptureSlotV1>,
    ) {
        (self.layout, self.slots)
    }
}

/// Affine proof that one canonical runner profile was mapped to one retained
/// descriptor root without accepting a detached locator from the caller.
///
/// Only [`project_authenticated_prepare_input_set_oci_topology`] can mint this
/// permit. The OCI bridge consumes it together with the exact typed projection
/// which supplied the role and campaign-global archive path.
#[must_use = "the authenticated OCI locator permit must be consumed by the fixed slot bridge"]
pub(super) struct AuthenticatedOciSlotConstructionPermitV1 {
    root_index: usize,
    root_relative_path: String,
    profile: B4PositiveOciImageLayoutV1,
}

impl AuthenticatedOciSlotConstructionPermitV1 {
    pub(super) fn into_parts(self) -> (usize, String, B4PositiveOciImageLayoutV1) {
        (self.root_index, self.root_relative_path, self.profile)
    }

    pub(super) const fn profile(&self) -> &B4PositiveOciImageLayoutV1 {
        &self.profile
    }

    fn capture_slot(&self) -> ProjectedOciImageLayoutCaptureSlotV1 {
        ProjectedOciImageLayoutCaptureSlotV1 {
            root_index: self.root_index,
            relative_path: self.root_relative_path.clone(),
        }
    }
}

/// Closed H0 projection which carries physical capture and semantic import
/// authority as one affine value.
#[must_use = "the authenticated H0 OCI topology must enter custody as one value"]
pub(super) struct AuthenticatedPrepareInputSetOciTopologyV1<const ROOTS: usize> {
    layout: ProjectedPrepareInputSetCampaignLayout<ROOTS>,
    capture_slots:
        [ProjectedOciImageLayoutCaptureSlotV1; MAX_PROJECTED_OCI_IMAGE_LAYOUT_CAPTURE_SLOTS],
    import_inventory: AuthenticatedOciOuterUstarInventoryV1,
}

impl<const ROOTS: usize> AuthenticatedPrepareInputSetOciTopologyV1<ROOTS> {
    pub(super) fn into_custody_parts(
        self,
        _bridge: OciTopologyCustodyBridgePermitV1,
    ) -> (
        ProjectedPrepareInputSetCampaignLayout<ROOTS>,
        [ProjectedOciImageLayoutCaptureSlotV1; MAX_PROJECTED_OCI_IMAGE_LAYOUT_CAPTURE_SLOTS],
        AuthenticatedOciOuterUstarInventoryV1,
    ) {
        (self.layout, self.capture_slots, self.import_inventory)
    }
}

/// Common custody and outer create-only projection consumed by the affine
/// executor kernel.
///
/// Implementations remain closed inside this module. Handler-specific
/// projections may expose additional typed paths, while the kernel receives
/// only the campaign roots and exact outer transaction contract shared by
/// every handler.
pub(super) trait ProjectedCampaignLayout<const ROOTS: usize> {
    /// Retained lexical campaign root used by the pure projection.
    fn campaign_root(&self) -> &Path;

    /// Exact prior roots which the executor must custody.
    fn prior_roots(&self) -> [&Path; ROOTS];

    /// Exact create-only layout bound to the projected outer transaction.
    fn outer_create_only_layout(&self) -> &super::create_only::CreateOnlyDirectoryLayout;

    /// Exact top-level names which must exist at outer commit.
    fn required_outer_top_level_entries(&self) -> &[String];

    /// Exact top-level entries which must be directories at outer commit.
    fn required_outer_top_level_directories(&self) -> &[String];
}

/// Sealed admission gate for the generic, unordered create-only transaction.
///
/// Layouts whose chronology is security-sensitive must not implement this
/// trait. They expose a dedicated typestate transaction instead, so sibling
/// modules cannot bypass their required effect order through the generic
/// `create_file` surface.
mod generic_create_only_sealed {
    pub trait Sealed {}
}

pub(super) trait GenericCreateOnlyCampaignLayout<const ROOTS: usize>:
    ProjectedCampaignLayout<ROOTS> + generic_create_only_sealed::Sealed
{
}

impl<const ROOTS: usize> ProjectedOuterCampaignLayout<ROOTS> {
    /// Retained lexical campaign root used by the pure projection.
    #[must_use]
    pub(super) fn campaign_root(&self) -> &Path {
        &self.campaign_root
    }

    /// Exact prior roots which the executor must custody.
    #[must_use]
    pub(super) fn prior_roots(&self) -> [&Path; ROOTS] {
        self.prior_roots.each_ref().map(PathBuf::as_path)
    }

    /// Exact create-only layout bound to the projected outer transaction.
    #[must_use]
    pub(super) const fn outer_create_only_layout(
        &self,
    ) -> &super::create_only::CreateOnlyDirectoryLayout {
        &self.outer_create_only
    }

    /// Intended create-only outer publication root.
    #[must_use]
    pub(super) fn outer_final_root(&self) -> &Path {
        &self.outer_final_root
    }

    /// Reserved create-only outer staging root.
    #[must_use]
    pub(super) fn outer_staging_root(&self) -> &Path {
        &self.outer_staging_root
    }

    /// Inner packet destination while the outer transaction is staged.
    #[must_use]
    pub(super) fn staged_inner_final_path(&self) -> &Path {
        &self.staged_inner_final_path
    }

    /// Reserved inner staging sibling while the outer transaction is staged.
    #[must_use]
    pub(super) fn staged_inner_staging_path(&self) -> &Path {
        &self.staged_inner_staging_path
    }

    /// Inner packet destination after the outer transaction is published.
    #[must_use]
    pub(super) fn projected_inner_final_path(&self) -> &Path {
        &self.projected_inner_final_path
    }

    /// Projected location of the reserved inner staging sibling.
    #[must_use]
    pub(super) fn projected_inner_staging_path(&self) -> &Path {
        &self.projected_inner_staging_path
    }

    /// Exact top-level names which must exist at outer commit.
    #[must_use]
    pub(super) fn required_outer_top_level_entries(&self) -> &[String] {
        &self.required_outer_top_level_entries
    }

    /// Exact top-level entries which must be directories at outer commit.
    #[must_use]
    pub(super) fn required_outer_top_level_directories(&self) -> &[String] {
        &self.required_outer_top_level_directories
    }

    /// Other direct transaction leaves beneath the outer staging root.
    #[must_use]
    pub(super) fn staged_additional_top_level_leaves(&self) -> &[PathBuf] {
        &self.staged_additional_top_level_leaves
    }

    /// Other direct transaction leaves projected beneath the outer final root.
    #[must_use]
    pub(super) fn projected_additional_top_level_leaves(&self) -> &[PathBuf] {
        &self.projected_additional_top_level_leaves
    }
}

impl<const ROOTS: usize> ProjectedCampaignLayout<ROOTS> for ProjectedOuterCampaignLayout<ROOTS> {
    fn campaign_root(&self) -> &Path {
        self.campaign_root()
    }

    fn prior_roots(&self) -> [&Path; ROOTS] {
        self.prior_roots()
    }

    fn outer_create_only_layout(&self) -> &super::create_only::CreateOnlyDirectoryLayout {
        self.outer_create_only_layout()
    }

    fn required_outer_top_level_entries(&self) -> &[String] {
        self.required_outer_top_level_entries()
    }

    fn required_outer_top_level_directories(&self) -> &[String] {
        self.required_outer_top_level_directories()
    }
}

impl<const ROOTS: usize> generic_create_only_sealed::Sealed
    for ProjectedOuterCampaignLayout<ROOTS>
{
}

impl<const ROOTS: usize> GenericCreateOnlyCampaignLayout<ROOTS>
    for ProjectedOuterCampaignLayout<ROOTS>
{
}

impl<const ROOTS: usize> ProjectedSingleSubtreeCampaignLayout<ROOTS> {
    /// Retained lexical campaign root used by the pure projection.
    #[must_use]
    pub(super) fn campaign_root(&self) -> &Path {
        &self.campaign_root
    }

    /// Exact prior roots which the executor must custody.
    #[must_use]
    pub(super) fn prior_roots(&self) -> [&Path; ROOTS] {
        self.prior_roots.each_ref().map(PathBuf::as_path)
    }

    /// Exact create-only layout bound to the projected outer transaction.
    #[must_use]
    pub(super) const fn outer_create_only_layout(
        &self,
    ) -> &super::create_only::CreateOnlyDirectoryLayout {
        &self.outer_create_only
    }

    /// Intended create-only outer publication root.
    #[must_use]
    pub(super) fn outer_final_root(&self) -> &Path {
        &self.outer_final_root
    }

    /// Reserved create-only outer staging root.
    #[must_use]
    pub(super) fn outer_staging_root(&self) -> &Path {
        &self.outer_staging_root
    }

    /// Single required subtree while the outer transaction is staged.
    #[must_use]
    pub(super) fn staged_subtree_path(&self) -> &Path {
        &self.staged_subtree_path
    }

    /// Single required subtree after the outer transaction is committed.
    #[must_use]
    pub(super) fn projected_subtree_path(&self) -> &Path {
        &self.projected_subtree_path
    }

    /// Exact top-level name which must exist at outer commit.
    #[must_use]
    pub(super) fn required_outer_top_level_entries(&self) -> &[String] {
        &self.required_outer_top_level_entries
    }

    /// Exact top-level entry which must be a directory at outer commit.
    #[must_use]
    pub(super) fn required_outer_top_level_directories(&self) -> &[String] {
        &self.required_outer_top_level_directories
    }
}

impl<const ROOTS: usize> ProjectedCampaignLayout<ROOTS>
    for ProjectedSingleSubtreeCampaignLayout<ROOTS>
{
    fn campaign_root(&self) -> &Path {
        self.campaign_root()
    }

    fn prior_roots(&self) -> [&Path; ROOTS] {
        self.prior_roots()
    }

    fn outer_create_only_layout(&self) -> &super::create_only::CreateOnlyDirectoryLayout {
        self.outer_create_only_layout()
    }

    fn required_outer_top_level_entries(&self) -> &[String] {
        self.required_outer_top_level_entries()
    }

    fn required_outer_top_level_directories(&self) -> &[String] {
        self.required_outer_top_level_directories()
    }
}
impl<const ROOTS: usize> generic_create_only_sealed::Sealed
    for ProjectedSingleSubtreeCampaignLayout<ROOTS>
{
}

impl<const ROOTS: usize> GenericCreateOnlyCampaignLayout<ROOTS>
    for ProjectedSingleSubtreeCampaignLayout<ROOTS>
{
}

impl<const ROOTS: usize> ProjectedSingleFileCampaignLayout<ROOTS> {
    /// Retained lexical campaign root used by the pure projection.
    #[must_use]
    pub(super) fn campaign_root(&self) -> &Path {
        &self.campaign_root
    }

    /// Exact prior roots which the executor must custody.
    #[must_use]
    pub(super) fn prior_roots(&self) -> [&Path; ROOTS] {
        self.prior_roots.each_ref().map(PathBuf::as_path)
    }

    /// Exact create-only layout bound to the projected outer transaction.
    #[must_use]
    pub(super) const fn outer_create_only_layout(
        &self,
    ) -> &super::create_only::CreateOnlyDirectoryLayout {
        &self.outer_create_only
    }

    /// Intended create-only outer publication root.
    #[must_use]
    pub(super) fn outer_final_root(&self) -> &Path {
        &self.outer_final_root
    }

    /// Reserved create-only outer staging root.
    #[must_use]
    pub(super) fn outer_staging_root(&self) -> &Path {
        &self.outer_staging_root
    }

    /// Single required file while the outer transaction is staged.
    #[must_use]
    pub(super) fn staged_file_path(&self) -> &Path {
        &self.staged_file_path
    }

    /// Single required file after the outer transaction is committed.
    #[must_use]
    pub(super) fn projected_file_path(&self) -> &Path {
        &self.projected_file_path
    }

    /// Exact top-level name which must exist at outer commit.
    #[must_use]
    pub(super) fn required_outer_top_level_entries(&self) -> &[String] {
        &self.required_outer_top_level_entries
    }

    /// This layout permits no top-level directories.
    #[must_use]
    pub(super) fn required_outer_top_level_directories(&self) -> &[String] {
        &self.required_outer_top_level_directories
    }
}

impl<const ROOTS: usize> ProjectedCampaignLayout<ROOTS>
    for ProjectedSingleFileCampaignLayout<ROOTS>
{
    fn campaign_root(&self) -> &Path {
        self.campaign_root()
    }

    fn prior_roots(&self) -> [&Path; ROOTS] {
        self.prior_roots()
    }

    fn outer_create_only_layout(&self) -> &super::create_only::CreateOnlyDirectoryLayout {
        self.outer_create_only_layout()
    }

    fn required_outer_top_level_entries(&self) -> &[String] {
        self.required_outer_top_level_entries()
    }

    fn required_outer_top_level_directories(&self) -> &[String] {
        self.required_outer_top_level_directories()
    }
}

impl<const ROOTS: usize> generic_create_only_sealed::Sealed
    for ProjectedSingleFileCampaignLayout<ROOTS>
{
}

impl<const ROOTS: usize> GenericCreateOnlyCampaignLayout<ROOTS>
    for ProjectedSingleFileCampaignLayout<ROOTS>
{
}

impl<const ROOTS: usize> ProjectedPrepareInputSetCampaignLayout<ROOTS> {
    #[cfg(test)]
    #[must_use]
    pub(super) fn outer_final_root(&self) -> &Path {
        &self.outer_final_root
    }

    #[cfg(test)]
    #[must_use]
    pub(super) fn outer_staging_root(&self) -> &Path {
        &self.outer_staging_root
    }

    #[cfg(test)]
    #[must_use]
    pub(super) fn staged_input_set_path(&self) -> &Path {
        &self.staged_input_set_path
    }

    #[cfg(test)]
    #[must_use]
    pub(super) fn staged_completion_path(&self) -> &Path {
        &self.staged_completion_path
    }

    #[cfg(test)]
    #[must_use]
    pub(super) fn projected_input_set_path(&self) -> &Path {
        &self.projected_input_set_path
    }

    #[cfg(test)]
    #[must_use]
    pub(super) fn projected_completion_path(&self) -> &Path {
        &self.projected_completion_path
    }

    #[cfg(test)]
    #[must_use]
    pub(super) fn input_set_campaign_relative_path(&self) -> &str {
        self.publication_paths.input_set_path()
    }

    #[cfg(test)]
    #[must_use]
    pub(super) fn completion_campaign_relative_path(&self) -> &str {
        self.publication_paths.completion_path()
    }

    /// Return the opaque semantic H0 paths retained by this physical layout.
    ///
    /// These paths grant no filesystem authority. The publication consumer
    /// cross-binds them only while it owns the matching mutation capability.
    #[must_use]
    pub(super) const fn publication_paths(&self) -> &B4PositiveInputSetPublicationPathsV1 {
        &self.publication_paths
    }

    #[must_use]
    fn required_outer_top_level_entries(&self) -> &[String] {
        &self.required_outer_top_level_entries
    }

    #[must_use]
    fn required_outer_top_level_directories(&self) -> &[String] {
        &self.required_outer_top_level_directories
    }
}

impl<const ROOTS: usize> ProjectedCampaignLayout<ROOTS>
    for ProjectedPrepareInputSetCampaignLayout<ROOTS>
{
    fn campaign_root(&self) -> &Path {
        &self.campaign_root
    }

    fn prior_roots(&self) -> [&Path; ROOTS] {
        self.prior_roots.each_ref().map(PathBuf::as_path)
    }

    fn outer_create_only_layout(&self) -> &super::create_only::CreateOnlyDirectoryLayout {
        &self.outer_create_only
    }

    fn required_outer_top_level_entries(&self) -> &[String] {
        self.required_outer_top_level_entries()
    }

    fn required_outer_top_level_directories(&self) -> &[String] {
        self.required_outer_top_level_directories()
    }
}

impl<const ROOTS: usize> ProjectedPrepareInputSetCampaignLayoutV2<ROOTS> {
    #[cfg(test)]
    #[must_use]
    pub(super) fn outer_final_root(&self) -> &Path {
        &self.outer_final_root
    }

    #[cfg(test)]
    #[must_use]
    pub(super) fn outer_staging_root(&self) -> &Path {
        &self.outer_staging_root
    }

    #[cfg(test)]
    #[must_use]
    pub(super) fn staged_input_set_path(&self) -> &Path {
        &self.staged_input_set_path
    }

    #[cfg(test)]
    #[must_use]
    pub(super) fn staged_completion_path(&self) -> &Path {
        &self.staged_completion_path
    }

    #[cfg(test)]
    #[must_use]
    pub(super) fn projected_input_set_path(&self) -> &Path {
        &self.projected_input_set_path
    }

    #[cfg(test)]
    #[must_use]
    pub(super) fn projected_completion_path(&self) -> &Path {
        &self.projected_completion_path
    }

    #[cfg(test)]
    #[must_use]
    pub(super) fn input_set_campaign_relative_path(&self) -> &str {
        self.publication_paths.input_set_path()
    }

    #[cfg(test)]
    #[must_use]
    pub(super) fn completion_campaign_relative_path(&self) -> &str {
        self.publication_paths.completion_path()
    }

    /// Return the opaque semantic H0 V2 paths retained by this physical layout.
    ///
    /// These paths grant no filesystem authority. The publication consumer
    /// cross-binds them only while it owns the matching mutation capability.
    #[must_use]
    pub(super) const fn publication_paths(&self) -> &B4PositiveInputSetPublicationPathsV2 {
        &self.publication_paths
    }

    #[must_use]
    fn required_outer_top_level_entries(&self) -> &[String] {
        &self.required_outer_top_level_entries
    }

    #[must_use]
    fn required_outer_top_level_directories(&self) -> &[String] {
        &self.required_outer_top_level_directories
    }
}

impl<const ROOTS: usize> ProjectedCampaignLayout<ROOTS>
    for ProjectedPrepareInputSetCampaignLayoutV2<ROOTS>
{
    fn campaign_root(&self) -> &Path {
        &self.campaign_root
    }

    fn prior_roots(&self) -> [&Path; ROOTS] {
        self.prior_roots.each_ref().map(PathBuf::as_path)
    }

    fn outer_create_only_layout(&self) -> &super::create_only::CreateOnlyDirectoryLayout {
        &self.outer_create_only
    }

    fn required_outer_top_level_entries(&self) -> &[String] {
        self.required_outer_top_level_entries()
    }

    fn required_outer_top_level_directories(&self) -> &[String] {
        self.required_outer_top_level_directories()
    }
}

fn project_campaign_root_closure<const ROOTS: usize>(
    campaign_root: &Path,
    prior_roots: [&Path; ROOTS],
    outer_final_root: &Path,
) -> Result<ProjectedCampaignRootClosure<ROOTS>> {
    ensure!(
        ROOTS <= MAX_PROJECTED_PRIOR_ROOTS,
        "projected layout exceeds the compiled prior-root bound"
    );
    validate_normalized_absolute(campaign_root, "campaign root")?;
    validate_normalized_absolute(outer_final_root, "outer final root")?;
    let outer_final_relative =
        require_strict_descendant(outer_final_root, campaign_root, "outer final root")?;
    validate_portable_relative_path(outer_final_relative, "outer final root")?;

    let prior_roots = prior_roots.map(Path::to_path_buf);
    for prior_root in &prior_roots {
        validate_normalized_absolute(prior_root, "prior root")?;
        let relative = require_strict_descendant(prior_root, campaign_root, "prior root")?;
        validate_portable_relative_path(relative, "prior root")?;
    }

    let outer_create_only = project_create_only_directory_layout(outer_final_root)
        .context("outer create-only layout projection failed")?;
    ensure!(
        outer_create_only.final_path() == outer_final_root,
        "outer create-only projector changed the requested final root"
    );
    let outer_final_parent = outer_final_root
        .parent()
        .context("outer final root has no parent")?;
    ensure!(
        outer_create_only.parent() == outer_final_parent,
        "outer create-only projector changed the requested final parent"
    );
    let outer_staging_root = outer_create_only.reserved_staging_path().to_path_buf();
    validate_normalized_absolute(&outer_staging_root, "outer staging root")?;
    require_strict_descendant(&outer_staging_root, campaign_root, "outer staging root")?;

    let mut root_closure = prior_roots.to_vec();
    root_closure.push(outer_final_root.to_path_buf());
    root_closure.push(outer_staging_root.clone());
    require_pairwise_antichain(&root_closure, "campaign root")?;

    Ok(ProjectedCampaignRootClosure {
        campaign_root: campaign_root.to_path_buf(),
        prior_roots,
        outer_create_only,
        outer_final_root: outer_final_root.to_path_buf(),
        outer_staging_root,
    })
}

/// Project the closed H0 two-file publication under one dynamic campaign root.
///
/// This function performs no I/O and grants no filesystem authority. The
/// returned projection becomes physically meaningful only after affine
/// executor preflight captures the campaign and immutable-root custody.
pub(super) fn project_prepare_input_set_campaign_layout<const ROOTS: usize>(
    campaign_root: &Path,
    prior_roots: [&Path; ROOTS],
    outer_final_root: &Path,
) -> Result<ProjectedPrepareInputSetCampaignLayout<ROOTS>> {
    let contract = B4PositiveInputSetLayoutV1::closed_v1();
    let ProjectedCampaignRootClosure {
        campaign_root,
        prior_roots,
        outer_create_only,
        outer_final_root,
        outer_staging_root,
    } = project_campaign_root_closure(campaign_root, prior_roots, outer_final_root)?;

    let staged_paths = [
        outer_staging_root.join(contract.input_set_file()),
        outer_staging_root.join(contract.completion_file()),
    ];
    for path in &staged_paths {
        validate_normalized_absolute(path, "staged H0 file")?;
        require_direct_descendant(path, &outer_staging_root, "staged H0 file")?;
    }
    require_pairwise_antichain(&staged_paths, "staged H0 file")?;
    let mut forbidden_staged_roots = prior_roots.to_vec();
    forbidden_staged_roots.push(outer_final_root.clone());
    require_no_conflicts(&staged_paths, &forbidden_staged_roots, "staged H0 file")?;

    let projected_paths = staged_paths
        .each_ref()
        .map(|path| project_staged_leaf(path, &outer_staging_root, &outer_final_root));
    let projected_paths = projected_paths.into_iter().collect::<Result<Vec<_>>>()?;
    require_pairwise_antichain(&projected_paths, "projected H0 file")?;
    let mut forbidden_final_roots = prior_roots.to_vec();
    forbidden_final_roots.push(outer_staging_root.clone());
    require_no_conflicts(
        &projected_paths,
        &forbidden_final_roots,
        "projected H0 file",
    )?;
    require_equivalent_leaf_closure(&staged_paths, &projected_paths)?;
    require_no_conflicts(&staged_paths, &projected_paths, "staged/projected H0 file")?;

    let phase_campaign_relative_path = campaign_relative_portable_path(
        &outer_final_root,
        &campaign_root,
        "positive input-set phase root",
    )?;
    let publication_paths =
        project_b4_positive_input_set_publication_paths_v1(&phase_campaign_relative_path)
            .context("closed H0 publication path projection failed")?;
    let independently_projected_input_set_path =
        campaign_relative_portable_path(&projected_paths[0], &campaign_root, "positive input set")?;
    let independently_projected_completion_path = campaign_relative_portable_path(
        &projected_paths[1],
        &campaign_root,
        "positive input-set completion",
    )?;
    ensure!(
        independently_projected_input_set_path == publication_paths.input_set_path(),
        "absolute H0 input-set projection differs from the closed publication paths"
    );
    ensure!(
        independently_projected_completion_path == publication_paths.completion_path(),
        "absolute H0 completion projection differs from the closed publication paths"
    );
    ensure!(
        !paths_conflict(
            Path::new(publication_paths.input_set_path()),
            Path::new(publication_paths.completion_path()),
        ),
        "H0 campaign-global file paths conflict"
    );

    let required_outer_top_level_entries = contract.publication_order().map(str::to_owned).to_vec();
    Ok(ProjectedPrepareInputSetCampaignLayout {
        campaign_root,
        prior_roots,
        outer_create_only,
        outer_final_root,
        outer_staging_root,
        staged_input_set_path: staged_paths[0].clone(),
        staged_completion_path: staged_paths[1].clone(),
        projected_input_set_path: projected_paths[0].clone(),
        projected_completion_path: projected_paths[1].clone(),
        publication_paths,
        required_outer_top_level_entries,
        required_outer_top_level_directories: Vec::new(),
    })
}

/// Project the closed H0 V2 two-file publication under one dynamic campaign root.
///
/// This function performs no I/O and grants no filesystem authority. The
/// returned projection becomes physically meaningful only after affine
/// executor preflight captures the campaign and immutable-root custody.
pub(super) fn project_prepare_input_set_campaign_layout_v2<const ROOTS: usize>(
    campaign_root: &Path,
    prior_roots: [&Path; ROOTS],
    outer_final_root: &Path,
) -> Result<ProjectedPrepareInputSetCampaignLayoutV2<ROOTS>> {
    let contract = B4PositiveInputSetLayoutV2::closed_v2();
    let ProjectedCampaignRootClosure {
        campaign_root,
        prior_roots,
        outer_create_only,
        outer_final_root,
        outer_staging_root,
    } = project_campaign_root_closure(campaign_root, prior_roots, outer_final_root)?;

    let staged_paths = [
        outer_staging_root.join(contract.input_set_file()),
        outer_staging_root.join(contract.completion_file()),
    ];
    for path in &staged_paths {
        validate_normalized_absolute(path, "staged H0 V2 file")?;
        require_direct_descendant(path, &outer_staging_root, "staged H0 V2 file")?;
    }
    require_pairwise_antichain(&staged_paths, "staged H0 V2 file")?;
    let mut forbidden_staged_roots = prior_roots.to_vec();
    forbidden_staged_roots.push(outer_final_root.clone());
    require_no_conflicts(&staged_paths, &forbidden_staged_roots, "staged H0 V2 file")?;

    let projected_paths = staged_paths
        .each_ref()
        .map(|path| project_staged_leaf(path, &outer_staging_root, &outer_final_root));
    let projected_paths = projected_paths.into_iter().collect::<Result<Vec<_>>>()?;
    require_pairwise_antichain(&projected_paths, "projected H0 V2 file")?;
    let mut forbidden_final_roots = prior_roots.to_vec();
    forbidden_final_roots.push(outer_staging_root.clone());
    require_no_conflicts(
        &projected_paths,
        &forbidden_final_roots,
        "projected H0 V2 file",
    )?;
    require_equivalent_leaf_closure(&staged_paths, &projected_paths)?;
    require_no_conflicts(
        &staged_paths,
        &projected_paths,
        "staged/projected H0 V2 file",
    )?;

    let phase_campaign_relative_path = campaign_relative_portable_path(
        &outer_final_root,
        &campaign_root,
        "positive input-set V2 phase root",
    )?;
    let publication_paths =
        project_b4_positive_input_set_publication_paths_v2(&phase_campaign_relative_path)
            .context("closed H0 V2 publication path projection failed")?;
    let independently_projected_input_set_path = campaign_relative_portable_path(
        &projected_paths[0],
        &campaign_root,
        "positive input set V2",
    )?;
    let independently_projected_completion_path = campaign_relative_portable_path(
        &projected_paths[1],
        &campaign_root,
        "positive input-set V2 completion",
    )?;
    ensure!(
        independently_projected_input_set_path == publication_paths.input_set_path(),
        "absolute H0 V2 input-set projection differs from the closed publication paths"
    );
    ensure!(
        independently_projected_completion_path == publication_paths.completion_path(),
        "absolute H0 V2 completion projection differs from the closed publication paths"
    );
    ensure!(
        !paths_conflict(
            Path::new(publication_paths.input_set_path()),
            Path::new(publication_paths.completion_path()),
        ),
        "H0 V2 campaign-global file paths conflict"
    );

    let required_outer_top_level_entries = contract.publication_order().map(str::to_owned).to_vec();
    Ok(ProjectedPrepareInputSetCampaignLayoutV2 {
        campaign_root,
        prior_roots,
        outer_create_only,
        outer_final_root,
        outer_staging_root,
        staged_input_set_path: staged_paths[0].clone(),
        staged_completion_path: staged_paths[1].clone(),
        projected_input_set_path: projected_paths[0].clone(),
        projected_completion_path: projected_paths[1].clone(),
        publication_paths,
        required_outer_top_level_entries,
        required_outer_top_level_directories: Vec::new(),
    })
}

const fn canonical_positive_runner_roles()
-> [PositiveRunnerRole; MAX_PROJECTED_OCI_IMAGE_LAYOUT_CAPTURE_SLOTS] {
    [
        PositiveRunnerRole::RustValidatorBuild,
        PositiveRunnerRole::JvmValidatorBuild,
        PositiveRunnerRole::RustVerifier,
        PositiveRunnerRole::JvmVerifier,
    ]
}

fn join_portable_relative(root: &Path, relative_path: &str, label: &str) -> Result<PathBuf> {
    let relative = Path::new(relative_path);
    validate_portable_relative_path(relative, label)?;
    let mut joined = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            anyhow::bail!("{label} contains a noncanonical component");
        };
        joined.push(component);
    }
    Ok(joined)
}

fn resolve_authenticated_oci_archive_locator<const ROOTS: usize>(
    campaign_root: &Path,
    prior_roots: &[PathBuf; ROOTS],
    campaign_archive_path: &str,
) -> Result<(usize, String)> {
    let archive_target = join_portable_relative(
        campaign_root,
        campaign_archive_path,
        "positive-profile OCI archive path",
    )?;
    validate_normalized_absolute(&archive_target, "positive-profile OCI archive target")?;
    let canonical_campaign_path = campaign_relative_portable_path(
        &archive_target,
        campaign_root,
        "positive-profile OCI archive target",
    )?;
    ensure!(
        canonical_campaign_path.as_bytes() == campaign_archive_path.as_bytes(),
        "positive-profile OCI archive path does not round-trip byte-exactly"
    );

    let mut resolved = None;
    for (root_index, prior_root) in prior_roots.iter().enumerate() {
        let Ok(root_relative) = archive_target.strip_prefix(prior_root) else {
            continue;
        };
        if root_relative.as_os_str().is_empty() {
            continue;
        }
        validate_portable_relative_path(root_relative, "root-relative OCI archive path")?;
        let root_relative_path = campaign_relative_portable_path(
            &archive_target,
            prior_root,
            "root-relative OCI archive target",
        )?;
        ensure!(
            join_portable_relative(
                prior_root,
                &root_relative_path,
                "root-relative OCI archive path",
            )? == archive_target,
            "root-relative OCI archive locator does not recompose byte-exactly"
        );
        ensure!(
            resolved.is_none(),
            "positive-profile OCI archive maps to multiple retained roots"
        );
        resolved = Some((root_index, root_relative_path));
    }
    resolved.context("positive-profile OCI archive does not map to exactly one retained root")
}

/// Project all four gate-authenticated OCI profiles into one affine H0 topology.
///
/// The caller supplies neither roles, archive paths, root indices, nor image
/// expectations. Role order and campaign-global archive paths come only from
/// one successful positive gate; physical locators are derived against the
/// already-closed retained-root layout before any custody or filesystem I/O.
pub(super) fn project_authenticated_prepare_input_set_oci_topology<const ROOTS: usize>(
    layout: ProjectedPrepareInputSetCampaignLayout<ROOTS>,
    gate: PositiveGateBindings,
) -> Result<AuthenticatedPrepareInputSetOciTopologyV1<ROOTS>> {
    let profiles: &[B4PositiveOciImageLayoutV1; MAX_PROJECTED_OCI_IMAGE_LAYOUT_CAPTURE_SLOTS] =
        gate.oci_image_layouts();
    let mut capture_slots = Vec::<ProjectedOciImageLayoutCaptureSlotV1>::with_capacity(
        MAX_PROJECTED_OCI_IMAGE_LAYOUT_CAPTURE_SLOTS,
    );
    let mut permits = Vec::with_capacity(MAX_PROJECTED_OCI_IMAGE_LAYOUT_CAPTURE_SLOTS);

    for (profile, expected_role) in profiles.iter().zip(canonical_positive_runner_roles()) {
        ensure!(
            profile.role() == expected_role,
            "positive-profile OCI runner role is outside canonical order"
        );
        let (root_index, root_relative_path) = resolve_authenticated_oci_archive_locator(
            &layout.campaign_root,
            &layout.prior_roots,
            profile.archive_path(),
        )?;
        for retained in &capture_slots {
            if retained.root_index == root_index {
                ensure!(
                    !paths_conflict(
                        Path::new(&retained.relative_path),
                        Path::new(&root_relative_path),
                    ),
                    "positive-profile OCI archive locators conflict within retained root {root_index}"
                );
            }
        }
        let permit = AuthenticatedOciSlotConstructionPermitV1 {
            root_index,
            root_relative_path,
            profile: profile.clone(),
        };
        capture_slots.push(permit.capture_slot());
        permits.push(permit);
    }

    capture_slots.sort_by(|left, right| {
        left.root_index
            .cmp(&right.root_index)
            .then_with(|| left.relative_path.cmp(&right.relative_path))
    });
    let capture_slots = capture_slots
        .try_into()
        .map_err(|_| anyhow::anyhow!("authenticated OCI capture-slot cardinality drift"))?;
    let permits = permits
        .try_into()
        .map_err(|_| anyhow::anyhow!("authenticated OCI permit cardinality drift"))?;
    let import_inventory = project_authenticated_oci_outer_ustar_inventory(permits, gate)?;

    Ok(AuthenticatedPrepareInputSetOciTopologyV1 {
        layout,
        capture_slots,
        import_inventory,
    })
}

/// Test-only projection of the OCI capture inventory which future H0 topology
/// must derive before entering descriptor custody.
#[cfg(test)]
pub(super) fn project_prepare_input_set_oci_capture_test_only<const ROOTS: usize>(
    layout: ProjectedPrepareInputSetCampaignLayout<ROOTS>,
    slots: &[(usize, &str)],
) -> Result<ProjectedPrepareInputSetOciCaptureV1<ROOTS>> {
    ensure!(
        (1..=MAX_PROJECTED_OCI_IMAGE_LAYOUT_CAPTURE_SLOTS).contains(&slots.len()),
        "OCI image-layout capture slot count is outside the closed H0 bound"
    );
    let mut projected = Vec::<ProjectedOciImageLayoutCaptureSlotV1>::new();
    projected
        .try_reserve_exact(slots.len())
        .context("cannot retain the bounded OCI image-layout capture slots")?;
    for &(root_index, relative_path) in slots {
        ensure!(
            root_index < ROOTS,
            "OCI image-layout capture root index is outside the projected prior-root set"
        );
        validate_portable_relative_path(Path::new(relative_path), "OCI image-layout capture path")?;
        for retained in &projected {
            if retained.root_index == root_index {
                ensure!(
                    !paths_conflict(Path::new(&retained.relative_path), Path::new(relative_path),),
                    "OCI image-layout capture paths conflict within prior root {root_index}"
                );
            }
        }
        let mut retained_path = String::new();
        retained_path
            .try_reserve_exact(relative_path.len())
            .context("cannot retain a bounded OCI image-layout capture path")?;
        retained_path.push_str(relative_path);
        projected.push(ProjectedOciImageLayoutCaptureSlotV1 {
            root_index,
            relative_path: retained_path,
        });
    }
    projected.sort_by(|left, right| {
        left.root_index
            .cmp(&right.root_index)
            .then_with(|| left.relative_path.cmp(&right.relative_path))
    });
    Ok(ProjectedPrepareInputSetOciCaptureV1 {
        layout,
        slots: projected,
    })
}

/// Project and validate one future outer campaign transaction without I/O.
///
/// # Errors
///
/// Returns an error unless every supplied path is normalized, absolute, and
/// strictly below `campaign_root`; the prior and outer roots form a
/// component-wise antichain; and all staging and projected final leaves are
/// safe, direct, and pairwise disjoint.
#[allow(
    clippy::too_many_lines,
    reason = "the pure projection keeps every related antichain and containment check together"
)]
pub(super) fn project_outer_campaign_layout<const ROOTS: usize, const LEAVES: usize>(
    campaign_root: &Path,
    prior_roots: [&Path; ROOTS],
    outer_final_root: &Path,
    additional_top_level_leaves: [&str; LEAVES],
) -> Result<ProjectedOuterCampaignLayout<ROOTS>> {
    ensure!(
        LEAVES <= MAX_PROJECTED_ADDITIONAL_LEAVES,
        "projected layout exceeds the compiled additional-leaf bound"
    );
    let ProjectedCampaignRootClosure {
        campaign_root,
        prior_roots,
        outer_create_only,
        outer_final_root,
        outer_staging_root,
    } = project_campaign_root_closure(campaign_root, prior_roots, outer_final_root)?;

    let staged_inner_destination = outer_staging_root.join(INNER_PACKET_COMPONENT);
    let inner_layout = project_b4_terminal_evidence_publication_layout(&staged_inner_destination)
        .context("inner terminal-evidence layout projection failed")?;
    ensure!(
        inner_layout.final_path() == staged_inner_destination,
        "inner projector changed the requested final path"
    );
    ensure!(
        inner_layout.parent() == outer_staging_root,
        "inner projector changed the requested staging parent"
    );

    let mut staged_leaves = vec![
        inner_layout.final_path().to_path_buf(),
        inner_layout.reserved_staging_path().to_path_buf(),
    ];
    let mut required_outer_top_level_entries = Vec::new();
    required_outer_top_level_entries
        .try_reserve_exact(LEAVES + 1)
        .context("cannot retain bounded required outer leaf names")?;
    required_outer_top_level_entries.push(INNER_PACKET_COMPONENT.to_owned());
    for leaf in additional_top_level_leaves {
        validate_portable_component(leaf, "additional top-level leaf")?;
        required_outer_top_level_entries.push(leaf.to_owned());
        staged_leaves.push(outer_staging_root.join(leaf));
    }

    for leaf in &staged_leaves {
        validate_normalized_absolute(leaf, "staged top-level leaf")?;
        require_direct_descendant(leaf, &outer_staging_root, "staged top-level leaf")?;
    }
    require_pairwise_antichain(&staged_leaves, "staged top-level leaf")?;

    let mut forbidden_staged_roots = prior_roots.to_vec();
    forbidden_staged_roots.push(outer_final_root.clone());
    require_no_conflicts(
        &staged_leaves,
        &forbidden_staged_roots,
        "staged top-level leaf",
    )?;

    let projected_final_leaves = staged_leaves
        .iter()
        .map(|leaf| project_staged_leaf(leaf, &outer_staging_root, &outer_final_root))
        .collect::<Result<Vec<_>>>()?;
    require_pairwise_antichain(&projected_final_leaves, "projected final leaf")?;

    let mut forbidden_final_roots = prior_roots.to_vec();
    forbidden_final_roots.push(outer_staging_root.clone());
    require_no_conflicts(
        &projected_final_leaves,
        &forbidden_final_roots,
        "projected final leaf",
    )?;
    require_equivalent_leaf_closure(&staged_leaves, &projected_final_leaves)?;
    require_no_conflicts(
        &staged_leaves,
        &projected_final_leaves,
        "staged/projected leaf",
    )?;

    let mut staged_leaves = staged_leaves.into_iter();
    let staged_inner_final_path = staged_leaves
        .next()
        .context("inner final path disappeared from projected layout")?;
    let staged_inner_staging_path = staged_leaves
        .next()
        .context("inner staging path disappeared from projected layout")?;
    let staged_additional_top_level_leaves = staged_leaves.collect();

    let mut projected_final_leaves = projected_final_leaves.into_iter();
    let projected_inner_final_path = projected_final_leaves
        .next()
        .context("projected inner final path disappeared from layout")?;
    let projected_inner_staging_path = projected_final_leaves
        .next()
        .context("projected inner staging path disappeared from layout")?;
    let projected_additional_top_level_leaves = projected_final_leaves.collect();

    Ok(ProjectedOuterCampaignLayout {
        campaign_root,
        prior_roots,
        outer_create_only,
        outer_final_root,
        outer_staging_root,
        staged_inner_final_path,
        staged_inner_staging_path,
        projected_inner_final_path,
        projected_inner_staging_path,
        required_outer_top_level_entries,
        required_outer_top_level_directories: vec![INNER_PACKET_COMPONENT.to_owned()],
        staged_additional_top_level_leaves,
        projected_additional_top_level_leaves,
    })
}

/// Project one exact direct directory subtree without any inner transaction.
///
/// # Errors
///
/// Returns an error unless the common campaign roots form the closed
/// component-wise antichain and `subtree_component` is one safe portable
/// direct child at both the staged and committed locations.
pub(super) fn project_single_subtree_campaign_layout<const ROOTS: usize>(
    campaign_root: &Path,
    prior_roots: [&Path; ROOTS],
    outer_final_root: &Path,
    subtree_component: &str,
) -> Result<ProjectedSingleSubtreeCampaignLayout<ROOTS>> {
    validate_portable_component(subtree_component, "single subtree component")?;
    let ProjectedCampaignRootClosure {
        campaign_root,
        prior_roots,
        outer_create_only,
        outer_final_root,
        outer_staging_root,
    } = project_campaign_root_closure(campaign_root, prior_roots, outer_final_root)?;

    let staged_subtree_path = outer_staging_root.join(subtree_component);
    validate_normalized_absolute(&staged_subtree_path, "staged single subtree")?;
    require_direct_descendant(
        &staged_subtree_path,
        &outer_staging_root,
        "staged single subtree",
    )?;
    let mut forbidden_staged_roots = prior_roots.to_vec();
    forbidden_staged_roots.push(outer_final_root.clone());
    require_no_conflicts(
        std::slice::from_ref(&staged_subtree_path),
        &forbidden_staged_roots,
        "staged single subtree",
    )?;

    let projected_subtree_path =
        project_staged_leaf(&staged_subtree_path, &outer_staging_root, &outer_final_root)?;
    require_direct_descendant(
        &projected_subtree_path,
        &outer_final_root,
        "projected single subtree",
    )?;
    let mut forbidden_final_roots = prior_roots.to_vec();
    forbidden_final_roots.push(outer_staging_root.clone());
    require_no_conflicts(
        std::slice::from_ref(&projected_subtree_path),
        &forbidden_final_roots,
        "projected single subtree",
    )?;
    require_no_conflicts(
        std::slice::from_ref(&staged_subtree_path),
        std::slice::from_ref(&projected_subtree_path),
        "staged/projected single subtree",
    )?;

    Ok(ProjectedSingleSubtreeCampaignLayout {
        campaign_root,
        prior_roots,
        outer_create_only,
        outer_final_root,
        outer_staging_root,
        staged_subtree_path,
        projected_subtree_path,
        required_outer_top_level_entries: vec![subtree_component.to_owned()],
        required_outer_top_level_directories: vec![subtree_component.to_owned()],
    })
}

/// Project one exact direct file beneath a fresh create-only directory.
///
/// # Errors
///
/// Returns an error unless the common campaign roots form the closed
/// component-wise antichain and `file_component` is one safe portable direct
/// child at both the staged and committed locations.
pub(super) fn project_single_file_campaign_layout<const ROOTS: usize>(
    campaign_root: &Path,
    prior_roots: [&Path; ROOTS],
    outer_final_root: &Path,
    file_component: &str,
) -> Result<ProjectedSingleFileCampaignLayout<ROOTS>> {
    validate_portable_component(file_component, "single file component")?;
    let ProjectedCampaignRootClosure {
        campaign_root,
        prior_roots,
        outer_create_only,
        outer_final_root,
        outer_staging_root,
    } = project_campaign_root_closure(campaign_root, prior_roots, outer_final_root)?;

    let staged_file_path = outer_staging_root.join(file_component);
    validate_normalized_absolute(&staged_file_path, "staged single file")?;
    require_direct_descendant(&staged_file_path, &outer_staging_root, "staged single file")?;
    let mut forbidden_staged_roots = prior_roots.to_vec();
    forbidden_staged_roots.push(outer_final_root.clone());
    require_no_conflicts(
        std::slice::from_ref(&staged_file_path),
        &forbidden_staged_roots,
        "staged single file",
    )?;

    let projected_file_path =
        project_staged_leaf(&staged_file_path, &outer_staging_root, &outer_final_root)?;
    require_direct_descendant(
        &projected_file_path,
        &outer_final_root,
        "projected single file",
    )?;
    let mut forbidden_final_roots = prior_roots.to_vec();
    forbidden_final_roots.push(outer_staging_root.clone());
    require_no_conflicts(
        std::slice::from_ref(&projected_file_path),
        &forbidden_final_roots,
        "projected single file",
    )?;
    require_equivalent_leaf_closure(
        std::slice::from_ref(&staged_file_path),
        std::slice::from_ref(&projected_file_path),
    )?;
    require_no_conflicts(
        std::slice::from_ref(&staged_file_path),
        std::slice::from_ref(&projected_file_path),
        "staged/projected single file",
    )?;

    Ok(ProjectedSingleFileCampaignLayout {
        campaign_root,
        prior_roots,
        outer_create_only,
        outer_final_root,
        outer_staging_root,
        staged_file_path,
        projected_file_path,
        required_outer_top_level_entries: vec![file_component.to_owned()],
        required_outer_top_level_directories: Vec::new(),
    })
}

fn validate_normalized_absolute(path: &Path, label: &str) -> Result<()> {
    ensure!(path.is_absolute(), "{label} must be absolute");
    ensure!(
        path.components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir)),
        "{label} contains a dot or parent component"
    );
    let rebuilt = path.components().collect::<PathBuf>();
    ensure!(
        rebuilt.as_os_str() == path.as_os_str(),
        "{label} is not lexically normalized"
    );
    Ok(())
}

fn require_strict_descendant<'a>(path: &'a Path, root: &Path, label: &str) -> Result<&'a Path> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("{label} is not derived from its retained root"))?;
    ensure!(
        !relative.as_os_str().is_empty(),
        "{label} conflict: path must be strictly below its root"
    );
    ensure!(!relative.is_absolute(), "{label} escaped its retained root");
    Ok(relative)
}

fn campaign_relative_portable_path(
    path: &Path,
    campaign_root: &Path,
    label: &str,
) -> Result<String> {
    let relative = require_strict_descendant(path, campaign_root, label)?;
    validate_portable_relative_path(relative, label)?;
    relative
        .components()
        .map(|component| {
            let Component::Normal(component) = component else {
                anyhow::bail!("{label} contains a noncanonical component");
            };
            component
                .to_str()
                .with_context(|| format!("{label} contains a non-UTF-8 component"))
                .map(str::to_owned)
        })
        .collect::<Result<Vec<_>>>()
        .map(|components| components.join("/"))
}

fn require_direct_descendant(path: &Path, root: &Path, label: &str) -> Result<()> {
    let relative = require_strict_descendant(path, root, label)?;
    ensure!(
        relative.components().count() == 1
            && matches!(relative.components().next(), Some(Component::Normal(_))),
        "{label} must be one direct component below its root"
    );
    Ok(())
}

fn validate_portable_relative_path(path: &Path, label: &str) -> Result<()> {
    ensure!(
        !path.as_os_str().is_empty(),
        "{label} has an empty relative path"
    );
    let mut encoded_length = 0_usize;
    let mut component_count = 0_usize;
    for component in path.components() {
        let Component::Normal(component) = component else {
            anyhow::bail!("{label} contains a noncanonical component");
        };
        let component = component
            .to_str()
            .with_context(|| format!("{label} contains a non-UTF-8 component"))?;
        validate_portable_component(component, label)?;
        encoded_length = encoded_length
            .checked_add(usize::from(component_count != 0))
            .and_then(|length| length.checked_add(component.len()))
            .context("campaign relative-path length overflowed")?;
        component_count += 1;
    }
    ensure!(
        component_count != 0 && (1..=MAX_CAMPAIGN_RELATIVE_PATH_BYTES).contains(&encoded_length),
        "{label} length is outside the campaign-relative bound"
    );
    Ok(())
}

fn validate_portable_component(component: &str, label: &str) -> Result<()> {
    ensure!(
        (1..=MAX_CAMPAIGN_RELATIVE_PATH_BYTES).contains(&component.len()),
        "{label} component length is outside the portable bound"
    );
    ensure!(
        component.is_ascii(),
        "{label} must use the portable ASCII subset"
    );
    let bytes = component.as_bytes();
    ensure!(
        bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit(),
        "{label} must start with a lowercase letter or digit"
    );
    ensure!(
        bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        }),
        "{label} contains a non-portable character"
    );
    ensure!(
        component != "." && component != ".." && !component.ends_with('.'),
        "{label} contains a dot, parent, or trailing-dot component"
    );
    let device_stem = component.split('.').next().unwrap_or(component);
    ensure!(
        !is_windows_device_name(device_stem),
        "{label} contains a reserved Windows device component"
    );
    Ok(())
}

fn is_windows_device_name(component: &str) -> bool {
    matches!(component, "con" | "prn" | "aux" | "nul")
        || component
            .strip_prefix("com")
            .is_some_and(is_windows_device_digit)
        || component
            .strip_prefix("lpt")
            .is_some_and(is_windows_device_digit)
}

fn is_windows_device_digit(suffix: &str) -> bool {
    suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9')
}

fn paths_conflict(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn require_pairwise_antichain(paths: &[PathBuf], label: &str) -> Result<()> {
    for (index, left) in paths.iter().enumerate() {
        for right in &paths[index + 1..] {
            ensure!(
                !paths_conflict(left, right),
                "{label} conflict between {} and {}",
                left.display(),
                right.display()
            );
        }
    }
    Ok(())
}

fn require_no_conflicts(paths: &[PathBuf], forbidden_roots: &[PathBuf], label: &str) -> Result<()> {
    for path in paths {
        for forbidden_root in forbidden_roots {
            ensure!(
                !paths_conflict(path, forbidden_root),
                "{label} conflict between {} and {}",
                path.display(),
                forbidden_root.display()
            );
        }
    }
    Ok(())
}

fn project_staged_leaf(
    staged_leaf: &Path,
    outer_staging_root: &Path,
    outer_final_root: &Path,
) -> Result<PathBuf> {
    let relative = staged_leaf
        .strip_prefix(outer_staging_root)
        .context("staged leaf escaped the outer staging root")?;
    ensure!(
        !relative.as_os_str().is_empty() && !relative.is_absolute(),
        "staged leaf did not project to a strict relative path"
    );
    let projected = outer_final_root.join(relative);
    validate_normalized_absolute(&projected, "projected final leaf")?;
    let projected_relative =
        require_strict_descendant(&projected, outer_final_root, "projected final leaf")?;
    ensure!(
        projected_relative.as_os_str() == relative.as_os_str(),
        "component-wise staging-to-final projection changed the relative leaf"
    );
    Ok(projected)
}

fn require_equivalent_leaf_closure(staged: &[PathBuf], projected: &[PathBuf]) -> Result<()> {
    ensure!(
        staged.len() == projected.len(),
        "staged and projected leaf closures have different cardinality"
    );
    for left in 0..staged.len() {
        for right in left + 1..staged.len() {
            ensure!(
                paths_conflict(&staged[left], &staged[right])
                    == paths_conflict(&projected[left], &projected[right]),
                "staging-to-final projection changed the component-wise leaf closure"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use super::{
        AuthenticatedOciSlotConstructionPermitV1, AuthenticatedPrepareInputSetOciTopologyV1,
        ProjectedPrepareInputSetCampaignLayoutV2, canonical_positive_runner_roles,
        project_authenticated_prepare_input_set_oci_topology, project_outer_campaign_layout,
        project_prepare_input_set_campaign_layout, project_prepare_input_set_campaign_layout_v2,
        project_prepare_input_set_oci_capture_test_only, project_single_file_campaign_layout,
        project_single_subtree_campaign_layout, resolve_authenticated_oci_archive_locator,
    };
    use eip_0045_reproduction::b4_positive_gate::{PositiveGateBindings, PositiveRunnerRole};
    use eip_0045_reproduction::b4_positive_input_set::{
        B4PositiveInputSetLayoutV1, B4PositiveInputSetLayoutV2,
    };

    #[test]
    fn prepare_input_set_projection_closes_two_direct_files_and_campaign_paths() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let prior = campaign.join("inputs");
        let outer_final = campaign.join("phases").join("prepare-001");

        let projection =
            project_prepare_input_set_campaign_layout(&campaign, [&prior], &outer_final).unwrap();
        let contract = B4PositiveInputSetLayoutV1::closed_v1();

        assert_eq!(
            projection.required_outer_top_level_entries(),
            contract.publication_order()
        );
        assert!(projection.required_outer_top_level_directories().is_empty());
        assert_eq!(
            projection.staged_input_set_path(),
            projection
                .outer_staging_root()
                .join(contract.input_set_file())
        );
        assert_eq!(
            projection.staged_completion_path(),
            projection
                .outer_staging_root()
                .join(contract.completion_file())
        );
        assert_eq!(
            projection.projected_input_set_path(),
            outer_final.join(contract.input_set_file())
        );
        assert_eq!(
            projection.projected_completion_path(),
            outer_final.join(contract.completion_file())
        );
        assert_eq!(
            projection.input_set_campaign_relative_path(),
            "phases/prepare-001/positive-input-set.json"
        );
        assert_eq!(
            projection.completion_campaign_relative_path(),
            "phases/prepare-001/positive-input-set-completion.json"
        );
        assert_eq!(
            projection.publication_paths().input_set_path(),
            projection.input_set_campaign_relative_path()
        );
        assert_eq!(
            projection.publication_paths().completion_path(),
            projection.completion_campaign_relative_path()
        );
        assert_eq!(
            projection.publication_paths().phase_root(),
            "phases/prepare-001"
        );
    }

    #[test]
    fn prepare_input_set_v2_projection_is_distinct_and_closes_the_same_two_leaf_names() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let prior = campaign.join("inputs");
        let outer_final = campaign.join("phases").join("prepare-v2");
        let projector: fn(
            &Path,
            [&Path; 1],
            &Path,
        ) -> anyhow::Result<ProjectedPrepareInputSetCampaignLayoutV2<1>> =
            project_prepare_input_set_campaign_layout_v2;

        let projection = projector(&campaign, [&prior], &outer_final).unwrap();
        let contract = B4PositiveInputSetLayoutV2::closed_v2();

        assert_eq!(
            projection.required_outer_top_level_entries(),
            contract.publication_order()
        );
        assert!(projection.required_outer_top_level_directories().is_empty());
        assert_eq!(
            contract.publication_order(),
            B4PositiveInputSetLayoutV1::closed_v1().publication_order(),
            "V2 changes the envelope identity, not the two physical leaf names"
        );
        assert_eq!(
            projection.publication_paths().phase_root(),
            "phases/prepare-v2"
        );
        assert_eq!(
            projection.publication_paths().input_set_path(),
            "phases/prepare-v2/positive-input-set.json"
        );
        assert_eq!(
            projection.publication_paths().completion_path(),
            "phases/prepare-v2/positive-input-set-completion.json"
        );
    }

    #[test]
    fn prepare_input_set_v2_projection_is_excluded_from_generic_create_only_layouts() {
        trait AmbiguousIfGeneric<Marker> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfGeneric<()> for T {}
        impl<T: ?Sized + super::GenericCreateOnlyCampaignLayout<1>> AmbiguousIfGeneric<u8> for T {}

        <ProjectedPrepareInputSetCampaignLayoutV2<1> as AmbiguousIfGeneric<_>>::marker();
    }

    #[test]
    fn prepare_input_set_projection_accepts_dynamic_antichain_phase_roots_without_io() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let build = campaign.join("imports").join("build");
        let validators = campaign.join("imports").join("validators");
        fs::create_dir_all(&build).unwrap();
        fs::create_dir_all(&validators).unwrap();
        fs::write(build.join("source.bin"), b"build").unwrap();
        fs::write(validators.join("source.bin"), b"validators").unwrap();
        let before = fs::read_dir(&campaign)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        let outer_final = campaign.join("h0").join("candidate-a");

        let projection = project_prepare_input_set_campaign_layout(
            &campaign,
            [&build, &validators],
            &outer_final,
        )
        .unwrap();
        let after = fs::read_dir(&campaign)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();

        assert_eq!(before, after);
        assert!(!projection.outer_final_root().exists());
        assert!(!projection.outer_staging_root().exists());
        assert_eq!(
            projection.input_set_campaign_relative_path(),
            "h0/candidate-a/positive-input-set.json"
        );
    }

    #[test]
    fn prepare_input_set_projection_rejects_root_conflicts_and_combined_path_overflow() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        fs::create_dir(&campaign).unwrap();
        let before = fs::read_dir(&campaign)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        let outer = campaign.join("phases").join("prepare-001");

        for invalid_outer in [campaign.clone(), temp.path().join("outside")] {
            assert!(
                project_prepare_input_set_campaign_layout(
                    &campaign,
                    [&campaign.join("inputs")],
                    &invalid_outer,
                )
                .is_err()
            );
        }
        for conflicting_prior in [outer.clone(), outer.join("nested"), campaign.join("phases")] {
            assert!(
                project_prepare_input_set_campaign_layout(&campaign, [&conflicting_prior], &outer,)
                    .is_err()
            );
        }

        let mut long_outer = campaign.clone();
        for _ in 0..11 {
            long_outer.push("aaaaaaaaaaaaaaaaaaaa");
        }
        let error = project_prepare_input_set_campaign_layout(
            &campaign,
            [&campaign.join("inputs")],
            &long_outer,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("length"));
        let after = fs::read_dir(&campaign)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(before, after);
        assert!(!outer.exists());
        assert!(!long_outer.exists());
    }

    #[test]
    fn authenticated_oci_archive_locator_requires_one_root_and_exact_round_trip() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let rust = campaign.join("imports").join("rust");
        let jvm = campaign.join("imports").join("jvm");
        let roots = [rust.clone(), jvm];

        let resolved = resolve_authenticated_oci_archive_locator(
            &campaign,
            &roots,
            "imports/rust/images/runner.oci.tar",
        )
        .unwrap();
        assert_eq!(resolved, (0, "images/runner.oci.tar".to_owned()));

        for rejected in [
            "imports/rust",
            "archives/runner.oci.tar",
            "imports/rust-extra/runner.oci.tar",
            "imports/Rust/runner.oci.tar",
            "imports/rust/../jvm/runner.oci.tar",
            "imports/rust/images//runner.oci.tar",
        ] {
            assert!(
                resolve_authenticated_oci_archive_locator(&campaign, &roots, rejected).is_err(),
                "accepted noncanonical or unrooted archive path {rejected}"
            );
        }

        let overlapping = [campaign.join("imports"), rust];
        let error = resolve_authenticated_oci_archive_locator(
            &campaign,
            &overlapping,
            "imports/rust/images/runner.oci.tar",
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("multiple retained roots"));
    }

    #[test]
    fn authenticated_oci_topology_types_are_affine_and_roles_are_canonical() {
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

        <AuthenticatedOciSlotConstructionPermitV1 as AmbiguousIfClone<_>>::marker();
        <AuthenticatedOciSlotConstructionPermitV1 as AmbiguousIfCopy<_>>::marker();
        <AuthenticatedPrepareInputSetOciTopologyV1<1> as AmbiguousIfClone<_>>::marker();
        <AuthenticatedPrepareInputSetOciTopologyV1<1> as AmbiguousIfCopy<_>>::marker();
        let project: fn(
            super::ProjectedPrepareInputSetCampaignLayout<1>,
            PositiveGateBindings,
        ) -> anyhow::Result<AuthenticatedPrepareInputSetOciTopologyV1<1>> =
            project_authenticated_prepare_input_set_oci_topology;
        std::hint::black_box(project);
        assert_eq!(
            canonical_positive_runner_roles(),
            [
                PositiveRunnerRole::RustValidatorBuild,
                PositiveRunnerRole::JvmValidatorBuild,
                PositiveRunnerRole::RustVerifier,
                PositiveRunnerRole::JvmVerifier,
            ]
        );
    }

    #[test]
    fn oci_capture_projection_owns_one_stably_ordered_closed_slot_set() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let rust_inputs = campaign.join("inputs").join("rust");
        let jvm_inputs = campaign.join("inputs").join("jvm");
        let outer = campaign.join("phases").join("prepare-001");
        let layout = project_prepare_input_set_campaign_layout(
            &campaign,
            [&rust_inputs, &jvm_inputs],
            &outer,
        )
        .unwrap();

        let projected = project_prepare_input_set_oci_capture_test_only(
            layout,
            &[
                (1, "images/jvm-verify.oci.tar"),
                (0, "images/rust.oci.tar"),
                (1, "images/jvm-build.oci.tar"),
            ],
        )
        .unwrap();
        let (retained_layout, slots) = projected.into_parts();

        assert_eq!(retained_layout.outer_final_root(), outer);
        assert_eq!(slots.len(), 3);
        assert_eq!(slots[0].root_index(), 0);
        assert_eq!(slots[0].relative_path(), "images/rust.oci.tar");
        assert_eq!(slots[1].root_index(), 1);
        assert_eq!(slots[1].relative_path(), "images/jvm-build.oci.tar");
        assert_eq!(slots[2].root_index(), 1);
        assert_eq!(slots[2].relative_path(), "images/jvm-verify.oci.tar");
    }

    #[test]
    fn oci_capture_projection_rejects_empty_oversized_or_out_of_range_slots() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let prior = campaign.join("inputs");
        let outer = campaign.join("phases").join("prepare-001");
        let layout =
            || project_prepare_input_set_campaign_layout(&campaign, [&prior], &outer).unwrap();

        assert!(project_prepare_input_set_oci_capture_test_only(layout(), &[]).is_err());
        assert!(
            project_prepare_input_set_oci_capture_test_only(
                layout(),
                &[
                    (0, "images/a.oci.tar"),
                    (0, "images/b.oci.tar"),
                    (0, "images/c.oci.tar"),
                    (0, "images/d.oci.tar"),
                    (0, "images/e.oci.tar"),
                ],
            )
            .is_err()
        );
        assert!(
            project_prepare_input_set_oci_capture_test_only(layout(), &[(1, "images/a.oci.tar")],)
                .is_err()
        );

        let second = campaign.join("inputs-second");
        let distributed =
            project_prepare_input_set_campaign_layout(&campaign, [&prior, &second], &outer)
                .unwrap();
        assert!(
            project_prepare_input_set_oci_capture_test_only(
                distributed,
                &[
                    (0, "images/a.oci.tar"),
                    (0, "images/b.oci.tar"),
                    (0, "images/c.oci.tar"),
                    (1, "images/d.oci.tar"),
                    (1, "images/e.oci.tar"),
                ],
            )
            .is_err()
        );
    }

    #[test]
    fn oci_capture_projection_rejects_nonportable_or_overlong_relative_paths() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let prior = campaign.join("inputs");
        let outer = campaign.join("phases").join("prepare-001");
        let layout =
            || project_prepare_input_set_campaign_layout(&campaign, [&prior], &outer).unwrap();
        let overlong = format!("images/{}.tar", "a".repeat(230));

        for invalid in [
            "",
            "/absolute.oci.tar",
            "../escape.oci.tar",
            "Images/a.oci.tar",
        ] {
            assert!(
                project_prepare_input_set_oci_capture_test_only(layout(), &[(0, invalid)],)
                    .is_err()
            );
        }
        assert!(
            project_prepare_input_set_oci_capture_test_only(layout(), &[(0, overlong.as_str())],)
                .is_err()
        );
    }

    #[test]
    fn oci_capture_projection_enforces_an_antichain_only_within_each_root() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let first = campaign.join("inputs").join("first");
        let second = campaign.join("inputs").join("second");
        let outer = campaign.join("phases").join("prepare-001");
        let layout = || {
            project_prepare_input_set_campaign_layout(&campaign, [&first, &second], &outer).unwrap()
        };

        for conflicting in [
            [(0, "images/base.oci.tar"), (0, "images/base.oci.tar")],
            [(0, "images/base"), (0, "images/base/layer.oci.tar")],
        ] {
            assert!(
                project_prepare_input_set_oci_capture_test_only(layout(), &conflicting).is_err()
            );
        }
        let projected = project_prepare_input_set_oci_capture_test_only(
            layout(),
            &[(0, "images/shared.oci.tar"), (1, "images/shared.oci.tar")],
        )
        .unwrap();
        assert_eq!(projected.into_parts().1.len(), 2);
    }

    #[test]
    fn oci_capture_authority_has_one_gate_rooted_production_origin() {
        let source = include_str!("preflight.rs").replace("\r\n", "\n");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        let topology = production
            .split("pub(super) fn project_authenticated_prepare_input_set_oci_topology")
            .nth(1)
            .unwrap()
            .split("/// Test-only projection of the OCI capture inventory")
            .next()
            .unwrap();
        let role_check = topology.find("profile.role() == expected_role").unwrap();
        let root_resolution = topology
            .find("resolve_authenticated_oci_archive_locator")
            .unwrap();
        let permit_mint = topology
            .find("let permit = AuthenticatedOciSlotConstructionPermitV1")
            .unwrap();
        let inventory_bridge = topology
            .find("project_authenticated_oci_outer_ustar_inventory")
            .unwrap();
        let (_, test_constructor) = production
            .split_once("/// Test-only projection of the OCI capture inventory")
            .unwrap();
        let test_constructor_prefix = test_constructor
            .split_once("pub(super) fn project_prepare_input_set_oci_capture_test_only")
            .unwrap()
            .0;
        let layout_trait = production
            .split("pub(super) trait ProjectedCampaignLayout")
            .nth(1)
            .unwrap()
            .split("/// Sealed admission gate")
            .next()
            .unwrap();

        assert!(topology.contains("gate: PositiveGateBindings"));
        assert!(topology.contains("gate.oci_image_layouts()"));
        assert!(production.contains("profile: B4PositiveOciImageLayoutV1,"));
        assert!(production.contains("gate: PositiveGateBindings,"));
        assert!(!production.contains("campaign_archive_path: String,"));
        assert!(role_check < root_resolution);
        assert!(root_resolution < permit_mint);
        assert!(permit_mint < inventory_bridge);
        assert_eq!(
            production
                .matches("let permit = AuthenticatedOciSlotConstructionPermitV1")
                .count(),
            1
        );
        assert_eq!(
            production
                .matches("project_authenticated_oci_outer_ustar_inventory(")
                .count(),
            1
        );
        assert!(production.contains("profile: profile.clone(),"));
        assert!(production.contains("OciTopologyCustodyBridgePermitV1"));
        let topology_impl = production
            .split("impl<const ROOTS: usize> AuthenticatedPrepareInputSetOciTopologyV1<ROOTS>")
            .nth(1)
            .unwrap()
            .split("/// Common custody")
            .next()
            .unwrap();
        assert!(topology_impl.contains("pub(super) fn into_custody_parts("));
        assert!(!topology_impl.contains("pub(super) fn into_parts("));
        for forbidden in [
            "BorrowedFd",
            "RawFd",
            "AsRawFd",
            "File::open",
            "OpenOptions",
            "/proc/self/fd",
        ] {
            assert!(!topology.contains(forbidden));
        }
        assert!(test_constructor_prefix.trim_end().ends_with("#[cfg(test)]"));
        assert_eq!(
            test_constructor
                .matches("Ok(ProjectedPrepareInputSetOciCaptureV1 {")
                .count(),
            1
        );
        assert!(!layout_trait.contains("OciImageLayout"));
        assert!(!layout_trait.contains("capture"));
    }

    #[test]
    fn single_subtree_projection_closes_exact_e3_inventory_without_inner_staging() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let prior = campaign.join("inputs");
        let outer_final = campaign.join("runs").join("run-001");

        let projection = project_single_subtree_campaign_layout(
            &campaign,
            [&prior],
            &outer_final,
            "reproduction",
        )
        .unwrap();

        assert_eq!(
            projection.required_outer_top_level_entries(),
            ["reproduction"]
        );
        assert_eq!(
            projection.required_outer_top_level_directories(),
            ["reproduction"]
        );
        assert_eq!(
            projection.staged_subtree_path(),
            projection.outer_staging_root().join("reproduction")
        );
        assert_eq!(
            projection.projected_subtree_path(),
            projection.outer_final_root().join("reproduction")
        );
        assert!(
            [
                projection.staged_subtree_path(),
                projection.projected_subtree_path(),
            ]
            .iter()
            .all(|path| !path.to_string_lossy().contains("terminal-evidence-packet"))
        );
    }

    #[test]
    fn single_subtree_projection_rejects_nonportable_or_conflicting_inputs() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let outer = campaign.join("runs").join("run-001");

        for component in ["", ".", "..", "nested/reproduction", "Reproduction", "con"] {
            assert!(
                project_single_subtree_campaign_layout(
                    &campaign,
                    [&campaign.join("inputs")],
                    &outer,
                    component,
                )
                .is_err(),
                "{component:?} unexpectedly passed"
            );
        }

        for prior in [outer.clone(), outer.join("nested"), campaign.join("runs")] {
            assert!(
                project_single_subtree_campaign_layout(
                    &campaign,
                    [&prior],
                    &outer,
                    "reproduction",
                )
                .is_err()
            );
        }
    }

    #[test]
    fn single_file_projection_accepts_canonical_postproof_sibling_and_closes_inventory() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let prior = campaign
            .join("reproduction")
            .join("schema")
            .join("b4-corpus-v1.candidate");
        let outer_final = campaign.join("reproduction").join("postproof");

        let projection = project_single_file_campaign_layout(
            &campaign,
            [&prior],
            &outer_final,
            "positive-generation-set-v2.json",
        )
        .unwrap();

        assert_eq!(
            projection.required_outer_top_level_entries(),
            ["positive-generation-set-v2.json"]
        );
        assert!(projection.required_outer_top_level_directories().is_empty());
        assert_eq!(
            projection.staged_file_path(),
            projection
                .outer_staging_root()
                .join("positive-generation-set-v2.json")
        );
        assert_eq!(
            projection.projected_file_path(),
            projection
                .outer_final_root()
                .join("positive-generation-set-v2.json")
        );
    }

    #[test]
    fn single_file_projection_rejects_old_ancestor_root_and_unsafe_names() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let prior = campaign
            .join("reproduction")
            .join("schema")
            .join("b4-corpus-v1.candidate");

        assert!(
            project_single_file_campaign_layout(
                &campaign,
                [&prior],
                &campaign.join("reproduction"),
                "positive-generation-set-v2.json",
            )
            .is_err(),
            "the old reproduction root must conflict with retained proof sources"
        );
        for component in [
            "",
            ".",
            "..",
            "postproof/positive-generation-set-v2.json",
            "Positive-Generation-Set-V2.json",
            "con",
        ] {
            assert!(
                project_single_file_campaign_layout(
                    &campaign,
                    [&prior],
                    &campaign.join("reproduction").join("postproof"),
                    component,
                )
                .is_err(),
                "{component:?} unexpectedly passed"
            );
        }
    }

    #[test]
    fn projection_accepts_an_absent_future_parent_without_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        fs::create_dir(&campaign).unwrap();
        let prior = campaign.join("inputs");
        fs::create_dir(&prior).unwrap();
        fs::write(prior.join("source.bin"), b"stable").unwrap();
        let before = fs::read_dir(&campaign)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        let outer_final = campaign.join("runs").join("run-001");

        let projection = project_outer_campaign_layout(
            &campaign,
            [&prior],
            &outer_final,
            [
                "terminal-evidence-campaign-receipt.json",
                "run-summary.json",
            ],
        )
        .unwrap();
        let after = fs::read_dir(&campaign)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();

        assert_eq!(before, after);
        assert!(!projection.outer_final_root().exists());
        assert!(!projection.outer_staging_root().exists());
        assert_eq!(
            projection
                .projected_inner_final_path()
                .strip_prefix(projection.outer_final_root())
                .unwrap(),
            Path::new("terminal-evidence-packet")
        );
    }

    #[test]
    fn projection_uses_component_ancestry_not_textual_prefixes() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let projection = project_outer_campaign_layout(
            &campaign,
            [&campaign.join("stage-evil")],
            &campaign.join("stage"),
            ["receipt.json"],
        )
        .unwrap();
        assert_eq!(projection.outer_final_root(), campaign.join("stage"));
    }

    #[test]
    fn projection_rejects_every_conflicting_leaf_or_root_relationship() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let outer = campaign.join("runs").join("run-001");

        for prior in [outer.clone(), outer.join("nested"), campaign.join("runs")] {
            let error =
                project_outer_campaign_layout(&campaign, [&prior], &outer, ["receipt.json"])
                    .unwrap_err();
            assert!(error.to_string().contains("conflict"));
        }

        let duplicate_leaf = project_outer_campaign_layout(
            &campaign,
            [&campaign.join("inputs")],
            &outer,
            ["receipt.json", "receipt.json"],
        )
        .unwrap_err();
        assert!(duplicate_leaf.to_string().contains("conflict"));
    }

    #[test]
    fn projection_rejects_noncanonical_or_escaping_components() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        for outer in [
            campaign.join("runs").join("..").join("escape"),
            campaign.join("runs").join("Run-001"),
            campaign.join("runs").join("con"),
            campaign.join("runs").join("trailing."),
        ] {
            assert!(
                project_outer_campaign_layout(
                    &campaign,
                    [&campaign.join("inputs")],
                    &outer,
                    ["receipt.json"],
                )
                .is_err()
            );
        }

        for leaf in [
            "",
            ".",
            "..",
            "nested/leaf",
            r"nested\leaf",
            "RÉSUMÉ.json",
            "con.json",
            "trailing.",
        ] {
            assert!(
                project_outer_campaign_layout(
                    &campaign,
                    [&campaign.join("inputs")],
                    &campaign.join("runs").join("run-001"),
                    [leaf],
                )
                .is_err(),
                "{leaf:?} unexpectedly passed"
            );
        }
    }
}
