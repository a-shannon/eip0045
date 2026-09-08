//! Affine descriptor-rooted publication kernel for future lifecycle handler H0.

use anyhow::{Result, ensure};
use eip_0045_reproduction::{
    b4_positive_gate::PositiveGateBindings,
    b4_positive_input_set::{
        B4_POSITIVE_INPUT_SET_COMPLETION_MAX_BYTES, B4_POSITIVE_INPUT_SET_MAX_BYTES,
        B4PositiveInputSetLayoutV1, B4PositiveInputSetLayoutV2,
        B4PositiveInputSetPublicationBindingV1, B4PositiveInputSetPublicationBindingV2,
        bind_b4_positive_input_set_publication, derive_b4_positive_input_set_completion_jcs,
        derive_b4_positive_input_set_completion_jcs_v2,
        validate_b4_positive_input_set_completion_jcs,
        validate_b4_positive_input_set_completion_jcs_v2,
    },
};

use super::{
    capability::MutationCapability,
    create_only::{self, CreateOnlyDirectoryTransaction},
    preflight::{ProjectedPrepareInputSetCampaignLayout, ProjectedPrepareInputSetCampaignLayoutV2},
};

/// Affine permit consumed only by the create-only module's H0 gateway.
///
/// The private field owns the exact exclusive mutation-capability borrow. A
/// sibling can name this type for the gateway signature, but cannot construct,
/// clone, or separate it from that borrow.
pub(super) struct PrepareInputSetCreateOnlyPermit<'capability, 'context, const ROOTS: usize> {
    capability: &'capability mut MutationCapability<
        'context,
        ROOTS,
        ProjectedPrepareInputSetCampaignLayout<ROOTS>,
    >,
}

impl<'capability, 'context, const ROOTS: usize>
    PrepareInputSetCreateOnlyPermit<'capability, 'context, ROOTS>
{
    pub(super) fn into_capability(
        self,
    ) -> &'capability mut MutationCapability<
        'context,
        ROOTS,
        ProjectedPrepareInputSetCampaignLayout<ROOTS>,
    > {
        self.capability
    }
}

/// Affine V2 permit consumed only by the create-only module's typed gateway.
///
/// Its exclusive borrow is parameterized by the distinct V2 layout, so neither
/// the V1 permit nor a generic create-only admission can enter the V2 kernel.
pub(super) struct PrepareInputSetCreateOnlyPermitV2<'capability, 'context, const ROOTS: usize> {
    capability: &'capability mut MutationCapability<
        'context,
        ROOTS,
        ProjectedPrepareInputSetCampaignLayoutV2<ROOTS>,
    >,
}

impl<'capability, 'context, const ROOTS: usize>
    PrepareInputSetCreateOnlyPermitV2<'capability, 'context, ROOTS>
{
    pub(super) fn into_capability(
        self,
    ) -> &'capability mut MutationCapability<
        'context,
        ROOTS,
        ProjectedPrepareInputSetCampaignLayoutV2<ROOTS>,
    > {
        self.capability
    }
}

/// Future production source minted only after descriptor-rooted reconstruction.
///
/// This boundary intentionally provides no constructor. The future physical
/// importer must rebuild the positive gate from retained immutable-root
/// descriptors, then move that gate into this non-clonable value. The layout
/// binding is deliberately absent: the consumer below derives it only while
/// borrowing the exact retained mutation capability. The permit owns that
/// exclusive borrow, so a source cannot later be paired with another execute
/// session.
struct AuthenticatedPrepareInputSetSourceV1<'capability, 'context, const ROOTS: usize> {
    permit: PrepareInputSetCreateOnlyPermit<'capability, 'context, ROOTS>,
    gate: PositiveGateBindings,
}

/// Future V2 source minted only by Task 19's authenticated live receive.
///
/// Task 3 deliberately supplies no constructor, decoder, conversion, derive,
/// or trait implementation. The exact V2 permit and inert document binding can
/// therefore enter the publication consumer only as this single affine value.
struct AuthenticatedPrepareInputSetSourceV2<'capability, 'context, const ROOTS: usize> {
    permit: PrepareInputSetCreateOnlyPermitV2<'capability, 'context, ROOTS>,
    binding: B4PositiveInputSetPublicationBindingV2,
}

/// Source cross-bound to the publication layout under the retained mutation
/// capability. This private value exists only for the ordered kernel lifetime.
struct BoundAuthenticatedPrepareInputSetSourceV1 {
    _gate: PositiveGateBindings,
    binding: B4PositiveInputSetPublicationBindingV1,
}

/// One source bound to the exact retained H0 layout and exclusive mutation
/// capability. Its fields are private so the permit cannot be detached from
/// the authenticated source before the ordered kernel consumes both.
struct PrepareInputSetPublicationGuard<'capability, 'context, const ROOTS: usize, Source> {
    permit: PrepareInputSetCreateOnlyPermit<'capability, 'context, ROOTS>,
    source: Source,
}

/// Private source contract consumed by the affine publication states.
///
/// It is intentionally private rather than `pub(super)`: no sibling handler
/// can inject a detached implementation. Tests below provide the only current
/// synthetic implementation; production has no mint until physical H0 import
/// lands.
trait PrepareInputSetPublicationSource {
    #[cfg(test)]
    fn input_set_path(&self) -> &str;
    #[cfg(test)]
    fn completion_path(&self) -> &str;
    fn input_set_jcs(&self) -> &[u8];
    fn completion_jcs(&self) -> Result<Vec<u8>>;
    fn validate_completion_jcs(&self, source: &[u8]) -> Result<()>;
}

impl PrepareInputSetPublicationSource for BoundAuthenticatedPrepareInputSetSourceV1 {
    #[cfg(test)]
    fn input_set_path(&self) -> &str {
        self.binding.input_set_path()
    }

    #[cfg(test)]
    fn completion_path(&self) -> &str {
        self.binding.completion_path()
    }

    fn input_set_jcs(&self) -> &[u8] {
        self.binding.input_set_jcs()
    }

    fn completion_jcs(&self) -> Result<Vec<u8>> {
        derive_b4_positive_input_set_completion_jcs(&self.binding)
    }

    fn validate_completion_jcs(&self, source: &[u8]) -> Result<()> {
        validate_b4_positive_input_set_completion_jcs(source, &self.binding)
    }
}

/// Synthetic-only binder used to exercise the physical kernel without
/// creating a production mint before descriptor-rooted import exists.
#[cfg(test)]
fn bind_prepare_input_set_publication_guard<'capability, 'context, const ROOTS: usize, Source>(
    capability: &'capability mut MutationCapability<
        'context,
        ROOTS,
        ProjectedPrepareInputSetCampaignLayout<ROOTS>,
    >,
    source: Source,
) -> Result<PrepareInputSetPublicationGuard<'capability, 'context, ROOTS, Source>>
where
    Source: PrepareInputSetPublicationSource,
{
    capability.recheck()?;
    let retained = capability.projected_layout().publication_paths();
    ensure!(
        source.input_set_path() == retained.input_set_path()
            && source.completion_path() == retained.completion_path(),
        "authenticated source differs from the retained H0 layout"
    );
    Ok(PrepareInputSetPublicationGuard {
        permit: PrepareInputSetCreateOnlyPermit { capability },
        source,
    })
}

#[must_use = "the H0 input set must be written before the completion marker"]
struct PrepareInputSetNeedInput<'capability, Source> {
    transaction: CreateOnlyDirectoryTransaction<'capability>,
    source: Source,
}

#[must_use = "the H0 completion marker must be written after the input set"]
struct PrepareInputSetNeedCompletion<'capability, Source> {
    transaction: CreateOnlyDirectoryTransaction<'capability>,
    source: Source,
}

#[must_use = "the complete H0 staging root must be committed and reopened"]
struct PrepareInputSetReadyToCommit<'capability, Source> {
    transaction: CreateOnlyDirectoryTransaction<'capability>,
    source: Source,
    completion_jcs: Vec<u8>,
}

/// Private postcommit result. It can be created only inside the descriptor-
/// rooted semantic reopen callback and is withheld if any final postcheck
/// fails.
struct PreparedInputSetPublicationV1<Source> {
    _source: Source,
}

fn begin_prepare_input_set_publication_kernel<'capability, const ROOTS: usize, Source>(
    guard: PrepareInputSetPublicationGuard<'capability, '_, ROOTS, Source>,
) -> Result<PrepareInputSetNeedInput<'capability, Source>>
where
    Source: PrepareInputSetPublicationSource,
{
    let PrepareInputSetPublicationGuard { permit, source } = guard;
    let transaction = create_only::begin_prepare_input_set_directory_transaction(permit)?;
    Ok(PrepareInputSetNeedInput {
        transaction,
        source,
    })
}

impl<'capability, Source> PrepareInputSetNeedInput<'capability, Source>
where
    Source: PrepareInputSetPublicationSource,
{
    fn write_input_set(mut self) -> Result<PrepareInputSetNeedCompletion<'capability, Source>> {
        let source = self.source.input_set_jcs();
        ensure!(
            !source.is_empty(),
            "authenticated positive input set is empty"
        );
        self.transaction.create_file(
            B4PositiveInputSetLayoutV1::closed_v1().input_set_file(),
            source,
            B4_POSITIVE_INPUT_SET_MAX_BYTES,
        )?;
        Ok(PrepareInputSetNeedCompletion {
            transaction: self.transaction,
            source: self.source,
        })
    }
}

impl<'capability, Source> PrepareInputSetNeedCompletion<'capability, Source>
where
    Source: PrepareInputSetPublicationSource,
{
    fn write_completion(mut self) -> Result<PrepareInputSetReadyToCommit<'capability, Source>> {
        let completion_jcs = self.source.completion_jcs()?;
        ensure!(
            !completion_jcs.is_empty(),
            "authenticated positive input-set completion is empty"
        );
        self.transaction.create_file(
            B4PositiveInputSetLayoutV1::closed_v1().completion_file(),
            &completion_jcs,
            B4_POSITIVE_INPUT_SET_COMPLETION_MAX_BYTES,
        )?;
        Ok(PrepareInputSetReadyToCommit {
            transaction: self.transaction,
            source: self.source,
            completion_jcs,
        })
    }
}

impl<Source> PrepareInputSetReadyToCommit<'_, Source>
where
    Source: PrepareInputSetPublicationSource,
{
    fn commit_and_reopen(self) -> Result<PreparedInputSetPublicationV1<Source>> {
        let layout = B4PositiveInputSetLayoutV1::closed_v1();
        let expected_input_set = self.source.input_set_jcs().to_vec();
        let expected_completion = self.completion_jcs;
        let source = self.source;
        self.transaction
            .commit_with_postcommit_validation(move |committed| {
                let reopened_input_set =
                    committed.read_file(layout.input_set_file(), expected_input_set.len())?;
                ensure!(
                    reopened_input_set == expected_input_set,
                    "reopened positive input set differs from its authenticated source"
                );
                let reopened_completion =
                    committed.read_file(layout.completion_file(), expected_completion.len())?;
                ensure!(
                    reopened_completion == expected_completion,
                    "reopened positive input-set completion differs from the staged witness"
                );
                source.validate_completion_jcs(&reopened_completion)?;
                Ok(PreparedInputSetPublicationV1 { _source: source })
            })
    }
}

/// Consume one physically authenticated H0 source under the exact retained
/// mutation capability and publish the closed two-file root.
///
/// This function intentionally remains private and its source has no
/// constructor. A later physical-import batch can therefore mint the source
/// only after rootfs identity and interpreter closure are complete, without
/// accepting a detached gate, layout binding, path, descriptor, or byte slice
/// at this publication boundary.
fn consume_authenticated_prepare_input_set_source<const ROOTS: usize>(
    source: AuthenticatedPrepareInputSetSourceV1<'_, '_, ROOTS>,
) -> Result<PreparedInputSetPublicationV1<BoundAuthenticatedPrepareInputSetSourceV1>> {
    let permit = source.permit;
    let gate = source.gate;
    permit.capability.recheck()?;
    let binding = bind_b4_positive_input_set_publication(
        permit.capability.projected_layout().publication_paths(),
        &gate,
    )?;
    let source = BoundAuthenticatedPrepareInputSetSourceV1 {
        _gate: gate,
        binding,
    };
    let guard = PrepareInputSetPublicationGuard { permit, source };
    begin_prepare_input_set_publication_kernel(guard)?
        .write_input_set()?
        .write_completion()?
        .commit_and_reopen()
}

#[must_use = "the H0 V2 input set must be written before the completion marker"]
struct PrepareInputSetV2NeedInput<'capability> {
    transaction: CreateOnlyDirectoryTransaction<'capability>,
    binding: B4PositiveInputSetPublicationBindingV2,
}

#[must_use = "the H0 V2 completion marker must be written after the input set"]
struct PrepareInputSetV2NeedCompletion<'capability> {
    transaction: CreateOnlyDirectoryTransaction<'capability>,
    binding: B4PositiveInputSetPublicationBindingV2,
}

#[must_use = "the complete H0 V2 staging root must be committed and reopened"]
struct PrepareInputSetV2ReadyToCommit<'capability> {
    transaction: CreateOnlyDirectoryTransaction<'capability>,
    binding: B4PositiveInputSetPublicationBindingV2,
    completion_jcs: Vec<u8>,
}

/// Private V2 postcommit result minted only after byte-exact descriptor reopen.
struct PreparedInputSetPublicationV2 {
    // Intentionally empty.
}

impl<'capability> PrepareInputSetV2NeedInput<'capability> {
    fn write_input_set(mut self) -> Result<PrepareInputSetV2NeedCompletion<'capability>> {
        let input_set_jcs = self.binding.input_set_jcs();
        ensure!(
            !input_set_jcs.is_empty(),
            "authenticated V2 positive input set is empty"
        );
        self.transaction.create_file(
            B4PositiveInputSetLayoutV2::closed_v2().input_set_file(),
            input_set_jcs,
            B4_POSITIVE_INPUT_SET_MAX_BYTES,
        )?;
        Ok(PrepareInputSetV2NeedCompletion {
            transaction: self.transaction,
            binding: self.binding,
        })
    }
}

impl<'capability> PrepareInputSetV2NeedCompletion<'capability> {
    fn write_completion(mut self) -> Result<PrepareInputSetV2ReadyToCommit<'capability>> {
        let completion_jcs = derive_b4_positive_input_set_completion_jcs_v2(&self.binding)?;
        ensure!(
            !completion_jcs.is_empty(),
            "authenticated V2 positive input-set completion is empty"
        );
        self.transaction.create_file(
            B4PositiveInputSetLayoutV2::closed_v2().completion_file(),
            &completion_jcs,
            B4_POSITIVE_INPUT_SET_COMPLETION_MAX_BYTES,
        )?;
        Ok(PrepareInputSetV2ReadyToCommit {
            transaction: self.transaction,
            binding: self.binding,
            completion_jcs,
        })
    }
}

impl PrepareInputSetV2ReadyToCommit<'_> {
    fn commit_and_reopen(self) -> Result<PreparedInputSetPublicationV2> {
        let layout = B4PositiveInputSetLayoutV2::closed_v2();
        let expected_input_set = self.binding.input_set_jcs().to_vec();
        let expected_completion = self.completion_jcs;
        let binding = self.binding;
        self.transaction
            .commit_with_postcommit_validation(move |committed| {
                let reopened_input_set =
                    committed.read_file(layout.input_set_file(), expected_input_set.len())?;
                ensure!(
                    reopened_input_set == expected_input_set,
                    "reopened V2 positive input set differs from its authenticated source"
                );
                let reopened_completion =
                    committed.read_file(layout.completion_file(), expected_completion.len())?;
                ensure!(
                    reopened_completion == expected_completion,
                    "reopened V2 positive input-set completion differs from the staged witness"
                );
                let rederived_completion =
                    derive_b4_positive_input_set_completion_jcs_v2(&binding)?;
                ensure!(
                    reopened_completion == rederived_completion,
                    "reopened V2 positive input-set completion differs from independent derivation"
                );
                validate_b4_positive_input_set_completion_jcs_v2(&reopened_completion, &binding)?;
                Ok(PreparedInputSetPublicationV2 {})
            })
    }
}

/// Consume exactly one authenticated V2 source and publish its closed envelope.
///
/// No detached permit, layout, bytes, or binding can enter this boundary. The
/// source remains deliberately uninhabited until Task 19 adds its sole live
/// receive transition in this module.
fn consume_authenticated_prepare_input_set_source_v2<const ROOTS: usize>(
    source: AuthenticatedPrepareInputSetSourceV2<'_, '_, ROOTS>,
) -> Result<PreparedInputSetPublicationV2> {
    let permit = source.permit;
    let binding = source.binding;
    permit.capability.recheck()?;
    let retained = permit.capability.projected_layout().publication_paths();
    ensure!(
        binding.input_set_path() == retained.input_set_path()
            && binding.completion_path() == retained.completion_path(),
        "authenticated V2 source differs from the retained H0 V2 layout"
    );
    let transaction = create_only::begin_prepare_input_set_directory_transaction_v2(permit)?;
    PrepareInputSetV2NeedInput {
        transaction,
        binding,
    }
    .write_input_set()?
    .write_completion()?
    .commit_and_reopen()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{fs, path::PathBuf};

    use anyhow::{Result, bail, ensure};

    use super::{
        AuthenticatedPrepareInputSetSourceV2, PrepareInputSetCreateOnlyPermitV2,
        PrepareInputSetPublicationSource, PrepareInputSetV2NeedInput,
        PreparedInputSetPublicationV2, begin_prepare_input_set_publication_kernel,
        bind_prepare_input_set_publication_guard,
        consume_authenticated_prepare_input_set_source_v2,
    };
    use crate::b4_campaign_executor::{
        capability::MutationCapability,
        create_only,
        preflight::{
            ProjectedPrepareInputSetCampaignLayoutV2, project_prepare_input_set_campaign_layout,
            project_prepare_input_set_campaign_layout_v2,
        },
        typestate::ExecutorPreflightContext,
    };
    use eip_0045_reproduction::b4_positive_input_set::{
        B4PositiveInputSetPublicationBindingV2, bind_b4_positive_input_set_publication_v2,
        derive_b4_positive_input_set_completion_jcs_v2,
        project_b4_positive_input_set_publication_paths_v2,
    };

    struct TestPublicationSource {
        input_set_path: String,
        completion_path: String,
        input_set_jcs: Vec<u8>,
        completion_jcs: Vec<u8>,
        fail_completion_derivation: bool,
        mutate_after_reopen: Option<PathBuf>,
    }

    impl TestPublicationSource {
        fn valid(input_set_path: &str, completion_path: &str) -> Self {
            Self {
                input_set_path: input_set_path.to_owned(),
                completion_path: completion_path.to_owned(),
                input_set_jcs: br#"{"format":"test-positive-input-set"}"#.to_vec(),
                completion_jcs: br#"{"format":"test-positive-input-set-completion"}"#.to_vec(),
                fail_completion_derivation: false,
                mutate_after_reopen: None,
            }
        }
    }

    impl PrepareInputSetPublicationSource for TestPublicationSource {
        #[cfg(test)]
        fn input_set_path(&self) -> &str {
            &self.input_set_path
        }

        #[cfg(test)]
        fn completion_path(&self) -> &str {
            &self.completion_path
        }

        fn input_set_jcs(&self) -> &[u8] {
            &self.input_set_jcs
        }

        fn completion_jcs(&self) -> Result<Vec<u8>> {
            if self.fail_completion_derivation {
                bail!("injected completion derivation failure")
            }
            Ok(self.completion_jcs.clone())
        }

        fn validate_completion_jcs(&self, source: &[u8]) -> Result<()> {
            ensure!(
                source == self.completion_jcs,
                "reopened completion differs from the test source"
            );
            if let Some(path) = &self.mutate_after_reopen {
                fs::write(path, b"postcommit mutation")?;
            }
            Ok(())
        }
    }

    fn captured_kernel(
        phase_name: &str,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        PathBuf,
        String,
        String,
        ExecutorPreflightContext<
            1,
            crate::b4_campaign_executor::preflight::ProjectedPrepareInputSetCampaignLayout<1>,
        >,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let prior = campaign.join("authoritative-inputs");
        let outer_final = campaign.join("phases").join(phase_name);
        fs::create_dir_all(&prior).unwrap();
        fs::create_dir_all(outer_final.parent().unwrap()).unwrap();
        fs::write(prior.join("source.bin"), b"stable").unwrap();
        let layout =
            project_prepare_input_set_campaign_layout(&campaign, [&prior], &outer_final).unwrap();
        let staging = layout.outer_staging_root().to_path_buf();
        let input_path = layout.input_set_campaign_relative_path().to_owned();
        let completion_path = layout.completion_campaign_relative_path().to_owned();
        let executable = fs::read_link("/proc/self/exe").unwrap();
        let preflight = ExecutorPreflightContext::capture(&executable, layout).unwrap();
        (
            temp,
            campaign,
            outer_final,
            staging,
            input_path,
            completion_path,
            preflight,
        )
    }

    type V2Preflight = ExecutorPreflightContext<1, ProjectedPrepareInputSetCampaignLayoutV2<1>>;

    fn captured_kernel_v2(
        phase_name: &str,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        PathBuf,
        Vec<u8>,
        B4PositiveInputSetPublicationBindingV2,
        V2Preflight,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let prior = campaign.join("authoritative-inputs");
        let outer_final = campaign.join("phases").join(phase_name);
        fs::create_dir_all(&prior).unwrap();
        fs::create_dir_all(outer_final.parent().unwrap()).unwrap();
        fs::write(prior.join("source.bin"), b"stable").unwrap();
        let layout =
            project_prepare_input_set_campaign_layout_v2(&campaign, [&prior], &outer_final)
                .unwrap();
        let staging = layout.outer_staging_root().to_path_buf();
        let input_set_jcs =
            br#"{"format":"Eip0045B4PositiveInputSetV2","formatVersion":2}"#.to_vec();
        let binding =
            bind_b4_positive_input_set_publication_v2(layout.publication_paths(), &input_set_jcs)
                .unwrap();
        let executable = fs::read_link("/proc/self/exe").unwrap();
        let preflight = ExecutorPreflightContext::capture(&executable, layout).unwrap();
        (
            temp,
            campaign,
            outer_final,
            staging,
            input_set_jcs,
            binding,
            preflight,
        )
    }

    fn begin_v2_test_kernel<'capability, 'context>(
        capability: &'capability mut MutationCapability<
            'context,
            1,
            ProjectedPrepareInputSetCampaignLayoutV2<1>,
        >,
        binding: B4PositiveInputSetPublicationBindingV2,
    ) -> Result<PrepareInputSetV2NeedInput<'capability>> {
        capability.recheck()?;
        let permit = PrepareInputSetCreateOnlyPermitV2 { capability };
        let transaction = create_only::begin_prepare_input_set_directory_transaction_v2(permit)?;
        Ok(PrepareInputSetV2NeedInput {
            transaction,
            binding,
        })
    }

    #[test]
    fn h0_kernel_writes_input_then_completion_and_reopens_exactly() {
        let (_temp, _campaign, outer_final, staging, input_path, completion_path, preflight) =
            captured_kernel("prepare-001");
        let source = TestPublicationSource::valid(&input_path, &completion_path);

        preflight
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    let guard = bind_prepare_input_set_publication_guard(capability, source)?;
                    begin_prepare_input_set_publication_kernel(guard)?
                        .write_input_set()?
                        .write_completion()?
                        .commit_and_reopen()
                        .map(|_prepared| ())
                })
            })
            .unwrap();

        assert_eq!(
            fs::read(outer_final.join("positive-input-set.json")).unwrap(),
            br#"{"format":"test-positive-input-set"}"#
        );
        assert_eq!(
            fs::read(outer_final.join("positive-input-set-completion.json")).unwrap(),
            br#"{"format":"test-positive-input-set-completion"}"#
        );
        assert!(!staging.exists());
        let mut entries = fs::read_dir(&outer_final)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        entries.sort();
        assert_eq!(
            entries,
            [
                std::ffi::OsString::from("positive-input-set-completion.json"),
                std::ffi::OsString::from("positive-input-set.json"),
            ]
        );
    }

    #[test]
    fn prepare_input_set_v2_writes_input_then_completion_and_reopens_exactly() {
        let (_temp, _campaign, outer_final, staging, input_set_jcs, binding, preflight) =
            captured_kernel_v2("prepare-v2");
        let completion_jcs = derive_b4_positive_input_set_completion_jcs_v2(&binding).unwrap();

        preflight
            .execute(move |execute| {
                execute.with_mutation(move |capability| {
                    let source = AuthenticatedPrepareInputSetSourceV2 {
                        permit: PrepareInputSetCreateOnlyPermitV2 { capability },
                        binding,
                    };
                    let prepared: PreparedInputSetPublicationV2 =
                        consume_authenticated_prepare_input_set_source_v2(source)?;
                    std::hint::black_box(prepared);
                    Ok(())
                })
            })
            .unwrap();

        assert_eq!(
            fs::read(outer_final.join("positive-input-set.json")).unwrap(),
            input_set_jcs
        );
        assert_eq!(
            fs::read(outer_final.join("positive-input-set-completion.json")).unwrap(),
            completion_jcs
        );
        assert!(!staging.exists());
        let mut entries = fs::read_dir(&outer_final)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        entries.sort();
        assert_eq!(
            entries,
            [
                std::ffi::OsString::from("positive-input-set-completion.json"),
                std::ffi::OsString::from("positive-input-set.json"),
            ]
        );
    }

    #[test]
    fn prepare_input_set_v2_rejects_detached_layout_before_staging() {
        let (_temp, _campaign, outer_final, staging, input_set_jcs, _binding, preflight) =
            captured_kernel_v2("prepare-v2-a");
        let detached_paths =
            project_b4_positive_input_set_publication_paths_v2("phases/prepare-v2-b").unwrap();
        let detached_binding =
            bind_b4_positive_input_set_publication_v2(&detached_paths, &input_set_jcs).unwrap();

        let error = preflight
            .execute(move |execute| {
                execute.with_mutation(move |capability| {
                    let source = AuthenticatedPrepareInputSetSourceV2 {
                        permit: PrepareInputSetCreateOnlyPermitV2 { capability },
                        binding: detached_binding,
                    };
                    consume_authenticated_prepare_input_set_source_v2(source).map(|_| ())
                })
            })
            .unwrap_err();

        assert!(
            format!("{error:#}")
                .contains("authenticated V2 source differs from the retained H0 V2 layout")
        );
        assert!(!staging.exists());
        assert!(!outer_final.exists());
    }

    #[test]
    fn prepare_input_set_v2_never_replaces_a_racing_final_destination() {
        let (_temp, _campaign, outer_final, staging, _input_set_jcs, binding, preflight) =
            captured_kernel_v2("prepare-v2-race");
        let adverse = outer_final.join("adverse.txt");
        let outer_final_for_effect = outer_final.clone();
        let adverse_for_effect = adverse.clone();

        let error = preflight
            .execute(move |execute| {
                execute.with_mutation(move |capability| {
                    let ready = begin_v2_test_kernel(capability, binding)?
                        .write_input_set()?
                        .write_completion()?;
                    fs::create_dir(&outer_final_for_effect)?;
                    fs::write(&adverse_for_effect, b"adverse winner")?;
                    ready.commit_and_reopen().map(|_| ())
                })
            })
            .unwrap_err();

        assert!(format!("{error:#}").contains("occupied"));
        assert_eq!(fs::read(adverse).unwrap(), b"adverse winner");
        assert!(staging.exists());
    }

    #[test]
    fn prepare_input_set_v2_rejects_each_staged_file_mutation_before_commit() {
        for (index, leaf) in [
            "positive-input-set.json",
            "positive-input-set-completion.json",
        ]
        .into_iter()
        .enumerate()
        {
            let phase = format!("prepare-v2-mutation-{index}");
            let (_temp, _campaign, outer_final, staging, _input_set_jcs, binding, preflight) =
                captured_kernel_v2(&phase);
            let mutation_path = staging.join(leaf);
            let leaf = leaf.to_owned();

            let error = preflight
                .execute(move |execute| {
                    execute.with_mutation(move |capability| {
                        let ready = begin_v2_test_kernel(capability, binding)?
                            .write_input_set()?
                            .write_completion()?;
                        let original = fs::read(&mutation_path)?;
                        let replacement = vec![b'x'; original.len()];
                        ensure!(
                            replacement != original,
                            "mutation fixture did not change bytes"
                        );
                        fs::write(&mutation_path, replacement)?;
                        ready.commit_and_reopen().map(|_| ())
                    })
                })
                .unwrap_err();

            let rendered = format!("{error:#}");
            assert!(
                rendered.contains("retained file")
                    && rendered.contains("changed")
                    && rendered.contains(&leaf),
                "unexpected mutation discriminator for {leaf}: {rendered}"
            );
            assert!(!outer_final.exists());
            assert!(staging.exists());
        }
    }

    #[test]
    fn prepare_input_set_v2_abandonment_after_input_has_no_completion_or_publication() {
        let (_temp, _campaign, outer_final, staging, _input_set_jcs, binding, preflight) =
            captured_kernel_v2("prepare-v2-abandon");

        preflight
            .execute(move |execute| {
                execute.with_mutation(move |capability| {
                    let _need_completion =
                        begin_v2_test_kernel(capability, binding)?.write_input_set()?;
                    Ok(())
                })
            })
            .unwrap();

        assert!(staging.join("positive-input-set.json").exists());
        assert!(!staging.join("positive-input-set-completion.json").exists());
        assert!(!outer_final.exists());
    }

    #[test]
    fn h0_kernel_rejects_a_detached_layout_before_staging() {
        let (_temp, _campaign, outer_final, staging, _input_path, _completion_path, preflight) =
            captured_kernel("prepare-a");
        let source = TestPublicationSource::valid(
            "phases/prepare-b/positive-input-set.json",
            "phases/prepare-b/positive-input-set-completion.json",
        );

        let error = preflight
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    let guard = bind_prepare_input_set_publication_guard(capability, source)?;
                    begin_prepare_input_set_publication_kernel(guard).map(|_| ())
                })
            })
            .unwrap_err();

        assert!(format!("{error:#}").contains("retained H0 layout"));
        assert!(!staging.exists());
        assert!(!outer_final.exists());
    }

    #[test]
    fn h0_kernel_failure_after_input_never_writes_the_completion() {
        let (_temp, _campaign, outer_final, staging, input_path, completion_path, preflight) =
            captured_kernel("prepare-001");
        let mut source = TestPublicationSource::valid(&input_path, &completion_path);
        source.fail_completion_derivation = true;

        let error = preflight
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    let guard = bind_prepare_input_set_publication_guard(capability, source)?;
                    begin_prepare_input_set_publication_kernel(guard)?
                        .write_input_set()?
                        .write_completion()
                        .map(|_| ())
                })
            })
            .unwrap_err();

        assert!(format!("{error:#}").contains("injected completion derivation failure"));
        assert!(!outer_final.exists());
        assert_eq!(
            fs::read(staging.join("positive-input-set.json")).unwrap(),
            br#"{"format":"test-positive-input-set"}"#
        );
        assert!(!staging.join("positive-input-set-completion.json").exists());
    }

    #[test]
    fn h0_kernel_rejects_input_above_its_compiled_role_ceiling() {
        let (_temp, _campaign, outer_final, staging, input_path, completion_path, preflight) =
            captured_kernel("prepare-001");
        let mut source = TestPublicationSource::valid(&input_path, &completion_path);
        source.input_set_jcs = vec![
            b'x';
            eip_0045_reproduction::b4_positive_input_set::B4_POSITIVE_INPUT_SET_MAX_BYTES
                + 1
        ];

        let error = preflight
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    let guard = bind_prepare_input_set_publication_guard(capability, source)?;
                    begin_prepare_input_set_publication_kernel(guard)?
                        .write_input_set()
                        .map(|_| ())
                })
            })
            .unwrap_err();

        assert!(format!("{error:#}").contains("byte bound"));
        assert!(!outer_final.exists());
        assert!(!staging.join("positive-input-set.json").exists());
        assert!(!staging.join("positive-input-set-completion.json").exists());
    }

    #[test]
    fn h0_kernel_rejects_completion_above_its_compiled_role_ceiling() {
        let (_temp, _campaign, outer_final, staging, input_path, completion_path, preflight) =
            captured_kernel("prepare-001");
        let mut source = TestPublicationSource::valid(&input_path, &completion_path);
        source.completion_jcs = vec![
            b'x';
            eip_0045_reproduction::b4_positive_input_set::B4_POSITIVE_INPUT_SET_COMPLETION_MAX_BYTES
                + 1
        ];

        let error = preflight
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    let guard = bind_prepare_input_set_publication_guard(capability, source)?;
                    begin_prepare_input_set_publication_kernel(guard)?
                        .write_input_set()?
                        .write_completion()
                        .map(|_| ())
                })
            })
            .unwrap_err();

        assert!(format!("{error:#}").contains("byte bound"));
        assert!(!outer_final.exists());
        assert!(staging.join("positive-input-set.json").exists());
        assert!(!staging.join("positive-input-set-completion.json").exists());
    }

    #[test]
    fn h0_kernel_never_replaces_a_racing_final_destination() {
        let (_temp, _campaign, outer_final, staging, input_path, completion_path, preflight) =
            captured_kernel("prepare-001");
        let source = TestPublicationSource::valid(&input_path, &completion_path);
        let adverse = outer_final.join("adverse.txt");

        let error = preflight
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    let guard = bind_prepare_input_set_publication_guard(capability, source)?;
                    let ready = begin_prepare_input_set_publication_kernel(guard)?
                        .write_input_set()?
                        .write_completion()?;
                    fs::create_dir(&outer_final)?;
                    fs::write(&adverse, b"adverse winner")?;
                    ready.commit_and_reopen().map(|_| ())
                })
            })
            .unwrap_err();

        assert!(format!("{error:#}").contains("occupied"));
        assert_eq!(fs::read(adverse).unwrap(), b"adverse winner");
        assert!(staging.exists());
    }

    #[test]
    fn h0_kernel_suppresses_authority_after_postcommit_mutation() {
        let (_temp, _campaign, outer_final, _staging, input_path, completion_path, preflight) =
            captured_kernel("prepare-001");
        let mut source = TestPublicationSource::valid(&input_path, &completion_path);
        source.mutate_after_reopen = Some(outer_final.join("positive-input-set.json"));

        let error = preflight
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    let guard = bind_prepare_input_set_publication_guard(capability, source)?;
                    begin_prepare_input_set_publication_kernel(guard)?
                        .write_input_set()?
                        .write_completion()?
                        .commit_and_reopen()
                        .map(|_prepared| ())
                })
            })
            .unwrap_err();

        assert!(outer_final.exists());
        assert!(
            format!("{error:#}").contains("postcheck") || format!("{error:#}").contains("changed")
        );
    }
}

#[cfg(test)]
mod contract_tests {
    use super::{
        AuthenticatedPrepareInputSetSourceV1, AuthenticatedPrepareInputSetSourceV2,
        BoundAuthenticatedPrepareInputSetSourceV1, PreparedInputSetPublicationV1,
        PreparedInputSetPublicationV2, consume_authenticated_prepare_input_set_source,
        consume_authenticated_prepare_input_set_source_v2,
    };

    fn standalone_sequence_count(source: &str, sequence: &str) -> usize {
        source
            .match_indices(sequence)
            .filter(|(start, _)| {
                *start == 0
                    || (!source.as_bytes()[*start - 1].is_ascii_alphanumeric()
                        && source.as_bytes()[*start - 1] != b'_')
            })
            .count()
    }

    #[test]
    fn authenticated_source_has_one_descriptor_rooted_publication_consumer() {
        let source = include_str!("prepare_input_set.rs").replace("\r\n", "\n");
        let production = source
            .split("#[cfg(all(test, target_os = \"linux\"))]\nmod tests")
            .next()
            .expect("production source must precede its tests");

        let source_shape = production
            .split_once("struct AuthenticatedPrepareInputSetSourceV1")
            .expect("authenticated H0 source type must exist")
            .1
            .split_once("/// Source cross-bound")
            .expect("authenticated H0 source type must remain bounded")
            .0;
        assert!(source_shape.contains("permit: PrepareInputSetCreateOnlyPermit"));
        assert!(source_shape.contains("gate: PositiveGateBindings"));
        assert!(
            !source_shape.contains("B4PositiveInputSetPublicationBindingV1"),
            "the authenticated source must not retain a detached publication binding"
        );
        assert_eq!(
            production
                .matches("struct AuthenticatedPrepareInputSetSourceV1<")
                .count(),
            1,
            "the authenticated H0 source must have one affine definition"
        );
        assert_eq!(
            standalone_sequence_count(production, "AuthenticatedPrepareInputSetSourceV1 {"),
            0,
            "the authenticated H0 source must have no production constructor"
        );
        assert!(!production.contains("impl AuthenticatedPrepareInputSetSourceV1"));
        assert_eq!(
            production
                .matches("fn consume_authenticated_prepare_input_set_source<const")
                .count(),
            1,
            "the authenticated H0 source must have one publication consumer"
        );

        let consumer = production
            .split_once("fn consume_authenticated_prepare_input_set_source<const")
            .expect("authenticated H0 source has no production publication consumer")
            .1;
        let (signature, body) = consumer
            .split_once('{')
            .expect("authenticated H0 consumer must have a function body");
        assert!(signature.contains("source: AuthenticatedPrepareInputSetSourceV1"));
        assert!(!signature.contains("capability:"));
        assert!(!signature.contains("MutationCapability"));
        assert!(signature.contains(
            "Result<PreparedInputSetPublicationV1<BoundAuthenticatedPrepareInputSetSourceV1>>"
        ));
        for detached_input in [
            "B4PositiveInputSetPublicationBindingV1",
            "B4PositiveInputSetPublicationPathsV1",
            "PositiveGateBindings",
            "&[u8]",
            "RawFd",
            "File",
        ] {
            assert!(
                !signature.contains(detached_input),
                "authenticated H0 consumer accepts detached input {detached_input}"
            );
        }
        assert!(body.contains("permit.capability.recheck()?"));
        assert!(body.contains("permit.capability.projected_layout().publication_paths()"));
        assert!(body.contains("bind_b4_positive_input_set_publication("));
        assert!(body.contains("_gate: gate"));
        assert!(body.contains("begin_prepare_input_set_publication_kernel(guard)?"));
        assert!(body.contains(".write_input_set()?"));
        assert!(body.contains(".write_completion()?"));
        assert!(body.contains(".commit_and_reopen()"));
        assert!(
            !production.contains("fn execute_prepare_input_set_handler"),
            "the incomplete H0 batch must not mint command authority"
        );
    }

    #[test]
    fn authenticated_source_consumer_signature_carries_one_session() {
        fn accepts(
            _consumer: for<'capability, 'context> fn(
                AuthenticatedPrepareInputSetSourceV1<'capability, 'context, 1>,
            ) -> anyhow::Result<
                PreparedInputSetPublicationV1<BoundAuthenticatedPrepareInputSetSourceV1>,
            >,
        ) {
        }

        accepts(consume_authenticated_prepare_input_set_source::<1>);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the source-shape audit keeps every forbidden construction and lifetime edge in one review unit"
    )]
    fn prepare_input_set_v2_source_is_uninhabited_nonserializable_and_singly_consumed() {
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

        trait AmbiguousIfDefault<Marker> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfDefault<()> for T {}
        impl<T: Default> AmbiguousIfDefault<u8> for T {}

        trait AmbiguousIfSerialize<Marker> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfSerialize<()> for T {}
        impl<T: serde::Serialize> AmbiguousIfSerialize<u8> for T {}

        trait AmbiguousIfDeserializeOwned<Marker> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfDeserializeOwned<()> for T {}
        impl<T: serde::de::DeserializeOwned> AmbiguousIfDeserializeOwned<u8> for T {}

        type Source = AuthenticatedPrepareInputSetSourceV2<'static, 'static, 1>;
        <Source as AmbiguousIfClone<_>>::marker();
        <Source as AmbiguousIfCopy<_>>::marker();
        <Source as AmbiguousIfDefault<_>>::marker();
        <Source as AmbiguousIfSerialize<_>>::marker();
        <Source as AmbiguousIfDeserializeOwned<_>>::marker();

        let source = include_str!("prepare_input_set.rs").replace("\r\n", "\n");
        let production = source
            .split("#[cfg(all(test, target_os = \"linux\"))]\nmod tests")
            .next()
            .expect("production source must precede its tests");
        let (before_source, after_source) = production
            .split_once("struct AuthenticatedPrepareInputSetSourceV2")
            .expect("authenticated V2 source type must exist");
        let source_shape = after_source
            .split_once("\n}")
            .expect("authenticated V2 source type must have a closed body")
            .0;
        let source_prefix = before_source
            .lines()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(source_shape.contains("permit: PrepareInputSetCreateOnlyPermitV2"));
        assert!(source_shape.contains("binding: B4PositiveInputSetPublicationBindingV2"));
        assert!(!source_prefix.contains("#[derive"));
        assert_eq!(
            production
                .matches("struct AuthenticatedPrepareInputSetSourceV2<")
                .count(),
            1,
            "the authenticated V2 source must have one affine definition"
        );
        assert_eq!(
            production
                .matches("AuthenticatedPrepareInputSetSourceV2")
                .count(),
            2,
            "the authenticated V2 source must appear only in its definition and concrete consumer"
        );
        assert_eq!(
            standalone_sequence_count(production, "AuthenticatedPrepareInputSetSourceV2 {"),
            0,
            "the authenticated V2 source must have no production constructor or literal"
        );
        for forbidden in [
            "pub struct AuthenticatedPrepareInputSetSourceV2",
            "pub(super) struct AuthenticatedPrepareInputSetSourceV2",
            "pub(crate) struct AuthenticatedPrepareInputSetSourceV2",
            "impl AuthenticatedPrepareInputSetSourceV2",
            "impl Clone for AuthenticatedPrepareInputSetSourceV2",
            "impl Copy for AuthenticatedPrepareInputSetSourceV2",
            "impl Default for AuthenticatedPrepareInputSetSourceV2",
            "impl serde::Serialize for AuthenticatedPrepareInputSetSourceV2",
            "impl serde::Deserialize",
            "impl From<",
            "impl TryFrom<",
            "impl PrepareInputSetPublicationSource for AuthenticatedPrepareInputSetSourceV2",
            "trait PrepareInputSetPublicationSourceV2",
            "pub(super) use AuthenticatedPrepareInputSetSourceV2",
            "pub(crate) use AuthenticatedPrepareInputSetSourceV2",
        ] {
            assert!(
                !production.contains(forbidden),
                "authenticated V2 source exposes forbidden surface {forbidden}"
            );
        }

        assert_eq!(
            production
                .matches("fn consume_authenticated_prepare_input_set_source_v2")
                .count(),
            1,
            "the authenticated V2 source must have one concrete consumer"
        );
        let consumer = production
            .split_once("fn consume_authenticated_prepare_input_set_source_v2")
            .expect("authenticated V2 source has no production consumer")
            .1;
        let (signature, body) = consumer
            .split_once('{')
            .expect("authenticated V2 consumer must have a function body");
        assert!(signature.contains("source: AuthenticatedPrepareInputSetSourceV2"));
        assert!(signature.contains("Result<PreparedInputSetPublicationV2>"));
        assert!(!signature.contains("PreparedInputSetPublicationV2<"));
        for detached_input in [
            "MutationCapability",
            "PrepareInputSetCreateOnlyPermitV2",
            "B4PositiveInputSetPublicationBindingV2",
            "B4PositiveInputSetPublicationPathsV2",
            "&[u8]",
            "RawFd",
            "File",
        ] {
            assert!(
                !signature.contains(detached_input),
                "authenticated V2 consumer accepts detached input {detached_input}"
            );
        }
        let write_input = body
            .find(".write_input_set()?")
            .expect("V2 consumer must write the input set");
        let write_completion = body
            .find(".write_completion()?")
            .expect("V2 consumer must write the completion after the input set");
        let commit = body
            .find(".commit_and_reopen()")
            .expect("V2 consumer must commit and reopen after both writes");
        assert!(write_input < write_completion && write_completion < commit);
        assert_eq!(body.matches(".write_input_set()?").count(), 1);
        assert_eq!(body.matches(".write_completion()?").count(), 1);
        assert_eq!(body.matches(".commit_and_reopen()").count(), 1);

        let prepared_shape = production
            .split_once("struct PreparedInputSetPublicationV2")
            .expect("V2 postcommit type must exist")
            .1
            .split_once("\n}")
            .expect("V2 postcommit type must have a closed body")
            .0
            .to_ascii_lowercase();
        for retained in [
            "source",
            "permit",
            "descriptor",
            "path",
            "session",
            "binding",
            "capability",
        ] {
            assert!(
                !prepared_shape.contains(retained),
                "V2 postcommit value retains forbidden authority {retained}"
            );
        }
    }

    #[test]
    fn prepare_input_set_v2_consumer_signature_is_concrete_and_non_generic() {
        fn accepts(
            _consumer: for<'capability, 'context> fn(
                AuthenticatedPrepareInputSetSourceV2<'capability, 'context, 1>,
            ) -> anyhow::Result<
                PreparedInputSetPublicationV2,
            >,
        ) {
        }

        accepts(consume_authenticated_prepare_input_set_source_v2::<1>);
    }
}
