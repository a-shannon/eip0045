//! Private retained-executable and direct-child custody for the H0 supervisor.

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const fn retained_executable_length_is_bounded_v2(byte_length: u64) -> bool {
    byte_length >= eip0045_h0_contract::executable::RETAINED_STATIC_AMD64_ELF_MIN_BYTES_V2
        && byte_length <= eip0045_h0_contract::executable::RETAINED_STATIC_AMD64_ELF_MAX_BYTES_V2
}

#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
mod selected_target {
    #![allow(
        dead_code,
        reason = "E4a custody remains unreachable until the same-crate G0 session join is added"
    )]

    use std::{
        ffi::CStr,
        os::fd::{AsFd as _, BorrowedFd, OwnedFd},
    };

    use eip0045_h0_contract::executable::{
        GeneratorExecutableExpectationV2, WorkerExecutableExpectationV2,
        inspect_retained_static_amd64_elf_v2,
    };
    use rustix::{
        fs::{OFlags, fcntl_getfl, flistxattr, fstat, major, minor},
        io::{FdFlags, fcntl_getfd, pread},
    };

    use crate::{
        SupervisorReceiveProjectionV1, WorkerBootstrapProjectionV1,
        ancillary::{
            GeneratorEndpointV1, SupervisorGeneratorSendOpV1, SupervisorGeneratorSentEndpointV1,
            SupervisorWorkerBootstrapSendOpV1, WorkerBootstrapEnqueuedEndpointV1, WorkerEndpointV1,
        },
        process::{
            BlockedWorkerV1, CheckedWorkerMapsV1, ExitObservationV1, GeneratorSpawnPlanV1,
            PostReleaseWorkerV1, ProcfsAuthorityV1, RetainedChildProcessV1, WorkerSpawnPlanV1,
            spawn_generator_once_v1, spawn_worker_once_v1,
        },
        statx::{
            DescriptorExpectationV1, DescriptorObservationErrorV1, DescriptorSubjectV1,
            observe_exact_descriptor_v1,
        },
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum ExecutableCustodyErrorV2 {
        DescriptorStatus,
        DescriptorFlags,
        DescriptorMetadata,
        DescriptorIdentity,
        DescriptorLength,
        DescriptorRead,
        DescriptorDigestOrPolicy,
        Process(crate::process::ProcessContractErrorV1),
    }

    impl From<crate::process::ProcessContractErrorV1> for ExecutableCustodyErrorV2 {
        fn from(error: crate::process::ProcessContractErrorV1) -> Self {
            Self::Process(error)
        }
    }

    impl From<DescriptorObservationErrorV1> for ExecutableCustodyErrorV2 {
        fn from(_: DescriptorObservationErrorV1) -> Self {
            Self::DescriptorIdentity
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct RetainedExecutableMetadataV2 {
        device: u64,
        inode: u64,
        byte_length: u64,
        hard_link_count: u64,
        mode: u32,
        modified_seconds: i64,
        modified_nanoseconds: u64,
        changed_seconds: i64,
        changed_nanoseconds: u64,
    }

    impl RetainedExecutableMetadataV2 {
        fn observe(descriptor: BorrowedFd<'_>) -> Result<Self, ExecutableCustodyErrorV2> {
            let metadata =
                fstat(descriptor).map_err(|_| ExecutableCustodyErrorV2::DescriptorMetadata)?;
            let byte_length = u64::try_from(metadata.st_size)
                .map_err(|_| ExecutableCustodyErrorV2::DescriptorLength)?;
            Ok(Self {
                device: metadata.st_dev,
                inode: metadata.st_ino,
                byte_length,
                hard_link_count: metadata.st_nlink,
                mode: metadata.st_mode,
                modified_seconds: metadata.st_mtime,
                modified_nanoseconds: metadata.st_mtime_nsec,
                changed_seconds: metadata.st_ctime,
                changed_nanoseconds: metadata.st_ctime_nsec,
            })
        }
    }

    struct RetainedExecutableCoreV2 {
        descriptor: OwnedFd,
        descriptor_expectation: DescriptorExpectationV1,
        byte_length: u64,
        sha256: [u8; 32],
        metadata: RetainedExecutableMetadataV2,
    }

    impl RetainedExecutableCoreV2 {
        fn capture(
            descriptor: OwnedFd,
            device: u64,
            inode: u64,
            mount_id: u64,
            byte_length: u64,
            sha256: [u8; 32],
            subject: DescriptorSubjectV1,
        ) -> Result<Self, ExecutableCustodyErrorV2> {
            if !super::retained_executable_length_is_bounded_v2(byte_length) {
                return Err(ExecutableCustodyErrorV2::DescriptorLength);
            }
            let descriptor_expectation = DescriptorExpectationV1::try_new(
                subject,
                major(device),
                minor(device),
                inode,
                mount_id,
            )?;
            let metadata = RetainedExecutableMetadataV2::observe(descriptor.as_fd())?;
            let retained = Self {
                descriptor,
                descriptor_expectation,
                byte_length,
                sha256,
                metadata,
            };
            retained.reauthenticate()?;
            Ok(retained)
        }

        fn reauthenticate(&self) -> Result<(), ExecutableCustodyErrorV2> {
            let status = fcntl_getfl(self.descriptor.as_fd())
                .map_err(|_| ExecutableCustodyErrorV2::DescriptorStatus)?;
            if status & OFlags::ACCMODE != OFlags::RDONLY {
                return Err(ExecutableCustodyErrorV2::DescriptorStatus);
            }
            let flags = fcntl_getfd(self.descriptor.as_fd())
                .map_err(|_| ExecutableCustodyErrorV2::DescriptorFlags)?;
            if !flags.contains(FdFlags::CLOEXEC) {
                return Err(ExecutableCustodyErrorV2::DescriptorFlags);
            }
            observe_exact_descriptor_v1(self.descriptor.as_fd(), self.descriptor_expectation)?;
            let before = RetainedExecutableMetadataV2::observe(self.descriptor.as_fd())?;
            if before != self.metadata
                || before.hard_link_count != 1
                || !rustix::fs::FileType::from_raw_mode(before.mode).is_file()
                || before.mode & 0o111 == 0
                || before.mode & 0o6000 != 0
            {
                return Err(ExecutableCustodyErrorV2::DescriptorMetadata);
            }
            let mut xattr_probe = [0_u8; 1];
            match flistxattr(self.descriptor.as_fd(), &mut xattr_probe) {
                Ok(0) => {}
                Ok(_) | Err(_) => return Err(ExecutableCustodyErrorV2::DescriptorMetadata),
            }
            if before.byte_length != self.byte_length {
                return Err(ExecutableCustodyErrorV2::DescriptorLength);
            }
            let capacity = usize::try_from(self.byte_length)
                .map_err(|_| ExecutableCustodyErrorV2::DescriptorLength)?;
            let mut body = Vec::new();
            body.try_reserve_exact(capacity)
                .map_err(|_| ExecutableCustodyErrorV2::DescriptorLength)?;
            body.resize(capacity, 0);
            let mut observed = 0_usize;
            while observed < body.len() {
                let offset = u64::try_from(observed)
                    .map_err(|_| ExecutableCustodyErrorV2::DescriptorLength)?;
                let count = pread(self.descriptor.as_fd(), &mut body[observed..], offset)
                    .map_err(|_| ExecutableCustodyErrorV2::DescriptorRead)?;
                if count == 0 {
                    return Err(ExecutableCustodyErrorV2::DescriptorLength);
                }
                observed = observed
                    .checked_add(count)
                    .ok_or(ExecutableCustodyErrorV2::DescriptorLength)?;
            }
            let mut eof_probe = [0_u8; 1];
            if pread(self.descriptor.as_fd(), &mut eof_probe, self.byte_length)
                .map_err(|_| ExecutableCustodyErrorV2::DescriptorRead)?
                != 0
            {
                return Err(ExecutableCustodyErrorV2::DescriptorLength);
            }
            let after = RetainedExecutableMetadataV2::observe(self.descriptor.as_fd())?;
            if after != before {
                return Err(ExecutableCustodyErrorV2::DescriptorMetadata);
            }
            inspect_retained_static_amd64_elf_v2(&body, self.byte_length, self.sha256)
                .map_err(|_| ExecutableCustodyErrorV2::DescriptorDigestOrPolicy)?;
            observe_exact_descriptor_v1(self.descriptor.as_fd(), self.descriptor_expectation)?;
            Ok(())
        }
    }

    pub(crate) struct GeneratorExecutableSpawnInputsV2<'a> {
        pub(crate) cgroup: BorrowedFd<'a>,
        pub(crate) endpoint: GeneratorEndpointV1,
        pub(crate) supervisor_pidfd: BorrowedFd<'a>,
        pub(crate) publication_root: BorrowedFd<'a>,
        pub(crate) ingress: &'a [BorrowedFd<'a>],
        pub(crate) procfs_authority: ProcfsAuthorityV1,
        pub(crate) argv: &'a [&'a CStr],
        pub(crate) envp: &'a [&'a CStr],
    }

    pub(crate) struct WorkerExecutableSpawnInputsV2<'a> {
        pub(crate) cgroup: BorrowedFd<'a>,
        pub(crate) endpoint: WorkerEndpointV1,
        pub(crate) procfs_authority: ProcfsAuthorityV1,
        pub(crate) argv: &'a [&'a CStr],
        pub(crate) envp: &'a [&'a CStr],
    }

    pub(crate) struct RetainedMeasuredGeneratorExecutableV2 {
        core: RetainedExecutableCoreV2,
    }

    pub(crate) struct GeneratorExecutableReauthenticatedBeforeExecV2 {
        core: RetainedExecutableCoreV2,
    }

    pub(crate) struct GeneratorChildExecutableCustodyV2 {
        retained: RetainedChildProcessV1,
        core: RetainedExecutableCoreV2,
    }

    pub(crate) struct GeneratorExitedExecutableCustodyV2 {
        retained: RetainedChildProcessV1,
        core: RetainedExecutableCoreV2,
        observed: ExitObservationV1,
    }

    pub(crate) fn retain_measured_generator_executable_v2(
        descriptor: OwnedFd,
        expectation: &GeneratorExecutableExpectationV2,
    ) -> Result<RetainedMeasuredGeneratorExecutableV2, ExecutableCustodyErrorV2> {
        let core = RetainedExecutableCoreV2::capture(
            descriptor,
            expectation.device(),
            expectation.inode(),
            expectation.mount_id(),
            expectation.byte_length(),
            expectation.sha256(),
            DescriptorSubjectV1::GeneratorExecutable,
        )?;
        Ok(RetainedMeasuredGeneratorExecutableV2 { core })
    }

    impl RetainedMeasuredGeneratorExecutableV2 {
        pub(crate) fn reauth_before_exec(
            self,
        ) -> Result<GeneratorExecutableReauthenticatedBeforeExecV2, ExecutableCustodyErrorV2>
        {
            self.core.reauthenticate()?;
            Ok(GeneratorExecutableReauthenticatedBeforeExecV2 { core: self.core })
        }
    }

    impl GeneratorExecutableReauthenticatedBeforeExecV2 {
        pub(crate) fn spawn_once(
            self,
            inputs: GeneratorExecutableSpawnInputsV2<'_>,
        ) -> Result<GeneratorChildExecutableCustodyV2, ExecutableCustodyErrorV2> {
            self.core.reauthenticate()?;
            let plan = GeneratorSpawnPlanV1::new_with_endpoint(
                self.core.descriptor.as_fd(),
                inputs.cgroup,
                inputs.endpoint,
                inputs.supervisor_pidfd,
                inputs.publication_root,
                inputs.ingress,
                inputs.procfs_authority,
                inputs.argv,
                inputs.envp,
            )?;
            let identity_ready = spawn_generator_once_v1(plan)?;
            self.core.reauthenticate()?;
            let retained = identity_ready.release_after_executable_reauthenticated_v1()?;
            retained.reauthenticate_live()?;
            Ok(GeneratorChildExecutableCustodyV2 {
                retained,
                core: self.core,
            })
        }
    }

    impl GeneratorChildExecutableCustodyV2 {
        pub(crate) fn supervisor_receive_projection_v1(
            &self,
        ) -> Result<SupervisorReceiveProjectionV1, ExecutableCustodyErrorV2> {
            self.core.reauthenticate()?;
            Ok(self.retained.supervisor_receive_projection_v1()?)
        }

        pub(crate) fn enqueue_supervisor_generator_once_v1(
            &self,
            op: SupervisorGeneratorSendOpV1,
        ) -> Result<
            (
                SupervisorReceiveProjectionV1,
                SupervisorGeneratorSentEndpointV1,
            ),
            ExecutableCustodyErrorV2,
        > {
            self.core.reauthenticate()?;
            let sent = self.retained.enqueue_supervisor_generator_once_v1(op)?;
            self.core.reauthenticate()?;
            Ok(sent)
        }

        pub(crate) fn reauthenticate_live_child(self) -> Result<Self, ExecutableCustodyErrorV2> {
            self.core.reauthenticate()?;
            self.retained.reauthenticate_live()?;
            Ok(self)
        }

        pub(crate) fn observe_exit_and_reauthenticate(
            self,
        ) -> Result<GeneratorExitedExecutableCustodyV2, ExecutableCustodyErrorV2> {
            let observed = self.retained.observe_exit()?;
            self.core.reauthenticate()?;
            Ok(GeneratorExitedExecutableCustodyV2 {
                retained: self.retained,
                core: self.core,
                observed,
            })
        }
    }

    impl GeneratorExitedExecutableCustodyV2 {
        pub(crate) fn reap_reauthenticate_and_consume(
            mut self,
        ) -> Result<ExitObservationV1, ExecutableCustodyErrorV2> {
            let reaped = self.retained.reap_exact(self.observed)?;
            self.core.reauthenticate()?;
            Ok(reaped)
        }
    }

    pub(crate) struct RetainedMeasuredWorkerExecutableV2 {
        core: RetainedExecutableCoreV2,
    }

    pub(crate) struct WorkerExecutableReauthenticatedBeforeExecV2 {
        core: RetainedExecutableCoreV2,
    }

    pub(crate) struct WorkerBlockedExecutableCustodyV2 {
        blocked: BlockedWorkerV1,
        core: RetainedExecutableCoreV2,
    }

    pub(crate) struct WorkerMapsVerifiedExecutableCustodyV2 {
        blocked: BlockedWorkerV1,
        checked: CheckedWorkerMapsV1,
        core: RetainedExecutableCoreV2,
    }

    pub(crate) fn retain_measured_worker_executable_v2(
        descriptor: OwnedFd,
        expectation: &WorkerExecutableExpectationV2,
    ) -> Result<RetainedMeasuredWorkerExecutableV2, ExecutableCustodyErrorV2> {
        let core = RetainedExecutableCoreV2::capture(
            descriptor,
            expectation.device(),
            expectation.inode(),
            expectation.mount_id(),
            expectation.byte_length(),
            expectation.sha256(),
            DescriptorSubjectV1::WorkerExecutable,
        )?;
        Ok(RetainedMeasuredWorkerExecutableV2 { core })
    }

    impl RetainedMeasuredWorkerExecutableV2 {
        pub(crate) fn reauth_before_exec(
            self,
        ) -> Result<WorkerExecutableReauthenticatedBeforeExecV2, ExecutableCustodyErrorV2> {
            self.core.reauthenticate()?;
            Ok(WorkerExecutableReauthenticatedBeforeExecV2 { core: self.core })
        }
    }

    impl WorkerExecutableReauthenticatedBeforeExecV2 {
        pub(crate) fn spawn_once(
            self,
            inputs: WorkerExecutableSpawnInputsV2<'_>,
        ) -> Result<WorkerBlockedExecutableCustodyV2, ExecutableCustodyErrorV2> {
            self.core.reauthenticate()?;
            let plan = WorkerSpawnPlanV1::new_with_endpoint(
                self.core.descriptor.as_fd(),
                inputs.cgroup,
                inputs.endpoint,
                inputs.procfs_authority,
                inputs.argv,
                inputs.envp,
            )?;
            let blocked = spawn_worker_once_v1(plan)?;
            self.core.reauthenticate()?;
            blocked.reauthenticate_live()?;
            Ok(WorkerBlockedExecutableCustodyV2 {
                blocked,
                core: self.core,
            })
        }
    }

    impl WorkerBlockedExecutableCustodyV2 {
        pub(crate) fn configure_namespace_maps(
            self,
        ) -> Result<WorkerMapsVerifiedExecutableCustodyV2, ExecutableCustodyErrorV2> {
            let checked = self.blocked.configure_namespace_maps()?;
            self.core.reauthenticate()?;
            Ok(WorkerMapsVerifiedExecutableCustodyV2 {
                blocked: self.blocked,
                checked,
                core: self.core,
            })
        }
    }

    impl WorkerMapsVerifiedExecutableCustodyV2 {
        pub(crate) fn worker_bootstrap_projection_v1(
            &self,
        ) -> Result<WorkerBootstrapProjectionV1, ExecutableCustodyErrorV2> {
            self.core.reauthenticate()?;
            Ok(self.blocked.worker_bootstrap_projection_v1(&self.checked)?)
        }

        pub(crate) fn enqueue_supervisor_bootstrap_once_v1(
            &self,
            op: SupervisorWorkerBootstrapSendOpV1,
        ) -> Result<
            (
                WorkerBootstrapProjectionV1,
                WorkerBootstrapEnqueuedEndpointV1,
            ),
            ExecutableCustodyErrorV2,
        > {
            self.core.reauthenticate()?;
            #[rustfmt::skip]
            let sent = self.blocked
                    .enqueue_supervisor_bootstrap_once_v1(&self.checked, op)?;
            self.core.reauthenticate()?;
            Ok(sent)
        }

        pub(crate) fn release_after_bootstrap_enqueued_v1(
            self,
            bootstrap_enqueued: &WorkerBootstrapEnqueuedEndpointV1,
        ) -> Result<WorkerChildExecutableCustodyV2, ExecutableCustodyErrorV2> {
            self.core.reauthenticate()?;
            let identity_ready = self
                .blocked
                .release_after_bootstrap_enqueued_v1(self.checked, bootstrap_enqueued)
                .map_err(|error| ExecutableCustodyErrorV2::Process(error.error()))?;
            self.core.reauthenticate()?;
            let post_release = identity_ready
                .release_after_executable_reauthenticated_v1()
                .map_err(|error| ExecutableCustodyErrorV2::Process(error.error()))?;
            post_release.reauthenticate_live()?;
            self.core.reauthenticate()?;
            Ok(WorkerChildExecutableCustodyV2 {
                post_release,
                core: self.core,
            })
        }
    }

    pub(crate) struct WorkerChildExecutableCustodyV2 {
        post_release: PostReleaseWorkerV1,
        core: RetainedExecutableCoreV2,
    }

    pub(crate) struct WorkerExitedExecutableCustodyV2 {
        post_release: PostReleaseWorkerV1,
        core: RetainedExecutableCoreV2,
        observed: ExitObservationV1,
    }

    impl WorkerChildExecutableCustodyV2 {
        pub(crate) fn supervisor_receive_projection_v1(
            &self,
        ) -> Result<SupervisorReceiveProjectionV1, ExecutableCustodyErrorV2> {
            self.core.reauthenticate()?;
            Ok(self.post_release.supervisor_receive_projection_v1()?)
        }

        pub(crate) fn reauthenticate_live_child(self) -> Result<Self, ExecutableCustodyErrorV2> {
            self.core.reauthenticate()?;
            self.post_release.reauthenticate_live()?;
            Ok(self)
        }

        pub(crate) fn observe_exit_and_reauthenticate(
            self,
        ) -> Result<WorkerExitedExecutableCustodyV2, ExecutableCustodyErrorV2> {
            let observed = self.post_release.observe_exit()?;
            self.core.reauthenticate()?;
            Ok(WorkerExitedExecutableCustodyV2 {
                post_release: self.post_release,
                core: self.core,
                observed,
            })
        }
    }

    impl WorkerExitedExecutableCustodyV2 {
        pub(crate) fn reap_reauthenticate_and_consume(
            mut self,
        ) -> Result<ExitObservationV1, ExecutableCustodyErrorV2> {
            let reaped = self.post_release.reap_exact(self.observed)?;
            self.core.reauthenticate()?;
            Ok(reaped)
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
#[allow(
    unused_imports,
    reason = "E4a values are consumed only after the same-crate G0 join is added"
)]
pub(crate) use selected_target::*;

#[cfg(test)]
mod retained_measured_executable_v2 {
    use super::retained_executable_length_is_bounded_v2;
    use eip0045_h0_contract::executable::{
        RETAINED_STATIC_AMD64_ELF_MAX_BYTES_V2, RETAINED_STATIC_AMD64_ELF_MIN_BYTES_V2,
    };

    #[test]
    fn joins_same_ofd_identity_bytes_and_static_policy() {
        let source = include_str!("executable_custody.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for required in [
            "RetainedExecutableCoreV2",
            "observe_exact_descriptor_v1",
            "inspect_retained_static_amd64_elf_v2",
            "pread",
            "DescriptorSubjectV1::GeneratorExecutable",
            "DescriptorSubjectV1::WorkerExecutable",
        ] {
            assert!(
                production.contains(required),
                "missing custody join {required}"
            );
        }
        assert!(!production.contains("StatxFlags::MNT_ID"));
    }

    #[test]
    fn reauthentication_brackets_exact_bytes_with_unique_mount_observations() {
        let source = include_str!("executable_custody.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let start = production.find("fn reauthenticate(&self)").unwrap();
        let end = production
            .find("pub(crate) struct GeneratorExecutableSpawnInputsV2")
            .unwrap();
        let body = &production[start..end];
        let first_identity = body.find("observe_exact_descriptor_v1").unwrap();
        let before = body.find("let before =").unwrap();
        let read = body.find("pread(self.descriptor.as_fd()").unwrap();
        let after = body.find("let after =").unwrap();
        let policy = body.find("inspect_retained_static_amd64_elf_v2").unwrap();
        let second_identity = body.rfind("observe_exact_descriptor_v1").unwrap();
        assert!(
            first_identity < before
                && before < read
                && read < after
                && after < policy
                && policy < second_identity
        );
        assert_eq!(body.matches("observe_exact_descriptor_v1").count(), 2);
        assert!(body.contains("before.hard_link_count != 1"));
        assert!(body.contains("before.mode & 0o111 == 0"));
        assert!(body.contains("let mut eof_probe = [0_u8; 1]"));
    }

    #[test]
    fn executable_length_is_rejected_before_metadata_or_allocation() {
        assert!(!retained_executable_length_is_bounded_v2(
            RETAINED_STATIC_AMD64_ELF_MIN_BYTES_V2 - 1
        ));
        assert!(retained_executable_length_is_bounded_v2(
            RETAINED_STATIC_AMD64_ELF_MIN_BYTES_V2
        ));
        assert!(retained_executable_length_is_bounded_v2(
            RETAINED_STATIC_AMD64_ELF_MAX_BYTES_V2
        ));
        assert!(!retained_executable_length_is_bounded_v2(
            RETAINED_STATIC_AMD64_ELF_MAX_BYTES_V2 + 1
        ));

        let source = include_str!("executable_custody.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let start = production.find("fn capture(").unwrap();
        let end = production[start..]
            .find("fn reauthenticate(&self)")
            .unwrap()
            + start;
        let capture = &production[start..end];
        assert!(
            capture
                .find("retained_executable_length_is_bounded_v2")
                .unwrap()
                < capture
                    .find("RetainedExecutableMetadataV2::observe")
                    .unwrap()
        );
        assert!(!capture.contains("try_reserve_exact"));
    }
}

#[cfg(test)]
mod generator_executable_custody_v2 {
    #[test]
    fn preserves_generator_child_and_same_ofd_through_exact_reap() {
        let source = include_str!("executable_custody.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for required in [
            "RetainedMeasuredGeneratorExecutableV2",
            "GeneratorChildExecutableCustodyV2",
            "observe_exit_and_reauthenticate",
            "reap_reauthenticate_and_consume",
        ] {
            assert!(
                production.contains(required),
                "missing generator custody {required}"
            );
        }
    }

    #[test]
    fn generator_orders_reauthentication_spawn_observation_and_reap() {
        let source = include_str!("executable_custody.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let spawn_start = production
            .find("impl GeneratorExecutableReauthenticatedBeforeExecV2")
            .unwrap();
        let spawn_end = production[spawn_start..]
            .find("impl GeneratorChildExecutableCustodyV2")
            .unwrap()
            + spawn_start;
        let spawn = &production[spawn_start..spawn_end];
        assert!(
            spawn.find("self.core.reauthenticate()?").unwrap()
                < spawn
                    .find("GeneratorSpawnPlanV1::new_with_endpoint")
                    .unwrap()
        );
        assert!(
            spawn.find("spawn_generator_once_v1(plan)?").unwrap()
                < spawn.rfind("self.core.reauthenticate()?").unwrap()
        );

        let live_start = production
            .find("impl GeneratorChildExecutableCustodyV2")
            .unwrap();
        let live_end = production[live_start..]
            .find("impl GeneratorExitedExecutableCustodyV2")
            .unwrap()
            + live_start;
        let live = &production[live_start..live_end];
        let checkpoint_start = live
            .find("pub(crate) fn reauthenticate_live_child")
            .unwrap();
        let checkpoint_end = live[checkpoint_start..]
            .find("pub(crate) fn observe_exit_and_reauthenticate")
            .unwrap()
            + checkpoint_start;
        let checkpoint = &live[checkpoint_start..checkpoint_end];
        assert!(
            checkpoint.find("self.core.reauthenticate()?").unwrap()
                < checkpoint
                    .find("self.retained.reauthenticate_live()?")
                    .unwrap()
        );
        assert!(
            live.find("self.retained.observe_exit()?").unwrap()
                < live.rfind("self.core.reauthenticate()?").unwrap()
        );
        let exited = &production[live_end..];
        assert!(
            exited
                .find("self.retained.reap_exact(self.observed)?")
                .unwrap()
                < exited.find("self.core.reauthenticate()?").unwrap()
        );
    }
}

#[cfg(test)]
mod worker_maps_verified_custody_v2 {
    #[test]
    fn maps_verification_retains_blocked_worker_and_same_ofd() {
        let source = include_str!("executable_custody.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for required in [
            "WorkerBlockedExecutableCustodyV2",
            "WorkerMapsVerifiedExecutableCustodyV2",
            "configure_namespace_maps",
            "blocked: BlockedWorkerV1",
            "checked: CheckedWorkerMapsV1",
            "core: RetainedExecutableCoreV2",
        ] {
            assert!(
                production.contains(required),
                "missing worker custody {required}"
            );
        }
        assert!(!production.contains("release_after_checked_maps"));
    }

    #[test]
    fn worker_orders_reauthentication_spawn_maps_and_retention() {
        let source = include_str!("executable_custody.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let spawn_start = production
            .find("impl WorkerExecutableReauthenticatedBeforeExecV2")
            .unwrap();
        let spawn_end = production[spawn_start..]
            .find("impl WorkerBlockedExecutableCustodyV2")
            .unwrap()
            + spawn_start;
        let spawn = &production[spawn_start..spawn_end];
        assert!(
            spawn.find("self.core.reauthenticate()?").unwrap()
                < spawn.find("WorkerSpawnPlanV1::new_with_endpoint").unwrap()
        );
        assert!(
            spawn.find("spawn_worker_once_v1(plan)?").unwrap()
                < spawn.rfind("self.core.reauthenticate()?").unwrap()
        );
        let maps_end = production[spawn_end..]
            .find("pub(crate) struct WorkerChildExecutableCustodyV2")
            .unwrap()
            + spawn_end;
        let maps = &production[spawn_end..maps_end];
        assert!(
            maps.find("self.blocked.configure_namespace_maps()?")
                .unwrap()
                < maps.find("self.core.reauthenticate()?").unwrap()
        );
        assert!(maps.contains("blocked: self.blocked"));
        assert!(maps.contains("checked,"));
        assert!(maps.contains("core: self.core"));
        assert!(!maps.contains("identity: self.identity"));

        assert!(production.contains("self.retained.reauthenticate_live()?"));
        assert!(production.contains("self.post_release.reauthenticate_live()?"));
    }
}

#[cfg(test)]
mod custody_has_no_public_transfer_surface_v1 {
    #[test]
    fn production_has_no_public_transfer_escape() {
        let source = include_str!("executable_custody.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "pub struct",
            "pub enum",
            "pub fn",
            "pub use",
            "into_parts",
            "into_inner",
            "try_clone",
            "as_raw_fd",
            "from_raw_fd",
            "Path",
            "Serialize",
            "Deserialize",
            "impl Clone",
            "impl Copy",
            "impl Default",
        ] {
            assert!(
                !production.contains(forbidden),
                "public custody escape {forbidden}"
            );
        }
    }

    #[test]
    fn process_child_custody_is_private_and_child_procfs_authority_is_opaque() {
        let source = include_str!("process.rs");
        for forbidden in [
            "pub struct RunningChildV1",
            "pub enum SpawnedRoleV1",
            "pub enum ExitObservationV1",
            "pub use selected_target::{ExitObservationV1",
        ] {
            assert!(
                !source.contains(forbidden),
                "public process escape {forbidden}"
            );
        }
        assert!(source.contains("pub struct ProcfsAuthorityV1"));
        assert!(source.contains("pub fn new(root: OwnedFd)"));
        assert!(source.contains("pub use selected_target::ProcfsAuthorityV1"));
        assert!(!source.contains("impl AsFd for ProcfsAuthorityV1"));
        assert!(!source.contains("impl AsRawFd for ProcfsAuthorityV1"));
    }
}
