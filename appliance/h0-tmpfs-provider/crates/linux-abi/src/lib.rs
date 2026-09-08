//! Exact-target Linux ABI boundary for the H0 appliance.
//!
//! Supervisor-side transition authority is private to this crate. These
//! compile-fail examples exercise the external boundary rather than a modeled
//! visibility flag.
//!
//! ```compile_fail
//! use eip0045_h0_linux_abi::ancillary::{
//!     ExpectedPeerCredentialsV1, StrictReceiveExpectationV1,
//! };
//!
//! let peer = ExpectedPeerCredentialsV1::try_new(1, 1, 1).unwrap();
//! let _ = StrictReceiveExpectationV1::try_for_generator(1, peer, &[]);
//! ```
//!
//! ```compile_fail
//! use eip0045_h0_linux_abi::ancillary::{
//!     create_worker_channel_v1, SupervisorWorkerEndpointV1,
//!     WorkerBootstrapEnqueuedEndpointV1,
//! };
//! ```
//!
//! ```compile_fail
//! use eip0045_h0_linux_abi::process::{
//!     BlockedWorkerV1, CheckedWorkerMapsV1, GeneratorSpawnPlanV1,
//!     WorkerSpawnPlanV1, spawn_generator_once_v1, spawn_worker_once_v1,
//! };
//! ```
//!
//! ```compile_fail
//! use eip0045_h0_linux_abi::process::{BlockedWorkerV1, CheckedWorkerMapsV1};
//!
//! fn cannot_release(blocked: BlockedWorkerV1, checked: CheckedWorkerMapsV1) {
//!     let _ = blocked.release_after_checked_maps(checked);
//! }
//! ```
//!
//! ```compile_fail
//! use eip0045_h0_linux_abi::executable_custody;
//! ```

#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(
    not(all(target_arch = "x86_64", target_os = "linux", target_env = "musl")),
    forbid(unsafe_code)
)]

#[cfg(all(
    target_os = "linux",
    not(all(target_arch = "x86_64", target_env = "musl"))
))]
compile_error!("the H0 Linux ABI is selected only for x86_64-unknown-linux-musl");

pub mod ancillary;
pub(crate) mod executable_custody;
pub mod process;
pub mod seccomp;
#[cfg(feature = "h0-tmpfs-provider-v2-g0")]
pub(crate) mod session;
pub mod statx;

#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
#[derive(Eq, PartialEq)]
pub(crate) struct SupervisorReceiveProjectionV1 {
    child_to_supervisor_expected: ancillary::ExpectedPeerCredentialsV1,
    child_to_supervisor_credentials: eip0045_h0_contract::wire::PeerCredentialsV1,
    supervisor_receiver_user_namespace_identity: eip0045_h0_contract::wire::DescriptorIdentityV1,
    supervisor_to_generator: Option<eip0045_h0_contract::wire::PeerCredentialsV1>,
}

#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
#[derive(Eq, PartialEq)]
pub(crate) struct WorkerBootstrapProjectionV1 {
    supervisor_to_worker_credentials: eip0045_h0_contract::wire::PeerCredentialsV1,
    worker_receiver_view_uid: u32,
    worker_receiver_view_gid: u32,
    supervisor_receiver_user_namespace_identity: eip0045_h0_contract::wire::DescriptorIdentityV1,
}

/// Sole selected target triple for executable ABI code.
pub const SELECTED_TARGET_TRIPLE_V1: &str = "x86_64-unknown-linux-musl";
/// Exact Linux stable tag whose UAPI and implementation sources are reviewed.
pub const LINUX_VERSION_V1: &str = "v7.1.8";
/// Exact Linux stable commit whose UAPI and implementation sources are reviewed.
pub const LINUX_COMMIT_V1: &str = "25c76bea853d0db65b51fb4697a47cbfd9e35e76";
/// Exact Rust compiler version selected by the appliance design.
pub const RUST_VERSION_V1: &str = "1.89.0";
/// Exact safe Unix wrapper version in the locked dependency closure.
pub const RUSTIX_VERSION_V1: &str = "1.1.4";
/// SHA-256 of the exact `rustix` registry archive.
pub const RUSTIX_CRATE_SHA256_V1: &str =
    "b6fe4565b9518b83ef4f91bb47ce29620ca828bd32cb7e408f0062e9930ba190";
/// Whether executable ABI modules are selected for this compilation target.
///
/// A false value exposes inventory metadata only; it is not a fallback ABI.
pub const ABI_TARGET_COMPILED_V1: bool = cfg!(all(
    target_arch = "x86_64",
    target_os = "linux",
    target_env = "musl"
));
/// Number of reviewed unsafe primitive classes implemented through D3.
///
/// The classes are strict ancillary receive, fixed `clone3`, the child
/// trampoline, retained `execveat`, and fixed seccomp installation. Pidfd
/// wait and descriptor statx use the pinned safe `rustix` surface.
pub const IMPLEMENTED_UNSAFE_PRIMITIVE_COUNT_V1: usize = 5;

/// Closed future source-module inventory for the reviewed ABI boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbiModuleV1 {
    /// Exact descriptor-rooted statx observation.
    Statx,
    /// Exhaustive ancillary receive and control traversal.
    Ancillary,
    /// Fixed process, execution, wait, namespace, cgroup, and probe operations.
    Process,
    /// Safe private retained-executable and direct-child lifecycle custody.
    ExecutableCustody,
    /// The two monotone seccomp installations.
    Seccomp,
}

#[cfg(test)]
mod e4d_projection_and_release_gates {
    fn bounded_block<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        let start = source.find(start).expect("start marker must exist");
        let tail = &source[start..];
        let end = tail.find(end).expect("end marker must exist");
        &tail[..end]
    }

    fn assert_endpoint_moves_into_spawn_plan(custody: &str) {
        for (start, end, constructor, spawn) in [
            (
                "impl GeneratorExecutableReauthenticatedBeforeExecV2",
                "impl GeneratorChildExecutableCustodyV2",
                "GeneratorSpawnPlanV1::new_with_endpoint",
                "let identity_ready = spawn_generator_once_v1(plan)?;",
            ),
            (
                "impl WorkerExecutableReauthenticatedBeforeExecV2",
                "impl WorkerBlockedExecutableCustodyV2",
                "WorkerSpawnPlanV1::new_with_endpoint",
                "let blocked = spawn_worker_once_v1(plan)?;",
            ),
        ] {
            let block = bounded_block(custody, start, end);
            let constructor_index = block
                .find(constructor)
                .expect("spawn plan constructor must exist");
            let constructor_tail = &block[constructor_index..];
            let constructor_end = constructor_tail
                .find(")?;")
                .expect("spawn plan constructor must terminate");
            let constructor_call = &constructor_tail[..constructor_end];
            assert!(constructor_call.contains("inputs.endpoint,"));
            assert!(!constructor_call.contains("&inputs.endpoint"));
            let spawn_index = block.find(spawn).expect("spawn must bind retained custody");
            let after_spawn = &block[spawn_index + spawn.len()..];
            assert!(after_spawn.contains("self.core.reauthenticate()?;"));
            assert!(after_spawn.contains("reauthenticate_live()?;"));
            assert!(!after_spawn.contains("inputs.endpoint"));
        }
    }

    #[test]
    fn retained_session_projections_v1() {
        let process = include_str!("process.rs");
        let production = bounded_block(
            process,
            "mod selected_target {",
            "pub use selected_target::ProcfsAuthorityV1;",
        );
        for required in [
            "enum ReceiverUserNamespaceRelationV1",
            "SameAsSupervisor",
            "DistinctFromSupervisor",
            "struct RetainedSessionProjectionsV1",
            "authority: ProcfsAuthorityV1",
            "child_procfs: ValidatedChildProcfsV1",
            "supervisor_receiver_user_namespace: OwnedFd",
            "supervisor_receiver_user_namespace_identity: ProcfsFileIdentityV1",
            "receiver_relation: ReceiverUserNamespaceRelationV1",
            "identity_transition: ChildIdentityTransitionV1",
            "supervisor_runtime: SupervisorRuntimeSnapshotV1",
            "pub(crate) struct RetainedChildProcessV1",
            "child: RunningChildV1",
            "projections: RetainedSessionProjectionsV1",
            "reauthenticate_supervisor_runtime()?",
            "fn reauthenticate(\n            &self,\n            child_pid: u32,\n        ) -> Result<ProcfsThreadSnapshotV1, ProcessContractErrorV1>",
            "Ok(caller)",
            "revalidate_receiver_user_namespace_relation",
        ] {
            assert!(
                production.contains(required),
                "missing retained projection: {required}"
            );
        }
        assert!(production.contains("struct RetainedChildProcessV1 {\n        child: RunningChildV1,\n        projections: RetainedSessionProjectionsV1,"));
        let retained_child = bounded_block(
            production,
            "impl RetainedChildProcessV1 {",
            "/// Opaque worker custody after the bootstrap-gated release transition.",
        );
        let reap_start = retained_child
            .find("pub(crate) fn reap_exact(")
            .expect("retained reap must exist");
        let reap = &retained_child[reap_start..];
        let projection_reauthentication = reap
            .find("self.projections.reauthenticate(self.child.pid())?;")
            .expect("retained projections must be reauthenticated before reap");
        let child_reap = reap
            .find("self.child.reap_exact(observed)")
            .expect("same retained child must be reaped");
        assert!(projection_reauthentication < child_reap);
        assert!(!reap[child_reap..].contains("self.projections.reauthenticate"));
    }

    #[test]
    fn child_endpoint_parent_copy_drops_before_return_v1() {
        let process = include_str!("process.rs");
        let custody = include_str!("executable_custody.rs");
        assert_endpoint_moves_into_spawn_plan(custody);

        let generator_spawn = bounded_block(
            process,
            "pub(crate) fn spawn_generator_once_v1(",
            "pub(crate) fn spawn_worker_once_v1(",
        );
        assert!(generator_spawn.contains("OwnedChildEndpointV1::Generator(endpoint)"));
        let worker_spawn = bounded_block(
            process,
            "pub(crate) fn spawn_worker_once_v1(",
            "fn spawn_exact(",
        );
        assert!(worker_spawn.contains("OwnedChildEndpointV1::Worker(endpoint)"));

        let spawn_exact = bounded_block(process, "fn spawn_exact(", "fn child_trampoline(");
        assert!(spawn_exact.contains("endpoint: OwnedChildEndpointV1"));
        let clone_result_binding = ["let result = ", "unsafe", " {"].concat();
        let clone_index = spawn_exact
            .find(&clone_result_binding)
            .expect("real clone result must be bound");
        let parent = &spawn_exact[clone_index..];
        let clone_call = parent
            .find("SYS_CLONE3")
            .expect("real clone3 call must be inside the bound");
        let negative_branch = parent
            .find("if result < 0 {")
            .expect("failed clone branch must exist");
        let child_branch = parent
            .find("if result == 0 {")
            .expect("child clone branch must exist");
        assert!(clone_call < negative_branch && negative_branch < child_branch);
        let child_call = parent[child_branch..]
            .find("child_trampoline(&prepared, barrier, signal_mask.previous);")
            .expect("child branch must enter the divergent trampoline")
            + child_branch;
        let child_branch_end = parent[child_call..]
            .find("\n        }")
            .expect("child branch must terminate syntactically")
            + child_call
            + "\n        }".len();
        let parent_after_child = parent[child_branch_end..].trim_start();
        assert!(parent_after_child.starts_with("drop(endpoint);"));
        let parent_after_drop = parent_after_child["drop(endpoint);".len()..].trim_start();
        assert!(parent_after_drop.starts_with("if pidfd_raw < 0 {"));
        let negative = &parent[negative_branch..child_branch];
        assert!(negative.contains("return Err(restore_before_error(signal_mask, error));"));
        assert!(!negative.contains("forget(endpoint)"));

        let child_trampoline = bounded_block(
            process,
            "fn child_trampoline(",
            "fn reset_child_signal_dispositions(",
        );
        assert_eq!(
            process
                .matches("fn reset_child_signal_dispositions(")
                .count(),
            1
        );
        assert!(child_trampoline.contains(") -> ! {"));

        for retained in [
            bounded_block(
                process,
                "pub(crate) struct RetainedChildProcessV1",
                "impl RetainedChildProcessV1",
            ),
            bounded_block(
                process,
                "pub(crate) struct PostReleaseWorkerV1",
                "impl PostReleaseWorkerV1",
            ),
            bounded_block(
                process,
                "pub(crate) struct WorkerReleaseErrorV1",
                "impl WorkerReleaseErrorV1",
            ),
        ] {
            assert!(!retained.contains("GeneratorEndpointV1"));
            assert!(!retained.contains("WorkerEndpointV1"));
        }
    }

    #[test]
    fn worker_post_release_custody_v1() {
        let process = include_str!("process.rs");
        let custody = include_str!("executable_custody.rs");
        for required in [
            "pub(crate) struct PostReleaseWorkerV1(RetainedChildProcessV1);",
            "pub(crate) fn release_after_bootstrap_enqueued_v1(",
            "bootstrap_enqueued: &WorkerBootstrapEnqueuedEndpointV1",
            ") -> Result<PostReleaseWorkerV1, WorkerReleaseErrorV1>",
            "Ok(PostReleaseWorkerV1(retained))",
        ] {
            assert!(
                process.contains(required),
                "missing release join: {required}"
            );
        }
        for required in [
            "post_release: PostReleaseWorkerV1",
            "bootstrap_enqueued: &WorkerBootstrapEnqueuedEndpointV1",
            ".release_after_bootstrap_enqueued_v1(self.checked, bootstrap_enqueued)",
        ] {
            assert!(
                custody.contains(required),
                "missing executable release join: {required}"
            );
        }
        assert!(!process.contains("release_after_checked_maps"));
    }

    #[test]
    fn caller_cannot_supply_credentials_or_namespace_v1() {
        let process = include_str!("process.rs");
        let custody = include_str!("executable_custody.rs");
        let generator_inputs = bounded_block(
            custody,
            "pub(crate) struct GeneratorExecutableSpawnInputsV2",
            "pub(crate) struct WorkerExecutableSpawnInputsV2",
        );
        let worker_inputs = bounded_block(
            custody,
            "pub(crate) struct WorkerExecutableSpawnInputsV2",
            "pub(crate) struct RetainedMeasuredGeneratorExecutableV2",
        );
        for inputs in [generator_inputs, worker_inputs] {
            for forbidden in [
                "identity:",
                "credentials:",
                "expected_peer",
                "user_namespace",
                "namespace_identity",
                "pid:",
                "uid:",
                "gid:",
            ] {
                assert!(
                    !inputs.contains(forbidden),
                    "caller-supplied identity: {forbidden}"
                );
            }
        }
        for required in [
            "const GENERATOR_UID_V1: u32 = 20_001;",
            "const GENERATOR_GID_V1: u32 = 20_001;",
            "const WORKER_OUTER_UID_V1: u32 = 20_002;",
            "const WORKER_OUTER_GID_V1: u32 = 20_002;",
            "identity_transition: ChildIdentityTransitionV1::GeneratorService",
            "identity_transition: ChildIdentityTransitionV1::WorkerInnerZero",
        ] {
            assert!(
                process.contains(required),
                "missing role-closed identity: {required}"
            );
        }
        assert!(!process.contains("fn capture_service_identity_v1("));
        assert!(!custody.contains("inputs.identity"));
    }

    #[test]
    fn post_release_custody_has_no_public_escape_v1() {
        let process = include_str!("process.rs");
        let custody = include_str!("executable_custody.rs");
        for required in [
            "pub(crate) struct RetainedChildProcessV1",
            "pub(crate) struct PostReleaseWorkerV1(RetainedChildProcessV1);",
            "pub(crate) struct WorkerReleaseErrorV1",
        ] {
            assert!(
                process.contains(required),
                "missing private custody: {required}"
            );
        }
        for forbidden in [
            "pub struct RetainedChildProcessV1",
            "pub struct RetainedSessionProjectionsV1",
            "pub struct PostReleaseWorkerV1",
            "pub fn release_after_bootstrap_enqueued_v1",
            "pub(crate) fn into_child",
            "pub fn into_child",
            "impl AsFd for RetainedChildProcessV1",
            "impl AsRawFd for RetainedChildProcessV1",
            "impl AsFd for PostReleaseWorkerV1",
            "impl AsRawFd for PostReleaseWorkerV1",
        ] {
            assert!(
                !process.contains(forbidden) && !custody.contains(forbidden),
                "post-release custody escape: {forbidden}"
            );
        }
    }
}

#[cfg(test)]
mod e4i_runtime_identity_gates {
    fn production_block<'a>(source: &'a str, export: &str) -> &'a str {
        let start = source
            .find("mod selected_target {")
            .expect("selected-target production module must exist");
        let end = source[start..]
            .find(export)
            .expect("selected-target export must follow production")
            + start;
        &source[start..end]
    }

    #[test]
    fn supervisor_identity_profile_is_exact_and_role_distinct_v1() {
        let process = include_str!("process.rs");
        for required in [
            "const GENERATOR_UID_V1: u32 = 20_001;",
            "const GENERATOR_GID_V1: u32 = 20_001;",
            "const WORKER_OUTER_UID_V1: u32 = 20_002;",
            "const WORKER_OUTER_GID_V1: u32 = 20_002;",
            "enum ChildIdentityTransitionV1",
            "GeneratorService",
            "WorkerInnerZero",
        ] {
            assert!(
                process.contains(required),
                "missing fixed role identity: {required}"
            );
        }
        for forbidden in [
            "pub struct ServiceIdentityV1",
            "ServiceIdentityV1::new(",
            "capture_service_identity_v1",
        ] {
            assert!(
                !process.contains(forbidden),
                "detached or caller-shaped identity remains: {forbidden}"
            );
        }
    }

    #[test]
    fn supervisor_send_capability_preconditions_are_reauthenticated_v1() {
        let process = production_block(
            include_str!("process.rs"),
            "pub use selected_target::ProcfsAuthorityV1;",
        );
        for required in [
            "struct SupervisorRuntimeSnapshotV1",
            "uids: [u32; 4]",
            "gids: [u32; 4]",
            "cap_effective: u64",
            "cap_permitted: u64",
            "cap_inheritable: u64",
            "cap_bounding: u64",
            "cap_ambient: u64",
            "securebits: u32",
            "no_new_privs: bool",
            "rustix::thread::capabilities(None)",
            "rustix::thread::capabilities_secure_bits()",
            "rustix::thread::no_new_privs()",
            "rustix::thread::CapabilitySet::SETUID",
            "rustix::thread::CapabilitySet::SETGID",
            "reauthenticate_supervisor_runtime",
        ] {
            assert!(
                process.contains(required),
                "missing supervisor recheck: {required}"
            );
        }
        assert_eq!(
            process
                .matches("status.cap_effective & required != required")
                .count(),
            1,
            "CapEff must have one independent required-capability predicate"
        );
        assert_eq!(
            process
                .matches("status.cap_permitted & required != required")
                .count(),
            1,
            "CapPrm must have one independent required-capability predicate"
        );
        let capability_join = process
            .split("fn validate_proc_status_against_rustix_v1(")
            .nth(1)
            .expect("procfs-to-rustix capability join must exist")
            .split("fn validate_supervisor_runtime_constraints_v1(")
            .next()
            .expect("procfs-to-rustix capability join must be bounded");
        assert_eq!(
            capability_join
                .matches("|| status.cap_effective != capabilities.effective.bits()")
                .count(),
            1,
            "procfs CapEff must join only to rustix CapEff"
        );
        assert_eq!(
            capability_join
                .matches("|| status.cap_permitted != capabilities.permitted.bits()")
                .count(),
            1,
            "procfs CapPrm must join only to rustix CapPrm"
        );
        assert_eq!(
            capability_join
                .matches("|| status.cap_inheritable != capabilities.inheritable.bits()")
                .count(),
            1,
            "procfs CapInh must join only to rustix CapInh"
        );

        fn bounded_method<'a>(owner: &'a str, method: &str, end: &str, label: &str) -> &'a str {
            let start = owner
                .find(method)
                .unwrap_or_else(|| panic!("missing {label}: {method}"));
            let finish = owner[start..]
                .find(end)
                .unwrap_or_else(|| panic!("unbounded {label}: {end}"))
                + start;
            &owner[start..finish]
        }

        fn assert_process_runtime_bracket(
            method: &str,
            pre: &str,
            projection: &str,
            enqueue: &str,
            post: &str,
        ) {
            let pre_offset = method.find(pre).expect("missing fresh pre-send S snapshot");
            let projection_offset = method
                .find(projection)
                .expect("missing projection derived from the pre-send snapshot");
            let enqueue_offset = method.find(enqueue).expect("missing sealed typed enqueue");
            let post_offset = method
                .find(post)
                .expect("missing fresh post-send S snapshot");
            let equality_offset = method
                .find("if before != after")
                .expect("pre/post S snapshots must compare before success");
            let success_offset = method
                .find("Ok((projection, endpoint))")
                .expect("success must join the projection and opaque sent endpoint");
            assert!(
                pre_offset < projection_offset
                    && projection_offset < enqueue_offset
                    && enqueue_offset < post_offset
                    && post_offset < equality_offset
                    && equality_offset < success_offset,
                "pre-reauth, projection, enqueue, post-reauth, equality, or success order drifted"
            );
            assert_eq!(
                method.matches("reauthenticate_live_snapshot_v1()?").count(),
                2,
                "each process-owned send needs one fresh S snapshot before and after enqueue"
            );
            for forbidden in [".ok()", "unwrap_or", "if let Ok", "let _ ="] {
                assert!(
                    !method.contains(forbidden),
                    "D6b reauthentication failure was swallowed: {forbidden}"
                );
            }
        }

        let retained = process
            .split("impl RetainedChildProcessV1 {")
            .nth(1)
            .expect("retained process owner")
            .split("/// Opaque worker custody after the bootstrap-gated release transition.")
            .next()
            .expect("bounded retained process owner");
        let generator = bounded_method(
            retained,
            "pub(crate) fn enqueue_supervisor_generator_once_v1(",
            "fn validate_child_identity_ready_v1(",
            "process-owned generator send",
        );
        assert_process_runtime_bracket(
            generator,
            "let before = self.reauthenticate_live_snapshot_v1()?;",
            "let projection = self.supervisor_receive_projection_from_snapshot_v1(before)?;",
            "let endpoint = op.enqueue_once_v1(credentials)?;",
            "let after = self.reauthenticate_live_snapshot_v1()?;",
        );

        let blocked = process
            .split("impl BlockedWorkerV1 {")
            .nth(1)
            .expect("blocked worker owner")
            .split("struct ProcEntryPathV1")
            .next()
            .expect("bounded blocked worker owner");
        let worker = bounded_method(
            blocked,
            "pub(crate) fn enqueue_supervisor_bootstrap_once_v1(",
            "/// Releases exactly one byte only after the opaque bootstrap enqueue.",
            "process-owned worker-bootstrap send",
        );
        assert_process_runtime_bracket(
            worker,
            "let before = self.child.reauthenticate_live_snapshot_v1()?;",
            "let projection = self.worker_bootstrap_projection_from_snapshot_v1(checked, before)?;",
            "let endpoint = op.enqueue_once_v1(credentials)?;",
            "let after = self.child.reauthenticate_live_snapshot_v1()?;",
        );

        let custody = production_block(
            include_str!("executable_custody.rs"),
            "pub(crate) use selected_target::*;",
        );
        for (owner_start, owner_end, method, call) in [
            (
                "impl GeneratorChildExecutableCustodyV2",
                "    impl GeneratorExitedExecutableCustodyV2",
                "pub(crate) fn enqueue_supervisor_generator_once_v1(",
                "self.retained.enqueue_supervisor_generator_once_v1(op)?",
            ),
            (
                "impl WorkerMapsVerifiedExecutableCustodyV2",
                "    pub(crate) struct WorkerChildExecutableCustodyV2",
                "pub(crate) fn enqueue_supervisor_bootstrap_once_v1(",
                "self.blocked\n                    .enqueue_supervisor_bootstrap_once_v1(&self.checked, op)?",
            ),
        ] {
            let owner = custody
                .split(owner_start)
                .nth(1)
                .unwrap_or_else(|| panic!("missing D6b executable custody: {owner_start}"))
                .split(owner_end)
                .next()
                .unwrap_or_else(|| panic!("unbounded D6b executable custody: {owner_end}"));
            let method = &owner[owner
                .find(method)
                .unwrap_or_else(|| panic!("missing typed custody send: {method}"))..];
            let before = method
                .find("self.core.reauthenticate()?;")
                .expect("missing pre-send same-OFD reauthentication");
            let enqueue = method.find(call).expect("missing process-owned send join");
            let after = method[enqueue + call.len()..]
                .find("self.core.reauthenticate()?;")
                .map(|offset| offset + enqueue + call.len())
                .expect("missing post-send same-OFD reauthentication");
            let success = method
                .find("Ok(sent)")
                .expect("custody must return only the checked process result");
            assert!(before < enqueue && enqueue < after && after < success);
            assert_eq!(
                method[..success]
                    .matches("self.core.reauthenticate()?;")
                    .count(),
                2,
                "same executable OFD must bracket the process-owned send"
            );
        }
    }

    fn assert_identity_ready_consumer_order_v1(process: &str) {
        let generator = process
            .split("pub(crate) fn spawn_generator_once_v1(")
            .nth(1)
            .expect("generator spawn must exist")
            .split("pub(crate) fn spawn_worker_once_v1(")
            .next()
            .expect("generator spawn must be bounded");
        let generator_transition = generator
            .find("write_control_byte_v1(parent_control.as_fd(), TRANSITION_RELEASE_V1)?;")
            .expect("generator transition release must exist");
        let generator_ready = generator
            .find("read_control_byte_v1(parent_control.as_fd(), IDENTITY_READY_V1)?;")
            .expect("generator must wait for identity-ready");
        let generator_validate = generator
            .find("child.validate_child_identity_ready_v1()?;")
            .expect("generator parent identity validation must exist");
        let generator_successor = generator
            .find("Ok(GeneratorIdentityReadyV1 {")
            .expect("generator identity-ready successor must exist");
        assert!(
            generator_transition < generator_ready
                && generator_ready < generator_validate
                && generator_validate < generator_successor
        );
        assert_eq!(
            generator
                .matches("read_control_byte_v1(parent_control.as_fd(), IDENTITY_READY_V1)?;")
                .count(),
            1,
            "generator must consume exactly one identity-ready byte"
        );

        let worker = process
            .split("pub(crate) fn release_after_bootstrap_enqueued_v1(")
            .nth(1)
            .expect("worker bootstrap release must exist")
            .split("struct ProcEntryPathV1")
            .next()
            .expect("worker bootstrap release must be bounded");
        let worker_transition = worker
            .find("write_control_byte_v1(self.release.as_fd(), TRANSITION_RELEASE_V1)")
            .expect("worker transition release must exist");
        let worker_ready = worker
            .find("read_control_byte_v1(self.release.as_fd(), IDENTITY_READY_V1)")
            .expect("worker must wait for identity-ready");
        let worker_validate = worker
            .find("self.child.validate_child_identity_ready_v1()")
            .expect("worker parent identity validation must exist");
        let worker_successor = worker
            .find("Ok(WorkerIdentityReadyV1 {")
            .expect("worker identity-ready successor must exist");
        assert!(
            worker_transition < worker_ready
                && worker_ready < worker_validate
                && worker_validate < worker_successor
        );
        for (exact_branch, label) in [
            (
                "if let Err(error) = write_control_byte_v1(self.release.as_fd(), TRANSITION_RELEASE_V1) {\n                return Err(WorkerReleaseErrorV1 { error });\n            }",
                "transition write",
            ),
            (
                "if let Err(error) = read_control_byte_v1(self.release.as_fd(), IDENTITY_READY_V1) {\n                return Err(WorkerReleaseErrorV1 { error });\n            }",
                "identity-ready read",
            ),
            (
                "if let Err(error) = self.child.validate_child_identity_ready_v1() {\n                return Err(WorkerReleaseErrorV1 { error });\n            }",
                "identity validation",
            ),
        ] {
            assert!(
                worker.contains(exact_branch),
                "worker {label} must return the exact error unconditionally before the successor"
            );
        }
        assert_eq!(
            worker
                .matches("read_control_byte_v1(self.release.as_fd(), IDENTITY_READY_V1)")
                .count(),
            1,
            "worker must consume exactly one identity-ready byte"
        );
    }

    fn assert_worker_trampoline_order_v1(process: &str) {
        let trampoline = process
            .split("fn child_trampoline(")
            .nth(1)
            .expect("child trampoline must exist");
        let gid = trampoline
            .find("syscall(SYS_SETRESGID, gid, gid, gid)")
            .expect("GID transition must exist");
        let groups = trampoline
            .find("transition_clears_supplementary_groups_v1(prepared.identity_transition)")
            .expect("role-closed supplementary-groups transition must exist");
        let uid = trampoline
            .find("syscall(SYS_SETRESUID, uid, uid, uid)")
            .expect("UID transition must exist");
        let observe = trampoline
            .find("verify_current_thread_identity_v1(&status, prepared.identity_transition)")
            .expect("child self-observation must exist");
        let ready = trampoline
            .find("let ready = IDENTITY_READY_V1;")
            .expect("identity-ready signal must exist");
        let exec_release = trampoline
            .find("release_byte != EXEC_RELEASE_V1")
            .expect("exec release wait must exist");
        let exec = trampoline
            .find("SYS_EXECVEAT")
            .expect("same-OFD exec must exist");
        assert!(
            groups < gid
                && gid < uid
                && uid < observe
                && observe < ready
                && ready < exec_release
                && exec_release < exec
        );
        assert_eq!(
            trampoline.matches("SYS_SETGROUPS").count(),
            1,
            "worker must not acquire an unconditional post-deny setgroups path"
        );
        let groups_predicate = process
            .split("const fn transition_clears_supplementary_groups_v1(")
            .nth(1)
            .expect("role-closed supplementary-groups predicate must exist")
            .split("fn verify_child_identity_v1(")
            .next()
            .expect("supplementary-groups predicate must be bounded");
        assert!(
            groups_predicate
                .contains("matches!(transition, ChildIdentityTransitionV1::GeneratorService)"),
            "only the generator may clear supplementary groups"
        );
    }

    fn assert_executable_reauthentication_order_v1(custody: &str) {
        let generator_spawn = custody
            .split("impl GeneratorExecutableReauthenticatedBeforeExecV2")
            .nth(1)
            .expect("generator custody must exist")
            .split("impl GeneratorChildExecutableCustodyV2")
            .next()
            .expect("generator custody must be bounded");
        let worker_release = custody
            .split("impl WorkerMapsVerifiedExecutableCustodyV2")
            .nth(1)
            .expect("worker custody must exist")
            .split("pub(crate) struct WorkerChildExecutableCustodyV2")
            .next()
            .expect("worker custody must be bounded");
        for block in [generator_spawn, worker_release] {
            let identity_ready = block
                .find("let identity_ready")
                .expect("identity-ready custody join must exist");
            let release = block
                .find("release_after_executable_reauthenticated_v1")
                .expect("exec release must exist");
            let deciding = &block[identity_ready..release];
            assert!(
                deciding.contains("self.core.reauthenticate()?"),
                "same-OFD reauthentication must be between identity-ready and release"
            );
        }
    }

    #[test]
    fn worker_post_map_setres_to_inner_zero_v1() {
        let process = production_block(
            include_str!("process.rs"),
            "pub use selected_target::ProcfsAuthorityV1;",
        );
        let custody = production_block(
            include_str!("executable_custody.rs"),
            "pub(crate) use selected_target::*;",
        );
        for required in [
            "const TRANSITION_RELEASE_V1: u8 = 0x54;",
            "const IDENTITY_READY_V1: u8 = 0x49;",
            "const EXEC_RELEASE_V1: u8 = 0x45;",
            "ChildIdentityTransitionV1::WorkerInnerZero",
            "verify_current_thread_identity_v1(&status, prepared.identity_transition)",
            "release_byte != EXEC_RELEASE_V1",
            "validate_child_identity_ready_v1",
            "SendFlags::NOSIGNAL",
            "if syscall(SYS_CLOSE_RANGE, barrier_writer, barrier_writer, 0) != 0",
            "if syscall(SYS_CLOSE_RANGE, thread_directory, thread_directory, 0) != 0",
            "if syscall(SYS_CLOSE_RANGE, status_descriptor, status_descriptor, 0) != 0",
            "fn transition_clears_supplementary_groups_v1(",
            "transition_clears_supplementary_groups_v1(prepared.identity_transition)",
            "EIP0045_E4I_SIGPIPE_CHILD",
            "std::process::Command::new(",
            "reset_child_signal_dispositions()",
        ] {
            assert!(
                process.contains(required),
                "missing worker transition join: {required}"
            );
        }
        for required in [
            "before.mode & 0o6000 != 0",
            "flistxattr(",
            "Ok(0) => {}",
            "Ok(_) | Err(_) => return Err(ExecutableCustodyErrorV2::DescriptorMetadata)",
        ] {
            assert!(
                custody.contains(required),
                "missing executable identity gate: {required}"
            );
        }
        assert_worker_trampoline_order_v1(process);
        assert_identity_ready_consumer_order_v1(process);
        assert_executable_reauthentication_order_v1(custody);
    }

    #[test]
    fn worker_real_effective_saved_fs_ids_are_inner_zero_v1() {
        let process = production_block(
            include_str!("process.rs"),
            "pub use selected_target::ProcfsAuthorityV1;",
        );
        for required in [
            "struct ProcStatusSnapshotV1",
            "uids: [u32; 4]",
            "gids: [u32; 4]",
            "groups: [u32; MAX_STATUS_GROUPS_V1]",
            "fn read_thread_self_status_v1(",
            "fn read_child_status_v1(",
            "fn verify_current_thread_identity_v1(",
            "fn verify_child_identity_v1(",
            "let first_status =",
            "let second_status =",
            "if first_status != second_status",
            "status.uids == [uid; 4]",
            "status.gids == [gid; 4]",
        ] {
            assert!(
                process.contains(required),
                "missing full-ID observation: {required}"
            );
        }
        assert_eq!(
            process.matches("status.uids == [uid; 4]").count(),
            2,
            "child self-view and parent receiver-view must independently bind all UID slots"
        );
        assert_eq!(
            process.matches("status.gids == [gid; 4]").count(),
            2,
            "child self-view and parent receiver-view must independently bind all GID slots"
        );
    }

    #[test]
    fn worker_map_has_exactly_one_extent_v1() {
        let process = include_str!("process.rs");
        for required in [
            "WorkerNamespaceMapsV1::fixed_worker_v1()",
            "Some((0, WORKER_OUTER_UID_V1, 1))",
            "Some((0, WORKER_OUTER_GID_V1, 1))",
            "b\"deny\\n\"",
        ] {
            assert!(
                process.contains(required),
                "missing exact worker map: {required}"
            );
        }
        assert!(
            !process.contains("WorkerNamespaceMapsV1::new("),
            "worker map still accepts a detached identity"
        );
        let release = process
            .split("pub(crate) fn release_after_bootstrap_enqueued_v1(")
            .nth(1)
            .expect("worker release must exist")
            .split("Ok(WorkerIdentityReadyV1")
            .next()
            .expect("worker release must be bounded");
        let reread = release
            .find("self.reread_namespace_maps_v1().is_err()")
            .expect("live map reread must exist");
        let transition = release
            .find("write_control_byte_v1(self.release.as_fd(), TRANSITION_RELEASE_V1)")
            .expect("transition release must exist");
        assert!(
            reread < transition,
            "live map reread must precede transition release"
        );
    }

    #[test]
    fn unmapped_supervisor_identity_cannot_be_adopted_v1() {
        let process_source = include_str!("process.rs");
        let process = production_block(
            process_source,
            "pub use selected_target::ProcfsAuthorityV1;",
        );
        let custody = production_block(
            include_str!("executable_custody.rs"),
            "pub(crate) use selected_target::*;",
        );
        for forbidden in [
            "identity: Option<ServiceIdentityV1>",
            "expected_peer_credentials_v1",
            "fn expected_peer_credentials",
            "pub(crate) fn expected_peer_credentials",
            "expected_credentials: ExpectedPeerCredentialsV1",
            "ExpectedPeerCredentialsV1,\n        process::",
            "AncillaryReceiveErrorV1",
        ] {
            assert!(
                !process.contains(forbidden) && !custody.contains(forbidden),
                "detached credential or supervisor identity escape: {forbidden}"
            );
        }
        assert_eq!(
            process
                .matches("ExpectedPeerCredentialsV1::try_new(")
                .count(),
            1,
            "retained supervisor projection must be the sole process credential producer"
        );
        assert!(process.contains("ChildIdentityTransitionV1::WorkerInnerZero"));
        for required in [
            "fn translate_inner_to_outer_v1(",
            "fn translate_outer_to_inner_v1(",
            "translate_inner_to_outer_v1(self.uid_map(), 0) == Some(WORKER_OUTER_UID_V1)",
            "translate_inner_to_outer_v1(self.gid_map(), 0) == Some(WORKER_OUTER_GID_V1)",
            "translate_outer_to_inner_v1(self.uid_map(), 0).is_none()",
            "translate_outer_to_inner_v1(self.gid_map(), 0).is_none()",
        ] {
            assert!(
                process_source.contains(required),
                "missing unmapped-supervisor proof: {required}"
            );
        }
    }
}

#[cfg(test)]
mod e4e_projection_gates {
    fn selected_production<'a>(source: &'a str, export: &str) -> &'a str {
        let start = source
            .find("mod selected_target {")
            .expect("selected-target production module must exist");
        let end = source[start..]
            .find(export)
            .expect("selected-target export must follow production")
            + start;
        &source[start..end]
    }

    fn exact_slice<'a>(source: &'a str, start: &str, end: &str, label: &str) -> &'a str {
        let body = source
            .split(start)
            .nth(1)
            .unwrap_or_else(|| panic!("missing E4e {label} production symbol: {start}"));
        body.split(end)
            .next()
            .unwrap_or_else(|| panic!("unbounded E4e {label} production slice: {end}"))
    }

    fn assert_no_projection_escape_v1(sources: &[&str]) {
        let projection_declarations: Vec<_> = sources
            .iter()
            .flat_map(|source| source.lines())
            .map(str::trim_start)
            .filter(|line| line.contains("struct ") && line.contains("ProjectionV1"))
            .collect();
        assert_eq!(
            projection_declarations,
            [
                "pub(crate) struct SupervisorReceiveProjectionV1 {",
                "pub(crate) struct WorkerBootstrapProjectionV1 {",
            ],
            "E4e permits exactly two projection-value declarations across owned production"
        );
        for source in sources {
            for forbidden in [
                "ProcfsNamespaceDescriptorProjectionV1",
                "SessionProjectionV1",
            ] {
                assert!(
                    !source.contains(forbidden),
                    "forbidden third E4e projection value: {forbidden}"
                );
            }
            for (offset, _) in source.match_indices("impl ") {
                let header = &source[offset..];
                let header = header.split('{').next().unwrap_or(header);
                assert!(
                    !header.contains("SupervisorReceiveProjectionV1")
                        && !header.contains("WorkerBootstrapProjectionV1"),
                    "E4e projection methods or trait implementations are forbidden"
                );
            }
            for (offset, _) in source.match_indices("pub ") {
                let declaration = &source[offset..];
                let end = declaration.find(['{', ';']).unwrap_or(declaration.len());
                let declaration = &declaration[..end];
                assert!(
                    !declaration.contains("SupervisorReceiveProjectionV1")
                        && !declaration.contains("WorkerBootstrapProjectionV1"),
                    "E4e projection public facade or re-export is forbidden"
                );
            }
        }
    }

    #[test]
    fn procfs_namespace_descriptor_projection_v1() {
        let root = include_str!("lib.rs").split("#[cfg(test)]").next().unwrap();
        for required in [
            "#[derive(Eq, PartialEq)]\npub(crate) struct SupervisorReceiveProjectionV1 {",
            "child_to_supervisor_expected: ancillary::ExpectedPeerCredentialsV1,",
            "child_to_supervisor_credentials: eip0045_h0_contract::wire::PeerCredentialsV1,",
            "supervisor_receiver_user_namespace_identity: eip0045_h0_contract::wire::DescriptorIdentityV1,",
            "supervisor_to_generator: Option<eip0045_h0_contract::wire::PeerCredentialsV1>,",
            "#[derive(Eq, PartialEq)]\npub(crate) struct WorkerBootstrapProjectionV1 {",
            "supervisor_to_worker_credentials: eip0045_h0_contract::wire::PeerCredentialsV1,",
            "worker_receiver_view_uid: u32,",
            "worker_receiver_view_gid: u32,",
        ] {
            assert!(
                root.contains(required),
                "missing one of the two exact root-private E4e values or fields: {required}"
            );
        }

        let process = selected_production(
            include_str!("process.rs"),
            "pub use selected_target::ProcfsAuthorityV1;",
        );
        let projection = exact_slice(
            process,
            "fn descriptor_identity_v1(",
            "    fn open_proc_magic_directory(",
            "namespace descriptor projection",
        );
        for required in [
            "DescriptorIdentityV1::try_new(",
            "(u64::from(observed.device_major) << 32) | u64::from(observed.device_minor),",
            "observed.inode,",
            "observed.unique_mount_id,",
            ".map_err(|_| ProcessContractErrorV1::ProcfsIdentity)",
        ] {
            assert!(
                projection.contains(required),
                "descriptor projection omits exact identity component: {required}"
            );
        }
    }

    #[test]
    fn supervisor_receive_projection_is_retained_and_reauthenticated_v1() {
        let process = selected_production(
            include_str!("process.rs"),
            "pub use selected_target::ProcfsAuthorityV1;",
        );
        let retained = exact_slice(
            process,
            "impl RetainedChildProcessV1 {",
            "    /// Opaque worker custody after the bootstrap-gated release transition.",
            "retained child process",
        );
        let live_snapshot = exact_slice(
            retained,
            "fn reauthenticate_live_snapshot_v1(",
            "        pub(crate) fn reauthenticate_live(",
            "retained live snapshot",
        );
        for required in [
            "let role_matches = matches!(",
            "(self.child.role(), self.projections.receiver_relation)",
            "SpawnedRoleV1::Generator,\n                    ReceiverUserNamespaceRelationV1::SameAsSupervisor",
            "SpawnedRoleV1::Worker,\n                    ReceiverUserNamespaceRelationV1::DistinctFromSupervisor",
            "if !role_matches {\n                return Err(ProcessContractErrorV1::ChildIdentity);\n            }",
            "self.child.require_live()?;",
            "self.projections.reauthenticate(self.child.pid())",
        ] {
            assert!(
                live_snapshot.contains(required),
                "live snapshot helper omits role/relation or retained reauthentication: {required}"
            );
        }
        let receiver_relation = exact_slice(
            process,
            "fn revalidate_receiver_user_namespace_relation(",
            "    /// Direct-child and process-observation authority retained as one private owner.",
            "receiver namespace relation",
        );
        for required in [
            "if receiver_user_namespace != self.child_procfs.user_namespace_identity {\n                return Err(ProcessContractErrorV1::ChildIdentity);\n            }",
            "let relation_matches = match self.receiver_relation {",
            "ReceiverUserNamespaceRelationV1::SameAsSupervisor => {\n                    receiver_user_namespace == supervisor_user_namespace\n                }",
            "ReceiverUserNamespaceRelationV1::DistinctFromSupervisor => {\n                    receiver_user_namespace != supervisor_user_namespace\n                }",
            "if !relation_matches {\n                return Err(ProcessContractErrorV1::ChildIdentity);\n            }",
        ] {
            assert!(
                receiver_relation.contains(required),
                "receiver namespace relation omits an exact fail-closed branch: {required}"
            );
        }
        let live_unit = exact_slice(
            retained,
            "pub(crate) fn reauthenticate_live(",
            "        pub(crate) fn supervisor_receive_projection_v1(",
            "retained live unit wrapper",
        );
        assert!(live_unit.contains("self.reauthenticate_live_snapshot_v1()?;"));
        assert!(live_unit.contains("Ok(())"));
        let capture = exact_slice(
            retained,
            "pub(crate) fn supervisor_receive_projection_v1(",
            "        fn validate_child_identity_ready_v1(",
            "supervisor receive projection",
        );
        for required in [
            "let supervisor = self.reauthenticate_live_snapshot_v1()?;",
            "let supervisor_user_namespace = descriptor_identity_v1(\n                self.projections.supervisor_receiver_user_namespace_identity,\n            )?;",
            "ExpectedPeerCredentialsV1::try_new(",
            "PeerCredentialsV1::try_new(",
            "SpawnedRoleV1::Generator => (\n                    GENERATOR_UID_V1,\n                    GENERATOR_GID_V1,\n                    Some(",
            "PeerCredentialsV1::try_new(\n                            supervisor_pid,\n                            WORKER_OUTER_UID_V1,\n                            WORKER_OUTER_GID_V1,\n                            supervisor_user_namespace,",
            "SpawnedRoleV1::Worker => (WORKER_OUTER_UID_V1, WORKER_OUTER_GID_V1, None),",
            "supervisor_receiver_user_namespace_identity: supervisor_user_namespace,",
        ] {
            assert!(
                capture.contains(required),
                "supervisor receive projection omits required role/credential/namespace join: {required}"
            );
        }
        assert!(!capture.contains("self.child.require_live()?;"));
        assert!(!capture.contains("self.projections.reauthenticate(self.child.pid())?;"));

        let post_release = exact_slice(
            process,
            "impl PostReleaseWorkerV1 {",
            "    impl ProcfsAuthorityV1 {",
            "post-release worker projection",
        );
        assert!(
            post_release.contains("self.0.supervisor_receive_projection_v1()"),
            "post-release W must project through the same retained child authority"
        );
    }

    #[test]
    fn worker_bootstrap_receiver_view_projection_v1() {
        let process = selected_production(
            include_str!("process.rs"),
            "pub use selected_target::ProcfsAuthorityV1;",
        );
        let blocked = exact_slice(
            process,
            "impl BlockedWorkerV1 {",
            "    struct ProcEntryPathV1 {",
            "blocked worker",
        );
        let reread = exact_slice(
            blocked,
            "fn reread_namespace_maps_v1(&self) -> Result<(u32, u32), ProcessContractErrorV1>",
            "        pub(crate) fn worker_bootstrap_projection_v1(",
            "worker live map reread",
        );
        for required in [
            "self.child.reauthenticate_live()?;",
            "read_relative_proc_entry(child_directory, c\"uid_map\")?;",
            "read_relative_proc_entry(child_directory, c\"setgroups\")?;",
            "read_relative_proc_entry(child_directory, c\"gid_map\")?;",
            "self.maps.verify_readback(\n                &uid_readback[..uid_len],\n                &setgroups_readback[..setgroups_len],\n                &gid_readback[..gid_len],\n                &WORKER_MAP_STAGES_V1,\n                0,\n            )?;",
            "if !self.maps.inner_zero_maps_to_worker_outer_v1()\n                || !self.maps.supervisor_outer_root_is_unmapped_v1()\n            {\n                return Err(ProcessContractErrorV1::ChildIdentity);\n            }",
            "translate_inner_to_outer_v1(&uid_readback[..uid_len], 0)",
            "translate_inner_to_outer_v1(&gid_readback[..gid_len], 0)",
            "Ok((outer_uid, outer_gid))",
        ] {
            assert!(
                reread.contains(required),
                "worker map result is not derived from this invocation's live bytes: {required}"
            );
        }
        let projection = exact_slice(
            blocked,
            "pub(crate) fn worker_bootstrap_projection_v1(",
            "        /// Releases exactly one byte only after the opaque bootstrap enqueue.",
            "worker bootstrap receiver-view projection",
        );
        for required in [
            "if checked.pid != self.child.pid()\n                || checked.directory_identity\n                    != self.child.projections.child_procfs.directory_identity\n                || checked.process_starttime\n                    != self.child.projections.child_procfs.process_starttime\n                || checked.pid_namespace != self.child.projections.child_procfs.pid_namespace\n            {\n                return Err(ProcessContractErrorV1::ChildIdentity);\n            }",
            "let (outer_uid, outer_gid) = self.reread_namespace_maps_v1()?;",
            "self.child.require_live()?;",
            "self.child.projections.reauthenticate(self.child.pid())?;",
            "let worker_user_namespace = descriptor_identity_v1(\n                self.child.projections.child_procfs.user_namespace_identity,\n            )?;",
            "let supervisor_user_namespace = descriptor_identity_v1(\n                self.child\n                    .projections\n                    .supervisor_receiver_user_namespace_identity,\n            )?;",
            "PeerCredentialsV1::try_new(supervisor_pid, 0, 0, worker_user_namespace)",
            "worker_receiver_view_uid: outer_uid,",
            "worker_receiver_view_gid: outer_gid,",
            "supervisor_receiver_user_namespace_identity: supervisor_user_namespace,",
        ] {
            assert!(
                projection.contains(required),
                "worker receiver-view projection omits an exact live join: {required}"
            );
        }
        assert!(
            !projection.contains("65532")
                && !projection.contains("WORKER_OUTER_UID_V1,")
                && !projection.contains("WORKER_OUTER_GID_V1,"),
            "worker body IDs must come from live map bytes, never literals or cached role constants"
        );
    }

    #[test]
    fn session_projection_has_no_public_or_raw_escape_v1() {
        let root = include_str!("lib.rs").split("#[cfg(test)]").next().unwrap();
        const SELECTED_TARGET_GATE_V1: &str =
            "#[cfg(all(target_arch = \"x86_64\", target_os = \"linux\", target_env = \"musl\"))]";
        let process = selected_production(
            include_str!("process.rs"),
            "pub use selected_target::ProcfsAuthorityV1;",
        );
        let custody = selected_production(
            include_str!("executable_custody.rs"),
            "pub(crate) use selected_target::*;",
        );
        let declaration_start = root
            .find("#[derive(Eq, PartialEq)]\npub(crate) struct SupervisorReceiveProjectionV1 {")
            .expect("supervisor root projection declaration");
        let declaration_end = root[declaration_start..]
            .find("\n\n/// Sole selected target triple")
            .expect("bounded root projection declarations")
            + declaration_start;
        let declarations = &root[declaration_start..declaration_end];
        let supervisor = exact_slice(
            root,
            "#[derive(Eq, PartialEq)]\npub(crate) struct SupervisorReceiveProjectionV1 {",
            "\n}\n\n#[cfg(all(target_arch = \"x86_64\", target_os = \"linux\", target_env = \"musl\"))]\n#[derive(Eq, PartialEq)]\npub(crate) struct WorkerBootstrapProjectionV1 {",
            "supervisor root projection",
        );
        let worker = exact_slice(
            root,
            "#[derive(Eq, PartialEq)]\npub(crate) struct WorkerBootstrapProjectionV1 {",
            "\n}\n\n/// Sole selected target triple",
            "worker root projection",
        );
        assert_eq!(root.matches(SELECTED_TARGET_GATE_V1).count(), 2);
        for declaration in [
            "#[cfg(all(target_arch = \"x86_64\", target_os = \"linux\", target_env = \"musl\"))]\n#[derive(Eq, PartialEq)]\npub(crate) struct SupervisorReceiveProjectionV1 {",
            "#[cfg(all(target_arch = \"x86_64\", target_os = \"linux\", target_env = \"musl\"))]\n#[derive(Eq, PartialEq)]\npub(crate) struct WorkerBootstrapProjectionV1 {",
        ] {
            assert_eq!(root.matches(declaration).count(), 1);
        }
        for forbidden in [
            "pub ",
            "pub(crate) ",
            "OwnedFd",
            "BorrowedFd",
            "RawFd",
            "AsFd",
            "AsRawFd",
            "impl ",
            "fn ",
        ] {
            assert!(
                !supervisor.contains(forbidden) && !worker.contains(forbidden),
                "session projection exposes authority, descriptors, or methods: {forbidden}"
            );
        }
        for forbidden in [
            "ProcfsNamespaceDescriptorProjectionV1",
            "SessionProjectionV1",
            "#[derive(Clone",
            "#[derive(Copy",
            "#[derive(Debug",
            "#[derive(Default",
        ] {
            assert!(
                !declarations.contains(forbidden),
                "E4e permits only two Eq+PartialEq opaque values without methods: {forbidden}"
            );
        }
        assert_no_projection_escape_v1(&[root, process, custody]);
        assert_eq!(
            declarations
                .matches("pub(crate) struct SupervisorReceiveProjectionV1")
                .count(),
            1
        );
        assert_eq!(
            declarations
                .matches("pub(crate) struct WorkerBootstrapProjectionV1")
                .count(),
            1
        );
        assert_eq!(declarations.matches("ProjectionV1 {").count(), 2);
    }

    #[test]
    fn executable_projection_reauthenticates_same_ofd_first_v1() {
        let custody = selected_production(
            include_str!("executable_custody.rs"),
            "pub(crate) use selected_target::*;",
        );
        let generator = exact_slice(
            custody,
            "impl GeneratorChildExecutableCustodyV2",
            "    impl GeneratorExitedExecutableCustodyV2",
            "generator executable projection consumer",
        );
        let worker_maps = exact_slice(
            custody,
            "impl WorkerMapsVerifiedExecutableCustodyV2",
            "    pub(crate) struct WorkerChildExecutableCustodyV2",
            "worker bootstrap projection consumer",
        );
        let worker_child = exact_slice(
            custody,
            "impl WorkerChildExecutableCustodyV2",
            "    impl WorkerExitedExecutableCustodyV2",
            "worker receive projection consumer",
        );
        for (consumer, method, call) in [
            (
                generator,
                "pub(crate) fn supervisor_receive_projection_v1(",
                "self.retained.supervisor_receive_projection_v1()?",
            ),
            (
                worker_maps,
                "pub(crate) fn worker_bootstrap_projection_v1(",
                "self.blocked.worker_bootstrap_projection_v1(&self.checked)?",
            ),
            (
                worker_child,
                "pub(crate) fn supervisor_receive_projection_v1(",
                "self.post_release.supervisor_receive_projection_v1()?",
            ),
        ] {
            let method_start = consumer
                .find(method)
                .unwrap_or_else(|| panic!("missing exact E4e custody method: {method}"));
            let method_body = &consumer[method_start..];
            let projection = method_body
                .find(call)
                .unwrap_or_else(|| panic!("missing exact E4e projection consumer join: {call}"));
            let prefix = &method_body[..projection];
            assert!(
                prefix.ends_with("self.core.reauthenticate()?;\n            Ok("),
                "same-OFD executable reauthentication must be immediately before projection"
            );
            assert!(
                !prefix.contains("release_")
                    && !prefix.contains("observe_exit")
                    && !prefix.contains("reap_exact"),
                "no successor construction or executable release may precede projection"
            );
            assert!(
                call.ends_with("?") && !method_body[..projection + call.len()].contains(".ok()"),
                "projection failure must propagate unconditionally"
            );
        }
    }
}

#[cfg(test)]
fn d6b_normalized_source_item_v1(source: &str) -> String {
    source.split_whitespace().collect()
}

#[cfg(test)]
fn d6b_token_boundary_v1(source: &[u8], start: usize, len: usize) -> bool {
    let is_identifier = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    (start == 0 || !is_identifier(source[start - 1]))
        && source
            .get(start + len)
            .is_none_or(|byte| !is_identifier(*byte))
}

#[cfg(test)]
fn d6b_rust_identifier_tokens_v1(source: &str) -> Vec<&str> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut cursor = 0_usize;

    while cursor < bytes.len() {
        if bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
            continue;
        }

        if bytes[cursor..].starts_with(b"//") {
            cursor += 2;
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                cursor += 1;
            }
            continue;
        }

        if bytes[cursor..].starts_with(b"/*") {
            let comment_start = cursor;
            cursor += 2;
            let mut depth = 1_usize;
            while cursor < bytes.len() && depth != 0 {
                if bytes[cursor..].starts_with(b"/*") {
                    depth = depth.checked_add(1).expect("D6b block-comment depth");
                    cursor += 2;
                } else if bytes[cursor..].starts_with(b"*/") {
                    depth -= 1;
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
            assert_eq!(
                depth, 0,
                "D6b Rust lexer found an unterminated block comment at byte {comment_start}"
            );
            continue;
        }

        let raw_marker = if bytes[cursor] == b'r' {
            Some(cursor)
        } else if matches!(bytes[cursor], b'b' | b'c') && bytes.get(cursor + 1) == Some(&b'r') {
            Some(cursor + 1)
        } else {
            None
        };
        if let Some(raw_marker) = raw_marker {
            let mut delimiter = raw_marker + 1;
            while bytes.get(delimiter) == Some(&b'#') {
                delimiter += 1;
            }
            if bytes.get(delimiter) == Some(&b'"') {
                let literal_start = cursor;
                let hashes = delimiter - raw_marker - 1;
                cursor = delimiter + 1;
                let mut closed = false;
                while cursor < bytes.len() {
                    if bytes[cursor] == b'"'
                        && bytes
                            .get(cursor + 1..cursor + 1 + hashes)
                            .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
                    {
                        cursor += 1 + hashes;
                        closed = true;
                        break;
                    }
                    cursor += 1;
                }
                assert!(
                    closed,
                    "D6b Rust lexer found an unterminated raw string at byte {literal_start}"
                );
                continue;
            }
        }

        let quote = if bytes[cursor] == b'"' {
            Some(cursor)
        } else if matches!(bytes[cursor], b'b' | b'c') && bytes.get(cursor + 1) == Some(&b'"') {
            Some(cursor + 1)
        } else {
            None
        };
        if let Some(quote) = quote {
            let literal_start = cursor;
            cursor = quote + 1;
            let mut closed = false;
            while cursor < bytes.len() {
                match bytes[cursor] {
                    b'\\' => cursor = (cursor + 2).min(bytes.len()),
                    b'"' => {
                        cursor += 1;
                        closed = true;
                        break;
                    }
                    _ => cursor += 1,
                }
            }
            assert!(
                closed,
                "D6b Rust lexer found an unterminated string at byte {literal_start}"
            );
            continue;
        }

        let character_quote = if bytes[cursor] == b'\'' {
            Some(cursor)
        } else if bytes[cursor] == b'b' && bytes.get(cursor + 1) == Some(&b'\'') {
            Some(cursor + 1)
        } else {
            None
        };
        if let Some(quote) = character_quote {
            let identifier_start = quote + 1;
            if bytes
                .get(identifier_start)
                .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
            {
                let mut identifier_end = identifier_start + 1;
                while bytes
                    .get(identifier_end)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    identifier_end += 1;
                }
                if bytes.get(identifier_end) != Some(&b'\'') {
                    cursor = identifier_end;
                    continue;
                }
            }

            let literal_start = cursor;
            cursor = quote + 1;
            let mut closed = false;
            while cursor < bytes.len() {
                match bytes[cursor] {
                    b'\\' => cursor = (cursor + 2).min(bytes.len()),
                    b'\'' => {
                        cursor += 1;
                        closed = true;
                        break;
                    }
                    _ => cursor += 1,
                }
            }
            assert!(
                closed,
                "D6b Rust lexer found an unterminated character literal at byte {literal_start}"
            );
            continue;
        }

        if bytes[cursor] == b'r'
            && bytes.get(cursor + 1) == Some(&b'#')
            && bytes
                .get(cursor + 2)
                .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        {
            let start = cursor;
            cursor += 3;
            while bytes
                .get(cursor)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                cursor += 1;
            }
            tokens.push(&source[start..cursor]);
            continue;
        }

        if bytes[cursor].is_ascii_alphabetic() || bytes[cursor] == b'_' {
            let start = cursor;
            cursor += 1;
            while bytes
                .get(cursor)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                cursor += 1;
            }
            tokens.push(&source[start..cursor]);
            continue;
        }

        if bytes[cursor] == b';' {
            tokens.push(&source[cursor..=cursor]);
            cursor += 1;
            continue;
        }

        cursor += 1;
    }

    tokens
}

#[cfg(test)]
fn d6b_blank_source_v1(output: &mut [u8], start: usize, end: usize) {
    for byte in &mut output[start..end] {
        if *byte != b'\n' && *byte != b'\r' {
            *byte = b' ';
        }
    }
}

#[cfg(test)]
fn d6b_rust_code_mask_v1(source: &str) -> String {
    let input = source.as_bytes();
    let mut output = input.to_vec();
    let mut cursor = 0_usize;
    while cursor < input.len() {
        if input[cursor..].starts_with(b"//") {
            let start = cursor;
            cursor += 2;
            while cursor < input.len() && input[cursor] != b'\n' {
                cursor += 1;
            }
            d6b_blank_source_v1(&mut output, start, cursor);
            continue;
        }
        if input[cursor..].starts_with(b"/*") {
            let start = cursor;
            cursor += 2;
            let mut depth = 1_usize;
            while cursor < input.len() && depth != 0 {
                if input[cursor..].starts_with(b"/*") {
                    depth += 1;
                    cursor += 2;
                } else if input[cursor..].starts_with(b"*/") {
                    depth -= 1;
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
            assert_eq!(depth, 0, "D6b unterminated block comment at byte {start}");
            d6b_blank_source_v1(&mut output, start, cursor);
            continue;
        }

        let raw_marker = if input[cursor] == b'r' {
            Some(cursor)
        } else if matches!(input[cursor], b'b' | b'c') && input.get(cursor + 1) == Some(&b'r') {
            Some(cursor + 1)
        } else {
            None
        };
        if let Some(raw_marker) = raw_marker {
            let mut delimiter = raw_marker + 1;
            while input.get(delimiter) == Some(&b'#') {
                delimiter += 1;
            }
            if input.get(delimiter) == Some(&b'"') {
                let start = cursor;
                let hashes = delimiter - raw_marker - 1;
                cursor = delimiter + 1;
                let mut closed = false;
                while cursor < input.len() {
                    if input[cursor] == b'"'
                        && input
                            .get(cursor + 1..cursor + 1 + hashes)
                            .is_some_and(|tail| tail.iter().all(|byte| *byte == b'#'))
                    {
                        cursor += 1 + hashes;
                        closed = true;
                        break;
                    }
                    cursor += 1;
                }
                assert!(closed, "D6b unterminated raw string at byte {start}");
                d6b_blank_source_v1(&mut output, start, cursor);
                continue;
            }
        }

        let quote = if input[cursor] == b'"' {
            Some(cursor)
        } else if matches!(input[cursor], b'b' | b'c') && input.get(cursor + 1) == Some(&b'"') {
            Some(cursor + 1)
        } else {
            None
        };
        if let Some(quote) = quote {
            let start = cursor;
            cursor = quote + 1;
            let mut closed = false;
            while cursor < input.len() {
                match input[cursor] {
                    b'\\' => cursor = (cursor + 2).min(input.len()),
                    b'"' => {
                        cursor += 1;
                        closed = true;
                        break;
                    }
                    _ => cursor += 1,
                }
            }
            assert!(closed, "D6b unterminated string at byte {start}");
            d6b_blank_source_v1(&mut output, start, cursor);
            continue;
        }

        let character_quote = if input[cursor] == b'\'' {
            Some(cursor)
        } else if input[cursor] == b'b' && input.get(cursor + 1) == Some(&b'\'') {
            Some(cursor + 1)
        } else {
            None
        };
        if let Some(quote) = character_quote {
            let identifier_start = quote + 1;
            if input
                .get(identifier_start)
                .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
            {
                let mut identifier_end = identifier_start + 1;
                while input
                    .get(identifier_end)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    identifier_end += 1;
                }
                if input.get(identifier_end) != Some(&b'\'') {
                    cursor = identifier_end;
                    continue;
                }
            }
            let start = cursor;
            cursor = quote + 1;
            let mut closed = false;
            while cursor < input.len() {
                match input[cursor] {
                    b'\\' => cursor = (cursor + 2).min(input.len()),
                    b'\'' => {
                        cursor += 1;
                        closed = true;
                        break;
                    }
                    _ => cursor += 1,
                }
            }
            assert!(closed, "D6b unterminated character at byte {start}");
            d6b_blank_source_v1(&mut output, start, cursor);
            continue;
        }
        cursor += 1;
    }
    String::from_utf8(output).expect("D6b Rust mask remains UTF-8")
}

#[cfg(test)]
fn d6b_skip_ws_v1(bytes: &[u8], mut cursor: usize) -> usize {
    while bytes
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        cursor += 1;
    }
    cursor
}

#[cfg(test)]
fn d6b_cfg_test_end_v1(mask: &[u8], start: usize) -> Option<usize> {
    let mut cursor = start;
    for token in [b"#".as_slice(), b"[", b"cfg", b"(", b"test", b")", b"]"] {
        cursor = d6b_skip_ws_v1(mask, cursor);
        if !mask.get(cursor..)?.starts_with(token) {
            return None;
        }
        cursor += token.len();
    }
    Some(cursor)
}

#[cfg(test)]
fn d6b_closing_brace_v1(mask: &[u8], opening: usize) -> usize {
    assert_eq!(mask[opening], b'{', "D6b expected opening brace");
    let mut depth = 1_usize;
    let mut cursor = opening + 1;
    while cursor < mask.len() {
        match mask[cursor] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return cursor;
                }
            }
            _ => {}
        }
        cursor += 1;
    }
    panic!("D6b unbalanced braced item at byte {opening}");
}

#[cfg(test)]
fn d6b_delimiter_depths_at_v1(mask: &str, at: usize) -> (usize, usize, usize) {
    let mut brace_depth = 0_usize;
    let mut parenthesis_depth = 0_usize;
    let mut bracket_depth = 0_usize;
    for byte in mask.as_bytes()[..at].iter().copied() {
        match byte {
            b'{' => brace_depth += 1,
            b'}' => {
                brace_depth = brace_depth
                    .checked_sub(1)
                    .expect("D6b unmatched closing brace")
            }
            b'(' => parenthesis_depth += 1,
            b')' => {
                parenthesis_depth = parenthesis_depth
                    .checked_sub(1)
                    .expect("D6b unmatched closing parenthesis")
            }
            b'[' => bracket_depth += 1,
            b']' => {
                bracket_depth = bracket_depth
                    .checked_sub(1)
                    .expect("D6b unmatched closing bracket")
            }
            _ => {}
        }
    }
    (brace_depth, parenthesis_depth, bracket_depth)
}

#[cfg(test)]
fn d6b_attribute_end_v1(mask: &[u8], start: usize) -> Option<(bool, usize)> {
    if mask.get(start) != Some(&b'#') {
        return None;
    }
    let mut cursor = d6b_skip_ws_v1(mask, start + 1);
    let inner = mask.get(cursor) == Some(&b'!');
    if inner {
        cursor = d6b_skip_ws_v1(mask, cursor + 1);
    }
    if mask.get(cursor) != Some(&b'[') {
        return None;
    }
    let mut depth = 1_usize;
    cursor += 1;
    while cursor < mask.len() {
        match mask[cursor] {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some((inner, cursor));
                }
            }
            _ => {}
        }
        cursor += 1;
    }
    panic!("D6b unterminated attribute at byte {start}");
}

#[cfg(test)]
fn d6b_inner_attribute_inventory_v1(source: &str) -> Vec<String> {
    let mask = d6b_rust_code_mask_v1(source);
    let mut result = Vec::new();
    let mut cursor = 0_usize;
    while let Some(relative) = mask[cursor..].find('#') {
        let start = cursor + relative;
        let Some((inner, end)) = d6b_attribute_end_v1(mask.as_bytes(), start) else {
            cursor = start + 1;
            continue;
        };
        if inner {
            result.push(d6b_normalized_source_item_v1(&source[start..=end]));
        }
        cursor = end + 1;
    }
    result
}

#[cfg(test)]
fn d6b_exact_root_item_v1(source: &str, exact: &str, gate: &str) -> (usize, usize) {
    let mask = d6b_rust_code_mask_v1(source);
    let starts = source
        .match_indices(exact)
        .map(|(start, _)| start)
        .filter(|start| mask.as_bytes().get(*start) == Some(&b'#'))
        .collect::<Vec<_>>();
    assert_eq!(
        starts.len(),
        1,
        "{gate}: exact registration must occur once"
    );
    let start = starts[0];
    assert_eq!(
        d6b_delimiter_depths_at_v1(&mask, start),
        (0, 0, 0),
        "{gate}: registration must be crate-root"
    );
    let previous = mask.as_bytes()[..start]
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace());
    assert!(
        !previous.is_some_and(|index| mask.as_bytes()[index] == b']'),
        "{gate}: registration gained a preceding attribute"
    );
    (start, start + exact.len())
}

#[cfg(test)]
fn d6b_assert_session_red_registration_v1(root: &str, session: &str, expected: &[&str]) {
    const ROOT_ITEM: &str =
        "#[cfg(feature = \"h0-tmpfs-provider-v2-g0\")]\npub(crate) mod session;";
    const TEST_MODULE: &str = "#[cfg(test)]\nmod g0a_red_tests {";

    d6b_exact_root_item_v1(root, ROOT_ITEM, "D6b session root registration");
    assert_eq!(
        d6b_normalized_source_item_v1(&d6b_rust_code_mask_v1(root))
            .matches("modsession;")
            .count(),
        1,
        "D6b session root module declaration must be unique"
    );
    assert_eq!(
        d6b_inner_attribute_inventory_v1(root),
        vec![
            "#![deny(unsafe_op_in_unsafe_fn)]".to_owned(),
            "#![cfg_attr(not(all(target_arch=\"x86_64\",target_os=\"linux\",target_env=\"musl\")),forbid(unsafe_code))]".to_owned(),
        ],
        "D6b crate inner-attribute inventory drifted"
    );
    assert!(
        d6b_inner_attribute_inventory_v1(session).is_empty(),
        "D6b session source forbids inner attributes"
    );

    let (_, module_header_end) =
        d6b_exact_root_item_v1(session, TEST_MODULE, "D6b g0a RED test-module registration");
    let mask = d6b_rust_code_mask_v1(session);
    assert_eq!(
        d6b_normalized_source_item_v1(&mask)
            .matches("modg0a_red_tests{")
            .count(),
        1,
        "D6b g0a RED test module declaration must be unique"
    );
    let opening = module_header_end - 1;
    let module_end = d6b_closing_brace_v1(mask.as_bytes(), opening);
    let mut observed = Vec::new();
    let mut cursor = 0_usize;
    while let Some(relative) = mask[cursor..].find('#') {
        let start = cursor + relative;
        let Some((inner, end)) = d6b_attribute_end_v1(mask.as_bytes(), start) else {
            cursor = start + 1;
            continue;
        };
        cursor = end + 1;
        if inner || d6b_normalized_source_item_v1(&session[start..=end]) != "#[test]" {
            continue;
        }
        assert!(
            start > opening && start < module_end,
            "D6b every #[test] must belong to g0a_red_tests"
        );
        assert_eq!(
            d6b_delimiter_depths_at_v1(&mask, start),
            (1, 0, 0),
            "D6b every RED test must be a direct module child"
        );
        let previous = mask.as_bytes()[..start]
            .iter()
            .rposition(|byte| !byte.is_ascii_whitespace());
        assert!(
            !previous.is_some_and(|index| mask.as_bytes()[index] == b']'),
            "D6b RED test gained a preceding cfg/ignore/attribute"
        );
        let fn_start = d6b_skip_ws_v1(mask.as_bytes(), end + 1);
        assert!(
            mask[fn_start..].starts_with("fn")
                && d6b_token_boundary_v1(mask.as_bytes(), fn_start, 2),
            "D6b #[test] must attach directly to fn"
        );
        let name_start = d6b_skip_ws_v1(mask.as_bytes(), fn_start + 2);
        let mut name_end = name_start;
        while mask
            .as_bytes()
            .get(name_end)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            name_end += 1;
        }
        let name = &session[name_start..name_end];
        let opening_body = mask[name_end..]
            .find('{')
            .map(|offset| name_end + offset)
            .expect("D6b RED test body must open");
        assert_eq!(
            d6b_normalized_source_item_v1(&session[start..opening_body]),
            format!("#[test]fn{name}()"),
            "D6b RED test gained cfg/ignore/qualifiers/parameters"
        );
        observed.push(name.to_owned());
    }
    assert_eq!(
        observed, expected,
        "D6b exact RED test registration inventory drifted"
    );
}

#[cfg(test)]
fn assert_d6b_session_red_registration_v1(root: &str, session: &str) {
    const TESTS: [&str; 19] = [
        "session_test_only_prefix_pin_v1",
        "private_supervisor_typed_transport_v1",
        "parent_child_endpoint_relinquished_before_first_enqueue_v1",
        "supervisor_transport_reuses_single_sendmsg_v1",
        "session_core_has_no_raw_transport_v1",
        "session_offer_send_v1",
        "worker_bootstrap_send_v1",
        "closed_result_v1",
        "external_cannot_accept_or_construct_advanced_state",
        "contract_cursor_is_non_authorizing_v1",
        "pre_kernel_failure_leaves_transcript_unadvanced",
        "kernel_success_advances_transcript_once",
        "post_enqueue_failure_contains_without_rollback_or_resend",
        "friend_crate_access_is_impossible",
        "raw_spawn_release_surface_is_absent",
        "executable_session_composite_is_private",
        "linux_abi_dependency_direction_v1",
        "g0_has_no_live_entry",
        "g0_has_no_boot_or_h0_authority_surface",
    ];
    d6b_assert_session_red_registration_v1(root, session, &TESTS);
}

#[cfg(test)]
fn assert_d6b_session_red_registration_fixtures_v1() {
    const ROOT_ITEM: &str =
        "#[cfg(feature = \"h0-tmpfs-provider-v2-g0\")]\npub(crate) mod session;";
    const FIXTURE_ROOT: &str = "#![deny(unsafe_op_in_unsafe_fn)]\n#![cfg_attr(not(all(target_arch = \"x86_64\", target_os = \"linux\", target_env = \"musl\")), forbid(unsafe_code))]\npub mod seccomp;\n#[cfg(feature = \"h0-tmpfs-provider-v2-g0\")]\npub(crate) mod session;";
    const VALID_SESSION: &str =
        "#[cfg(test)]\nmod g0a_red_tests {\n    #[test]\n    fn one() {}\n}";

    d6b_exact_root_item_v1(ROOT_ITEM, ROOT_ITEM, "registration positive fixture");
    d6b_assert_session_red_registration_v1(FIXTURE_ROOT, VALID_SESSION, &["one"]);

    let cfg_any_root = FIXTURE_ROOT.replace(
        "#[cfg(feature = \"h0-tmpfs-provider-v2-g0\")]",
        "#[cfg(any())]",
    );
    let extra_root_attribute =
        FIXTURE_ROOT.replace(ROOT_ITEM, &format!("#[cfg(any())]\n{ROOT_ITEM}"));
    let extra_test_cfg = VALID_SESSION.replace("    #[test]", "    #[cfg(any())]\n    #[test]");
    let nested_test = VALID_SESSION.replace(
        "    #[test]\n    fn one() {}",
        "    const _: () = { #[test] fn one() {} };",
    );
    let cfg_any_test_module = VALID_SESSION.replacen("#[cfg(test)]", "#[cfg(any())]", 1);
    let inner_cfg = VALID_SESSION.replacen(
        "mod g0a_red_tests {",
        "mod g0a_red_tests {\n    #![cfg(any())]",
        1,
    );
    let ignored_test = VALID_SESSION.replace("    #[test]", "    #[ignore]\n    #[test]");
    let renamed_test = VALID_SESSION.replace("fn one()", "fn renamed() ");
    let parenthesized_root = FIXTURE_ROOT.replace(
        ROOT_ITEM,
        &format!(
            "#[cfg(test)]\nmacro_rules! wrap {{ ($item:item) => {{ $item }}; }}\n#[cfg(test)]\nwrap!({ROOT_ITEM});"
        ),
    );
    let bracketed_root = FIXTURE_ROOT.replace(
        ROOT_ITEM,
        &format!(
            "#[cfg(test)]\nmacro_rules! wrap {{ ($item:item) => {{ $item }}; }}\n#[cfg(test)]\nwrap![{ROOT_ITEM}];"
        ),
    );
    let parenthesized_module = format!(
        "#[cfg(test)]\nmacro_rules! wrap {{ ($item:item) => {{ $item }}; }}\n#[cfg(test)]\nwrap!({VALID_SESSION});"
    );
    let bracketed_module = format!(
        "#[cfg(test)]\nmacro_rules! wrap {{ ($item:item) => {{ $item }}; }}\n#[cfg(test)]\nwrap![{VALID_SESSION}];"
    );
    let parenthesized_test = VALID_SESSION.replace(
        "    #[test]\n    fn one() {}",
        "    macro_rules! wrap { ($item:item) => { $item }; }\n    wrap!(#[test] fn one() {});",
    );
    let bracketed_test = VALID_SESSION.replace(
        "    #[test]\n    fn one() {}",
        "    macro_rules! wrap { ($item:item) => { $item }; }\n    wrap![#[test] fn one() {}];",
    );
    for (root, session, label) in [
        (cfg_any_root.as_str(), VALID_SESSION, "cfg(any) root"),
        (
            extra_root_attribute.as_str(),
            VALID_SESSION,
            "extra root attribute",
        ),
        (FIXTURE_ROOT, extra_test_cfg.as_str(), "per-test cfg"),
        (FIXTURE_ROOT, nested_test.as_str(), "nested test"),
        (
            FIXTURE_ROOT,
            cfg_any_test_module.as_str(),
            "cfg(any) test module",
        ),
        (FIXTURE_ROOT, inner_cfg.as_str(), "inner test-module cfg"),
        (FIXTURE_ROOT, ignored_test.as_str(), "ignored test"),
        (FIXTURE_ROOT, renamed_test.as_str(), "renamed test"),
        (
            parenthesized_root.as_str(),
            VALID_SESSION,
            "parenthesized macro-wrapped root module",
        ),
        (
            bracketed_root.as_str(),
            VALID_SESSION,
            "bracketed macro-wrapped root module",
        ),
        (
            FIXTURE_ROOT,
            parenthesized_module.as_str(),
            "parenthesized macro-wrapped test module",
        ),
        (
            FIXTURE_ROOT,
            bracketed_module.as_str(),
            "bracketed macro-wrapped test module",
        ),
        (
            FIXTURE_ROOT,
            parenthesized_test.as_str(),
            "parenthesized macro-wrapped test",
        ),
        (
            FIXTURE_ROOT,
            bracketed_test.as_str(),
            "bracketed macro-wrapped test",
        ),
    ] {
        let rejected = std::panic::catch_unwind(|| {
            d6b_assert_session_red_registration_v1(root, session, &["one"])
        });
        assert!(rejected.is_err(), "{label} registration mutant must fail");
    }
}

#[cfg(test)]
fn d6b_production_without_tests_v1(source: &str) -> String {
    let mut output = source.as_bytes().to_vec();
    let mut mask = d6b_rust_code_mask_v1(source).into_bytes();
    let mut cursor = 0_usize;
    while cursor < mask.len() {
        let Some(relative) = mask[cursor..].iter().position(|byte| *byte == b'#') else {
            break;
        };
        let start = cursor + relative;
        let Some(attribute_end) = d6b_cfg_test_end_v1(&mask, start) else {
            cursor = start + 1;
            continue;
        };
        let mut terminator = attribute_end;
        while terminator < mask.len() && !matches!(mask[terminator], b'{' | b';') {
            terminator += 1;
        }
        assert!(terminator < mask.len(), "D6b cfg(test) item must terminate");
        let end = if mask[terminator] == b'{' {
            d6b_closing_brace_v1(&mask, terminator) + 1
        } else {
            terminator + 1
        };
        d6b_blank_source_v1(&mut output, start, end);
        d6b_blank_source_v1(&mut mask, start, end);
        cursor = end;
    }
    String::from_utf8(output).expect("D6b production extraction remains UTF-8")
}

#[cfg(test)]
fn d6b_rust_use_aliases_v1(tokens: &[&str]) -> Vec<String> {
    let mut aliases = Vec::new();
    let mut in_use = false;
    let mut previous = None;
    let mut alias_source = None;

    for token in tokens {
        if !in_use {
            if *token == "use" {
                in_use = true;
                previous = None;
            }
            continue;
        }

        if *token == ";" {
            assert!(
                alias_source.is_none(),
                "D6b Rust lexer found a use alias without a target"
            );
            in_use = false;
            previous = None;
            continue;
        }

        if let Some(source) = alias_source.take() {
            assert_ne!(*token, "as", "D6b Rust lexer found a repeated use alias");
            aliases.push(format!("{source} as {token}"));
            previous = Some(*token);
            continue;
        }

        if *token == "as" {
            alias_source = Some(previous.expect("D6b use alias must name its source"));
        } else {
            previous = Some(*token);
        }
    }

    assert!(!in_use, "D6b Rust lexer found an unterminated use item");
    aliases
}

#[cfg(test)]
fn d6b_module_inventory_v1(source: &str) -> Vec<String> {
    let production = d6b_production_without_tests_v1(source);
    let source = d6b_rust_code_mask_v1(&production);
    let bytes = source.as_bytes();
    let mut modules = Vec::new();
    let mut cursor = 0_usize;

    while let Some(relative_start) = source[cursor..].find("mod") {
        let start = cursor + relative_start;
        cursor = start + "mod".len();
        if !d6b_token_boundary_v1(bytes, start, "mod".len()) {
            continue;
        }

        let name_start = d6b_skip_ws_v1(bytes, cursor);
        let mut name_end = name_start;
        if bytes.get(name_end..name_end + 2) == Some(b"r#".as_slice()) {
            name_end += 2;
        }
        let identifier_start = name_end;
        if !bytes
            .get(name_end)
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        {
            continue;
        }
        name_end += 1;
        while bytes
            .get(name_end)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            name_end += 1;
        }
        assert!(
            name_end > identifier_start,
            "D6b module item must name an identifier"
        );
        let terminator = d6b_skip_ws_v1(bytes, name_end);
        let Some(kind) = bytes.get(terminator) else {
            panic!("D6b module item must terminate: {}", &source[start..]);
        };
        if matches!(*kind, b'{' | b';') {
            modules.push(format!(
                "{}{}",
                &source[name_start..name_end],
                char::from(*kind)
            ));
            cursor = terminator + 1;
        }
    }
    modules
}

#[cfg(test)]
fn d6b_macro_segment_start_v1(bytes: &[u8], end: usize) -> Option<usize> {
    let mut start = end;
    while start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
        start -= 1;
    }
    if start == end {
        return None;
    }
    if start >= 2 && bytes.get(start - 2..start) == Some(b"r#".as_slice()) {
        start -= 2;
    }
    Some(start)
}

#[cfg(test)]
fn d6b_macro_inventory_v1(source: &str) -> Vec<(String, usize)> {
    let production = d6b_production_without_tests_v1(source);
    let source = d6b_rust_code_mask_v1(&production);
    let bytes = source.as_bytes();
    let mut paths = Vec::new();

    for bang in 0..bytes.len() {
        if bytes[bang] != b'!' {
            continue;
        }
        let opening = d6b_skip_ws_v1(bytes, bang + 1);
        if !bytes
            .get(opening)
            .is_some_and(|byte| matches!(*byte, b'(' | b'[' | b'{'))
        {
            continue;
        }

        let mut segment_end = bang;
        while segment_end > 0 && bytes[segment_end - 1].is_ascii_whitespace() {
            segment_end -= 1;
        }
        let Some(mut segment_start) = d6b_macro_segment_start_v1(bytes, segment_end) else {
            continue;
        };
        let mut segments = vec![source[segment_start..segment_end].to_owned()];

        loop {
            let mut separator_end = segment_start;
            while separator_end > 0 && bytes[separator_end - 1].is_ascii_whitespace() {
                separator_end -= 1;
            }
            if separator_end < 2
                || bytes.get(separator_end - 2..separator_end) != Some(b"::".as_slice())
            {
                break;
            }
            let mut previous_end = separator_end - 2;
            while previous_end > 0 && bytes[previous_end - 1].is_ascii_whitespace() {
                previous_end -= 1;
            }
            let Some(previous_start) = d6b_macro_segment_start_v1(bytes, previous_end) else {
                break;
            };
            segments.push(source[previous_start..previous_end].to_owned());
            segment_start = previous_start;
        }
        segments.reverse();
        let path = segments.join("::");
        if matches!(
            path.as_str(),
            "if" | "while" | "match" | "return" | "let" | "else"
        ) {
            continue;
        }
        paths.push(path);
    }

    paths.sort();
    let mut inventory: Vec<(String, usize)> = Vec::new();
    for path in paths {
        if let Some((previous, count)) = inventory.last_mut() {
            if *previous == path {
                *count += 1;
                continue;
            }
        }
        inventory.push((path, 1));
    }
    inventory
}

#[cfg(test)]
fn d6b_assert_no_path_attributes_v1(label: &str, source: &str) {
    let production = d6b_production_without_tests_v1(source);
    let source = d6b_rust_code_mask_v1(&production);
    let bytes = source.as_bytes();
    let mut cursor = 0_usize;

    while let Some(relative_hash) = source[cursor..].find('#') {
        let hash = cursor + relative_hash;
        let mut opening = d6b_skip_ws_v1(bytes, hash + 1);
        if bytes.get(opening) == Some(&b'!') {
            opening = d6b_skip_ws_v1(bytes, opening + 1);
        }
        if bytes.get(opening) != Some(&b'[') {
            cursor = hash + 1;
            continue;
        }

        let mut depth = 1_usize;
        let mut closing = opening + 1;
        while closing < bytes.len() && depth != 0 {
            match bytes[closing] {
                b'[' => depth += 1,
                b']' => depth -= 1,
                _ => {}
            }
            closing += 1;
        }
        assert_eq!(depth, 0, "D6b attribute must close in {label}");
        let identifiers = d6b_rust_identifier_tokens_v1(&source[opening + 1..closing - 1]);
        assert!(
            identifiers
                .iter()
                .all(|identifier| !matches!(*identifier, "path" | "r#path")),
            "D6b production forbids path attributes, including cfg_attr(path), in {label}"
        );
        cursor = closing;
    }
}

#[cfg(test)]
fn d6b_has_union_item_v1(source: &str) -> bool {
    let bytes = source.as_bytes();
    let mut cursor = 0_usize;
    while let Some(relative_start) = source[cursor..].find("union") {
        let start = cursor + relative_start;
        cursor = start + "union".len();
        if !d6b_token_boundary_v1(bytes, start, "union".len()) {
            continue;
        }
        let mut previous = start;
        while previous > 0 && bytes[previous - 1].is_ascii_whitespace() {
            previous -= 1;
        }
        if previous > 0 && matches!(bytes[previous - 1], b'.' | b':') {
            continue;
        }
        let mut name_end = d6b_skip_ws_v1(bytes, cursor);
        if bytes.get(name_end..name_end + 2) == Some(b"r#".as_slice()) {
            name_end += 2;
        }
        if !bytes
            .get(name_end)
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        {
            continue;
        }
        name_end += 1;
        while bytes
            .get(name_end)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            name_end += 1;
        }
        let after_name = d6b_skip_ws_v1(bytes, name_end);
        if bytes
            .get(after_name)
            .is_some_and(|byte| matches!(*byte, b'<' | b'{'))
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
fn assert_d6b_source_extension_one_v1(
    label: &str,
    source: &str,
    expected_modules: &[&str],
    expected_macros: &[(&str, usize)],
    expected_aliases: &[&str],
) {
    let production = d6b_production_without_tests_v1(source);
    let masked = d6b_rust_code_mask_v1(&production);
    let identifiers = d6b_rust_identifier_tokens_v1(&masked);
    assert!(
        !identifiers.contains(&"macro_rules") && !identifiers.contains(&"macro"),
        "D6b production forbids declarative macro definitions in {label}"
    );
    assert!(
        !identifiers.contains(&"trait"),
        "D6b production forbids local trait surfaces in {label}"
    );
    assert!(
        !identifiers.contains(&"type"),
        "D6b production forbids Rust type aliases in {label}"
    );
    assert!(
        !d6b_has_union_item_v1(&masked),
        "D6b production forbids union declarations in {label}"
    );
    d6b_assert_no_path_attributes_v1(label, source);
    assert_eq!(
        d6b_module_inventory_v1(source),
        expected_modules,
        "D6b production module inventory drifted in {label}"
    );
    assert_eq!(
        d6b_macro_inventory_v1(source),
        expected_macros
            .iter()
            .map(|(path, count)| ((*path).to_owned(), *count))
            .collect::<Vec<_>>(),
        "D6b production macro invocation inventory drifted in {label}"
    );
    let mut aliases = d6b_rust_use_aliases_v1(&identifiers);
    aliases.sort();
    assert_eq!(
        aliases,
        expected_aliases
            .iter()
            .map(|alias| (*alias).to_owned())
            .collect::<Vec<_>>(),
        "D6b production use-alias inventory drifted in {label}"
    );
}

#[cfg(test)]
fn assert_d6b_source_extension_closure_v1(sources: &[(&str, &str)]) {
    const LIB_MODULES: &[&str] = &[
        "ancillary;",
        "executable_custody;",
        "process;",
        "seccomp;",
        "session;",
        "statx;",
    ];
    const SELECTED_MODULE: &[&str] = &["selected_target{"];
    const ANCILLARY_MODULES: &[&str] = &["strict_model{", "selected_target{"];
    const SECCOMP_MODULES: &[&str] = &["filter_model{", "selected_target{"];
    const NO_ITEMS: &[&str] = &[];
    const NO_MACROS: &[(&str, usize)] = &[];
    const LIB_MACROS: &[(&str, usize)] = &[("cfg", 1), ("compile_error", 1)];
    const PROCESS_MACROS: &[(&str, usize)] =
        &[("core::mem::offset_of", 15), ("matches", 2), ("write", 1)];
    const ANCILLARY_MACROS: &[(&str, usize)] = &[
        ("core::mem::offset_of", 15),
        ("debug_assert_eq", 1),
        ("format", 1),
        ("rustix::cmsg_space", 1),
        ("write", 16),
    ];
    const SECCOMP_MACROS: &[(&str, usize)] = &[("core::mem::offset_of", 6), ("write", 1)];
    const STATX_MACROS: &[(&str, usize)] = &[("debug_assert_eq", 2), ("write", 7)];
    const ANCILLARY_ALIASES: &[&str] = &[
        "FdRoleV1 as ContractFdRoleV1",
        "MAX_FRAME_BYTES_V1 as CONTRACT_MAX_FRAME_BYTES_V1",
        "MAX_FRAME_FDS_V1 as CONTRACT_MAX_FRAME_FDS_V1",
    ];
    const CUSTODY_ALIASES: &[&str] = &["AsFd as _"];

    assert_eq!(
        sources.iter().map(|(label, _)| *label).collect::<Vec<_>>(),
        [
            "lib.rs",
            "process.rs",
            "executable_custody.rs",
            "ancillary.rs",
            "session.rs",
            "seccomp.rs",
            "statx.rs",
        ],
        "D6b source-extension closure must inspect the exact seven production sources"
    );

    for (label, source) in sources {
        let (modules, macros, aliases) = match *label {
            "lib.rs" => (LIB_MODULES, LIB_MACROS, NO_ITEMS),
            "process.rs" => (SELECTED_MODULE, PROCESS_MACROS, NO_ITEMS),
            "executable_custody.rs" => (SELECTED_MODULE, NO_MACROS, CUSTODY_ALIASES),
            "ancillary.rs" => (ANCILLARY_MODULES, ANCILLARY_MACROS, ANCILLARY_ALIASES),
            "session.rs" => (NO_ITEMS, NO_MACROS, NO_ITEMS),
            "seccomp.rs" => (SECCOMP_MODULES, SECCOMP_MACROS, NO_ITEMS),
            "statx.rs" => (NO_ITEMS, STATX_MACROS, NO_ITEMS),
            _ => panic!("D6b unexpected source-extension label: {label}"),
        };
        assert_d6b_source_extension_one_v1(label, source, modules, macros, aliases);
    }
}

#[cfg(test)]
fn assert_d6b_source_extension_closure_fixtures_v1() {
    let valid = r##"
        // include!("comment.rs"); mod comment_only;
        const NOTE: &str = "#[path = \"string.rs\"] mod string_only;";
        #[cfg(test)]
        mod tests {
            include!("test-only.rs");
            trait TestOnlyRetryV1 {}
            impl<T> TestOnlyRetryV1 for T {}
        }
        fn unary_not_is_not_a_macro_v1(flag: bool) { if !(flag) {} }
        mod selected_target {}
    "##;
    assert_d6b_source_extension_one_v1("fixture.rs", valid, &["selected_target{"], &[], &[]);
    assert_eq!(
        d6b_macro_inventory_v1("fn route() { if !(flag) {} call ! (); }"),
        vec![("call".to_owned(), 1)],
        "D6b macro scanner must reject unary keyword bang while retaining spaced macro calls"
    );

    let mutants = [
        format!("include!(\"retry.rs\"); {valid}"),
        format!("mod injected; {valid}"),
        valid.replacen(
            "mod selected_target {}",
            "#[path = \"retry.rs\"] mod selected_target {}",
            1,
        ),
        format!(
            "trait RetryV1 {{ fn retry(self) -> Self; }} impl<T> RetryV1 for T {{ fn retry(self) -> Self {{ self }} }} {valid}"
        ),
    ];
    for mutant in mutants {
        let rejected = std::panic::catch_unwind(|| {
            assert_d6b_source_extension_one_v1(
                "fixture.rs",
                &mutant,
                &["selected_target{"],
                &[],
                &[],
            )
        });
        assert!(
            rejected.is_err(),
            "D6b include, external module, path attribute, and blanket-trait mutants must each fail closed"
        );
    }
}

#[cfg(test)]
fn d6b_impl_headers_v1(source: &str) -> Vec<String> {
    let production = d6b_production_without_tests_v1(source);
    let source = d6b_rust_code_mask_v1(&production);
    let mut headers = Vec::new();
    let mut cursor = 0;
    while let Some(relative_start) = source[cursor..].find("impl") {
        let start = cursor + relative_start;
        cursor = start + "impl".len();
        if !d6b_token_boundary_v1(source.as_bytes(), start, "impl".len()) {
            continue;
        }
        let Some(next) = source.as_bytes().get(cursor) else {
            continue;
        };
        if *next != b'<' && !next.is_ascii_whitespace() {
            continue;
        }
        let end = source[cursor..]
            .find('{')
            .unwrap_or_else(|| panic!("D6b impl header must have a body: {}", &source[start..]))
            + cursor;
        headers.push(source[start..end].to_owned());
    }
    headers
}

#[cfg(test)]
fn d6b_expected_selected_impl_inventory_v1() -> Vec<String> {
    let mut expected = [
        "impl<'a>GeneratorBoundSendInputV1<'a>",
        "implChildTypedReceiveErrorV1",
        "implChildTypedSendErrorV1",
        "implGeneratorChannelV1",
        "implGeneratorBoundAwaitClosedResultEndpointV1",
        "implGeneratorEndpointV1",
        "implGeneratorPeerGCommitSendEndpointV1",
        "implGeneratorPeerGRevealSendEndpointV1",
        "implGeneratorPeerSCommitReceiveEndpointV1",
        "implGeneratorPeerSRevealReceiveEndpointV1",
        "implGeneratorPeerSessionOfferEndpointV1",
        "implGeneratorProviderSessionEndpointV1",
        "implInheritedEndpointAdoptionErrorV1",
        "implFrom<AncillaryReceiveErrorV1>forSupervisorTypedTransitionErrorV1",
        "implFrom<WireErrorV1>forSupervisorTypedTransitionErrorV1",
        "implReceivedFdV1",
        "implReceivedFrameV1",
        "implSupervisorGeneratorEndpointV1",
        "implSupervisorGeneratorSendOpV1",
        "implSupervisorGeneratorSentEndpointV1",
        "implSupervisorTypedTransitionErrorV1",
        "implSupervisorWorkerBootstrapSendOpV1",
        "implSupervisorWorkerEndpointV1",
        "implWorkerBootstrapPreflightErrorV1",
        "implWorkerBootstrapEnqueuedEndpointV1",
        "implWorkerChannelV1",
        "implWorkerEndpointV1",
        "implWorkerPostExecFdInventoryV1",
        "implfmt::DebugforChildTypedReceiveErrorV1",
        "implfmt::DebugforChildTypedSendErrorV1",
        "implfmt::DebugforInheritedEndpointAdoptionErrorV1",
        "implfmt::DisplayforChildTypedReceiveErrorV1",
        "implfmt::DisplayforChildTypedSendErrorV1",
        "implfmt::DisplayforInheritedEndpointAdoptionErrorV1",
        "implstd::error::ErrorforChildTypedReceiveErrorV1",
        "implstd::error::ErrorforChildTypedSendErrorV1",
        "implstd::error::ErrorforInheritedEndpointAdoptionErrorV1",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    expected.sort();
    expected
}

#[cfg(test)]
fn d6b_expected_whole_impl_inventory_v1() -> Vec<String> {
    let mut expected = d6b_expected_selected_impl_inventory_v1();
    expected.extend(
        [
            "implControlParseOutcomeV1",
            "implExpectedPeerCredentialsV1",
            "implStrictReceiveExpectationV1",
            "implValidatedAncillaryV1",
            "implfmt::DisplayforAncillaryReceiveErrorV1",
            "implfmt::DisplayforAncillarySendErrorV1",
            "implfmt::DisplayforSeqpacketEndpointErrorV1",
            "implstd::error::ErrorforAncillaryReceiveErrorV1",
            "implstd::error::ErrorforAncillarySendErrorV1",
            "implstd::error::ErrorforSeqpacketEndpointErrorV1",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    expected.sort();
    expected
}

#[cfg(test)]
fn d6b_exact_impl_inventory_v1(source: &str) -> Vec<String> {
    let mut headers = d6b_impl_headers_v1(source)
        .into_iter()
        .map(|header| d6b_normalized_source_item_v1(&header))
        .collect::<Vec<_>>();
    headers.sort();
    headers
}

#[cfg(test)]
fn assert_d6b_successor_function_closure_v1(source: &str) {
    let signatures = d6b_function_signatures_v1(source);
    for forbidden in ["fninto_parts(", "fnreplay(", "fnresend(", "fnretry("] {
        assert!(
            signatures
                .iter()
                .all(|signature| !signature.contains(forbidden)),
            "D6b whole ancillary gained named replay/extraction function: {forbidden}"
        );
    }
    let mut observed = signatures
        .into_iter()
        .filter(|signature| {
            signature.contains("SupervisorGeneratorSentEndpointV1")
                || signature.contains("WorkerBootstrapEnqueuedEndpointV1")
        })
        .map(|signature| signature.replace(",)->", ")->"))
        .collect::<Vec<_>>();
    observed.sort();
    let mut expected = [
        "fnenqueue_once_v1(self,credentials:UCred)->Result<SupervisorGeneratorSentEndpointV1,AncillarySendErrorV1>",
        "fnenqueue_once_v1(self,credentials:UCred)->Result<WorkerBootstrapEnqueuedEndpointV1,AncillarySendErrorV1>",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(
        observed, expected,
        "D6b whole ancillary successor function-signature inventory drifted"
    );
}

#[cfg(test)]
fn assert_d6b_successor_impl_location_closure_v1(full_source: &str, selected_source: &str) {
    let full_production = d6b_production_without_tests_v1(full_source);
    let full_identifiers = d6b_rust_identifier_tokens_v1(&full_production);
    assert!(
        !full_identifiers.contains(&"type")
            && !full_identifiers.contains(&"macro_rules")
            && !full_identifiers.contains(&"macro"),
        "D6b whole ancillary production forbids alias or macro-defined successor surfaces"
    );
    let mut aliases = d6b_rust_use_aliases_v1(&full_identifiers);
    aliases.sort();
    assert_eq!(
        aliases,
        [
            "FdRoleV1 as ContractFdRoleV1",
            "MAX_FRAME_BYTES_V1 as CONTRACT_MAX_FRAME_BYTES_V1",
            "MAX_FRAME_FDS_V1 as CONTRACT_MAX_FRAME_FDS_V1",
        ],
        "D6b whole ancillary use-alias inventory drifted"
    );
    assert_eq!(
        full_identifiers
            .iter()
            .filter(|identifier| **identifier == "trait")
            .count(),
        0,
        "D6b whole ancillary production forbids local trait surfaces"
    );
    assert_eq!(
        d6b_exact_impl_inventory_v1(selected_source),
        d6b_expected_selected_impl_inventory_v1(),
        "D6b selected-target exact impl inventory drifted"
    );
    assert_eq!(
        d6b_exact_impl_inventory_v1(&full_production),
        d6b_expected_whole_impl_inventory_v1(),
        "D6b whole ancillary exact impl inventory drifted"
    );
    assert_d6b_successor_function_closure_v1(&full_production);
    assert_d6b_protected_operation_method_closure_v1(selected_source);
}

#[cfg(test)]
fn d6b_function_signatures_v1(source: &str) -> Vec<String> {
    let production = d6b_production_without_tests_v1(source);
    let source = d6b_rust_code_mask_v1(&production);
    let mut signatures = Vec::new();
    let mut cursor = 0;
    while let Some(relative_start) = source[cursor..].find("fn") {
        let start = cursor + relative_start;
        cursor = start + "fn".len();
        if !d6b_token_boundary_v1(source.as_bytes(), start, "fn".len()) {
            continue;
        }
        let Some(name_start) = source[cursor..]
            .find(|character: char| !character.is_whitespace())
            .map(|offset| cursor + offset)
        else {
            continue;
        };
        if !source.as_bytes()[name_start].is_ascii_alphabetic()
            && source.as_bytes()[name_start] != b'_'
        {
            continue;
        }
        let tail = &source[name_start..];
        let body = tail.find('{');
        let declaration = tail.find(';');
        let Some(relative_end) = (match (body, declaration) {
            (Some(body), Some(declaration)) => Some(body.min(declaration)),
            (Some(body), None) => Some(body),
            (None, Some(declaration)) => Some(declaration),
            (None, None) => None,
        }) else {
            panic!(
                "D6b function signature must terminate: {}",
                &source[start..]
            );
        };
        signatures.push(d6b_normalized_source_item_v1(
            &source[start..name_start + relative_end],
        ));
    }
    signatures
}

#[cfg(test)]
fn d6b_canonical_method_signature_v1(signature: &str) -> String {
    d6b_normalized_source_item_v1(signature)
        .replace(",)", ")")
        .replace(",>", ">")
}

#[cfg(test)]
fn d6b_inherent_method_inventory_v1(source: &str, owners: &[&str]) -> Vec<String> {
    let production = d6b_production_without_tests_v1(source);
    let mask = d6b_rust_code_mask_v1(&production);
    let bytes = mask.as_bytes();
    let mut observed = Vec::new();
    let mut owner_counts = vec![0_usize; owners.len()];
    let mut cursor = 0_usize;

    while let Some(relative_start) = mask[cursor..].find("impl") {
        let start = cursor + relative_start;
        cursor = start + "impl".len();
        if !d6b_token_boundary_v1(bytes, start, "impl".len()) {
            continue;
        }

        let opening = mask[cursor..]
            .find('{')
            .map(|offset| cursor + offset)
            .unwrap_or_else(|| panic!("D6b protected impl must have a body: {}", &mask[start..]));
        let closing = d6b_closing_brace_v1(bytes, opening);
        let header = d6b_normalized_source_item_v1(&mask[start..opening]);

        if let Some((owner_index, owner)) = owners
            .iter()
            .copied()
            .enumerate()
            .find(|(_, owner)| header == format!("impl{owner}"))
        {
            owner_counts[owner_index] += 1;
            let block = &production[opening + 1..closing];
            let block_mask = d6b_rust_code_mask_v1(block);
            assert!(
                !block_mask.match_indices('#').any(|(start, _)| {
                    d6b_delimiter_depths_at_v1(&block_mask, start) == (0, 0, 0)
                }),
                "D6b protected `{owner}` impl gained an attribute-controlled method surface"
            );
            let normalized_block = d6b_normalized_source_item_v1(&block_mask);

            for signature in d6b_function_signatures_v1(block) {
                let qualified = format!("pub(crate){signature}");
                assert!(
                    normalized_block.contains(&qualified),
                    "D6b protected `{owner}` method gained non-pub(crate), async, const, unsafe, extern, or other unapproved qualifiers: {signature}"
                );
                observed.push(format!(
                    "{owner}:{}",
                    d6b_canonical_method_signature_v1(&qualified)
                ));
            }
        }

        cursor = closing + 1;
    }

    assert!(
        owner_counts.iter().all(|count| *count == 1),
        "D6b protected operation owners must each have exactly one inherent impl: {owner_counts:?}"
    );
    observed.sort();
    observed
}

#[cfg(test)]
fn assert_d6b_inherent_method_inventory_v1(
    source: &str,
    owners: &[&str],
    expected: &[&str],
    label: &str,
) {
    let observed = d6b_inherent_method_inventory_v1(source, owners);
    let mut expected = expected
        .iter()
        .map(|signature| (*signature).to_owned())
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(
        observed, expected,
        "{label}: protected method inventory drifted"
    );
}

#[cfg(test)]
fn assert_d6b_protected_operation_method_closure_v1(source: &str) {
    const OWNERS: [&str; 2] = [
        "SupervisorGeneratorSendOpV1",
        "SupervisorWorkerBootstrapSendOpV1",
    ];
    const EXPECTED: [&str; 2] = [
        "SupervisorGeneratorSendOpV1:pub(crate)fnenqueue_once_v1(self,credentials:UCred)->Result<SupervisorGeneratorSentEndpointV1,AncillarySendErrorV1>",
        "SupervisorWorkerBootstrapSendOpV1:pub(crate)fnenqueue_once_v1(self,credentials:UCred)->Result<WorkerBootstrapEnqueuedEndpointV1,AncillarySendErrorV1>",
    ];

    assert_d6b_inherent_method_inventory_v1(
        source,
        &OWNERS,
        &EXPECTED,
        "D6b owner-keyed protected operation closure",
    );
}

#[cfg(test)]
fn assert_d6b_protected_operation_method_closure_fixtures_v1() {
    for (owner, successor) in [
        (
            "SupervisorGeneratorSendOpV1",
            "SupervisorGeneratorSentEndpointV1",
        ),
        (
            "SupervisorWorkerBootstrapSendOpV1",
            "WorkerBootstrapEnqueuedEndpointV1",
        ),
    ] {
        let expected = format!(
            "{owner}:pub(crate)fnenqueue_once_v1(self,credentials:UCred)->Result<{successor},AncillarySendErrorV1>"
        );
        let valid = format!(
            "impl {owner} {{ pub(crate) fn enqueue_once_v1(self, credentials: UCred) -> Result<{successor}, AncillarySendErrorV1> {{ unreachable!() }} }}"
        );
        assert_d6b_inherent_method_inventory_v1(
            &valid,
            &[owner],
            &[expected.as_str()],
            "D6b protected-operation positive fixture",
        );

        let attribute_controlled = valid.replacen(
            "pub(crate) fn enqueue_once_v1",
            "#[cfg(any())] pub(crate) fn enqueue_once_v1",
            1,
        );
        let rejected = std::panic::catch_unwind(|| {
            assert_d6b_inherent_method_inventory_v1(
                &attribute_controlled,
                &[owner],
                &[expected.as_str()],
                "D6b attribute-controlled method mutant",
            )
        });
        assert!(
            rejected.is_err(),
            "`{owner}` method-level cfg must be rejected at direct impl depth"
        );

        let anchor = format!("impl {owner} {{");
        let mutant = valid.replacen(
            &anchor,
            &format!("{anchor} pub(crate) fn x(self) -> OwnedFd {{ unreachable!() }}"),
            1,
        );
        let rejected = std::panic::catch_unwind(|| {
            assert_d6b_inherent_method_inventory_v1(
                &mutant,
                &[owner],
                &[expected.as_str()],
                "D6b receiver-only OwnedFd mutant",
            )
        });
        assert!(
            rejected.is_err(),
            "`{owner}` receiver-only owning-descriptor escape must change the owner-keyed inventory"
        );
    }
}

#[cfg(test)]
fn d6b_impl_header_mentions_trait_v1(header: &str, trait_name: &str) -> bool {
    let mut cursor = 0;
    while let Some(relative_start) = header[cursor..].find(trait_name) {
        let start = cursor + relative_start;
        if d6b_token_boundary_v1(header.as_bytes(), start, trait_name.len()) {
            return true;
        }
        cursor = start + trait_name.len();
    }
    false
}

#[cfg(test)]
fn assert_d6b_role_closure_v1(sources: &[(&str, &str)]) {
    const SEALED_TYPES: [&str; 4] = [
        "SupervisorGeneratorSendOpV1",
        "SupervisorWorkerBootstrapSendOpV1",
        "SupervisorGeneratorSentEndpointV1",
        "WorkerBootstrapEnqueuedEndpointV1",
    ];
    const SUCCESSOR_TYPES: [&str; 2] = [
        "SupervisorGeneratorSentEndpointV1",
        "WorkerBootstrapEnqueuedEndpointV1",
    ];
    const CONVERSION_TRAITS: [&str; 10] = [
        "From",
        "Into",
        "TryFrom",
        "TryInto",
        "Deref",
        "DerefMut",
        "Borrow",
        "BorrowMut",
        "AsRef",
        "AsMut",
    ];

    assert_eq!(
        sources.iter().map(|(label, _)| *label).collect::<Vec<_>>(),
        ["lib.rs", "ancillary.rs", "process.rs", "custody.rs"],
        "D6b alias closure must inspect the exact four selected production sources"
    );

    let mut observed_sealed_types = [false; SEALED_TYPES.len()];
    let mut use_aliases = Vec::new();
    let mut successor_impls = Vec::new();
    let mut successor_signatures = Vec::new();
    for (label, source) in sources {
        let identifiers = d6b_rust_identifier_tokens_v1(source);
        assert!(
            !identifiers.is_empty(),
            "D6b alias closure received an empty token inventory for {label}"
        );
        assert!(
            !identifiers.contains(&"type"),
            "D6b selected production forbids every Rust type alias so sealed types cannot be hidden in {label}"
        );
        assert!(
            !identifiers.contains(&"macro_rules") && !identifiers.contains(&"macro"),
            "D6b selected production forbids every declarative macro definition so sealed types cannot be hidden in {label}"
        );
        for (index, sealed_type) in SEALED_TYPES.iter().enumerate() {
            observed_sealed_types[index] |= identifiers.contains(sealed_type);
        }
        use_aliases.extend(
            d6b_rust_use_aliases_v1(&identifiers)
                .into_iter()
                .map(|alias| format!("{label}:{alias}")),
        );

        let normalized = d6b_normalized_source_item_v1(source);
        for forbidden in ["fninto_parts", "fnretry", "fnresend"] {
            assert!(
                !normalized.contains(forbidden),
                "D6b selected production gained a named extraction/replay function in {label}: {forbidden}"
            );
        }

        for header in d6b_impl_headers_v1(source) {
            if SEALED_TYPES.iter().any(|name| header.contains(name)) {
                assert!(
                    !CONVERSION_TRAITS
                        .iter()
                        .any(|trait_name| d6b_impl_header_mentions_trait_v1(&header, trait_name)),
                    "D6b sealed type gained a conversion trait in {label}: {header}"
                );
            }
            if SUCCESSOR_TYPES.iter().any(|name| header.contains(name)) {
                successor_impls.push(format!(
                    "{label}:{}",
                    d6b_normalized_source_item_v1(&header)
                ));
            }
        }

        for signature in d6b_function_signatures_v1(source) {
            if SUCCESSOR_TYPES.iter().any(|name| signature.contains(name)) {
                successor_signatures.push(format!("{label}:{signature}"));
            }
        }
    }

    assert!(
        observed_sealed_types.into_iter().all(|observed| observed),
        "D6b alias closure must non-vacuously observe all four sealed canonical types"
    );
    use_aliases.sort();
    assert_eq!(
        use_aliases,
        ["custody.rs:AsFd as _"],
        "D6b selected production may retain only the exact non-naming AsFd import alias"
    );

    successor_impls.sort();
    assert_eq!(
        successor_impls,
        [
            "ancillary.rs:implSupervisorGeneratorSentEndpointV1",
            "ancillary.rs:implWorkerBootstrapEnqueuedEndpointV1",
        ],
        "D6b successors may have only the exact G0a generator and worker typed-receive implementations"
    );

    successor_signatures.sort();
    let mut expected_signatures = vec![
        "ancillary.rs:fn enqueue_once_v1(self,credentials:UCred,)->Result<SupervisorGeneratorSentEndpointV1,AncillarySendErrorV1>",
        "ancillary.rs:fn enqueue_once_v1(self,credentials:UCred,)->Result<WorkerBootstrapEnqueuedEndpointV1,AncillarySendErrorV1>",
        "custody.rs:fn enqueue_supervisor_bootstrap_once_v1(&self,op:SupervisorWorkerBootstrapSendOpV1,)->Result<(WorkerBootstrapProjectionV1,WorkerBootstrapEnqueuedEndpointV1,),ExecutableCustodyErrorV2,>",
        "custody.rs:fn enqueue_supervisor_generator_once_v1(&self,op:SupervisorGeneratorSendOpV1,)->Result<(SupervisorReceiveProjectionV1,SupervisorGeneratorSentEndpointV1,),ExecutableCustodyErrorV2,>",
        "custody.rs:fn release_after_bootstrap_enqueued_v1(self,bootstrap_enqueued:&WorkerBootstrapEnqueuedEndpointV1,)->Result<WorkerChildExecutableCustodyV2,ExecutableCustodyErrorV2>",
        "process.rs:fn enqueue_supervisor_bootstrap_once_v1(&self,checked:&CheckedWorkerMapsV1,op:SupervisorWorkerBootstrapSendOpV1,)->Result<(WorkerBootstrapProjectionV1,WorkerBootstrapEnqueuedEndpointV1),ProcessContractErrorV1>",
        "process.rs:fn enqueue_supervisor_generator_once_v1(&self,op:SupervisorGeneratorSendOpV1,)->Result<(SupervisorReceiveProjectionV1,SupervisorGeneratorSentEndpointV1),ProcessContractErrorV1>",
        "process.rs:fn release_after_bootstrap_enqueued_v1(self,checked:CheckedWorkerMapsV1,bootstrap_enqueued:&WorkerBootstrapEnqueuedEndpointV1,)->Result<WorkerIdentityReadyV1,WorkerReleaseErrorV1>",
    ];
    for signature in &mut expected_signatures {
        *signature = Box::leak(d6b_normalized_source_item_v1(signature).into_boxed_str());
    }
    expected_signatures.sort();
    assert_eq!(
        successor_signatures, expected_signatures,
        "D6b successors may occur only in the exact enqueue results, release borrows, and worker typed receive ownership"
    );
}

#[cfg(test)]
mod d6b_explicit_supervisor_credential_gates {
    fn exact_slice<'a>(source: &'a str, start: &str, end: &str, label: &str) -> &'a str {
        let start = source
            .find(start)
            .unwrap_or_else(|| panic!("missing {label} start marker: {start}"));
        let end = source[start..]
            .find(end)
            .unwrap_or_else(|| panic!("missing {label} end marker: {end}"))
            + start;
        &source[start..end]
    }

    fn selected_production<'a>(source: &'a str, export: &str) -> &'a str {
        exact_slice(
            source,
            "mod selected_target {",
            export,
            "selected production",
        )
    }

    fn ancillary_production(source: &str) -> &str {
        exact_slice(
            source,
            "pub(super) mod selected_target {",
            "        #[cfg(test)]\n        mod inherited_fd3_subprocess_tests {",
            "selected ancillary production",
        )
    }

    fn send_helper(source: &str) -> &str {
        exact_slice(
            source,
            "fn send_seqpacket_once_v1(",
            "fn verify_worker_post_enqueue_cloexec_v1(",
            "sole sendmsg helper",
        )
    }

    fn normalized(source: &str) -> String {
        source.split_whitespace().collect()
    }

    fn signature<'a>(source: &'a str, method: &str) -> &'a str {
        let start = source
            .find(method)
            .unwrap_or_else(|| panic!("missing typed D6b method: {method}"));
        let tail = &source[start..];
        let end = tail
            .find('{')
            .unwrap_or_else(|| panic!("missing typed D6b method body: {method}"));
        &tail[..end]
    }

    fn braced_item<'a>(source: &'a str, marker: &str, label: &str) -> &'a str {
        let mask = super::d6b_rust_code_mask_v1(source);
        let start = mask
            .find(marker)
            .unwrap_or_else(|| panic!("missing {label}: {marker}"));
        let open = mask[start..]
            .find('{')
            .unwrap_or_else(|| panic!("missing {label} body"))
            + start;
        let close = super::d6b_closing_brace_v1(mask.as_bytes(), open);
        &source[start..=close]
    }

    const G0A_FEATURE_GATE_V1: &str = "#[cfg(feature = \"h0-tmpfs-provider-v2-g0\")]";
    const SELECTED_TARGET_GATE_V1: &str =
        "#[cfg(all(target_arch = \"x86_64\", target_os = \"linux\", target_env = \"musl\"))]";

    fn has_item_boundary_before_v1(mask: &str, start: usize) -> bool {
        let prefix = mask[..start].trim_end();
        prefix.is_empty() || matches!(prefix.as_bytes().last(), Some(b'{' | b'}' | b';' | b','))
    }

    fn lexical_immediate_attribute_start_v1(
        source: &str,
        mask: &str,
        item_start: usize,
        expected: &str,
    ) -> Option<usize> {
        let attribute_end = mask[..item_start].trim_end().len();
        if attribute_end == 0 || mask.as_bytes().get(attribute_end - 1) != Some(&b']') {
            return None;
        }
        let attribute_start = mask[..attribute_end].rfind("#[")?;
        if source.get(attribute_start..attribute_end)? != expected {
            return None;
        }
        Some(attribute_start)
    }

    fn exact_immediate_attribute_start_v1(
        source: &str,
        mask: &str,
        item_start: usize,
        expected: &str,
    ) -> Option<usize> {
        let attribute_start =
            lexical_immediate_attribute_start_v1(source, mask, item_start, expected)?;
        has_item_boundary_before_v1(mask, attribute_start).then_some(attribute_start)
    }

    fn immediately_feature_gated_v1(
        source: &str,
        mask: &str,
        marker: &str,
        expected: usize,
    ) -> bool {
        let starts = mask
            .match_indices(marker)
            .map(|(start, _)| start)
            .collect::<Vec<_>>();
        starts.len() == expected
            && starts.into_iter().all(|start| {
                exact_immediate_attribute_start_v1(source, mask, start, G0A_FEATURE_GATE_V1)
                    .is_some()
            })
    }

    fn contract_wire_import_blocks_are_exact_v1(source: &str, mask: &str) -> bool {
        let marker = "use eip0045_h0_contract::wire::";
        let starts = mask
            .match_indices(marker)
            .map(|(start, _)| start)
            .collect::<Vec<_>>();
        if starts.len() != 2 {
            return false;
        }
        let mut blocks = Vec::new();
        for start in starts.iter().copied() {
            let Some(open) = mask[start..].find('{').map(|offset| start + offset) else {
                return false;
            };
            let close = super::d6b_closing_brace_v1(mask.as_bytes(), open);
            if mask.as_bytes().get(close + 1) != Some(&b';') {
                return false;
            }
            blocks.push(normalized(&mask[start..=close + 1]));
        }
        blocks
            == [
                "useeip0045_h0_contract::wire::{ChannelIdentityV1,ProviderSessionMaterialV1,SeqpacketEndpointCommitmentV1,};",
                "useeip0045_h0_contract::wire::{FdAccessV1,FdStatusV1,G0_CLOSED_RESULT_RAW_FRAME_BYTES_V1,G0_FINAL_RESULT_MAX_BYTES_V1,G0_PRE_SESSION_RECORD_BYTES_V1,G0_SESSION_OFFER_BYTES_V1,G0ClosedResultInboundInputV1,G0ClosedResultVerifiedV1,G0GeneratorBoundAwaitClosedResultV1,G0GeneratorBoundOutboundCandidateV1,G0GeneratorBoundTranscriptCandidateV1,G0GeneratorCommitRecordV1,G0GeneratorPeerLocalFactsV1,G0GeneratorPeerSessionCandidateV1,G0GeneratorPeerSessionInputV1,G0GeneratorRevealRecordV1,G0TranscriptCandidateV1,G0WorkerBootstrapContentVerifierV1,G0WorkerBootstrapInboundCandidateV1,G0WorkerBootstrapInboundInputV1,GeneratorSealProfileV1,MemfdSealsV1,PeerCredentialsV1,ProcessInventoryV1,SealPresenceV1,SealedIngressManifestV1,WireErrorV1,WireFrameV1,};",
            ]
            && has_item_boundary_before_v1(mask, starts[0])
            && exact_immediate_attribute_start_v1(source, mask, starts[1], G0A_FEATURE_GATE_V1)
                .is_some()
    }

    fn g0a_ancillary_feature_isolated_v1(source: &str) -> bool {
        let mask = super::d6b_rust_code_mask_v1(source);
        let selected = ancillary_production(source);
        let selected_mask = super::d6b_rust_code_mask_v1(selected);
        let begin_marker = "pub fn begin_peer_session_v1(";
        let begin_starts = mask
            .match_indices(begin_marker)
            .map(|(start, _)| start)
            .collect::<Vec<_>>();
        let begin_feature_stack_is_exact = begin_starts.len() == 1
            && lexical_immediate_attribute_start_v1(
                source,
                &mask,
                begin_starts[0],
                G0A_FEATURE_GATE_V1,
            )
            .and_then(|feature_start| {
                exact_immediate_attribute_start_v1(source, &mask, feature_start, "#[must_use]")
            })
            .is_some();
        let exact_items = [
            ("struct PreparedSupervisorReceiveV1 {", 1),
            ("pub(crate) struct SessionOfferSendInputV1 {", 1),
            ("pub(crate) struct GeneratorCommitReceiveInputV1 {", 1),
            ("pub(crate) struct SupervisorCommitSendInputV1 {", 1),
            ("pub(crate) struct GeneratorRevealReceiveInputV1 {", 1),
            ("pub(crate) struct SupervisorRevealSendInputV1 {", 1),
            ("enum UninhabitedSupervisorSemanticJoinV1 {}", 1),
            ("pub(crate) struct GeneratorBoundReceiveInputV1 {", 1),
            ("pub(crate) struct WorkerBootstrapSendInputV1 {", 1),
            ("pub(crate) struct WorkerExecBoundReceiveInputV1 {", 1),
            ("pub(crate) struct ClosedResultSendInputV1 {", 1),
            ("pub(crate) struct SupervisorTypedTransitionErrorV1 {", 1),
            ("impl SupervisorTypedTransitionErrorV1 {", 1),
            (
                "impl From<AncillaryReceiveErrorV1> for SupervisorTypedTransitionErrorV1 {",
                1,
            ),
            (
                "impl From<WireErrorV1> for SupervisorTypedTransitionErrorV1 {",
                1,
            ),
            ("enum SupervisorGeneratorSendPhaseV1 {", 1),
            ("pub(crate) struct GeneratorCommitReceivedEndpointV1 {", 1),
            ("pub(crate) struct GeneratorRevealReceivedEndpointV1 {", 1),
            ("pub(crate) struct GeneratorBoundReceivedEndpointV1 {", 1),
            ("pub(crate) struct WorkerExecBoundReceivedEndpointV1 {", 1),
            ("pub struct ChildTypedReceiveErrorV1 {", 1),
            ("impl ChildTypedReceiveErrorV1 {", 1),
            ("impl fmt::Debug for ChildTypedReceiveErrorV1 {", 1),
            ("impl fmt::Display for ChildTypedReceiveErrorV1 {", 1),
            ("impl std::error::Error for ChildTypedReceiveErrorV1 {", 1),
            ("pub struct GeneratorBoundSendInputV1<'a> {", 1),
            ("impl<'a> GeneratorBoundSendInputV1<'a> {", 1),
            ("pub struct GeneratorBoundAwaitClosedResultEndpointV1 {", 1),
            ("pub struct GeneratorPeerSessionOfferEndpointV1 {", 1),
            ("pub struct GeneratorPeerGCommitSendEndpointV1 {", 1),
            ("pub struct GeneratorPeerSCommitReceiveEndpointV1 {", 1),
            ("pub struct GeneratorPeerGRevealSendEndpointV1 {", 1),
            ("pub struct GeneratorPeerSRevealReceiveEndpointV1 {", 1),
            ("pub struct GeneratorProviderSessionEndpointV1 {", 1),
            ("struct ParentSupervisorIdentityV1 {", 1),
            ("use crate::process::{", 1),
            (
                "use rustix::process::{Resource, getgid, getpid, getppid, getrlimit, getuid};",
                1,
            ),
            ("fn generator_outbound_credentials_v1(", 1),
            ("fn observed_supervisor_credentials_v1(", 1),
            ("fn validate_received_final_result_once_v1(", 1),
            ("impl GeneratorProviderSessionEndpointV1 {", 1),
            ("impl GeneratorBoundAwaitClosedResultEndpointV1 {", 1),
            ("fn expected_supervisor_credentials_v1(", 1),
            ("fn receive_current_parent_zero_fd_once_v1", 1),
            ("fn require_parent_unchanged_v1(", 1),
            ("fn send_generator_pre_session_record_once_v1(", 1),
            ("impl GeneratorPeerSessionOfferEndpointV1 {", 1),
            ("impl GeneratorPeerGCommitSendEndpointV1 {", 1),
            ("impl GeneratorPeerSCommitReceiveEndpointV1 {", 1),
            ("impl GeneratorPeerGRevealSendEndpointV1 {", 1),
            ("impl GeneratorPeerSRevealReceiveEndpointV1 {", 1),
            ("phase: SupervisorGeneratorSendPhaseV1,", 2),
            ("phase: self.phase,", 1),
            ("impl SupervisorGeneratorSentEndpointV1 {", 1),
            ("pub(crate) fn prepare_session_offer_send_v1(", 1),
            ("pub(crate) fn prepare_supervisor_commit_send_v1(", 1),
            ("pub(crate) fn prepare_supervisor_reveal_send_v1(", 1),
            ("pub(crate) fn prepare_worker_bootstrap_send_v1(", 1),
            ("pub(crate) fn receive_worker_exec_bound_once_v1(", 1),
            ("pub(crate) fn prepare_closed_result_send_v1(", 1),
            ("fn prepare_supervisor_typed_send_v1(", 1),
            ("fn prepare_supervisor_typed_receive_v1(", 1),
            ("fn receive_exact_generator_once_v1(", 1),
            ("fn receive_exact_worker_once_v1(", 1),
            ("fn join_worker_bootstrap_post_receive_v1(", 1),
        ];
        begin_feature_stack_is_exact
            && exact_items.into_iter().all(|(marker, expected)| {
                immediately_feature_gated_v1(source, &mask, marker, expected)
            })
            && contract_wire_import_blocks_are_exact_v1(selected, &selected_mask)
            && mask
                .rfind("ClosedResultSendInputV1")
                .and_then(|symbol_at| mask[..symbol_at].rfind("pub(crate) use "))
                .and_then(|item_at| {
                    lexical_immediate_attribute_start_v1(
                        source,
                        &mask,
                        item_at,
                        G0A_FEATURE_GATE_V1,
                    )
                })
                .is_some_and(|feature_at| {
                    exact_immediate_attribute_start_v1(
                        source,
                        &mask,
                        feature_at,
                        SELECTED_TARGET_GATE_V1,
                    )
                    .is_some()
                })
    }

    fn assert_g0a_generator_successor_impl_v1(ancillary: &str, gate: &str) {
        assert_eq!(
            ancillary
                .matches("impl SupervisorGeneratorSentEndpointV1 {")
                .count(),
            1,
            "{gate}: generator successor must expose one closed typed-receive implementation"
        );
        let implementation =
            braced_item(ancillary, "impl SupervisorGeneratorSentEndpointV1 {", gate);
        assert_eq!(
            super::d6b_function_signatures_v1(implementation).len(),
            3,
            "{gate}: generator successor may expose exactly three consuming typed receives"
        );
        let mut previous_method = 0_usize;
        for (method, expected) in [
            (
                "pub(crate) fn receive_generator_nonce_commit_once_v1(",
                "pub(crate)fnreceive_generator_nonce_commit_once_v1(self,input:GeneratorCommitReceiveInputV1)->Result<GeneratorCommitReceivedEndpointV1,SupervisorTypedTransitionErrorV1>",
            ),
            (
                "pub(crate) fn receive_generator_nonce_reveal_once_v1(",
                "pub(crate)fnreceive_generator_nonce_reveal_once_v1(self,input:GeneratorRevealReceiveInputV1)->Result<GeneratorRevealReceivedEndpointV1,SupervisorTypedTransitionErrorV1>",
            ),
            (
                "pub(crate) fn receive_generator_bound_once_v1(",
                "pub(crate)fnreceive_generator_bound_once_v1(self,input:GeneratorBoundReceiveInputV1)->Result<(GeneratorBoundReceivedEndpointV1,G0GeneratorBoundTranscriptCandidateV1),SupervisorTypedTransitionErrorV1>",
            ),
        ] {
            let method_position = implementation
                .find(method)
                .unwrap_or_else(|| panic!("{gate}: missing exact generator receive: {method}"));
            assert!(
                method_position >= previous_method,
                "{gate}: generator receive order drifted: {method}"
            );
            previous_method = method_position;
            let observed = normalized(signature(implementation, method)).replace(",)->", ")->");
            let rustfmt_bound_signature = "pub(crate)fnreceive_generator_bound_once_v1(self,input:GeneratorBoundReceiveInputV1)->Result<(GeneratorBoundReceivedEndpointV1,G0GeneratorBoundTranscriptCandidateV1,),SupervisorTypedTransitionErrorV1,>";
            assert!(
                observed == expected
                    || (method == "pub(crate) fn receive_generator_bound_once_v1("
                        && observed == rustfmt_bound_signature),
                "{gate}: generator typed-receive signature drifted: {method}: {observed}"
            );
        }
        for forbidden in [
            "fn into_parts",
            "fn endpoint",
            "fn descriptor",
            "fn retry",
            "fn resend",
            "Box<[u8]>",
            "Vec<OwnedFd>",
            "BorrowedFd",
            "OwnedFd",
            "RawFd",
            "UCred",
            "&[u8]",
        ] {
            assert!(
                !implementation.contains(forbidden),
                "{gate}: generator successor gained raw, duplicating, or replay authority: {forbidden}"
            );
        }
        for forbidden in [
            "impl Clone for SupervisorGeneratorSentEndpointV1",
            "impl Copy for SupervisorGeneratorSentEndpointV1",
            "impl Default for SupervisorGeneratorSentEndpointV1",
            "impl AsFd for SupervisorGeneratorSentEndpointV1",
            "impl AsRawFd for SupervisorGeneratorSentEndpointV1",
        ] {
            assert!(
                !ancillary.contains(forbidden),
                "{gate}: generator successor gained a raw or duplicating trait: {forbidden}"
            );
        }
    }

    fn assert_g0a_generator_successor_impl_fixtures_v1() {
        let valid = "impl SupervisorGeneratorSentEndpointV1 { pub(crate) fn receive_generator_nonce_commit_once_v1(self, input: GeneratorCommitReceiveInputV1) -> Result<GeneratorCommitReceivedEndpointV1, SupervisorTypedTransitionErrorV1> { unreachable!() } pub(crate) fn receive_generator_nonce_reveal_once_v1(self, input: GeneratorRevealReceiveInputV1) -> Result<GeneratorRevealReceivedEndpointV1, SupervisorTypedTransitionErrorV1> { unreachable!() } pub(crate) fn receive_generator_bound_once_v1(self, input: GeneratorBoundReceiveInputV1) -> Result<(GeneratorBoundReceivedEndpointV1, G0GeneratorBoundTranscriptCandidateV1), SupervisorTypedTransitionErrorV1> { unreachable!() } }";
        assert_g0a_generator_successor_impl_v1(valid, "generator successor positive fixture");
        let lexical_brace_decoy = valid.replacen(
            "{ pub(crate) fn",
            "{ /* a lexical } must not close this impl */ pub(crate) fn",
            1,
        );
        assert_g0a_generator_successor_impl_v1(
            &lexical_brace_decoy,
            "generator successor lexical-brace fixture",
        );
        let closing = valid.rfind('}').expect("fixture impl closes");
        let retry = format!(
            "{} pub(crate) fn retry(self) -> Self {{ self }} {}",
            &valid[..closing],
            &valid[closing..]
        );
        let raw_getter = format!(
            "{} pub(crate) fn descriptor(&self) -> RawFd {{ value }} {}",
            &valid[..closing],
            &valid[closing..]
        );
        for mutant in [
            format!("{valid}{valid}"),
            valid.replacen("pub(crate) fn", "pub fn", 1),
            valid.replacen("(self,", "(&self,", 1),
            retry,
            raw_getter,
        ] {
            let rejected = std::panic::catch_unwind(|| {
                assert_g0a_generator_successor_impl_v1(
                    &mutant,
                    "generator successor negative fixture",
                )
            });
            assert!(
                rejected.is_err(),
                "second impl, fourth method, widened visibility, borrowed receiver, or raw getter must be rejected"
            );
        }
    }

    fn assert_d6b_successor_impl_location_closure_fixtures_v1() {
        let selected = "impl AlphaV1 {} impl BetaV1 {}";
        let expected = ["implAlphaV1".to_owned(), "implBetaV1".to_owned()];
        let imports = "use contract::{FdRoleV1 as ContractFdRoleV1, MAX_FRAME_BYTES_V1 as CONTRACT_MAX_FRAME_BYTES_V1, MAX_FRAME_FDS_V1 as CONTRACT_MAX_FRAME_FDS_V1};";
        let valid = format!(
            "{imports} mod strict_model {{ pub(super) mod selected_target {{ {selected} }} }}"
        );
        assert_eq!(super::d6b_exact_impl_inventory_v1(selected), expected);
        let masked_decoys = format!(
            "// impl CommentV1 {{}}\nconst NOTE: &str = \"impl StringV1 {{}}\"; #[cfg(test)] mod tests {{ impl TestOnlyV1 {{}} }} {selected}"
        );
        assert_eq!(
            super::d6b_exact_impl_inventory_v1(&masked_decoys),
            expected,
            "comments, strings, and cfg(test) items must not contaminate production impl inventory"
        );
        for mutant in [
            format!("impl GammaV1 {{ pub(crate) fn retry(self) -> Self {{ self }} }} {valid}"),
            format!(
                "pub(crate) trait RetryV1: Sized {{ fn retry(self) -> Self {{ self }} }} impl<T> RetryV1 for T {{}} {valid}"
            ),
        ] {
            assert!(
                super::d6b_exact_impl_inventory_v1(&mutant) != expected,
                "a direct or blanket impl before strict_model must change the D6b whole-file inventory"
            );
        }
        let valid_aliases =
            super::d6b_rust_use_aliases_v1(&super::d6b_rust_identifier_tokens_v1(&valid));
        let aliased = format!("use strict_model::selected_target::AlphaV1 as Hidden; {valid}");
        assert_ne!(
            super::d6b_rust_use_aliases_v1(&super::d6b_rust_identifier_tokens_v1(&aliased)),
            valid_aliases,
            "a successor alias must change the D6b whole-file inventory"
        );
        let function_valid = "pub(crate) fn enqueue_once_v1(self, credentials: UCred) -> Result<SupervisorGeneratorSentEndpointV1, AncillarySendErrorV1> { unreachable!() } pub(crate) fn enqueue_once_v1(self, credentials: UCred) -> Result<WorkerBootstrapEnqueuedEndpointV1, AncillarySendErrorV1> { unreachable!() }";
        super::assert_d6b_successor_function_closure_v1(function_valid);
        let function_mutant = format!(
            "pub(crate) fn retry(value: SupervisorGeneratorSentEndpointV1) -> SupervisorGeneratorSentEndpointV1 {{ value }} {function_valid}"
        );
        let rejected = std::panic::catch_unwind(|| {
            super::assert_d6b_successor_function_closure_v1(&function_mutant)
        });
        assert!(
            rejected.is_err(),
            "a named successor retry function before strict_model must be rejected"
        );
    }

    #[test]
    fn supervisor_explicit_scm_credentials_v1() {
        let ancillary = ancillary_production(include_str!("ancillary.rs"));
        let helper = send_helper(ancillary);
        let helper_normalized = normalized(helper);

        assert_eq!(
            ancillary.matches("rustix::net::sendmsg(").count(),
            1,
            "D6b must preserve one sole private sendmsg call"
        );
        assert_eq!(
            helper
                .matches("SendAncillaryMessage::ScmCredentials(")
                .count(),
            1,
            "the sole helper must have exactly one explicit credential construction site"
        );
        assert!(
            helper_normalized.contains(
                "rustix::cmsg_space!(ScmCredentials(1),ScmRights(CONTRACT_MAX_FRAME_FDS_V1))"
            ),
            "the bounded control buffer must reserve one credential and the fixed rights maximum"
        );
        assert_eq!(helper.matches("ScmCredentials(1)").count(), 1);
        assert!(helper.contains("credential_source: SendCredentialSourceV1"));
        assert!(helper.contains("SendCredentialSourceV1::ExplicitSupervisor(credentials)"));
        assert!(!helper.contains("Option<UCred>"));
        for forbidden in [
            "rustix::net::sendmmsg(",
            "libc::sendmsg(",
            "libc::sendmmsg(",
            "SYS_SENDMSG",
            "SYS_SENDMMSG",
            "fn sendmmsg(",
        ] {
            assert!(
                !ancillary.contains(forbidden),
                "alternate or raw send path bypasses the sole helper: {forbidden}"
            );
        }
        for forbidden in ["loop {", "while ", "EINTR", "retry", "resend"] {
            assert!(
                !helper.contains(forbidden),
                "the one-shot helper acquired a cursor or retry path: {forbidden}"
            );
        }
    }

    #[test]
    fn supervisor_channel_identity_is_worker_service_v1() {
        let root = include_str!("lib.rs").split("#[cfg(test)]").next().unwrap();
        let ancillary = ancillary_production(include_str!("ancillary.rs"));
        let process = include_str!("process.rs");
        let custody = selected_production(
            include_str!("executable_custody.rs"),
            "pub(crate) use selected_target::*;",
        );
        for required in [
            "pub(crate) const WORKER_OUTER_UID_V1: u32 = 20_002;",
            "pub(crate) const WORKER_OUTER_GID_V1: u32 = 20_002;",
        ] {
            assert!(
                process.contains(required),
                "process.rs must remain the sole fixed worker-service source: {required}"
            );
        }
        assert!(!process.contains("pub const WORKER_OUTER_UID_V1"));
        assert!(!process.contains("pub const WORKER_OUTER_GID_V1"));
        assert_eq!(process.matches("20_002").count(), 2);
        assert!(!ancillary.contains("20_002"));
        assert!(!custody.contains("20_002"));
        assert!(!root.contains("20_002"));
        assert!(g0b_worker_service_identity_source_is_exact_v1(
            include_str!("ancillary.rs"),
            process,
        ));

        let generator = braced_item(
            process,
            "pub(crate) fn enqueue_supervisor_generator_once_v1(",
            "process-owned generator send",
        );
        let worker = braced_item(
            process,
            "pub(crate) fn enqueue_supervisor_bootstrap_once_v1(",
            "process-owned worker-bootstrap send",
        );
        for method in [generator, worker] {
            for required in [
                "let credentials = UCred {",
                "uid: Uid::from_raw(WORKER_OUTER_UID_V1),",
                "gid: Gid::from_raw(WORKER_OUTER_GID_V1),",
            ] {
                assert!(
                    method.contains(required),
                    "process-owned S send omits worker-service identity: {required}"
                );
            }
            assert_eq!(method.matches("let credentials = UCred {").count(), 1);
            for forbidden in [
                "Uid::ROOT",
                "Gid::ROOT",
                "GENERATOR_UID_V1",
                "GENERATOR_GID_V1",
                "getuid()",
                "geteuid()",
                "getgid()",
                "getegid()",
                "from_raw(0)",
            ] {
                assert!(
                    !method.contains(forbidden),
                    "actual, root, or generator identity replaced the channel claim: {forbidden}"
                );
            }
        }

        let claim_text = format!("{process}\n{ancillary}");
        for required in [
            "kernel-delivered and kernel-validated privileged channel-identity claim",
            "not proof of S's actual UID/GID",
            "receiver cardinality is not sender construction proof",
        ] {
            assert!(
                claim_text.contains(required),
                "D6b must retain its bounded claim ceiling: {required}"
            );
        }
    }

    #[test]
    fn supervisor_claimed_pid_is_current_retained_pid_v1() {
        let root = include_str!("lib.rs").split("#[cfg(test)]").next().unwrap();
        let ancillary = ancillary_production(include_str!("ancillary.rs"));
        let process = include_str!("process.rs");
        let custody = selected_production(
            include_str!("executable_custody.rs"),
            "pub(crate) use selected_target::*;",
        );

        let projection_declarations = exact_slice(
            root,
            "#[cfg(all(target_arch = \"x86_64\", target_os = \"linux\", target_env = \"musl\"))]\n#[derive(Eq, PartialEq)]\npub(crate) struct SupervisorReceiveProjectionV1 {",
            "/// Sole selected target triple for executable ABI code.",
            "two root-private E4e projections",
        );
        assert_eq!(
            normalized(projection_declarations),
            normalized(
                "#[cfg(all(target_arch = \"x86_64\", target_os = \"linux\", target_env = \"musl\"))]
#[derive(Eq, PartialEq)]
pub(crate) struct SupervisorReceiveProjectionV1 {
    child_to_supervisor_expected: ancillary::ExpectedPeerCredentialsV1,
    child_to_supervisor_credentials: eip0045_h0_contract::wire::PeerCredentialsV1,
    supervisor_receiver_user_namespace_identity: eip0045_h0_contract::wire::DescriptorIdentityV1,
    supervisor_to_generator: Option<eip0045_h0_contract::wire::PeerCredentialsV1>,
}

#[cfg(all(target_arch = \"x86_64\", target_os = \"linux\", target_env = \"musl\"))]
#[derive(Eq, PartialEq)]
pub(crate) struct WorkerBootstrapProjectionV1 {
    supervisor_to_worker_credentials: eip0045_h0_contract::wire::PeerCredentialsV1,
    worker_receiver_view_uid: u32,
    worker_receiver_view_gid: u32,
    supervisor_receiver_user_namespace_identity: eip0045_h0_contract::wire::DescriptorIdentityV1,
}

"
            ),
            "D6b must not add PID, credential, authority, or any other field to the two E4e projections"
        );
        for forbidden in [
            "supervisor_process_id",
            "rustix::process::Pid",
            "UCred",
            "impl SupervisorReceiveProjectionV1",
            "impl WorkerBootstrapProjectionV1",
            "fn supervisor_process_id(",
            "fn process_id(",
            "fn pid(",
            "SupervisorCredentialProjectionV1",
            "SupervisorSendAuthorityV1",
            "CredentialAuthorityV1",
        ] {
            assert!(
                !projection_declarations.contains(forbidden),
                "retained supervisor PID escaped or became detached authority: {forbidden}"
            );
        }

        let generator = braced_item(
            process,
            "pub(crate) fn enqueue_supervisor_generator_once_v1(",
            "process-owned generator send",
        );
        let worker = braced_item(
            process,
            "pub(crate) fn enqueue_supervisor_bootstrap_once_v1(",
            "process-owned worker-bootstrap send",
        );
        for (method, pre, projection) in [
            (
                generator,
                "let before = self.reauthenticate_live_snapshot_v1()?;",
                "let projection = self.supervisor_receive_projection_from_snapshot_v1(before)?;",
            ),
            (
                worker,
                "let before = self.child.reauthenticate_live_snapshot_v1()?;",
                "let projection = self.worker_bootstrap_projection_from_snapshot_v1(checked, before)?;",
            ),
        ] {
            let pre_offset = method.find(pre).expect("fresh retained S snapshot");
            let projection_offset = method
                .find(projection)
                .expect("E4e projection must derive from the same fresh snapshot");
            let pid_offset = method
                .find("rustix::process::Pid::from_raw(before.process_id)")
                .expect("typed PID must derive from that same fresh snapshot");
            let credential_offset = method
                .find("let credentials = UCred {")
                .expect("ephemeral explicit credential must be process-owned");
            let enqueue_offset = method
                .find("op.enqueue_once_v1(credentials)?")
                .expect("credential must be consumed immediately by the sealed operation");
            let post_offset = method
                .find("let after = ")
                .expect("missing post-send retained S reauthentication");
            let equality_offset = method
                .find("if before != after")
                .expect("retained S snapshot drift must reject");
            let success_offset = method
                .find("Ok((projection, endpoint))")
                .expect("only the projection and opaque endpoint may escape success");
            assert!(
                pre_offset < projection_offset
                    && projection_offset < pid_offset
                    && pid_offset < credential_offset
                    && credential_offset < enqueue_offset
                    && enqueue_offset < post_offset
                    && post_offset < equality_offset
                    && equality_offset < success_offset,
                "same-snapshot PID-to-UCred-to-send causal order drifted"
            );
            assert_eq!(method.matches("rustix::process::Pid::from_raw(").count(), 1);
            assert_eq!(method.matches("let credentials = UCred {").count(), 1);
            assert!(method.contains("pid: supervisor_pid,"));
            for forbidden in [
                "rustix::process::getpid(",
                "getpid(",
                "self.pid()",
                "self.child.pid()",
                "checked.pid",
                "Pid::from_raw(0)",
                "Pid::from_raw(op",
            ] {
                assert!(
                    !method.contains(forbidden),
                    "foreign, cached, zero, or detached PID source survived: {forbidden}"
                );
            }
        }
        assert_eq!(process.matches("let credentials = UCred {").count(), 2);
        assert_eq!(
            process
                .matches("rustix::process::Pid::from_raw(before.process_id)")
                .count(),
            2
        );
        for outside_process in [root, custody] {
            assert!(!outside_process.contains("Pid::from_raw("));
            assert!(!outside_process.contains("Pid::from_raw_unchecked("));
            assert!(!outside_process.contains("getpid("));
            assert!(!outside_process.contains("UCred {"));
        }
        let generator_credentials = braced_item(
            ancillary,
            "fn generator_outbound_credentials_v1(",
            "generator kernel-observed outbound credentials",
        );
        assert_eq!(ancillary.matches("getpid(").count(), 1);
        assert!(generator_credentials.contains("getpid()"));
        assert!(!generator_credentials.contains("UCred {"));
        for forbidden in [
            "pub fn supervisor_process_id(",
            "pub(crate) fn supervisor_process_id(",
            "pub fn process_id(",
            "pub(crate) fn process_id(",
            "pub fn pid(",
            "pub(crate) fn pid(",
            "impl AsRef<SupervisorReceiveProjectionV1",
            "impl AsRef<WorkerBootstrapProjectionV1",
        ] {
            assert!(
                !ancillary.contains(forbidden) && !custody.contains(forbidden),
                "D6b projection/PID facade or getter escaped process ownership: {forbidden}"
            );
        }
        for source in [root, ancillary, process, custody] {
            assert!(!source.contains("CAP_SYS_ADMIN"));
        }
    }

    #[test]
    fn supervisor_credential_cmsg_precedes_rights_v1() {
        let ancillary = ancillary_production(include_str!("ancillary.rs"));
        let helper = send_helper(ancillary);
        let credential = helper
            .find("control.push(SendAncillaryMessage::ScmCredentials(credentials))")
            .expect("sole helper must push its one explicit credential");
        let rights = helper
            .find("control.push(SendAncillaryMessage::ScmRights(&borrowed_descriptors))")
            .expect("sole helper must retain its ordered rights push");
        let syscall = helper
            .find("rustix::net::sendmsg(")
            .expect("sole helper must retain one kernel enqueue");

        assert!(
            credential < rights && rights < syscall,
            "SCM_CREDENTIALS must be serialized before optional SCM_RIGHTS and sendmsg"
        );
        assert_eq!(
            helper
                .matches("control.push(SendAncillaryMessage::ScmCredentials(credentials))")
                .count(),
            1
        );
        assert_eq!(
            helper
                .matches("control.push(SendAncillaryMessage::ScmRights(&borrowed_descriptors))")
                .count(),
            1
        );
        assert_eq!(helper.matches("control.push(").count(), 2);
        assert_eq!(helper.matches("rustix::net::sendmsg(").count(), 1);
        assert!(helper.contains("if !borrowed_descriptors.is_empty() {"));
        assert!(helper.contains("SendCredentialSourceV1::ExplicitSupervisor(credentials)"));
        for forbidden in ["loop {", "while ", "retry", "resend", "EINTR"] {
            assert!(!helper.contains(forbidden));
        }
    }

    #[test]
    fn child_sends_use_automatic_real_credentials_v1() {
        let ancillary = ancillary_production(include_str!("ancillary.rs"));
        let generator_helper = braced_item(
            ancillary,
            "fn send_generator_pre_session_record_once_v1(",
            "generator pre-session send helper",
        );
        let generator_commit = braced_item(
            ancillary,
            "impl GeneratorPeerGCommitSendEndpointV1 {",
            "generator commitment send state",
        );
        let generator_reveal = braced_item(
            ancillary,
            "impl GeneratorPeerGRevealSendEndpointV1 {",
            "generator reveal send state",
        );
        let worker = exact_slice(
            ancillary,
            "impl WorkerEndpointV1",
            "/// Generator-channel endpoint custody",
            "worker child endpoint",
        );
        let generator_bound = braced_item(
            ancillary,
            "impl GeneratorProviderSessionEndpointV1 {",
            "GeneratorBound child send state",
        );

        assert!(normalized(generator_helper).contains(
            "send_seqpacket_once_v1(endpoint,record,&[],SendCredentialSourceV1::AutomaticChild,)"
        ));
        assert_eq!(
            generator_helper.matches("send_seqpacket_once_v1(").count(),
            1
        );
        assert!(!generator_helper.contains("pub fn send_generator_pre_session_record_once_v1"));
        for (state, expected_record) in [
            (generator_commit, "generator_commit.bytes()"),
            (generator_reveal, "generator_reveal.bytes()"),
        ] {
            assert_eq!(
                state
                    .matches("send_generator_pre_session_record_once_v1(")
                    .count(),
                1
            );
            assert!(state.contains(expected_record));
            assert!(!state.contains("send_seqpacket_once_v1("));
        }
        let worker_normalized = normalized(worker);
        assert!(!worker_normalized.contains("SendCredentialSourceV1::AutomaticChild"));
        assert_eq!(worker.matches("send_seqpacket_once_v1(").count(), 0);
        assert!(normalized(generator_bound).contains(
            "send_seqpacket_once_v1(endpoint,outbound.bytes(),&[],SendCredentialSourceV1::AutomaticChild,)"
        ));
        assert_eq!(
            generator_bound.matches("send_seqpacket_once_v1(").count(),
            1
        );
        for child in [
            generator_helper,
            generator_commit,
            generator_reveal,
            generator_bound,
            worker,
        ] {
            for forbidden in [
                "ScmCredentials",
                "UCred",
                "SupervisorGenerator",
                "SupervisorWorkerBootstrap",
                "WORKER_OUTER_UID_V1",
                "WORKER_OUTER_GID_V1",
            ] {
                assert!(
                    !child.contains(forbidden),
                    "child send gained an explicit-credential choice: {forbidden}"
                );
            }
        }
        assert_eq!(
            ancillary
                .matches("send_generator_pre_session_record_once_v1(")
                .count(),
            3,
            "only the private helper definition plus GCommit and GReveal may use the generator pre-session route"
        );
        assert_eq!(
            ancillary
                .matches("SendCredentialSourceV1::AutomaticChild")
                .count(),
            3,
            "only the two reachable typed child calls plus the helper match arm may select automatic credentials"
        );
    }

    #[test]
    fn explicit_credential_send_is_role_closed_v1() {
        assert_g0a_generator_successor_impl_fixtures_v1();
        assert_d6b_successor_impl_location_closure_fixtures_v1();
        super::assert_d6b_source_extension_closure_fixtures_v1();
        super::assert_d6b_protected_operation_method_closure_fixtures_v1();
        super::assert_d6b_session_red_registration_fixtures_v1();
        let root_source = include_str!("lib.rs");
        let ancillary_source = include_str!("ancillary.rs");
        let process_source = include_str!("process.rs");
        let custody_source = include_str!("executable_custody.rs");
        let session_source = include_str!("session.rs");
        assert!(
            g0a_ancillary_feature_isolated_v1(ancillary_source),
            "every G0a-specific ancillary import, state, field, method, helper, and re-export must be compiled only with the exact non-default feature"
        );
        let feature_gate_mutant =
            ancillary_source.replacen(G0A_FEATURE_GATE_V1, "#[cfg(any())]", 1);
        assert!(
            !g0a_ancillary_feature_isolated_v1(&feature_gate_mutant),
            "removing one exact G0a feature gate must be rejected"
        );
        let mut comment_and_duplicate_gate_mutant =
            ancillary_source.replacen(G0A_FEATURE_GATE_V1, &format!("// {G0A_FEATURE_GATE_V1}"), 1);
        let duplicate_at = comment_and_duplicate_gate_mutant
            .find("struct PreparedSupervisorReceiveV1 {")
            .expect("prepared receive state exists in the causal cfg mutant");
        comment_and_duplicate_gate_mutant
            .insert_str(duplicate_at, &format!("{G0A_FEATURE_GATE_V1}\n        "));
        assert!(
            !g0a_ancillary_feature_isolated_v1(&comment_and_duplicate_gate_mutant),
            "a commented cfg plus a duplicated active cfg must not preserve G0a isolation"
        );
        let moved_g0_imports_mutant = ancillary_source
            .replacen(", WireErrorV1", "", 1)
            .replacen("WireFrameV1,", "", 1)
            .replacen(
                "SeqpacketEndpointCommitmentV1,",
                "SeqpacketEndpointCommitmentV1, WireErrorV1, WireFrameV1,",
                1,
            );
        let added_base_import_mutant = ancillary_source.replacen(
            "ChannelIdentityV1,",
            "ChannelIdentityV1, AlternateContractNameV1,",
            1,
        );
        let permuted_imports_mutant = ancillary_source
            .replacen("ChannelIdentityV1,", "__G0A_IMPORT_SWAP__,", 1)
            .replacen("G0TranscriptCandidateV1,", "ChannelIdentityV1,", 1)
            .replacen("__G0A_IMPORT_SWAP__,", "G0TranscriptCandidateV1,", 1);
        for mutant in [
            moved_g0_imports_mutant,
            added_base_import_mutant,
            permuted_imports_mutant,
        ] {
            assert!(
                !g0a_ancillary_feature_isolated_v1(&mutant),
                "the ordered base/G0 contract import inventories must remain exact"
            );
        }
        super::assert_d6b_session_red_registration_v1(root_source, session_source);
        super::assert_d6b_source_extension_closure_v1(&[
            ("lib.rs", root_source),
            ("process.rs", process_source),
            ("executable_custody.rs", custody_source),
            ("ancillary.rs", ancillary_source),
            ("session.rs", session_source),
            ("seccomp.rs", include_str!("seccomp.rs")),
            ("statx.rs", include_str!("statx.rs")),
        ]);
        let root_production = super::d6b_production_without_tests_v1(root_source);
        let root = root_production.as_str();
        let ancillary = ancillary_production(ancillary_source);
        super::assert_d6b_successor_impl_location_closure_v1(ancillary_source, ancillary);
        let process_production = super::d6b_production_without_tests_v1(process_source);
        let process = process_production.as_str();
        let custody_production = super::d6b_production_without_tests_v1(custody_source);
        let custody = custody_production.as_str();
        super::assert_d6b_role_closure_v1(&[
            ("lib.rs", root),
            ("ancillary.rs", ancillary),
            ("process.rs", process),
            ("custody.rs", custody),
        ]);
        let helper = send_helper(ancillary);
        let policy = braced_item(
            ancillary,
            "enum SendCredentialSourceV1",
            "closed credential-source policy",
        );
        assert_eq!(
            normalized(policy),
            "enumSendCredentialSourceV1{AutomaticChild,ExplicitSupervisor(UCred),}",
            "the private helper has exactly automatic-child or explicit-supervisor modes"
        );
        assert!(!policy.contains("pub enum"));
        assert!(!policy.contains("pub(crate) enum"));
        for forbidden in [
            "SupervisorReceiveProjectionV1",
            "WorkerBootstrapProjectionV1",
            "Authority",
            "Token",
        ] {
            assert!(!policy.contains(forbidden));
        }

        let generator_op = braced_item(
            ancillary,
            "pub(crate) struct SupervisorGeneratorSendOpV1",
            "sealed generator send operation",
        );
        let worker_op = braced_item(
            ancillary,
            "pub(crate) struct SupervisorWorkerBootstrapSendOpV1",
            "sealed worker-bootstrap send operation",
        );
        for op in [generator_op, worker_op] {
            assert!(
                op.lines()
                    .skip(1)
                    .all(|line| !line.trim_start().starts_with("pub")),
                "sealed operation fields must remain private"
            );
            for forbidden in [
                "cursor",
                "count",
                "retry",
                "resend",
                "UCred",
                "Pid",
                "Uid",
                "Gid",
                "Box<[u8]>",
                "Vec<OwnedFd>",
                "&[u8]",
            ] {
                assert!(
                    !op.contains(forbidden),
                    "sealed operation stores credential or transition authority: {forbidden}"
                );
            }
        }

        let generator_op_impl = braced_item(
            ancillary,
            "impl SupervisorGeneratorSendOpV1",
            "sealed generator send implementation",
        );
        let worker_op_impl = braced_item(
            ancillary,
            "impl SupervisorWorkerBootstrapSendOpV1",
            "sealed worker-bootstrap send implementation",
        );
        for op_impl in [generator_op_impl, worker_op_impl] {
            let enqueue_signature = signature(op_impl, "pub(crate) fn enqueue_once_v1(");
            assert!(enqueue_signature.contains("self,"));
            assert!(enqueue_signature.contains("credentials: UCred,"));
            for forbidden in [
                "Box<[u8]>",
                "Vec<OwnedFd>",
                "&[u8]",
                "rustix::process::Pid",
                "rustix::ugid::Uid",
                "rustix::ugid::Gid",
                "cursor",
                "count",
                "retry",
                "resend",
            ] {
                assert!(
                    !enqueue_signature.contains(forbidden),
                    "sealed operation accepts caller-selected transport state: {forbidden}"
                );
            }
            assert_eq!(op_impl.matches("send_seqpacket_once_v1(").count(), 1);
            assert_eq!(
                op_impl
                    .matches("SendCredentialSourceV1::ExplicitSupervisor(credentials)")
                    .count(),
                1
            );
            for forbidden in [
                "Err((",
                "Err { endpoint",
                "return Ok(self)",
                "loop {",
                "while ",
            ] {
                assert!(!op_impl.contains(forbidden));
            }
        }

        let worker_successor_declaration = exact_slice(
            ancillary,
            "/// Opaque kernel-success state for the exact worker-bootstrap packet.",
            "impl WorkerBootstrapEnqueuedEndpointV1 {",
            "opaque worker enqueue-success declaration",
        );
        assert!(!worker_successor_declaration.contains("#[derive("));
        assert_eq!(
            ancillary
                .matches("impl WorkerBootstrapEnqueuedEndpointV1 {")
                .count(),
            1,
            "the opaque worker successor must have one closed inherent implementation"
        );
        let worker_successor_impl = braced_item(
            ancillary,
            "impl WorkerBootstrapEnqueuedEndpointV1 {",
            "opaque worker enqueue-success implementation",
        );
        let worker_successor_scope = exact_slice(
            ancillary,
            "pub(crate) struct WorkerChannelV1 {",
            "fn descriptor_identity_v1(",
            "opaque worker enqueue-success scope",
        );
        for forbidden in ["Clone", "Copy", "Default"] {
            assert!(
                !worker_successor_scope.contains(forbidden),
                "opaque worker successor gained derive/trait authority: {forbidden}"
            );
        }
        assert_eq!(
            super::d6b_function_signatures_v1(worker_successor_impl).len(),
            2
        );
        assert_eq!(
            worker_successor_impl
                .matches("pub(crate) fn receive_worker_exec_bound_once_v1(")
                .count(),
            1,
            "the worker successor must expose its one consuming exec-bound receive"
        );
        assert_eq!(
            worker_successor_impl
                .matches("pub(crate) fn receive_worker_frame_v1(")
                .count(),
            1,
            "the worker successor must retain its one borrowed typed receive"
        );
        let worker_exec_bound_receive_signature = signature(
            worker_successor_impl,
            "pub(crate) fn receive_worker_exec_bound_once_v1(",
        );
        assert_eq!(
            normalized(worker_exec_bound_receive_signature),
            "pub(crate)fnreceive_worker_exec_bound_once_v1(self,input:WorkerExecBoundReceiveInputV1,previous_digest:[u8;32],)->Result<(WorkerExecBoundReceivedEndpointV1,G0TranscriptCandidateV1),SupervisorTypedTransitionErrorV1,>"
        );
        let worker_receive_signature = signature(
            worker_successor_impl,
            "pub(crate) fn receive_worker_frame_v1(",
        );
        assert_eq!(
            normalized(worker_receive_signature),
            "pub(crate)fnreceive_worker_frame_v1(&self,frame_buffer:&mut[u8;CONTRACT_MAX_FRAME_BYTES_V1],expectation:&StrictReceiveExpectationV1,)->Result<ReceivedFrameV1,AncillaryReceiveErrorV1>"
        );
        for forbidden in [
            "fn into_parts",
            "fn endpoint",
            "fn descriptor",
            "fn retry",
            "fn resend",
            "Box<[u8]>",
            "Vec<OwnedFd>",
            "BorrowedFd",
            "OwnedFd",
            "RawFd",
            "UCred",
            "&[u8]",
        ] {
            assert!(
                !worker_successor_impl.contains(forbidden),
                "opaque worker successor gained raw or generic authority: {forbidden}"
            );
        }

        assert_g0a_generator_successor_impl_v1(
            ancillary,
            "opaque G0a generator enqueue-success implementation",
        );
        let generator_successor_declaration = exact_slice(
            ancillary,
            "/// Opaque same-endpoint custody after one supervisor-to-generator",
            "impl SupervisorGeneratorSendOpV1 {",
            "opaque generator enqueue-success declaration",
        );
        assert!(!generator_successor_declaration.contains("#[derive("));
        let generator_successor_scope = exact_slice(
            ancillary,
            "pub(crate) struct SupervisorGeneratorEndpointV1",
            "impl SupervisorGeneratorSendOpV1 {",
            "opaque generator enqueue-success scope",
        );
        for forbidden in ["Clone", "Copy", "Default"] {
            assert!(
                !generator_successor_scope.contains(forbidden),
                "opaque generator successor gained derive/trait authority: {forbidden}"
            );
        }
        for forbidden in [
            "AsFd for WorkerBootstrapEnqueuedEndpointV1",
            "AsRawFd for WorkerBootstrapEnqueuedEndpointV1",
            "Clone for WorkerBootstrapEnqueuedEndpointV1",
            "Copy for WorkerBootstrapEnqueuedEndpointV1",
            "Default for WorkerBootstrapEnqueuedEndpointV1",
            "WorkerBootstrapEnqueuedEndpointV1::default",
            "AsFd for SupervisorGeneratorSentEndpointV1",
            "AsRawFd for SupervisorGeneratorSentEndpointV1",
            "Clone for SupervisorGeneratorSentEndpointV1",
            "Copy for SupervisorGeneratorSentEndpointV1",
            "Default for SupervisorGeneratorSentEndpointV1",
            "SupervisorGeneratorSentEndpointV1::default",
        ] {
            assert!(
                !ancillary.contains(forbidden),
                "opaque D6b successor gained a raw or duplicating trait: {forbidden}"
            );
        }

        let generator_process = braced_item(
            process,
            "pub(crate) fn enqueue_supervisor_generator_once_v1(",
            "process-owned generator send",
        );
        let worker_process = braced_item(
            process,
            "pub(crate) fn enqueue_supervisor_bootstrap_once_v1(",
            "process-owned worker-bootstrap send",
        );
        let generator_process_signature = signature(
            process,
            "pub(crate) fn enqueue_supervisor_generator_once_v1(",
        );
        let worker_process_signature = signature(
            process,
            "pub(crate) fn enqueue_supervisor_bootstrap_once_v1(",
        );
        let generator_process_signature = normalized(generator_process_signature);
        let worker_process_signature = normalized(worker_process_signature);
        assert!(generator_process_signature.contains(
            "&self,op:SupervisorGeneratorSendOpV1,)->Result<(SupervisorReceiveProjectionV1,SupervisorGeneratorSentEndpointV1),"
        ));
        assert!(worker_process_signature.contains(
            "&self,checked:&CheckedWorkerMapsV1,op:SupervisorWorkerBootstrapSendOpV1,)->Result<(WorkerBootstrapProjectionV1,WorkerBootstrapEnqueuedEndpointV1),"
        ));
        for method in [generator_process, worker_process] {
            assert_eq!(
                method.matches("op.enqueue_once_v1(credentials)?").count(),
                1
            );
            assert_eq!(method.matches("Ok((projection, endpoint))").count(), 1);
            for forbidden in [
                "SendCredentialSourceV1",
                "Box<[u8]>",
                "Vec<OwnedFd>",
                "&[u8]",
                "cursor",
                "count",
                "retry",
                "resend",
                "Err((",
                "Err { endpoint",
            ] {
                assert!(
                    !method.contains(forbidden),
                    "process-owned role join exposes transport or retry choice: {forbidden}"
                );
            }
        }

        let generator_custody_signature = signature(
            custody,
            "pub(crate) fn enqueue_supervisor_generator_once_v1(",
        );
        let worker_custody_signature = signature(
            custody,
            "pub(crate) fn enqueue_supervisor_bootstrap_once_v1(",
        );
        for (method, op) in [
            (generator_custody_signature, "SupervisorGeneratorSendOpV1"),
            (
                worker_custody_signature,
                "SupervisorWorkerBootstrapSendOpV1",
            ),
        ] {
            assert!(method.contains("&self,"));
            assert!(method.contains(op));
            for forbidden in [
                "UCred",
                "rustix::process::Pid",
                "rustix::ugid::Uid",
                "rustix::ugid::Gid",
                "Box<[u8]>",
                "Vec<OwnedFd>",
                "&[u8]",
                "cursor",
                "count",
                "retry",
                "resend",
            ] {
                assert!(!method.contains(forbidden));
            }
        }

        assert_eq!(root.matches("ProjectionV1 {").count(), 2);
        for forbidden in [
            "SupervisorCredentialProjectionV1",
            "SupervisorSendAuthorityV1",
            "CredentialAuthorityV1",
            "pub fn send_seqpacket_once_v1",
            "pub(crate) fn send_seqpacket_once_v1",
            "pub(super) fn send_seqpacket_once_v1",
        ] {
            assert!(
                !ancillary.contains(forbidden),
                "D6b added a projection, authority, or raw send escape: {forbidden}"
            );
        }
        assert_eq!(
            ancillary
                .matches("SendCredentialSourceV1::ExplicitSupervisor")
                .count(),
            3,
            "only two sealed op calls plus the helper match arm may select explicit credentials"
        );
        assert!(!process.contains("SendCredentialSourceV1"));
        assert!(!custody.contains("SendCredentialSourceV1"));
        assert!(!root.contains("SendCredentialSourceV1"));
        let normalized_ancillary = ancillary.split_whitespace().collect::<String>();
        assert!(!normalized_ancillary.contains(
            "pub(crate)fnenqueue_worker_bootstrap_once(self,frame:Box<[u8]>,descriptors:Vec<OwnedFd>,"
        ));
        for forbidden in [
            "#[derive(Clone)]\npub(crate) struct SupervisorGeneratorSendOpV1",
            "#[derive(Copy)]\npub(crate) struct SupervisorGeneratorSendOpV1",
            "#[derive(Debug)]\npub(crate) struct SupervisorGeneratorSendOpV1",
            "#[derive(Clone)]\npub(crate) struct SupervisorWorkerBootstrapSendOpV1",
            "#[derive(Copy)]\npub(crate) struct SupervisorWorkerBootstrapSendOpV1",
            "#[derive(Debug)]\npub(crate) struct SupervisorWorkerBootstrapSendOpV1",
        ] {
            assert!(!ancillary.contains(forbidden));
        }
        for scope in [
            generator_op_impl,
            worker_op_impl,
            generator_process,
            worker_process,
            helper,
        ] {
            for forbidden in [
                "cursor",
                "count",
                "retry",
                "resend",
                "Err((",
                "Err { endpoint",
            ] {
                assert!(
                    !scope.contains(forbidden),
                    "D6b operation acquired state advance, retry, or endpoint-on-error: {forbidden}"
                );
            }
        }

        let public_exports = exact_slice(
            ancillary_source,
            "pub use strict_model::selected_target::{",
            "pub(crate) use strict_model::selected_target::{",
            "public ancillary exports",
        );
        for forbidden in [
            "SupervisorGeneratorSendOpV1",
            "SupervisorWorkerBootstrapSendOpV1",
            "SupervisorGeneratorSentEndpointV1",
            "SendCredentialSourceV1",
            "UCred",
        ] {
            assert!(!public_exports.contains(forbidden));
        }
    }

    fn g0b_worker_service_identity_source_is_exact_v1(
        ancillary_source: &str,
        process_source: &str,
    ) -> bool {
        let ancillary = super::d6b_production_without_tests_v1(ancillary_source);
        let process = super::d6b_production_without_tests_v1(process_source);
        let ancillary_mask = super::d6b_rust_code_mask_v1(&ancillary);
        let process_mask = super::d6b_rust_code_mask_v1(&process);
        let normalized_ancillary = normalized(&ancillary_mask);
        let normalized_process = normalized(&process_mask);
        let import = "usecrate::process::{WORKER_OUTER_GID_V1,WORKER_OUTER_UID_V1};";
        let credential_join = "ExpectedPeerCredentialsV1::try_new(supervisor_pid,WORKER_OUTER_UID_V1,WORKER_OUTER_GID_V1,)";
        let supervisor_pid_source =
            "letexpected=expected_supervisor_credentials_v1(supervisor_pid)?;";

        immediately_feature_gated_v1(&ancillary, &ancillary_mask, "use crate::process::{", 1)
            && normalized_ancillary.matches(import).count() == 1
            && !normalized_ancillary.contains("20_002")
            && normalized_ancillary.matches("WORKER_OUTER_UID_V1").count() == 2
            && normalized_ancillary.matches("WORKER_OUTER_GID_V1").count() == 2
            && normalized_ancillary.matches(credential_join).count() == 1
            && normalized_ancillary.matches(supervisor_pid_source).count() == 1
            && normalized_process.matches("20_002").count() == 2
            && normalized_process
                .matches("pub(crate)constWORKER_OUTER_UID_V1:u32=20_002;")
                .count()
                == 1
            && normalized_process
                .matches("pub(crate)constWORKER_OUTER_GID_V1:u32=20_002;")
                .count()
                == 1
            && !normalized_process.contains("pubconstWORKER_OUTER_UID_V1")
            && !normalized_process.contains("pubconstWORKER_OUTER_GID_V1")
    }

    fn g0b_worker_prebootstrap_surface_is_closed_v1(source: &str) -> bool {
        let production = super::d6b_production_without_tests_v1(source);
        let Some(start) = production.find("impl WorkerEndpointV1 {") else {
            return false;
        };
        let Some(relative_end) = production[start..].find("/// Generator-channel endpoint custody")
        else {
            return false;
        };
        let worker = &production[start..start + relative_end];
        let normalized_worker = normalized(&super::d6b_rust_code_mask_v1(worker));
        normalized_worker
            == "implWorkerEndpointV1{pub(crate)fndescriptor(&self)->BorrowedFd<'_>{self.0.descriptor.as_fd()}}"
            && [
                "WorkerExecBoundSendInputV1",
                "WorkerExecBoundSentEndpointV1",
                "send_worker_exec_bound_once_v1",
            ]
            .iter()
            .all(|forbidden| !production.contains(forbidden))
    }

    fn assert_g0b_worker_prebootstrap_surface_fixtures_v1() {
        let valid = r#"
            pub struct WorkerEndpointV1(SeqpacketEndpointV1);
            impl WorkerEndpointV1 {
                pub(crate) fn descriptor(&self) -> BorrowedFd<'_> {
                    self.0.descriptor.as_fd()
                }
            }
            /// Generator-channel endpoint custody
        "#;
        assert!(g0b_worker_prebootstrap_surface_is_closed_v1(valid));
        for mutant in [
            valid.replacen("pub(crate) fn descriptor", "pub fn descriptor", 1),
            format!(
                "{valid} impl WorkerEndpointV1 {{ pub fn send_worker_exec_bound_once_v1(self) {{}} }}"
            ),
            format!("pub struct WorkerExecBoundSendInputV1; {valid}"),
            format!("pub struct WorkerExecBoundSentEndpointV1; {valid}"),
        ] {
            assert!(
                !g0b_worker_prebootstrap_surface_is_closed_v1(&mutant),
                "each pre-bootstrap Worker authority mutant must fail closed"
            );
        }
    }

    fn final_result_two_pass_components_are_exact_v1(
        observation: &str,
        validator: &str,
        await_impl: &str,
    ) -> bool {
        let ordered_observation_markers = [
            "fcntl_getfd(descriptor.as_fd())",
            "!descriptor_flags.contains(FdFlags::CLOEXEC)",
            "fcntl_getfl(descriptor.as_fd())",
            "status_flags & OFlags::ACCMODE != OFlags::RDONLY",
            "status_flags.contains(OFlags::NONBLOCK)",
            "fstat(descriptor.as_fd())",
            ".is_file()",
            "u64::try_from(metadata.st_size)",
            "usize::try_from(byte_length_u64)",
            "(1..=G0_FINAL_RESULT_MAX_BYTES_V1).contains(&byte_length)",
            "read_link(format!(\"/proc/self/fd/{raw_descriptor}\"))",
            ".starts_with(\"/memfd:\")",
            "fcntl_get_seals(descriptor.as_fd())",
            "SealFlags::GROW | SealFlags::SHRINK | SealFlags::WRITE | SealFlags::SEAL",
            "if seals != required_seals",
            "let mut bytes = Vec::new()",
            ".try_reserve_exact(byte_length)",
            "bytes.resize(byte_length, 0)",
            "pread(descriptor.as_fd(), &mut bytes[observed..], offset)",
            "if count == 0",
            ".checked_add(count)",
            "let mut eof_probe = [0_u8; 1]",
            "pread(descriptor.as_fd(), &mut eof_probe, byte_length_u64)",
            "bytes: bytes.into_boxed_slice()",
        ];
        let mut prior = 0_usize;
        for marker in ordered_observation_markers {
            let Some(relative) = observation[prior..].find(marker) else {
                return false;
            };
            prior += relative + marker.len();
        }
        for required in [
            "device: metadata.st_dev",
            "inode: metadata.st_ino",
            "mode: metadata.st_mode",
            "byte_length,",
            "descriptor_flags,",
            "status_flags,",
            "seals,",
            "descriptor_link,",
        ] {
            if !observation.contains(required) {
                return false;
            }
        }
        for forbidden in [
            "metadata.st_size as",
            "byte_length_u64 as",
            "seals.contains(required_seals)",
            "seals.contains(SealFlags",
            "read_to_end",
            "read_exact",
            "seek(",
        ] {
            if observation.contains(forbidden) {
                return false;
            }
        }
        if observation.matches("let mut bytes = Vec::new()").count() != 1 {
            return false;
        }

        let direct_observer = "observe_final_result_physical_pass_v1(&descriptor)?";
        if validator.matches(direct_observer).count() != 2
            || validator
                .matches("require_matching_final_result_observations_v1(")
                .count()
                != 1
            || !validator.contains("received.role != ContractFdRoleV1::FinalResult")
            || !validator.contains("let descriptor = received.descriptor")
        {
            return false;
        }
        for forbidden in [
            "validate_received_final_result_with_test_observer_v1",
            "FnMut",
            "mut observe",
            "observe(&descriptor)",
            "Ok(first.bytes)",
            "Ok(second.bytes)",
        ] {
            if validator.contains(forbidden) {
                return false;
            }
        }

        let Some(receive_at) = await_impl.find("receive_supervisor_for_generator_frame_v1(") else {
            return false;
        };
        let Some(physical_at) =
            await_impl.find("validate_received_final_result_once_v1(final_result)?")
        else {
            return false;
        };
        let Some(credentials_at) = await_impl.find("observed_supervisor_credentials_v1(") else {
            return false;
        };
        let Some(contract_at) = await_impl.find("verify_observed_closed_result_once_v1(") else {
            return false;
        };
        receive_at < physical_at
            && physical_at < credentials_at
            && credentials_at < contract_at
            && await_impl.contains("&final_result_content")
            && !await_impl.contains("validate_received_final_result_with_test_observer_v1")
    }

    #[test]
    fn final_result_two_pass_physical_source_oracle_v1() {
        let ancillary_source = include_str!("ancillary.rs");
        let ancillary = ancillary_production(ancillary_source);
        let observation = braced_item(
            ancillary,
            "fn observe_final_result_physical_pass_v1(",
            "G0b-2 FinalResult physical observation pass",
        );
        let validator = braced_item(
            ancillary,
            "fn validate_received_final_result_once_v1(",
            "G0b-2 FinalResult two-pass validator",
        );
        let await_impl = braced_item(
            ancillary,
            "impl GeneratorBoundAwaitClosedResultEndpointV1 {",
            "G0b-2 consuming ClosedResult verifier",
        );
        assert!(final_result_two_pass_components_are_exact_v1(
            observation,
            validator,
            await_impl,
        ));

        let test_seam_gate = concat!(
            "#[cfg(test)]\n",
            "        #[cfg(feature = \"h0-tmpfs-provider-v2-g0\")]\n",
            "        fn validate_received_final_result_with_test_observer_v1<F>("
        );
        assert!(ancillary_source.contains(test_seam_gate));
        assert!(
            !ancillary_source
                .contains("pub fn validate_received_final_result_with_test_observer_v1")
        );

        let mut mutants = Vec::new();
        mutants.push((
            observation.replacen(
                "u64::try_from(metadata.st_size)",
                "metadata.st_size as u64",
                1,
            ),
            validator.to_owned(),
            await_impl.to_owned(),
        ));
        mutants.push((
            observation.replacen(
                "if seals != required_seals",
                "if !seals.contains(required_seals)",
                1,
            ),
            validator.to_owned(),
            await_impl.to_owned(),
        ));
        mutants.push((
            observation.replacen(
                "let byte_length_u64 =",
                "let mut bytes = Vec::new(); let byte_length_u64 =",
                1,
            ),
            validator.to_owned(),
            await_impl.to_owned(),
        ));
        mutants.push((
            observation.to_owned(),
            validator.replacen(
                "observe_final_result_physical_pass_v1(&descriptor)?",
                "first",
                1,
            ),
            await_impl.to_owned(),
        ));
        mutants.push((
            observation.to_owned(),
            validator.replacen(
                "let second = observe_final_result_physical_pass_v1(&descriptor)?;",
                "let second = observe(&descriptor)?;",
                1,
            ),
            await_impl.to_owned(),
        ));
        mutants.push((
            observation.to_owned(),
            validator.to_owned(),
            await_impl.replacen(
                "validate_received_final_result_once_v1(final_result)?",
                "validate_received_final_result_with_test_observer_v1(final_result, observe)?",
                1,
            ),
        ));
        for (mutant_observation, mutant_validator, mutant_await) in mutants {
            assert!(
                !final_result_two_pass_components_are_exact_v1(
                    &mutant_observation,
                    &mutant_validator,
                    &mutant_await,
                ),
                "each unchecked size, relaxed seal, pre-bound allocation, single pass, generic observer, and production test-seam mutant must fail closed"
            );
        }
    }

    #[test]
    fn generator_bound_atomic_send_and_closed_result_verify_route_v1() {
        let ancillary_source = include_str!("ancillary.rs");
        let ancillary = ancillary_production(ancillary_source);
        let normalized_ancillary = ancillary.split_whitespace().collect::<String>();

        for required in [
            "pub struct GeneratorBoundSendInputV1<'a> {",
            "pub struct GeneratorBoundAwaitClosedResultEndpointV1 {",
            "pub fn send_generator_bound_once_v1(",
            "pub fn receive_and_verify_closed_result_once_v1(",
            "G0GeneratorBoundOutboundCandidateV1::prepare(",
            "G0ClosedResultInboundInputV1 {",
            "G0ClosedResultVerifiedV1",
        ] {
            assert!(
                ancillary.contains(required),
                "G0b-2 atomic producer-to-consumer route is missing: {required}"
            );
        }

        assert_eq!(
            ancillary
                .matches("pub fn send_generator_bound_once_v1(")
                .count(),
            1,
            "G0b-2 must have one public GeneratorBound producer"
        );
        assert_eq!(
            ancillary
                .matches("pub fn receive_and_verify_closed_result_once_v1(")
                .count(),
            1,
            "G0b-2 must have one consuming ClosedResult verifier"
        );

        let provider_impl = braced_item(
            ancillary,
            "impl GeneratorProviderSessionEndpointV1 {",
            "G0b-2 provider-session producer",
        );
        let send_at = provider_impl
            .find("send_seqpacket_once_v1(")
            .expect("G0b-2 must perform the sole exact sendmsg operation");
        let await_at = provider_impl
            .find("GeneratorBoundAwaitClosedResultEndpointV1 {")
            .expect("G0b-2 must construct the affine await state");
        assert!(
            send_at < await_at,
            "G0b-2 must construct Await only after exact GeneratorBound enqueue"
        );

        let await_impl = braced_item(
            ancillary,
            "impl GeneratorBoundAwaitClosedResultEndpointV1 {",
            "G0b-2 consuming ClosedResult verifier",
        );
        assert_eq!(
            normalized(signature(
                await_impl,
                "pub fn receive_and_verify_closed_result_once_v1("
            )),
            "pubfnreceive_and_verify_closed_result_once_v1(self,)->Result<G0ClosedResultVerifiedV1,ChildTypedReceiveErrorV1>"
        );
        for forbidden in [
            "ClosedResultReceiveInputV1",
            "ClosedResultReceivedV1",
            "GeneratorBoundSentEndpointV1",
            "&self",
            "&mut self",
            "retry",
            "resend",
            "reconnect",
            "into_parts",
            "fn endpoint",
            "fn descriptor",
            "BorrowedFd",
            "OwnedFd",
            "RawFd",
        ] {
            assert!(
                !await_impl.contains(forbidden),
                "G0b-2 await state gained legacy, replay, or descriptor escape: {forbidden}"
            );
        }

        for owner in [
            "GeneratorBoundAwaitClosedResultEndpointV1",
            "G0ClosedResultVerifiedV1",
        ] {
            for forbidden in [
                format!("impl Clone for {owner}"),
                format!("impl Copy for {owner}"),
                format!("impl Default for {owner}"),
                format!("impl AsFd for {owner}"),
                format!("impl AsRawFd for {owner}"),
            ] {
                assert!(
                    !ancillary.contains(&forbidden),
                    "G0b-2 affine owner gained a duplicating or descriptor trait: {forbidden}"
                );
            }
        }

        let public_reexports = exact_slice(
            ancillary_source,
            "pub use strict_model::selected_target::{",
            "pub(crate) use strict_model::selected_target::{",
            "G0b-2 public selected-target reexports",
        );
        for required in [
            "GeneratorBoundSendInputV1",
            "GeneratorBoundAwaitClosedResultEndpointV1",
        ] {
            assert!(
                public_reexports.contains(required),
                "G0b-2 typed capability missing from public exports: {required}"
            );
        }
        for forbidden in [
            "ClosedResultReceiveInputV1",
            "ClosedResultReceivedV1",
            "GeneratorBoundSentEndpointV1",
        ] {
            assert!(
                !public_reexports.contains(forbidden),
                "G0b-2 legacy route remained publicly exported: {forbidden}"
            );
        }

        assert_eq!(
            normalized_ancillary
                .matches("send_generator_bound_once_v1(")
                .count(),
            1,
            "G0b-2 must retain a sole GeneratorBound producer"
        );
    }

    #[test]
    fn generator_successor_closed_result_route_v1() {
        let ancillary_source = include_str!("ancillary.rs");
        let ancillary = ancillary_production(ancillary_source);

        let input = braced_item(
            ancillary,
            "pub struct GeneratorBoundSendInputV1<'a>",
            "G0b-2 GeneratorBound semantic input",
        );
        assert_eq!(
            normalized(input),
            "pubstructGeneratorBoundSendInputV1<'a>{seal_profile:&'aGeneratorSealProfileV1,inventory:&'aProcessInventoryV1,ingress:&'aSealedIngressManifestV1,}"
        );
        for forbidden in [
            "ExpectedPeerCredentialsV1",
            "PeerCredentialsV1",
            "UCred",
            "pid",
            "uid",
            "gid",
            "namespace",
            "WireFrameV1",
            "TranscriptCursorV1",
            "Authority",
            "generator_bound_digest",
        ] {
            assert!(
                !input.contains(forbidden),
                "G0b-2 input gained caller credential, digest, frame, cursor, or authority: {forbidden}"
            );
        }

        let input_impl = braced_item(
            ancillary,
            "impl<'a> GeneratorBoundSendInputV1<'a> {",
            "G0b-2 GeneratorBound input implementation",
        );
        assert_eq!(
            normalized(signature(input_impl, "pub const fn new(")),
            "pubconstfnnew(seal_profile:&'aGeneratorSealProfileV1,inventory:&'aProcessInventoryV1,ingress:&'aSealedIngressManifestV1,)->Self"
        );

        let awaiting = braced_item(
            ancillary,
            "pub struct GeneratorBoundAwaitClosedResultEndpointV1",
            "G0b-2 affine await state",
        );
        assert_eq!(
            normalized(awaiting),
            "pubstructGeneratorBoundAwaitClosedResultEndpointV1{endpoint:SeqpacketEndpointV1,await_closed_result:G0GeneratorBoundAwaitClosedResultV1,supervisor_pid:u32,supervisor_receiver_user_namespace:DescriptorIdentityV1,}"
        );

        let provider_impl = braced_item(
            ancillary,
            "impl GeneratorProviderSessionEndpointV1 {",
            "G0b-2 sole GeneratorBound producer",
        );
        assert_eq!(
            normalized(signature(
                provider_impl,
                "pub fn send_generator_bound_once_v1("
            )),
            "pubfnsend_generator_bound_once_v1(self,input:&GeneratorBoundSendInputV1<'_>,)->Result<GeneratorBoundAwaitClosedResultEndpointV1,ChildTypedSendErrorV1>"
        );
        for required in [
            ".prepare_generator_bound_body_v1(",
            "G0GeneratorBoundOutboundCandidateV1::prepare(",
            "send_seqpacket_once_v1(",
            "outbound.bytes()",
            "SendCredentialSourceV1::AutomaticChild",
            "outbound.into_await_closed_result_v1()",
        ] {
            assert!(
                provider_impl.contains(required),
                "G0b-2 producer lost a causal prepare/send/join step: {required}"
            );
        }
        let send_at = provider_impl.find("send_seqpacket_once_v1(").unwrap();
        let await_at = provider_impl
            .find("GeneratorBoundAwaitClosedResultEndpointV1 {")
            .unwrap();
        let contract_await_at = provider_impl
            .find("outbound.into_await_closed_result_v1()")
            .unwrap();
        assert!(send_at < await_at && send_at < contract_await_at);

        let await_impl = braced_item(
            ancillary,
            "impl GeneratorBoundAwaitClosedResultEndpointV1 {",
            "G0b-2 consuming ClosedResult verifier",
        );
        assert_eq!(
            normalized(signature(
                await_impl,
                "pub fn receive_and_verify_closed_result_once_v1("
            )),
            "pubfnreceive_and_verify_closed_result_once_v1(self,)->Result<G0ClosedResultVerifiedV1,ChildTypedReceiveErrorV1>"
        );
        let receive_at = await_impl
            .find("receive_supervisor_for_generator_frame_v1(")
            .unwrap();
        let physical_at = await_impl
            .find("validate_received_final_result_once_v1(final_result)")
            .unwrap();
        let observed_at = await_impl
            .find("observed_supervisor_credentials_v1(")
            .unwrap();
        let contract_at = await_impl
            .find("verify_observed_closed_result_once_v1(")
            .unwrap();
        assert!(receive_at < physical_at && physical_at < contract_at);
        assert!(receive_at < observed_at && observed_at < contract_at);
        for required in [
            "observed_credentials,",
            "G0ClosedResultInboundInputV1 {",
            "actual_rights_count: 1",
        ] {
            assert!(await_impl.contains(required));
        }
        for forbidden in [
            "ClosedResultReceiveInputV1",
            "ClosedResultReceivedV1",
            "GeneratorBoundSentEndpointV1",
            "&self",
            "&mut self",
            "retry",
            "resend",
            "reconnect",
            "into_parts",
            "fn endpoint",
            "fn descriptor",
            "BorrowedFd",
            "OwnedFd",
            "RawFd",
        ] {
            assert!(
                !await_impl.contains(forbidden),
                "G0b-2 await state gained legacy, replay, or descriptor escape: {forbidden}"
            );
        }

        let observation = braced_item(
            ancillary,
            "fn observe_final_result_physical_pass_v1(",
            "G0b-2 private FinalResult observation pass",
        );
        for required in [
            "fcntl_getfd(descriptor.as_fd())",
            "FdFlags::CLOEXEC",
            "fcntl_getfl(descriptor.as_fd())",
            "status_flags & OFlags::ACCMODE != OFlags::RDONLY",
            "status_flags.contains(OFlags::NONBLOCK)",
            "fstat(descriptor.as_fd())",
            ".is_file()",
            "u64::try_from(metadata.st_size)",
            "usize::try_from(byte_length_u64)",
            "(1..=G0_FINAL_RESULT_MAX_BYTES_V1).contains(&byte_length)",
            "read_link(format!(\"/proc/self/fd/{raw_descriptor}\"))",
            ".starts_with(\"/memfd:\")",
            "fcntl_get_seals(descriptor.as_fd())",
            "SealFlags::GROW | SealFlags::SHRINK | SealFlags::WRITE | SealFlags::SEAL",
            "if seals != required_seals",
            "try_reserve_exact(byte_length)",
            "pread(descriptor.as_fd(), &mut bytes[observed..], offset)",
            "if count == 0",
            "let mut eof_probe = [0_u8; 1]",
            "bytes: bytes.into_boxed_slice()",
        ] {
            assert!(
                observation.contains(required),
                "G0b-2 FinalResult observation lost an exact physical check: {required}"
            );
        }
        let validator = braced_item(
            ancillary,
            "fn validate_received_final_result_once_v1(",
            "G0b-2 private FinalResult validator",
        );
        assert!(validator.contains("received: ReceivedFdV1"));
        assert!(validator.contains("received.role != ContractFdRoleV1::FinalResult"));
        assert_eq!(
            validator
                .matches("observe_final_result_physical_pass_v1(&descriptor)?")
                .count(),
            2
        );
        assert!(validator.contains("require_matching_final_result_observations_v1(first, second)"));
        assert!(!validator.contains("validate_received_final_result_with_test_observer_v1"));

        let observed = braced_item(
            ancillary,
            "fn observed_supervisor_credentials_v1(",
            "G0b-2 observed credential projection",
        );
        for required in [
            "observed.process_id()",
            "observed.user_id()",
            "observed.group_id()",
            "user_namespace",
        ] {
            assert!(
                observed.contains(required),
                "G0b-2 must carry kernel-observed credentials: {required}"
            );
        }
        assert!(!observed.contains("WORKER_OUTER_UID_V1"));
        assert!(!observed.contains("WORKER_OUTER_GID_V1"));

        let public_reexports = exact_slice(
            ancillary_source,
            "pub use strict_model::selected_target::{",
            "pub(crate) use strict_model::selected_target::{",
            "G0b-2 public selected-target reexports",
        );
        for required in [
            "GeneratorBoundSendInputV1",
            "GeneratorBoundAwaitClosedResultEndpointV1",
        ] {
            assert!(public_reexports.contains(required));
        }
        for forbidden in [
            "ClosedResultReceiveInputV1",
            "ClosedResultReceivedV1",
            "GeneratorBoundSentEndpointV1",
        ] {
            assert!(!public_reexports.contains(forbidden));
        }

        let signatures = super::d6b_function_signatures_v1(ancillary);
        assert_eq!(
            signatures
                .iter()
                .filter(|item| item.contains("send_generator_bound_once_v1"))
                .count(),
            1,
            "G0b-2 must retain a sole GeneratorBound producer"
        );
        for forbidden in [
            "impl Clone for GeneratorBoundAwaitClosedResultEndpointV1",
            "impl Copy for GeneratorBoundAwaitClosedResultEndpointV1",
            "impl Default for GeneratorBoundAwaitClosedResultEndpointV1",
            "impl AsFd for GeneratorBoundAwaitClosedResultEndpointV1",
            "impl AsRawFd for GeneratorBoundAwaitClosedResultEndpointV1",
            "impl Clone for G0ClosedResultVerifiedV1",
            "impl Copy for G0ClosedResultVerifiedV1",
            "impl Default for G0ClosedResultVerifiedV1",
            "impl AsFd for G0ClosedResultVerifiedV1",
            "impl AsRawFd for G0ClosedResultVerifiedV1",
        ] {
            assert!(!ancillary.contains(forbidden));
        }
    }

    #[test]
    fn worker_prebootstrap_route_remains_closed_until_contract_v1() {
        assert_g0b_worker_prebootstrap_surface_fixtures_v1();
        let ancillary_source = include_str!("ancillary.rs");
        let ancillary = ancillary_production(ancillary_source);
        assert!(ancillary.contains("pub struct WorkerEndpointV1(SeqpacketEndpointV1);"));
        assert!(g0b_worker_prebootstrap_surface_is_closed_v1(ancillary));
        for forbidden in [
            "WorkerExecBoundSendInputV1",
            "WorkerExecBoundSentEndpointV1",
            "send_worker_exec_bound_once_v1",
        ] {
            assert!(!ancillary.contains(forbidden));
        }
    }
}

impl AbiModuleV1 {
    /// Modules in the only reviewed source order.
    pub const ALL: [Self; 5] = [
        Self::Statx,
        Self::Ancillary,
        Self::Process,
        Self::ExecutableCustody,
        Self::Seccomp,
    ];
}

/// Closed public-operation inventory reserved for D2 and D3.
///
/// These discriminants are descriptive only. D1 exports no operation that can
/// access a descriptor, process, namespace, filter, or kernel result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbiOperationV1 {
    /// Fixed empty-path statx observation over an exact descriptor.
    DescriptorObservation,
    /// Non-reconnectable role-specific seqpacket pair and endpoint ledger.
    ExactEndpointSocketpair,
    /// Exact-length receive with exhaustive credentials and rights handling.
    StrictAncillaryReceive,
    /// Consuming single-attempt complete ancillary enqueue.
    OneShotAncillarySend,
    /// Provider-fixed generator creation and inheritance boundary.
    ExactGeneratorSpawn,
    /// Provider-fixed worker creation and inheritance boundary.
    ExactWorkerSpawn,
    /// Execution through the retained measured worker descriptor.
    RetainedWorkerExec,
    /// Pidfd-bound exit observation and exact reap.
    PidfdWait,
    /// Provider-fixed namespace and cgroup setup.
    NamespaceAndCgroupSetup,
    /// Initial phase-specific seccomp installation.
    InitialSeccompInstall,
    /// Final no-acquire seccomp installation.
    NoAcquireSeccompInstall,
    /// Exact feature probes for the pinned appliance.
    ExactFeatureProbes,
}

impl AbiOperationV1 {
    /// Operations in their reviewed module order.
    pub const ALL: [Self; 12] = [
        Self::DescriptorObservation,
        Self::ExactEndpointSocketpair,
        Self::StrictAncillaryReceive,
        Self::OneShotAncillarySend,
        Self::ExactGeneratorSpawn,
        Self::ExactWorkerSpawn,
        Self::RetainedWorkerExec,
        Self::PidfdWait,
        Self::NamespaceAndCgroupSetup,
        Self::InitialSeccompInstall,
        Self::NoAcquireSeccompInstall,
        Self::ExactFeatureProbes,
    ];

    /// Returns the sole future source owner for this operation.
    #[must_use]
    pub const fn owner(self) -> AbiModuleV1 {
        match self {
            Self::DescriptorObservation => AbiModuleV1::Statx,
            Self::ExactEndpointSocketpair
            | Self::StrictAncillaryReceive
            | Self::OneShotAncillarySend => AbiModuleV1::Ancillary,
            Self::ExactGeneratorSpawn
            | Self::ExactWorkerSpawn
            | Self::RetainedWorkerExec
            | Self::PidfdWait
            | Self::NamespaceAndCgroupSetup
            | Self::ExactFeatureProbes => AbiModuleV1::Process,
            Self::InitialSeccompInstall | Self::NoAcquireSeccompInstall => AbiModuleV1::Seccomp,
        }
    }
}

/// Closed inventory of raw primitives implemented or planned for independent
/// review.
///
/// Presence in this enum does not implement or authorize the primitive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlannedUnsafePrimitiveV1 {
    /// Raw receive and exhaustive control-message traversal.
    RecvmsgControlTraversal,
    /// Raw clone3 call with fixed arguments.
    Clone3,
    /// Allocation-free post-clone trampoline.
    PostCloneTrampoline,
    /// Retained-descriptor execveat call.
    RetainedExecveat,
    /// Fixed seccomp installation call.
    SeccompInstall,
    /// Raw probe absent from the safe wrapper surface.
    ExactFeatureProbe,
}

impl PlannedUnsafePrimitiveV1 {
    /// Planned raw primitives in their reviewed source order.
    pub const ALL: [Self; 6] = [
        Self::RecvmsgControlTraversal,
        Self::Clone3,
        Self::PostCloneTrampoline,
        Self::RetainedExecveat,
        Self::SeccompInstall,
        Self::ExactFeatureProbe,
    ];

    /// Returns the sole future source owner for this raw primitive.
    #[must_use]
    pub const fn owner(self) -> AbiModuleV1 {
        match self {
            Self::RecvmsgControlTraversal => AbiModuleV1::Ancillary,
            Self::Clone3
            | Self::PostCloneTrampoline
            | Self::RetainedExecveat
            | Self::ExactFeatureProbe => AbiModuleV1::Process,
            Self::SeccompInstall => AbiModuleV1::Seccomp,
        }
    }
}

#[cfg(test)]
mod abi_boundary {
    use super::*;

    #[test]
    fn abi_boundary_pins_the_exact_external_contract() {
        assert_eq!(SELECTED_TARGET_TRIPLE_V1, "x86_64-unknown-linux-musl");
        assert_eq!(LINUX_VERSION_V1, "v7.1.8");
        assert_eq!(LINUX_COMMIT_V1.len(), 40);
        assert_eq!(RUST_VERSION_V1, "1.89.0");
        assert_eq!(RUSTIX_VERSION_V1, "1.1.4");
        assert_eq!(RUSTIX_CRATE_SHA256_V1.len(), 64);
    }

    #[test]
    fn abi_boundary_has_a_closed_future_module_and_operation_inventory() {
        use crate::statx::DescriptorSubjectV1;

        assert_eq!(AbiModuleV1::ALL.len(), 5);
        assert_eq!(AbiOperationV1::ALL.len(), 12);
        assert_eq!(PlannedUnsafePrimitiveV1::ALL.len(), 6);
        assert_eq!(IMPLEMENTED_UNSAFE_PRIMITIVE_COUNT_V1, 5);
        assert_eq!(
            AbiOperationV1::ALL.map(AbiOperationV1::owner),
            [
                AbiModuleV1::Statx,
                AbiModuleV1::Ancillary,
                AbiModuleV1::Ancillary,
                AbiModuleV1::Ancillary,
                AbiModuleV1::Process,
                AbiModuleV1::Process,
                AbiModuleV1::Process,
                AbiModuleV1::Process,
                AbiModuleV1::Process,
                AbiModuleV1::Seccomp,
                AbiModuleV1::Seccomp,
                AbiModuleV1::Process,
            ]
        );
        assert_ne!(
            DescriptorSubjectV1::GeneratorExecutable,
            DescriptorSubjectV1::WorkerExecutable,
            "the two measured executable roles must remain distinct"
        );
    }

    #[test]
    fn abi_boundary_has_exact_locally_documented_unsafe_sites() {
        let workspace = include_str!("../../../Cargo.toml");
        let package = include_str!("../Cargo.toml");
        let contract = include_str!("../../contract/src/lib.rs");
        let root_source = include_str!("lib.rs");
        let statx_source = include_str!("statx.rs");
        let ancillary_source = include_str!("ancillary.rs");
        let worker_inventory_fixture_source =
            include_str!("../tests/worker_post_exec_fd_inventory.rs");
        let worker_inventory_leaf_source =
            include_str!("../tests/fixtures/worker_post_exec_fd_inventory_leaf.rs");
        let process_source = include_str!("process.rs");
        let executable_custody_source = include_str!("executable_custody.rs");
        let seccomp_source = include_str!("seccomp.rs");
        let unsafe_block = ["unsafe", " {"].concat();
        let inherited_generator_fd3_owner = [
            "unsafe",
            " { OwnedFd::from_raw_fd(INHERITED_GENERATOR_ENDPOINT_FD_V1) }",
        ]
        .concat();
        let inherited_worker_fd3_owner = "OwnedFd::from_raw_fd(WORKER_ENDPOINT_FD_V1)";
        let foreign_block = ["extern ", "\"C\""].concat();
        let architecture_intrinsic = ["std", "::arch"].concat();

        assert!(workspace.contains("unsafe_code = \"forbid\""));
        assert!(workspace.contains("default-members = [\"crates/contract\"]"));
        assert_eq!(package.matches("unsafe_code = \"allow\"").count(), 1);
        assert!(package.contains("unsafe_op_in_unsafe_fn = \"deny\""));
        assert!(package.contains("non-selected-target-policy = \"inventory-only\""));
        assert!(contract.starts_with("#![forbid(unsafe_code)]"));
        assert!(!root_source.contains(&unsafe_block));
        assert!(!root_source.contains(&foreign_block));
        assert!(!statx_source.contains(&unsafe_block));
        assert!(!statx_source.contains(&foreign_block));
        assert!(statx_source.contains("rustix::fs::statx"));
        assert!(!executable_custody_source.contains(&unsafe_block));
        assert!(!executable_custody_source.contains(&foreign_block));
        assert_eq!(ancillary_source.matches(&unsafe_block).count(), 3);
        assert_eq!(
            worker_inventory_fixture_source
                .matches(&unsafe_block)
                .count(),
            1
        );
        assert_eq!(
            worker_inventory_leaf_source.matches(&unsafe_block).count(),
            2
        );
        assert_eq!(
            ancillary_source
                .matches(&inherited_generator_fd3_owner)
                .count(),
            1,
            "the runtime fixture must own inherited generator fd3 exactly once"
        );
        assert_eq!(
            worker_inventory_leaf_source
                .matches(&inherited_worker_fd3_owner)
                .count(),
            1,
            "the runtime fixture must own inherited Worker fd3 exactly once"
        );
        assert_eq!(ancillary_source.matches(&foreign_block).count(), 1);
        assert_eq!(
            worker_inventory_fixture_source
                .matches(&foreign_block)
                .count(),
            1
        );
        assert_eq!(
            worker_inventory_leaf_source.matches(&foreign_block).count(),
            2
        );
        assert_eq!(process_source.matches(&unsafe_block).count(), 14);
        assert_eq!(process_source.matches(&foreign_block).count(), 1);
        assert_eq!(seccomp_source.matches(&unsafe_block).count(), 3);
        assert_eq!(seccomp_source.matches(&foreign_block).count(), 1);
        assert!(process_source.contains("retained_executable: BorrowedFd<'a>"));
        assert!(process_source.contains("pub(crate) fn configure_namespace_maps"));
        assert!(!process_source.contains("pub fn check_namespace_maps"));
        assert!(!process_source.contains("pub fn syscall"));
        assert!(!seccomp_source.contains("pub struct SockFilter"));
        assert!(!root_source.contains(&architecture_intrinsic));
        assert!(!statx_source.contains(&architecture_intrinsic));
        assert!(!ancillary_source.contains(&architecture_intrinsic));
        assert!(!worker_inventory_fixture_source.contains(&architecture_intrinsic));
        assert!(!worker_inventory_leaf_source.contains(&architecture_intrinsic));
        assert!(!process_source.contains(&architecture_intrinsic));
        assert!(!executable_custody_source.contains(&architecture_intrinsic));
        assert!(!seccomp_source.contains(&architecture_intrinsic));
    }

    #[test]
    fn abi_boundary_excludes_executable_abi_on_non_selected_targets() {
        assert_eq!(
            ABI_TARGET_COMPILED_V1,
            cfg!(all(
                target_arch = "x86_64",
                target_os = "linux",
                target_env = "musl"
            ))
        );
    }

    #[test]
    fn d3_child_exit_is_defined_even_if_kernel_exit_returns() {
        let source = include_str!("process.rs");
        assert!(!source.contains("unreachable_unchecked"));
        assert_eq!(source.matches("child_failure_exit_forever();").count(), 22);
        assert!(source.contains("fn child_failure_exit_forever() -> !"));
        assert!(source.contains("loop {"));
        assert!(source.contains("SYS_EXIT_GROUP"));
    }

    #[test]
    fn d3_descriptor_ledger_is_kernel_observed() {
        let source = include_str!("process.rs");
        assert!(!source.contains("observed_open_descriptors"));
        assert!(source.contains("authority: ProcfsAuthorityV1"));
        assert!(source.contains("sources[additional_end] = authority_root"));
        assert!(source.contains("observe_live_descriptor_inventory"));
        assert!(source.contains("rustix::fs::Dir::new"));
        assert!(source.contains("enumeration_descriptor"));
        assert!(source.contains("validate_single_thread_snapshots"));
    }

    #[test]
    fn d3_child_containment_preserves_wait_ownership() {
        let source = include_str!("process.rs");
        assert!(source.contains("impl Drop for RunningChildV1"));
        assert!(source.contains("reaped: bool"));
        assert!(source.contains("error == rustix::io::Errno::INTR"));
        assert!(source.contains("pidfd_send_signal"));
        assert!(source.contains("contain_child_without_pidfd"));
    }

    #[test]
    fn d3_wait_errors_leave_the_child_handle_with_the_caller() {
        let source = include_str!("process.rs");
        assert!(source.contains("pub(crate) fn observe_exit(&self)"));
        assert!(source.contains("pub(crate) fn reap_exact(\n            &mut self,"));
        let mark = source.find("self.reaped = true;").unwrap();
        let decode = source[mark..].find("decode_exit(status)?").unwrap() + mark;
        assert!(
            mark < decode,
            "a successful kernel reap must be marked first"
        );
    }

    #[test]
    fn d3_drop_containment_is_pidfd_bound_and_non_panicking() {
        let source = include_str!("process.rs");
        let blocked_start = source.find("pub(crate) struct BlockedWorkerV1").unwrap();
        let blocked_end = source[blocked_start..]
            .find("impl BlockedWorkerV1")
            .unwrap()
            + blocked_start;
        let blocked = &source[blocked_start..blocked_end];
        assert!(blocked.find("release: OwnedFd").unwrap() < blocked.find("child:").unwrap());
        let start = source.find("impl Drop for RunningChildV1").unwrap();
        let end = source[start..].find("fn decode_exit").unwrap() + start;
        let implementation = &source[start..end];
        assert!(implementation.contains("pidfd_send_signal"));
        assert!(implementation.contains("WaitId::PidFd"));
        assert!(!implementation.contains("Err(_) => break"));
        assert!(implementation.contains("rustix::io::Errno::AGAIN"));
        assert!(implementation.contains("rustix::io::Errno::CHILD"));
        assert!(!implementation.contains("contain_child_without_pidfd"));
        assert!(implementation.contains("containment_failure_exit_forever"));
        assert!(!implementation.contains("unwrap("));
        assert!(!implementation.contains("expect("));
        assert!(!implementation.contains("panic!("));
    }

    #[test]
    fn d3_no_pidfd_fallback_retries_both_containment_syscalls() {
        let source = include_str!("process.rs");
        let start = source.find("fn contain_child_without_pidfd").unwrap();
        let implementation = &source[start..];
        assert!(implementation.contains("SYS_KILL"));
        assert!(implementation.contains("SYS_WAIT4"));
        assert!(implementation.matches("loop {").count() >= 2);
        assert!(implementation.contains("Some(3)"));
        assert!(implementation.contains("Some(10)"));
        assert!(implementation.contains("SYS_SCHED_YIELD"));
    }

    #[test]
    fn d3_seccomp_install_is_single_thread_and_tid_bound() {
        let source = include_str!("seccomp.rs");
        assert!(source.contains("authority: &ProcfsAuthorityV1"));
        assert!(source.contains("validate_procfs_thread_snapshots"));
        assert!(source.contains("SignalMaskGuardV1"));
        assert!(source.contains("PhantomData<Rc<()>>"));
        assert!(source.contains("ensure_current_tid"));
        assert_eq!(crate::seccomp::SECCOMP_INSTALL_FLAGS_V1, 0);
    }

    #[test]
    fn d3_selected_abi_layouts_are_asserted() {
        let process = include_str!("process.rs");
        let ancillary = include_str!("ancillary.rs");
        let seccomp = include_str!("seccomp.rs");
        assert!(process.contains("offset_of!(CloneArgsV1, cgroup)"));
        assert!(ancillary.contains("offset_of!(MessageHeaderV1, returned_flags)"));
        assert!(ancillary.contains("offset_of!(ControlMessageHeaderV1, kind)"));
        assert!(seccomp.contains("offset_of!(SockFilterV1, k)"));
        assert!(seccomp.contains("offset_of!(SockFprogV1, filter)"));
    }

    #[test]
    fn d3_second_pidfd_custody_closes_nonblocking_escape() {
        let source = include_str!("process.rs");
        assert!(!source.contains("pub fn pidfd(&self)"));
        assert!(source.contains("error == rustix::io::Errno::AGAIN"));
        assert!(source.contains("pidfd_send_signal_retry"));
        assert!(source.contains("fcntl_setfl"));
        assert!(source.contains("OFlags::NONBLOCK"));
    }

    #[test]
    fn d3_third_pidfd_custody_never_reuses_a_numeric_pid() {
        let source = include_str!("process.rs");
        let drop_start = source.find("impl Drop for RunningChildV1").unwrap();
        let drop_end = source[drop_start..].find("fn decode_exit").unwrap() + drop_start;
        let drop_implementation = &source[drop_start..drop_end];
        assert!(!drop_implementation.contains("contain_child_without_pidfd"));
        assert!(!drop_implementation.contains("SYS_KILL"));
        assert!(!drop_implementation.contains("SYS_WAIT4"));
        assert!(drop_implementation.contains("containment_failure_exit_forever"));

        let spawn_start = source.find("fn spawn_exact(").unwrap();
        let pidfd_acquired_marker = [
            "let pidfd = ",
            "unsafe",
            " { OwnedFd::from_raw_fd(pidfd_raw) };",
        ]
        .concat();
        let pidfd_acquired = source.find(&pidfd_acquired_marker).unwrap();
        let child_constructed = source.find("let child = RunningChildV1").unwrap();
        assert!(spawn_start < pidfd_acquired);
        assert!(pidfd_acquired < child_constructed);
        assert_eq!(
            source[spawn_start..pidfd_acquired]
                .matches("contain_child_without_pidfd(")
                .count(),
            1
        );
        let post_acquisition = &source[pidfd_acquired..child_constructed];
        assert!(!post_acquisition.contains("contain_child_without_pidfd("));
        assert_eq!(
            post_acquisition
                .matches("containment_failure_exit_forever()")
                .count(),
            2
        );
        assert_eq!(source.matches("contain_child_without_pidfd(").count(), 2);
        assert!(source.contains("rustix::io::Errno::SRCH"));
        assert!(source.contains("PidfdContainmentEventV1::SignalNoSuchProcess"));
        assert!(source.contains("PidfdContainmentEventV1::WaitNoChild"));
        assert!(source.contains("PidfdContainmentActionV1::FailClosed"));
    }

    #[test]
    fn d3_second_procfs_authority_is_owned_revalidated_and_not_reinjected() {
        let process = include_str!("process.rs");
        let seccomp = include_str!("seccomp.rs");
        assert!(process.contains("pub struct ProcfsAuthorityV1"));
        assert!(process.contains("pub fn new(root: OwnedFd)"));
        assert!(process.contains("pub use selected_target::ProcfsAuthorityV1"));
        assert!(process.contains("thread-self"));
        assert!(process.contains("process_starttime"));
        assert!(process.contains("pid_namespace"));
        assert!(process.contains("SignalMaskGuardV1"));
        assert!(process.contains("reset_child_signal_dispositions"));
        assert!(!process.contains("pub fn procfs_root"));
        assert!(!process.contains("impl AsFd for ProcfsAuthorityV1"));
        assert!(!seccomp.contains("procfs_root: BorrowedFd"));
        assert!(seccomp.contains("authority: &ProcfsAuthorityV1"));
    }

    #[test]
    fn d3_second_bpf_tests_interpret_the_real_program() {
        let source = include_str!("seccomp.rs");
        assert!(source.contains("fn interpret_filter_for_test"));
        assert!(source.contains("SECCOMP_DATA_ARG0_LOW_OFFSET"));
        assert!(source.contains("SECCOMP_DATA_ARG0_HIGH_OFFSET"));
        assert!(source.contains("SECCOMP_DATA_ARG1_LOW_OFFSET"));
        assert!(source.contains("SECCOMP_DATA_ARG1_HIGH_OFFSET"));
        assert!(source.contains("wrong_pointer_low"));
        assert!(source.contains("wrong_pointer_high"));
        assert!(source.contains("wrong_flags_low"));
        assert!(source.contains("wrong_flags_high"));
    }

    #[test]
    fn d3_second_cmsghdr_matches_pinned_musl_layout() {
        let source = include_str!("ancillary.rs");
        assert!(source.contains("padding: u32"));
        assert!(source.contains("align_of::<ControlMessageHeaderV1>()];"));
        assert!(source.contains("offset_of!(ControlMessageHeaderV1, padding)"));
        assert!(
            source.contains(
                "const _: [(); 4] = [(); core::mem::align_of::<ControlMessageHeaderV1>()]"
            )
        );
    }

    #[test]
    fn seqpacket_endpoint_ledger_v1() {
        let ancillary = include_str!("ancillary.rs");
        assert!(ancillary.contains("pub(crate) fn create_generator_channel_v1"));
        assert!(ancillary.contains("pub(crate) fn create_worker_channel_v1"));
        assert!(ancillary.contains("SocketType::SEQPACKET"));
        assert!(ancillary.contains("SocketFlags::CLOEXEC"));
        assert!(ancillary.contains("use rustix::net::sockopt::{"));
        assert!(!ancillary.contains("use rustix::net::{\n            set_socket_passcred"));
        assert!(ancillary.contains("socket_cookie"));
        assert!(ancillary.contains("socket_domain"));
        assert!(ancillary.contains("socket_type"));
        assert!(ancillary.contains("socket_protocol"));
        assert!(ancillary.contains("set_socket_passcred"));
        assert!(ancillary.contains("socket_passcred"));
        assert!(ancillary.contains("reread_endpoint_observation_v1"));
    }

    #[test]
    fn strict_child_receive_v1() {
        let ancillary = include_str!("ancillary.rs");
        assert!(ancillary.contains("SupervisorForGenerator"));
        assert!(ancillary.contains("SupervisorForWorker"));
        for endpoint in [
            "impl GeneratorEndpointV1",
            "impl SupervisorGeneratorEndpointV1",
            "impl SupervisorWorkerEndpointV1",
            "impl WorkerEndpointV1",
        ] {
            assert!(
                ancillary.contains(endpoint),
                "missing opaque role API: {endpoint}"
            );
        }
        for raw_receive in [
            "pub fn receive_generator_frame_v1(\n            socket: BorrowedFd",
            "pub fn receive_worker_frame_v1(\n            socket: BorrowedFd",
            "pub fn receive_supervisor_for_generator_frame_v1(\n            socket: BorrowedFd",
            "pub fn receive_supervisor_for_worker_frame_v1(\n            socket: BorrowedFd",
        ] {
            assert!(
                !ancillary.contains(raw_receive),
                "public raw receive bypass: {raw_receive}"
            );
        }
        assert!(ancillary.contains("MSG_CMSG_CLOEXEC_V1"));
    }

    #[test]
    fn send_once_v1() {
        let ancillary = include_str!("ancillary.rs");
        assert!(ancillary.contains("pub(crate) struct SupervisorWorkerBootstrapSendOpV1"));
        assert!(ancillary.contains("pub(crate) fn enqueue_once_v1("));
        assert!(ancillary.contains("SendFlags::EOR | SendFlags::NOSIGNAL"));
        assert_eq!(ancillary.matches("rustix::net::sendmsg(").count(), 1);
        assert!(!ancillary.contains("sendmsg_retry"));
    }

    #[test]
    fn worker_bootstrap_enqueue_once_v1() {
        let ancillary = include_str!("ancillary.rs");
        let process = include_str!("process.rs");
        assert!(ancillary.contains("pub(crate) struct WorkerBootstrapEnqueuedEndpointV1"));
        assert!(ancillary.contains("pub(crate) struct SupervisorWorkerBootstrapSendOpV1"));
        assert!(process.contains("pub(crate) fn enqueue_supervisor_bootstrap_once_v1("));
        assert!(!ancillary.contains("pub(crate) fn enqueue_worker_bootstrap_once("));
        assert!(process.contains("bootstrap_enqueued: &WorkerBootstrapEnqueuedEndpointV1"));
        assert!(!process.contains("WorkerBootstrapEnqueueCauseV1"));
        assert!(!process.contains("WorkerBootstrapEnqueueErrorV1"));
        assert!(!process.contains("enqueue_worker_bootstrap_then_release"));
        assert!(!process.contains("send_worker_bootstrap_once_v1"));
        assert!(!process.contains("NamespaceMapStageV1::EnqueueWorkerBootstrap"));
        assert!(!process.contains("NamespaceMapStageV1::ReleaseWorker"));
        assert!(process.contains("WORKER_MAP_STAGES_V1: [NamespaceMapStageV1; 6]"));
        assert!(process.contains("pub(crate) fn release_after_bootstrap_enqueued_v1"));
        assert!(!process.contains("pub fn release_after_bootstrap_enqueued_v1"));
        assert!(!process.contains("pub fn into_child"));
        assert!(!process.contains(
            "pub fn new(\n            retained_executable: BorrowedFd<'a>,\n            cgroup: BorrowedFd<'a>,\n            endpoint: BorrowedFd<'a>,"
        ));
        assert!(process.contains("pub(crate) fn new_with_endpoint("));
        assert!(process.contains("open_proc_user_namespace"));
        assert!(process.contains("user_namespace_identity"));
        assert!(process.contains("revalidate_receiver_user_namespace"));
    }

    #[test]
    fn kernel_enqueue_success_is_opaque_v1() {
        assert_d6b_source_extension_closure_fixtures_v1();
        assert_d6b_protected_operation_method_closure_fixtures_v1();
        assert_d6b_session_red_registration_fixtures_v1();
        let root_source = include_str!("lib.rs");
        let ancillary_source = include_str!("ancillary.rs");
        let process_source = include_str!("process.rs");
        let custody_source = include_str!("executable_custody.rs");
        let session_source = include_str!("session.rs");
        assert_d6b_session_red_registration_v1(root_source, session_source);
        assert_d6b_source_extension_closure_v1(&[
            ("lib.rs", root_source),
            ("process.rs", process_source),
            ("executable_custody.rs", custody_source),
            ("ancillary.rs", ancillary_source),
            ("session.rs", session_source),
            ("seccomp.rs", include_str!("seccomp.rs")),
            ("statx.rs", include_str!("statx.rs")),
        ]);
        let root_production = d6b_production_without_tests_v1(root_source);
        let root = root_production.as_str();
        let selected_start = ancillary_source
            .find("pub(super) mod selected_target {")
            .expect("selected ancillary production must exist");
        let selected_end = ancillary_source[selected_start..]
            .find("        #[cfg(test)]\n        mod inherited_fd3_subprocess_tests {")
            .expect("selected ancillary production must close before tests")
            + selected_start;
        let ancillary = &ancillary_source[selected_start..selected_end];
        assert_d6b_successor_impl_location_closure_v1(ancillary_source, ancillary);
        let process_production = d6b_production_without_tests_v1(process_source);
        let process = process_production.as_str();
        let custody_production = d6b_production_without_tests_v1(custody_source);
        let custody = custody_production.as_str();
        assert_d6b_role_closure_v1(&[
            ("lib.rs", root),
            ("ancillary.rs", ancillary),
            ("process.rs", process),
            ("custody.rs", custody),
        ]);
        let declaration_start = ancillary
            .find("pub(crate) struct WorkerBootstrapEnqueuedEndpointV1")
            .expect("D4 enqueue-success token must exist");
        let tail = &ancillary[declaration_start..];
        let end = tail
            .find("\n        }")
            .expect("token declaration must close");
        let declaration = &tail[..=end];
        let fields = declaration
            .split_once('{')
            .map(|(_, fields)| fields)
            .expect("token declaration must contain fields");
        assert!(!fields.contains("pub "));
        for forbidden in [
            "Clone",
            "Copy",
            "Default",
            "Serialize",
            "Deserialize",
            "cursor",
            "digest",
            "count",
            "frame",
            "bytes",
        ] {
            assert!(
                !declaration.contains(forbidden),
                "forbidden token field: {forbidden}"
            );
        }
        assert!(declaration.contains("endpoint: SeqpacketEndpointV1"));
        assert!(!declaration.contains("child"));
        assert!(!declaration.contains("user_namespace"));
        assert!(!declaration.contains("release"));
        let declaration_prelude_start = ancillary
            .find("/// Opaque kernel-success state for the exact worker-bootstrap packet.")
            .expect("opaque worker successor documentation must exist");
        let declaration_prelude = &ancillary[declaration_prelude_start..declaration_start];
        assert!(!declaration_prelude.contains("#[derive("));

        assert_eq!(
            ancillary
                .matches("impl WorkerBootstrapEnqueuedEndpointV1 {")
                .count(),
            1,
            "the worker enqueue-success state must have one inherent implementation"
        );
        let impl_start = ancillary
            .find("impl WorkerBootstrapEnqueuedEndpointV1 {")
            .expect("worker enqueue-success implementation must exist");
        let impl_open = ancillary[impl_start..]
            .find('{')
            .expect("worker enqueue-success implementation must open")
            + impl_start;
        let ancillary_mask = d6b_rust_code_mask_v1(ancillary);
        let impl_end = d6b_closing_brace_v1(ancillary_mask.as_bytes(), impl_open) + 1;
        let successor_impl = &ancillary[impl_start..impl_end];
        let successor_scope_start = ancillary
            .find("pub(crate) struct WorkerChannelV1 {")
            .expect("worker channel must precede its opaque successor");
        let successor_scope = &ancillary[successor_scope_start..impl_end];
        for forbidden in ["Clone", "Copy", "Default"] {
            assert!(
                !successor_scope.contains(forbidden),
                "worker enqueue-success state gained derive/trait authority: {forbidden}"
            );
        }
        assert_eq!(d6b_function_signatures_v1(successor_impl).len(), 2);
        assert_eq!(
            successor_impl
                .matches("pub(crate) fn receive_worker_exec_bound_once_v1(")
                .count(),
            1,
            "the successor must expose one consuming exec-bound receive"
        );
        assert_eq!(
            successor_impl
                .matches("pub(crate) fn receive_worker_frame_v1(")
                .count(),
            1,
            "the successor must retain one borrowed typed worker receive"
        );
        let exec_receive_start = successor_impl
            .find("pub(crate) fn receive_worker_exec_bound_once_v1(")
            .expect("consuming exec-bound worker receive must exist");
        let exec_receive_end = successor_impl[exec_receive_start..]
            .find('{')
            .expect("consuming exec-bound worker receive must have a body")
            + exec_receive_start;
        let exec_receive_signature = successor_impl[exec_receive_start..exec_receive_end]
            .split_whitespace()
            .collect::<String>();
        assert_eq!(
            exec_receive_signature,
            "pub(crate)fnreceive_worker_exec_bound_once_v1(self,input:WorkerExecBoundReceiveInputV1,previous_digest:[u8;32],)->Result<(WorkerExecBoundReceivedEndpointV1,G0TranscriptCandidateV1),SupervisorTypedTransitionErrorV1,>"
        );
        let receive_start = successor_impl
            .find("pub(crate) fn receive_worker_frame_v1(")
            .expect("typed worker receive must exist");
        let receive_end = successor_impl[receive_start..]
            .find('{')
            .expect("typed worker receive must have a body")
            + receive_start;
        let receive_signature = successor_impl[receive_start..receive_end]
            .split_whitespace()
            .collect::<String>();
        assert_eq!(
            receive_signature,
            "pub(crate)fnreceive_worker_frame_v1(&self,frame_buffer:&mut[u8;CONTRACT_MAX_FRAME_BYTES_V1],expectation:&StrictReceiveExpectationV1,)->Result<ReceivedFrameV1,AncillaryReceiveErrorV1>"
        );
        for forbidden in [
            "fn into_parts",
            "fn endpoint",
            "fn descriptor",
            "fn retry",
            "fn resend",
            "Box<[u8]>",
            "Vec<OwnedFd>",
            "BorrowedFd",
            "OwnedFd",
            "RawFd",
            "UCred",
            "&[u8]",
        ] {
            assert!(
                !successor_impl.contains(forbidden),
                "worker enqueue-success state gained raw authority: {forbidden}"
            );
        }
        for forbidden in [
            "AsFd for WorkerBootstrapEnqueuedEndpointV1",
            "AsRawFd for WorkerBootstrapEnqueuedEndpointV1",
            "Clone for WorkerBootstrapEnqueuedEndpointV1",
            "Copy for WorkerBootstrapEnqueuedEndpointV1",
            "Default for WorkerBootstrapEnqueuedEndpointV1",
            "WorkerBootstrapEnqueuedEndpointV1::default",
        ] {
            assert!(
                !ancillary.contains(forbidden),
                "worker enqueue-success state gained a raw or duplicating trait: {forbidden}"
            );
        }
        assert!(process.contains("bootstrap_enqueued: &WorkerBootstrapEnqueuedEndpointV1"));
        assert!(!process.contains("WorkerBootstrapEnqueuedEndpointV1 {"));
        assert!(!process.contains("WorkerBootstrapEnqueuedEndpointV1::"));
    }

    #[test]
    fn supervisor_abi_surface_is_crate_private_v1() {
        let ancillary = include_str!("ancillary.rs");
        let process = include_str!("process.rs");

        for required in [
            "pub(crate) fn try_for_generator(",
            "pub(crate) fn try_for_worker(",
            "pub(crate) struct SupervisorGeneratorEndpointV1",
            "pub(crate) struct SupervisorWorkerEndpointV1",
            "pub(crate) struct GeneratorChannelV1",
            "pub(crate) struct WorkerChannelV1",
            "pub(crate) struct SupervisorGeneratorSendOpV1",
            "pub(crate) struct SupervisorWorkerBootstrapSendOpV1",
            "pub(crate) struct WorkerBootstrapEnqueuedEndpointV1",
            "pub(crate) fn create_generator_channel_v1(",
            "pub(crate) fn create_worker_channel_v1(",
        ] {
            assert!(
                ancillary.contains(required),
                "missing crate-private ancillary boundary: {required}"
            );
        }
        for required in [
            "pub(crate) struct GeneratorSpawnPlanV1",
            "pub(crate) struct WorkerSpawnPlanV1",
            "pub(crate) struct CheckedWorkerMapsV1",
            "pub(crate) struct BlockedWorkerV1",
            "pub(crate) struct WorkerReleaseErrorV1",
            "pub(crate) fn spawn_generator_once_v1(",
            "pub(crate) fn spawn_worker_once_v1(",
            "pub(crate) fn configure_namespace_maps(",
            "pub(crate) fn release_after_bootstrap_enqueued_v1(",
        ] {
            assert!(
                process.contains(required),
                "missing crate-private process boundary: {required}"
            );
        }
    }

    #[test]
    fn generic_child_receive_surface_is_private_v1() {
        let ancillary = include_str!("ancillary.rs");
        let generator_start = ancillary.find("impl GeneratorEndpointV1").unwrap();
        let generator_end = ancillary[generator_start..]
            .find("/// Opaque supervisor endpoint on the generator channel.")
            .unwrap()
            + generator_start;
        let generator_impl = &ancillary[generator_start..generator_end];
        let worker_start = ancillary.find("impl WorkerEndpointV1").unwrap();
        let worker_end = ancillary[worker_start..]
            .find("/// Generator-channel endpoint custody")
            .unwrap()
            + worker_start;
        let worker_impl = &ancillary[worker_start..worker_end];

        for required in [
            "pub struct GeneratorEndpointV1",
            "pub struct WorkerEndpointV1",
            "pub(crate) struct ExpectedPeerCredentialsV1",
            "pub(crate) struct StrictReceiveExpectationV1",
            "pub(crate) fn try_for_supervisor_to_generator(",
            "pub(crate) fn try_for_supervisor_to_worker(",
        ] {
            assert!(
                ancillary.contains(required),
                "missing child-side boundary: {required}"
            );
        }
        for forbidden in [
            "impl AsFd for GeneratorEndpointV1",
            "impl AsRawFd for GeneratorEndpointV1",
            "impl AsFd for WorkerEndpointV1",
            "impl AsRawFd for WorkerEndpointV1",
            "pub fn into_parts",
            "pub fn reconnect",
            "pub fn receive_supervisor_for_generator_frame_v1(",
            "pub fn receive_supervisor_for_worker_frame_v1(",
            "pub fn try_for_supervisor_to_generator(",
            "pub fn try_for_supervisor_to_worker(",
            "pub struct ReceivedFdV1",
            "pub struct ReceivedFrameV1",
            "pub fn descriptor(&self) -> BorrowedFd",
            "pub fn descriptors(&self) -> Vec<BorrowedFd",
        ] {
            assert!(
                !ancillary.contains(forbidden),
                "child endpoint escape hatch: {forbidden}"
            );
        }
        assert!(!generator_impl.contains("pub fn descriptor(&self)"));
        assert!(!worker_impl.contains("pub fn descriptor(&self)"));
        assert!(!generator_impl.contains("pub fn receive_supervisor_for_generator_frame_v1"));
        assert!(!worker_impl.contains("pub fn receive_supervisor_for_worker_frame_v1"));

        let public_reexports = ancillary
            .split("pub use strict_model::selected_target::{")
            .skip(1)
            .filter_map(|tail| tail.split("};").next())
            .collect::<String>();
        for forbidden in [
            "ExpectedPeerCredentialsV1",
            "StrictReceiveExpectationV1",
            "ReceivedFdV1",
            "ReceivedFrameV1",
        ] {
            assert!(
                !public_reexports.contains(forbidden),
                "generic child receive type escaped through public reexport: {forbidden}"
            );
        }
    }

    #[test]
    fn external_cannot_spawn_split_or_release_v1() {
        let root = include_str!("lib.rs");
        let ancillary = include_str!("ancillary.rs");
        let process = include_str!("process.rs");

        for forbidden in [
            "pub struct SupervisorGeneratorEndpointV1",
            "pub struct SupervisorWorkerEndpointV1",
            "pub struct GeneratorChannelV1",
            "pub struct WorkerChannelV1",
            "pub struct WorkerBootstrapEnqueuedEndpointV1",
            "pub fn create_generator_channel_v1(",
            "pub fn create_worker_channel_v1(",
            "pub fn enqueue_worker_bootstrap_once(",
        ] {
            assert!(
                !ancillary.contains(forbidden),
                "public supervisor ancillary bypass: {forbidden}"
            );
        }
        for forbidden in [
            "pub struct GeneratorSpawnPlanV1",
            "pub struct WorkerSpawnPlanV1",
            "pub struct CheckedWorkerMapsV1",
            "pub struct BlockedWorkerV1",
            "pub struct WorkerReleaseErrorV1",
            "pub fn spawn_generator_once_v1(",
            "pub fn spawn_worker_once_v1(",
            "pub fn configure_namespace_maps(",
            "pub fn release_after_checked_maps(",
            "pub fn into_child(",
        ] {
            assert!(
                !process.contains(forbidden),
                "public supervisor process bypass: {forbidden}"
            );
        }
        let crate_docs = root
            .split("#![deny(unsafe_op_in_unsafe_fn)]")
            .next()
            .unwrap();
        assert_eq!(crate_docs.matches("```compile_fail").count(), 5);
        assert!(!root.contains("pub use selected_target::{\n    BlockedWorkerV1"));
    }

    #[test]
    fn inherited_fd3_adoption_is_owned_safe_once_v1() {
        let ancillary = include_str!("ancillary.rs");
        for signature in [
            "pub fn try_adopt_generator_exec_inherited_fd3_once_v1(\n            descriptor: OwnedFd,",
            "pub fn try_adopt_worker_exec_inherited_fd3_once_v1(\n            descriptor: OwnedFd,",
        ] {
            assert!(
                ancillary.contains(signature),
                "missing owned role-specific fd3 adoption: {signature}"
            );
        }
        assert_eq!(
            ancillary
                .matches("static INHERITED_ENDPOINT_ADOPTION_ATTEMPTED_V1: AtomicBool")
                .count(),
            1
        );
        assert_eq!(
            ancillary
                .matches("AtomicBool = AtomicBool::new(false)")
                .count(),
            1,
            "generator and worker must share one adoption gate"
        );
        let adoption_start = ancillary
            .find("fn adopt_inherited_endpoint_v1(")
            .expect("shared adoption implementation must exist");
        let adoption = &ancillary[adoption_start..];
        let body = adoption
            .split_once('{')
            .expect("adoption implementation must have a body")
            .1
            .trim_start();
        assert!(body.starts_with("if INHERITED_ENDPOINT_ADOPTION_ATTEMPTED_V1"));
        let normalized = adoption.split_whitespace().collect::<String>();
        assert!(normalized.contains(
            "INHERITED_ENDPOINT_ADOPTION_ATTEMPTED_V1.compare_exchange(false,true,Ordering::AcqRel,Ordering::Acquire)"
        ));
        assert!(ancillary.contains("Ordering::AcqRel"));
        assert!(ancillary.contains("Ordering::Acquire"));
        assert!(!ancillary.contains("reset_inherited_endpoint_adoption"));
        assert!(!ancillary.contains("pub fn adopt_inherited_endpoint_v1"));
        assert!(!ancillary.contains("pub(crate) fn adopt_inherited_endpoint_v1"));
        assert!(!ancillary.contains("pub(super) fn adopt_inherited_endpoint_v1"));
        assert!(!ancillary.contains("pub unsafe fn try_adopt"));
        let public_reexports = ancillary
            .split("pub use strict_model::selected_target::{")
            .nth(1)
            .and_then(|tail| tail.split("};").next())
            .expect("selected-target child API must be reexported");
        for required in [
            "try_adopt_generator_exec_inherited_fd3_once_v1",
            "try_adopt_worker_exec_inherited_fd3_once_v1",
            "InheritedEndpointAdoptionErrorV1",
        ] {
            assert!(public_reexports.contains(required));
        }
    }

    #[test]
    fn inherited_fd3_adoption_reobserves_and_fails_terminal_v1() {
        let ancillary = include_str!("ancillary.rs");
        let start = ancillary
            .find("fn adopt_inherited_endpoint_v1(")
            .expect("shared adoption implementation must exist");
        let end = ancillary[start..]
            .find("\n        /// Adopts the owning inherited fd3 generator endpoint exactly once.")
            .expect("shared adoption implementation must close before its public wrappers")
            + start;
        let adoption = &ancillary[start..end];
        assert!(adoption.contains("descriptor.as_raw_fd() != 3"));
        assert_eq!(adoption.matches("observe_endpoint_v1(").count(), 2);
        assert!(adoption.contains("validate_endpoint_reread_v1(first, second)"));
        assert!(adoption.contains("!first.nonblocking"));
        assert!(adoption.contains("!first.close_on_exec"));
        assert!(adoption.contains("second.nonblocking || second.close_on_exec"));
        for required_fs_import in [
            "CWD",
            "Dir",
            "Mode",
            "OFlags",
            "PROC_SUPER_MAGIC",
            "SealFlags",
            "fstatfs",
            "openat",
        ] {
            assert!(
                ancillary.contains(required_fs_import),
                "missing selected-target filesystem import: {required_fs_import}"
            );
        }
        let normalized_ancillary = ancillary.split_whitespace().collect::<String>();
        assert_eq!(
            normalized_ancillary
                .matches(
                    "userustix::io::{FdFlags,fcntl_dupfd_cloexec,fcntl_getfd,fcntl_setfd,pread};"
                )
                .count(),
            1
        );
        assert!(ancillary.contains("nonblocking: status_flags.contains(OFlags::NONBLOCK)"));
        assert!(ancillary.contains("close_on_exec: descriptor_flags.contains(FdFlags::CLOEXEC)"));
        assert!(!adoption.contains("FromRawFd"));
        assert!(!adoption.contains("fcntl_dup"));
        assert!(!adoption.contains("try_clone"));
        assert!(!adoption.contains(".store("));
        assert!(!adoption.contains(".swap("));
        assert!(!adoption.contains("compare_exchange_weak"));
        assert!(ancillary.contains("pub struct InheritedEndpointAdoptionErrorV1"));
        assert!(!ancillary.contains("impl Clone for InheritedEndpointAdoptionErrorV1"));
        assert!(!ancillary.contains("impl Copy for InheritedEndpointAdoptionErrorV1"));
    }

    #[test]
    fn worker_post_exec_fd3_inventory_is_exact_and_precedes_observation_v1() {
        let ancillary = include_str!("ancillary.rs");
        let inventory_start = ancillary
            .find("struct WorkerPostExecFdInventoryV1")
            .expect("private Worker post-exec inventory state must exist");
        let inventory_end = ancillary[inventory_start..]
            .find("\n        fn adopt_inherited_endpoint_v1(")
            .map(|offset| inventory_start + offset)
            .expect("Worker inventory helpers must close before adoption");
        let inventory = &ancillary[inventory_start..inventory_end];
        for required in [
            "fn parse_canonical_worker_fd_name_v1(",
            "name.is_empty()",
            "name.len() > 1 && name[0] == b'0'",
            "byte.is_ascii_digit()",
            ".checked_mul(10)",
            ".checked_add(",
            "if self.observed_numeric_entries >= 2",
            "self.observed_numeric_entries == 2",
            "self.endpoint_fd3_seen",
            "self.enumeration_fd_seen",
            "fn require_exact_worker_post_exec_fd3_inventory_v1()",
            "openat(",
            "CWD",
            "c\"/proc/self/fd\"",
            "OFlags::RDONLY",
            "OFlags::DIRECTORY",
            "OFlags::CLOEXEC",
            "OFlags::NOFOLLOW",
            "Mode::empty()",
            "fstatfs(descriptor.as_fd())",
            "filesystem.f_type != PROC_SUPER_MAGIC",
            "Dir::new(descriptor)",
            ".fd()",
            ".as_raw_fd()",
            "enumeration_descriptor == 3",
            "while let Some(entry) = directory.read()",
            "entry.file_name().to_bytes()",
            "drop(directory)",
        ] {
            assert!(
                inventory.contains(required),
                "missing exact Worker inventory invariant: {required}"
            );
        }
        for forbidden in [
            "Vec<",
            ".collect::<Vec",
            ".sort",
            ".sort_unstable",
            "pub fn ",
        ] {
            assert!(
                !inventory.contains(forbidden),
                "Worker inventory escaped or became unbounded: {forbidden}"
            );
        }

        let adoption_start = ancillary
            .find("fn adopt_inherited_endpoint_v1(")
            .expect("shared adoption implementation must exist");
        let adoption_end = ancillary[adoption_start..]
            .find("\n        /// Adopts the owning inherited fd3 generator endpoint exactly once.")
            .map(|offset| adoption_start + offset)
            .expect("shared adoption implementation must remain bounded");
        let adoption = &ancillary[adoption_start..adoption_end];
        let cas = adoption.find(".compare_exchange(").unwrap();
        let fd3 = adoption.find("descriptor.as_raw_fd() != 3").unwrap();
        let worker_role = adoption
            .find("role == SeqpacketEndpointRoleV1::Worker")
            .unwrap();
        let worker_inventory = adoption
            .find("require_exact_worker_post_exec_fd3_inventory_v1()")
            .unwrap();
        let first_observation = adoption.find("observe_endpoint_v1(").unwrap();
        assert!(cas < fd3);
        assert!(fd3 < worker_role);
        assert!(worker_role < worker_inventory);
        assert!(worker_inventory < first_observation);
        assert_eq!(
            adoption
                .matches("require_exact_worker_post_exec_fd3_inventory_v1()")
                .count(),
            1
        );
        assert!(!adoption.contains("SeqpacketEndpointRoleV1::Generator {"));
    }

    #[test]
    fn private_endpoint_commitment_v1() {
        let ancillary = include_str!("ancillary.rs");
        let endpoint_start = ancillary
            .find("struct SeqpacketEndpointV1")
            .expect("private endpoint owner must exist");
        let endpoint_end = ancillary[endpoint_start..]
            .find("/// Opaque generator-side endpoint")
            .expect("private endpoint declaration must close")
            + endpoint_start;
        let endpoint = &ancillary[endpoint_start..endpoint_end];
        assert!(endpoint.contains("commitment: SeqpacketEndpointCommitmentV1"));
        assert!(ancillary.contains("fn commitment(&self) -> &SeqpacketEndpointCommitmentV1"));
        assert_eq!(
            ancillary
                .matches("fn commitment(&self) -> &SeqpacketEndpointCommitmentV1")
                .count(),
            3,
            "one child-local and both supervisor commitments stay private"
        );
        assert!(!endpoint.contains("pub commitment"));
        assert!(!ancillary.contains("pub fn commitment("));
        assert!(!ancillary.contains("pub fn endpoint_commitment("));
    }

    #[test]
    fn session_offer_receive_v1() {
        let ancillary = include_str!("ancillary.rs");
        for required in [
            "pub struct GeneratorPeerSessionOfferEndpointV1",
            "pub struct GeneratorPeerGCommitSendEndpointV1",
            "pub fn begin_peer_session_v1(",
            "pub fn receive_session_offer_once_v1(",
            "let parent_before = getppid()",
            "let parent_after = getppid()",
            "parent_after != parent_before",
            "G0_SESSION_OFFER_BYTES_V1",
        ] {
            assert!(
                ancillary.contains(required),
                "missing consuming SessionOffer receive boundary: {required}"
            );
        }
        assert!(
            ancillary.contains("process_id: u32::try_from(parent_before.as_raw_nonzero().get())")
        );
        assert!(!ancillary.contains("SO_PEERCRED"));
        assert!(!ancillary.contains("receive_session_offer_once_v1(\n                &self"));
    }

    #[test]
    fn provider_session_v1() {
        let ancillary = include_str!("ancillary.rs");
        for required in [
            "pub struct GeneratorPeerGCommitSendEndpointV1",
            "pub struct GeneratorPeerSCommitReceiveEndpointV1",
            "pub struct GeneratorPeerGRevealSendEndpointV1",
            "pub struct GeneratorPeerSRevealReceiveEndpointV1",
            "pub struct GeneratorProviderSessionEndpointV1",
            "prepare_generator_commit_record_v1()",
            "prepare_generator_reveal_record_v1()",
            "G0GeneratorPeerSessionInputV1 {",
            "G0GeneratorPeerSessionCandidateV1::try_new(",
            "local_generator_endpoint: self.endpoint.commitment()",
            "pub fn send_generator_bound_once_v1(",
        ] {
            assert!(
                ancillary.contains(required),
                "missing provider-session producer/consumer join: {required}"
            );
        }
        for forbidden in [
            "impl Clone for GeneratorProviderSessionEndpointV1",
            "impl Copy for GeneratorProviderSessionEndpointV1",
            "pub fn endpoint(",
            "pub fn candidate(",
            "pub fn into_parts(",
        ] {
            assert!(
                !ancillary.contains(forbidden),
                "provider-session custody escaped or advanced too early: {forbidden}"
            );
        }
    }

    #[test]
    fn raw_generator_cannot_bypass_peer_session_v1() {
        let ancillary = include_str!("ancillary.rs");
        assert!(ancillary.contains("pub fn begin_peer_session_v1("));
        let raw_generator_start = ancillary
            .find("impl GeneratorEndpointV1 {")
            .expect("raw generator endpoint implementation must exist");
        let raw_generator_end = ancillary[raw_generator_start..]
            .find("struct ParentSupervisorIdentityV1 {")
            .expect("raw generator implementation must close before supervisor identity")
            + raw_generator_start;
        let raw_generator = &ancillary[raw_generator_start..raw_generator_end];
        for forbidden in ["send_generator_bound_once_v1", "GeneratorBoundSendInputV1"] {
            assert!(
                !raw_generator.contains(forbidden),
                "raw generator can bypass peer-session custody: {forbidden}"
            );
        }
        let public_reexports = ancillary
            .split("pub use strict_model::selected_target::{")
            .skip(1)
            .filter_map(|tail| tail.split("};").next())
            .collect::<Vec<_>>();
        assert_eq!(
            public_reexports.len(),
            2,
            "selected-target child API must have exactly two public reexport blocks"
        );
        for required in [
            "GeneratorBoundSendInputV1",
            "GeneratorBoundAwaitClosedResultEndpointV1",
        ] {
            assert!(
                public_reexports
                    .iter()
                    .any(|reexports| reexports.contains(required)),
                "selected-target child API must publicly reexport {required}"
            );
        }
        for forbidden in ["GeneratorBoundSentEndpointV1"] {
            assert!(
                !public_reexports
                    .iter()
                    .any(|reexports| reexports.contains(forbidden)),
                "raw GeneratorBound surface remained publicly reexported: {forbidden}"
            );
        }
    }

    #[test]
    fn worker_prebootstrap_send_surface_is_closed_v1() {
        let ancillary_source = include_str!("ancillary.rs");
        let ancillary = super::d6b_production_without_tests_v1(ancillary_source);
        for forbidden in [
            "pub struct WorkerExecBoundSendInputV1",
            "pub fn send_worker_exec_bound_once_v1(",
            "pub struct WorkerExecBoundSentEndpointV1",
        ] {
            assert!(
                !ancillary.contains(forbidden),
                "pre-bootstrap worker bypass remained reachable: {forbidden}"
            );
        }
        let start = ancillary
            .find("impl WorkerEndpointV1")
            .expect("worker endpoint impl must remain bounded");
        let end = ancillary[start..]
            .find("/// Generator-channel endpoint custody")
            .expect("worker endpoint impl must end before channel custody")
            + start;
        assert!(!ancillary[start..end].contains("pub fn "));
    }

    #[test]
    fn worker_exec_bound_send_is_unreachable_before_bootstrap_v1() {
        let ancillary_source = include_str!("ancillary.rs");
        let ancillary = super::d6b_production_without_tests_v1(ancillary_source);
        for forbidden in [
            "WorkerExecBoundSendInputV1",
            "WorkerExecBoundSentEndpointV1",
            "send_worker_exec_bound_once_v1",
            "encode_worker_exec_bound_raw_frame_v1",
            "ChannelIdentityV1::try_worker_child(",
            "worker_bootstrap_digest: TranscriptDigestV1",
            "input.supervisor_worker_endpoint_digest",
            "input.worker_bootstrap_digest",
        ] {
            assert!(
                !ancillary.contains(forbidden),
                "pre-bootstrap Worker semantic authority remained: {forbidden}"
            );
        }
    }

    #[test]
    fn worker_cloexec_transition_is_unreachable_before_bootstrap_v1() {
        let ancillary_source = include_str!("ancillary.rs");
        let ancillary = super::d6b_production_without_tests_v1(ancillary_source);
        let start = ancillary.find("impl WorkerEndpointV1 {").unwrap();
        let end = ancillary[start..]
            .find("/// Generator-channel endpoint custody")
            .unwrap()
            + start;
        let worker = &ancillary[start..end];
        for forbidden in [
            "send_seqpacket_once_v1(",
            "fcntl_setfd(",
            "FdFlags::CLOEXEC",
            "verify_worker_post_enqueue_cloexec_v1",
        ] {
            assert!(!worker.contains(forbidden));
        }
    }

    #[test]
    fn child_typed_send_surface_v1() {
        let ancillary = include_str!("ancillary.rs");
        for required in [
            "ChildTypedSendErrorV1",
            "pub(crate) struct ExpectedPeerCredentialsV1",
            "pub(crate) struct StrictReceiveExpectationV1",
            "pub(crate) struct ReceivedFdV1",
            "pub(crate) struct ReceivedFrameV1",
        ] {
            assert!(
                ancillary.contains(required),
                "missing typed child surface: {required}"
            );
        }
        let public_reexports = ancillary
            .split("pub use strict_model::selected_target::{")
            .skip(1)
            .map(|tail| {
                tail.split("};")
                    .next()
                    .expect("selected-target child API must be bounded")
            })
            .collect::<Vec<_>>();
        assert_eq!(public_reexports.len(), 2);
        for required in [
            "ChildTypedSendErrorV1",
            "GeneratorEndpointV1",
            "WorkerEndpointV1",
        ] {
            assert!(public_reexports[0].contains(required));
        }
        for required in [
            "GeneratorPeerSessionOfferEndpointV1",
            "GeneratorPeerGCommitSendEndpointV1",
            "GeneratorPeerSCommitReceiveEndpointV1",
            "GeneratorPeerGRevealSendEndpointV1",
            "GeneratorPeerSRevealReceiveEndpointV1",
            "GeneratorProviderSessionEndpointV1",
            "GeneratorBoundSendInputV1",
            "GeneratorBoundAwaitClosedResultEndpointV1",
        ] {
            assert!(public_reexports[1].contains(required));
        }
        for forbidden in [
            "GeneratorBoundSentEndpointV1",
            "WorkerExecBoundSendInputV1",
            "WorkerExecBoundSentEndpointV1",
            "ExpectedPeerCredentialsV1",
            "StrictReceiveExpectationV1",
            "ReceivedFdV1",
            "ReceivedFrameV1",
        ] {
            assert!(
                public_reexports
                    .iter()
                    .all(|exports| !exports.contains(forbidden))
            );
        }
        for forbidden in [
            "pub fn send_raw",
            "pub fn send_frame",
            "pub fn sendmsg",
            "pub fn resend",
            "pub fn retry",
            "pub fn into_parts",
            "pub fn send_worker_exec_bound_once_v1",
            "pub struct WorkerExecBoundSendInputV1",
            "pub struct WorkerExecBoundSentEndpointV1",
            "impl AsFd for GeneratorEndpointV1",
            "impl AsFd for WorkerEndpointV1",
            "pub fn send_seqpacket_once_v1",
            "pub(crate) fn send_seqpacket_once_v1",
            "pub(super) fn send_seqpacket_once_v1",
        ] {
            assert!(
                !ancillary.contains(forbidden),
                "child send escape: {forbidden}"
            );
        }
    }

    #[test]
    fn child_send_error_consumes_endpoint_v1() {
        let ancillary = include_str!("ancillary.rs");
        for signature in [
            "pub fn send_generator_commit_once_v1(\n                self,\n            ) -> Result<GeneratorPeerSCommitReceiveEndpointV1, ChildTypedSendErrorV1>",
            "pub fn send_generator_reveal_once_v1(\n                self,\n            ) -> Result<GeneratorPeerSRevealReceiveEndpointV1, ChildTypedSendErrorV1>",
        ] {
            assert!(
                ancillary.contains(signature),
                "send must consume its current state and return only its successor: {signature}"
            );
        }
        assert!(ancillary.contains("pub struct ChildTypedSendErrorV1"));
        assert!(!ancillary.contains("Result<(GeneratorPeer"));
        assert!(!ancillary.contains("Result<(WorkerEndpointV1"));
        assert!(!ancillary.contains("Result<WorkerEndpointV1, ChildTypedSendErrorV1>"));
        assert!(!ancillary.contains("send_worker_exec_bound_once_v1"));
        assert!(!ancillary.contains("WorkerExecBoundSendInputV1"));
        assert!(!ancillary.contains("WorkerExecBoundSentEndpointV1"));
    }

    #[test]
    fn inherited_fd3_adoption_has_selected_target_subprocess_matrix_v1() {
        let ancillary = include_str!("ancillary.rs");
        let start = ancillary
            .find("mod inherited_fd3_subprocess_tests {")
            .expect("selected-target adoption subprocess module must exist");
        let end = ancillary[start..]
            .find("mod generator_peer_session_runtime_tests {")
            .map(|offset| start + offset)
            .expect("generator peer-session runtime module must bound the adoption matrix");
        let matrix = &ancillary[start..end];
        assert!(matrix.contains("const SCENARIOS_V1: [&str; 9]"));
        for scenario in [
            "generator-success",
            "worker-stdio-surplus",
            "repeated-after-success",
            "first-failure-cross-role",
            "wrong-fd",
            "wrong-shape",
            "passcred-disabled",
            "nonblocking",
            "cloexec",
        ] {
            assert!(
                matrix.contains(scenario),
                "missing subprocess scenario: {scenario}"
            );
        }
        assert!(matrix.contains("std::env::current_exe()"));
        assert_eq!(matrix.matches("Command::new(\"/bin/bash\")").count(), 1);
        assert_eq!(
            matrix
                .matches("for fd in {3..37}; do eval \\\"exec ${fd}>&-\\\"; done; exec \\\"$@\\\"")
                .count(),
            1
        );
        assert!(matrix.contains(".arg(\"eip0045-g0b31-adoption-fixture\")"));
        assert!(matrix.contains(".arg(&executable)"));
        assert!(matrix.contains(".env(SCENARIO_ENV_V1, scenario)"));
        assert!(matrix.contains("try_adopt_generator_exec_inherited_fd3_once_v1("));
        assert!(matrix.contains("try_adopt_worker_exec_inherited_fd3_once_v1("));
        assert!(matrix.contains("ENDPOINT_OBSERVATION_CALLS_V1.load(Ordering::Relaxed)"));
        assert!(matrix.contains("assert_observation_delta_v1(before, 2)"));
        assert!(matrix.contains("SeqpacketEndpointRoleV1::Generator,"));
        assert!(matrix.contains("SeqpacketEndpointRoleV1::Worker,"));
        assert_eq!(
            matrix
                .matches("SeqpacketEndpointCommitmentV1::from_observation(")
                .count(),
            1
        );
        assert!(matrix.contains("assert_closed_v1("));
        assert!(matrix.contains("read_link(format!(\"/proc/self/fd/{raw_descriptor}\"))"));
        assert!(!matrix.contains("from_raw_fd"));
        assert!(!matrix.contains("FromRawFd"));
        assert!(!matrix.contains("INHERITED_ENDPOINT_ADOPTION_ATTEMPTED_V1.store"));
    }

    #[test]
    fn worker_post_exec_fd3_inventory_has_fresh_exact_subprocess_matrix_v1() {
        let package = include_str!("../Cargo.toml");
        let fixture = include_str!("../tests/worker_post_exec_fd_inventory.rs");
        let leaf = include_str!("../tests/fixtures/worker_post_exec_fd_inventory_leaf.rs");
        for required_manifest in [
            "[[test]]",
            "name = \"worker-post-exec-fd-inventory\"",
            "path = \"tests/worker_post_exec_fd_inventory.rs\"",
            "harness = false",
            "required-features = [\"h0-tmpfs-provider-v2-g0\"]",
        ] {
            assert!(
                package.contains(required_manifest),
                "missing harness-free Worker inventory target: {required_manifest}"
            );
        }
        for required_leaf_manifest in [
            "[[bin]]",
            "name = \"worker-post-exec-fd-inventory-leaf\"",
            "path = \"tests/fixtures/worker_post_exec_fd_inventory_leaf.rs\"",
            "test = false",
            "bench = false",
            "doc = false",
            "harness = false",
        ] {
            assert!(
                package.contains(required_leaf_manifest),
                "missing no-std-runtime Worker inventory leaf: {required_leaf_manifest}"
            );
        }
        assert!(fixture.contains("const SCENARIOS_V1: [&str; 5]"));
        for scenario in [
            "exact-fd3",
            "fd0-surplus",
            "fd4-surplus",
            "fd4-alias",
            "retry-after-surplus",
        ] {
            assert!(
                fixture.contains(scenario),
                "missing Worker inventory scenario: {scenario}"
            );
        }
        for required in [
            "ORCHESTRATOR_STAGE_V1",
            "CLOSER_STAGE_V1",
            "Command::new(\"/usr/bin/timeout\")",
            ".arg(\"--signal=KILL\")",
            ".arg(\"20s\")",
            "fn prepare_closer_v1(",
            "fstatfs(descriptor.as_fd())",
            "expected_surplus_v1(scenario)",
            "fn closer_exec_v1(",
            "rustix::io::close(*descriptor)",
            "require_expected_inventory_v1(scenario)",
            "CARGO_BIN_EXE_worker-post-exec-fd-inventory-leaf",
            "CString::new(scenario)",
            "let environment_pointers = [std::ptr::null::<c_char>()];",
            "c_execve(",
            "c_exit(127)",
            "rustix::io::dup(worker)",
        ] {
            assert!(
                fixture.contains(required),
                "missing fresh Worker inventory runtime invariant: {required}"
            );
        }
        for required_leaf in [
            "#![cfg_attr(",
            "no_main",
            "fn c_fcntl(descriptor: i32, command: i32, ...) -> i32",
            "c_fcntl(WORKER_ENDPOINT_FD_V1, F_GETFD_V1) < 0",
            "#[unsafe(export_name = \"main\")]",
            "pub extern \"C\" fn fixture_main(",
            "_environment: *mut *mut core::ffi::c_char",
            "OwnedFd::from_raw_fd(WORKER_ENDPOINT_FD_V1)",
            "let first_adoption = try_adopt_worker_exec_inherited_fd3_once_v1(inherited);",
            "CStr::from_ptr(scenario).to_bytes()",
            "fn retry_after_surplus_v1(",
            "try_adopt_worker_exec_inherited_fd3_once_v1(repeated)",
            "descriptor_is_closed_v1(WORKER_ENDPOINT_FD_V1)",
        ] {
            assert!(
                leaf.contains(required_leaf),
                "missing C-entry Worker inventory leaf invariant: {required_leaf}"
            );
        }
        let closer_start = fixture.find("fn closer_exec_v1(").unwrap();
        let closer_end = fixture[closer_start..]
            .find("\n    fn wait_for_leaf_v1(")
            .unwrap()
            + closer_start;
        let closer = &fixture[closer_start..closer_end];
        let close = closer.find("rustix::io::close(*descriptor)").unwrap();
        let directory_drop = closer.find("drop(directory)").unwrap();
        let reread = closer
            .find("require_expected_inventory_v1(scenario)")
            .unwrap();
        let exec = closer.find("c_execve(").unwrap();
        assert!(close < directory_drop);
        assert!(directory_drop < reread);
        assert!(reread < exec);
        assert!(!closer.contains("vars_os"));
        assert!(!closer.contains("SCENARIO_ENV_V1"));

        let leaf_start = leaf.find("pub(super) fn main_v1(").unwrap();
        let leaf_end = leaf[leaf_start..].find("\n}\n\n/// C ABI entry").unwrap() + leaf_start;
        let leaf_main = &leaf[leaf_start..leaf_end];
        let raw_guard = leaf_main
            .find("c_fcntl(WORKER_ENDPOINT_FD_V1, F_GETFD_V1)")
            .unwrap();
        let raw_owner = leaf_main
            .find("OwnedFd::from_raw_fd(WORKER_ENDPOINT_FD_V1)")
            .unwrap();
        let adoption = leaf_main
            .find("try_adopt_worker_exec_inherited_fd3_once_v1(inherited)")
            .unwrap();
        let argument_check = leaf_main.find("argument_count != 2").unwrap();
        let dispatch = leaf_main.find("match scenario").unwrap();
        assert!(raw_guard < raw_owner);
        assert!(raw_owner < adoption);
        assert!(adoption < argument_check);
        assert!(argument_check < dispatch);
        let pre_adoption = &leaf_main[raw_owner..adoption];
        for forbidden_before_adoption in [
            "File::open",
            "socketpair(",
            "CStr::from_ptr",
            "std::env",
            "println!",
            "eprintln!",
        ] {
            assert!(!pre_adoption.contains(forbidden_before_adoption));
        }
        assert_eq!(
            leaf.matches("OwnedFd::from_raw_fd(WORKER_ENDPOINT_FD_V1)")
                .count(),
            1
        );
        assert_eq!(leaf.matches("#[unsafe(export_name = \"main\")]").count(), 1);
        assert_eq!(leaf.matches("fn main() {}").count(), 1);
        assert_eq!(package.matches("harness = false").count(), 2);
        assert!(!fixture.contains("LEAF_STAGE_V1"));
        assert!(!fixture.contains("FromRawFd"));
        assert!(!fixture.contains("try_adopt_worker_exec_inherited_fd3_once_v1"));
        assert!(!leaf.contains("pub extern \"C\" fn main("));
        for forbidden_leaf in [
            "std::process::exit",
            "std::env",
            ".unwrap(",
            ".expect(",
            "assert!",
            "panic!",
            "println!",
            "eprintln!",
        ] {
            assert!(!leaf.contains(forbidden_leaf));
        }
        assert!(!fixture.contains("INHERITED_ENDPOINT_ADOPTION_ATTEMPTED_V1.store"));
        assert!(!leaf.contains("INHERITED_ENDPOINT_ADOPTION_ATTEMPTED_V1.store"));
        assert!(!fixture.contains("reset_inherited_endpoint_adoption"));
        assert!(!leaf.contains("reset_inherited_endpoint_adoption"));
        assert!(!fixture.contains("#[ignore]"));
        assert!(!leaf.contains("#[ignore]"));
    }
}
