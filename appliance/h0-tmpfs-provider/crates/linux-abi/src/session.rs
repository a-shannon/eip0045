use crate::ancillary::{
    ClosedResultSendInputV1, GeneratorBoundReceiveInputV1, GeneratorBoundReceivedEndpointV1,
    GeneratorCommitReceiveInputV1, GeneratorRevealReceiveInputV1, SessionOfferSendInputV1,
    SupervisorCommitSendInputV1, SupervisorGeneratorEndpointV1, SupervisorGeneratorSentEndpointV1,
    SupervisorRevealSendInputV1, SupervisorTypedTransitionErrorV1, SupervisorWorkerEndpointV1,
    WorkerBootstrapEnqueuedEndpointV1, WorkerBootstrapSendInputV1, WorkerExecBoundReceiveInputV1,
    WorkerExecBoundReceivedEndpointV1, prepare_closed_result_send_v1,
    prepare_session_offer_send_v1, prepare_supervisor_commit_send_v1,
    prepare_supervisor_reveal_send_v1,
};
use crate::executable_custody::{
    ExecutableCustodyErrorV2, GeneratorChildExecutableCustodyV2, WorkerChildExecutableCustodyV2,
    WorkerMapsVerifiedExecutableCustodyV2,
};
use eip0045_h0_contract::wire::{G0GeneratorBoundTranscriptCandidateV1, G0TranscriptCandidateV1};

enum UninhabitedSessionInputV1 {}

struct RelinquishedChildEndpointsV1 {
    generator_endpoint: SupervisorGeneratorEndpointV1,
    worker_endpoint: SupervisorWorkerEndpointV1,
    generator_executable: GeneratorChildExecutableCustodyV2,
    worker_executable: WorkerMapsVerifiedExecutableCustodyV2,
}

struct ExecutableSessionCompositeV1 {
    generator: GeneratorChildExecutableCustodyV2,
    worker: WorkerMapsVerifiedExecutableCustodyV2,
}

struct PostReleaseSessionCustodyV1 {
    generator: GeneratorChildExecutableCustodyV2,
    worker: WorkerChildExecutableCustodyV2,
}

enum PrivateSessionPhaseV1 {
    AwaitSessionOffer {
        seal: UninhabitedSessionInputV1,
        relinquished: RelinquishedChildEndpointsV1,
    },
}

struct AcceptedGeneratorFrameV1 {
    endpoint: GeneratorBoundReceivedEndpointV1,
}

struct GeneratorAwaitBoundTranscriptStateV1 {
    generator_cursor: u8,
}

struct GeneratorTranscriptStateV1 {
    generator_cursor: u8,
    generator_previous_digest: [u8; 32],
    accepted_worker_genesis: [u8; 32],
}

struct WorkerAwaitBootstrapTranscriptStateV1 {
    worker_cursor: u8,
}

struct WorkerTranscriptStateV1 {
    worker_cursor: u8,
    worker_previous_digest: [u8; 32],
}

struct AggregateCountV1 {
    frames: u8,
}

struct GeneratorBoundPendingV1 {
    seal: UninhabitedSessionInputV1,
    generator_endpoint: SupervisorGeneratorSentEndpointV1,
    worker_endpoint: SupervisorWorkerEndpointV1,
    generator: GeneratorAwaitBoundTranscriptStateV1,
    worker: WorkerAwaitBootstrapTranscriptStateV1,
    aggregate_count: AggregateCountV1,
    executable: ExecutableSessionCompositeV1,
}

struct PrivateSupervisorSessionCoreV1 {
    seal: UninhabitedSessionInputV1,
    accepted_generator: AcceptedGeneratorFrameV1,
    worker_endpoint: SupervisorWorkerEndpointV1,
    generator: GeneratorTranscriptStateV1,
    worker: WorkerAwaitBootstrapTranscriptStateV1,
    aggregate_count: AggregateCountV1,
    executable: ExecutableSessionCompositeV1,
}

struct WorkerBootstrapReleasedV1 {
    seal: UninhabitedSessionInputV1,
    accepted_generator: AcceptedGeneratorFrameV1,
    generator: GeneratorTranscriptStateV1,
    worker: WorkerTranscriptStateV1,
    aggregate_count: AggregateCountV1,
    executable: PostReleaseSessionCustodyV1,
    bootstrap_enqueued: WorkerBootstrapEnqueuedEndpointV1,
}

struct WorkerExecBoundAcceptedV1 {
    seal: UninhabitedSessionInputV1,
    accepted_generator: AcceptedGeneratorFrameV1,
    generator: GeneratorTranscriptStateV1,
    worker: WorkerTranscriptStateV1,
    aggregate_count: AggregateCountV1,
    executable: PostReleaseSessionCustodyV1,
    worker_received: WorkerExecBoundReceivedEndpointV1,
}

struct ResultQueuedV1 {
    seal: UninhabitedSessionInputV1,
    sent_endpoint: SupervisorGeneratorSentEndpointV1,
    generator: GeneratorTranscriptStateV1,
    worker: WorkerTranscriptStateV1,
    aggregate_count: AggregateCountV1,
    executable: PostReleaseSessionCustodyV1,
    worker_received: WorkerExecBoundReceivedEndpointV1,
}

struct SessionTransitionErrorV1 {
    _private: (),
}

impl SessionTransitionErrorV1 {
    fn terminal() -> Self {
        Self { _private: () }
    }
}

impl From<ExecutableCustodyErrorV2> for SessionTransitionErrorV1 {
    fn from(_: ExecutableCustodyErrorV2) -> Self {
        Self::terminal()
    }
}

impl From<SupervisorTypedTransitionErrorV1> for SessionTransitionErrorV1 {
    fn from(_: SupervisorTypedTransitionErrorV1) -> Self {
        Self::terminal()
    }
}

impl GeneratorAwaitBoundTranscriptStateV1 {
    fn advance_generator_bound_after_kernel_success_v1(
        self,
        candidate: G0GeneratorBoundTranscriptCandidateV1,
    ) -> Result<GeneratorTranscriptStateV1, SessionTransitionErrorV1> {
        let generator_cursor = self
            .generator_cursor
            .checked_add(1)
            .ok_or(SessionTransitionErrorV1::terminal())?;
        Ok(GeneratorTranscriptStateV1 {
            generator_cursor,
            generator_previous_digest: candidate.digest(),
            accepted_worker_genesis: candidate.worker_genesis(),
        })
    }
}

impl GeneratorTranscriptStateV1 {
    fn advance_closed_result_after_kernel_success_v1(
        mut self,
        candidate: G0TranscriptCandidateV1,
    ) -> Result<Self, SessionTransitionErrorV1> {
        self.generator_cursor = self
            .generator_cursor
            .checked_add(1)
            .ok_or(SessionTransitionErrorV1::terminal())?;
        self.generator_previous_digest = candidate.digest();
        Ok(self)
    }
}

impl WorkerAwaitBootstrapTranscriptStateV1 {
    fn advance_worker_bootstrap_after_kernel_success_v1(
        self,
        candidate: G0TranscriptCandidateV1,
    ) -> Result<WorkerTranscriptStateV1, SessionTransitionErrorV1> {
        let worker_cursor = self
            .worker_cursor
            .checked_add(1)
            .ok_or(SessionTransitionErrorV1::terminal())?;
        Ok(WorkerTranscriptStateV1 {
            worker_cursor,
            worker_previous_digest: candidate.digest(),
        })
    }
}

impl WorkerTranscriptStateV1 {
    fn advance_worker_exec_bound_after_kernel_success_v1(
        mut self,
        candidate: G0TranscriptCandidateV1,
    ) -> Result<Self, SessionTransitionErrorV1> {
        self.worker_cursor = self
            .worker_cursor
            .checked_add(1)
            .ok_or(SessionTransitionErrorV1::terminal())?;
        self.worker_previous_digest = candidate.digest();
        Ok(self)
    }
}

impl AggregateCountV1 {
    fn require_capacity_v1(&self) -> Result<(), SessionTransitionErrorV1> {
        if self.frames >= 64 {
            return Err(SessionTransitionErrorV1::terminal());
        }
        Ok(())
    }

    fn advance_after_kernel_success_v1(mut self) -> Result<Self, SessionTransitionErrorV1> {
        self.frames = self
            .frames
            .checked_add(1)
            .ok_or(SessionTransitionErrorV1::terminal())?;
        Ok(self)
    }
}

fn require_equal_projection_v1<T: PartialEq>(
    before: &T,
    after: &T,
) -> Result<(), SessionTransitionErrorV1> {
    if before != after {
        return Err(SessionTransitionErrorV1::terminal());
    }
    Ok(())
}

fn begin_after_parent_endpoint_relinquishment_v1(
    relinquished: RelinquishedChildEndpointsV1,
    seal: UninhabitedSessionInputV1,
) -> PrivateSessionPhaseV1 {
    PrivateSessionPhaseV1::AwaitSessionOffer { seal, relinquished }
}

fn send_offer_before_nonce_exchange_v1(
    state: PrivateSessionPhaseV1,
    session_offer: SessionOfferSendInputV1,
    generator_commit: GeneratorCommitReceiveInputV1,
    supervisor_commit: SupervisorCommitSendInputV1,
    generator_reveal: GeneratorRevealReceiveInputV1,
    supervisor_reveal: SupervisorRevealSendInputV1,
) -> Result<GeneratorBoundPendingV1, SessionTransitionErrorV1> {
    let PrivateSessionPhaseV1::AwaitSessionOffer { seal, relinquished } = state;
    let RelinquishedChildEndpointsV1 {
        generator_endpoint,
        worker_endpoint,
        generator_executable,
        worker_executable,
    } = relinquished;
    let operation = prepare_session_offer_send_v1(generator_endpoint, session_offer)?;
    let (offer_before, generator_endpoint) =
        generator_executable.enqueue_supervisor_generator_once_v1(operation)?;
    let offer_after = generator_executable.supervisor_receive_projection_v1()?;
    require_equal_projection_v1(&offer_before, &offer_after)?;
    let commit_before = generator_executable.supervisor_receive_projection_v1()?;
    let commit_endpoint =
        generator_endpoint.receive_generator_nonce_commit_once_v1(generator_commit)?;
    let commit_after = generator_executable.supervisor_receive_projection_v1()?;
    require_equal_projection_v1(&commit_before, &commit_after)?;
    let operation = prepare_supervisor_commit_send_v1(commit_endpoint, supervisor_commit)?;
    let (commit_send_before, generator_endpoint) =
        generator_executable.enqueue_supervisor_generator_once_v1(operation)?;
    let commit_send_after = generator_executable.supervisor_receive_projection_v1()?;
    require_equal_projection_v1(&commit_send_before, &commit_send_after)?;
    let reveal_before = generator_executable.supervisor_receive_projection_v1()?;
    let reveal_endpoint =
        generator_endpoint.receive_generator_nonce_reveal_once_v1(generator_reveal)?;
    let reveal_after = generator_executable.supervisor_receive_projection_v1()?;
    require_equal_projection_v1(&reveal_before, &reveal_after)?;
    let operation = prepare_supervisor_reveal_send_v1(reveal_endpoint, supervisor_reveal)?;
    let (reveal_send_before, generator_endpoint) =
        generator_executable.enqueue_supervisor_generator_once_v1(operation)?;
    let reveal_send_after = generator_executable.supervisor_receive_projection_v1()?;
    require_equal_projection_v1(&reveal_send_before, &reveal_send_after)?;
    let successor = GeneratorBoundPendingV1 {
        seal,
        generator_endpoint,
        worker_endpoint,
        generator: GeneratorAwaitBoundTranscriptStateV1 {
            generator_cursor: 0,
        },
        worker: WorkerAwaitBootstrapTranscriptStateV1 { worker_cursor: 0 },
        aggregate_count: AggregateCountV1 { frames: 0 },
        executable: ExecutableSessionCompositeV1 {
            generator: generator_executable,
            worker: worker_executable,
        },
    };
    Ok(successor)
}

fn receive_then_advance_generator_bound_v1(
    mut state: GeneratorBoundPendingV1,
    input: GeneratorBoundReceiveInputV1,
) -> Result<PrivateSupervisorSessionCoreV1, SessionTransitionErrorV1> {
    state.aggregate_count.require_capacity_v1()?;
    let before = state
        .executable
        .generator
        .supervisor_receive_projection_v1()?;
    let (received_endpoint, candidate) = state
        .generator_endpoint
        .receive_generator_bound_once_v1(input)?;
    let after = state
        .executable
        .generator
        .supervisor_receive_projection_v1()?;
    require_equal_projection_v1(&before, &after)?;
    let generator = state
        .generator
        .advance_generator_bound_after_kernel_success_v1(candidate)?;
    state.aggregate_count = state.aggregate_count.advance_after_kernel_success_v1()?;
    let successor = PrivateSupervisorSessionCoreV1 {
        seal: state.seal,
        accepted_generator: AcceptedGeneratorFrameV1 {
            endpoint: received_endpoint,
        },
        worker_endpoint: state.worker_endpoint,
        generator,
        worker: state.worker,
        aggregate_count: state.aggregate_count,
        executable: state.executable,
    };
    Ok(successor)
}

fn enqueue_then_release_worker_v1(
    mut state: PrivateSupervisorSessionCoreV1,
    input: WorkerBootstrapSendInputV1,
) -> Result<WorkerBootstrapReleasedV1, SessionTransitionErrorV1> {
    state.aggregate_count.require_capacity_v1()?;
    let (operation, candidate) = state
        .worker_endpoint
        .prepare_worker_bootstrap_send_v1(input, state.generator.accepted_worker_genesis)?;
    let (before, bootstrap_enqueued) = state
        .executable
        .worker
        .enqueue_supervisor_bootstrap_once_v1(operation)?;
    let worker_transcript = state
        .worker
        .advance_worker_bootstrap_after_kernel_success_v1(candidate)?;
    state.aggregate_count = state.aggregate_count.advance_after_kernel_success_v1()?;
    let after = state.executable.worker.worker_bootstrap_projection_v1()?;
    require_equal_projection_v1(&before, &after)?;
    let worker = state
        .executable
        .worker
        .release_after_bootstrap_enqueued_v1(&bootstrap_enqueued)?;
    let successor = WorkerBootstrapReleasedV1 {
        seal: state.seal,
        accepted_generator: state.accepted_generator,
        generator: state.generator,
        worker: worker_transcript,
        aggregate_count: state.aggregate_count,
        executable: PostReleaseSessionCustodyV1 {
            generator: state.executable.generator,
            worker,
        },
        bootstrap_enqueued,
    };
    Ok(successor)
}

fn receive_then_advance_worker_exec_bound_v1(
    mut state: WorkerBootstrapReleasedV1,
    input: WorkerExecBoundReceiveInputV1,
) -> Result<WorkerExecBoundAcceptedV1, SessionTransitionErrorV1> {
    state.aggregate_count.require_capacity_v1()?;
    let before = state.executable.worker.supervisor_receive_projection_v1()?;
    let (worker_received, candidate) = state
        .bootstrap_enqueued
        .receive_worker_exec_bound_once_v1(input, state.worker.worker_previous_digest)?;
    let after = state.executable.worker.supervisor_receive_projection_v1()?;
    require_equal_projection_v1(&before, &after)?;
    state.worker = state
        .worker
        .advance_worker_exec_bound_after_kernel_success_v1(candidate)?;
    state.aggregate_count = state.aggregate_count.advance_after_kernel_success_v1()?;
    let successor = WorkerExecBoundAcceptedV1 {
        seal: state.seal,
        accepted_generator: state.accepted_generator,
        generator: state.generator,
        worker: state.worker,
        aggregate_count: state.aggregate_count,
        executable: state.executable,
        worker_received,
    };
    Ok(successor)
}

fn enqueue_then_advance_closed_result_v1(
    mut state: WorkerExecBoundAcceptedV1,
    input: ClosedResultSendInputV1,
) -> Result<ResultQueuedV1, SessionTransitionErrorV1> {
    state.aggregate_count.require_capacity_v1()?;
    let (operation, candidate) = prepare_closed_result_send_v1(
        state.accepted_generator.endpoint,
        input,
        state.generator.generator_previous_digest,
    )?;
    let (before, sent_endpoint) = state
        .executable
        .generator
        .enqueue_supervisor_generator_once_v1(operation)?;
    state.generator = state
        .generator
        .advance_closed_result_after_kernel_success_v1(candidate)?;
    state.aggregate_count = state.aggregate_count.advance_after_kernel_success_v1()?;
    let after = state
        .executable
        .generator
        .supervisor_receive_projection_v1()?;
    require_equal_projection_v1(&before, &after)?;
    let result_queued = ResultQueuedV1 {
        seal: state.seal,
        sent_endpoint,
        generator: state.generator,
        worker: state.worker,
        aggregate_count: state.aggregate_count,
        executable: state.executable,
        worker_received: state.worker_received,
    };
    Ok(result_queued)
}

#[cfg(test)]
mod g0a_red_tests {
    use std::sync::OnceLock;

    const ANCILLARY_SOURCE_V1: &str = ::core::include_str!("ancillary.rs");
    const CARGO_SOURCE_V1: &str = ::core::include_str!("../Cargo.toml");
    const EXECUTABLE_CUSTODY_SOURCE_V1: &str = ::core::include_str!("executable_custody.rs");
    const LIB_SOURCE_V1: &str = ::core::include_str!("lib.rs");
    const PROCESS_SOURCE_V1: &str = ::core::include_str!("process.rs");
    const SECCOMP_SOURCE_V1: &str = ::core::include_str!("seccomp.rs");
    const SESSION_SOURCE_V1: &str = ::core::include_str!("session.rs");
    const STATX_SOURCE_V1: &str = ::core::include_str!("statx.rs");

    #[test]
    fn session_test_only_prefix_pin_v1() {
        let boundary = SESSION_SOURCE_V1
            .find("#[cfg(test)]")
            .expect("session production boundary");
        assert_eq!(boundary, 15_387);
        assert!(
            boundary
                < SESSION_SOURCE_V1
                    .find("mod g0a_red_tests")
                    .expect("session test module")
        );
        let expected = [
            0xd4, 0x3a, 0x2b, 0x56, 0xd8, 0x86, 0x95, 0xd5, 0x63, 0xfa, 0x94, 0xa9, 0x07, 0xce,
            0xa4, 0x24, 0xb0, 0x12, 0x73, 0x91, 0xff, 0x8b, 0x62, 0x5c, 0xe9, 0xc1, 0x10, 0x3e,
            0xf4, 0x1c, 0x71, 0x97,
        ];
        let prefix = &SESSION_SOURCE_V1.as_bytes()[..boundary];
        assert_eq!(
            eip0045_h0_contract::wire::g0_final_result_content_digest_v1(prefix).unwrap(),
            expected
        );
        let mut mutant = prefix.to_vec();
        mutant[0] ^= 1;
        assert_ne!(
            eip0045_h0_contract::wire::g0_final_result_content_digest_v1(&mutant).unwrap(),
            expected
        );
    }

    fn token_boundary_v1(source: &[u8], start: usize, len: usize) -> bool {
        let identifier = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
        (start == 0 || !identifier(source[start - 1]))
            && source
                .get(start + len)
                .is_none_or(|byte| !identifier(*byte))
    }

    fn blank_v1(bytes: &mut [u8], start: usize, end: usize) {
        for byte in &mut bytes[start..end] {
            if !matches!(*byte, b'\n' | b'\r') {
                *byte = b' ';
            }
        }
    }

    /// Returns a byte-for-byte positional mask whose comments and every Rust
    /// string/byte-string/C-string/character/raw literal are blanked. Newlines
    /// and all production punctuation retain their original offsets.
    fn rust_code_mask_v1(source: &str) -> String {
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
                blank_v1(&mut output, start, cursor);
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
                assert_eq!(depth, 0, "unterminated Rust block comment at byte {start}");
                blank_v1(&mut output, start, cursor);
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
                    assert!(closed, "unterminated Rust raw string at byte {start}");
                    blank_v1(&mut output, start, cursor);
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
                assert!(closed, "unterminated Rust string at byte {start}");
                blank_v1(&mut output, start, cursor);
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
                assert!(closed, "unterminated Rust character at byte {start}");
                blank_v1(&mut output, start, cursor);
                continue;
            }
            cursor += 1;
        }
        String::from_utf8(output).expect("Rust source mask remains UTF-8")
    }

    fn skip_ws_v1(bytes: &[u8], mut cursor: usize) -> usize {
        while bytes
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            cursor += 1;
        }
        cursor
    }

    fn exact_cfg_test_end_v1(mask: &[u8], start: usize) -> Option<usize> {
        let mut cursor = start;
        for token in [b"#".as_slice(), b"[", b"cfg", b"(", b"test", b")", b"]"] {
            cursor = skip_ws_v1(mask, cursor);
            if !mask.get(cursor..)?.starts_with(token) {
                return None;
            }
            cursor += token.len();
        }
        Some(cursor)
    }

    fn closing_brace_v1(mask: &[u8], opening: usize, gate: &str) -> usize {
        assert_eq!(mask[opening], b'{', "{gate}: expected opening brace");
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
        panic!("{gate}: unbalanced braced item at byte {opening}");
    }

    /// Removes every exact `cfg(test)` item while retaining all production
    /// before, between, and after test-only items.
    fn production_without_tests_v1(source: &str) -> String {
        let mut output = source.as_bytes().to_vec();
        let mut mask = rust_code_mask_v1(source).into_bytes();
        let mut cursor = 0_usize;
        while cursor < mask.len() {
            let Some(relative) = mask[cursor..].iter().position(|byte| *byte == b'#') else {
                break;
            };
            let start = cursor + relative;
            let Some(attribute_end) = exact_cfg_test_end_v1(&mask, start) else {
                cursor = start + 1;
                continue;
            };
            let mut terminator = attribute_end;
            while terminator < mask.len() && !matches!(mask[terminator], b'{' | b';') {
                terminator += 1;
            }
            assert!(terminator < mask.len(), "cfg(test) item must terminate");
            let end = if mask[terminator] == b'{' {
                closing_brace_v1(&mask, terminator, "cfg(test) item") + 1
            } else {
                terminator + 1
            };
            blank_v1(&mut output, start, end);
            blank_v1(&mut mask, start, end);
            cursor = end;
        }
        String::from_utf8(output).expect("production extraction remains UTF-8")
    }

    fn session_production_v1() -> &'static str {
        static SOURCE: OnceLock<String> = OnceLock::new();
        SOURCE.get_or_init(|| production_without_tests_v1(SESSION_SOURCE_V1))
    }

    fn root_production_v1() -> &'static str {
        static SOURCE: OnceLock<String> = OnceLock::new();
        SOURCE.get_or_init(|| production_without_tests_v1(LIB_SOURCE_V1))
    }

    fn ancillary_production_v1() -> &'static str {
        static SOURCE: OnceLock<String> = OnceLock::new();
        SOURCE.get_or_init(|| production_without_tests_v1(ANCILLARY_SOURCE_V1))
    }

    fn process_production_v1() -> &'static str {
        static SOURCE: OnceLock<String> = OnceLock::new();
        SOURCE.get_or_init(|| production_without_tests_v1(PROCESS_SOURCE_V1))
    }

    fn executable_custody_production_v1() -> &'static str {
        static SOURCE: OnceLock<String> = OnceLock::new();
        SOURCE.get_or_init(|| production_without_tests_v1(EXECUTABLE_CUSTODY_SOURCE_V1))
    }

    fn seccomp_production_v1() -> &'static str {
        static SOURCE: OnceLock<String> = OnceLock::new();
        SOURCE.get_or_init(|| production_without_tests_v1(SECCOMP_SOURCE_V1))
    }

    fn statx_production_v1() -> &'static str {
        static SOURCE: OnceLock<String> = OnceLock::new();
        SOURCE.get_or_init(|| production_without_tests_v1(STATX_SOURCE_V1))
    }

    fn ancillary_selected_v1() -> &'static str {
        find_braced_declaration_v1(
            ancillary_production_v1(),
            "mod",
            "selected_target",
            "selected-target production module",
        )
    }

    fn normalized_code_v1(source: &str) -> String {
        rust_code_mask_v1(source).split_whitespace().collect()
    }

    fn normalized_function_body_v1(source: &str, gate: &str) -> String {
        let compact = normalized_code_v1(source);
        let opening = compact
            .find('{')
            .unwrap_or_else(|| panic!("{gate}: function has no body"));
        assert!(
            compact.ends_with('}'),
            "{gate}: function body must end at its closing brace"
        );
        compact[opening + 1..compact.len() - 1].to_owned()
    }

    fn normalized_rustfmt_affine_code_v1(source: &str, gate: &str) -> String {
        assert!(
            macro_invocations_v1(source).is_empty() && macro_definition_names_v1(source).is_empty(),
            "{gate}: trailing-comma canonicalization requires macro-free Rust"
        );
        let mask = rust_code_mask_v1(source);
        let bytes = mask.as_bytes();
        let mut output = Vec::with_capacity(bytes.len());
        let mut callable_parens = Vec::new();
        let mut cursor = 0_usize;
        while cursor < bytes.len() {
            let byte = bytes[cursor];
            if byte.is_ascii_whitespace() {
                cursor += 1;
                continue;
            }
            match byte {
                b'(' => {
                    let previous = cursor.checked_sub(1).map(|at| bytes[at]);
                    let callable = previous.is_some_and(|previous| {
                        !previous.is_ascii_whitespace()
                            && (previous.is_ascii_alphanumeric()
                                || previous >= 0x80
                                || matches!(previous, b'_' | b')' | b']'))
                    });
                    callable_parens.push(callable);
                    output.push(byte);
                }
                b')' => {
                    assert!(
                        callable_parens.pop().is_some(),
                        "{gate}: unmatched closing parenthesis"
                    );
                    output.push(byte);
                }
                b',' => {
                    let next = skip_ws_v1(bytes, cursor + 1);
                    let redundant = bytes.get(next) == Some(&b'}')
                        || (bytes.get(next) == Some(&b')')
                            && callable_parens.last() == Some(&true));
                    if !redundant {
                        output.push(byte);
                    }
                }
                _ => output.push(byte),
            }
            cursor += 1;
        }
        assert!(
            callable_parens.is_empty(),
            "{gate}: unclosed opening parenthesis"
        );
        String::from_utf8(output).expect("canonical Rust mask remains UTF-8")
    }

    fn normalized_affine_body_v1(source: &str, gate: &str) -> String {
        let mask = rust_code_mask_v1(source);
        let opening = mask
            .find('{')
            .unwrap_or_else(|| panic!("{gate}: function has no body"));
        let closing = closing_brace_v1(mask.as_bytes(), opening, gate);
        assert_eq!(
            skip_ws_v1(mask.as_bytes(), closing + 1),
            mask.len(),
            "{gate}: function body must end at its closing brace"
        );
        normalized_rustfmt_affine_code_v1(&source[opening + 1..closing], gate)
    }

    fn normalized_match_depth_v1(source: &str, needle: &str, gate: &str) -> usize {
        let mask = rust_code_mask_v1(source);
        let mut compact = Vec::with_capacity(mask.len());
        let mut offsets = Vec::with_capacity(mask.len());
        for (offset, byte) in mask.bytes().enumerate() {
            if !byte.is_ascii_whitespace() {
                compact.push(byte);
                offsets.push(offset);
            }
        }
        let compact = String::from_utf8(compact).expect("masked Rust source remains UTF-8");
        let matches = compact
            .match_indices(needle)
            .map(|(offset, _)| offset)
            .collect::<Vec<_>>();
        assert_eq!(
            matches.len(),
            1,
            "{gate}: expected one normalized `{needle}`, found {}",
            matches.len()
        );
        let source_offset = offsets[matches[0]];
        let mut depth = 0_usize;
        for byte in mask.as_bytes()[..source_offset].iter().copied() {
            if byte == b'{' {
                depth += 1;
            } else if byte == b'}' {
                depth = depth.saturating_sub(1);
            }
        }
        depth
    }

    fn identifiers_v1(source: &str) -> Vec<String> {
        let mask = rust_code_mask_v1(source);
        let bytes = mask.as_bytes();
        let mut result = Vec::new();
        let mut cursor = 0_usize;
        while cursor < bytes.len() {
            if bytes[cursor].is_ascii_alphabetic() || bytes[cursor] == b'_' {
                let start = cursor;
                cursor += 1;
                while bytes
                    .get(cursor)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    cursor += 1;
                }
                result.push(mask[start..cursor].to_owned());
            } else if bytes[cursor] == b';' {
                result.push(";".to_owned());
                cursor += 1;
            } else {
                cursor += 1;
            }
        }
        result
    }

    fn assert_no_hidden_source_shapes_v1(label: &str, source: &str) {
        let identifiers = identifiers_v1(source);
        assert!(
            !identifiers.iter().any(|token| token == "type"),
            "{label}: type aliases are forbidden"
        );
        assert!(
            !identifiers
                .iter()
                .any(|token| token == "macro_rules" || token == "macro"),
            "{label}: declarative macro definitions are forbidden"
        );
        let mut in_use = false;
        for token in &identifiers {
            if token == "use" {
                in_use = true;
            } else if token == ";" {
                in_use = false;
            } else if in_use && token == "as" {
                panic!("{label}: use aliases are forbidden");
            }
        }
        let compact = normalized_code_v1(source);
        assert!(
            !compact.contains("include!("),
            "{label}: include! is forbidden"
        );
        assert!(
            !compact.contains("#[path="),
            "{label}: #[path] is forbidden"
        );
    }

    fn assert_session_root_source_shape_v1(source: &str, gate: &str) {
        let mask = rust_code_mask_v1(source);
        let bytes = mask.as_bytes();
        let mut cursor = 0_usize;
        while cursor < bytes.len() {
            if bytes[cursor] == b'#' {
                let mut next = skip_ws_v1(bytes, cursor + 1);
                if bytes.get(next) == Some(&b'!') {
                    next = skip_ws_v1(bytes, next + 1);
                }
                assert_ne!(
                    bytes.get(next),
                    Some(&b'['),
                    "{gate}: session production forbids every outer/inner attribute"
                );
            }
            let raw_identifier =
                cursor >= 2 && bytes[cursor - 2] == b'r' && bytes[cursor - 1] == b'#';
            if bytes
                .get(cursor..)
                .is_some_and(|tail| tail.starts_with(b"mod"))
                && token_boundary_v1(bytes, cursor, 3)
                && !raw_identifier
            {
                panic!("{gate}: session production forbids nested/module declarations");
            }
            cursor += 1;
        }
        for forbidden in ["const", "static", "union", "trait"] {
            assert_eq!(
                token_count_v1(source, forbidden),
                0,
                "{gate}: session production forbids `{forbidden}` item scopes"
            );
        }
        assert_function_bodies_have_no_nested_items_v1(source, None, gate);
    }

    fn assert_session_root_source_shape_fixtures_v1() {
        assert_session_root_source_shape_v1(
            "fn route(value: u8) { let _ = value; } // #[cfg(any())] mod decoy {}\nfn note() { let _ = \"#[cfg(any())] mod decoy {}\"; }",
            "root-shape positive fixture",
        );
        for invalid in [
            "#[cfg(any())] mod decoy { fn route() {} }",
            "#![cfg(any())]\nfn route() {}",
            "#[cfg(any())] fn route() {}",
            "#[cfg_attr(all(), cfg(any()))] fn route() {}",
            "mod decoy { fn route() {} }",
            "pub(crate) mod decoy;",
            "const _: () = { fn route() {} };",
            "fn route() { fn hidden() {} }",
        ] {
            let rejected = std::panic::catch_unwind(|| {
                assert_session_root_source_shape_v1(invalid, "root-shape negative fixture")
            });
            assert!(
                rejected.is_err(),
                "cfg/attribute/module decoy must be rejected: {invalid}"
            );
        }
    }

    fn token_count_v1(source: &str, token: &str) -> usize {
        identifiers_v1(source)
            .iter()
            .filter(|candidate| *candidate == token)
            .count()
    }

    fn token_call_count_v1(source: &str, token: &str) -> usize {
        let mask = rust_code_mask_v1(source);
        let bytes = mask.as_bytes();
        let mut count = 0_usize;
        let mut cursor = 0_usize;
        while let Some(relative) = mask[cursor..].find(token) {
            let start = cursor + relative;
            cursor = start + token.len();
            if token_boundary_v1(bytes, start, token.len())
                && bytes.get(skip_ws_v1(bytes, cursor)) == Some(&b'(')
            {
                count += 1;
            }
        }
        count
    }

    fn find_function_v1<'a>(source: &'a str, name: &str, gate: &str) -> &'a str {
        let mask = rust_code_mask_v1(source);
        let bytes = mask.as_bytes();
        let mut matches = Vec::new();
        let mut cursor = 0_usize;
        while let Some(relative) = mask[cursor..].find("fn") {
            let start = cursor + relative;
            cursor = start + 2;
            if !token_boundary_v1(bytes, start, 2) {
                continue;
            }
            let name_start = skip_ws_v1(bytes, cursor);
            if !mask[name_start..].starts_with(name)
                || !token_boundary_v1(bytes, name_start, name.len())
            {
                continue;
            }
            let mut opening = name_start + name.len();
            let mut square_depth = 0_usize;
            while opening < bytes.len() {
                match bytes[opening] {
                    b'[' => square_depth += 1,
                    b']' => square_depth = square_depth.saturating_sub(1),
                    b'{' | b';' if square_depth == 0 => break,
                    _ => {}
                }
                opening += 1;
            }
            assert!(
                opening < bytes.len() && bytes[opening] == b'{',
                "{gate}: `{name}` must be a braced function"
            );
            matches.push((start, closing_brace_v1(bytes, opening, gate) + 1));
        }
        assert_eq!(
            matches.len(),
            1,
            "{gate}: expected exactly one braced `fn {name}`, found {}",
            matches.len()
        );
        &source[matches[0].0..matches[0].1]
    }

    fn find_braced_declaration_v1<'a>(
        source: &'a str,
        keyword: &str,
        name: &str,
        gate: &str,
    ) -> &'a str {
        let mask = rust_code_mask_v1(source);
        let bytes = mask.as_bytes();
        let mut matches = Vec::new();
        let mut cursor = 0_usize;
        while let Some(relative) = mask[cursor..].find(keyword) {
            let start = cursor + relative;
            cursor = start + keyword.len();
            if !token_boundary_v1(bytes, start, keyword.len()) {
                continue;
            }
            let name_start = skip_ws_v1(bytes, cursor);
            if !mask[name_start..].starts_with(name)
                || !token_boundary_v1(bytes, name_start, name.len())
            {
                continue;
            }
            let mut opening = name_start + name.len();
            while opening < bytes.len() && !matches!(bytes[opening], b'{' | b';' | b'(') {
                opening += 1;
            }
            assert!(
                opening < bytes.len() && bytes[opening] == b'{',
                "{gate}: `{keyword} {name}` must have named braced fields"
            );
            matches.push((start, closing_brace_v1(bytes, opening, gate) + 1));
        }
        assert_eq!(
            matches.len(),
            1,
            "{gate}: expected exactly one `{keyword} {name}`, found {}",
            matches.len()
        );
        &source[matches[0].0..matches[0].1]
    }

    fn require_code_v1(source: &str, needle: &str, gate: &str) {
        let code = rust_code_mask_v1(source);
        assert!(
            code.contains(needle),
            "{gate}: missing production code `{needle}`"
        );
    }

    fn require_order_v1(source: &str, needles: &[&str], gate: &str) {
        let code = rust_code_mask_v1(source);
        let mut cursor = 0_usize;
        for needle in needles {
            let offset = code[cursor..]
                .find(needle)
                .unwrap_or_else(|| panic!("{gate}: missing ordered production code `{needle}`"));
            cursor += offset + needle.len();
        }
    }

    fn require_once_v1(source: &str, needle: &str, gate: &str) {
        let count = rust_code_mask_v1(source).matches(needle).count();
        assert_eq!(count, 1, "{gate}: expected one `{needle}`, found {count}");
    }

    fn function_signatures_v1(source: &str) -> Vec<String> {
        let mask = rust_code_mask_v1(source);
        let bytes = mask.as_bytes();
        let mut signatures = Vec::new();
        let mut cursor = 0_usize;
        while let Some(relative) = mask[cursor..].find("fn") {
            let fn_start = cursor + relative;
            cursor = fn_start + 2;
            if !token_boundary_v1(bytes, fn_start, 2) {
                continue;
            }
            let line_start = mask[..fn_start]
                .rfind(|character| matches!(character, '\n' | '}' | ';' | '{'))
                .map_or(0, |index| index + 1);
            let mut start = line_start;
            while start < fn_start && bytes[start].is_ascii_whitespace() {
                start += 1;
            }
            let mut end = cursor;
            let mut square_depth = 0_usize;
            while end < bytes.len() {
                match bytes[end] {
                    b'[' => square_depth += 1,
                    b']' => square_depth = square_depth.saturating_sub(1),
                    b'{' | b';' if square_depth == 0 => break,
                    _ => {}
                }
                end += 1;
            }
            assert!(end < bytes.len(), "function signature must terminate");
            signatures.push(mask[start..end].split_whitespace().collect());
        }
        signatures
    }

    fn signature_visibility_v1(signature: &str) -> &'static str {
        let fn_at = signature
            .find("fn")
            .expect("function signature contains fn");
        let prefix = &signature[..fn_at];
        if prefix == "pub(crate)" {
            "pub(crate)"
        } else if prefix.contains("pub") {
            "pub"
        } else {
            "private"
        }
    }

    fn function_name_from_signature_v1(signature: &str) -> &str {
        let after_fn = signature
            .find("fn")
            .map(|index| &signature[index + 2..])
            .expect("function inventory entry must contain fn");
        let end = after_fn
            .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .unwrap_or(after_fn.len());
        &after_fn[..end]
    }

    fn impl_headers_v1(source: &str) -> Vec<String> {
        let mask = rust_code_mask_v1(source);
        let bytes = mask.as_bytes();
        let mut headers = Vec::new();
        let mut cursor = 0_usize;
        while let Some(relative) = mask[cursor..].find("impl") {
            let start = cursor + relative;
            cursor = start + 4;
            if !token_boundary_v1(bytes, start, 4) {
                continue;
            }
            let end = mask[cursor..]
                .find('{')
                .map(|relative_end| cursor + relative_end)
                .expect("impl header must have a body");
            headers.push(mask[start..end].split_whitespace().collect());
        }
        headers
    }

    fn use_alias_inventory_v1(source: &str) -> Vec<String> {
        let identifiers = identifiers_v1(source);
        let mut aliases = Vec::new();
        let mut in_use = false;
        for (index, token) in identifiers.iter().enumerate() {
            if token == "use" {
                in_use = true;
            } else if token == ";" {
                in_use = false;
            } else if in_use && token == "as" {
                let source = identifiers
                    .get(index.wrapping_sub(1))
                    .expect("use alias must name its source");
                let target = identifiers
                    .get(index + 1)
                    .expect("use alias must name its target");
                aliases.push(format!("{source} as {target}"));
            }
        }
        aliases.sort();
        aliases
    }

    fn expected_selected_impl_inventory_v1() -> Vec<String> {
        let mut expected = [
            "implChildTypedReceiveErrorV1",
            "implChildTypedSendErrorV1",
            "impl<'a>GeneratorBoundSendInputV1<'a>",
            "implGeneratorBoundAwaitClosedResultEndpointV1",
            "implGeneratorChannelV1",
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

    fn expected_whole_impl_inventory_v1() -> Vec<String> {
        let mut expected = expected_selected_impl_inventory_v1();
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

    fn assert_exact_impl_inventory_v1(source: &str, expected: &[String], gate: &str) {
        let mut observed = impl_headers_v1(source);
        observed.sort();
        assert_eq!(observed, expected, "{gate}: exact impl inventory drifted");
    }

    fn assert_whole_successor_function_closure_v1(source: &str, gate: &str) {
        let signatures = function_signatures_v1(source);
        for signature in &signatures {
            let name = function_name_from_signature_v1(signature);
            assert!(
                !["into_parts", "replay", "resend", "retry"].contains(&name),
                "{gate}: whole ancillary gained named replay/extraction function `{name}`"
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
            "pub(crate)fnenqueue_once_v1(self,credentials:UCred)->Result<SupervisorGeneratorSentEndpointV1,AncillarySendErrorV1>",
            "pub(crate)fnenqueue_once_v1(self,credentials:UCred)->Result<WorkerBootstrapEnqueuedEndpointV1,AncillarySendErrorV1>",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(
            observed, expected,
            "{gate}: whole ancillary successor function-signature inventory drifted"
        );
    }

    fn assert_whole_ancillary_successor_impl_closure_v1(
        full_source: &str,
        selected_source: &str,
        gate: &str,
    ) {
        assert_eq!(
            use_alias_inventory_v1(full_source),
            [
                "FdRoleV1 as ContractFdRoleV1".to_owned(),
                "MAX_FRAME_BYTES_V1 as CONTRACT_MAX_FRAME_BYTES_V1".to_owned(),
                "MAX_FRAME_FDS_V1 as CONTRACT_MAX_FRAME_FDS_V1".to_owned(),
            ],
            "{gate}: whole ancillary use-alias inventory drifted"
        );
        assert_eq!(
            token_count_v1(full_source, "trait"),
            0,
            "{gate}: whole ancillary production forbids local trait surfaces"
        );
        assert_exact_impl_inventory_v1(
            selected_source,
            &expected_selected_impl_inventory_v1(),
            &format!("{gate}: selected-target"),
        );
        assert_exact_impl_inventory_v1(
            full_source,
            &expected_whole_impl_inventory_v1(),
            &format!("{gate}: whole ancillary"),
        );
        assert_whole_successor_function_closure_v1(full_source, gate);
    }

    fn assert_whole_ancillary_successor_impl_closure_fixtures_v1() {
        let selected = "impl AlphaV1 {} impl BetaV1 {}";
        let expected = ["implAlphaV1".to_owned(), "implBetaV1".to_owned()];
        let imports = "use contract::{FdRoleV1 as ContractFdRoleV1, MAX_FRAME_BYTES_V1 as CONTRACT_MAX_FRAME_BYTES_V1, MAX_FRAME_FDS_V1 as CONTRACT_MAX_FRAME_FDS_V1};";
        let valid = format!(
            "{imports} mod strict_model {{ pub(super) mod selected_target {{ {selected} }} }}"
        );
        assert_exact_impl_inventory_v1(selected, &expected, "whole impl positive fixture");
        for mutant in [
            format!("impl GammaV1 {{ pub(crate) fn retry(self) -> Self {{ self }} }} {valid}"),
            format!(
                "pub(crate) trait RetryV1: Sized {{ fn retry(self) -> Self {{ self }} }} impl<T> RetryV1 for T {{}} {valid}"
            ),
        ] {
            let rejected = std::panic::catch_unwind(|| {
                assert_exact_impl_inventory_v1(
                    &mutant,
                    &expected,
                    "whole ancillary impl negative fixture",
                )
            });
            assert!(
                rejected.is_err(),
                "a direct or blanket impl before strict_model must not escape the whole-file inventory"
            );
        }
        let function_mutant = format!(
            "pub(crate) fn retry(value: SupervisorGeneratorSentEndpointV1) -> SupervisorGeneratorSentEndpointV1 {{ value }} {valid}"
        );
        let rejected = std::panic::catch_unwind(|| {
            assert_whole_successor_function_closure_v1(
                &function_mutant,
                "whole ancillary function negative fixture",
            )
        });
        assert!(
            rejected.is_err(),
            "a named successor retry function before strict_model must be rejected"
        );
        assert_eq!(
            use_alias_inventory_v1(&valid),
            [
                "FdRoleV1 as ContractFdRoleV1".to_owned(),
                "MAX_FRAME_BYTES_V1 as CONTRACT_MAX_FRAME_BYTES_V1".to_owned(),
                "MAX_FRAME_FDS_V1 as CONTRACT_MAX_FRAME_FDS_V1".to_owned(),
            ]
        );
        let aliased = format!("use strict_model::selected_target::AlphaV1 as Hidden; {valid}");
        assert_ne!(
            use_alias_inventory_v1(&aliased),
            use_alias_inventory_v1(&valid),
            "a successor alias must change the exact whole-file inventory"
        );
        let function_valid = "pub(crate) fn enqueue_once_v1(self, credentials: UCred) -> Result<SupervisorGeneratorSentEndpointV1, AncillarySendErrorV1> { unreachable!() } pub(crate) fn enqueue_once_v1(self, credentials: UCred) -> Result<WorkerBootstrapEnqueuedEndpointV1, AncillarySendErrorV1> { unreachable!() }";
        assert_whole_successor_function_closure_v1(
            function_valid,
            "whole ancillary function positive fixture",
        );
    }

    fn inherent_impl_blocks_v1<'a>(source: &'a str, type_name: &str) -> Vec<&'a str> {
        let mask = rust_code_mask_v1(source);
        let bytes = mask.as_bytes();
        let mut blocks = Vec::new();
        let mut cursor = 0_usize;
        while let Some(relative) = mask[cursor..].find("impl") {
            let start = cursor + relative;
            cursor = start + 4;
            if !token_boundary_v1(bytes, start, 4) {
                continue;
            }
            let opening = mask[cursor..]
                .find('{')
                .map(|offset| cursor + offset)
                .expect("impl must have a body");
            let header = mask[start..opening].split_whitespace().collect::<String>();
            let closing = closing_brace_v1(bytes, opening, "inherent impl inventory");
            if header == format!("impl{type_name}") {
                blocks.push(&source[start..closing + 1]);
            }
            cursor = closing + 1;
        }
        blocks
    }

    fn assert_inherent_method_allowlist_v1(
        source: &str,
        type_name: &str,
        expected: &[(&str, &str)],
        gate: &str,
    ) {
        let blocks = inherent_impl_blocks_v1(source, type_name);
        if expected.is_empty() {
            assert!(
                blocks.is_empty(),
                "{gate}: methodless `{type_name}` gained an inherent impl"
            );
            return;
        }
        assert_eq!(
            blocks.len(),
            1,
            "{gate}: `{type_name}` must have exactly one inherent impl"
        );
        let observed = function_signatures_v1(blocks[0])
            .into_iter()
            .map(|signature| {
                let visibility = signature_visibility_v1(&signature);
                let exact_prefix = if visibility == "pub(crate)" { "pub(crate)fn" } else { "fn" };
                assert!(signature.starts_with(exact_prefix), "{gate}: `{type_name}` method has an unapproved qualifier/attribute: `{signature}`");
                (visibility, function_name_from_signature_v1(&signature).to_owned())
            })
            .collect::<Vec<_>>();
        let expected = expected
            .iter()
            .map(|(visibility, name)| (*visibility, (*name).to_owned()))
            .collect::<Vec<_>>();
        assert_eq!(
            observed, expected,
            "{gate}: `{type_name}` method allowlist drifted"
        );
    }

    fn allowed_session_function_names_v1() -> [&'static str; 15] {
        [
            "begin_after_parent_endpoint_relinquishment_v1",
            "send_offer_before_nonce_exchange_v1",
            "receive_then_advance_generator_bound_v1",
            "advance_generator_bound_after_kernel_success_v1",
            "enqueue_then_release_worker_v1",
            "advance_worker_bootstrap_after_kernel_success_v1",
            "receive_then_advance_worker_exec_bound_v1",
            "advance_worker_exec_bound_after_kernel_success_v1",
            "enqueue_then_advance_closed_result_v1",
            "advance_closed_result_after_kernel_success_v1",
            "require_equal_projection_v1",
            "require_capacity_v1",
            "advance_after_kernel_success_v1",
            "terminal",
            "from",
        ]
    }

    fn session_function_names_v1(source: &str, gate: &str) -> Vec<String> {
        let expected = allowed_session_function_names_v1();
        function_signatures_v1(source)
            .into_iter()
            .map(|signature| {
                assert_eq!(signature_visibility_v1(&signature), "private", "{gate}: every session function must be private: `{signature}`");
                assert!(signature.starts_with("fn"), "{gate}: session signatures forbid qualifiers/attributes before fn: `{signature}`");
                let name = function_name_from_signature_v1(&signature).to_owned();
                assert!(expected.contains(&name.as_str()), "{gate}: unapproved session function `{name}`");
                name
            })
            .collect()
    }

    fn assert_session_function_allowlist_v1(source: &str, gate: &str) {
        let expected = [
            "begin_after_parent_endpoint_relinquishment_v1",
            "send_offer_before_nonce_exchange_v1",
            "receive_then_advance_generator_bound_v1",
            "advance_generator_bound_after_kernel_success_v1",
            "enqueue_then_release_worker_v1",
            "advance_worker_bootstrap_after_kernel_success_v1",
            "receive_then_advance_worker_exec_bound_v1",
            "advance_worker_exec_bound_after_kernel_success_v1",
            "enqueue_then_advance_closed_result_v1",
            "advance_closed_result_after_kernel_success_v1",
            "require_equal_projection_v1",
            "require_capacity_v1",
            "advance_after_kernel_success_v1",
            "terminal",
            "from",
        ];
        let observed = session_function_names_v1(source, gate);
        for required in &expected[..10] {
            assert_eq!(
                observed
                    .iter()
                    .filter(|name| name.as_str() == *required)
                    .count(),
                1,
                "{gate}: required transition `{required}` inventory drifted"
            );
        }
        assert!(
            observed
                .iter()
                .filter(|name| name.as_str() == expected[10])
                .count()
                <= 1,
            "{gate}: equality helper may occur at most once"
        );
        assert_eq!(
            observed
                .iter()
                .filter(|name| name.as_str() == expected[11])
                .count(),
            1,
            "{gate}: aggregate capacity guard inventory drifted"
        );
        assert_eq!(
            observed
                .iter()
                .filter(|name| name.as_str() == expected[12])
                .count(),
            1,
            "{gate}: aggregate kernel-success advance inventory drifted"
        );
        assert_eq!(
            observed
                .iter()
                .filter(|name| name.as_str() == expected[13])
                .count(),
            1,
            "{gate}: terminal session error constructor inventory drifted"
        );
        assert_eq!(
            observed
                .iter()
                .filter(|name| name.as_str() == expected[14])
                .count(),
            2,
            "{gate}: exact session error conversion inventory drifted"
        );
    }

    fn assert_session_error_closure_v1(source: &str, gate: &str) {
        let declaration = normalized_code_v1(find_braced_declaration_v1(
            source,
            "struct",
            "SessionTransitionErrorV1",
            gate,
        ));
        assert_eq!(
            declaration, "structSessionTransitionErrorV1{_private:(),}",
            "{gate}: session error must remain terminal and payload-free"
        );
        let mut headers = impl_headers_v1(source)
            .into_iter()
            .filter(|header| header.contains("SessionTransitionErrorV1"))
            .collect::<Vec<_>>();
        headers.sort();
        let mut expected = vec![
            "implFrom<ExecutableCustodyErrorV2>forSessionTransitionErrorV1".to_owned(),
            "implFrom<SupervisorTypedTransitionErrorV1>forSessionTransitionErrorV1".to_owned(),
            "implSessionTransitionErrorV1".to_owned(),
        ];
        expected.sort();
        assert_eq!(
            headers, expected,
            "{gate}: session error conversion surface drifted"
        );
        let inherent = inherent_impl_blocks_v1(source, "SessionTransitionErrorV1");
        assert_eq!(
            inherent.len(),
            1,
            "{gate}: session error must have one inherent impl"
        );
        assert_inherent_method_allowlist_v1(
            source,
            "SessionTransitionErrorV1",
            &[("private", "terminal")],
            gate,
        );
        let terminal = normalized_code_v1(find_function_v1(inherent[0], "terminal", gate));
        assert_eq!(
            terminal, "fnterminal()->Self{Self{_private:()}}",
            "{gate}: terminal error constructor drifted"
        );
        let compact = normalized_code_v1(source);
        for input in [
            "ExecutableCustodyErrorV2",
            "SupervisorTypedTransitionErrorV1",
        ] {
            let needle = format!(
                "implFrom<{input}>forSessionTransitionErrorV1{{fnfrom(_:{input})->Self{{Self::terminal()}}}}"
            );
            assert_eq!(
                compact.matches(&needle).count(),
                1,
                "{gate}: `{input}` must convert only to the payload-free terminal error"
            );
        }
    }

    fn assert_propagates_without_swallow_v1(source: &str, call: &str, gate: &str) {
        let compact = normalized_code_v1(source);
        let call_at = compact
            .find(call)
            .unwrap_or_else(|| panic!("{gate}: missing `{call}`"));
        assert_eq!(
            compact.matches(call).count(),
            1,
            "{gate}: target call must occur exactly once"
        );
        let opening = call_at + call.len() - 1;
        let bytes = compact.as_bytes();
        let closing = closing_delimiter_v1(bytes, opening, b'(', b')', gate);
        assert_eq!(
            bytes.get(closing + 1),
            Some(&b'?'),
            "{gate}: `?` must immediately consume the exact target call result"
        );
        for forbidden in ["let_=", ".ok()", "unwrap_or", "unwrap_or_else", "or_else"] {
            assert!(
                !compact.contains(forbidden),
                "{gate}: swallowed/rewritten failure via `{forbidden}`"
            );
        }
    }

    #[derive(Clone, Copy)]
    enum ProjectionTransitionOrderV1 {
        Inbound,
        Outbound,
    }

    fn simple_binding_v1(candidate: &str) -> bool {
        let candidate = candidate.strip_prefix("r#").unwrap_or(candidate);
        let mut bytes = candidate.bytes();
        bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    }

    fn projection_binding_v1(compact: &str, call: &str, call_at: usize) -> Option<(String, usize)> {
        let bytes = compact.as_bytes();
        let opening = call_at + call.len().checked_sub(1)?;
        if bytes.get(opening) != Some(&b'(') {
            return None;
        }
        let closing =
            closing_delimiter_v1(bytes, opening, b'(', b')', "projection binding fixture");
        if bytes.get(closing + 1) != Some(&b'?') || bytes.get(closing + 2) != Some(&b';') {
            return None;
        }
        let statement_start = compact[..call_at]
            .rfind(|character| matches!(character, ';' | '{' | '}'))
            .map_or(0, |index| index + 1);
        let statement_prefix = &compact[statement_start..call_at];
        if !statement_prefix.starts_with("let") {
            return None;
        }
        let equals = statement_prefix.find('=')?;
        let binding = &statement_prefix[3..equals];
        if !simple_binding_v1(binding)
            || statement_prefix[equals + 1..].is_empty()
            || statement_prefix[equals + 1..].contains('?')
        {
            return None;
        }
        Some((binding.to_owned(), call_at))
    }

    fn tuple_projection_binding_v1(
        compact: &str,
        call: &str,
        call_at: usize,
    ) -> Option<(String, String, usize)> {
        let bytes = compact.as_bytes();
        let opening = call_at + call.len().checked_sub(1)?;
        if bytes.get(opening) != Some(&b'(') {
            return None;
        }
        let closing = closing_delimiter_v1(
            bytes,
            opening,
            b'(',
            b')',
            "tuple projection binding fixture",
        );
        if bytes.get(closing + 1) != Some(&b'?') || bytes.get(closing + 2) != Some(&b';') {
            return None;
        }
        let statement_start = compact[..call_at]
            .rfind(|character| matches!(character, ';' | '{' | '}'))
            .map_or(0, |index| index + 1);
        let statement_prefix = &compact[statement_start..call_at];
        if !statement_prefix.starts_with("let(") {
            return None;
        }
        let equals = statement_prefix.find(")=")?;
        let bindings = statement_prefix[4..equals].split(',').collect::<Vec<_>>();
        let rhs_prefix = &statement_prefix[equals + 2..];
        let direct_call = rhs_prefix.is_empty()
            || rhs_prefix
                .strip_suffix('.')
                .is_some_and(simple_state_path_v1);
        if bindings.len() != 2
            || !bindings.iter().all(|binding| simple_binding_v1(binding))
            || !direct_call
        {
            return None;
        }
        Some((bindings[0].to_owned(), bindings[1].to_owned(), call_at))
    }

    fn exact_call_arguments_v1<'a>(compact: &'a str, call: &str, gate: &str) -> &'a str {
        assert_eq!(
            compact.matches(call).count(),
            1,
            "{gate}: `{call}` must occur exactly once"
        );
        let call_at = compact
            .find(call)
            .unwrap_or_else(|| panic!("{gate}: missing `{call}`"));
        let opening = call_at + call.len() - 1;
        let closing = closing_delimiter_v1(compact.as_bytes(), opening, b'(', b')', gate);
        let arguments = &compact[opening + 1..closing];
        arguments.strip_suffix(',').unwrap_or(arguments)
    }

    fn assert_candidate_flow_v1(
        source: &str,
        producer_call: &str,
        producer_arguments: &str,
        transport_binding: &str,
        kernel_call: Option<(&str, &str)>,
        transport_sink: Option<&str>,
        advance_call: &str,
        advance_assignment: &str,
        gate: &str,
    ) {
        let compact = normalized_code_v1(source);
        let producer_at = compact
            .find(producer_call)
            .unwrap_or_else(|| panic!("{gate}: missing candidate producer `{producer_call}`"));
        assert_eq!(
            exact_call_arguments_v1(&compact, producer_call, gate),
            producer_arguments,
            "{gate}: candidate producer arguments drifted"
        );
        let (observed_transport, observed_candidate, _) =
            tuple_projection_binding_v1(&compact, producer_call, producer_at)
                .unwrap_or_else(|| panic!("{gate}: candidate producer must bind one exact pair"));
        assert_eq!(
            observed_transport, transport_binding,
            "{gate}: candidate transport binding drifted"
        );
        assert_eq!(
            observed_candidate, "candidate",
            "{gate}: candidate binding must be the sole local `candidate`"
        );
        assert_eq!(
            exact_call_arguments_v1(&compact, advance_call, gate),
            "candidate",
            "{gate}: the exact producer candidate must move into the advance"
        );
        assert_eq!(
            compact.matches(advance_assignment).count(),
            1,
            "{gate}: the candidate advance result must replace the exact transcript owner"
        );
        assert_propagates_without_swallow_v1(source, producer_call, gate);
        assert_propagates_without_swallow_v1(source, advance_call, gate);
        let advance_at = compact
            .find(advance_call)
            .expect("validated candidate advance exists");
        if let Some((kernel, expected_argument)) = kernel_call {
            assert_eq!(
                exact_call_arguments_v1(&compact, kernel, gate),
                expected_argument,
                "{gate}: candidate-bound operation must be the exact D6b input"
            );
            let kernel_at = compact.find(kernel).expect("validated kernel call exists");
            assert!(
                producer_at < kernel_at && kernel_at < advance_at,
                "{gate}: candidate preparation, kernel success, and advance order drifted"
            );
        } else {
            assert!(
                producer_at < advance_at,
                "{gate}: receive candidate must precede its advance"
            );
        }
        if let Some(sink) = transport_sink {
            require_once_v1(source, sink, "exact candidate transport custody sink");
            assert!(
                advance_at
                    < compact
                        .find(&normalized_code_v1(sink))
                        .expect("transport sink exists"),
                "{gate}: accepted transport custody must be retained only after candidate advance"
            );
            assert_eq!(
                token_count_v1(source, transport_binding),
                2,
                "{gate}: transport may occur only in its producer binding and exact custody sink"
            );
        } else if kernel_call.is_none() {
            assert_eq!(
                token_count_v1(source, transport_binding),
                1,
                "{gate}: terminal inbound transport may not escape its producer binding"
            );
        }
        let signature_end = compact.find('{').expect("transition function body exists");
        let signature = &compact[..signature_end];
        for forbidden in [
            "G0GeneratorBoundTranscriptCandidateV1",
            "G0TranscriptCandidateV1",
            "digest",
            "Digest",
            "previous_hash",
            "worker_genesis",
            "Genesis",
            "[u8;32]",
        ] {
            assert!(
                !signature.contains(forbidden),
                "{gate}: transition accepts caller-supplied `{forbidden}`"
            );
        }
        assert_eq!(
            token_count_v1(source, "candidate"),
            2,
            "{gate}: candidate may occur only in the producer binding and consuming advance"
        );
        for forbidden in [
            "candidate.clone(",
            "candidate.to_owned(",
            "candidate.digest(",
        ] {
            assert!(
                !compact.contains(forbidden),
                "{gate}: candidate authority was detached via `{forbidden}`"
            );
        }
    }

    fn assert_candidate_flow_fixtures_v1() {
        let valid = "fn route(mut state: StateV1, input: InputV1) -> Result<StateV1, SessionTransitionErrorV1> { let (received_endpoint, candidate) = state.receiver.receive_generator_bound_once_v1(input)?; let generator = state.generator.advance_generator_bound_after_kernel_success_v1(candidate)?; state.accepted_generator = AcceptedGeneratorFrameV1 { endpoint: received_endpoint }; Ok(state) }";
        let advance_assignment = "letgenerator=state.generator.advance_generator_bound_after_kernel_success_v1(candidate)?;";
        assert_candidate_flow_v1(
            valid,
            "receive_generator_bound_once_v1(",
            "input",
            "received_endpoint",
            None,
            Some(
                "state.accepted_generator = AcceptedGeneratorFrameV1 { endpoint: received_endpoint };",
            ),
            ".advance_generator_bound_after_kernel_success_v1(",
            advance_assignment,
            "candidate-flow positive fixture",
        );
        let chained_receiver = normalized_code_v1(
            "let (received_endpoint, candidate) = state.receiver.clone().receive_generator_bound_once_v1(input)?;",
        );
        let chained_call = "receive_generator_bound_once_v1(";
        let chained_call_at = chained_receiver
            .find(chained_call)
            .expect("chained receiver fixture contains the target call");
        assert!(
            tuple_projection_binding_v1(&chained_receiver, chained_call, chained_call_at).is_none(),
            "a computed/chained receiver must not satisfy the direct tuple projection binding"
        );
        let ignored = valid.replace(
            "let generator = state.generator.advance_generator_bound_after_kernel_success_v1(candidate)?;",
            "let _ = state.generator.advance_generator_bound_after_kernel_success_v1(candidate)?;",
        );
        let rejection = std::panic::catch_unwind(|| {
            assert_candidate_flow_v1(
                &ignored,
                "receive_generator_bound_once_v1(",
                "input",
                "received_endpoint",
                None,
                Some(
                    "state.accepted_generator = AcceptedGeneratorFrameV1 { endpoint: received_endpoint };",
                ),
                ".advance_generator_bound_after_kernel_success_v1(",
                advance_assignment,
                "ignored candidate-flow fixture",
            );
        });
        assert!(
            rejection.is_err(),
            "discarding the consuming transcript advance must be rejected"
        );
    }

    fn assert_aggregate_transition_v1(
        source: &str,
        preparation_call: &str,
        kernel_call: &str,
        cursor_advance_call: &str,
        count_must_precede: Option<&str>,
        gate: &str,
    ) {
        let compact = normalized_code_v1(source);
        let capacity = "state.aggregate_count.require_capacity_v1(";
        let count_advance = "state.aggregate_count.advance_after_kernel_success_v1(";
        for call in [
            capacity,
            preparation_call,
            kernel_call,
            cursor_advance_call,
            count_advance,
        ] {
            assert_eq!(
                compact.matches(call).count(),
                1,
                "{gate}: `{call}` must occur exactly once"
            );
        }
        assert_eq!(
            exact_call_arguments_v1(&compact, capacity, gate),
            "",
            "{gate}: aggregate capacity guard accepts no caller input"
        );
        assert_eq!(
            exact_call_arguments_v1(&compact, count_advance, gate),
            "",
            "{gate}: aggregate advance accepts no caller input"
        );
        assert_propagates_without_swallow_v1(source, capacity, gate);
        assert_propagates_without_swallow_v1(source, count_advance, gate);
        let capacity_at = compact.find(capacity).expect("capacity call exists");
        let preparation_at = compact
            .find(preparation_call)
            .expect("preparation call exists");
        let kernel_at = compact.find(kernel_call).expect("kernel call exists");
        let cursor_at = compact
            .find(cursor_advance_call)
            .expect("cursor advance exists");
        let count_at = compact
            .find(count_advance)
            .expect("aggregate advance exists");
        let success_at = compact.rfind("Ok(").unwrap_or(compact.len());
        assert!(
            capacity_at < preparation_at
                && preparation_at <= kernel_at
                && kernel_at < cursor_at
                && cursor_at < count_at
                && count_at < success_at,
            "{gate}: capacity, preparation, kernel success, cursor, and aggregate order drifted"
        );
        if let Some(boundary) = count_must_precede {
            let boundary_at = compact
                .find(boundary)
                .unwrap_or_else(|| panic!("{gate}: missing post-advance boundary `{boundary}`"));
            assert!(
                count_at < boundary_at,
                "{gate}: aggregate advance must precede `{boundary}`"
            );
        }
        require_once_v1(
            source,
            "state.aggregate_count = state.aggregate_count.advance_after_kernel_success_v1()?;",
            "exact aggregate advance assignment",
        );
        let signature_end = compact.find('{').expect("transition body exists");
        assert!(
            !compact[..signature_end].contains("AggregateCountV1")
                && !compact[..signature_end].contains("aggregate_count"),
            "{gate}: transition accepts caller-supplied aggregate state"
        );
    }

    fn has_early_success_token_v1(source: &str) -> bool {
        identifiers_v1(source)
            .iter()
            .any(|identifier| matches!(identifier.as_str(), "Ok" | "return"))
    }

    enum LinearStatementV1<'a> {
        Exact(&'a str),
        StateCall {
            prefix: &'a str,
            receiver: &'a str,
            method: &'a str,
            arguments: &'a str,
        },
    }

    fn simple_identifier_v1(source: &str) -> bool {
        let bytes = source.as_bytes();
        bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
            && bytes
                .iter()
                .skip(1)
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    }

    fn simple_state_path_v1(source: &str) -> bool {
        let mut segments = source.split('.');
        segments.next() == Some("state")
            && segments
                .next()
                .is_some_and(|segment| simple_identifier_v1(segment))
            && segments.all(simple_identifier_v1)
    }

    fn top_level_function_parts_v1(source: &str, gate: &str) -> (Vec<String>, String) {
        let mask = rust_code_mask_v1(source);
        let bytes = mask.as_bytes();
        let opening = mask
            .find('{')
            .unwrap_or_else(|| panic!("{gate}: transition has no function body"));
        let closing = closing_brace_v1(bytes, opening, gate);
        assert!(
            mask[closing + 1..].trim().is_empty(),
            "{gate}: transition slice extends beyond its function body"
        );

        let mut statements = Vec::new();
        let mut statement_start = opening + 1;
        let mut paren_depth = 0_usize;
        let mut bracket_depth = 0_usize;
        let mut brace_depth = 0_usize;
        for cursor in opening + 1..closing {
            match bytes[cursor] {
                b'(' => paren_depth += 1,
                b')' => {
                    assert!(paren_depth > 0, "{gate}: unbalanced transition parentheses");
                    paren_depth -= 1;
                }
                b'[' => bracket_depth += 1,
                b']' => {
                    assert!(bracket_depth > 0, "{gate}: unbalanced transition brackets");
                    bracket_depth -= 1;
                }
                b'{' => brace_depth += 1,
                b'}' => {
                    assert!(
                        brace_depth > 0,
                        "{gate}: unbalanced inner transition braces"
                    );
                    brace_depth -= 1;
                }
                b';' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                    let statement =
                        normalized_rustfmt_affine_code_v1(&source[statement_start..cursor], gate);
                    assert!(!statement.is_empty(), "{gate}: empty top-level statement");
                    statements.push(statement);
                    statement_start = cursor + 1;
                }
                _ => {}
            }
        }
        assert_eq!(paren_depth, 0, "{gate}: unclosed transition parentheses");
        assert_eq!(bracket_depth, 0, "{gate}: unclosed transition brackets");
        assert_eq!(brace_depth, 0, "{gate}: unclosed inner transition braces");
        let tail = normalized_rustfmt_affine_code_v1(&source[statement_start..closing], gate);
        assert!(
            !tail.is_empty(),
            "{gate}: transition has no terminal expression"
        );
        (statements, tail)
    }

    fn assert_exact_function_signature_v1(source: &str, expected: &str, gate: &str) {
        let signature_end = rust_code_mask_v1(source)
            .find('{')
            .unwrap_or_else(|| panic!("{gate}: function has no body"));
        assert_eq!(
            normalized_code_v1(&source[..signature_end]).replace(",)->", ")->"),
            normalized_code_v1(expected).replace(",)->", ")->"),
            "{gate}: exact function signature drifted"
        );
    }

    fn assert_linear_transition_body_v1(
        source: &str,
        expected_signature: &str,
        expected: &[LinearStatementV1<'_>],
        expected_tail: &str,
        gate: &str,
    ) {
        for forbidden in [
            "if", "else", "match", "loop", "while", "for", "break", "continue", "return", "async",
            "await", "yield", "unsafe",
        ] {
            assert_eq!(
                token_count_v1(source, forbidden),
                0,
                "{gate}: transition contains forbidden control token `{forbidden}`"
            );
        }
        assert_exact_function_signature_v1(source, expected_signature, gate);

        let (observed, tail) = top_level_function_parts_v1(source, gate);
        assert_eq!(
            observed.len(),
            expected.len(),
            "{gate}: top-level statement inventory drifted"
        );
        for (index, (observed, expected)) in observed.iter().zip(expected).enumerate() {
            match expected {
                LinearStatementV1::Exact(expected) => assert_eq!(
                    observed,
                    &normalized_rustfmt_affine_code_v1(expected, gate),
                    "{gate}: exact statement {index} drifted"
                ),
                LinearStatementV1::StateCall {
                    prefix,
                    receiver,
                    method,
                    arguments,
                } => {
                    let prefix = normalized_code_v1(prefix);
                    let expected_receiver = normalized_code_v1(receiver);
                    let method = normalized_code_v1(method);
                    let arguments = normalized_code_v1(arguments);
                    let suffix = format!(".{method}({arguments})?");
                    assert!(
                        observed.starts_with(&prefix) && observed.ends_with(&suffix),
                        "{gate}: state-call statement {index} shape drifted: `{observed}`"
                    );
                    let receiver = &observed[prefix.len()..observed.len() - suffix.len()];
                    assert!(
                        simple_state_path_v1(receiver),
                        "{gate}: state-call statement {index} has non-field receiver `{receiver}`"
                    );
                    assert_eq!(
                        receiver, expected_receiver,
                        "{gate}: state-call statement {index} owner drifted"
                    );
                }
            }
        }
        assert_eq!(
            tail,
            normalized_rustfmt_affine_code_v1(expected_tail, gate),
            "{gate}: terminal expression drifted"
        );
    }

    fn assert_rustfmt_affine_code_fixtures_v1() {
        let compact = "fn route(input: InputV1) -> Result<StateV1, ErrorV1> { let StateV1 { field, nested: NestedV1 { value } } = state; let built = build(input)?; Ok(StateV1 { field: built, nested: NestedV1 { value } }) }";
        let formatted = "fn route(\n input: InputV1,\n) -> Result<StateV1, ErrorV1> { let StateV1 {\n field,\n nested: NestedV1 { value, },\n } = state; let built = build(\n input,\n)?; Ok(StateV1 {\n field: built,\n nested: NestedV1 { value, },\n }) }";
        assert_eq!(
            normalized_rustfmt_affine_code_v1(compact, "compact affine fixture"),
            normalized_rustfmt_affine_code_v1(formatted, "rustfmt affine fixture")
        );
        for (left, right, label) in [
            (
                "fn route(){consume((value,));}",
                "fn route(){consume((value));}",
                "nested one-tuple",
            ),
            (
                "fn route(){let (value,)=input;}",
                "fn route(){let (value)=input;}",
                "one-tuple pattern",
            ),
            (
                "fn route(){build(first,second,);}",
                "fn route(){build(first,);}",
                "argument removal",
            ),
            (
                "fn route(){build(first,second,);}",
                "fn route(){build(second,first,);}",
                "argument reorder",
            ),
            (
                "fn route(){StateV1{first,second,};}",
                "fn route(){StateV1{first,};}",
                "field removal",
            ),
            (
                "fn route(){StateV1{first,second,};}",
                "fn route(){StateV1{second,first,};}",
                "field reorder",
            ),
        ] {
            assert_ne!(
                normalized_rustfmt_affine_code_v1(left, label),
                normalized_rustfmt_affine_code_v1(right, label),
                "{label} must remain deciding"
            );
        }
        let macro_rejected = std::panic::catch_unwind(|| {
            normalized_rustfmt_affine_code_v1(
                "fn route(){token!{value,}}",
                "macro-bearing affine fixture",
            )
        });
        assert!(
            macro_rejected.is_err(),
            "macro token commas require no canonicalization"
        );
    }

    fn assert_linear_transition_fixtures_v1() {
        assert_rustfmt_affine_code_fixtures_v1();
        let valid = "fn route(mut state: StateV1, input: InputV1) -> Result<StateV1, ErrorV1> { state.aggregate_count.require_capacity_v1()?; let (before, endpoint) = state.owner.kernel_v1(input)?; state.owner.advance_v1(); let after = state.owner.projection_v1()?; require_equal_projection_v1(&before, &after)?; Ok(state) }";
        let expected = [
            LinearStatementV1::Exact("state.aggregate_count.require_capacity_v1()?"),
            LinearStatementV1::StateCall {
                prefix: "let (before, endpoint) = ",
                receiver: "state.owner",
                method: "kernel_v1",
                arguments: "input",
            },
            LinearStatementV1::Exact("state.owner.advance_v1()"),
            LinearStatementV1::StateCall {
                prefix: "let after = ",
                receiver: "state.owner",
                method: "projection_v1",
                arguments: "",
            },
            LinearStatementV1::Exact("require_equal_projection_v1(&before, &after)?"),
        ];
        let signature = "fn route(mut state: StateV1, input: InputV1) -> Result<StateV1, ErrorV1>";
        assert_linear_transition_body_v1(
            valid,
            signature,
            &expected,
            "Ok(state)",
            "linear positive fixture",
        );
        for invalid in [
            valid.replace("kernel_v1(input)?;", "kernel_v1(input)?; loop {}"),
            valid.replace("kernel_v1(input)?;", "kernel_v1(input)?; diverge();"),
            valid.replace(
                "kernel_v1(input)?;",
                "kernel_v1(input)?; None::<()>.unwrap();",
            ),
            valid.replace("kernel_v1(input)?;", "kernel_v1(input)?; let _ = 1 / 0;"),
            valid.replace(
                "state.owner.kernel_v1(input)?",
                "(1 / 0, state.owner).1.kernel_v1(input)?",
            ),
            valid.replacen(
                "state.owner.kernel_v1(input)?",
                "state.alternate.kernel_v1(input)?",
                1,
            ),
            valid.replacen(
                "state.owner.projection_v1()?",
                "state.alternate.projection_v1()?",
                1,
            ),
            valid.replace(
                "fn route(mut state: StateV1, input: InputV1)",
                "fn route<T>(mut state: StateV1, input: InputV1, _drop_bomb: T)",
            ),
        ] {
            let rejected = std::panic::catch_unwind(|| {
                assert_linear_transition_body_v1(
                    &invalid,
                    signature,
                    &expected,
                    "Ok(state)",
                    "linear negative fixture",
                )
            });
            assert!(
                rejected.is_err(),
                "control/divergence statement must not survive the linear transition gate"
            );
        }
    }

    fn projection_transition_valid_v1(
        source: &str,
        projection_call: &str,
        kernel_call: &str,
        advance_call: &str,
        order: ProjectionTransitionOrderV1,
    ) -> bool {
        let compact = normalized_code_v1(source);
        let projections = compact
            .match_indices(projection_call)
            .map(|(at, _)| at)
            .collect::<Vec<_>>();
        if compact.matches(kernel_call).count() != 1 || compact.matches(advance_call).count() != 1 {
            return false;
        }
        let kernel_at = compact
            .find(kernel_call)
            .expect("single kernel call exists");
        let (before, before_at, after, after_at) = match order {
            ProjectionTransitionOrderV1::Inbound => {
                if projections.len() != 2 {
                    return false;
                }
                let Some((before, before_at)) =
                    projection_binding_v1(&compact, projection_call, projections[0])
                else {
                    return false;
                };
                let Some((after, after_at)) =
                    projection_binding_v1(&compact, projection_call, projections[1])
                else {
                    return false;
                };
                (before, before_at, after, after_at)
            }
            ProjectionTransitionOrderV1::Outbound => {
                if projections.len() != 1 {
                    return false;
                }
                let Some((before, _endpoint, before_at)) =
                    tuple_projection_binding_v1(&compact, kernel_call, kernel_at)
                else {
                    return false;
                };
                let Some((after, after_at)) =
                    projection_binding_v1(&compact, projection_call, projections[0])
                else {
                    return false;
                };
                (before, before_at, after, after_at)
            }
        };
        if before == after {
            return false;
        }
        let equality_call = "require_equal_projection_v1(";
        let equalities = compact
            .match_indices(equality_call)
            .map(|(at, _)| at)
            .collect::<Vec<_>>();
        if equalities.len() != 1 {
            return false;
        }
        let equality_at = equalities[0];
        let opening = equality_at + equality_call.len() - 1;
        let closing = closing_delimiter_v1(
            compact.as_bytes(),
            opening,
            b'(',
            b')',
            "projection equality fixture",
        );
        if &compact[opening + 1..closing] != format!("&{before},&{after}")
            || compact.as_bytes().get(closing + 1) != Some(&b'?')
            || compact.as_bytes().get(closing + 2) != Some(&b';')
        {
            return false;
        }
        let advance_at = compact
            .find(advance_call)
            .expect("single advance call exists");
        let ordered = match order {
            ProjectionTransitionOrderV1::Inbound => {
                before_at < kernel_at
                    && kernel_at < after_at
                    && after_at < equality_at
                    && equality_at < advance_at
            }
            ProjectionTransitionOrderV1::Outbound => {
                before_at == kernel_at
                    && kernel_at < advance_at
                    && advance_at < after_at
                    && after_at < equality_at
            }
        };
        let source_equality_at = rust_code_mask_v1(source)
            .find(equality_call)
            .expect("validated equality call exists in positional source");
        ordered && !has_early_success_token_v1(&source[..source_equality_at])
    }

    fn assert_projection_transition_v1(
        source: &str,
        projection_call: &str,
        kernel_call: &str,
        advance_call: &str,
        order: ProjectionTransitionOrderV1,
        gate: &str,
    ) {
        assert!(
            projection_transition_valid_v1(
                source,
                projection_call,
                kernel_call,
                advance_call,
                order
            ),
            "{gate}: projections must bind distinct before/after values, compare exactly those values, and preserve transition order before success"
        );
    }

    fn assert_outbound_kernel_tuple_v1(
        source: &str,
        kernel_call: &str,
        expected_projection: &str,
        expected_endpoint: &str,
        gate: &str,
    ) {
        let compact = normalized_code_v1(source);
        assert_eq!(
            compact.matches(kernel_call).count(),
            1,
            "{gate}: enqueue call must occur exactly once"
        );
        let call_at = compact
            .find(kernel_call)
            .expect("validated outbound enqueue exists");
        let (projection, endpoint, _) = tuple_projection_binding_v1(&compact, kernel_call, call_at)
            .unwrap_or_else(|| {
                panic!("{gate}: enqueue must bind one propagated projection/endpoint pair")
            });
        assert_eq!(
            projection, expected_projection,
            "{gate}: returned pre-send projection binding drifted"
        );
        assert_eq!(
            endpoint, expected_endpoint,
            "{gate}: returned endpoint binding drifted"
        );
    }

    fn equal_projection_helper_valid_v1(source: &str) -> bool {
        let compact = normalized_code_v1(source);
        let prefix = "fnrequire_equal_projection_v1";
        if !compact.starts_with(prefix)
            || compact.matches(prefix).count() != 1
            || !compact.ends_with('}')
        {
            return false;
        }
        let Some(relative_opening) = compact[prefix.len()..].find('(') else {
            return false;
        };
        let opening = prefix.len() + relative_opening;
        let closing = closing_delimiter_v1(
            compact.as_bytes(),
            opening,
            b'(',
            b')',
            "projection helper fixture",
        );
        let parameter_source = &compact[opening + 1..closing];
        let parameter_source = parameter_source
            .strip_suffix(',')
            .unwrap_or(parameter_source);
        let parameters = parameter_source.split(',').collect::<Vec<_>>();
        if parameters.len() != 2 {
            return false;
        }
        let Some((before_name, before_type)) = parameters[0].split_once(':') else {
            return false;
        };
        let Some((after_name, after_type)) = parameters[1].split_once(':') else {
            return false;
        };
        if before_name != "before"
            || after_name != "after"
            || before_name == after_name
            || !before_type.starts_with('&')
            || before_type != after_type
        {
            return false;
        }
        let Some(relative_body) = compact[closing + 1..].find('{') else {
            return false;
        };
        let body_opening = closing + 1 + relative_body;
        if &compact[closing + 1..body_opening] != "->Result<(),SessionTransitionErrorV1>" {
            return false;
        }
        &compact[body_opening + 1..compact.len() - 1]
            == "ifbefore!=after{returnErr(SessionTransitionErrorV1::terminal());}Ok(())"
    }

    fn assert_equal_projection_helper_v1(source: &str) {
        let helper = find_function_v1(
            source,
            "require_equal_projection_v1",
            "fail-closed projection equality helper",
        );
        assert!(
            equal_projection_helper_valid_v1(helper),
            "projection equality helper must compare distinct refs and return terminal error on inequality before its sole Ok"
        );
    }

    fn assert_outbound_success_v1(
        source: &str,
        successor: &str,
        expected_ok_argument: &str,
        successor_must_precede_ok: bool,
        gate: &str,
    ) {
        let compact = normalized_code_v1(source);
        assert!(
            compact.ends_with('}'),
            "{gate}: transition must retain one closing function brace"
        );
        let equality_call = "require_equal_projection_v1(";
        let equality_at = compact
            .find(equality_call)
            .expect("validated equality call exists");
        let source_equality_at = rust_code_mask_v1(source)
            .find(equality_call)
            .expect("validated equality call exists in positional source");
        assert!(
            !has_early_success_token_v1(&source[..source_equality_at]),
            "{gate}: success occurs before equality"
        );
        assert_eq!(
            compact.matches(successor).count(),
            1,
            "{gate}: exact successor marker drifted"
        );
        let successor_at = compact
            .find(successor)
            .expect("single successor marker exists");
        assert!(
            equality_at < successor_at,
            "{gate}: successor/release occurs before equality"
        );
        let bytes = compact.as_bytes();
        let equality_opening = equality_at + equality_call.len() - 1;
        let equality_closing = closing_delimiter_v1(bytes, equality_opening, b'(', b')', gate);
        assert_eq!(
            bytes.get(equality_closing + 1..equality_closing + 3),
            Some(b"?;".as_slice()),
            "{gate}: projection equality must end in the exact propagated statement"
        );
        if successor_must_precede_ok {
            let (successor_binding, _) = projection_binding_v1(&compact, successor, successor_at)
                .unwrap_or_else(|| {
                    panic!("{gate}: worker release must bind one exact propagated successor")
                });
            assert_eq!(
                successor_binding, "worker",
                "{gate}: release must bind the exact worker custody"
            );
            let successor_opening = successor_at + successor.len() - 1;
            let successor_closing =
                closing_delimiter_v1(bytes, successor_opening, b'(', b')', gate);
            assert_eq!(
                bytes.get(successor_closing + 1..successor_closing + 3),
                Some(b"?;".as_slice()),
                "{gate}: worker release must end in the exact propagated binding statement"
            );
            let tail = &compact[successor_closing + 3..compact.len() - 1];
            assert!(
                tail.starts_with("letsuccessor=WorkerBootstrapReleasedV1{")
                    && tail.ends_with(&format!("}};Ok({expected_ok_argument})")),
                "{gate}: release must be followed only by construction and return of the typed worker successor"
            );
            let opening = tail.find('{').expect("validated worker successor literal");
            let closing = closing_delimiter_v1(tail.as_bytes(), opening, b'{', b'}', gate);
            assert_eq!(
                &tail[closing + 1..],
                format!(";Ok({expected_ok_argument})"),
                "{gate}: only the exact typed worker successor may escape"
            );
            let fields = &tail[opening + 1..closing];
            assert_eq!(
                token_count_v1(fields, "worker"),
                1,
                "{gate}: released worker custody must enter the successor exactly once"
            );
            assert_eq!(
                token_count_v1(fields, "bootstrap_enqueued"),
                1,
                "{gate}: enqueued endpoint must enter the successor exactly once"
            );
            assert!(
                !fields.contains("..") && !fields.contains('('),
                "{gate}: successor construction may not invoke or spread alternate authority"
            );
        } else {
            assert_eq!(
                &compact[equality_closing + 3..compact.len() - 1],
                format!(
                    "let{expected_ok_argument}=ResultQueuedV1{{seal:state.seal,sent_endpoint}};Ok({expected_ok_argument})"
                ),
                "{gate}: only construction and return of the exact queued-result token may remain after projection equality"
            );
        }
    }

    fn assert_inbound_success_v1(
        source: &str,
        cursor_advance_assignment: &str,
        custody_sink: Option<&str>,
        gate: &str,
    ) {
        let compact = normalized_code_v1(source);
        assert!(
            compact.ends_with('}'),
            "{gate}: transition must end with one function brace"
        );

        let equality_call = "require_equal_projection_v1(";
        assert_eq!(
            compact.matches(equality_call).count(),
            1,
            "{gate}: projection equality must occur exactly once"
        );
        let equality_at = compact.find(equality_call).expect("equality exists");
        let equality_opening = equality_at + equality_call.len() - 1;
        let equality_closing =
            closing_delimiter_v1(compact.as_bytes(), equality_opening, b'(', b')', gate);
        assert_eq!(
            compact
                .as_bytes()
                .get(equality_closing + 1..equality_closing + 3),
            Some(b"?;".as_slice()),
            "{gate}: equality must be one propagated statement"
        );

        let positional = rust_code_mask_v1(source);
        let source_equality_at = positional
            .find(equality_call)
            .expect("positional equality exists");
        assert!(
            !has_early_success_token_v1(&source[..source_equality_at]),
            "{gate}: success occurs before equality"
        );
        assert_eq!(
            token_count_v1(source, "Ok"),
            1,
            "{gate}: transition must contain exactly one success constructor"
        );
        assert_eq!(
            token_count_v1(source, "return"),
            0,
            "{gate}: transition may not return before its exact terminal Ok"
        );

        let cursor_advance_assignment = normalized_code_v1(cursor_advance_assignment);
        let aggregate_assignment =
            "state.aggregate_count=state.aggregate_count.advance_after_kernel_success_v1()?;";
        let custody_sink = custody_sink.map(normalized_code_v1).unwrap_or_default();
        let expected_tail =
            format!("{cursor_advance_assignment}{aggregate_assignment}{custody_sink}Ok(state)");
        assert_eq!(
            &compact[equality_closing + 3..compact.len() - 1],
            expected_tail,
            "{gate}: equality must be followed only by cursor advance, aggregate advance, optional custody retention, and the sole Ok"
        );
    }

    fn assert_inbound_success_fixtures_v1() {
        let equality = "require_equal_projection_v1(&before, &after)?;";
        let fixtures = [
            (
                "GeneratorBound inbound-tail fixture",
                "fn route(mut state: StateV1, before: ProjectionV1, after: ProjectionV1, candidate: G0GeneratorBoundTranscriptCandidateV1, received_endpoint: GeneratorBoundReceivedEndpointV1) -> Result<StateV1, SessionTransitionErrorV1> { require_equal_projection_v1(&before, &after)?; state.generator = state.generator.advance_generator_bound_after_kernel_success_v1(candidate)?; state.aggregate_count = state.aggregate_count.advance_after_kernel_success_v1()?; state.accepted_generator = AcceptedGeneratorFrameV1 { endpoint: received_endpoint }; Ok(state) }",
                "state.generator = state.generator.advance_generator_bound_after_kernel_success_v1(candidate)?;",
                Some(
                    "state.accepted_generator = AcceptedGeneratorFrameV1 { endpoint: received_endpoint };",
                ),
            ),
            (
                "WorkerExecBound inbound-tail fixture",
                "fn route(mut state: StateV1, before: ProjectionV1, after: ProjectionV1, candidate: G0TranscriptCandidateV1) -> Result<StateV1, SessionTransitionErrorV1> { require_equal_projection_v1(&before, &after)?; state.worker = state.worker.advance_worker_exec_bound_after_kernel_success_v1(candidate)?; state.aggregate_count = state.aggregate_count.advance_after_kernel_success_v1()?; Ok(state) }",
                "state.worker = state.worker.advance_worker_exec_bound_after_kernel_success_v1(candidate)?;",
                None,
            ),
        ];

        for (label, valid, cursor_assignment, custody_sink) in fixtures {
            assert_inbound_success_v1(valid, cursor_assignment, custody_sink, label);
            let mutant = valid.replace(
                equality,
                "require_equal_projection_v1(&before, &after)?; if before == after { return Ok(state); }",
            );
            assert_ne!(mutant, valid, "{label}: mutant injection failed");
            let rejected = std::panic::catch_unwind(|| {
                assert_inbound_success_v1(&mutant, cursor_assignment, custody_sink, label);
            });
            assert!(
                rejected.is_err(),
                "{label}: conditional early-success mutant survived"
            );
        }
    }

    fn checked_cursor_advance_valid_v1(
        source: &str,
        method_name: &str,
        cursor: &str,
        previous_digest: &str,
        candidate_type: &str,
        successor_type: Option<&str>,
        captures_worker_genesis: bool,
    ) -> bool {
        let compact = normalized_code_v1(source).replace(",)->", ")->");
        if let Some(successor_type) = successor_type {
            let worker_genesis = if captures_worker_genesis {
                "accepted_worker_genesis:candidate.worker_genesis(),"
            } else {
                ""
            };
            compact
                == format!(
                    "fn{method_name}(self,candidate:{candidate_type})->Result<{successor_type},SessionTransitionErrorV1>{{let{cursor}=self.{cursor}.checked_add(1).ok_or(SessionTransitionErrorV1::terminal())?;Ok({successor_type}{{{cursor},{previous_digest}:candidate.digest(),{worker_genesis}}})}}"
                )
        } else {
            let cursor_advance = format!(
                "self.{cursor}=self.{cursor}.checked_add(1).ok_or(SessionTransitionErrorV1::terminal())?;"
            );
            let digest_advance = format!("self.{previous_digest}=candidate.digest();");
            compact
                == format!(
                    "fn{method_name}(mutself,candidate:{candidate_type})->Result<Self,SessionTransitionErrorV1>{{{cursor_advance}{digest_advance}Ok(self)}}"
                )
        }
    }

    fn assert_checked_cursor_advance_v1(
        source: &str,
        method_name: &str,
        cursor: &str,
        previous_digest: &str,
        candidate_type: &str,
        successor_type: Option<&str>,
        captures_worker_genesis: bool,
        gate: &str,
    ) {
        assert!(
            checked_cursor_advance_valid_v1(
                source,
                method_name,
                cursor,
                previous_digest,
                candidate_type,
                successor_type,
                captures_worker_genesis,
            ),
            "{gate}: the exact contract candidate must advance the private cursor by checked +1 and become its private previous digest"
        );
    }

    fn aggregate_capacity_valid_v1(source: &str) -> bool {
        normalized_code_v1(source)
            == "fnrequire_capacity_v1(&self)->Result<(),SessionTransitionErrorV1>{ifself.frames>=64{returnErr(SessionTransitionErrorV1::terminal());}Ok(())}"
    }

    fn aggregate_advance_valid_v1(source: &str) -> bool {
        normalized_code_v1(source)
            == "fnadvance_after_kernel_success_v1(mutself)->Result<Self,SessionTransitionErrorV1>{self.frames=self.frames.checked_add(1).ok_or(SessionTransitionErrorV1::terminal())?;Ok(self)}"
    }

    fn assert_checked_transcript_advance_fixtures_v1() {
        let valid = "fn advance(self, candidate: G0GeneratorBoundTranscriptCandidateV1) -> Result<GeneratorTranscriptStateV1, SessionTransitionErrorV1> { let generator_cursor = self.generator_cursor.checked_add(1).ok_or(SessionTransitionErrorV1::terminal())?; Ok(GeneratorTranscriptStateV1 { generator_cursor, generator_previous_digest: candidate.digest(), accepted_worker_genesis: candidate.worker_genesis(), }) }";
        assert!(checked_cursor_advance_valid_v1(
            valid,
            "advance",
            "generator_cursor",
            "generator_previous_digest",
            "G0GeneratorBoundTranscriptCandidateV1",
            Some("GeneratorTranscriptStateV1"),
            true,
        ));
        for invalid in [
            valid.replace("checked_add(1)", "checked_add(0)"),
            valid.replacen("checked_add(1)", "wrapping_add(1)", 1),
            valid.replace("candidate.digest()", "[0_u8; 32]"),
            valid.replace("accepted_worker_genesis: candidate.worker_genesis(),", ""),
            valid.replace(
                "candidate: G0GeneratorBoundTranscriptCandidateV1",
                "digest: [u8; 32]",
            ),
            valid.replace(
                "Ok(GeneratorTranscriptStateV1",
                "std::process::abort(); Ok(GeneratorTranscriptStateV1",
            ),
            valid.replace(
                "Ok(GeneratorTranscriptStateV1",
                "loop {} Ok(GeneratorTranscriptStateV1",
            ),
            valid.replace(
                "Ok(GeneratorTranscriptStateV1",
                "panic!(); Ok(GeneratorTranscriptStateV1",
            ),
            valid.replace(
                "Ok(GeneratorTranscriptStateV1",
                "diverge(); Ok(GeneratorTranscriptStateV1",
            ),
        ] {
            assert!(
                !checked_cursor_advance_valid_v1(
                    &invalid,
                    "advance",
                    "generator_cursor",
                    "generator_previous_digest",
                    "G0GeneratorBoundTranscriptCandidateV1",
                    Some("GeneratorTranscriptStateV1"),
                    true,
                ),
                "neutralized or unchecked transcript advancement fixture must be rejected"
            );
        }
        let capacity = "fn require_capacity_v1(&self) -> Result<(), SessionTransitionErrorV1> { if self.frames >= 64 { return Err(SessionTransitionErrorV1::terminal()); } Ok(()) }";
        let aggregate = "fn advance_after_kernel_success_v1(mut self) -> Result<Self, SessionTransitionErrorV1> { self.frames = self.frames.checked_add(1).ok_or(SessionTransitionErrorV1::terminal())?; Ok(self) }";
        assert!(aggregate_capacity_valid_v1(capacity));
        assert!(aggregate_advance_valid_v1(aggregate));
        for invalid in [
            capacity.replace("self.frames >= 64", "self.frames > 64"),
            capacity.replace("self.frames >= 64", "false && self.frames >= 64"),
        ] {
            assert!(!aggregate_capacity_valid_v1(&invalid));
        }
        for invalid in [
            aggregate.replace("checked_add(1)", "checked_add(0)"),
            aggregate.replace("checked_add(1)", "wrapping_add(1)"),
            aggregate.replace("checked_add(1)", "saturating_add(1)"),
        ] {
            assert!(!aggregate_advance_valid_v1(&invalid));
        }
    }

    fn assert_projection_gate_fixtures_v1() {
        let valid = "fn route() -> Result<(), SessionTransitionErrorV1> { let (before, bootstrap_enqueued) = state.owner.kernel()?; state.owner.advance(); let after = state.owner.projection()?; require_equal_projection_v1(&before, &after)?; let worker = custody.release()?; let successor = WorkerBootstrapReleasedV1 { worker, bootstrap_enqueued }; Ok(successor) }";
        assert!(projection_transition_valid_v1(
            valid,
            "projection(",
            "kernel(",
            ".advance(",
            ProjectionTransitionOrderV1::Outbound
        ));
        let neutral = valid.replace("&before, &after", "&after, &after");
        assert!(
            !projection_transition_valid_v1(
                &neutral,
                "projection(",
                "kernel(",
                ".advance(",
                ProjectionTransitionOrderV1::Outbound
            ),
            "neutral equality arguments must be rejected"
        );
        let late_advance = valid
            .replace(
                "kernel()?; state.owner.advance(); let after",
                "kernel()?; let after",
            )
            .replace(
                "require_equal_projection_v1(&before, &after)?;",
                "require_equal_projection_v1(&before, &after)?; owner.advance();",
            );
        assert!(
            !projection_transition_valid_v1(
                &late_advance,
                "projection(",
                "kernel(",
                ".advance(",
                ProjectionTransitionOrderV1::Outbound
            ),
            "second projection before advance must be rejected"
        );
        let premature = valid.replace("kernel()?;", "kernel()?; Ok(())?;");
        assert!(
            !projection_transition_valid_v1(
                &premature,
                "projection(",
                "kernel(",
                ".advance(",
                ProjectionTransitionOrderV1::Outbound
            ),
            "success before equality must be rejected"
        );
        let early_return = valid.replace("kernel()?;", "kernel()?; return Ok(());");
        assert!(
            !projection_transition_valid_v1(
                &early_return,
                "projection(",
                "kernel(",
                ".advance(",
                ProjectionTransitionOrderV1::Outbound
            ),
            "return Ok before equality must be rejected"
        );
        let turbofish_return = valid.replace(
            "kernel()?;",
            "kernel()?; return Ok::<_, SessionTransitionErrorV1>(successor);",
        );
        assert!(
            !projection_transition_valid_v1(
                &turbofish_return,
                "projection(",
                "kernel(",
                ".advance(",
                ProjectionTransitionOrderV1::Outbound
            ),
            "turbofish Ok before equality must be rejected"
        );
        let qualified_return = valid.replace(
            "kernel()?;",
            "kernel()?; return core::result::Result::Ok(successor);",
        );
        assert!(
            !projection_transition_valid_v1(
                &qualified_return,
                "projection(",
                "kernel(",
                ".advance(",
                ProjectionTransitionOrderV1::Outbound
            ),
            "qualified Result::Ok before equality must be rejected"
        );
        assert_outbound_success_v1(
            valid,
            "release(",
            "successor",
            true,
            "valid successor provenance fixture",
        );
        let block_success =
            valid.replace("Ok(successor)", "Ok({ let _ = successor; other_value })");
        let block_rejected = std::panic::catch_unwind(|| {
            assert_outbound_success_v1(
                &block_success,
                "release(",
                "successor",
                true,
                "block success provenance fixture",
            )
        });
        assert!(
            block_rejected.is_err(),
            "block-valued Ok must not satisfy exact successor provenance"
        );
        let method_success = valid.replace("Ok(successor)", "carrier.Ok(successor)");
        let method_rejected = std::panic::catch_unwind(|| {
            assert_outbound_success_v1(
                &method_success,
                "release(",
                "successor",
                true,
                "method success provenance fixture",
            )
        });
        assert!(
            method_rejected.is_err(),
            "method-like Ok must not satisfy exact successor provenance"
        );
        let closed_valid = "fn route() -> Result<ResultQueuedV1, SessionTransitionErrorV1> { require_equal_projection_v1(&before, &after)?; let result_queued = ResultQueuedV1 { seal: state.seal, sent_endpoint }; Ok(result_queued) }";
        assert_outbound_success_v1(
            closed_valid,
            "ResultQueuedV1{seal:state.seal,sent_endpoint}",
            "result_queued",
            false,
            "valid queued-result provenance fixture",
        );
        let branched_result = closed_valid.replace(
            "Ok(result_queued)",
            "Ok(if branch { result_queued } else { other })",
        );
        let branch_rejected = std::panic::catch_unwind(|| {
            assert_outbound_success_v1(
                &branched_result,
                "ResultQueuedV1{seal:state.seal,sent_endpoint}",
                "result_queued",
                false,
                "branched queued-result provenance fixture",
            )
        });
        assert!(
            branch_rejected.is_err(),
            "branch-valued Ok must not satisfy exact queued-result provenance"
        );
        let method_result = closed_valid.replace("Ok(result_queued)", "carrier.Ok(result_queued)");
        let method_result_rejected = std::panic::catch_unwind(|| {
            assert_outbound_success_v1(
                &method_result,
                "ResultQueuedV1{seal:state.seal,sent_endpoint}",
                "result_queued",
                false,
                "method queued-result provenance fixture",
            )
        });
        assert!(
            method_result_rejected.is_err(),
            "method-like Ok must not satisfy exact queued-result provenance"
        );
        let helper = "fn require_equal_projection_v1<T: PartialEq>(before: &T, after: &T) -> Result<(), SessionTransitionErrorV1> { if before != after { return Err(SessionTransitionErrorV1::terminal()); } Ok(()) }";
        assert!(equal_projection_helper_valid_v1(helper));
        assert!(
            !equal_projection_helper_valid_v1(
                "fn require_equal_projection_v1<T: PartialEq>(before: &T, after: &T) -> Result<(), SessionTransitionErrorV1> { Ok(()) }"
            ),
            "always-Ok equality helper must be rejected"
        );
    }

    fn closing_delimiter_v1(
        bytes: &[u8],
        opening: usize,
        open: u8,
        close: u8,
        gate: &str,
    ) -> usize {
        assert_eq!(
            bytes.get(opening),
            Some(&open),
            "{gate}: target call has no opening delimiter"
        );
        let mut depth = 1_usize;
        let mut cursor = opening + 1;
        while cursor < bytes.len() {
            if bytes[cursor] == open {
                depth += 1;
            } else if bytes[cursor] == close {
                depth -= 1;
                if depth == 0 {
                    return cursor;
                }
            }
            cursor += 1;
        }
        panic!("{gate}: unbalanced target call")
    }

    fn assert_signature_visibility_fixture_v1() {
        let signatures = function_signatures_v1(
            "pub fn leak(x: OwnerV1) {}\npub(crate) fn join(x: OwnerV1) {}\nfn hidden(x: OwnerV1) {}",
        );
        assert_eq!(
            signatures
                .iter()
                .map(|signature| signature_visibility_v1(signature))
                .collect::<Vec<_>>(),
            ["pub", "pub(crate)", "private"],
            "signature inventory must retain visibility before fn",
        );
    }

    fn assert_exact_question_fixture_v1() {
        let decoy = std::panic::catch_unwind(|| {
            assert_propagates_without_swallow_v1(
                "fn route() { decoy()?; target(nested(one(), two())) ; }",
                "target(",
                "decoy question fixture",
            )
        });
        assert!(
            decoy.is_err(),
            "a preceding decoy `?` must not satisfy target propagation"
        );
        assert_propagates_without_swallow_v1(
            "fn route() { target(nested(one(), two()))?; }",
            "target(",
            "balanced target question fixture",
        );
    }

    fn assert_private_opaque_inventory_v1(source: &str, names: &[&str], gate: &str) {
        assert_no_hidden_source_shapes_v1(gate, source);
        let normalized = normalized_code_v1(source);
        assert!(
            !normalized.contains("#[derive("),
            "{gate}: session authority owners forbid derive-based trait surfaces"
        );
        let allowed_private_functions = [
            "begin_after_parent_endpoint_relinquishment_v1",
            "send_offer_before_nonce_exchange_v1",
            "receive_then_advance_generator_bound_v1",
            "advance_generator_bound_after_kernel_success_v1",
            "enqueue_then_release_worker_v1",
            "advance_worker_bootstrap_after_kernel_success_v1",
            "receive_then_advance_worker_exec_bound_v1",
            "advance_worker_exec_bound_after_kernel_success_v1",
            "enqueue_then_advance_closed_result_v1",
            "advance_closed_result_after_kernel_success_v1",
        ];
        for name in names {
            let declaration = find_braced_declaration_v1(source, "struct", name, gate);
            assert!(
                !rust_code_mask_v1(declaration).contains('!'),
                "{gate}: `{name}` fields may not be macro-generated"
            );
            assert!(
                !normalized.contains(&format!("pubstruct{name}")),
                "{gate}: `{name}` is public"
            );
            assert!(
                !normalized.contains(&format!("pub(crate)struct{name}")),
                "{gate}: `{name}` is crate-visible"
            );
            assert!(
                !normalized.contains(&format!("pubuse{name}")),
                "{gate}: `{name}` is re-exported"
            );
            assert!(
                !normalized.contains(&format!("pub(crate)use{name}")),
                "{gate}: `{name}` is crate re-exported"
            );
            for header in impl_headers_v1(source)
                .into_iter()
                .filter(|header| header.contains(name))
            {
                assert!(
                    !header.contains("for"),
                    "{gate}: `{name}` gained trait surface `{header}`"
                );
                assert_eq!(
                    header,
                    format!("impl{name}"),
                    "{gate}: `{name}` gained generic or wrapper impl surface `{header}`"
                );
            }
            for signature in function_signatures_v1(source)
                .into_iter()
                .filter(|signature| signature.contains(name))
            {
                assert_eq!(
                    signature_visibility_v1(&signature),
                    "private",
                    "{gate}: `{name}` may occur only in private signatures: `{signature}`"
                );
                let function_name = function_name_from_signature_v1(&signature);
                assert!(
                    allowed_private_functions.contains(&function_name),
                    "{gate}: `{name}` gained unapproved function/method `{signature}`"
                );
                assert!(
                    !signature.contains("->&") && !signature.contains("->*"),
                    "{gate}: `{name}` gained a borrowed/raw return `{signature}`"
                );
                for extracted in [
                    "PreparedSupervisorSendV1",
                    "PreparedSupervisor",
                    "PreparedSend",
                    "PreparedFrame",
                ] {
                    assert!(
                        !signature.contains(extracted),
                        "{gate}: `{name}` extracts prepared transport `{extracted}`: `{signature}`"
                    );
                }
            }
        }
        let normalized = normalized_code_v1(source);
        for forbidden in [
            "fninto_parts",
            "fnas_fd",
            "fnas_raw_fd",
            "fnborrow",
            "fnclone",
            "fnsplit",
            "fnretry",
            "fnresend",
            "fnrollback",
        ] {
            assert!(
                !normalized.contains(forbidden),
                "{gate}: opaque inventory gained `{forbidden}`"
            );
        }
        for forbidden_trait in [
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
            "Clone",
            "Copy",
            "Default",
            "Drop",
        ] {
            for name in names {
                assert!(
                    !normalized.contains(&format!("impl{forbidden_trait}for{name}")),
                    "{gate}: `{name}` gained `{forbidden_trait}`"
                );
            }
        }
        for (name, methods) in [
            ("AcceptedGeneratorFrameV1", &[][..]),
            (
                "GeneratorAwaitBoundTranscriptStateV1",
                &[("private", "advance_generator_bound_after_kernel_success_v1")][..],
            ),
            (
                "GeneratorTranscriptStateV1",
                &[("private", "advance_closed_result_after_kernel_success_v1")][..],
            ),
            (
                "WorkerAwaitBootstrapTranscriptStateV1",
                &[(
                    "private",
                    "advance_worker_bootstrap_after_kernel_success_v1",
                )][..],
            ),
            (
                "WorkerTranscriptStateV1",
                &[(
                    "private",
                    "advance_worker_exec_bound_after_kernel_success_v1",
                )][..],
            ),
            (
                "AggregateCountV1",
                &[
                    ("private", "require_capacity_v1"),
                    ("private", "advance_after_kernel_success_v1"),
                ][..],
            ),
            ("ResultQueuedV1", &[][..]),
            ("RelinquishedChildEndpointsV1", &[][..]),
            ("ExecutableSessionCompositeV1", &[][..]),
            ("PostReleaseSessionCustodyV1", &[][..]),
            ("GeneratorBoundPendingV1", &[][..]),
            ("PrivateSupervisorSessionCoreV1", &[][..]),
            ("WorkerBootstrapReleasedV1", &[][..]),
            ("WorkerExecBoundAcceptedV1", &[][..]),
        ] {
            if names.contains(&name) {
                assert_inherent_method_allowlist_v1(source, name, methods, gate);
            }
        }
        assert!(
            impl_headers_v1(source)
                .into_iter()
                .all(|header| !header.contains("PrivateSessionPhaseV1")),
            "{gate}: private pre-session phase may have no inherent or trait implementation"
        );
        assert_session_function_allowlist_v1(source, gate);
    }

    fn assert_exact_session_typestate_layouts_v1(source: &str, gate: &str) {
        for (name, expected) in [
            (
                "RelinquishedChildEndpointsV1",
                "structRelinquishedChildEndpointsV1{generator_endpoint:SupervisorGeneratorEndpointV1,worker_endpoint:SupervisorWorkerEndpointV1,generator_executable:GeneratorChildExecutableCustodyV2,worker_executable:WorkerMapsVerifiedExecutableCustodyV2,}",
            ),
            (
                "ExecutableSessionCompositeV1",
                "structExecutableSessionCompositeV1{generator:GeneratorChildExecutableCustodyV2,worker:WorkerMapsVerifiedExecutableCustodyV2,}",
            ),
            (
                "PostReleaseSessionCustodyV1",
                "structPostReleaseSessionCustodyV1{generator:GeneratorChildExecutableCustodyV2,worker:WorkerChildExecutableCustodyV2,}",
            ),
            (
                "GeneratorAwaitBoundTranscriptStateV1",
                "structGeneratorAwaitBoundTranscriptStateV1{generator_cursor:u8,}",
            ),
            (
                "GeneratorTranscriptStateV1",
                "structGeneratorTranscriptStateV1{generator_cursor:u8,generator_previous_digest:[u8;32],accepted_worker_genesis:[u8;32],}",
            ),
            (
                "WorkerAwaitBootstrapTranscriptStateV1",
                "structWorkerAwaitBootstrapTranscriptStateV1{worker_cursor:u8,}",
            ),
            (
                "WorkerTranscriptStateV1",
                "structWorkerTranscriptStateV1{worker_cursor:u8,worker_previous_digest:[u8;32],}",
            ),
            (
                "GeneratorBoundPendingV1",
                "structGeneratorBoundPendingV1{seal:UninhabitedSessionInputV1,generator_endpoint:SupervisorGeneratorSentEndpointV1,worker_endpoint:SupervisorWorkerEndpointV1,generator:GeneratorAwaitBoundTranscriptStateV1,worker:WorkerAwaitBootstrapTranscriptStateV1,aggregate_count:AggregateCountV1,executable:ExecutableSessionCompositeV1,}",
            ),
            (
                "PrivateSupervisorSessionCoreV1",
                "structPrivateSupervisorSessionCoreV1{seal:UninhabitedSessionInputV1,accepted_generator:AcceptedGeneratorFrameV1,worker_endpoint:SupervisorWorkerEndpointV1,generator:GeneratorTranscriptStateV1,worker:WorkerAwaitBootstrapTranscriptStateV1,aggregate_count:AggregateCountV1,executable:ExecutableSessionCompositeV1,}",
            ),
            (
                "WorkerBootstrapReleasedV1",
                "structWorkerBootstrapReleasedV1{seal:UninhabitedSessionInputV1,accepted_generator:AcceptedGeneratorFrameV1,generator:GeneratorTranscriptStateV1,worker:WorkerTranscriptStateV1,aggregate_count:AggregateCountV1,executable:PostReleaseSessionCustodyV1,bootstrap_enqueued:WorkerBootstrapEnqueuedEndpointV1,}",
            ),
            (
                "WorkerExecBoundAcceptedV1",
                "structWorkerExecBoundAcceptedV1{seal:UninhabitedSessionInputV1,accepted_generator:AcceptedGeneratorFrameV1,generator:GeneratorTranscriptStateV1,worker:WorkerTranscriptStateV1,aggregate_count:AggregateCountV1,executable:PostReleaseSessionCustodyV1,worker_received:WorkerExecBoundReceivedEndpointV1,}",
            ),
            (
                "ResultQueuedV1",
                "structResultQueuedV1{seal:UninhabitedSessionInputV1,sent_endpoint:SupervisorGeneratorSentEndpointV1,generator:GeneratorTranscriptStateV1,worker:WorkerTranscriptStateV1,aggregate_count:AggregateCountV1,executable:PostReleaseSessionCustodyV1,worker_received:WorkerExecBoundReceivedEndpointV1,}",
            ),
        ] {
            assert_eq!(
                normalized_code_v1(find_braced_declaration_v1(source, "struct", name, gate)),
                expected,
                "{gate}: `{name}` exact affine layout drifted"
            );
        }
        assert_eq!(
            normalized_code_v1(find_braced_declaration_v1(
                source,
                "enum",
                "PrivateSessionPhaseV1",
                gate,
            )),
            "enumPrivateSessionPhaseV1{AwaitSessionOffer{seal:UninhabitedSessionInputV1,relinquished:RelinquishedChildEndpointsV1,},}",
            "{gate}: private pre-session phase must own the sole relinquished carrier and uninhabited seal"
        );
    }

    fn assert_exact_session_typestate_layout_fixtures_v1() {
        let valid = "struct GeneratorBoundPendingV1 { seal: UninhabitedSessionInputV1, generator_endpoint: SupervisorGeneratorSentEndpointV1, worker_endpoint: SupervisorWorkerEndpointV1, generator: GeneratorAwaitBoundTranscriptStateV1, worker: WorkerAwaitBootstrapTranscriptStateV1, aggregate_count: AggregateCountV1, executable: ExecutableSessionCompositeV1, }";
        let observed = normalized_code_v1(find_braced_declaration_v1(
            valid,
            "struct",
            "GeneratorBoundPendingV1",
            "typestate layout positive fixture",
        ));
        assert_eq!(
            observed,
            "structGeneratorBoundPendingV1{seal:UninhabitedSessionInputV1,generator_endpoint:SupervisorGeneratorSentEndpointV1,worker_endpoint:SupervisorWorkerEndpointV1,generator:GeneratorAwaitBoundTranscriptStateV1,worker:WorkerAwaitBootstrapTranscriptStateV1,aggregate_count:AggregateCountV1,executable:ExecutableSessionCompositeV1,}"
        );
        for mutant in [
            valid.replace(
                "generator_endpoint:",
                "alternate_generator: GeneratorChildExecutableCustodyV2, generator_endpoint:",
            ),
            valid.replace(
                "executable: ExecutableSessionCompositeV1,",
                "executable: PostReleaseSessionCustodyV1,",
            ),
        ] {
            let rejected = std::panic::catch_unwind(|| {
                let declaration = normalized_code_v1(find_braced_declaration_v1(
                    &mutant,
                    "struct",
                    "GeneratorBoundPendingV1",
                    "typestate layout negative fixture",
                ));
                assert_eq!(declaration, observed);
            });
            assert!(
                rejected.is_err(),
                "alternate owner fields or owner types must not survive exact typestate layout"
            );
        }
    }

    fn assert_uninhabited_session_seal_v1(source: &str, gate: &str) {
        let seal = normalized_code_v1(find_braced_declaration_v1(
            source,
            "enum",
            "UninhabitedSessionInputV1",
            gate,
        ));
        assert_eq!(
            seal, "enumUninhabitedSessionInputV1{}",
            "{gate}: session seal must be an exact empty enum"
        );
        assert!(
            impl_headers_v1(source)
                .into_iter()
                .all(|header| !header.contains("UninhabitedSessionInputV1")),
            "{gate}: empty session seal may have no inherent or trait implementation"
        );
        assert!(
            function_signatures_v1(source)
                .into_iter()
                .filter(|signature| signature.contains("UninhabitedSessionInputV1"))
                .all(|signature| function_name_from_signature_v1(&signature)
                    == "begin_after_parent_endpoint_relinquishment_v1"),
            "{gate}: empty session seal may occur only in the private begin signature"
        );
        let phase = find_braced_declaration_v1(source, "enum", "PrivateSessionPhaseV1", gate);
        require_once_v1(
            phase,
            "UninhabitedSessionInputV1",
            "uninhabited private pre-session phase seal",
        );
        for state in [
            "GeneratorBoundPendingV1",
            "PrivateSupervisorSessionCoreV1",
            "WorkerBootstrapReleasedV1",
            "WorkerExecBoundAcceptedV1",
            "ResultQueuedV1",
        ] {
            let declaration = find_braced_declaration_v1(source, "struct", state, gate);
            require_once_v1(
                declaration,
                "UninhabitedSessionInputV1",
                "affine session typestate uninhabited seal",
            );
        }
        let queued = find_braced_declaration_v1(source, "struct", "ResultQueuedV1", gate);
        require_once_v1(
            queued,
            "PostReleaseSessionCustodyV1",
            "queued-result retained released executable custody composite",
        );
        require_once_v1(
            queued,
            "WorkerExecBoundReceivedEndpointV1",
            "queued-result retained worker received endpoint custody",
        );
        require_once_v1(
            queued,
            "SupervisorGeneratorSentEndpointV1",
            "queued-result sent endpoint custody",
        );
        let released =
            find_braced_declaration_v1(source, "struct", "WorkerBootstrapReleasedV1", gate);
        require_once_v1(
            released,
            "PostReleaseSessionCustodyV1",
            "released worker process custody composite in the next affine phase",
        );
        require_once_v1(
            released,
            "WorkerBootstrapEnqueuedEndpointV1",
            "released worker endpoint custody in the next affine phase",
        );
        let compact = normalized_code_v1(source);
        for forbidden in [
            "UninhabitedSessionInputV1::",
            "implDefaultforUninhabitedSessionInputV1",
            "MaybeUninit<UninhabitedSessionInputV1>",
            "transmute",
            "zeroed",
        ] {
            assert!(
                !compact.contains(forbidden),
                "{gate}: uninhabited seal gained fabrication route `{forbidden}`"
            );
        }
    }

    fn typed_input_specs_v1() -> [(&'static str, &'static str, &'static str, &'static str); 9] {
        [
            (
                "SessionOfferSendInputV1",
                "PreparedSupervisorSendV1",
                "prepare_session_offer_send_v1",
                "SupervisorGeneratorSendOpV1",
            ),
            (
                "GeneratorCommitReceiveInputV1",
                "PreparedSupervisorReceiveV1",
                "receive_generator_nonce_commit_once_v1",
                "GeneratorCommitReceivedEndpointV1",
            ),
            (
                "SupervisorCommitSendInputV1",
                "PreparedSupervisorSendV1",
                "prepare_supervisor_commit_send_v1",
                "SupervisorGeneratorSendOpV1",
            ),
            (
                "GeneratorRevealReceiveInputV1",
                "PreparedSupervisorReceiveV1",
                "receive_generator_nonce_reveal_once_v1",
                "GeneratorRevealReceivedEndpointV1",
            ),
            (
                "SupervisorRevealSendInputV1",
                "PreparedSupervisorSendV1",
                "prepare_supervisor_reveal_send_v1",
                "SupervisorGeneratorSendOpV1",
            ),
            (
                "GeneratorBoundReceiveInputV1",
                "PreparedSupervisorReceiveV1",
                "receive_generator_bound_once_v1",
                "GeneratorBoundReceivedEndpointV1",
            ),
            (
                "WorkerBootstrapSendInputV1",
                "PreparedSupervisorSendV1",
                "prepare_worker_bootstrap_send_v1",
                "SupervisorWorkerBootstrapSendOpV1",
            ),
            (
                "WorkerExecBoundReceiveInputV1",
                "PreparedSupervisorReceiveV1",
                "receive_worker_exec_bound_once_v1",
                "WorkerExecBoundReceivedEndpointV1",
            ),
            (
                "ClosedResultSendInputV1",
                "PreparedSupervisorSendV1",
                "prepare_closed_result_send_v1",
                "SupervisorGeneratorSendOpV1",
            ),
        ]
    }

    fn pre_session_input_specs_v1() -> [(&'static str, &'static str); 5] {
        [
            ("SessionOfferSendInputV1", "PreparedSupervisorSendV1"),
            (
                "GeneratorCommitReceiveInputV1",
                "PreparedSupervisorReceiveV1",
            ),
            ("SupervisorCommitSendInputV1", "PreparedSupervisorSendV1"),
            (
                "GeneratorRevealReceiveInputV1",
                "PreparedSupervisorReceiveV1",
            ),
            ("SupervisorRevealSendInputV1", "PreparedSupervisorSendV1"),
        ]
    }

    fn assert_exact_pre_session_input_layout_v1(
        source: &str,
        name: &str,
        carrier: &str,
        gate: &str,
    ) {
        let declaration = find_braced_declaration_v1(source, "struct", name, gate);
        assert_eq!(
            normalized_code_v1(declaration),
            format!("struct{name}{{prepared:{carrier},}}"),
            "{gate}: `{name}` must contain only its exact prepared transport"
        );
        assert_eq!(
            normalized_code_v1(source)
                .matches(&format!("pub(crate)struct{name}{{"))
                .count(),
            1,
            "{gate}: `{name}` must have exactly crate-private visibility"
        );
    }

    fn assert_exact_pre_session_input_layouts_v1(source: &str, whole_ancillary: &str, gate: &str) {
        for (name, carrier) in pre_session_input_specs_v1() {
            assert_exact_pre_session_input_layout_v1(source, name, carrier, gate);
            assert_eq!(
                token_count_v1(source, name),
                2,
                "{gate}: `{name}` must occur only in its declaration and sole consumer signature inside selected_target"
            );
            assert_eq!(
                token_count_v1(whole_ancillary, name),
                3,
                "{gate}: `{name}` must add only its sole crate-private re-export outside selected_target"
            );
        }
    }

    fn assert_exact_pre_session_input_layout_fixtures_v1() {
        for (name, carrier) in pre_session_input_specs_v1() {
            let valid = format!("pub(crate) struct {name} {{ prepared: {carrier}, }}");
            assert_exact_pre_session_input_layout_v1(
                &valid,
                name,
                carrier,
                "pre-session input positive fixture",
            );
            let detached = valid.replace("}", "detached: SupervisorWorkerEndpointV1, }");
            let rejected = std::panic::catch_unwind(|| {
                assert_exact_pre_session_input_layout_v1(
                    &detached,
                    name,
                    carrier,
                    "pre-session detached-owner fixture",
                )
            });
            assert!(
                rejected.is_err(),
                "detached opaque ownership must be rejected for `{name}`"
            );
        }
    }

    #[derive(Clone, Copy)]
    struct CandidateProducerSpecV1 {
        input: &'static str,
        function: &'static str,
        output: &'static str,
        output_binding: &'static str,
        candidate: &'static str,
        ordinal: Option<u8>,
    }

    fn candidate_producer_specs_v1() -> [CandidateProducerSpecV1; 4] {
        [
            CandidateProducerSpecV1 {
                input: "GeneratorBoundReceiveInputV1",
                function: "receive_generator_bound_once_v1",
                output: "GeneratorBoundReceivedEndpointV1",
                output_binding: "received_endpoint",
                candidate: "G0GeneratorBoundTranscriptCandidateV1",
                ordinal: None,
            },
            CandidateProducerSpecV1 {
                input: "WorkerBootstrapSendInputV1",
                function: "prepare_worker_bootstrap_send_v1",
                output: "SupervisorWorkerBootstrapSendOpV1",
                output_binding: "operation",
                candidate: "G0TranscriptCandidateV1",
                ordinal: Some(0),
            },
            CandidateProducerSpecV1 {
                input: "WorkerExecBoundReceiveInputV1",
                function: "receive_worker_exec_bound_once_v1",
                output: "WorkerExecBoundReceivedEndpointV1",
                output_binding: "received_endpoint",
                candidate: "G0TranscriptCandidateV1",
                ordinal: Some(1),
            },
            CandidateProducerSpecV1 {
                input: "ClosedResultSendInputV1",
                function: "prepare_closed_result_send_v1",
                output: "SupervisorGeneratorSendOpV1",
                output_binding: "operation",
                candidate: "G0TranscriptCandidateV1",
                ordinal: Some(1),
            },
        ]
    }

    const UNINHABITED_SEMANTIC_JOIN_V1: &str = "UninhabitedSupervisorSemanticJoinV1";
    const G0A_FEATURE_GATE_V1: &str = "#[cfg(feature = \"h0-tmpfs-provider-v2-g0\")]";

    fn has_item_boundary_before_v1(mask: &str, start: usize) -> bool {
        let prefix = mask[..start].trim_end();
        prefix.is_empty() || matches!(prefix.as_bytes().last(), Some(b'{' | b'}' | b';' | b','))
    }

    fn exact_immediate_attribute_start_v1(
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
        if source.get(attribute_start..attribute_end)? != expected
            || !has_item_boundary_before_v1(mask, attribute_start)
        {
            return None;
        }
        Some(attribute_start)
    }

    fn assert_candidate_input_is_uninhabited_join_v1(
        source: &str,
        name: &str,
        carrier: &str,
        gate: &str,
    ) {
        let declaration = find_braced_declaration_v1(source, "struct", name, gate);
        let expected = format!(
            "struct{name}{{prepared:{carrier},session:ProviderSessionMaterialV1,frame:WireFrameV1,_seal:{UNINHABITED_SEMANTIC_JOIN_V1},}}"
        );
        assert_eq!(
            normalized_code_v1(declaration),
            expected,
            "{gate}: `{name}` must be the exact affine, unconstructible prepared/session/frame carrier"
        );
        assert_eq!(
            normalized_code_v1(source)
                .matches(&format!("pub(crate)struct{name}{{"))
                .count(),
            1,
            "{gate}: `{name}` must have exactly crate-private visibility"
        );
    }

    fn assert_private_empty_enum_v1(
        source: &str,
        name: &str,
        expected_attribute: Option<&str>,
        gate: &str,
    ) {
        let mask = rust_code_mask_v1(source);
        let bytes = mask.as_bytes();
        let mut matches = Vec::new();
        let mut cursor = 0_usize;
        while let Some(relative) = mask[cursor..].find("enum") {
            let start = cursor + relative;
            cursor = start + 4;
            if !token_boundary_v1(bytes, start, 4) {
                continue;
            }
            let name_start = skip_ws_v1(bytes, cursor);
            if mask[name_start..].starts_with(name)
                && token_boundary_v1(bytes, name_start, name.len())
            {
                matches.push(start);
            }
        }
        assert_eq!(
            matches.len(),
            1,
            "{gate}: expected exactly one enum declaration for `{name}`"
        );
        let start = matches[0];
        let prefix_start = expected_attribute.map_or(start, |attribute| {
            exact_immediate_attribute_start_v1(source, &mask, start, attribute)
                .unwrap_or_else(|| {
                    panic!(
                        "{gate}: `{name}` lacks its sole exact active immediately preceding attribute"
                    )
                })
        });
        let mut previous = prefix_start;
        while previous > 0 && bytes[previous - 1].is_ascii_whitespace() {
            previous -= 1;
        }
        assert!(
            previous == 0 || matches!(bytes[previous - 1], b'{' | b'}' | b';'),
            "{gate}: `{name}` must have no Rust visibility or unowned attribute prefix"
        );
        let declaration = find_braced_declaration_v1(source, "enum", name, gate);
        assert_eq!(
            normalized_code_v1(declaration),
            format!("enum{name}{{}}"),
            "{gate}: `{name}` must remain a private empty enum"
        );
    }

    fn assert_uninhabited_semantic_join_fixtures_v1() {
        assert_private_empty_enum_v1(
            "enum UninhabitedSupervisorSemanticJoinV1 {}",
            UNINHABITED_SEMANTIC_JOIN_V1,
            None,
            "private empty semantic seal positive fixture",
        );
        let feature_gate = G0A_FEATURE_GATE_V1;
        let gated = format!("{feature_gate} enum {UNINHABITED_SEMANTIC_JOIN_V1} {{}}");
        assert_private_empty_enum_v1(
            &gated,
            UNINHABITED_SEMANTIC_JOIN_V1,
            Some(feature_gate),
            "feature-gated private empty semantic seal positive fixture",
        );
        for mutant in [
            gated.replace(feature_gate, "#[cfg(any())]"),
            gated.replace(" enum", " pub(crate) enum"),
            format!("// {feature_gate}\nenum {UNINHABITED_SEMANTIC_JOIN_V1} {{}}"),
            format!("{feature_gate}\n{feature_gate}\nenum {UNINHABITED_SEMANTIC_JOIN_V1} {{}}"),
            format!("#[cfg(any())]\n{feature_gate}\nenum {UNINHABITED_SEMANTIC_JOIN_V1} {{}}"),
        ] {
            let rejected = std::panic::catch_unwind(|| {
                assert_private_empty_enum_v1(
                    &mutant,
                    UNINHABITED_SEMANTIC_JOIN_V1,
                    Some(feature_gate),
                    "feature-gated private empty semantic seal negative fixture",
                )
            });
            assert!(
                rejected.is_err(),
                "semantic join seal must retain its exact feature gate and private visibility"
            );
        }
        let balanced_valid = format!(
            "{feature_gate}\nstruct DonorV1;\n{feature_gate}\nenum {UNINHABITED_SEMANTIC_JOIN_V1} {{}}"
        );
        let balanced_comment_and_duplicate_mutant = format!(
            "{feature_gate}\n{feature_gate}\nstruct DonorV1;\n// {feature_gate}\nenum {UNINHABITED_SEMANTIC_JOIN_V1} {{}}"
        );
        assert_eq!(
            attribute_inventory_v1(&balanced_comment_and_duplicate_mutant),
            attribute_inventory_v1(&balanced_valid),
            "the causal cfg mutant must preserve the aggregate active-attribute inventory"
        );
        let rejected = std::panic::catch_unwind(|| {
            assert_private_empty_enum_v1(
                &balanced_comment_and_duplicate_mutant,
                UNINHABITED_SEMANTIC_JOIN_V1,
                Some(feature_gate),
                "balanced comment/duplicate feature-gate mutant",
            )
        });
        assert!(
            rejected.is_err(),
            "aggregate cfg counts must not substitute for an active gate owned by the enum"
        );
        for visibility in ["pub ", "pub(crate) ", "pub(super) ", "pub(in crate) "] {
            let mutant = format!("{visibility}enum UninhabitedSupervisorSemanticJoinV1 {{}}");
            let rejected = std::panic::catch_unwind(|| {
                assert_private_empty_enum_v1(
                    &mutant,
                    UNINHABITED_SEMANTIC_JOIN_V1,
                    None,
                    "private empty semantic seal visibility fixture",
                )
            });
            assert!(
                rejected.is_err(),
                "semantic join seal visibility `{visibility}` must be rejected"
            );
        }
        let valid = "
            pub(crate) struct GeneratorBoundReceiveInputV1 {
                prepared: PreparedSupervisorReceiveV1,
                session: ProviderSessionMaterialV1,
                frame: WireFrameV1,
                _seal: UninhabitedSupervisorSemanticJoinV1,
            }
        ";
        assert_candidate_input_is_uninhabited_join_v1(
            valid,
            "GeneratorBoundReceiveInputV1",
            "PreparedSupervisorReceiveV1",
            "uninhabited semantic join positive fixture",
        );
        for mutant in [
            valid.replace(
                "_seal: UninhabitedSupervisorSemanticJoinV1",
                "credentials: PeerCredentialsV1",
            ),
            valid.replace(
                "_seal: UninhabitedSupervisorSemanticJoinV1",
                "fd_commitments: Vec<FdCommitmentV1>",
            ),
        ] {
            let rejected = std::panic::catch_unwind(|| {
                assert_candidate_input_is_uninhabited_join_v1(
                    &mutant,
                    "GeneratorBoundReceiveInputV1",
                    "PreparedSupervisorReceiveV1",
                    "uninhabited semantic join negative fixture",
                )
            });
            assert!(
                rejected.is_err(),
                "detached credential/commitment input must not replace the uninhabited join seal"
            );
        }
    }

    fn assert_uninhabited_semantic_join_inventory_v1(
        source: &str,
        whole_ancillary: &str,
        gate: &str,
    ) {
        assert_private_empty_enum_v1(
            source,
            UNINHABITED_SEMANTIC_JOIN_V1,
            Some("#[cfg(feature = \"h0-tmpfs-provider-v2-g0\")]"),
            gate,
        );
        let seal = find_braced_declaration_v1(source, "enum", UNINHABITED_SEMANTIC_JOIN_V1, gate);
        assert_eq!(
            normalized_code_v1(seal),
            format!("enum{UNINHABITED_SEMANTIC_JOIN_V1}{{}}"),
            "{gate}: semantic join seal must remain a private empty enum"
        );
        let compact = normalized_code_v1(source);
        assert_eq!(
            compact
                .matches(&format!("enum{UNINHABITED_SEMANTIC_JOIN_V1}{{"))
                .count(),
            1,
            "{gate}: semantic join seal declaration inventory drifted"
        );
        assert_eq!(
            token_count_v1(source, UNINHABITED_SEMANTIC_JOIN_V1),
            5,
            "{gate}: semantic join seal must occur only in its declaration and four carriers"
        );
        assert!(
            impl_headers_v1(source)
                .iter()
                .all(|header| !header.contains(UNINHABITED_SEMANTIC_JOIN_V1)),
            "{gate}: semantic join seal gained an impl"
        );
        assert!(
            function_signatures_v1(source)
                .iter()
                .all(|signature| !signature.contains(UNINHABITED_SEMANTIC_JOIN_V1)),
            "{gate}: semantic join seal escaped through a function signature"
        );
        for spec in candidate_producer_specs_v1() {
            let carrier = typed_input_specs_v1()
                .into_iter()
                .find_map(|(name, carrier, _, _)| (name == spec.input).then_some(carrier))
                .expect("candidate producer input has one typed carrier");
            assert_candidate_input_is_uninhabited_join_v1(source, spec.input, carrier, gate);
            assert_eq!(
                compact.matches(&format!("{}{{", spec.input)).count(),
                1,
                "{gate}: `{}` must have no struct literal, pattern constructor, or duplicate declaration",
                spec.input,
            );
            assert_eq!(
                token_count_v1(source, spec.input),
                2,
                "{gate}: `{}` must occur only in its declaration and sole consumer signature inside selected_target",
                spec.input,
            );
            assert_eq!(
                token_count_v1(whole_ancillary, spec.input),
                3,
                "{gate}: `{}` must add only its sole crate-private re-export outside selected_target",
                spec.input,
            );
            assert_eq!(
                token_count_v1(source, spec.function),
                1,
                "{gate}: `{}` must have no selected-target caller or wrapper",
                spec.function,
            );
            let expected_whole_function_count =
                usize::from(spec.function == "prepare_closed_result_send_v1") + 1;
            assert_eq!(
                token_count_v1(whole_ancillary, spec.function),
                expected_whole_function_count,
                "{gate}: `{}` must have only its definition{} in whole ancillary production",
                spec.function,
                if expected_whole_function_count == 2 {
                    " and sole crate-private free-function re-export"
                } else {
                    " (inherent methods cannot be re-exported as free functions)"
                },
            );
        }
        for forbidden in [
            "UninhabitedSupervisorSemanticJoinV1::",
            "MaybeUninit<UninhabitedSupervisorSemanticJoinV1>",
            "MaybeUninit<GeneratorBoundReceiveInputV1>",
            "MaybeUninit<WorkerBootstrapSendInputV1>",
            "MaybeUninit<WorkerExecBoundReceiveInputV1>",
            "MaybeUninit<ClosedResultSendInputV1>",
        ] {
            assert!(
                !compact.contains(forbidden),
                "{gate}: uninhabited semantic join gained fabrication route `{forbidden}`"
            );
        }
    }

    fn assert_candidate_producer_straight_line_v1(
        body: &str,
        expected_guard_count: usize,
        fallible_calls: &[&str],
        gate: &str,
    ) {
        for token in ["if", "return", "Err"] {
            assert_eq!(
                token_count_v1(body, token),
                expected_guard_count,
                "{gate}: candidate producer `{token}` inventory permits an early terminal path"
            );
        }
        assert_eq!(
            token_count_v1(body, "Ok"),
            1,
            "{gate}: candidate producer must have only its exact final success"
        );
        for forbidden in [
            "else",
            "match",
            "loop",
            "while",
            "for",
            "break",
            "continue",
            "panic",
            "panic_any",
            "unreachable",
            "unreachable_unchecked",
            "todo",
            "unimplemented",
            "abort",
            "exit",
            "_exit",
        ] {
            assert_eq!(
                token_count_v1(body, forbidden),
                0,
                "{gate}: candidate producer contains divergent control token `{forbidden}`"
            );
        }
        for call in fallible_calls {
            assert_propagates_without_swallow_v1(body, call, gate);
        }
        assert_eq!(
            rust_code_mask_v1(body)
                .bytes()
                .filter(|byte| *byte == b'?')
                .count(),
            fallible_calls.len(),
            "{gate}: candidate producer has a detached or missing error-propagation site"
        );
    }

    fn assert_candidate_producer_straight_line_fixtures_v1() {
        let valid_receive = "fn route() -> Result<(), E> { let raw = first()?; if bad() { return Err(E); } second()?; third()?; Ok(()) }";
        assert_candidate_producer_straight_line_v1(
            valid_receive,
            1,
            &["first(", "second(", "third("],
            "straight-line receive positive fixture",
        );
        let valid_send = "fn route() -> Result<(), E> { let raw = first()?; if bad() { return Err(E); } second()?; Ok(()) }";
        assert_candidate_producer_straight_line_v1(
            valid_send,
            1,
            &["first(", "second("],
            "straight-line send positive fixture",
        );
        for mutant in [
            valid_receive.replace("{ let raw", "{ return Err(E); let raw"),
            valid_receive.replace("second()?;", "Err::<(), E>(E)?; second()?;"),
            valid_receive.replace("second()?;", "panic!(); second()?;"),
            valid_receive.replace("second()?;", "loop { break; } second()?;"),
            valid_receive.replace("second()?;", "extra()?; second()?;"),
        ] {
            let rejected = std::panic::catch_unwind(|| {
                assert_candidate_producer_straight_line_v1(
                    &mutant,
                    1,
                    &["first(", "second(", "third("],
                    "straight-line candidate negative fixture",
                )
            });
            assert!(
                rejected.is_err(),
                "early terminal or detached propagation must be rejected"
            );
        }
        let exact = "fn route() { first(); Ok(()) }";
        assert_eq!(
            normalized_function_body_v1(exact, "exact producer body positive fixture"),
            "first();Ok(())"
        );
        for mutant in [
            exact.replace("Ok(())", "None::<()>.unwrap(); Ok(())"),
            exact.replace("Ok(())", "diverge(); Ok(())"),
        ] {
            assert_ne!(
                normalized_function_body_v1(&mutant, "exact producer body negative fixture"),
                "first();Ok(())",
                "an extra divergent statement must not satisfy an exact producer body"
            );
        }
    }

    fn expected_pre_session_consumer_body_v1(name: &str) -> &'static str {
        match name {
            "prepare_session_offer_send_v1" => {
                "letprepared=prepare_supervisor_typed_send_v1(input.prepared,&[])?;letoperation=SupervisorGeneratorSendOpV1{endpoint,prepared,phase:SupervisorGeneratorSendPhaseV1::AwaitGeneratorCommit};Ok(operation)"
            }
            "receive_generator_nonce_commit_once_v1" => {
                "letSupervisorGeneratorSentEndpointV1{endpoint,phase}=self;ifphaseasu8!=SupervisorGeneratorSendPhaseV1::AwaitGeneratorCommitasu8{returnErr(SupervisorTypedTransitionErrorV1::terminal());}letprepared=prepare_supervisor_typed_receive_v1(input.prepared,&[])?;letendpoint=receive_exact_generator_once_v1(endpoint,prepared)?;Ok(GeneratorCommitReceivedEndpointV1{endpoint})"
            }
            "prepare_supervisor_commit_send_v1" => {
                "letprepared=prepare_supervisor_typed_send_v1(input.prepared,&[])?;letGeneratorCommitReceivedEndpointV1{endpoint}=endpoint;letoperation=SupervisorGeneratorSendOpV1{endpoint:SupervisorGeneratorEndpointV1(endpoint),prepared,phase:SupervisorGeneratorSendPhaseV1::AwaitGeneratorReveal};Ok(operation)"
            }
            "receive_generator_nonce_reveal_once_v1" => {
                "letSupervisorGeneratorSentEndpointV1{endpoint,phase}=self;ifphaseasu8!=SupervisorGeneratorSendPhaseV1::AwaitGeneratorRevealasu8{returnErr(SupervisorTypedTransitionErrorV1::terminal());}letprepared=prepare_supervisor_typed_receive_v1(input.prepared,&[])?;letendpoint=receive_exact_generator_once_v1(endpoint,prepared)?;Ok(GeneratorRevealReceivedEndpointV1{endpoint})"
            }
            "prepare_supervisor_reveal_send_v1" => {
                "letprepared=prepare_supervisor_typed_send_v1(input.prepared,&[])?;letGeneratorRevealReceivedEndpointV1{endpoint}=endpoint;letoperation=SupervisorGeneratorSendOpV1{endpoint:SupervisorGeneratorEndpointV1(endpoint),prepared,phase:SupervisorGeneratorSendPhaseV1::AwaitGeneratorBound};Ok(operation)"
            }
            _ => unreachable!("fixed pre-session consumer inventory"),
        }
    }

    fn expected_shared_preparation_body_v1(name: &str) -> &'static str {
        match name {
            "prepare_supervisor_typed_send_v1" => {
                "ifprepared.descriptors.len()!=expected_roles.len(){returnErr(SupervisorTypedTransitionErrorV1::terminal());}Ok(prepared)"
            }
            "prepare_supervisor_typed_receive_v1" => {
                "ifprepared.expectation.ordered_roles.as_slice()!=expected_roles{returnErr(SupervisorTypedTransitionErrorV1::terminal());}Ok(prepared)"
            }
            _ => unreachable!("fixed shared preparation inventory"),
        }
    }

    fn assert_exact_pre_session_consumers_and_helpers_v1(source: &str, gate: &str) {
        for name in [
            "prepare_session_offer_send_v1",
            "receive_generator_nonce_commit_once_v1",
            "prepare_supervisor_commit_send_v1",
            "receive_generator_nonce_reveal_once_v1",
            "prepare_supervisor_reveal_send_v1",
        ] {
            let function = find_function_v1(source, name, gate);
            assert_eq!(
                normalized_affine_body_v1(function, gate),
                expected_pre_session_consumer_body_v1(name),
                "{gate}: `{name}` must remain the exact affine pre-session consumer"
            );
        }
        for (name, signature) in [
            (
                "prepare_supervisor_typed_send_v1",
                "fn prepare_supervisor_typed_send_v1(prepared: PreparedSupervisorSendV1, expected_roles: &[ContractFdRoleV1]) -> Result<PreparedSupervisorSendV1, SupervisorTypedTransitionErrorV1>",
            ),
            (
                "prepare_supervisor_typed_receive_v1",
                "fn prepare_supervisor_typed_receive_v1(prepared: PreparedSupervisorReceiveV1, expected_roles: &[ContractFdRoleV1]) -> Result<PreparedSupervisorReceiveV1, SupervisorTypedTransitionErrorV1>",
            ),
        ] {
            let function = find_function_v1(source, name, gate);
            assert_exact_function_signature_v1(function, signature, gate);
            let matching = function_signatures_v1(source)
                .into_iter()
                .filter(|candidate| function_name_from_signature_v1(candidate) == name)
                .collect::<Vec<_>>();
            assert_eq!(
                matching.len(),
                1,
                "{gate}: `{name}` must have one exact private signature"
            );
            assert_eq!(
                matching[0].replace(",)->", ")->"),
                normalized_code_v1(signature).replace(",)->", ")->"),
                "{gate}: `{name}` must remain exactly private and unqualified"
            );
            assert_eq!(
                normalized_affine_body_v1(function, gate),
                expected_shared_preparation_body_v1(name),
                "{gate}: `{name}` must remain the exact terminal shared preparation"
            );
        }
    }

    fn assert_exact_pre_session_consumer_fixtures_v1() {
        for name in [
            "prepare_session_offer_send_v1",
            "receive_generator_nonce_commit_once_v1",
            "prepare_supervisor_commit_send_v1",
            "receive_generator_nonce_reveal_once_v1",
            "prepare_supervisor_reveal_send_v1",
        ] {
            let expected = expected_pre_session_consumer_body_v1(name);
            let valid = format!("fn {name}() {{ {expected} }}");
            assert_eq!(
                normalized_affine_body_v1(&valid, "pre-session body positive fixture"),
                expected
            );
            for injected in [
                "return Err(SupervisorTypedTransitionErrorV1::terminal());",
                "None::<()>.unwrap();",
                "loop {}",
            ] {
                let mutant = format!("fn {name}() {{ {injected} {expected} }}");
                assert_ne!(
                    normalized_affine_body_v1(&mutant, "pre-session body negative fixture"),
                    expected,
                    "early terminal or divergence must be rejected for `{name}`"
                );
            }
        }
        for name in [
            "prepare_supervisor_typed_send_v1",
            "prepare_supervisor_typed_receive_v1",
        ] {
            let expected = expected_shared_preparation_body_v1(name);
            let valid = format!("fn {name}() {{ {expected} }}");
            assert_eq!(
                normalized_affine_body_v1(&valid, "shared preparation positive fixture"),
                expected
            );
            let guard_mutant = if name == "prepare_supervisor_typed_send_v1" {
                expected.replace(
                    "prepared.descriptors.len()!=expected_roles.len()",
                    "prepared.descriptors.len()==expected_roles.len()",
                )
            } else {
                expected.replace(
                    "prepared.expectation.ordered_roles.as_slice()!=expected_roles",
                    "prepared.expectation.ordered_roles.len()!=expected_roles.len()",
                )
            };
            for mutant_body in [
                format!("return Err(SupervisorTypedTransitionErrorV1::terminal());{expected}"),
                format!("return Ok(prepared);{expected}"),
                format!("loop{{}}{expected}"),
                guard_mutant,
            ] {
                let mutant = format!("fn {name}() {{ {mutant_body} }}");
                assert_ne!(
                    normalized_affine_body_v1(&mutant, "shared preparation negative fixture"),
                    expected,
                    "a terminal, divergent, or relaxed helper must be rejected for `{name}`"
                );
            }
        }
    }

    fn expected_candidate_producer_body_v1(spec: CandidateProducerSpecV1) -> String {
        let receive_guard = "ifinput.prepared.frame.as_ref()!=raw.as_slice()||input.prepared.expectation.ordered_roles.len()!=input.frame.fd_commitments().len(){returnErr(SupervisorTypedTransitionErrorV1::terminal());}";
        let send_guard = "ifinput.prepared.frame.as_ref()!=raw.as_slice()||input.prepared.descriptors.len()!=input.frame.fd_commitments().len(){returnErr(SupervisorTypedTransitionErrorV1::terminal());}";
        match spec.function {
            "receive_generator_bound_once_v1" => format!(
                "letSupervisorGeneratorSentEndpointV1{{endpoint,phase}}=self;ifphaseasu8!=SupervisorGeneratorSendPhaseV1::AwaitGeneratorBoundasu8{{returnErr(SupervisorTypedTransitionErrorV1::terminal());}}letraw=input.frame.encode_raw_frame()?;{receive_guard}letendpoint=receive_exact_generator_once_v1(endpoint,input.prepared)?;letcandidate=G0GeneratorBoundTranscriptCandidateV1::prepare(&input.session,&input.frame)?;letreceived_endpoint=GeneratorBoundReceivedEndpointV1{{endpoint}};Ok((received_endpoint,candidate))"
            ),
            "prepare_worker_bootstrap_send_v1" => format!(
                "letraw=input.frame.encode_raw_frame()?;{send_guard}letcandidate=G0TranscriptCandidateV1::prepare(&input.session,0,previous_digest,&input.frame)?;letoperation=SupervisorWorkerBootstrapSendOpV1{{endpoint:self,prepared:input.prepared}};Ok((operation,candidate))"
            ),
            "receive_worker_exec_bound_once_v1" => format!(
                "letWorkerBootstrapEnqueuedEndpointV1{{endpoint}}=self;letraw=input.frame.encode_raw_frame()?;{receive_guard}letendpoint=receive_exact_worker_once_v1(endpoint,input.prepared)?;letcandidate=G0TranscriptCandidateV1::prepare(&input.session,1,previous_digest,&input.frame)?;letreceived_endpoint=WorkerExecBoundReceivedEndpointV1{{endpoint}};Ok((received_endpoint,candidate))"
            ),
            "prepare_closed_result_send_v1" => format!(
                "letraw=input.frame.encode_raw_frame()?;{send_guard}letcandidate=G0TranscriptCandidateV1::prepare(&input.session,1,previous_digest,&input.frame)?;letGeneratorBoundReceivedEndpointV1{{endpoint}}=endpoint;letoperation=SupervisorGeneratorSendOpV1{{endpoint:SupervisorGeneratorEndpointV1(endpoint),prepared:input.prepared,phase:SupervisorGeneratorSendPhaseV1::ClosedResult}};Ok((operation,candidate))"
            ),
            _ => unreachable!("fixed candidate producer inventory"),
        }
    }

    fn assert_exact_candidate_producer_body_v1(
        body: &str,
        spec: CandidateProducerSpecV1,
        gate: &str,
    ) {
        assert_eq!(
            normalized_affine_body_v1(body, gate),
            expected_candidate_producer_body_v1(spec),
            "{gate}: `{}` must remain the exact straight-line affine producer",
            spec.function,
        );
    }

    fn assert_exact_candidate_receive_helpers_v1(source: &str, gate: &str) {
        for (name, receive) in [
            (
                "receive_exact_generator_once_v1",
                "receive_generator_frame_v1",
            ),
            ("receive_exact_worker_once_v1", "receive_worker_frame_v1"),
        ] {
            let helper = find_function_v1(source, name, gate);
            let compact = normalized_code_v1(helper).replace(",)->", ")->");
            let opening = compact.find('{').expect("exact receive helper has a body");
            assert_eq!(
                &compact[..opening],
                format!(
                    "fn{name}(endpoint:SeqpacketEndpointV1,prepared:PreparedSupervisorReceiveV1)->Result<SeqpacketEndpointV1,SupervisorTypedTransitionErrorV1>"
                ),
                "{gate}: `{name}` signature must consume endpoint custody and prepared transport"
            );
            let expected = format!(
                "letPreparedSupervisorReceiveV1{{frame,expectation}}=prepared;ifframe.len()!=expectation.frame_length{{returnErr(SupervisorTypedTransitionErrorV1::terminal());}}letmutbuffer=[0_u8;CONTRACT_MAX_FRAME_BYTES_V1];letreceived={receive}(endpoint.descriptor.as_fd(),&mutbuffer,&expectation)?;if!received.descriptors.is_empty()||received.received_length!=frame.len()||buffer[..received.received_length]!=frame[..]{{returnErr(SupervisorTypedTransitionErrorV1::terminal());}}Ok(endpoint)"
            );
            assert_eq!(
                normalized_function_body_v1(helper, gate),
                expected,
                "{gate}: `{name}` must preserve exact endpoint custody after one validated receive"
            );
        }
    }

    fn assert_transcript_candidate_producers_v1(source: &str, whole_ancillary: &str, gate: &str) {
        let compact = normalized_code_v1(source);
        assert_uninhabited_semantic_join_inventory_v1(source, whole_ancillary, gate);
        assert_eq!(
            compact.matches("require_semantic_frame_matches_v1").count(),
            0,
            "{gate}: detached raw/count semantic comparison helper is forbidden"
        );
        assert_eq!(
            compact
                .matches("G0GeneratorBoundTranscriptCandidateV1::prepare(")
                .count(),
            1,
            "{gate}: generator-bound candidate must have one producer"
        );
        assert_eq!(
            compact.matches("G0TranscriptCandidateV1::prepare(").count(),
            3,
            "{gate}: ordinary transcript candidates must have exactly three producers"
        );
        for spec in candidate_producer_specs_v1() {
            let declaration = find_braced_declaration_v1(source, "struct", spec.input, gate);
            require_once_v1(
                declaration,
                "ProviderSessionMaterialV1",
                "candidate producer retained provider session",
            );
            require_once_v1(
                declaration,
                "WireFrameV1",
                "candidate producer retained semantic frame",
            );
            for forbidden in [
                "G0GeneratorBoundTranscriptCandidateV1",
                "G0TranscriptCandidateV1",
                "digest",
                "Digest",
                "previous_digest",
                "previous_hash",
                "worker_genesis",
                "Genesis",
                "[u8;32]",
            ] {
                assert!(
                    !normalized_code_v1(declaration).contains(forbidden),
                    "{gate}: `{}` accepts caller-prepared `{forbidden}`",
                    spec.input,
                );
            }
            let body = find_function_v1(source, spec.function, gate);
            let body_compact = normalized_code_v1(body).replace(",)", ")");
            let signature_end = body_compact
                .find('{')
                .expect("candidate producer body exists");
            let canonical_signature = body_compact[..signature_end]
                .replace(",)", ")")
                .replace(",>", ">");
            let signature = canonical_signature.as_str();
            require_once_v1(signature, spec.input, "candidate producer opaque input");
            require_once_v1(
                signature,
                spec.output,
                "candidate producer transport output",
            );
            require_once_v1(
                signature,
                spec.candidate,
                "candidate producer candidate output",
            );
            for forbidden in [
                "ProviderSessionMaterialV1",
                "WireFrameV1",
                "PeerCredentialsV1",
                "FdCommitmentV1",
                "PreparedSupervisorSendV1",
                "PreparedSupervisorReceiveV1",
                "UCred",
                "OwnedFd",
                "BorrowedFd",
                "RawFd",
            ] {
                assert!(
                    !signature.contains(forbidden),
                    "{gate}: `{}` gained detached signature input `{forbidden}`",
                    spec.function,
                );
            }
            let parameters = match spec.function {
                "receive_generator_bound_once_v1" => {
                    "self,input:GeneratorBoundReceiveInputV1".to_owned()
                }
                "prepare_worker_bootstrap_send_v1" => {
                    "self,input:WorkerBootstrapSendInputV1,previous_digest:[u8;32]".to_owned()
                }
                "receive_worker_exec_bound_once_v1" => {
                    "self,input:WorkerExecBoundReceiveInputV1,previous_digest:[u8;32]"
                        .to_owned()
                }
                "prepare_closed_result_send_v1" => {
                    "endpoint:GeneratorBoundReceivedEndpointV1,input:ClosedResultSendInputV1,previous_digest:[u8;32]".to_owned()
                }
                _ => unreachable!("fixed candidate producer inventory"),
            };
            assert_eq!(
                signature,
                format!(
                    "fn{}({parameters})->Result<({},{}),SupervisorTypedTransitionErrorV1>",
                    spec.function, spec.output, spec.candidate,
                ),
                "{gate}: `{}` signature must expose only its exact affine carrier inputs and typed result",
                spec.function,
            );
            let prepare = if let Some(ordinal) = spec.ordinal {
                require_once_v1(
                    signature,
                    "previous_digest:[u8;32]",
                    "candidate producer private previous digest",
                );
                format!(
                    "{}::prepare(&input.session,{ordinal},previous_digest,&input.frame)",
                    spec.candidate
                )
            } else {
                assert!(
                    !signature.contains("previous_digest") && !signature.contains("[u8;32]"),
                    "{gate}: first generator candidate accepts a previous digest"
                );
                format!("{}::prepare(&input.session,&input.frame)", spec.candidate)
            };
            assert_eq!(
                exact_call_arguments_v1(&body_compact, "input.frame.encode_raw_frame(", gate),
                "",
                "{gate}: `{}` must encode the frame retained by the single opaque carrier",
                spec.function,
            );
            assert_propagates_without_swallow_v1(body, "input.frame.encode_raw_frame(", gate);
            let raw_binding = "letraw=input.frame.encode_raw_frame()?;";
            assert_eq!(
                body_compact.matches(raw_binding).count(),
                1,
                "{gate}: `{}` must bind exactly one raw frame from the retained semantic frame",
                spec.function,
            );
            assert_eq!(
                normalized_match_depth_v1(body, raw_binding, gate),
                1,
                "{gate}: `{}` raw binding must be a direct function-body statement",
                spec.function,
            );
            let consistency = if spec.function.starts_with("receive_") {
                "ifinput.prepared.frame.as_ref()!=raw.as_slice()||input.prepared.expectation.ordered_roles.len()!=input.frame.fd_commitments().len(){returnErr(SupervisorTypedTransitionErrorV1::terminal());}"
            } else {
                "ifinput.prepared.frame.as_ref()!=raw.as_slice()||input.prepared.descriptors.len()!=input.frame.fd_commitments().len(){returnErr(SupervisorTypedTransitionErrorV1::terminal());}"
            };
            assert_eq!(
                body_compact.matches(consistency).count(),
                1,
                "{gate}: `{}` must keep the uninhabited carrier's transport and semantic frame internally consistent",
                spec.function,
            );
            assert_eq!(
                normalized_match_depth_v1(body, consistency, gate),
                1,
                "{gate}: `{}` carrier guard must execute directly in the function body",
                spec.function,
            );
            for forbidden in [
                "prepare_supervisor_typed_send_v1(",
                "prepare_supervisor_typed_receive_v1(",
                "letprepared=",
                "PreparedSupervisorSendV1{",
                "PreparedSupervisorReceiveV1{",
                "unsafe",
                "assume_init",
                "transmute",
                "zeroed",
            ] {
                assert_eq!(
                    body_compact.matches(forbidden).count(),
                    0,
                    "{gate}: `{}` must consume its carrier instead of using `{forbidden}`",
                    spec.function,
                );
            }
            require_once_v1(
                &body_compact,
                &prepare,
                "exact internal transcript candidate producer",
            );
            let prepare_call = format!("{}::prepare(", spec.candidate);
            assert_propagates_without_swallow_v1(body, &prepare_call, gate);
            assert_eq!(
                exact_call_arguments_v1(&body_compact, &prepare_call, gate),
                prepare
                    .strip_prefix(&prepare_call)
                    .and_then(|suffix| suffix.strip_suffix(')'))
                    .expect("exact prepared candidate call shape"),
                "{gate}: `{}` candidate arguments drifted",
                spec.function,
            );
            let raw_at = body_compact
                .find(raw_binding)
                .expect("retained semantic frame encoding exists");
            let consistency_at = body_compact
                .find(consistency)
                .expect("carrier consistency guard exists");
            let candidate_at = body_compact
                .find(&prepare_call)
                .expect("candidate preparation exists");
            assert_eq!(
                normalized_match_depth_v1(body, &prepare_call, gate),
                1,
                "{gate}: `{}` candidate preparation must execute directly in the function body",
                spec.function,
            );
            if spec.function.starts_with("receive_generator") {
                let kernel_call = "receive_exact_generator_once_v1(";
                let kernel_at = body_compact
                    .find(kernel_call)
                    .expect("generator candidate receive exists");
                let kernel_arguments = exact_call_arguments_v1(&body_compact, kernel_call, gate);
                assert_eq!(
                    kernel_arguments.matches("input.prepared").count(),
                    1,
                    "{gate}: generator receive must move the carrier's prepared transport exactly once"
                );
                assert!(
                    !kernel_arguments.contains("&input.prepared")
                        && !kernel_arguments.contains("&mutinput.prepared"),
                    "{gate}: generator receive may not borrow its prepared transport for retry"
                );
                assert_eq!(
                    normalized_match_depth_v1(body, kernel_call, gate),
                    1,
                    "{gate}: generator kernel receive must be a direct function-body call"
                );
                assert!(
                    raw_at < consistency_at
                        && consistency_at < kernel_at
                        && kernel_at < candidate_at,
                    "{gate}: generator candidate must follow carrier consistency and exact receive"
                );
                assert_candidate_producer_straight_line_v1(
                    body,
                    2,
                    &[
                        "input.frame.encode_raw_frame(",
                        kernel_call,
                        prepare_call.as_str(),
                    ],
                    gate,
                );
            } else if spec.function.starts_with("receive_worker") {
                let kernel_call = "receive_exact_worker_once_v1(";
                let kernel_at = body_compact
                    .find(kernel_call)
                    .expect("worker candidate receive exists");
                let kernel_arguments = exact_call_arguments_v1(&body_compact, kernel_call, gate);
                assert_eq!(
                    kernel_arguments.matches("input.prepared").count(),
                    1,
                    "{gate}: worker receive must move the carrier's prepared transport exactly once"
                );
                assert!(
                    !kernel_arguments.contains("&input.prepared")
                        && !kernel_arguments.contains("&mutinput.prepared"),
                    "{gate}: worker receive may not borrow its prepared transport for retry"
                );
                assert_eq!(
                    normalized_match_depth_v1(body, kernel_call, gate),
                    1,
                    "{gate}: worker kernel receive must be a direct function-body call"
                );
                assert!(
                    raw_at < consistency_at
                        && consistency_at < kernel_at
                        && kernel_at < candidate_at,
                    "{gate}: worker candidate must follow carrier consistency and exact receive"
                );
                assert_candidate_producer_straight_line_v1(
                    body,
                    1,
                    &[
                        "input.frame.encode_raw_frame(",
                        kernel_call,
                        prepare_call.as_str(),
                    ],
                    gate,
                );
            } else {
                let operation_binding = format!("letoperation={}{{", spec.output);
                let operation_at = body_compact
                    .find(&operation_binding)
                    .expect("carrier-consuming operation binding exists");
                assert_eq!(
                    body_compact.matches(&operation_binding).count(),
                    1,
                    "{gate}: `{}` must construct exactly one returned operation",
                    spec.function,
                );
                assert_eq!(
                    normalized_match_depth_v1(body, &operation_binding, gate),
                    1,
                    "{gate}: `{}` returned operation must be a direct function-body binding",
                    spec.function,
                );
                let operation_opening = operation_at + operation_binding.len() - 1;
                let operation_closing = closing_delimiter_v1(
                    body_compact.as_bytes(),
                    operation_opening,
                    b'{',
                    b'}',
                    gate,
                );
                let operation = &body_compact[operation_opening + 1..operation_closing];
                assert_eq!(
                    operation.matches("prepared:input.prepared").count(),
                    1,
                    "{gate}: `{}` must move the carrier's exact prepared transport into its returned operation",
                    spec.function,
                );
                assert!(
                    raw_at < consistency_at && consistency_at < candidate_at,
                    "{gate}: outbound candidate must follow direct carrier consistency"
                );
                assert!(
                    candidate_at < operation_at,
                    "{gate}: outbound operation must consume the carrier only after candidate preparation"
                );
                assert_candidate_producer_straight_line_v1(
                    body,
                    1,
                    &["input.frame.encode_raw_frame(", prepare_call.as_str()],
                    gate,
                );
            }
            assert!(
                body_compact.ends_with(&format!("Ok(({},candidate))}}", spec.output_binding)),
                "{gate}: `{}` must return the exact transport and internally prepared candidate",
                spec.function,
            );
            assert_eq!(
                token_count_v1(body, "candidate"),
                2,
                "{gate}: `{}` may bind and return its candidate exactly once",
                spec.function,
            );
            for forbidden in [
                "candidate.clone(",
                "candidate.to_owned(",
                "candidate.digest(",
                "[49..81]",
                ".get(49..81)",
                "input._seal",
            ] {
                assert!(
                    !body_compact.contains(forbidden),
                    "{gate}: `{}` detached candidate via `{forbidden}`",
                    spec.function,
                );
            }
            assert_exact_candidate_producer_body_v1(body, spec, gate);
        }
        for (name, _, _, _) in typed_input_specs_v1() {
            if candidate_producer_specs_v1()
                .iter()
                .any(|spec| spec.input == name)
            {
                continue;
            }
            let declaration = find_braced_declaration_v1(source, "struct", name, gate);
            for forbidden in ["ProviderSessionMaterialV1", "WireFrameV1"] {
                assert!(
                    !normalized_code_v1(declaration).contains(forbidden),
                    "{gate}: non-candidate input `{name}` gained `{forbidden}`"
                );
            }
        }
    }

    fn assert_crate_private_typed_input_inventory_v1(
        source: &str,
        inputs: &[(&str, &str, &str, &str)],
        gate: &str,
    ) {
        assert_no_hidden_source_shapes_v1(gate, source);
        let normalized = normalized_code_v1(source);
        let prepared_receive =
            find_braced_declaration_v1(source, "struct", "PreparedSupervisorReceiveV1", gate);
        assert!(
            normalized_code_v1(prepared_receive).starts_with("structPreparedSupervisorReceiveV1"),
            "{gate}: the raw receive preparation must remain ancillary-private"
        );
        require_code_v1(
            prepared_receive,
            "StrictReceiveExpectationV1",
            "typed receive preparation expectation",
        );
        require_code_v1(
            prepared_receive,
            "Box<[u8]>",
            "typed receive preparation exact frame",
        );
        for &(name, carrier, function, output) in inputs {
            let declaration = find_braced_declaration_v1(source, "struct", name, gate);
            let normalized_declaration = normalized_code_v1(declaration);
            assert!(
                !rust_code_mask_v1(declaration).contains('!'),
                "{gate}: `{name}` fields may not be macro-generated"
            );
            assert!(
                normalized_declaration.starts_with(&format!("struct{name}"))
                    || normalized_declaration.starts_with(&format!("pub(crate)struct{name}")),
                "{gate}: `{name}` must be a direct struct declaration"
            );
            assert!(
                normalized.contains(&format!("pub(crate)struct{name}")),
                "{gate}: `{name}` must be visible only inside linux-abi"
            );
            assert!(
                !normalized.contains(&format!("pubstruct{name}")),
                "{gate}: `{name}` escaped publicly"
            );
            assert!(
                !normalized.contains(&format!("pubuse{name}")),
                "{gate}: `{name}` was publicly re-exported"
            );
            assert!(
                rust_code_mask_v1(declaration).contains(':'),
                "{gate}: `{name}` may not be an empty marker"
            );
            require_once_v1(
                declaration,
                carrier,
                "opaque typed supervisor input carrier",
            );
            let other_carrier = if carrier == "PreparedSupervisorSendV1" {
                "PreparedSupervisorReceiveV1"
            } else {
                "PreparedSupervisorSendV1"
            };
            assert!(
                !normalized_declaration.contains(other_carrier),
                "{gate}: `{name}` mixes send/receive prepared carriers"
            );
            for forbidden in [
                "OwnedFd",
                "RawFd",
                "BorrowedFd",
                "UCred",
                "Vec<u8>",
                "&[u8]",
                "i32",
                "u32",
            ] {
                assert!(
                    !normalized_declaration.contains(forbidden),
                    "{gate}: `{name}` exposes raw carrier `{forbidden}`"
                );
            }
            for conversion in [
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
                "Clone",
                "Copy",
            ] {
                assert!(
                    !normalized.contains(&format!("impl{conversion}for{name}")),
                    "{gate}: `{name}` gained `{conversion}`"
                );
            }
            for header in impl_headers_v1(source)
                .into_iter()
                .filter(|header| header.contains(name))
            {
                panic!("{gate}: typed input `{name}` gained an implementation surface `{header}`");
            }
            let matching = function_signatures_v1(source)
                .into_iter()
                .filter(|signature| signature.contains(name))
                .collect::<Vec<_>>();
            assert_eq!(
                matching.len(),
                1,
                "{gate}: `{name}` must occur in exactly one typed consumer signature"
            );
            for signature in &matching {
                assert_eq!(
                    signature_visibility_v1(&signature),
                    "pub(crate)",
                    "{gate}: `{name}` signatures must be exactly pub(crate): `{signature}`"
                );
                let function_name = function_name_from_signature_v1(&signature);
                assert_eq!(function_name, function, "{gate}: `{name}` consumer drifted");
                require_once_v1(
                    signature,
                    &format!("input:{name}"),
                    "consuming opaque typed supervisor input",
                );
                assert!(
                    !signature.contains(&format!("&{name}"))
                        && !signature.contains(&format!("&mut{name}")),
                    "{gate}: `{name}` may not be borrowed for retry/reuse"
                );
                require_code_v1(signature, output, "typed supervisor input output");
                for raw in [
                    "UCred",
                    "OwnedFd",
                    "BorrowedFd",
                    "RawFd",
                    "&[u8]",
                    "Vec<u8>",
                ] {
                    assert!(
                        !signature.contains(raw),
                        "{gate}: `{name}` signature gained raw carrier `{raw}`: {signature}"
                    );
                }
                for extracted in [
                    "PreparedSupervisorSendV1",
                    "PreparedSupervisor",
                    "PreparedSend",
                    "PreparedFrame",
                ] {
                    assert!(
                        !signature.contains(extracted),
                        "{gate}: `{name}` extracts prepared transport `{extracted}`: `{signature}`"
                    );
                }
            }
            assert_inherent_method_allowlist_v1(source, name, &[], gate);
        }
    }

    fn assert_crate_private_received_endpoint_inventory_v1(source: &str, gate: &str) {
        let normalized = normalized_code_v1(source);
        for (name, functions) in [
            (
                "GeneratorCommitReceivedEndpointV1",
                &[
                    "receive_generator_nonce_commit_once_v1",
                    "prepare_supervisor_commit_send_v1",
                ][..],
            ),
            (
                "GeneratorRevealReceivedEndpointV1",
                &[
                    "receive_generator_nonce_reveal_once_v1",
                    "prepare_supervisor_reveal_send_v1",
                ][..],
            ),
            (
                "GeneratorBoundReceivedEndpointV1",
                &[
                    "receive_generator_bound_once_v1",
                    "prepare_closed_result_send_v1",
                ][..],
            ),
            (
                "WorkerExecBoundReceivedEndpointV1",
                &["receive_worker_exec_bound_once_v1"][..],
            ),
        ] {
            let declaration = find_braced_declaration_v1(source, "struct", name, gate);
            let declaration = normalized_code_v1(declaration);
            assert!(
                declaration.starts_with(&format!("struct{name}")),
                "{gate}: `{name}` must be a direct struct declaration"
            );
            assert!(
                normalized.contains(&format!("pub(crate)struct{name}")),
                "{gate}: `{name}` must be crate-private"
            );
            require_code_v1(
                &declaration,
                "SeqpacketEndpointV1",
                "typed received endpoint custody",
            );
            assert!(
                !normalized.contains(&format!("pubstruct{name}")),
                "{gate}: `{name}` escaped publicly"
            );
            assert!(
                !normalized.contains(&format!("pubuse{name}")),
                "{gate}: `{name}` was publicly re-exported"
            );
            assert_inherent_method_allowlist_v1(source, name, &[], gate);
            for header in impl_headers_v1(source)
                .into_iter()
                .filter(|header| header.contains(name))
            {
                panic!(
                    "{gate}: received endpoint `{name}` gained trait/wrapper surface `{header}`"
                );
            }
            let mut observed = function_signatures_v1(source)
                .into_iter()
                .filter(|signature| signature.contains(name))
                .map(|signature| {
                    assert_eq!(
                        signature_visibility_v1(&signature),
                        "pub(crate)",
                        "{gate}: `{name}` signature escaped: `{signature}`"
                    );
                    let function = function_name_from_signature_v1(&signature).to_owned();
                    if function.starts_with("prepare_") {
                        require_once_v1(
                            &signature,
                            &format!("endpoint:{name}"),
                            "consuming typed received endpoint",
                        );
                        assert!(
                            !signature.contains(&format!("&{name}"))
                                && !signature.contains(&format!("&mut{name}")),
                            "{gate}: `{name}` consumer may not borrow retry authority"
                        );
                    } else {
                        let return_at = signature
                            .find("->")
                            .expect("typed receive producer has a return type");
                        assert!(
                            signature[return_at..].contains(name),
                            "{gate}: `{function}` must produce `{name}`"
                        );
                    }
                    function
                })
                .collect::<Vec<_>>();
            observed.sort();
            let mut expected = functions
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>();
            expected.sort();
            assert_eq!(
                observed, expected,
                "{gate}: `{name}` producer/consumer inventory drifted"
            );
        }
    }

    fn assert_generator_phase_closure_v1(source: &str, gate: &str) {
        let error = normalized_code_v1(find_braced_declaration_v1(
            source,
            "struct",
            "SupervisorTypedTransitionErrorV1",
            gate,
        ));
        assert_eq!(
            error, "structSupervisorTypedTransitionErrorV1{_private:(),}",
            "{gate}: typed ancillary error must remain terminal and payload-free"
        );
        assert!(
            normalized_code_v1(source)
                .contains("pub(crate)structSupervisorTypedTransitionErrorV1{_private:(),}"),
            "{gate}: typed ancillary error must remain crate-private"
        );
        assert_inherent_method_allowlist_v1(
            source,
            "SupervisorTypedTransitionErrorV1",
            &[("private", "terminal")],
            gate,
        );
        let error_impl = inherent_impl_blocks_v1(source, "SupervisorTypedTransitionErrorV1");
        let terminal = normalized_code_v1(find_function_v1(error_impl[0], "terminal", gate));
        assert_eq!(
            terminal, "fnterminal()->Self{Self{_private:()}}",
            "{gate}: typed ancillary error constructor drifted"
        );
        let mut error_headers = impl_headers_v1(source)
            .into_iter()
            .filter(|header| header.contains("SupervisorTypedTransitionErrorV1"))
            .collect::<Vec<_>>();
        error_headers.sort();
        let mut expected_error_headers = vec![
            "implFrom<AncillaryReceiveErrorV1>forSupervisorTypedTransitionErrorV1".to_owned(),
            "implFrom<WireErrorV1>forSupervisorTypedTransitionErrorV1".to_owned(),
            "implSupervisorTypedTransitionErrorV1".to_owned(),
        ];
        expected_error_headers.sort();
        assert_eq!(
            error_headers, expected_error_headers,
            "{gate}: typed ancillary terminal-error conversion inventory drifted"
        );
        let compact_source = normalized_code_v1(source);
        for input in ["AncillaryReceiveErrorV1", "WireErrorV1"] {
            require_once_v1(
                &compact_source,
                &format!(
                    "implFrom<{input}>forSupervisorTypedTransitionErrorV1{{fnfrom(_:{input})->Self{{Self::terminal()}}}}"
                ),
                "typed ancillary terminal-error conversion",
            );
        }
        let phase = normalized_code_v1(find_braced_declaration_v1(
            source,
            "enum",
            "SupervisorGeneratorSendPhaseV1",
            gate,
        ));
        assert_eq!(
            phase,
            "enumSupervisorGeneratorSendPhaseV1{AwaitGeneratorCommit,AwaitGeneratorReveal,AwaitGeneratorBound,ClosedResult,}",
            "{gate}: generator phase inventory drifted"
        );
        let operation =
            find_braced_declaration_v1(source, "struct", "SupervisorGeneratorSendOpV1", gate);
        let sent =
            find_braced_declaration_v1(source, "struct", "SupervisorGeneratorSentEndpointV1", gate);
        for declaration in [operation, sent] {
            require_once_v1(
                declaration,
                "SupervisorGeneratorSendPhaseV1",
                "generator phase-bearing custody",
            );
        }
        let operation_impls = inherent_impl_blocks_v1(source, "SupervisorGeneratorSendOpV1");
        assert_eq!(
            operation_impls.len(),
            1,
            "{gate}: generic generator send op must retain one inherent impl"
        );
        let enqueue = find_function_v1(operation_impls[0], "enqueue_once_v1", gate);
        require_order_v1(
            enqueue,
            &[
                "send_seqpacket_once_v1(",
                "Ok(SupervisorGeneratorSentEndpointV1 {",
                "phase: self.phase",
            ],
            "generator enqueue must transfer its private phase only after kernel success",
        );
        for (builder, phase) in [
            ("prepare_session_offer_send_v1", "AwaitGeneratorCommit"),
            ("prepare_supervisor_commit_send_v1", "AwaitGeneratorReveal"),
            ("prepare_supervisor_reveal_send_v1", "AwaitGeneratorBound"),
            ("prepare_closed_result_send_v1", "ClosedResult"),
        ] {
            let body = find_function_v1(source, builder, gate);
            require_once_v1(
                body,
                &format!("SupervisorGeneratorSendPhaseV1::{phase}"),
                "typed generator builder phase",
            );
            let expected_shared_preparations =
                usize::from(builder != "prepare_closed_result_send_v1");
            assert_eq!(
                normalized_code_v1(body)
                    .matches("prepare_supervisor_typed_send_v1(")
                    .count(),
                expected_shared_preparations,
                "{gate}: `{builder}` shared-send preparation classification drifted"
            );
        }
        for (receiver, phase) in [
            (
                "receive_generator_nonce_commit_once_v1",
                "AwaitGeneratorCommit",
            ),
            (
                "receive_generator_nonce_reveal_once_v1",
                "AwaitGeneratorReveal",
            ),
            ("receive_generator_bound_once_v1", "AwaitGeneratorBound"),
        ] {
            let body = find_function_v1(source, receiver, gate);
            let phase_needle = format!("SupervisorGeneratorSendPhaseV1::{phase}");
            if receiver == "receive_generator_bound_once_v1" {
                require_order_v1(
                    body,
                    &[
                        "let SupervisorGeneratorSentEndpointV1 { endpoint, phase }",
                        &phase_needle,
                        "return Err(SupervisorTypedTransitionErrorV1::terminal());",
                        "receive_exact_generator_once_v1(",
                    ],
                    "typed generator-bound receive phase rejection",
                );
            } else {
                require_order_v1(
                    body,
                    &[
                        "let SupervisorGeneratorSentEndpointV1 { endpoint, phase }",
                        &phase_needle,
                        "return Err(SupervisorTypedTransitionErrorV1::terminal());",
                        "prepare_supervisor_typed_receive_v1(",
                        "receive_exact_generator_once_v1(",
                    ],
                    "typed generator receive phase rejection",
                );
            }
            let expected_shared_preparations =
                usize::from(receiver != "receive_generator_bound_once_v1");
            assert_eq!(
                normalized_code_v1(body)
                    .matches("prepare_supervisor_typed_receive_v1(")
                    .count(),
                expected_shared_preparations,
                "{gate}: `{receiver}` shared-receive preparation classification drifted"
            );
            require_once_v1(
                body,
                "receive_exact_generator_once_v1(",
                "typed generator receive kernel path",
            );
            if expected_shared_preparations == 1 {
                assert_propagates_without_swallow_v1(
                    body,
                    "prepare_supervisor_typed_receive_v1(",
                    "typed generator receive preparation failure",
                );
            }
            assert_propagates_without_swallow_v1(
                body,
                "receive_exact_generator_once_v1(",
                "typed generator receive failure",
            );
        }
        assert_inherent_method_allowlist_v1(
            source,
            "SupervisorGeneratorSentEndpointV1",
            &[
                ("pub(crate)", "receive_generator_nonce_commit_once_v1"),
                ("pub(crate)", "receive_generator_nonce_reveal_once_v1"),
                ("pub(crate)", "receive_generator_bound_once_v1"),
            ],
            gate,
        );
        let worker = find_function_v1(source, "receive_worker_exec_bound_once_v1", gate);
        assert_eq!(
            normalized_code_v1(worker)
                .matches("prepare_supervisor_typed_receive_v1(")
                .count(),
            0,
            "{gate}: WorkerExecBound must consume its prepared carrier directly"
        );
        require_once_v1(
            worker,
            "receive_exact_worker_once_v1(",
            "typed worker receive kernel path",
        );
        assert_propagates_without_swallow_v1(
            worker,
            "receive_exact_worker_once_v1(",
            "typed worker receive failure",
        );
        assert_inherent_method_allowlist_v1(
            source,
            "WorkerBootstrapEnqueuedEndpointV1",
            &[
                ("pub(crate)", "receive_worker_exec_bound_once_v1"),
                ("pub(crate)", "receive_worker_frame_v1"),
            ],
            gate,
        );
    }

    fn assert_opaque_inventory_fixtures_v1() {
        let public_leak = std::panic::catch_unwind(|| {
            assert_private_opaque_inventory_v1(
                "struct AcceptedGeneratorFrameV1 { state: u8 } pub fn leak(value: AcceptedGeneratorFrameV1) {}",
                &["AcceptedGeneratorFrameV1"],
                "public leak fixture",
            )
        });
        assert!(
            public_leak.is_err(),
            "plain pub opaque leak must be rejected"
        );

        let extractor = std::panic::catch_unwind(|| {
            assert_crate_private_typed_input_inventory_v1(
                "struct PreparedSupervisorReceiveV1 { frame: Box<[u8]>, expectation: StrictReceiveExpectationV1 } pub(crate) struct SessionOfferSendInputV1 { prepared: PreparedSupervisorSendV1 } impl SessionOfferSendInputV1 { pub(crate) fn into_prepared(self) -> PreparedSupervisorSendV1 { self.prepared } } pub(crate) fn prepare_session_offer_send_v1(input: SessionOfferSendInputV1) -> SupervisorGeneratorSendOpV1 { value }",
                &[(
                    "SessionOfferSendInputV1",
                    "PreparedSupervisorSendV1",
                    "prepare_session_offer_send_v1",
                    "SupervisorGeneratorSendOpV1",
                )],
                "prepared extractor fixture",
            )
        });
        assert!(extractor.is_err(), "Prepared* extractor must be rejected");
    }

    fn assert_no_module_level_macro_v1(source: &str, module_depth: usize, gate: &str) {
        let mask = rust_code_mask_v1(source);
        let bytes = mask.as_bytes();
        let mut depth = 0_usize;
        let mut cursor = 0_usize;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'{' => depth += 1,
                b'}' => depth = depth.saturating_sub(1),
                b'!' if depth == module_depth => {
                    panic!("{gate}: macro invocation may not generate or hide a module-level item")
                }
                _ => {}
            }
            cursor += 1;
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct MacroInvocationV1 {
        path: String,
        context: String,
    }

    fn function_ranges_v1(source: &str) -> Vec<(usize, usize, String)> {
        let mask = rust_code_mask_v1(source);
        let bytes = mask.as_bytes();
        let mut ranges = Vec::new();
        let mut cursor = 0_usize;
        while let Some(relative) = mask[cursor..].find("fn") {
            let start = cursor + relative;
            cursor = start + 2;
            if !token_boundary_v1(bytes, start, 2) {
                continue;
            }
            let name_start = skip_ws_v1(bytes, cursor);
            if !bytes
                .get(name_start)
                .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
            {
                continue;
            }
            let mut name_end = name_start + 1;
            while bytes
                .get(name_end)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                name_end += 1;
            }
            let mut opening = name_end;
            let mut parentheses = 0_usize;
            let mut brackets = 0_usize;
            while opening < bytes.len() {
                match bytes[opening] {
                    b'(' => parentheses += 1,
                    b')' => parentheses = parentheses.saturating_sub(1),
                    b'[' => brackets += 1,
                    b']' => brackets = brackets.saturating_sub(1),
                    b'{' if parentheses == 0 && brackets == 0 => break,
                    b';' if parentheses == 0 && brackets == 0 => break,
                    _ => {}
                }
                opening += 1;
            }
            assert!(
                opening < bytes.len(),
                "macro inventory function must terminate"
            );
            if bytes[opening] == b'{' {
                let closing = closing_brace_v1(bytes, opening, "macro inventory function") + 1;
                ranges.push((start, closing, mask[name_start..name_end].to_owned()));
                cursor = closing;
            }
        }
        ranges
    }

    fn assert_function_bodies_have_no_nested_items_v1(
        source: &str,
        allowed_local_const_function: Option<&str>,
        gate: &str,
    ) {
        for (start, end, name) in function_ranges_v1(source) {
            let function = &source[start..end];
            let mask = rust_code_mask_v1(function);
            let opening = mask
                .find('{')
                .expect("braced function inventory retains its body");
            let body = &function[opening + 1..function.len() - 1];
            for forbidden in [
                "fn", "struct", "enum", "impl", "trait", "type", "mod", "use", "static", "extern",
                "union",
            ] {
                assert_eq!(
                    token_count_v1(body, forbidden),
                    0,
                    "{gate}: function `{name}` contains nested `{forbidden}` item"
                );
            }
            let local_const_count = token_count_v1(body, "const");
            if Some(name.as_str()) == allowed_local_const_function {
                assert_eq!(
                    local_const_count, 1,
                    "{gate}: `{name}` must retain only its one historical local constant"
                );
                assert_eq!(
                    normalized_code_v1(body)
                        .matches("constSTATX_MNT_ID_UNIQUE_V1:u32=0x4000;")
                        .count(),
                    1,
                    "{gate}: `{name}` local constant drifted"
                );
            } else {
                assert_eq!(
                    local_const_count, 0,
                    "{gate}: function `{name}` contains a nested const item"
                );
            }
        }
    }

    fn attribute_inventory_v1(source: &str) -> Vec<String> {
        let mask = rust_code_mask_v1(source);
        let bytes = mask.as_bytes();
        let mut attributes = Vec::new();
        let mut cursor = 0_usize;
        while cursor < bytes.len() {
            if bytes[cursor] != b'#' {
                cursor += 1;
                continue;
            }
            let start = cursor;
            let mut opening = skip_ws_v1(bytes, cursor + 1);
            if bytes.get(opening) == Some(&b'!') {
                opening = skip_ws_v1(bytes, opening + 1);
            }
            if bytes.get(opening) != Some(&b'[') {
                cursor += 1;
                continue;
            }
            let closing = closing_delimiter_v1(bytes, opening, b'[', b']', "attribute inventory");
            attributes.push(source[start..=closing].split_whitespace().collect());
            cursor = closing + 1;
        }
        attributes.sort();
        attributes
    }

    fn assert_selected_target_source_shape_fixtures_v1() {
        assert_candidate_producer_straight_line_fixtures_v1();
        assert_ancillary_contract_wire_import_blocks_fixtures_v1();
        assert!(attribute_inventory_v1("fn route() {}").is_empty());
        for invalid in [
            "#[cfg(any())] fn route() {}",
            "fn route() { #[cfg(any())] if true {} }",
            "#[cfg_attr(all(), cfg(any()))] fn route() {}",
        ] {
            assert!(
                !attribute_inventory_v1(invalid).is_empty(),
                "selected-target attribute fixture must be detected"
            );
        }
        let generic_fabrication = "pub(crate) fn fabricate<T>() -> T { unsafe { MaybeUninit::<T>::uninit().assume_init() } }";
        let rejected = std::panic::catch_unwind(|| {
            assert_no_generic_fabrication_v1(generic_fabrication, "generic fabrication fixture")
        });
        assert!(
            rejected.is_err(),
            "generic MaybeUninit fabrication must be rejected"
        );
        let direct = "fn route() { if input.prepared.frame.as_ref() != raw.as_slice() { return Err(error); } }";
        let nested = "fn route() { if false { if input.prepared.frame.as_ref() != raw.as_slice() { return Err(error); } } }";
        let guard = "ifinput.prepared.frame.as_ref()!=raw.as_slice(){returnErr(error);}";
        assert_eq!(
            normalized_match_depth_v1(direct, guard, "direct guard fixture"),
            1
        );
        assert_eq!(
            normalized_match_depth_v1(nested, guard, "nested guard fixture"),
            2,
            "a lexically present guard under a false branch must not look direct"
        );
    }

    fn assert_no_generic_fabrication_v1(source: &str, gate: &str) {
        let identifiers = identifiers_v1(source);
        for forbidden in [
            "assume_init",
            "assume_init_drop",
            "assume_init_mut",
            "assume_init_read",
            "assume_init_ref",
            "transmute",
            "transmute_copy",
            "zeroed",
            "unreachable_unchecked",
            "from_raw_parts",
            "from_raw_parts_mut",
            "read_unaligned",
            "read_volatile",
            "set_len",
        ] {
            assert!(
                !identifiers.iter().any(|identifier| identifier == forbidden),
                "{gate}: generic fabrication primitive `{forbidden}` is forbidden"
            );
        }
        let compact = normalized_code_v1(source);
        for forbidden in ["ptr::read(", "ptr::read_unaligned(", "ptr::read_volatile("] {
            assert!(
                !compact.contains(forbidden),
                "{gate}: generic fabrication route `{forbidden}` is forbidden"
            );
        }
    }

    fn assert_selected_target_source_shape_v1(source: &str, gate: &str) {
        assert_ancillary_contract_wire_import_blocks_v1(source, gate);
        let mut expected_attributes = vec![
            "#[allow(dead_code)]".to_owned(),
            "#[allow(dead_code)]".to_owned(),
            "#[derive(Debug)]".to_owned(),
            "#[derive(Debug)]".to_owned(),
            "#[derive(Debug,Eq,PartialEq)]".to_owned(),
            "#[derive(Debug,Eq,PartialEq)]".to_owned(),
            "#[derive(Eq,PartialEq)]".to_owned(),
            "#[link_name=\"recvmsg\"]".to_owned(),
            "#[must_use]".to_owned(),
            "#[must_use]".to_owned(),
            "#[must_use]".to_owned(),
            "#[must_use]".to_owned(),
            "#[must_use]".to_owned(),
            "#[must_use]".to_owned(),
            "#[must_use]".to_owned(),
            "#[must_use]".to_owned(),
            "#[must_use]".to_owned(),
            "#[must_use]".to_owned(),
            "#[must_use]".to_owned(),
        ];
        expected_attributes
            .extend((0..91).map(|_| "#[cfg(feature=\"h0-tmpfs-provider-v2-g0\")]".to_owned()));
        expected_attributes.sort();
        assert_eq!(
            attribute_inventory_v1(source),
            expected_attributes,
            "{gate}: selected-target attribute inventory drifted"
        );
        assert_eq!(
            token_count_v1(source, "mod"),
            1,
            "{gate}: selected target must contain only its root module"
        );
        assert!(
            normalized_code_v1(source).starts_with("modselected_target{"),
            "{gate}: selected-target slice must start at its root module"
        );
        assert_function_bodies_have_no_nested_items_v1(
            source,
            Some("descriptor_identity_v1"),
            gate,
        );
        assert_eq!(
            token_count_v1(source, "const"),
            18,
            "{gate}: selected-target const inventory drifted"
        );
        let compact = normalized_code_v1(source);
        for (needle, count) in [
            ("constfnterminal(", 4),
            ("constfnnew()->Self", 1),
            ("pub(crate)constfnchannel_identity(", 2),
            ("pub(crate)constfnrole(", 1),
            ("pub(crate)constfnreceived_length(", 1),
            ("constSTATX_MNT_ID_UNIQUE_V1:u32=0x4000;", 1),
            ("constWORKER_BOOTSTRAP_FINAL_FIRST_FD_V1:i32=4;", 1),
            ("constWORKER_BOOTSTRAP_TEMP_FIRST_FD_V1:i32=22;", 1),
            ("constWORKER_BOOTSTRAP_RLIMIT_NOFILE_MIN_V1:u64=38;", 1),
            ("constfnworker_bootstrap_rlimit_nofile_accepts_v1(", 1),
            ("constfnworker_bootstrap_seal_presence_v1(", 1),
        ] {
            assert_eq!(
                compact.matches(needle).count(),
                count,
                "{gate}: exact const surface `{needle}` drifted"
            );
        }
        assert_eq!(
            token_count_v1(source, "static"),
            1,
            "{gate}: selected-target static inventory drifted"
        );
        require_once_v1(
            source,
            "static INHERITED_ENDPOINT_ADOPTION_ATTEMPTED_V1: AtomicBool = AtomicBool::new(false);",
            gate,
        );
        assert_no_generic_fabrication_v1(source, gate);
        assert_eq!(
            token_count_v1(source, "unsafe"),
            3,
            "{gate}: selected-target unsafe inventory drifted"
        );
        assert_eq!(
            compact
                .matches("unsafe{c_recvmsg(socket.as_raw_fd(),&mutmessage,MSG_CMSG_CLOEXEC_V1)}")
                .count(),
            1,
            "{gate}: the sole c_recvmsg unsafe block drifted"
        );
        assert_eq!(
            compact
                .matches("unsafe{OwnedFd::from_raw_fd(raw_descriptor)}")
                .count(),
            1,
            "{gate}: the sole received-FD ownership unsafe block drifted"
        );
        assert_eq!(
            compact.matches("unsafeextern").count(),
            1,
            "{gate}: the sole foreign declaration unsafe marker drifted"
        );
    }

    fn macro_invocations_v1(source: &str) -> Vec<MacroInvocationV1> {
        let mask = rust_code_mask_v1(source);
        let bytes = mask.as_bytes();
        let function_ranges = function_ranges_v1(source);
        let mut invocations = Vec::new();
        let mut cursor = 0_usize;
        while cursor < bytes.len() {
            if bytes[cursor] != b'!' {
                cursor += 1;
                continue;
            }
            if bytes.get(cursor + 1) == Some(&b'=') {
                cursor += 2;
                continue;
            }
            let delimiter = skip_ws_v1(bytes, cursor + 1);
            if !bytes
                .get(delimiter)
                .is_some_and(|byte| matches!(*byte, b'(' | b'[' | b'{'))
            {
                cursor += 1;
                continue;
            }
            let mut path_end = cursor;
            while path_end > 0 && bytes[path_end - 1].is_ascii_whitespace() {
                path_end -= 1;
            }
            let mut path_start = path_end;
            while path_start > 0
                && (bytes[path_start - 1].is_ascii_alphanumeric()
                    || matches!(bytes[path_start - 1], b'_' | b':' | b'#'))
            {
                path_start -= 1;
            }
            let path = &mask[path_start..path_end];
            if path.is_empty()
                || path_start == path_end
                || bytes.get(path_start.wrapping_sub(1)) == Some(&b'#')
                || matches!(path, "if" | "while" | "match" | "return" | "let" | "else")
                || !valid_simple_path_v1(path)
            {
                cursor += 1;
                continue;
            }
            let context = function_ranges
                .iter()
                .filter(|(start, end, _)| *start <= path_start && cursor < *end)
                .max_by_key(|(start, _, _)| *start)
                .map_or("<module>", |(_, _, name)| name.as_str())
                .to_owned();
            invocations.push(MacroInvocationV1 {
                path: path.to_owned(),
                context,
            });
            cursor += 1;
        }
        invocations
            .sort_by(|left, right| (&left.path, &left.context).cmp(&(&right.path, &right.context)));
        invocations
    }

    fn valid_simple_path_v1(path: &str) -> bool {
        let path = path.strip_prefix("::").unwrap_or(path);
        !path.is_empty()
            && path.split("::").all(|segment| {
                let identifier = segment.strip_prefix("r#").unwrap_or(segment);
                !identifier.is_empty()
                    && identifier
                        .as_bytes()
                        .first()
                        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
                    && identifier
                        .as_bytes()
                        .iter()
                        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            })
    }

    fn macro_definition_names_v1(source: &str) -> Vec<String> {
        let identifiers = identifiers_v1(source);
        let mut definitions = Vec::new();
        for window in identifiers.windows(2) {
            if window[0] == "macro_rules" {
                definitions.push(format!("macro_rules:{}", window[1]));
            } else if window[0] == "macro" {
                definitions.push(format!("macro:{}", window[1]));
            }
        }
        definitions.sort();
        definitions
    }

    fn crate_private_selected_reexports_v1(
        source: &str,
        expected_block_count: usize,
        gate: &str,
    ) -> Vec<String> {
        let compact = normalized_code_v1(source);
        let prefix = "pub(crate)usestrict_model::selected_target::{";
        assert_eq!(
            compact.matches(prefix).count(),
            expected_block_count,
            "{gate}: direct crate-private selected-target re-export block count drifted"
        );
        let mut names = Vec::new();
        let mut cursor = 0_usize;
        for _ in 0..expected_block_count {
            let start = compact[cursor..]
                .find(prefix)
                .map(|offset| cursor + offset)
                .expect("direct crate-private selected-target re-export exists");
            let opening = start + prefix.len() - 1;
            let closing = closing_delimiter_v1(compact.as_bytes(), opening, b'{', b'}', gate);
            assert_eq!(
                compact.as_bytes().get(closing + 1),
                Some(&b';'),
                "{gate}: direct crate-private selected-target re-export must end at its semicolon"
            );
            let contents = &compact[opening + 1..closing];
            assert!(
                !contents.contains("as"),
                "{gate}: crate-private selected-target re-export aliases are forbidden"
            );
            names.extend(
                contents
                    .split(',')
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned),
            );
            cursor = closing + 2;
        }
        names.sort();
        assert!(
            names.windows(2).all(|pair| pair[0] != pair[1]),
            "{gate}: crate-private selected-target re-exports must not overlap"
        );
        names
    }

    fn visibility_start_before_keyword_v1(mask: &str, keyword_start: usize) -> Option<usize> {
        let bytes = mask.as_bytes();
        let mut end = keyword_start;
        while end > 0 && bytes[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        if end >= 3 && &bytes[end - 3..end] == b"pub" && token_boundary_v1(bytes, end - 3, 3) {
            return Some(end - 3);
        }
        if bytes.get(end.wrapping_sub(1)) != Some(&b')') {
            return None;
        }
        let closing = end - 1;
        let mut opening = closing;
        while opening > 0 && bytes[opening] != b'(' {
            opening -= 1;
        }
        if bytes.get(opening) != Some(&b'(') {
            return None;
        }
        let mut pub_end = opening;
        while pub_end > 0 && bytes[pub_end - 1].is_ascii_whitespace() {
            pub_end -= 1;
        }
        if pub_end >= 3
            && &bytes[pub_end - 3..pub_end] == b"pub"
            && token_boundary_v1(bytes, pub_end - 3, 3)
        {
            Some(pub_end - 3)
        } else {
            None
        }
    }

    fn visible_use_statements_v1(source: &str, gate: &str) -> Vec<String> {
        let mask = rust_code_mask_v1(source);
        let bytes = mask.as_bytes();
        let mut statements = Vec::new();
        let mut cursor = 0_usize;
        while cursor + 3 <= bytes.len() {
            let raw_identifier =
                cursor >= 2 && bytes[cursor - 2] == b'r' && bytes[cursor - 1] == b'#';
            if &bytes[cursor..cursor + 3] != b"use"
                || !token_boundary_v1(bytes, cursor, 3)
                || raw_identifier
            {
                cursor += 1;
                continue;
            }
            let Some(start) = visibility_start_before_keyword_v1(&mask, cursor) else {
                cursor += 3;
                continue;
            };
            let end = bytes[cursor..]
                .iter()
                .position(|byte| *byte == b';')
                .map(|offset| cursor + offset)
                .unwrap_or_else(|| panic!("{gate}: visible use statement is unterminated"));
            statements.push(normalized_code_v1(&source[start..=end]));
            cursor = end + 1;
        }
        statements
    }

    fn module_headers_v1(source: &str, gate: &str) -> Vec<String> {
        let mask = rust_code_mask_v1(source);
        let bytes = mask.as_bytes();
        let mut headers = Vec::new();
        let mut cursor = 0_usize;
        while cursor + 3 <= bytes.len() {
            let raw_identifier =
                cursor >= 2 && bytes[cursor - 2] == b'r' && bytes[cursor - 1] == b'#';
            if &bytes[cursor..cursor + 3] != b"mod"
                || !token_boundary_v1(bytes, cursor, 3)
                || raw_identifier
            {
                cursor += 1;
                continue;
            }
            let start = visibility_start_before_keyword_v1(&mask, cursor).unwrap_or(cursor);
            let end = bytes[cursor..]
                .iter()
                .position(|byte| *byte == b'{' || *byte == b';')
                .map(|offset| cursor + offset)
                .unwrap_or_else(|| panic!("{gate}: module declaration is unterminated"));
            headers.push(normalized_code_v1(&source[start..=end]));
            cursor = end + 1;
        }
        headers
    }

    fn item_declaration_names_v1(source: &str, keyword: &str) -> Vec<String> {
        let mask = rust_code_mask_v1(source);
        let bytes = mask.as_bytes();
        let mut names = Vec::new();
        let mut cursor = 0_usize;
        while let Some(relative) = mask[cursor..].find(keyword) {
            let start = cursor + relative;
            cursor = start + keyword.len();
            if !token_boundary_v1(bytes, start, keyword.len()) {
                continue;
            }
            let previous = mask[..start]
                .bytes()
                .rfind(|byte| !byte.is_ascii_whitespace());
            if previous.is_some_and(|byte| matches!(byte, b'.' | b':')) {
                continue;
            }
            let name_start = skip_ws_v1(bytes, cursor);
            if !bytes
                .get(name_start)
                .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
            {
                continue;
            }
            let mut name_end = name_start + 1;
            while bytes
                .get(name_end)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                name_end += 1;
            }
            names.push(mask[name_start..name_end].to_owned());
            cursor = name_end;
        }
        names.sort();
        names
    }

    fn extern_crate_inventory_v1(source: &str) -> Vec<String> {
        let identifiers = identifiers_v1(source);
        let mut inventory = Vec::new();
        for (index, window) in identifiers.windows(2).enumerate() {
            if window[0] == "extern" && window[1] == "crate" {
                inventory.push(
                    identifiers
                        .get(index + 2)
                        .cloned()
                        .unwrap_or_else(|| "<missing>".to_owned()),
                );
            }
        }
        inventory.sort();
        inventory
    }

    fn path_attribute_inventory_v1(source: &str) -> Vec<String> {
        attribute_inventory_v1(source)
            .into_iter()
            .filter(|attribute| {
                identifiers_v1(attribute)
                    .iter()
                    .any(|token| token == "path")
            })
            .collect()
    }

    fn protected_type_names_v1() -> [&'static str; 4] {
        [
            "SupervisorGeneratorSendOpV1",
            "SupervisorGeneratorSentEndpointV1",
            "SupervisorWorkerBootstrapSendOpV1",
            "WorkerBootstrapEnqueuedEndpointV1",
        ]
    }

    fn protected_impl_inventory_v1(source: &str) -> Vec<String> {
        let mut inventory = impl_headers_v1(source)
            .into_iter()
            .filter(|header| {
                protected_type_names_v1()
                    .iter()
                    .any(|name| header.contains(name))
            })
            .collect::<Vec<_>>();
        inventory.sort();
        inventory
    }

    fn protected_signature_inventory_v1(source: &str) -> Vec<String> {
        let mut inventory = function_signatures_v1(source)
            .into_iter()
            .filter(|signature| {
                protected_type_names_v1()
                    .iter()
                    .any(|name| signature.contains(name))
            })
            .map(|signature| signature.replace(",)->", ")->"))
            .collect::<Vec<_>>();
        inventory.sort();
        inventory
    }

    fn blanket_impl_inventory_v1(source: &str) -> Vec<String> {
        impl_headers_v1(source)
            .into_iter()
            .filter(|header| {
                header.starts_with("impl<")
                    && header
                        .find('>')
                        .is_some_and(|closing| header[closing + 1..].contains("for"))
            })
            .collect()
    }

    fn macro_inventory_strings_v1(source: &str) -> Vec<String> {
        macro_invocations_v1(source)
            .into_iter()
            .map(|invocation| format!("{}!@{}", invocation.path, invocation.context))
            .collect()
    }

    struct TransitiveSourceSpecV1 {
        label: &'static str,
        modules: &'static [&'static str],
        macros: &'static [(&'static str, &'static str)],
        aliases: &'static [&'static str],
        required_protected_impls: &'static [&'static str],
        optional_protected_impls: &'static [&'static str],
        protected_signatures: &'static [&'static str],
    }

    fn exact_transitive_source_specs_v1() -> [TransitiveSourceSpecV1; 7] {
        [
            TransitiveSourceSpecV1 {
                label: "lib.rs",
                modules: &[
                    "pubmodancillary;",
                    "pub(crate)modexecutable_custody;",
                    "pubmodprocess;",
                    "pubmodseccomp;",
                    "pub(crate)modsession;",
                    "pubmodstatx;",
                ],
                macros: &[("cfg", "<module>"), ("compile_error", "<module>")],
                aliases: &[],
                required_protected_impls: &[],
                optional_protected_impls: &[],
                protected_signatures: &[],
            },
            TransitiveSourceSpecV1 {
                label: "ancillary.rs",
                modules: &["modstrict_model{", "pub(super)modselected_target{"],
                macros: &[
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("debug_assert_eq", "receive_for_peer_v1"),
                    ("format", "observe_final_result_physical_pass_v1"),
                    ("rustix::cmsg_space", "send_seqpacket_once_v1"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                ],
                aliases: &[
                    "FdRoleV1 as ContractFdRoleV1",
                    "MAX_FRAME_BYTES_V1 as CONTRACT_MAX_FRAME_BYTES_V1",
                    "MAX_FRAME_FDS_V1 as CONTRACT_MAX_FRAME_FDS_V1",
                ],
                required_protected_impls: &[
                    "implSupervisorGeneratorSendOpV1",
                    "implSupervisorWorkerBootstrapSendOpV1",
                    "implWorkerBootstrapEnqueuedEndpointV1",
                ],
                optional_protected_impls: &["implSupervisorGeneratorSentEndpointV1"],
                protected_signatures: &[
                    "pub(crate)fnenqueue_once_v1(self,credentials:UCred)->Result<SupervisorGeneratorSentEndpointV1,AncillarySendErrorV1>",
                    "pub(crate)fnenqueue_once_v1(self,credentials:UCred)->Result<WorkerBootstrapEnqueuedEndpointV1,AncillarySendErrorV1>",
                    "pub(crate)fnprepare_closed_result_send_v1(endpoint:GeneratorBoundReceivedEndpointV1,input:ClosedResultSendInputV1,previous_digest:[u8;32])->Result<(SupervisorGeneratorSendOpV1,G0TranscriptCandidateV1),SupervisorTypedTransitionErrorV1,>",
                    "pub(crate)fnprepare_session_offer_send_v1(endpoint:SupervisorGeneratorEndpointV1,input:SessionOfferSendInputV1)->Result<SupervisorGeneratorSendOpV1,SupervisorTypedTransitionErrorV1>",
                    "pub(crate)fnprepare_supervisor_commit_send_v1(endpoint:GeneratorCommitReceivedEndpointV1,input:SupervisorCommitSendInputV1)->Result<SupervisorGeneratorSendOpV1,SupervisorTypedTransitionErrorV1>",
                    "pub(crate)fnprepare_supervisor_reveal_send_v1(endpoint:GeneratorRevealReceivedEndpointV1,input:SupervisorRevealSendInputV1)->Result<SupervisorGeneratorSendOpV1,SupervisorTypedTransitionErrorV1>",
                    "pub(crate)fnprepare_worker_bootstrap_send_v1(self,input:WorkerBootstrapSendInputV1,previous_digest:[u8;32])->Result<(SupervisorWorkerBootstrapSendOpV1,G0TranscriptCandidateV1),SupervisorTypedTransitionErrorV1,>",
                ],
            },
            TransitiveSourceSpecV1 {
                label: "process.rs",
                modules: &["modselected_target{"],
                macros: &[
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("matches", "reauthenticate_live_snapshot_v1"),
                    ("matches", "transition_clears_supplementary_groups_v1"),
                    ("write", "fmt"),
                ],
                aliases: &[],
                required_protected_impls: &[],
                optional_protected_impls: &[],
                protected_signatures: &[
                    "pub(crate)fnenqueue_supervisor_bootstrap_once_v1(&self,checked:&CheckedWorkerMapsV1,op:SupervisorWorkerBootstrapSendOpV1)->Result<(WorkerBootstrapProjectionV1,WorkerBootstrapEnqueuedEndpointV1),ProcessContractErrorV1>",
                    "pub(crate)fnenqueue_supervisor_generator_once_v1(&self,op:SupervisorGeneratorSendOpV1)->Result<(SupervisorReceiveProjectionV1,SupervisorGeneratorSentEndpointV1),ProcessContractErrorV1>",
                    "pub(crate)fnrelease_after_bootstrap_enqueued_v1(self,checked:CheckedWorkerMapsV1,bootstrap_enqueued:&WorkerBootstrapEnqueuedEndpointV1)->Result<WorkerIdentityReadyV1,WorkerReleaseErrorV1>",
                ],
            },
            TransitiveSourceSpecV1 {
                label: "executable_custody.rs",
                modules: &["modselected_target{"],
                macros: &[],
                aliases: &["AsFd as _"],
                required_protected_impls: &[],
                optional_protected_impls: &[],
                protected_signatures: &[
                    "pub(crate)fnenqueue_supervisor_bootstrap_once_v1(&self,op:SupervisorWorkerBootstrapSendOpV1)->Result<(WorkerBootstrapProjectionV1,WorkerBootstrapEnqueuedEndpointV1,),ExecutableCustodyErrorV2,>",
                    "pub(crate)fnenqueue_supervisor_generator_once_v1(&self,op:SupervisorGeneratorSendOpV1)->Result<(SupervisorReceiveProjectionV1,SupervisorGeneratorSentEndpointV1,),ExecutableCustodyErrorV2,>",
                    "pub(crate)fnrelease_after_bootstrap_enqueued_v1(self,bootstrap_enqueued:&WorkerBootstrapEnqueuedEndpointV1)->Result<WorkerChildExecutableCustodyV2,ExecutableCustodyErrorV2>",
                ],
            },
            TransitiveSourceSpecV1 {
                label: "seccomp.rs",
                modules: &["modfilter_model{", "modselected_target{"],
                macros: &[
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("core::mem::offset_of", "<module>"),
                    ("write", "fmt"),
                ],
                aliases: &[],
                required_protected_impls: &[],
                optional_protected_impls: &[],
                protected_signatures: &[],
            },
            TransitiveSourceSpecV1 {
                label: "statx.rs",
                modules: &[],
                macros: &[
                    ("debug_assert_eq", "observe_exact_descriptor_v1"),
                    ("debug_assert_eq", "observe_exact_descriptor_v1"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                    ("write", "fmt"),
                ],
                aliases: &[],
                required_protected_impls: &[],
                optional_protected_impls: &[],
                protected_signatures: &[],
            },
            TransitiveSourceSpecV1 {
                label: "session.rs",
                modules: &[],
                macros: &[],
                aliases: &[],
                required_protected_impls: &[],
                optional_protected_impls: &[],
                protected_signatures: &[],
            },
        ]
    }

    fn transitive_sources_v1() -> [(&'static str, &'static str); 7] {
        [
            ("lib.rs", root_production_v1()),
            ("ancillary.rs", ancillary_production_v1()),
            ("process.rs", process_production_v1()),
            ("executable_custody.rs", executable_custody_production_v1()),
            ("seccomp.rs", seccomp_production_v1()),
            ("statx.rs", statx_production_v1()),
            ("session.rs", session_production_v1()),
        ]
    }

    fn assert_transitive_source_closure_from_v1(sources: &[(&str, &str)], gate: &str) {
        let specs = exact_transitive_source_specs_v1();
        assert_eq!(
            sources.len(),
            specs.len(),
            "{gate}: the exact seven-source closure drifted"
        );
        for ((label, source), spec) in sources.iter().zip(specs) {
            assert_eq!(*label, spec.label, "{gate}: source order/name drifted");
            assert_eq!(
                module_headers_v1(source, gate),
                spec.modules
                    .iter()
                    .map(|header| (*header).to_owned())
                    .collect::<Vec<_>>(),
                "{gate}: {label} module/visibility inventory drifted"
            );
            assert_eq!(
                macro_inventory_strings_v1(source),
                spec.macros
                    .iter()
                    .map(|(path, context)| format!("{path}!@{context}"))
                    .collect::<Vec<_>>(),
                "{gate}: {label} macro path/context/count inventory drifted"
            );
            assert!(
                macro_definition_names_v1(source).is_empty(),
                "{gate}: {label} gained a macro definition"
            );
            assert!(
                path_attribute_inventory_v1(source).is_empty(),
                "{gate}: {label} gained a path-bearing attribute"
            );
            assert!(
                macro_invocations_v1(source).iter().all(|invocation| ![
                    "include",
                    "include_str",
                    "include_bytes"
                ]
                .contains(&invocation.path.as_str())),
                "{gate}: {label} gained a transitive include route"
            );
            assert_eq!(
                use_alias_inventory_v1(source),
                spec.aliases
                    .iter()
                    .map(|alias| (*alias).to_owned())
                    .collect::<Vec<_>>(),
                "{gate}: {label} use-alias inventory drifted"
            );
            assert!(
                extern_crate_inventory_v1(source).is_empty(),
                "{gate}: {label} gained an extern-crate substitution"
            );
            for keyword in ["trait", "type", "union"] {
                assert!(
                    item_declaration_names_v1(source, keyword).is_empty(),
                    "{gate}: {label} gained a `{keyword}` item surface"
                );
            }
            assert!(
                blanket_impl_inventory_v1(source).is_empty(),
                "{gate}: {label} gained a generic blanket impl"
            );
            assert_no_generic_fabrication_v1(source, &format!("{gate}: {label}"));

            let protected_impls = protected_impl_inventory_v1(source);
            for required in spec.required_protected_impls {
                assert_eq!(
                    protected_impls
                        .iter()
                        .filter(|header| header.as_str() == *required)
                        .count(),
                    1,
                    "{gate}: {label} required protected impl `{required}` drifted"
                );
            }
            for optional in spec.optional_protected_impls {
                assert!(
                    protected_impls
                        .iter()
                        .filter(|header| header.as_str() == *optional)
                        .count()
                        <= 1,
                    "{gate}: {label} duplicated optional protected impl `{optional}`"
                );
            }
            assert!(
                protected_impls.iter().all(|header| spec
                    .required_protected_impls
                    .contains(&header.as_str())
                    || spec.optional_protected_impls.contains(&header.as_str())),
                "{gate}: {label} gained an unowned/qualified protected impl: {protected_impls:?}"
            );
            assert_eq!(
                protected_signature_inventory_v1(source),
                spec.protected_signatures
                    .iter()
                    .map(|signature| (*signature).to_owned())
                    .collect::<Vec<_>>(),
                "{gate}: {label} protected function-signature inventory drifted"
            );
            for type_name in protected_type_names_v1() {
                for implementation in inherent_impl_blocks_v1(source, type_name) {
                    for forbidden in ["const", "type", "static"] {
                        assert_eq!(
                            token_count_v1(implementation, forbidden),
                            0,
                            "{gate}: {label} `{type_name}` impl gained associated `{forbidden}` authority"
                        );
                    }
                }
            }
            if spec.label == "ancillary.rs" {
                assert_inherent_method_allowlist_v1(
                    source,
                    "SupervisorGeneratorSendOpV1",
                    &[("pub(crate)", "enqueue_once_v1")],
                    gate,
                );
                assert_inherent_method_allowlist_v1(
                    source,
                    "SupervisorWorkerBootstrapSendOpV1",
                    &[("pub(crate)", "enqueue_once_v1")],
                    gate,
                );
            }
        }
    }

    fn assert_exact_transitive_source_closure_v1() {
        assert_transitive_source_closure_from_v1(
            &transitive_sources_v1(),
            "exact seven-source production closure",
        );
    }

    fn assert_transitive_source_closure_fixtures_v1() {
        let live = transitive_sources_v1();
        assert_transitive_source_closure_from_v1(&live, "seven-source closure positive fixture");

        for (index, addition, label) in [
            (
                2_usize,
                "\n#[cfg(any())] include!(\"external_retry.rs\");",
                "cfg-hidden include",
            ),
            (3, "\nmod alternate_custody;", "alternate module"),
            (
                5,
                "\n#[path = \"alternate_statx.rs\"] mod alternate_statx;",
                "path module",
            ),
            (
                4,
                "\nuse crate::ancillary::SupervisorGeneratorSentEndpointV1 as ReplayEndpointV1;",
                "successor alias",
            ),
            (
                2,
                "\ntrait RetryV1 {} impl<T> RetryV1 for T {}",
                "blanket impl",
            ),
            (
                3,
                "\nimpl crate::ancillary::SupervisorGeneratorSentEndpointV1 { const REPLAY: u8 = 1; fn retry(self) -> Self { self } }",
                "qualified protected impl",
            ),
        ] {
            let mut mutant = live
                .iter()
                .map(|(name, source)| (*name, (*source).to_owned()))
                .collect::<Vec<_>>();
            mutant[index].1.push_str(addition);
            let borrowed = mutant
                .iter()
                .map(|(name, source)| (*name, source.as_str()))
                .collect::<Vec<_>>();
            let rejected = std::panic::catch_unwind(|| {
                assert_transitive_source_closure_from_v1(
                    &borrowed,
                    "seven-source closure negative fixture",
                )
            });
            assert!(rejected.is_err(), "{label} must be rejected");
        }

        let ancillary_index = live
            .iter()
            .position(|(name, _)| *name == "ancillary.rs")
            .expect("receiver-only fixture requires ancillary.rs");
        for type_name in [
            "SupervisorGeneratorSendOpV1",
            "SupervisorWorkerBootstrapSendOpV1",
        ] {
            let anchor = format!("impl {type_name} {{");
            let mut mutant = live
                .iter()
                .map(|(name, source)| (*name, (*source).to_owned()))
                .collect::<Vec<_>>();
            assert_eq!(
                rust_code_mask_v1(&mutant[ancillary_index].1)
                    .matches(&anchor)
                    .count(),
                1,
                "receiver-only protected-method fixture anchor drifted"
            );
            mutant[ancillary_index].1 = mutant[ancillary_index].1.replacen(
                &anchor,
                &format!(
                    "{anchor}\n            pub(crate) fn x(self) -> OwnedFd {{ self.endpoint.0.descriptor }}"
                ),
                1,
            );
            let borrowed = mutant
                .iter()
                .map(|(name, source)| (*name, source.as_str()))
                .collect::<Vec<_>>();
            let rejected = std::panic::catch_unwind(|| {
                assert_transitive_source_closure_from_v1(
                    &borrowed,
                    "receiver-only protected-method negative fixture",
                )
            });
            assert!(
                rejected.is_err(),
                "`{type_name}` receiver-only owning-descriptor escape must be rejected"
            );
        }

        let decoys = r###"
            // include!("external_retry.rs"); mod alternate;
            fn note() {
                let _ = "#[path = \"alternate.rs\"] mod alternate;";
                let _ = "impl<T> RetryV1 for T {}";
                let _ = "use EndpointV1 as ReplayEndpointV1;";
            }
        "###;
        assert!(macro_invocations_v1(decoys).is_empty());
        assert!(macro_definition_names_v1(decoys).is_empty());
        assert!(module_headers_v1(decoys, "masked decoy fixture").is_empty());
        assert!(path_attribute_inventory_v1(decoys).is_empty());
        assert!(use_alias_inventory_v1(decoys).is_empty());
        assert!(protected_impl_inventory_v1(decoys).is_empty());

        let test_only = production_without_tests_v1(
            "#[cfg(test)] mod tests { include!(\"external_retry.rs\"); } mod live {}",
        );
        assert_eq!(
            module_headers_v1(&test_only, "cfg(test) transitive fixture"),
            ["modlive{".to_owned()]
        );
        assert!(macro_invocations_v1(&test_only).is_empty());
    }

    fn expected_public_selected_reexport_v1() -> &'static str {
        "pubusestrict_model::selected_target::{ChildTypedSendErrorV1,GeneratorEndpointV1,InheritedEndpointAdoptionErrorV1,WorkerEndpointV1,try_adopt_generator_exec_inherited_fd3_once_v1,try_adopt_worker_exec_inherited_fd3_once_v1,};"
    }

    fn expected_g0_public_selected_reexport_v1() -> &'static str {
        "pubusestrict_model::selected_target::{ChildTypedReceiveErrorV1,GeneratorBoundAwaitClosedResultEndpointV1,GeneratorBoundSendInputV1,GeneratorPeerGCommitSendEndpointV1,GeneratorPeerGRevealSendEndpointV1,GeneratorPeerSCommitReceiveEndpointV1,GeneratorPeerSRevealReceiveEndpointV1,GeneratorPeerSessionOfferEndpointV1,GeneratorProviderSessionEndpointV1,};"
    }

    fn expected_base_private_selected_reexport_v1() -> &'static str {
        "pub(crate)usestrict_model::selected_target::{GeneratorChannelV1,SupervisorGeneratorEndpointV1,SupervisorGeneratorSendOpV1,SupervisorGeneratorSentEndpointV1,SupervisorWorkerBootstrapSendOpV1,SupervisorWorkerEndpointV1,WorkerBootstrapEnqueuedEndpointV1,WorkerChannelV1,create_generator_channel_v1,create_worker_channel_v1,};"
    }

    fn expected_g0_private_selected_reexport_v1() -> &'static str {
        "pub(crate)usestrict_model::selected_target::{ClosedResultSendInputV1,GeneratorBoundReceiveInputV1,GeneratorBoundReceivedEndpointV1,GeneratorCommitReceiveInputV1,GeneratorCommitReceivedEndpointV1,GeneratorRevealReceiveInputV1,GeneratorRevealReceivedEndpointV1,SessionOfferSendInputV1,SupervisorCommitSendInputV1,SupervisorRevealSendInputV1,SupervisorTypedTransitionErrorV1,WorkerBootstrapSendInputV1,WorkerExecBoundReceiveInputV1,WorkerExecBoundReceivedEndpointV1,prepare_closed_result_send_v1,prepare_session_offer_send_v1,prepare_supervisor_commit_send_v1,prepare_supervisor_reveal_send_v1,};"
    }

    fn assert_whole_ancillary_visible_item_inventory_v1(source: &str, gate: &str) {
        assert_eq!(
            visible_use_statements_v1(source, gate),
            [
                expected_public_selected_reexport_v1().to_owned(),
                expected_g0_public_selected_reexport_v1().to_owned(),
                expected_base_private_selected_reexport_v1().to_owned(),
                expected_g0_private_selected_reexport_v1().to_owned(),
            ],
            "{gate}: visible use/re-export inventory drifted anywhere in ancillary production"
        );
        assert_eq!(
            module_headers_v1(source, gate),
            [
                "modstrict_model{".to_owned(),
                "pub(super)modselected_target{".to_owned()
            ],
            "{gate}: ancillary production module/visibility inventory drifted"
        );
    }

    fn assert_whole_ancillary_visible_item_inventory_fixtures_v1() {
        let public = expected_public_selected_reexport_v1().replacen(
            "pubusestrict_model",
            "pub use strict_model",
            1,
        );
        let g0_public = expected_g0_public_selected_reexport_v1().replacen(
            "pubusestrict_model",
            "pub use strict_model",
            1,
        );
        let base_private = expected_base_private_selected_reexport_v1().replacen(
            "pub(crate)usestrict_model",
            "pub(crate) use strict_model",
            1,
        );
        let g0_private = expected_g0_private_selected_reexport_v1().replacen(
            "pub(crate)usestrict_model",
            "pub(crate) use strict_model",
            1,
        );
        let valid = format!(
            "mod strict_model {{ pub(super) mod selected_target {{}} }} {} {} {} {}",
            public, g0_public, base_private, g0_private,
        );
        assert_whole_ancillary_visible_item_inventory_v1(
            &valid,
            "whole ancillary visible item positive fixture",
        );
        for mutant in [
            format!("pub(crate) use strict_model::selected_target::*; {valid}"),
            format!(
                "pub(crate) mod alternate_exports {{ pub(crate) use super::strict_model::selected_target::*; }} {valid}"
            ),
            valid.replacen("mod strict_model", "pub(crate) mod strict_model", 1),
            valid.replacen(
                "pub(super) mod selected_target",
                "pub(crate) mod selected_target",
                1,
            ),
        ] {
            let rejected = std::panic::catch_unwind(|| {
                assert_whole_ancillary_visible_item_inventory_v1(
                    &mutant,
                    "whole ancillary visible item negative fixture",
                )
            });
            assert!(
                rejected.is_err(),
                "alternate visible import/module surface must be rejected"
            );
        }
    }

    fn assert_whole_ancillary_fabrication_closure_v1(source: &str, gate: &str) {
        assert_eq!(
            token_count_v1(source, "type"),
            0,
            "{gate}: whole ancillary production forbids every type alias"
        );
        assert_eq!(
            token_count_v1(source, "unsafe"),
            3,
            "{gate}: whole ancillary unsafe inventory must remain exactly the three selected-target sites"
        );
        assert_no_generic_fabrication_v1(source, gate);
    }

    fn assert_whole_ancillary_fabrication_closure_fixtures_v1() {
        let valid = "unsafe extern \"C\" {} fn route() { let _ = unsafe { c_recvmsg() }; let _ = unsafe { OwnedFd::from_raw_fd(raw) }; }";
        assert_whole_ancillary_fabrication_closure_v1(
            valid,
            "whole ancillary fabrication positive fixture",
        );
        for mutant in [
            format!(
                "{valid} pub(crate) fn fabricate<T>() -> T {{ unsafe {{ core::mem::MaybeUninit::<T>::uninit().assume_init() }} }}"
            ),
            format!(
                "{valid} pub(crate) type AlternateGeneratorChannelV1 = strict_model::selected_target::GeneratorChannelV1;"
            ),
        ] {
            let rejected = std::panic::catch_unwind(|| {
                assert_whole_ancillary_fabrication_closure_v1(
                    &mutant,
                    "whole ancillary fabrication negative fixture",
                )
            });
            assert!(
                rejected.is_err(),
                "generic fabrication and visible type aliases must be rejected"
            );
        }
    }

    fn contract_wire_import_blocks_v1(
        source: &str,
        expected_block_count: usize,
        expected_depth: usize,
        gate: &str,
    ) -> Vec<(usize, Vec<String>)> {
        let mask = rust_code_mask_v1(source);
        let prefix = "use eip0045_h0_contract::wire::";
        assert_eq!(
            mask.matches(prefix).count(),
            expected_block_count,
            "{gate}: direct eip0045_h0_contract::wire import block count drifted"
        );
        let mut blocks = Vec::new();
        let mut cursor = 0_usize;
        for _ in 0..expected_block_count {
            let start = mask[cursor..]
                .find(prefix)
                .map(|offset| cursor + offset)
                .expect("direct contract wire import exists");
            let depth = mask.as_bytes()[..start]
                .iter()
                .fold(0_usize, |depth, byte| match byte {
                    b'{' => depth + 1,
                    b'}' => depth.saturating_sub(1),
                    _ => depth,
                });
            assert_eq!(
                depth, expected_depth,
                "{gate}: contract candidate import must be module-level at the exact owner depth"
            );
            let opening = mask[start..]
                .find('{')
                .map(|offset| start + offset)
                .expect("direct contract wire import opens its name inventory");
            let closing = closing_delimiter_v1(mask.as_bytes(), opening, b'{', b'}', gate);
            assert_eq!(
                mask.as_bytes().get(closing + 1),
                Some(&b';'),
                "{gate}: direct contract wire import must end at its semicolon"
            );
            let contents = normalized_code_v1(&source[opening + 1..closing]);
            assert!(
                !contents.contains('*') && !contents.contains("as"),
                "{gate}: contract candidate import forbids glob and alias substitution"
            );
            let names = contents
                .split(',')
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            blocks.push((start, names));
            cursor = closing + 2;
        }
        blocks
    }

    fn contract_wire_import_names_v1(
        source: &str,
        expected_block_count: usize,
        expected_depth: usize,
        gate: &str,
    ) -> Vec<String> {
        let mut names =
            contract_wire_import_blocks_v1(source, expected_block_count, expected_depth, gate)
                .into_iter()
                .flat_map(|(_, names)| names)
                .collect::<Vec<_>>();
        names.sort();
        assert!(
            names.windows(2).all(|pair| pair[0] != pair[1]),
            "{gate}: direct contract wire import blocks must not overlap"
        );
        names
    }

    fn assert_ancillary_contract_wire_import_blocks_v1(source: &str, gate: &str) {
        let blocks = contract_wire_import_blocks_v1(source, 2, 1, gate);
        assert_eq!(
            blocks[0].1,
            [
                "ChannelIdentityV1",
                "ProviderSessionMaterialV1",
                "SeqpacketEndpointCommitmentV1",
            ],
            "{gate}: base contract wire import inventory/order drifted"
        );
        assert_eq!(
            blocks[1].1,
            [
                "FdAccessV1",
                "FdStatusV1",
                "G0_CLOSED_RESULT_RAW_FRAME_BYTES_V1",
                "G0_FINAL_RESULT_MAX_BYTES_V1",
                "G0_PRE_SESSION_RECORD_BYTES_V1",
                "G0_SESSION_OFFER_BYTES_V1",
                "G0ClosedResultInboundInputV1",
                "G0ClosedResultVerifiedV1",
                "G0GeneratorBoundAwaitClosedResultV1",
                "G0GeneratorBoundOutboundCandidateV1",
                "G0GeneratorBoundTranscriptCandidateV1",
                "G0GeneratorCommitRecordV1",
                "G0GeneratorPeerLocalFactsV1",
                "G0GeneratorPeerSessionCandidateV1",
                "G0GeneratorPeerSessionInputV1",
                "G0GeneratorRevealRecordV1",
                "G0TranscriptCandidateV1",
                "G0WorkerBootstrapContentVerifierV1",
                "G0WorkerBootstrapInboundCandidateV1",
                "G0WorkerBootstrapInboundInputV1",
                "GeneratorSealProfileV1",
                "MemfdSealsV1",
                "PeerCredentialsV1",
                "ProcessInventoryV1",
                "SealPresenceV1",
                "SealedIngressManifestV1",
                "WireErrorV1",
                "WireFrameV1",
            ],
            "{gate}: G0 contract wire import inventory/order drifted"
        );
        let mask = rust_code_mask_v1(source);
        assert!(
            has_item_boundary_before_v1(&mask, blocks[0].0),
            "{gate}: base contract wire import must remain feature-off"
        );
        assert!(
            exact_immediate_attribute_start_v1(source, &mask, blocks[1].0, G0A_FEATURE_GATE_V1,)
                .is_some(),
            "{gate}: the complete G0 contract wire import must have one exact active feature gate"
        );
    }

    fn assert_ancillary_contract_wire_import_blocks_fixtures_v1() {
        let base = "use eip0045_h0_contract::wire::{ChannelIdentityV1, ProviderSessionMaterialV1, SeqpacketEndpointCommitmentV1,};";
        let g0 = format!(
            "{G0A_FEATURE_GATE_V1} use eip0045_h0_contract::wire::{{FdAccessV1, FdStatusV1, G0_CLOSED_RESULT_RAW_FRAME_BYTES_V1, G0_FINAL_RESULT_MAX_BYTES_V1, G0_PRE_SESSION_RECORD_BYTES_V1, G0_SESSION_OFFER_BYTES_V1, G0ClosedResultInboundInputV1, G0ClosedResultVerifiedV1, G0GeneratorBoundAwaitClosedResultV1, G0GeneratorBoundOutboundCandidateV1, G0GeneratorBoundTranscriptCandidateV1, G0GeneratorCommitRecordV1, G0GeneratorPeerLocalFactsV1, G0GeneratorPeerSessionCandidateV1, G0GeneratorPeerSessionInputV1, G0GeneratorRevealRecordV1, G0TranscriptCandidateV1, G0WorkerBootstrapContentVerifierV1, G0WorkerBootstrapInboundCandidateV1, G0WorkerBootstrapInboundInputV1, GeneratorSealProfileV1, MemfdSealsV1, PeerCredentialsV1, ProcessInventoryV1, SealPresenceV1, SealedIngressManifestV1, WireErrorV1, WireFrameV1,}};"
        );
        let valid = format!("mod selected_target {{ {base} {g0} }}");
        assert_ancillary_contract_wire_import_blocks_v1(
            &valid,
            "ordered contract wire import positive fixture",
        );

        let moved = valid
            .replacen(
                "SeqpacketEndpointCommitmentV1,",
                "SeqpacketEndpointCommitmentV1, WireErrorV1, WireFrameV1,",
                1,
            )
            .replacen(
                "SealedIngressManifestV1, WireErrorV1, WireFrameV1,",
                "SealedIngressManifestV1,",
                1,
            );
        let added = valid.replacen(
            "ChannelIdentityV1,",
            "ChannelIdentityV1, PeerCredentialsV1,",
            1,
        );
        let permuted = valid.replacen("WireErrorV1, WireFrameV1,", "WireFrameV1, WireErrorV1,", 1);
        let commented_gate = valid.replacen(
            G0A_FEATURE_GATE_V1,
            &format!("// {G0A_FEATURE_GATE_V1}\n"),
            1,
        );
        let stacked_gate = valid.replacen(
            G0A_FEATURE_GATE_V1,
            &format!("#[cfg(any())]\n{G0A_FEATURE_GATE_V1}"),
            1,
        );
        for mutant in [moved, added, permuted, commented_gate, stacked_gate] {
            let rejected = std::panic::catch_unwind(|| {
                assert_ancillary_contract_wire_import_blocks_v1(
                    &mutant,
                    "ordered contract wire import negative fixture",
                )
            });
            assert!(
                rejected.is_err(),
                "contract wire block movement, addition, permutation, or cfg reassignment must fail"
            );
        }
    }

    fn assert_contract_candidate_provenance_v1(
        import_source: &str,
        declaration_source: &str,
        expected_block_count: usize,
        expected_depth: usize,
        gate: &str,
    ) {
        let imports = contract_wire_import_names_v1(
            import_source,
            expected_block_count,
            expected_depth,
            gate,
        );
        let candidates = [
            "G0GeneratorBoundTranscriptCandidateV1",
            "G0TranscriptCandidateV1",
        ];
        for candidate in candidates {
            assert_eq!(
                imports
                    .iter()
                    .filter(|name| name.as_str() == candidate)
                    .count(),
                1,
                "{gate}: `{candidate}` must resolve directly from eip0045_h0_contract::wire"
            );
        }
        let identifiers = identifiers_v1(declaration_source);
        for window in identifiers.windows(2) {
            if ["struct", "enum", "union", "trait", "mod"].contains(&window[0].as_str())
                && candidates.contains(&window[1].as_str())
            {
                panic!(
                    "{gate}: local declaration `{}` may not substitute a contract candidate",
                    window[1]
                );
            }
            assert!(
                !(window[0] == "extern" && window[1] == "crate"),
                "{gate}: extern-crate substitution is forbidden"
            );
        }
    }

    fn assert_contract_crate_root_unshadowed_v1(source: &str, gate: &str) {
        assert_no_hidden_source_shapes_v1(gate, source);
        assert_eq!(
            token_count_v1(source, "use"),
            0,
            "{gate}: crate root forbids every import/alias that could shadow the contract crate"
        );
        assert_eq!(
            token_count_v1(source, "extern"),
            0,
            "{gate}: crate root forbids extern-crate/self alias substitution"
        );
        assert_eq!(
            module_headers_v1(source, gate),
            [
                "pubmodancillary;".to_owned(),
                "pub(crate)modexecutable_custody;".to_owned(),
                "pubmodprocess;".to_owned(),
                "pubmodseccomp;".to_owned(),
                "pub(crate)modsession;".to_owned(),
                "pubmodstatx;".to_owned(),
            ],
            "{gate}: crate-root module/visibility inventory drifted"
        );
        let candidates = [
            "G0GeneratorBoundTranscriptCandidateV1",
            "G0TranscriptCandidateV1",
        ];
        for window in identifiers_v1(source).windows(2) {
            if ["struct", "enum", "union", "trait", "mod"].contains(&window[0].as_str())
                && candidates.contains(&window[1].as_str())
            {
                panic!(
                    "{gate}: crate-root declaration `{}` may not substitute a contract candidate",
                    window[1]
                );
            }
        }
    }

    fn assert_contract_crate_root_unshadowed_fixtures_v1() {
        let valid = "pub mod ancillary; pub(crate) mod executable_custody; pub mod process; pub mod seccomp; pub(crate) mod session; pub mod statx;";
        assert_contract_crate_root_unshadowed_v1(
            valid,
            "contract crate-root provenance positive fixture",
        );
        for mutant in [
            format!("extern crate self as eip0045_h0_contract; mod wire {{}} {valid}"),
            format!("use crate as eip0045_h0_contract; mod wire {{}} {valid}"),
            format!("mod wire {{}} {valid}"),
            format!(
                "macro_rules! shadow_contract {{ () => {{ extern crate self as eip0045_h0_contract; }} }} {valid}"
            ),
        ] {
            let rejected = std::panic::catch_unwind(|| {
                assert_contract_crate_root_unshadowed_v1(
                    &mutant,
                    "contract crate-root provenance negative fixture",
                )
            });
            assert!(
                rejected.is_err(),
                "crate-root extern/use/module/macro contract substitution must be rejected"
            );
        }
    }

    fn assert_contract_candidate_provenance_fixtures_v1() {
        let import = "use eip0045_h0_contract::wire::{G0GeneratorBoundTranscriptCandidateV1, G0TranscriptCandidateV1};";
        assert_contract_candidate_provenance_v1(
            import,
            import,
            1,
            0,
            "contract candidate provenance positive fixture",
        );
        for (import_source, declaration_source) in [
            (
                "use super::{G0GeneratorBoundTranscriptCandidateV1, G0TranscriptCandidateV1};",
                "pub(crate) struct G0GeneratorBoundTranscriptCandidateV1; pub(crate) struct G0TranscriptCandidateV1;",
            ),
            (
                import,
                "pub(crate) struct G0GeneratorBoundTranscriptCandidateV1; pub(crate) struct G0TranscriptCandidateV1;",
            ),
            (
                "use eip0045_h0_contract::wire::{G0GeneratorBoundTranscriptCandidateV1 as G0TranscriptCandidateV1, *};",
                "extern crate self as eip0045_h0_contract;",
            ),
        ] {
            let rejected = std::panic::catch_unwind(|| {
                assert_contract_candidate_provenance_v1(
                    import_source,
                    declaration_source,
                    1,
                    0,
                    "contract candidate provenance negative fixture",
                )
            });
            assert!(
                rejected.is_err(),
                "local, aliased, globbed, or extern-crate candidate substitution must be rejected"
            );
        }
    }

    fn assert_whole_ancillary_reexport_inventory_fixtures_v1() {
        assert_eq!(
            crate_private_selected_reexports_v1(
                "pub(crate) use strict_model::selected_target::{AlphaV1}; #[cfg(feature = \"h0-tmpfs-provider-v2-g0\")] pub(crate) use strict_model::selected_target::{beta_v1};",
                2,
                "direct re-export positive fixture",
            ),
            ["AlphaV1", "beta_v1"]
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        );
        let macro_only = "macro_rules! export_both { ($name:ident) => { pub(crate) use strict_model::selected_target::$name; } } export_both!(beta_v1);";
        assert!(
            !macro_definition_names_v1(macro_only).is_empty(),
            "macro-emitted re-export fixture must expose its definition"
        );
        let rejected = std::panic::catch_unwind(|| {
            crate_private_selected_reexports_v1(
                macro_only,
                2,
                "macro-emitted re-export negative fixture",
            )
        });
        assert!(
            rejected.is_err(),
            "macro-emitted aliases must not replace the direct re-export inventory"
        );
    }

    fn assert_whole_ancillary_reexport_inventory_v1(source: &str, gate: &str) {
        assert!(
            macro_definition_names_v1(source).is_empty(),
            "{gate}: whole ancillary production forbids macro-defined export surfaces"
        );
        let invocations = macro_invocations_v1(source);
        let expected_macro_counts = [
            ("core::mem::offset_of", 15_usize),
            ("debug_assert_eq", 1_usize),
            ("format", 1_usize),
            ("rustix::cmsg_space", 1_usize),
            ("write", 16_usize),
        ];
        assert_eq!(
            invocations.len(),
            expected_macro_counts
                .iter()
                .map(|(_, count)| *count)
                .sum::<usize>(),
            "{gate}: whole ancillary macro invocation inventory drifted"
        );
        for (path, expected) in expected_macro_counts {
            assert_eq!(
                invocations
                    .iter()
                    .filter(|invocation| invocation.path == path)
                    .count(),
                expected,
                "{gate}: whole ancillary macro path `{path}` drifted"
            );
        }
        let mut expected = [
            "ClosedResultSendInputV1",
            "GeneratorBoundReceiveInputV1",
            "GeneratorBoundReceivedEndpointV1",
            "GeneratorChannelV1",
            "GeneratorCommitReceiveInputV1",
            "GeneratorCommitReceivedEndpointV1",
            "GeneratorRevealReceiveInputV1",
            "GeneratorRevealReceivedEndpointV1",
            "SessionOfferSendInputV1",
            "SupervisorCommitSendInputV1",
            "SupervisorGeneratorEndpointV1",
            "SupervisorGeneratorSendOpV1",
            "SupervisorGeneratorSentEndpointV1",
            "SupervisorRevealSendInputV1",
            "SupervisorTypedTransitionErrorV1",
            "SupervisorWorkerBootstrapSendOpV1",
            "SupervisorWorkerEndpointV1",
            "WorkerBootstrapEnqueuedEndpointV1",
            "WorkerBootstrapSendInputV1",
            "WorkerChannelV1",
            "WorkerExecBoundReceiveInputV1",
            "WorkerExecBoundReceivedEndpointV1",
            "create_generator_channel_v1",
            "create_worker_channel_v1",
            "prepare_closed_result_send_v1",
            "prepare_session_offer_send_v1",
            "prepare_supervisor_commit_send_v1",
            "prepare_supervisor_reveal_send_v1",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(
            crate_private_selected_reexports_v1(source, 2, gate),
            expected,
            "{gate}: direct crate-private selected-target re-export inventory drifted"
        );
        assert_whole_ancillary_fabrication_closure_v1(source, gate);
        assert_whole_ancillary_visible_item_inventory_v1(source, gate);
        assert_whole_ancillary_top_level_suffix_v1(source, gate);
    }

    fn expected_whole_ancillary_top_level_suffix_v1() -> String {
        let target_cfg = "#[cfg(all(target_arch=,target_os=,target_env=))]";
        let feature_cfg = "#[cfg(feature=)]";
        format!(
            "{target_cfg}{}{target_cfg}{feature_cfg}{}{target_cfg}{}{target_cfg}{feature_cfg}{}",
            expected_public_selected_reexport_v1(),
            expected_g0_public_selected_reexport_v1(),
            expected_base_private_selected_reexport_v1(),
            expected_g0_private_selected_reexport_v1(),
        )
    }

    fn assert_whole_ancillary_top_level_suffix_v1(source: &str, gate: &str) {
        let strict_model = find_braced_declaration_v1(source, "mod", "strict_model", gate);
        assert_eq!(
            source.matches(strict_model).count(),
            1,
            "{gate}: strict_model root declaration inventory drifted"
        );
        let start = source
            .find(strict_model)
            .expect("strict_model root declaration exists")
            + strict_model.len();
        assert_eq!(
            normalized_code_v1(&source[start..]),
            expected_whole_ancillary_top_level_suffix_v1(),
            "{gate}: top-level public/private exports must be the exact live musl suffix"
        );
    }

    fn assert_whole_ancillary_top_level_suffix_fixtures_v1() {
        let masked_cfg = "#[cfg(all(target_arch=,target_os=,target_env=))]";
        let source_cfg =
            "#[cfg(all(target_arch=\"x86_64\",target_os=\"linux\",target_env=\"musl\"))]";
        let source_feature_cfg = "#[cfg(feature=\"h0-tmpfs-provider-v2-g0\")]";
        let source_suffix = expected_whole_ancillary_top_level_suffix_v1()
            .replace(masked_cfg, source_cfg)
            .replace("#[cfg(feature=)]", source_feature_cfg);
        let valid = format!("mod strict_model {{}} {}", source_suffix);
        assert_whole_ancillary_top_level_suffix_v1(
            &valid,
            "whole ancillary suffix positive fixture",
        );
        let dead_cfg = "#[cfg(all(target_arch=\"x86_64\",target_os=\"linux\",target_env=\"musl\"))]pub(crate)usestrict_model::selected_target::{";
        let mutant = valid.replace(
            dead_cfg,
            "#[cfg(any())]pub(crate)usestrict_model::selected_target::{",
        ) + "#[cfg(all(target_arch=\"x86_64\",target_os=\"linux\",target_env=\"musl\"))]pub(crate)usestrict_model::selected_target::*;";
        let rejected = std::panic::catch_unwind(|| {
            assert_whole_ancillary_top_level_suffix_v1(
                &mutant,
                "dead named export plus live glob negative fixture",
            )
        });
        assert!(
            rejected.is_err(),
            "dead exact named export plus live glob must be rejected"
        );
    }

    fn expected_macro_v1(path: &str, context: &str) -> MacroInvocationV1 {
        MacroInvocationV1 {
            path: path.to_owned(),
            context: context.to_owned(),
        }
    }

    fn assert_exact_macro_inventories_v1() {
        assert!(
            macro_definition_names_v1(ancillary_selected_v1()).is_empty(),
            "selected_target forbids macro definitions"
        );
        assert!(
            macro_definition_names_v1(root_production_v1()).is_empty(),
            "lib.rs production forbids macro definitions"
        );
        assert!(
            macro_definition_names_v1(session_production_v1()).is_empty(),
            "session.rs production forbids macro definitions"
        );
        assert_eq!(
            macro_invocations_v1(ancillary_selected_v1()),
            [
                expected_macro_v1("debug_assert_eq", "receive_for_peer_v1"),
                expected_macro_v1("format", "observe_final_result_physical_pass_v1"),
                expected_macro_v1("rustix::cmsg_space", "send_seqpacket_once_v1"),
            ],
            "selected_target macro path/context/count inventory drifted",
        );
        assert_eq!(
            macro_invocations_v1(root_production_v1()),
            [
                expected_macro_v1("cfg", "<module>"),
                expected_macro_v1("compile_error", "<module>"),
            ],
            "lib.rs production macro path/context/count inventory drifted",
        );
        assert!(
            macro_invocations_v1(session_production_v1()).is_empty(),
            "session.rs production forbids every macro invocation at every depth",
        );
    }

    fn assert_macro_scanner_fixtures_v1() {
        let fixture = "struct Hidden { field: make_transport![u8] } fn route() { emit_transport!({ nested() }); if left != right && !flag {} }";
        assert_eq!(
            macro_invocations_v1(fixture),
            [
                expected_macro_v1("emit_transport", "route"),
                expected_macro_v1("make_transport", "<module>"),
            ],
            "macro scanner must detect function-call and type-position macros while excluding != and unary !",
        );
        assert!(
            macro_invocations_v1("type Alias = type_transport!(OpaqueStateV1);")
                .iter()
                .any(|invocation| invocation.path == "type_transport"),
            "direct type-position macro must be detected",
        );
        assert!(
            macro_invocations_v1("fn route() { call_transport ! (); }")
                .iter()
                .any(|invocation| invocation.path == "call_transport"
                    && invocation.context == "route"),
            "direct call macro with whitespace on both sides of ! must be detected",
        );
        assert_eq!(
            macro_invocations_v1("r#transport::r#send! { token }")[0].path,
            "r#transport::r#send",
            "raw-identifier SimplePath macro must be retained exactly",
        );
        assert!(
            macro_invocations_v1("#![allow(dead_code)]").is_empty(),
            "inner attributes are not macro invocations"
        );
        assert_eq!(
            macro_definition_names_v1("macro_rules! hidden { () => {} }"),
            ["macro_rules:hidden"],
            "root macro_rules definition must be detected",
        );
    }

    fn extern_function_inventory_v1(source: &str) -> Vec<(String, Option<String>)> {
        let mask = rust_code_mask_v1(source);
        let bytes = mask.as_bytes();
        let mut result = Vec::new();
        let mut cursor = 0_usize;
        while let Some(relative) = mask[cursor..].find("extern") {
            let extern_at = cursor + relative;
            cursor = extern_at + "extern".len();
            if !token_boundary_v1(bytes, extern_at, "extern".len()) {
                continue;
            }
            let abi_at = skip_ws_v1(source.as_bytes(), cursor);
            if !source[abi_at..].starts_with("\"C\"") {
                continue;
            }
            let opening = mask[abi_at + 3..]
                .find('{')
                .map(|offset| abi_at + 3 + offset)
                .expect("extern C block must have a body");
            let closing = closing_brace_v1(bytes, opening, "extern C inventory");
            let body = &mask[opening + 1..closing];
            let fn_at = body
                .find("fn")
                .expect("extern C block must declare a function");
            let name_start = skip_ws_v1(body.as_bytes(), fn_at + 2);
            let name_end = body[name_start..]
                .find('(')
                .map(|offset| name_start + offset)
                .expect("extern C function must have arguments");
            let name = body[name_start..name_end].trim().to_owned();
            let fn_absolute = opening + 1 + fn_at;
            let prefix_start = opening + 1;
            let prefix_mask = &mask[prefix_start..fn_absolute];
            let link_name = prefix_mask.rfind("link_name").map(|relative_name| {
                let name_at = prefix_start + relative_name;
                let attribute_start = mask[prefix_start..name_at]
                    .rfind("#[")
                    .map(|relative| prefix_start + relative)
                    .expect("link_name must be inside a function attribute");
                let attribute_end = mask[name_at..]
                    .find(']')
                    .map(|offset| name_at + offset + 1)
                    .expect("link_name attribute must close");
                source[attribute_start..attribute_end]
                    .split_whitespace()
                    .collect::<String>()
            });
            result.push((name, link_name));
            cursor = closing + 1;
        }
        result
    }

    fn assert_sole_kernel_send_closure_v1(source: &str, gate: &str) {
        let selected = find_braced_declaration_v1(source, "mod", "selected_target", gate);
        let compact = normalized_code_v1(selected);
        assert_eq!(
            extern_function_inventory_v1(selected),
            [(
                "c_recvmsg".to_owned(),
                Some("#[link_name=\"recvmsg\"]".to_owned())
            )],
            "{gate}: selected C5 FFI allowlist drifted",
        );
        assert_eq!(
            compact.matches("#[link_name=").count(),
            1,
            "{gate}: exactly one link_name is allowed"
        );
        assert_eq!(
            extern_function_inventory_v1(selected).len(),
            1,
            "{gate}: exactly one extern C block is allowed"
        );
        assert_eq!(
            token_count_v1(selected, "extern"),
            1,
            "{gate}: every extern ABI is closed except C5 c_recvmsg"
        );
        for forbidden in [
            "asm!(",
            "global_asm!(",
            "syscall(",
            "libc::syscall",
            "rustix::io::write(",
            "rustix::io::writev(",
            "rustix::net::send(",
            "rustix::net::sendto(",
            "rustix::net::sendmmsg(",
            "libc::sendmsg(",
            "c_sendmsg(",
        ] {
            assert!(
                !compact.contains(forbidden),
                "{gate}: alternate kernel-send route `{forbidden}`"
            );
        }
        assert_eq!(
            compact.matches("rustix::net::sendmsg(").count(),
            1,
            "{gate}: exactly one rustix sendmsg route is allowed"
        );
        assert_eq!(
            token_call_count_v1(selected, "sendmsg"),
            1,
            "{gate}: aliases/wrappers may not add a sendmsg call"
        );
        for alternate in [
            "send", "sendto", "sendmmsg", "write", "writev", "pwrite", "pwritev", "syscall",
        ] {
            assert_eq!(
                token_call_count_v1(selected, alternate),
                0,
                "{gate}: alternate kernel-send call `{alternate}` is forbidden"
            );
        }
    }

    fn assert_kernel_send_fixture_v1() {
        let source = "mod selected_target { unsafe extern \"C\" { #[link_name = \"recvmsg\"] fn c_recvmsg(); } fn send_seqpacket_once_v1() { rustix::net::sendmsg(); } unsafe extern \"C\" { #[link_name = \"sendmsg\"] fn hidden_send(); } }";
        let result = std::panic::catch_unwind(|| {
            assert_sole_kernel_send_closure_v1(source, "FFI alias fixture")
        });
        assert!(
            result.is_err(),
            "a second link_name/extern send route must be rejected"
        );
    }

    fn assert_no_live_constructor_or_caller_v1(session: &str, root: &str, gate: &str) {
        let root_compact = normalized_code_v1(root);
        assert_eq!(
            root_compact.matches("pub(crate)modsession;").count(),
            1,
            "{gate}: exact private session module declaration required"
        );
        assert_eq!(
            root_compact.matches("session::").count(),
            0,
            "{gate}: crate root may not call any G0a session route"
        );
        for function in &allowed_session_function_names_v1()[..11] {
            assert_eq!(
                token_count_v1(root, function),
                0,
                "{gate}: crate root gained caller/import for `{function}`"
            );
        }
        let session_compact = normalized_code_v1(session);
        assert_session_function_allowlist_v1(session, gate);
        for (name, owner) in [
            (
                "RelinquishedChildEndpointsV1",
                Some("send_offer_before_nonce_exchange_v1"),
            ),
            (
                "GeneratorAwaitBoundTranscriptStateV1",
                Some("send_offer_before_nonce_exchange_v1"),
            ),
            (
                "GeneratorTranscriptStateV1",
                Some("advance_generator_bound_after_kernel_success_v1"),
            ),
            (
                "WorkerAwaitBootstrapTranscriptStateV1",
                Some("send_offer_before_nonce_exchange_v1"),
            ),
            (
                "WorkerTranscriptStateV1",
                Some("advance_worker_bootstrap_after_kernel_success_v1"),
            ),
            (
                "AggregateCountV1",
                Some("send_offer_before_nonce_exchange_v1"),
            ),
            (
                "ExecutableSessionCompositeV1",
                Some("send_offer_before_nonce_exchange_v1"),
            ),
            (
                "GeneratorBoundPendingV1",
                Some("send_offer_before_nonce_exchange_v1"),
            ),
            (
                "PrivateSupervisorSessionCoreV1",
                Some("receive_then_advance_generator_bound_v1"),
            ),
            (
                "PostReleaseSessionCustodyV1",
                Some("enqueue_then_release_worker_v1"),
            ),
            (
                "WorkerBootstrapReleasedV1",
                Some("enqueue_then_release_worker_v1"),
            ),
            (
                "WorkerExecBoundAcceptedV1",
                Some("receive_then_advance_worker_exec_bound_v1"),
            ),
            (
                "ResultQueuedV1",
                Some("enqueue_then_advance_closed_result_v1"),
            ),
        ] {
            let constructor = format!("{name}{{");
            let declaration_count = session_compact
                .matches(&format!("struct{constructor}"))
                .count();
            let inherent_impl_count = session_compact
                .matches(&format!("impl{constructor}"))
                .count();
            let owner_count = owner.map_or(0, |function| {
                normalized_code_v1(find_function_v1(session, function, gate))
                    .matches(&constructor)
                    .count()
            });
            assert_eq!(
                session_compact.matches(&constructor).count(),
                declaration_count + inherent_impl_count + owner_count,
                "{gate}: `{name}` gained a constructor outside its sole affine transition"
            );
            assert_eq!(
                owner_count,
                usize::from(owner.is_some()),
                "{gate}: `{name}` constructor inventory drifted"
            );
        }
        let begin = normalized_code_v1(find_function_v1(
            session,
            "begin_after_parent_endpoint_relinquishment_v1",
            gate,
        ));
        let offer = normalized_code_v1(find_function_v1(
            session,
            "send_offer_before_nonce_exchange_v1",
            gate,
        ));
        assert_eq!(
            session_compact
                .matches("PrivateSessionPhaseV1::AwaitSessionOffer{")
                .count(),
            2,
            "{gate}: pre-session phase must occur only in begin construction and send-offer destructure"
        );
        require_once_v1(
            &begin,
            "PrivateSessionPhaseV1::AwaitSessionOffer{",
            "pre-session phase constructor",
        );
        require_once_v1(
            &offer,
            "PrivateSessionPhaseV1::AwaitSessionOffer{",
            "pre-session phase consumer",
        );
    }

    fn assert_no_live_fixture_v1() {
        let result = std::panic::catch_unwind(|| {
            session_function_names_v1(
                "fn begin_after_parent_endpoint_relinquishment_v1() {} fn launch() {}",
                "launch-entry fixture",
            );
        });
        assert!(
            result.is_err(),
            "an arbitrary launch entry must be rejected without relying on a run/start/serve denylist"
        );
    }

    fn canonical_toml_line_v1(source: &str) -> Option<String> {
        let mut output = String::new();
        let mut quote = None;
        let mut escaped = false;
        for character in source.chars() {
            match quote {
                Some('"') => {
                    output.push(character);
                    if escaped {
                        escaped = false;
                    } else if character == '\\' {
                        escaped = true;
                    } else if character == '"' {
                        quote = None;
                    }
                }
                Some('\'') => {
                    output.push(character);
                    if character == '\'' {
                        quote = None;
                    }
                }
                Some(_) => unreachable!("bounded TOML quote state"),
                None => match character {
                    '#' => break,
                    '"' | '\'' => {
                        quote = Some(character);
                        output.push(character);
                    }
                    character if character.is_whitespace() => {}
                    _ => output.push(character),
                },
            }
        }
        if quote.is_some() || escaped {
            None
        } else {
            Some(output)
        }
    }

    fn toml_semantic_lines_from_v1(source: &str) -> Option<Vec<String>> {
        let mut lines = Vec::new();
        for line in source.lines() {
            let line = canonical_toml_line_v1(line)?;
            if !line.is_empty() {
                lines.push(line);
            }
        }
        Some(lines)
    }

    fn exact_cargo_inventory_v1() -> Vec<String> {
        [
            "[package]",
            "name=\"eip0045-h0-linux-abi\"",
            "build=false",
            "workspace=\"../..\"",
            "description=\"Isolated exact-target Linux ABI boundary for the EIP-0045 H0 appliance\"",
            "version.workspace=true",
            "edition.workspace=true",
            "rust-version.workspace=true",
            "license.workspace=true",
            "authors.workspace=true",
            "publish.workspace=true",
            "[[test]]",
            "name=\"worker-post-exec-fd-inventory\"",
            "path=\"tests/worker_post_exec_fd_inventory.rs\"",
            "harness=false",
            "required-features=[\"h0-tmpfs-provider-v2-g0\"]",
            "[[bin]]",
            "name=\"worker-post-exec-fd-inventory-leaf\"",
            "path=\"tests/fixtures/worker_post_exec_fd_inventory_leaf.rs\"",
            "test=false",
            "bench=false",
            "doc=false",
            "harness=false",
            "required-features=[\"h0-tmpfs-provider-v2-g0\"]",
            "[features]",
            "default=[]",
            "h0-tmpfs-provider-v2-g0=[]",
            "[dependencies]",
            "eip0045-h0-contract={path=\"../contract\",default-features=false}",
            "[target.'cfg(all(target_arch = \"x86_64\", target_os = \"linux\", target_env = \"musl\"))'.dependencies]",
            "rustix={version=\"=1.1.4\",default-features=false,features=[\"std\",\"event\",\"fs\",\"mount\",\"net\",\"process\",\"thread\",\"time\"]}",
            "[lints.rust]",
            "unsafe_code=\"allow\"",
            "unsafe_op_in_unsafe_fn=\"deny\"",
            "missing_docs=\"warn\"",
            "[lints.clippy]",
            "all=\"warn\"",
            "pedantic=\"warn\"",
            "[package.metadata.eip0045]",
            "selected-target=\"x86_64-unknown-linux-musl\"",
            "linux-version=\"v7.1.8\"",
            "linux-commit=\"25c76bea853d0db65b51fb4697a47cbfd9e35e76\"",
            "rustix-version=\"1.1.4\"",
            "rustix-crate-sha256=\"b6fe4565b9518b83ef4f91bb47ce29620ca828bd32cb7e408f0062e9930ba190\"",
            "non-selected-target-policy=\"inventory-only\"",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    fn toml_semantic_lines_v1() -> Vec<String> {
        toml_semantic_lines_from_v1(CARGO_SOURCE_V1)
            .expect("frozen Cargo inventory must contain only bounded single-line strings")
    }

    fn cargo_inventory_matches_exact_v1(source: &str) -> bool {
        toml_semantic_lines_from_v1(source).is_some_and(|lines| lines == exact_cargo_inventory_v1())
    }

    fn assert_cargo_inventory_source_v1(source: &str) {
        let lines = toml_semantic_lines_from_v1(source)
            .expect("Cargo inventory contains an unterminated single-line string");
        assert_eq!(
            lines,
            exact_cargo_inventory_v1(),
            "Cargo semantic inventory drifted from the complete frozen manifest"
        );
    }

    fn assert_cargo_inventory_v1() {
        assert_cargo_inventory_source_v1(CARGO_SOURCE_V1);
    }

    fn assert_cargo_inventory_fixture_v1() {
        assert!(
            cargo_inventory_matches_exact_v1(CARGO_SOURCE_V1),
            "current frozen Cargo fixture must be accepted"
        );
        let missing_build_false = CARGO_SOURCE_V1.replace("build = false\n", "");
        assert_ne!(
            missing_build_false, CARGO_SOURCE_V1,
            "missing-build fixture must mutate the frozen inventory"
        );
        assert!(
            !cargo_inventory_matches_exact_v1(&missing_build_false),
            "a missing package build=false must be rejected"
        );
        let enabled_build_script = CARGO_SOURCE_V1.replace("build = false", "build = \"build.rs\"");
        assert_ne!(
            enabled_build_script, CARGO_SOURCE_V1,
            "enabled-build fixture must mutate the frozen inventory"
        );
        assert!(
            !cargo_inventory_matches_exact_v1(&enabled_build_script),
            "an enabled package build-script route must be rejected"
        );
        let legacy = CARGO_SOURCE_V1
            .replace(
                "all(target_arch = \"x86_64\", target_os = \"linux\", target_env = \"musl\")",
                "all(target_os = \"linux\", target_env = \"musl\")",
            )
            .replace(
                "rustix = { version = \"=1.1.4\", default-features = false, features = [\"std\", \"event\", \"fs\", \"mount\", \"net\", \"process\", \"thread\", \"time\"] }",
                "rustix = { version = \"0.38.44\", default-features = false, features = [\"fs\", \"mount\", \"net\", \"process\", \"thread\"] }",
            );
        assert_ne!(
            legacy, CARGO_SOURCE_V1,
            "legacy Cargo fixture must mutate the frozen inventory"
        );
        assert!(
            !cargo_inventory_matches_exact_v1(&legacy),
            "legacy 0.38/no-target_arch Cargo inventory must be rejected"
        );
        let shadow_lib = format!("{CARGO_SOURCE_V1}\n[lib]\npath = \"shadow.rs\"\n");
        assert!(
            !cargo_inventory_matches_exact_v1(&shadow_lib),
            "an alternate Cargo library root must be rejected"
        );
        let quoted_shadow_lib =
            format!("{CARGO_SOURCE_V1}\n[\"lib\"]\npath = \"src/session.rs\"\n");
        assert!(
            !cargo_inventory_matches_exact_v1(&quoted_shadow_lib),
            "a quoted alternate Cargo library root must be rejected"
        );
        let dotted_shadow_lib = format!("{CARGO_SOURCE_V1}\n\"lib\".path = \"src/session.rs\"\n");
        assert!(
            !cargo_inventory_matches_exact_v1(&dotted_shadow_lib),
            "a dotted alternate Cargo library root must be rejected"
        );
    }

    #[test]
    fn private_supervisor_typed_transport_v1() {
        assert_signature_visibility_fixture_v1();
        assert_opaque_inventory_fixtures_v1();
        assert_exact_pre_session_input_layout_fixtures_v1();
        assert_exact_pre_session_consumer_fixtures_v1();
        assert_macro_scanner_fixtures_v1();
        assert_uninhabited_semantic_join_fixtures_v1();
        assert_selected_target_source_shape_fixtures_v1();
        assert_whole_ancillary_reexport_inventory_fixtures_v1();
        assert_whole_ancillary_fabrication_closure_fixtures_v1();
        assert_contract_candidate_provenance_fixtures_v1();
        assert_contract_crate_root_unshadowed_fixtures_v1();
        assert_whole_ancillary_visible_item_inventory_fixtures_v1();
        assert_whole_ancillary_top_level_suffix_fixtures_v1();
        assert_whole_ancillary_successor_impl_closure_fixtures_v1();
        assert_transitive_source_closure_fixtures_v1();
        assert_exact_transitive_source_closure_v1();
        assert_exact_macro_inventories_v1();
        let ancillary = ancillary_selected_v1();
        assert_whole_ancillary_successor_impl_closure_v1(
            ancillary_production_v1(),
            ancillary,
            "whole ancillary successor impl location closure",
        );
        assert_whole_ancillary_reexport_inventory_v1(
            ancillary_production_v1(),
            "whole ancillary private re-export closure",
        );
        assert_selected_target_source_shape_v1(ancillary, "private selected-target source shape");
        assert_contract_candidate_provenance_v1(
            ancillary,
            ancillary_production_v1(),
            2,
            1,
            "ancillary contract transcript candidate provenance",
        );
        assert_contract_crate_root_unshadowed_v1(
            root_production_v1(),
            "contract crate-root provenance closure",
        );
        assert_crate_private_typed_input_inventory_v1(
            ancillary,
            &typed_input_specs_v1(),
            "private typed supervisor transport input inventory",
        );
        assert_exact_pre_session_input_layouts_v1(
            ancillary,
            ancillary_production_v1(),
            "exact pre-session typed input layouts",
        );
        assert_exact_pre_session_consumers_and_helpers_v1(
            ancillary,
            "exact affine pre-session ancillary consumers",
        );
        assert_transcript_candidate_producers_v1(
            ancillary,
            ancillary_production_v1(),
            "private transcript candidate producer inventory",
        );
        assert_exact_candidate_receive_helpers_v1(
            ancillary,
            "private exact candidate receive helpers",
        );
        assert_crate_private_received_endpoint_inventory_v1(
            ancillary,
            "private typed supervisor receive inventory",
        );
        assert_generator_phase_closure_v1(ancillary, "private typed supervisor phase closure");
        assert_no_module_level_macro_v1(
            ancillary,
            1,
            "private typed supervisor transport inventory",
        );
        for operation in [
            "SupervisorGeneratorSendOpV1",
            "SupervisorWorkerBootstrapSendOpV1",
        ] {
            let declaration = find_braced_declaration_v1(
                ancillary,
                "struct",
                operation,
                "existing D6b sealed operation",
            );
            require_code_v1(
                declaration,
                "PreparedSupervisorSendV1",
                "existing D6b operation must retain the common prepared packet",
            );
            assert!(
                normalized_code_v1(declaration).starts_with(&format!("struct{operation}")),
                "existing D6b operation must remain a direct struct declaration"
            );
            assert!(
                normalized_code_v1(ancillary).contains(&format!("pub(crate)struct{operation}")),
                "existing D6b operation must remain crate-private"
            );
        }
    }

    #[test]
    fn parent_child_endpoint_relinquished_before_first_enqueue_v1() {
        let session = session_production_v1();
        let transition = find_function_v1(
            session,
            "begin_after_parent_endpoint_relinquishment_v1",
            "parent child-endpoint relinquishment join",
        );
        assert_eq!(
            normalized_code_v1(transition).replace(",)->", ")->"),
            "fnbegin_after_parent_endpoint_relinquishment_v1(relinquished:RelinquishedChildEndpointsV1,seal:UninhabitedSessionInputV1)->PrivateSessionPhaseV1{PrivateSessionPhaseV1::AwaitSessionOffer{seal,relinquished}}",
            "G0a begin must move the sole relinquished carrier and seal into the exact private pre-session phase"
        );
        for forbidden in [
            "spawn_generator_once_v1",
            "spawn_worker_once_v1",
            "enqueue_once_v1",
        ] {
            assert_eq!(
                token_count_v1(transition, forbidden),
                0,
                "parent relinquishment join cannot perform `{forbidden}`"
            );
        }
    }

    #[test]
    fn supervisor_transport_reuses_single_sendmsg_v1() {
        assert_kernel_send_fixture_v1();
        let ancillary = ancillary_selected_v1();
        assert_sole_kernel_send_closure_v1(
            ancillary_production_v1(),
            "sole kernel-send/FFI closure",
        );
        assert_no_hidden_source_shapes_v1("sole sendmsg selected target", ancillary);
        assert_no_module_level_macro_v1(ancillary, 1, "sole sendmsg selected target");
        let helper = find_function_v1(ancillary, "send_seqpacket_once_v1", "sole sendmsg helper");
        let preparation = find_function_v1(
            ancillary,
            "prepare_supervisor_typed_send_v1",
            "shared typed supervisor preparation",
        );
        require_code_v1(
            preparation,
            "PreparedSupervisorSendV1",
            "shared typed supervisor preparation result",
        );
        assert_eq!(
            rust_code_mask_v1(ancillary)
                .matches("rustix::net::sendmsg(")
                .count(),
            1,
            "all supervisor transports must retain the sole sendmsg site"
        );
        require_once_v1(helper, "rustix::net::sendmsg(", "sole sendmsg helper");
        assert_eq!(
            token_count_v1(ancillary, "sendmsg"),
            1,
            "aliases, wrappers, and extra sendmsg symbols are forbidden"
        );
        for builder in [
            "prepare_session_offer_send_v1",
            "prepare_supervisor_commit_send_v1",
            "prepare_supervisor_reveal_send_v1",
        ] {
            let body = find_function_v1(ancillary, builder, "typed builder callgraph");
            require_once_v1(
                body,
                "prepare_supervisor_typed_send_v1(",
                "typed builder callgraph",
            );
            assert_propagates_without_swallow_v1(
                body,
                "prepare_supervisor_typed_send_v1(",
                "typed builder preparation failure",
            );
        }
        for candidate in [
            "receive_generator_bound_once_v1",
            "prepare_worker_bootstrap_send_v1",
            "receive_worker_exec_bound_once_v1",
            "prepare_closed_result_send_v1",
        ] {
            let body = find_function_v1(ancillary, candidate, "candidate carrier consumer");
            assert_eq!(
                normalized_code_v1(body)
                    .matches("prepare_supervisor_typed_send_v1(")
                    .count()
                    + normalized_code_v1(body)
                        .matches("prepare_supervisor_typed_receive_v1(")
                        .count(),
                0,
                "candidate `{candidate}` must not replace its prepared carrier"
            );
        }
    }

    #[test]
    fn session_core_has_no_raw_transport_v1() {
        assert_session_root_source_shape_fixtures_v1();
        assert_exact_session_typestate_layout_fixtures_v1();
        let session = session_production_v1();
        assert_session_root_source_shape_v1(session, "private supervisor session root shape");
        assert!(
            macro_invocations_v1(session).is_empty(),
            "session production must remain macro-free at every depth",
        );
        assert_no_hidden_source_shapes_v1("private supervisor session core", session);
        assert_no_module_level_macro_v1(session, 0, "private supervisor session core");
        assert_session_error_closure_v1(session, "private supervisor session error closure");
        assert_exact_session_typestate_layouts_v1(
            session,
            "exact private supervisor session typestates",
        );
        assert_eq!(
            token_count_v1(session, "pub"),
            0,
            "session production may expose no item or field outside its crate-private root module"
        );
        for forbidden in [
            "OwnedFd",
            "RawFd",
            "BorrowedFd",
            "UCred",
            "sendmsg",
            "recvmsg",
            "WireFrameV1",
            "FrameInputV1",
            "ExpectedPeerCredentialsV1",
            "DescriptorIdentityV1",
            "unsafe",
        ] {
            assert!(
                !identifiers_v1(session)
                    .iter()
                    .any(|token| token == forbidden),
                "session core contains raw or generic transport surface: {forbidden}"
            );
        }
        let compact = normalized_code_v1(session);
        for forbidden in ["Vec<u8>", "&[u8]", "*const", "*mut", "extern\"C\""] {
            assert!(
                !compact.contains(forbidden),
                "session core contains raw carrier `{forbidden}`"
            );
        }
    }

    #[test]
    fn session_offer_send_v1() {
        let ancillary = ancillary_selected_v1();
        let builder = find_function_v1(
            ancillary,
            "prepare_session_offer_send_v1",
            "typed SessionOffer send builder",
        );
        assert_exact_function_signature_v1(
            builder,
            "fn prepare_session_offer_send_v1(endpoint: SupervisorGeneratorEndpointV1, input: SessionOfferSendInputV1) -> Result<SupervisorGeneratorSendOpV1, SupervisorTypedTransitionErrorV1>",
            "typed SessionOffer send builder",
        );
        require_order_v1(
            builder,
            &[
                "fn prepare_session_offer_send_v1(",
                "SessionOfferSendInputV1",
                "SupervisorGeneratorSendOpV1",
                "{",
                "prepare_supervisor_typed_send_v1(",
                "&[]",
            ],
            "SessionOffer must be encoded into its sealed send operation",
        );
        require_once_v1(
            builder,
            "prepare_supervisor_typed_send_v1(",
            "SessionOffer typed builder",
        );
        for (function, signature) in [
            (
                "receive_generator_nonce_commit_once_v1",
                "fn receive_generator_nonce_commit_once_v1(self, input: GeneratorCommitReceiveInputV1) -> Result<GeneratorCommitReceivedEndpointV1, SupervisorTypedTransitionErrorV1>",
            ),
            (
                "prepare_supervisor_commit_send_v1",
                "fn prepare_supervisor_commit_send_v1(endpoint: GeneratorCommitReceivedEndpointV1, input: SupervisorCommitSendInputV1) -> Result<SupervisorGeneratorSendOpV1, SupervisorTypedTransitionErrorV1>",
            ),
            (
                "receive_generator_nonce_reveal_once_v1",
                "fn receive_generator_nonce_reveal_once_v1(self, input: GeneratorRevealReceiveInputV1) -> Result<GeneratorRevealReceivedEndpointV1, SupervisorTypedTransitionErrorV1>",
            ),
            (
                "prepare_supervisor_reveal_send_v1",
                "fn prepare_supervisor_reveal_send_v1(endpoint: GeneratorRevealReceivedEndpointV1, input: SupervisorRevealSendInputV1) -> Result<SupervisorGeneratorSendOpV1, SupervisorTypedTransitionErrorV1>",
            ),
        ] {
            assert_exact_function_signature_v1(
                find_function_v1(ancillary, function, "typed nonce exchange surface"),
                signature,
                "typed nonce exchange surface",
            );
        }
        let transition = find_function_v1(
            session_production_v1(),
            "send_offer_before_nonce_exchange_v1",
            "SessionOffer before nonce exchange",
        );
        assert_linear_transition_body_v1(
            transition,
            "fn send_offer_before_nonce_exchange_v1(state: PrivateSessionPhaseV1, session_offer: SessionOfferSendInputV1, generator_commit: GeneratorCommitReceiveInputV1, supervisor_commit: SupervisorCommitSendInputV1, generator_reveal: GeneratorRevealReceiveInputV1, supervisor_reveal: SupervisorRevealSendInputV1) -> Result<GeneratorBoundPendingV1, SessionTransitionErrorV1>",
            &[
                LinearStatementV1::Exact(
                    "let PrivateSessionPhaseV1::AwaitSessionOffer { seal, relinquished } = state",
                ),
                LinearStatementV1::Exact(
                    "let RelinquishedChildEndpointsV1 { generator_endpoint, worker_endpoint, generator_executable, worker_executable } = relinquished",
                ),
                LinearStatementV1::Exact(
                    "let operation = prepare_session_offer_send_v1(generator_endpoint, session_offer)?",
                ),
                LinearStatementV1::Exact(
                    "let (offer_before, generator_endpoint) = generator_executable.enqueue_supervisor_generator_once_v1(operation)?",
                ),
                LinearStatementV1::Exact(
                    "let offer_after = generator_executable.supervisor_receive_projection_v1()?",
                ),
                LinearStatementV1::Exact(
                    "require_equal_projection_v1(&offer_before, &offer_after)?",
                ),
                LinearStatementV1::Exact(
                    "let commit_before = generator_executable.supervisor_receive_projection_v1()?",
                ),
                LinearStatementV1::Exact(
                    "let commit_endpoint = generator_endpoint.receive_generator_nonce_commit_once_v1(generator_commit)?",
                ),
                LinearStatementV1::Exact(
                    "let commit_after = generator_executable.supervisor_receive_projection_v1()?",
                ),
                LinearStatementV1::Exact(
                    "require_equal_projection_v1(&commit_before, &commit_after)?",
                ),
                LinearStatementV1::Exact(
                    "let operation = prepare_supervisor_commit_send_v1(commit_endpoint, supervisor_commit)?",
                ),
                LinearStatementV1::Exact(
                    "let (commit_send_before, generator_endpoint) = generator_executable.enqueue_supervisor_generator_once_v1(operation)?",
                ),
                LinearStatementV1::Exact(
                    "let commit_send_after = generator_executable.supervisor_receive_projection_v1()?",
                ),
                LinearStatementV1::Exact(
                    "require_equal_projection_v1(&commit_send_before, &commit_send_after)?",
                ),
                LinearStatementV1::Exact(
                    "let reveal_before = generator_executable.supervisor_receive_projection_v1()?",
                ),
                LinearStatementV1::Exact(
                    "let reveal_endpoint = generator_endpoint.receive_generator_nonce_reveal_once_v1(generator_reveal)?",
                ),
                LinearStatementV1::Exact(
                    "let reveal_after = generator_executable.supervisor_receive_projection_v1()?",
                ),
                LinearStatementV1::Exact(
                    "require_equal_projection_v1(&reveal_before, &reveal_after)?",
                ),
                LinearStatementV1::Exact(
                    "let operation = prepare_supervisor_reveal_send_v1(reveal_endpoint, supervisor_reveal)?",
                ),
                LinearStatementV1::Exact(
                    "let (reveal_send_before, generator_endpoint) = generator_executable.enqueue_supervisor_generator_once_v1(operation)?",
                ),
                LinearStatementV1::Exact(
                    "let reveal_send_after = generator_executable.supervisor_receive_projection_v1()?",
                ),
                LinearStatementV1::Exact(
                    "require_equal_projection_v1(&reveal_send_before, &reveal_send_after)?",
                ),
                LinearStatementV1::Exact(
                    "let successor = GeneratorBoundPendingV1 { seal, generator_endpoint, worker_endpoint, generator: GeneratorAwaitBoundTranscriptStateV1 { generator_cursor: 0 }, worker: WorkerAwaitBootstrapTranscriptStateV1 { worker_cursor: 0 }, aggregate_count: AggregateCountV1 { frames: 0 }, executable: ExecutableSessionCompositeV1 { generator: generator_executable, worker: worker_executable } }",
                ),
            ],
            "Ok(successor)",
            "exact affine SessionOffer and nonce exchange transition",
        );
    }

    #[test]
    fn worker_bootstrap_send_v1() {
        let builder = find_function_v1(
            ancillary_selected_v1(),
            "prepare_worker_bootstrap_send_v1",
            "typed worker-bootstrap send builder",
        );
        require_order_v1(
            builder,
            &[
                "fn prepare_worker_bootstrap_send_v1(",
                "WorkerBootstrapSendInputV1",
                "SupervisorWorkerBootstrapSendOpV1",
                "{",
                "input.frame.encode_raw_frame(",
                "input.prepared.frame",
                "let operation = SupervisorWorkerBootstrapSendOpV1 {",
                "prepared: input.prepared",
            ],
            "worker bootstrap must consume its uninhabited semantic/prepared carrier",
        );
        assert_eq!(
            normalized_code_v1(builder)
                .matches("prepare_supervisor_typed_send_v1(")
                .count(),
            0,
            "worker-bootstrap candidate may not replace its prepared carrier"
        );
    }

    #[test]
    fn closed_result_v1() {
        let builder = find_function_v1(
            ancillary_selected_v1(),
            "prepare_closed_result_send_v1",
            "typed ClosedResult send builder",
        );
        require_order_v1(
            builder,
            &[
                "fn prepare_closed_result_send_v1(",
                "ClosedResultSendInputV1",
                "SupervisorGeneratorSendOpV1",
                "{",
                "input.frame.encode_raw_frame(",
                "input.prepared.frame",
                "let operation = SupervisorGeneratorSendOpV1 {",
                "prepared: input.prepared",
            ],
            "ClosedResult must consume its uninhabited semantic/prepared carrier",
        );
        assert_eq!(
            normalized_code_v1(builder)
                .matches("prepare_supervisor_typed_send_v1(")
                .count(),
            0,
            "ClosedResult candidate may not replace its prepared carrier"
        );
        let transition = find_function_v1(
            session_production_v1(),
            "enqueue_then_advance_closed_result_v1",
            "ClosedResult outbound transition",
        );
        require_order_v1(
            transition,
            &[
                "state.aggregate_count.require_capacity_v1(",
                "prepare_closed_result_send_v1(",
                "enqueue_supervisor_generator_once_v1(",
                ".advance_closed_result_after_kernel_success_v1(",
                "supervisor_receive_projection_v1(",
                "require_equal_projection_v1(",
            ],
            "ClosedResult must advance before its second projection equality",
        );
        assert_projection_transition_v1(
            transition,
            "supervisor_receive_projection_v1(",
            "enqueue_supervisor_generator_once_v1(",
            ".advance_closed_result_after_kernel_success_v1(",
            ProjectionTransitionOrderV1::Outbound,
            "ClosedResult projection equality",
        );
        assert_outbound_kernel_tuple_v1(
            transition,
            "enqueue_supervisor_generator_once_v1(",
            "before",
            "sent_endpoint",
            "ClosedResult D6b projection/endpoint join",
        );
        assert_propagates_without_swallow_v1(
            transition,
            "enqueue_supervisor_generator_once_v1(",
            "ClosedResult enqueue failure",
        );
        assert_candidate_flow_v1(
            transition,
            "prepare_closed_result_send_v1(",
            "state.accepted_generator.endpoint,input,state.generator.generator_previous_digest",
            "operation",
            Some(("enqueue_supervisor_generator_once_v1(", "operation")),
            None,
            ".advance_closed_result_after_kernel_success_v1(",
            "state.generator=state.generator.advance_closed_result_after_kernel_success_v1(candidate)?;",
            "ClosedResult candidate provenance",
        );
        assert_aggregate_transition_v1(
            transition,
            "prepare_closed_result_send_v1(",
            "enqueue_supervisor_generator_once_v1(",
            ".advance_closed_result_after_kernel_success_v1(",
            Some("supervisor_receive_projection_v1("),
            "ClosedResult aggregate transition",
        );
    }

    #[test]
    fn external_cannot_accept_or_construct_advanced_state() {
        let session = session_production_v1();
        assert_private_opaque_inventory_v1(
            session,
            &[
                "AcceptedGeneratorFrameV1",
                "GeneratorAwaitBoundTranscriptStateV1",
                "GeneratorTranscriptStateV1",
                "WorkerAwaitBootstrapTranscriptStateV1",
                "WorkerTranscriptStateV1",
                "AggregateCountV1",
                "RelinquishedChildEndpointsV1",
                "ExecutableSessionCompositeV1",
                "PostReleaseSessionCustodyV1",
                "GeneratorBoundPendingV1",
                "PrivateSupervisorSessionCoreV1",
                "WorkerBootstrapReleasedV1",
                "WorkerExecBoundAcceptedV1",
                "ResultQueuedV1",
            ],
            "private accepted generator state",
        );
        let accepted_generator = find_braced_declaration_v1(
            session,
            "struct",
            "AcceptedGeneratorFrameV1",
            "private accepted generator endpoint custody",
        );
        assert_eq!(
            normalized_code_v1(accepted_generator),
            "structAcceptedGeneratorFrameV1{endpoint:GeneratorBoundReceivedEndpointV1,}",
            "accepted GeneratorBound state must retain only its typed generator endpoint custody"
        );
        assert_uninhabited_session_seal_v1(session, "private accepted generator state");
        let compact = normalized_code_v1(session);
        for forbidden in [
            "pubfnaccept",
            "pub(crate)fnaccept",
            "pubfnadvanced",
            "pub(crate)fnadvanced",
            "Default",
            "serde",
            "deserialize",
            "into_parts",
            "callback",
        ] {
            assert!(
                !compact.contains(forbidden),
                "accepted or advanced state is externally constructible: {forbidden}"
            );
        }
    }

    #[test]
    fn contract_cursor_is_non_authorizing_v1() {
        let session = session_production_v1();
        let generator = find_braced_declaration_v1(
            session,
            "struct",
            "GeneratorTranscriptStateV1",
            "private generator transcript owner",
        );
        let worker = find_braced_declaration_v1(
            session,
            "struct",
            "WorkerTranscriptStateV1",
            "private worker transcript owner",
        );
        for (declaration, cursor, digest) in [
            (generator, "generator_cursor", "generator_previous_digest"),
            (worker, "worker_cursor", "worker_previous_digest"),
        ] {
            require_once_v1(declaration, cursor, "private transcript cursor");
            require_once_v1(declaration, digest, "private transcript previous digest");
            require_once_v1(
                declaration,
                &format!("{cursor}: u8"),
                "private numeric transcript cursor field",
            );
            require_once_v1(
                declaration,
                &format!("{digest}: [u8; 32]"),
                "private transcript digest bytes field",
            );
            assert!(
                !normalized_code_v1(declaration).contains("aggregate_count"),
                "one aggregate count must not be duplicated into a channel owner"
            );
        }
        require_once_v1(
            generator,
            "accepted_worker_genesis",
            "private GeneratorBound worker-genesis anchor",
        );
        require_once_v1(
            generator,
            "accepted_worker_genesis: [u8; 32]",
            "private GeneratorBound worker-genesis bytes",
        );
        let aggregate = find_braced_declaration_v1(
            session,
            "struct",
            "AggregateCountV1",
            "private aggregate count owner",
        );
        assert_eq!(
            normalized_code_v1(aggregate),
            "structAggregateCountV1{frames:u8,}",
            "the single aggregate count must be one private bounded scalar"
        );
        assert_eq!(
            normalized_code_v1(session)
                .matches("AggregateCountV1{frames:0}")
                .count(),
            1,
            "G0a must initialize its single aggregate owner exactly once after the nonce exchange"
        );
        require_once_v1(
            find_function_v1(
                session,
                "send_offer_before_nonce_exchange_v1",
                "aggregate zero initialization owner",
            ),
            "AggregateCountV1 { frames: 0 }",
            "sole aggregate zero initialization after pre-session records",
        );
        assert!(
            !identifiers_v1(session)
                .iter()
                .any(|token| token == "TranscriptCursorV1"),
            "public contract cursor cannot represent session authority"
        );
        let compact = normalized_code_v1(session);
        for forbidden in [
            "pubfncursor",
            "pub(crate)fncursor",
            "pubfnaggregate_count",
            "pub(crate)fnaggregate_count",
            "pubfnprevious_digest",
            "pub(crate)fnprevious_digest",
            "pubfnworker_genesis",
            "pub(crate)fnworker_genesis",
        ] {
            assert!(
                !compact.contains(forbidden),
                "cursor/count getter escaped: {forbidden}"
            );
        }
    }

    #[test]
    fn pre_kernel_failure_leaves_transcript_unadvanced() {
        assert_exact_question_fixture_v1();
        assert_projection_gate_fixtures_v1();
        assert_inbound_success_fixtures_v1();
        assert_linear_transition_fixtures_v1();
        let session = session_production_v1();
        assert_equal_projection_helper_v1(session);
        let generator = find_function_v1(
            session,
            "receive_then_advance_generator_bound_v1",
            "inbound generator transition",
        );
        require_order_v1(
            generator,
            &[
                "fn receive_then_advance_generator_bound_v1(",
                "state.aggregate_count.require_capacity_v1(",
                "supervisor_receive_projection_v1(",
                "receive_generator_bound_once_v1(",
                "supervisor_receive_projection_v1(",
                "require_equal_projection_v1(",
                ".advance_generator_bound_after_kernel_success_v1(",
            ],
            "generator state may advance only after receive and second projection equality",
        );
        assert_projection_transition_v1(
            generator,
            "supervisor_receive_projection_v1(",
            "receive_generator_bound_once_v1(",
            ".advance_generator_bound_after_kernel_success_v1(",
            ProjectionTransitionOrderV1::Inbound,
            "GeneratorBound projection equality",
        );
        assert_propagates_without_swallow_v1(
            generator,
            "receive_generator_bound_once_v1(",
            "GeneratorBound receive failure",
        );
        assert_candidate_flow_v1(
            generator,
            "receive_generator_bound_once_v1(",
            "input",
            "received_endpoint",
            None,
            Some("let successor = PrivateSupervisorSessionCoreV1 {"),
            ".advance_generator_bound_after_kernel_success_v1(",
            "letgenerator=state.generator.advance_generator_bound_after_kernel_success_v1(candidate)?;",
            "GeneratorBound candidate provenance",
        );
        assert_aggregate_transition_v1(
            generator,
            "receive_generator_bound_once_v1(",
            "receive_generator_bound_once_v1(",
            ".advance_generator_bound_after_kernel_success_v1(",
            None,
            "GeneratorBound aggregate transition",
        );
        assert_linear_transition_body_v1(
            generator,
            "fn receive_then_advance_generator_bound_v1(mut state: GeneratorBoundPendingV1, input: GeneratorBoundReceiveInputV1) -> Result<PrivateSupervisorSessionCoreV1, SessionTransitionErrorV1>",
            &[
                LinearStatementV1::Exact("state.aggregate_count.require_capacity_v1()?"),
                LinearStatementV1::StateCall {
                    prefix: "let before = ",
                    receiver: "state.executable.generator",
                    method: "supervisor_receive_projection_v1",
                    arguments: "",
                },
                LinearStatementV1::StateCall {
                    prefix: "let (received_endpoint, candidate) = ",
                    receiver: "state.generator_endpoint",
                    method: "receive_generator_bound_once_v1",
                    arguments: "input",
                },
                LinearStatementV1::StateCall {
                    prefix: "let after = ",
                    receiver: "state.executable.generator",
                    method: "supervisor_receive_projection_v1",
                    arguments: "",
                },
                LinearStatementV1::Exact("require_equal_projection_v1(&before, &after)?"),
                LinearStatementV1::Exact(
                    "let generator = state.generator.advance_generator_bound_after_kernel_success_v1(candidate)?",
                ),
                LinearStatementV1::Exact(
                    "state.aggregate_count = state.aggregate_count.advance_after_kernel_success_v1()?",
                ),
                LinearStatementV1::Exact(
                    "let successor = PrivateSupervisorSessionCoreV1 { seal: state.seal, accepted_generator: AcceptedGeneratorFrameV1 { endpoint: received_endpoint }, worker_endpoint: state.worker_endpoint, generator, worker: state.worker, aggregate_count: state.aggregate_count, executable: state.executable }",
                ),
            ],
            "Ok(successor)",
            "GeneratorBound exact linear transition body",
        );
        let worker = find_function_v1(
            session,
            "receive_then_advance_worker_exec_bound_v1",
            "inbound WorkerExecBound transition",
        );
        require_order_v1(
            worker,
            &[
                "state.aggregate_count.require_capacity_v1(",
                "supervisor_receive_projection_v1(",
                "receive_worker_exec_bound_once_v1(",
                "supervisor_receive_projection_v1(",
                "require_equal_projection_v1(",
                ".advance_worker_exec_bound_after_kernel_success_v1(",
            ],
            "WorkerExecBound state may advance only after receive and second projection equality",
        );
        assert_projection_transition_v1(
            worker,
            "supervisor_receive_projection_v1(",
            "receive_worker_exec_bound_once_v1(",
            ".advance_worker_exec_bound_after_kernel_success_v1(",
            ProjectionTransitionOrderV1::Inbound,
            "WorkerExecBound projection equality",
        );
        assert_propagates_without_swallow_v1(
            worker,
            "receive_worker_exec_bound_once_v1(",
            "WorkerExecBound receive failure",
        );
        assert_candidate_flow_v1(
            worker,
            "receive_worker_exec_bound_once_v1(",
            "input,state.worker.worker_previous_digest",
            "worker_received",
            None,
            Some("let successor = WorkerExecBoundAcceptedV1 {"),
            ".advance_worker_exec_bound_after_kernel_success_v1(",
            "state.worker=state.worker.advance_worker_exec_bound_after_kernel_success_v1(candidate)?;",
            "WorkerExecBound candidate provenance",
        );
        assert_aggregate_transition_v1(
            worker,
            "receive_worker_exec_bound_once_v1(",
            "receive_worker_exec_bound_once_v1(",
            ".advance_worker_exec_bound_after_kernel_success_v1(",
            None,
            "WorkerExecBound aggregate transition",
        );
        assert_linear_transition_body_v1(
            worker,
            "fn receive_then_advance_worker_exec_bound_v1(mut state: WorkerBootstrapReleasedV1, input: WorkerExecBoundReceiveInputV1) -> Result<WorkerExecBoundAcceptedV1, SessionTransitionErrorV1>",
            &[
                LinearStatementV1::Exact("state.aggregate_count.require_capacity_v1()?"),
                LinearStatementV1::StateCall {
                    prefix: "let before = ",
                    receiver: "state.executable.worker",
                    method: "supervisor_receive_projection_v1",
                    arguments: "",
                },
                LinearStatementV1::StateCall {
                    prefix: "let (worker_received, candidate) = ",
                    receiver: "state.bootstrap_enqueued",
                    method: "receive_worker_exec_bound_once_v1",
                    arguments: "input, state.worker.worker_previous_digest",
                },
                LinearStatementV1::StateCall {
                    prefix: "let after = ",
                    receiver: "state.executable.worker",
                    method: "supervisor_receive_projection_v1",
                    arguments: "",
                },
                LinearStatementV1::Exact("require_equal_projection_v1(&before, &after)?"),
                LinearStatementV1::Exact(
                    "state.worker = state.worker.advance_worker_exec_bound_after_kernel_success_v1(candidate)?",
                ),
                LinearStatementV1::Exact(
                    "state.aggregate_count = state.aggregate_count.advance_after_kernel_success_v1()?",
                ),
                LinearStatementV1::Exact(
                    "let successor = WorkerExecBoundAcceptedV1 { seal: state.seal, accepted_generator: state.accepted_generator, generator: state.generator, worker: state.worker, aggregate_count: state.aggregate_count, executable: state.executable, worker_received }",
                ),
            ],
            "Ok(successor)",
            "WorkerExecBound exact linear transition body",
        );
    }

    #[test]
    fn kernel_success_advances_transcript_once() {
        assert_checked_transcript_advance_fixtures_v1();
        assert_contract_crate_root_unshadowed_v1(
            root_production_v1(),
            "kernel transcript contract crate-root provenance",
        );
        assert_contract_candidate_provenance_v1(
            session_production_v1(),
            session_production_v1(),
            1,
            0,
            "session contract transcript candidate provenance",
        );
        assert_candidate_flow_fixtures_v1();
        let session = session_production_v1();
        let aggregate_impls = inherent_impl_blocks_v1(session, "AggregateCountV1");
        assert_eq!(
            aggregate_impls.len(),
            1,
            "aggregate count must retain one exact inherent implementation"
        );
        let capacity = find_function_v1(
            aggregate_impls[0],
            "require_capacity_v1",
            "aggregate capacity guard",
        );
        let aggregate_advance = find_function_v1(
            aggregate_impls[0],
            "advance_after_kernel_success_v1",
            "aggregate kernel-success advance",
        );
        assert!(
            aggregate_capacity_valid_v1(capacity),
            "aggregate capacity must fail closed before the 64th counted frame"
        );
        assert!(
            aggregate_advance_valid_v1(aggregate_advance),
            "aggregate count must advance by checked +1 only after kernel success"
        );
        for (transition, cursor, digest, candidate, successor, worker_genesis) in [
            (
                "advance_generator_bound_after_kernel_success_v1",
                "generator_cursor",
                "generator_previous_digest",
                "G0GeneratorBoundTranscriptCandidateV1",
                Some("GeneratorTranscriptStateV1"),
                true,
            ),
            (
                "advance_worker_bootstrap_after_kernel_success_v1",
                "worker_cursor",
                "worker_previous_digest",
                "G0TranscriptCandidateV1",
                Some("WorkerTranscriptStateV1"),
                false,
            ),
            (
                "advance_worker_exec_bound_after_kernel_success_v1",
                "worker_cursor",
                "worker_previous_digest",
                "G0TranscriptCandidateV1",
                None,
                false,
            ),
            (
                "advance_closed_result_after_kernel_success_v1",
                "generator_cursor",
                "generator_previous_digest",
                "G0TranscriptCandidateV1",
                None,
                false,
            ),
        ] {
            let body =
                find_function_v1(session, transition, "kernel-success transcript transition");
            assert_checked_cursor_advance_v1(
                body,
                transition,
                cursor,
                digest,
                candidate,
                successor,
                worker_genesis,
                "kernel-success transcript transition",
            );
            let calls = rust_code_mask_v1(session)
                .matches(&format!(".{transition}("))
                .count();
            assert_eq!(
                calls, 1,
                "{transition} must have exactly one production call site"
            );
        }
        assert_eq!(
            rust_code_mask_v1(session)
                .matches(".require_capacity_v1(")
                .count(),
            4,
            "each counted G0 transition must check the single aggregate capacity"
        );
        assert_eq!(
            rust_code_mask_v1(session)
                .matches(".advance_after_kernel_success_v1(")
                .count(),
            4,
            "each counted G0 transition must advance the single aggregate exactly once"
        );
    }

    #[test]
    fn post_enqueue_failure_contains_without_rollback_or_resend() {
        let session = session_production_v1();
        find_braced_declaration_v1(
            session,
            "struct",
            "ResultQueuedV1",
            "post-enqueue queued-result owner",
        );
        let bootstrap = find_function_v1(
            session,
            "enqueue_then_release_worker_v1",
            "worker-bootstrap outbound transition",
        );
        require_order_v1(
            bootstrap,
            &[
                "fn enqueue_then_release_worker_v1(",
                "state.aggregate_count.require_capacity_v1(",
                "prepare_worker_bootstrap_send_v1(",
                "enqueue_supervisor_bootstrap_once_v1(",
                ".advance_worker_bootstrap_after_kernel_success_v1(",
                "worker_bootstrap_projection_v1(",
                "require_equal_projection_v1(",
                "release_after_bootstrap_enqueued_v1(",
            ],
            "enqueue must precede advance, second projection, and worker release",
        );
        assert_projection_transition_v1(
            bootstrap,
            "worker_bootstrap_projection_v1(",
            "enqueue_supervisor_bootstrap_once_v1(",
            ".advance_worker_bootstrap_after_kernel_success_v1(",
            ProjectionTransitionOrderV1::Outbound,
            "worker-bootstrap projection equality",
        );
        assert_outbound_kernel_tuple_v1(
            bootstrap,
            "enqueue_supervisor_bootstrap_once_v1(",
            "before",
            "bootstrap_enqueued",
            "worker-bootstrap D6b projection/endpoint join",
        );
        assert_propagates_without_swallow_v1(
            bootstrap,
            "enqueue_supervisor_bootstrap_once_v1(",
            "worker-bootstrap enqueue failure",
        );
        assert_candidate_flow_v1(
            bootstrap,
            "prepare_worker_bootstrap_send_v1(",
            "input,state.generator.accepted_worker_genesis",
            "operation",
            Some(("enqueue_supervisor_bootstrap_once_v1(", "operation")),
            None,
            ".advance_worker_bootstrap_after_kernel_success_v1(",
            "letworker_transcript=state.worker.advance_worker_bootstrap_after_kernel_success_v1(candidate)?;",
            "worker-bootstrap candidate provenance",
        );
        assert_aggregate_transition_v1(
            bootstrap,
            "prepare_worker_bootstrap_send_v1(",
            "enqueue_supervisor_bootstrap_once_v1(",
            ".advance_worker_bootstrap_after_kernel_success_v1(",
            Some("worker_bootstrap_projection_v1("),
            "worker-bootstrap aggregate transition",
        );
        assert_linear_transition_body_v1(
            bootstrap,
            "fn enqueue_then_release_worker_v1(mut state: PrivateSupervisorSessionCoreV1, input: WorkerBootstrapSendInputV1) -> Result<WorkerBootstrapReleasedV1, SessionTransitionErrorV1>",
            &[
                LinearStatementV1::Exact("state.aggregate_count.require_capacity_v1()?"),
                LinearStatementV1::StateCall {
                    prefix: "let (operation, candidate) = ",
                    receiver: "state.worker_endpoint",
                    method: "prepare_worker_bootstrap_send_v1",
                    arguments: "input, state.generator.accepted_worker_genesis",
                },
                LinearStatementV1::StateCall {
                    prefix: "let (before, bootstrap_enqueued) = ",
                    receiver: "state.executable.worker",
                    method: "enqueue_supervisor_bootstrap_once_v1",
                    arguments: "operation",
                },
                LinearStatementV1::Exact(
                    "let worker_transcript = state.worker.advance_worker_bootstrap_after_kernel_success_v1(candidate)?",
                ),
                LinearStatementV1::Exact(
                    "state.aggregate_count = state.aggregate_count.advance_after_kernel_success_v1()?",
                ),
                LinearStatementV1::StateCall {
                    prefix: "let after = ",
                    receiver: "state.executable.worker",
                    method: "worker_bootstrap_projection_v1",
                    arguments: "",
                },
                LinearStatementV1::Exact("require_equal_projection_v1(&before, &after)?"),
                LinearStatementV1::StateCall {
                    prefix: "let worker = ",
                    receiver: "state.executable.worker",
                    method: "release_after_bootstrap_enqueued_v1",
                    arguments: "&bootstrap_enqueued",
                },
                LinearStatementV1::Exact(
                    "let successor = WorkerBootstrapReleasedV1 { seal: state.seal, accepted_generator: state.accepted_generator, generator: state.generator, worker: worker_transcript, aggregate_count: state.aggregate_count, executable: PostReleaseSessionCustodyV1 { generator: state.executable.generator, worker }, bootstrap_enqueued }",
                ),
            ],
            "Ok(successor)",
            "worker-bootstrap exact linear transition body",
        );
        let closed = find_function_v1(
            session,
            "enqueue_then_advance_closed_result_v1",
            "ClosedResult outbound transition",
        );
        assert_projection_transition_v1(
            closed,
            "supervisor_receive_projection_v1(",
            "enqueue_supervisor_generator_once_v1(",
            ".advance_closed_result_after_kernel_success_v1(",
            ProjectionTransitionOrderV1::Outbound,
            "ClosedResult post-enqueue projection equality",
        );
        assert_propagates_without_swallow_v1(
            closed,
            "enqueue_supervisor_generator_once_v1(",
            "ClosedResult enqueue failure",
        );
        assert_linear_transition_body_v1(
            closed,
            "fn enqueue_then_advance_closed_result_v1(mut state: WorkerExecBoundAcceptedV1, input: ClosedResultSendInputV1) -> Result<ResultQueuedV1, SessionTransitionErrorV1>",
            &[
                LinearStatementV1::Exact("state.aggregate_count.require_capacity_v1()?"),
                LinearStatementV1::Exact(
                    "let (operation, candidate) = prepare_closed_result_send_v1(state.accepted_generator.endpoint, input, state.generator.generator_previous_digest)?",
                ),
                LinearStatementV1::StateCall {
                    prefix: "let (before, sent_endpoint) = ",
                    receiver: "state.executable.generator",
                    method: "enqueue_supervisor_generator_once_v1",
                    arguments: "operation",
                },
                LinearStatementV1::Exact(
                    "state.generator = state.generator.advance_closed_result_after_kernel_success_v1(candidate)?",
                ),
                LinearStatementV1::Exact(
                    "state.aggregate_count = state.aggregate_count.advance_after_kernel_success_v1()?",
                ),
                LinearStatementV1::StateCall {
                    prefix: "let after = ",
                    receiver: "state.executable.generator",
                    method: "supervisor_receive_projection_v1",
                    arguments: "",
                },
                LinearStatementV1::Exact("require_equal_projection_v1(&before, &after)?"),
                LinearStatementV1::Exact(
                    "let result_queued = ResultQueuedV1 { seal: state.seal, sent_endpoint, generator: state.generator, worker: state.worker, aggregate_count: state.aggregate_count, executable: state.executable, worker_received: state.worker_received }",
                ),
            ],
            "Ok(result_queued)",
            "ClosedResult exact linear transition body",
        );
        for forbidden in ["fn retry", "fn resend", "fn rollback", "fn rewind"] {
            assert!(
                !rust_code_mask_v1(session).contains(forbidden),
                "post-enqueue state exposes recovery authority: {forbidden}"
            );
        }
    }

    #[test]
    fn friend_crate_access_is_impossible() {
        let session = session_production_v1();
        assert_eq!(
            macro_invocations_v1(root_production_v1()),
            [
                expected_macro_v1("cfg", "<module>"),
                expected_macro_v1("compile_error", "<module>"),
            ],
            "crate-root macro inventory drifted",
        );
        find_braced_declaration_v1(
            session,
            "struct",
            "GeneratorBoundPendingV1",
            "same-crate session join",
        );
        require_code_v1(
            root_production_v1(),
            "pub(crate) mod session;",
            "crate-private feature-gated session module",
        );
        let root = normalized_code_v1(root_production_v1());
        assert_eq!(
            root.matches("pub(crate)modsession;").count(),
            1,
            "crate root must declare exactly one crate-private session module"
        );
        for forbidden in [
            "pubmodsession;",
            "pubusesession",
            "pubusecrate::session",
            "pub(crate)usesession",
        ] {
            assert!(
                !root.contains(forbidden),
                "friend-crate access route exists: {forbidden}"
            );
        }
        let compact = normalized_code_v1(session);
        assert!(!compact.contains("pubstructGeneratorBoundPendingV1"));
        assert!(!compact.contains("pub(crate)structGeneratorBoundPendingV1"));
    }

    #[test]
    fn raw_spawn_release_surface_is_absent() {
        let session = session_production_v1();
        let transition = find_function_v1(
            session,
            "enqueue_then_release_worker_v1",
            "private enqueue-before-release transition",
        );
        for forbidden in [
            "spawn_generator_once_v1(",
            "spawn_worker_once_v1(",
            "release_after_checked_maps(",
            "release_after_checked_maps_v1(",
            "pub fn release",
            "pub(crate) fn release",
        ] {
            assert!(
                !rust_code_mask_v1(session).contains(forbidden),
                "raw spawn/release surface entered session core: {forbidden}"
            );
        }
        require_once_v1(
            transition,
            "release_after_bootstrap_enqueued_v1(",
            "token-bound worker release",
        );
        require_order_v1(
            transition,
            &[
                "enqueue_supervisor_bootstrap_once_v1(",
                "release_after_bootstrap_enqueued_v1(",
            ],
            "release must remain downstream of the exact bootstrap enqueue",
        );
    }

    #[test]
    fn executable_session_composite_is_private() {
        let session = session_production_v1();
        assert_exact_session_typestate_layouts_v1(
            session,
            "executable/session affine typestate composite",
        );
        let compact = normalized_code_v1(session);
        for state in [
            "ExecutableSessionCompositeV1",
            "PostReleaseSessionCustodyV1",
            "GeneratorBoundPendingV1",
            "PrivateSupervisorSessionCoreV1",
            "WorkerBootstrapReleasedV1",
            "WorkerExecBoundAcceptedV1",
            "ResultQueuedV1",
        ] {
            assert!(!compact.contains(&format!("pubstruct{state}")));
            assert!(!compact.contains(&format!("pub(crate)struct{state}")));
            let declaration = find_braced_declaration_v1(
                session,
                "struct",
                state,
                "private executable/session affine typestate",
            );
            for forbidden in ["into_parts", "AsFd", "AsRawFd", "BorrowedFd", "OwnedFd"] {
                assert_eq!(
                    token_count_v1(declaration, forbidden),
                    0,
                    "typestate `{state}` exposes `{forbidden}`"
                );
            }
        }
    }

    #[test]
    fn linux_abi_dependency_direction_v1() {
        assert_cargo_inventory_fixture_v1();
        assert_cargo_inventory_v1();
        assert_contract_crate_root_unshadowed_v1(
            root_production_v1(),
            "direct contract dependency crate-root provenance",
        );
        assert_contract_candidate_provenance_v1(
            session_production_v1(),
            session_production_v1(),
            1,
            0,
            "session direct contract candidate dependency",
        );
        require_code_v1(
            session_production_v1(),
            "use eip0045_h0_contract::wire::{",
            "safe contract dependency consumer",
        );
        let cargo = toml_semantic_lines_v1().join("");
        for forbidden in [
            "eip0045-h0-reproduction",
            "eip0045-h0-generator",
            "h0-child-entry",
            "path = \"../reproduction\"",
            "path = \"../generator\"",
        ] {
            assert!(
                !cargo.contains(forbidden),
                "forbidden linux-abi dependency direction: {forbidden}"
            );
        }
    }

    #[test]
    fn g0_has_no_live_entry() {
        assert_no_live_fixture_v1();
        let session = session_production_v1();
        assert_no_live_constructor_or_caller_v1(
            session,
            root_production_v1(),
            "pre-BA0 constructor/caller inventory",
        );
        find_braced_declaration_v1(
            session,
            "enum",
            "PrivateSessionPhaseV1",
            "unreachable private G0 session owner",
        );
        assert_cargo_inventory_v1();
        let compact = normalized_code_v1(session);
        for forbidden in [
            "fnmain(",
            "pubfnrun(",
            "pub(crate)fnrun(",
            "pubfnstart(",
            "pub(crate)fnstart(",
            "pubfnserve(",
            "pub(crate)fnserve(",
            "no_mangle",
            "export_name",
        ] {
            assert!(
                !compact.contains(forbidden),
                "live G0 entry exists: {forbidden}"
            );
        }
    }

    #[test]
    fn g0_has_no_boot_or_h0_authority_surface() {
        let session = session_production_v1();
        find_braced_declaration_v1(
            session,
            "enum",
            "PrivateSessionPhaseV1",
            "private non-authorizing session phase",
        );
        let tokens = identifiers_v1(session);
        for forbidden in [
            "Booted",
            "VerifiedBootAuthority",
            "H0Authority",
            "SourceAuthority",
            "VerifiedBootAuthorityV1",
            "SourceAuthorityV1",
            "ProviderAuthorityV1",
        ] {
            assert!(
                !tokens.iter().any(|token| token == forbidden),
                "boot or H0 authority entered G0a: {forbidden}"
            );
        }
        let compact = normalized_code_v1(session);
        for forbidden in [
            "pubfnboot",
            "pub(crate)fnboot",
            "pubfnh0",
            "pub(crate)fnh0",
            "fnprovider_entry",
            "fnsource_entry",
        ] {
            assert!(
                !compact.contains(forbidden),
                "boot/H0 entry entered G0a: {forbidden}"
            );
        }
    }
}
