//! Non-authorizing phase labels for the H0 attempt protocol.

use core::fmt;

/// Number of labels in the sole successful attempt order.
pub const ATTEMPT_PHASE_COUNT_V1: usize = 25;

/// One non-authorizing label in the compiled successful attempt order.
///
/// These values describe protocol progress only. They contain no descriptor,
/// kernel result, session ownership, boot capability, or source capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AttemptPhaseV1 {
    /// External boot evidence has been accepted by its separate owner.
    ExternalBootEvidenceAccepted = 0,
    /// The measured supervisor has started.
    SupervisorStarted = 1,
    /// The generator process and its closed inventory have been bound.
    GeneratorBound = 2,
    /// One fresh attempt namespace/cgroup allocation has been created.
    AttemptAllocated = 3,
    /// The worker child is blocked before user-map installation.
    WorkerBlocked = 4,
    /// Exact UID/GID maps and the empty supplementary-group state match.
    UserMapsVerified = 5,
    /// The retained measured worker executable and inventory match.
    WorkerExecBound = 6,
    /// The worker has acknowledged the exact sealed manifest.
    ManifestAcknowledged = 7,
    /// The phase-specific process restrictions have been installed and read back.
    ProcessSealed = 8,
    /// The provider-owned tmpfs is live under the worker continuation.
    MountedLive = 9,
    /// Parent and child live-state observations have joined.
    ParentChildLiveBarrierJoined = 10,
    /// The complete non-rootfs observation has been staged.
    ObservationStaged = 11,
    /// All four role roots have been cleaned.
    RootfsCleaned = 12,
    /// The final no-acquire process restrictions have been installed.
    NoAcquireSealed = 13,
    /// Ordinary flags-zero unmount has succeeded.
    OrdinaryUnmounted = 14,
    /// Worker exit has been observed without reaping it yet.
    ExitObserved = 15,
    /// The same worker has been reaped.
    Reaped = 16,
    /// The attempt cgroup population is zero.
    CgroupZero = 17,
    /// Attempt-local names have been removed through retained anchors.
    NamesRemoved = 18,
    /// The supervisor's initial inventory has been restored.
    InventoryRestored = 19,
    /// The supervisor-produced final result bytes are fully sealed.
    ResultSealed = 20,
    /// The aggregate supervisor-side attempt is closed.
    Closed = 21,
    /// The one result transfer has been queued.
    ResultQueued = 22,
    /// The generator has minted its private source in the separate runtime owner.
    SourceMinted = 23,
    /// Create-only commit and exact reopen have completed.
    GeneratorCommitted = 24,
}

impl AttemptPhaseV1 {
    /// Labels in the only successful order.
    pub const ALL: [Self; ATTEMPT_PHASE_COUNT_V1] = [
        Self::ExternalBootEvidenceAccepted,
        Self::SupervisorStarted,
        Self::GeneratorBound,
        Self::AttemptAllocated,
        Self::WorkerBlocked,
        Self::UserMapsVerified,
        Self::WorkerExecBound,
        Self::ManifestAcknowledged,
        Self::ProcessSealed,
        Self::MountedLive,
        Self::ParentChildLiveBarrierJoined,
        Self::ObservationStaged,
        Self::RootfsCleaned,
        Self::NoAcquireSealed,
        Self::OrdinaryUnmounted,
        Self::ExitObserved,
        Self::Reaped,
        Self::CgroupZero,
        Self::NamesRemoved,
        Self::InventoryRestored,
        Self::ResultSealed,
        Self::Closed,
        Self::ResultQueued,
        Self::SourceMinted,
        Self::GeneratorCommitted,
    ];

    /// Returns the fixed one-byte wire discriminant.
    #[must_use]
    pub const fn wire_code(self) -> u8 {
        self as u8
    }

    fn next(self) -> Option<Self> {
        Self::ALL.get(usize::from(self.wire_code()) + 1).copied()
    }
}

/// A rejected mutation of the successful phase sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseErrorV1 {
    /// A same-label, skipped, or reverse transition was requested.
    NonAdjacent {
        /// Current label.
        from: AttemptPhaseV1,
        /// Requested next label.
        to: AttemptPhaseV1,
        /// Sole accepted next label.
        expected: AttemptPhaseV1,
    },
    /// The terminal label has no successor.
    Terminal {
        /// Terminal label.
        phase: AttemptPhaseV1,
    },
}

impl fmt::Display for PhaseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "H0 phase model rejected transition: {self:?}")
    }
}

impl std::error::Error for PhaseErrorV1 {}

/// A move-only, non-authorizing model of successful protocol progress.
#[derive(Debug, Eq, PartialEq)]
pub struct AttemptProgressModelV1 {
    current: AttemptPhaseV1,
}

impl AttemptProgressModelV1 {
    /// Starts the model at the first externally established label.
    #[must_use]
    pub const fn start() -> Self {
        Self {
            current: AttemptPhaseV1::ExternalBootEvidenceAccepted,
        }
    }

    /// Returns the current descriptive label.
    #[must_use]
    pub const fn current(&self) -> AttemptPhaseV1 {
        self.current
    }

    /// Consumes this model and advances exactly one compiled step.
    ///
    /// # Errors
    ///
    /// Returns [`PhaseErrorV1::NonAdjacent`] for a same-label, skipped, or
    /// reverse request, and [`PhaseErrorV1::Terminal`] after the final label.
    pub fn try_advance(self, requested: AttemptPhaseV1) -> Result<Self, PhaseErrorV1> {
        let Some(expected) = self.current.next() else {
            return Err(PhaseErrorV1::Terminal {
                phase: self.current,
            });
        };
        if requested != expected {
            return Err(PhaseErrorV1::NonAdjacent {
                from: self.current,
                to: requested,
                expected,
            });
        }
        Ok(Self { current: requested })
    }
}

#[cfg(test)]
mod affine_state {
    use super::*;

    #[test]
    fn affine_state_contains_the_exact_success_order() {
        assert_eq!(ATTEMPT_PHASE_COUNT_V1, 25);
        assert_eq!(
            AttemptPhaseV1::ALL,
            [
                AttemptPhaseV1::ExternalBootEvidenceAccepted,
                AttemptPhaseV1::SupervisorStarted,
                AttemptPhaseV1::GeneratorBound,
                AttemptPhaseV1::AttemptAllocated,
                AttemptPhaseV1::WorkerBlocked,
                AttemptPhaseV1::UserMapsVerified,
                AttemptPhaseV1::WorkerExecBound,
                AttemptPhaseV1::ManifestAcknowledged,
                AttemptPhaseV1::ProcessSealed,
                AttemptPhaseV1::MountedLive,
                AttemptPhaseV1::ParentChildLiveBarrierJoined,
                AttemptPhaseV1::ObservationStaged,
                AttemptPhaseV1::RootfsCleaned,
                AttemptPhaseV1::NoAcquireSealed,
                AttemptPhaseV1::OrdinaryUnmounted,
                AttemptPhaseV1::ExitObserved,
                AttemptPhaseV1::Reaped,
                AttemptPhaseV1::CgroupZero,
                AttemptPhaseV1::NamesRemoved,
                AttemptPhaseV1::InventoryRestored,
                AttemptPhaseV1::ResultSealed,
                AttemptPhaseV1::Closed,
                AttemptPhaseV1::ResultQueued,
                AttemptPhaseV1::SourceMinted,
                AttemptPhaseV1::GeneratorCommitted,
            ]
        );
        for (wire_code, phase) in AttemptPhaseV1::ALL.iter().copied().enumerate() {
            assert_eq!(usize::from(phase.wire_code()), wire_code);
        }
    }

    #[test]
    fn affine_state_advances_only_one_compiled_step() {
        let mut model = AttemptProgressModelV1::start();
        assert_eq!(
            model.current(),
            AttemptPhaseV1::ExternalBootEvidenceAccepted
        );

        for phase in AttemptPhaseV1::ALL.iter().copied().skip(1) {
            model = model.try_advance(phase).unwrap();
            assert_eq!(model.current(), phase);
        }
        assert_eq!(
            model.try_advance(AttemptPhaseV1::GeneratorCommitted),
            Err(PhaseErrorV1::Terminal {
                phase: AttemptPhaseV1::GeneratorCommitted,
            })
        );
    }

    #[test]
    fn affine_state_rejects_same_reverse_and_skipped_labels_independently() {
        assert_eq!(
            AttemptProgressModelV1::start()
                .try_advance(AttemptPhaseV1::ExternalBootEvidenceAccepted),
            Err(PhaseErrorV1::NonAdjacent {
                from: AttemptPhaseV1::ExternalBootEvidenceAccepted,
                to: AttemptPhaseV1::ExternalBootEvidenceAccepted,
                expected: AttemptPhaseV1::SupervisorStarted,
            })
        );
        assert_eq!(
            AttemptProgressModelV1::start().try_advance(AttemptPhaseV1::GeneratorBound),
            Err(PhaseErrorV1::NonAdjacent {
                from: AttemptPhaseV1::ExternalBootEvidenceAccepted,
                to: AttemptPhaseV1::GeneratorBound,
                expected: AttemptPhaseV1::SupervisorStarted,
            })
        );

        let advanced = AttemptProgressModelV1::start()
            .try_advance(AttemptPhaseV1::SupervisorStarted)
            .unwrap();
        assert_eq!(
            advanced.try_advance(AttemptPhaseV1::ExternalBootEvidenceAccepted),
            Err(PhaseErrorV1::NonAdjacent {
                from: AttemptPhaseV1::SupervisorStarted,
                to: AttemptPhaseV1::ExternalBootEvidenceAccepted,
                expected: AttemptPhaseV1::GeneratorBound,
            })
        );
    }

    #[test]
    fn affine_state_values_do_not_claim_runtime_authority() {
        let model = AttemptProgressModelV1::start();
        let copied_label = model.current();
        assert_eq!(copied_label, AttemptPhaseV1::ExternalBootEvidenceAccepted);
        assert_eq!(model.current(), copied_label);
    }
}
