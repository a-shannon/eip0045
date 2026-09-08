//! Exactly-once terminal capture for the pinned upstream verifier callback.

use core::cell::RefCell;

use risc0_zkp::{core::digest::Digest, verify::VerificationError};

use crate::{
    constants::{
        TERMINAL_CONTROL_KIND_JOIN, TERMINAL_CONTROL_KIND_LIFT, TERMINAL_CONTROL_KIND_RESOLVE,
    },
    profile_manifest::{StarkProfileManifestV1, TerminalControl},
};

use super::errors::B4StarkError;

/// Closed terminal-program kinds admitted by the initial profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum B4TerminalKind {
    /// Normal RV32IM lift.
    Lift,
    /// Stock recursive join.
    Join,
    /// Stock recursive resolve.
    Resolve,
}

impl B4TerminalKind {
    fn from_manifest(value: u8) -> Result<Self, B4StarkError> {
        match value {
            TERMINAL_CONTROL_KIND_LIFT => Ok(Self::Lift),
            TERMINAL_CONTROL_KIND_JOIN => Ok(Self::Join),
            TERMINAL_CONTROL_KIND_RESOLVE => Ok(Self::Resolve),
            kind => Err(B4StarkError::TerminalKindUnsupported { kind }),
        }
    }
}

/// Terminal tuple authenticated by a completed STARK verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct B4VerifiedTerminal {
    kind: B4TerminalKind,
    parameter: u8,
    control_id: [u8; 32],
}

impl B4VerifiedTerminal {
    /// Verified terminal-program kind.
    #[must_use]
    pub(super) const fn kind(self) -> B4TerminalKind {
        self.kind
    }

    /// Verified kind-specific parameter.
    #[must_use]
    pub(super) const fn parameter(self) -> u8 {
        self.parameter
    }

    /// Verified control ID in explicit little-endian word order.
    #[must_use]
    pub(super) const fn control_id(self) -> [u8; 32] {
        self.control_id
    }
}

#[derive(Debug)]
struct TerminalCaptureState {
    callback_count: u8,
    terminal: Option<B4VerifiedTerminal>,
    failure: Option<B4StarkError>,
}

/// Private exactly-once adapter for `risc0_zkp::verify::verify`.
///
/// It receives no caller-supplied control ID. Both the exponent and all ten
/// allowed code roots come from the already decoded profile manifest.
pub(super) struct TerminalCapture<'a> {
    expected_outer_po2: u32,
    controls: &'a [TerminalControl; 10],
    state: RefCell<TerminalCaptureState>,
}

impl<'a> TerminalCapture<'a> {
    pub(super) fn new(manifest: &'a StarkProfileManifestV1) -> Self {
        Self {
            expected_outer_po2: u32::from(manifest.outer_po2()),
            controls: manifest.terminal_controls(),
            state: RefCell::new(TerminalCaptureState {
                callback_count: 0,
                terminal: None,
                failure: None,
            }),
        }
    }

    pub(super) fn check_code(&self, po2: u32, code_root: &Digest) -> Result<(), VerificationError> {
        let mut state = self.state.borrow_mut();
        if state.callback_count != 0 {
            state.callback_count = state.callback_count.saturating_add(1);
            if state.failure.is_none() {
                state.failure = Some(B4StarkError::TerminalCallbackRepeated);
            }
            return Err(VerificationError::ReceiptFormatError);
        }
        state.callback_count = 1;

        if po2 != self.expected_outer_po2 {
            state.failure = Some(B4StarkError::TerminalOuterPo2Mismatch {
                actual: po2,
                expected: self.expected_outer_po2,
            });
            return Err(VerificationError::ControlVerificationError {
                control_id: *code_root,
            });
        }

        let actual = digest_words_le(code_root);
        let mut matched = None;
        for control in self.controls {
            if control.control_id() == actual {
                if matched.is_some() {
                    state.failure = Some(B4StarkError::TerminalControlIdNotAllowed { actual });
                    return Err(VerificationError::ControlVerificationError {
                        control_id: *code_root,
                    });
                }
                matched = Some(*control);
            }
        }
        let Some(control) = matched else {
            state.failure = Some(B4StarkError::TerminalControlIdNotAllowed { actual });
            return Err(VerificationError::ControlVerificationError {
                control_id: *code_root,
            });
        };
        let kind = match B4TerminalKind::from_manifest(control.control_kind()) {
            Ok(kind) => kind,
            Err(error) => {
                state.failure = Some(error);
                return Err(VerificationError::ControlVerificationError {
                    control_id: *code_root,
                });
            }
        };
        state.terminal = Some(B4VerifiedTerminal {
            kind,
            parameter: control.parameter(),
            control_id: actual,
        });
        Ok(())
    }

    pub(super) fn finish(
        self,
        upstream: Result<(), VerificationError>,
    ) -> Result<B4VerifiedTerminal, B4StarkError> {
        let state = self.state.into_inner();
        if let Some(failure) = state.failure {
            return Err(failure);
        }
        upstream.map_err(B4StarkError::from)?;
        match (state.callback_count, state.terminal) {
            (0, _) => Err(B4StarkError::TerminalCallbackMissing),
            (1, Some(terminal)) => Ok(terminal),
            _ => Err(B4StarkError::TerminalCallbackRepeated),
        }
    }
}

fn digest_words_le(digest: &Digest) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    for (index, word) in digest.as_words().iter().copied().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile_manifest::StarkProfileManifestV1;

    const MANIFEST: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");

    fn manifest() -> StarkProfileManifestV1 {
        let manifest = StarkProfileManifestV1::decode(MANIFEST).unwrap();
        manifest.validate_initial_profile_target().unwrap();
        manifest
    }

    fn digest_from_le_bytes(bytes: [u8; 32]) -> Digest {
        let mut words = [0_u32; 8];
        for (index, chunk) in bytes.chunks_exact(4).enumerate() {
            words[index] = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        Digest::from(words)
    }

    #[test]
    fn zero_callbacks_cannot_produce_a_verified_terminal() {
        let manifest = manifest();
        let capture = TerminalCapture::new(&manifest);
        assert_eq!(
            capture.finish(Ok(())),
            Err(B4StarkError::TerminalCallbackMissing)
        );
    }

    #[test]
    fn zero_callbacks_do_not_mask_an_upstream_failure() {
        let manifest = manifest();
        let capture = TerminalCapture::new(&manifest);
        assert_eq!(
            capture.finish(Err(VerificationError::ReceiptFormatError)),
            Err(B4StarkError::Risc0Verifier(
                super::super::errors::B4Risc0Failure::ReceiptFormat
            ))
        );
    }

    #[test]
    fn exactly_one_callback_captures_the_manifest_terminal() {
        let manifest = manifest();
        let control = manifest.terminal_controls()[0];
        let digest = digest_from_le_bytes(control.control_id());
        let capture = TerminalCapture::new(&manifest);

        capture
            .check_code(u32::from(manifest.outer_po2()), &digest)
            .unwrap();
        let terminal = capture.finish(Ok(())).unwrap();

        assert_eq!(terminal.kind(), B4TerminalKind::Lift);
        assert_eq!(terminal.parameter(), 15);
        assert_eq!(terminal.control_id(), control.control_id());
    }

    #[test]
    fn valid_callback_does_not_mask_a_later_upstream_failure() {
        let manifest = manifest();
        let control = manifest.terminal_controls()[0];
        let digest = digest_from_le_bytes(control.control_id());
        let capture = TerminalCapture::new(&manifest);

        capture
            .check_code(u32::from(manifest.outer_po2()), &digest)
            .unwrap();
        assert_eq!(
            capture.finish(Err(VerificationError::InvalidProof)),
            Err(B4StarkError::Risc0Verifier(
                super::super::errors::B4Risc0Failure::InvalidProof
            ))
        );
    }

    #[test]
    fn two_callbacks_are_rejected_even_when_both_are_identical() {
        let manifest = manifest();
        let control = manifest.terminal_controls()[0];
        let digest = digest_from_le_bytes(control.control_id());
        let capture = TerminalCapture::new(&manifest);

        capture
            .check_code(u32::from(manifest.outer_po2()), &digest)
            .unwrap();
        assert!(
            capture
                .check_code(u32::from(manifest.outer_po2()), &digest)
                .is_err()
        );
        assert_eq!(
            capture.finish(Err(VerificationError::ReceiptFormatError)),
            Err(B4StarkError::TerminalCallbackRepeated)
        );
    }

    #[test]
    fn callback_rejects_a_control_outside_the_manifest_allowlist() {
        let manifest = manifest();
        let digest = Digest::ZERO;
        let capture = TerminalCapture::new(&manifest);

        assert!(
            capture
                .check_code(u32::from(manifest.outer_po2()), &digest)
                .is_err()
        );
        assert_eq!(
            capture.finish(Err(VerificationError::ControlVerificationError {
                control_id: digest,
            })),
            Err(B4StarkError::TerminalControlIdNotAllowed { actual: [0; 32] })
        );
    }

    #[test]
    fn callback_checks_the_manifest_outer_po2_independently() {
        let manifest = manifest();
        let control = manifest.terminal_controls()[0];
        let digest = digest_from_le_bytes(control.control_id());
        let capture = TerminalCapture::new(&manifest);

        let actual = u32::from(manifest.outer_po2()) - 1;
        assert!(capture.check_code(actual, &digest).is_err());
        assert_eq!(
            capture.finish(Err(VerificationError::ControlVerificationError {
                control_id: digest,
            })),
            Err(B4StarkError::TerminalOuterPo2Mismatch {
                actual,
                expected: u32::from(manifest.outer_po2()),
            })
        );
    }

    #[test]
    fn digest_projection_is_explicit_little_endian_word_encoding() {
        let digest = Digest::from([
            0x0302_0100,
            0x0706_0504,
            0x0b0a_0908,
            0x0f0e_0d0c,
            0x1312_1110,
            0x1716_1514,
            0x1b1a_1918,
            0x1f1e_1d1c,
        ]);
        assert_eq!(
            digest_words_le(&digest),
            core::array::from_fn(|index| u8::try_from(index).unwrap())
        );
    }
}
