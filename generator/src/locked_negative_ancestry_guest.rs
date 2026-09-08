//! Non-selectable embedded guest authority for the E3 negative-ancestry handler.

use anyhow::{Context as _, Result, ensure};
use eip_0045_methods::{
    EIP_0045_ALTERNATE_PROGRAM_GUEST_ELF, EIP_0045_ALTERNATE_PROGRAM_GUEST_ID, EIP_0045_GUEST_ELF,
    EIP_0045_GUEST_ID,
};
#[cfg(feature = "b4-negative-ancestry-handler")]
use eip_0045_reproduction::b4_negative_ancestry_authority::{
    B4NegativeAncestrySourceAuthorityV1, B4NegativeAncestrySourceAuthorityV2,
};
use risc0_zkvm::{Digest, compute_image_id};

struct LockedGuestV1 {
    elf: &'static [u8],
    image_id: Digest,
}

pub(crate) struct LockedGuestPairV1 {
    consumer: LockedGuestV1,
    alternate: LockedGuestV1,
}

#[cfg(any(test, feature = "b4-negative-ancestry-handler"))]
fn digest_bytes(digest: &Digest) -> Result<[u8; 32]> {
    digest
        .as_bytes()
        .try_into()
        .context("RISC Zero image ID digest is not exactly 32 bytes")
}

fn require_generated_identity(
    label: &str,
    elf: &'static [u8],
    declared_words: [u32; 8],
) -> Result<LockedGuestV1> {
    ensure!(!elf.is_empty(), "{label} embedded ELF is empty");
    let computed = compute_image_id(elf)
        .with_context(|| format!("cannot recompute the embedded {label} image ID"))?;
    ensure!(
        computed == Digest::from(declared_words),
        "{label} generated image ID differs from its embedded ELF"
    );
    Ok(LockedGuestV1 {
        elf,
        image_id: computed,
    })
}

pub(crate) fn embedded_negative_ancestry_guest_pair() -> Result<LockedGuestPairV1> {
    let consumer =
        require_generated_identity("consumer guest", EIP_0045_GUEST_ELF, EIP_0045_GUEST_ID)?;
    let alternate = require_generated_identity(
        "alternate-program guest",
        EIP_0045_ALTERNATE_PROGRAM_GUEST_ELF,
        EIP_0045_ALTERNATE_PROGRAM_GUEST_ID,
    )?;
    ensure!(
        consumer.image_id != alternate.image_id,
        "alternate-program guest image ID equals the consumer guest image ID"
    );
    Ok(LockedGuestPairV1 {
        consumer,
        alternate,
    })
}

impl LockedGuestPairV1 {
    pub(crate) fn consumer(&self) -> (&'static [u8], Digest) {
        (self.consumer.elf, self.consumer.image_id)
    }

    pub(crate) fn alternate(&self) -> (&'static [u8], Digest) {
        (self.alternate.elf, self.alternate.image_id)
    }
}

#[cfg(any(test, feature = "b4-negative-ancestry-handler"))]
fn require_locked_guest_bytes(
    locked: &LockedGuestPairV1,
    consumer_elf: &[u8],
    consumer_program_id: [u8; 32],
    alternate_elf: &[u8],
    alternate_program_id: [u8; 32],
) -> Result<()> {
    ensure!(
        consumer_elf == locked.consumer.elf
            && consumer_program_id == digest_bytes(&locked.consumer.image_id)?,
        "negative-ancestry source consumer guest differs from the locked embedded consumer"
    );
    ensure!(
        alternate_elf == locked.alternate.elf
            && alternate_program_id == digest_bytes(&locked.alternate.image_id)?,
        "negative-ancestry source alternate guest differs from the locked embedded alternate"
    );
    Ok(())
}

/// Require one source authority to contain exactly the two locked embedded guests.
#[cfg(feature = "b4-negative-ancestry-handler")]
pub(crate) fn require_locked_negative_ancestry_source(
    authority: &B4NegativeAncestrySourceAuthorityV1,
) -> Result<()> {
    let locked = embedded_negative_ancestry_guest_pair()?;
    let source = authority.producer_source();
    require_locked_guest_bytes(
        &locked,
        source.consumer_guest_elf(),
        source.consumer_program_id(),
        source.alternate_guest_elf(),
        source.alternate_program_id(),
    )
}

/// Require one V2 source authority to contain exactly the two locked embedded guests.
#[cfg(feature = "b4-negative-ancestry-handler")]
pub(crate) fn require_locked_negative_ancestry_source_v2(
    authority: &B4NegativeAncestrySourceAuthorityV2,
) -> Result<()> {
    let locked = embedded_negative_ancestry_guest_pair()?;
    let source = authority.producer_source();
    require_locked_guest_bytes(
        &locked,
        source.consumer_guest_elf(),
        source.consumer_program_id(),
        source.alternate_guest_elf(),
        source.alternate_program_id(),
    )
}

#[cfg(test)]
mod tests {
    use eip_0045_methods::{GUEST_STATEMENT_CHUNK_BYTES, GuestInputHeader, GuestMode};
    use risc0_zkvm::{Executor, ExecutorEnv, ExitCode, LocalProver, SessionInfo};

    use super::*;

    const TEST_WORKLOAD_SEED: u64 = 0x4549_5030_3034_3503;

    fn execute_alternate_guest(input: &[u8]) -> SessionInfo {
        let mut builder = ExecutorEnv::builder();
        builder
            .segment_limit_po2(crate::EXECUTOR_SEGMENT_LIMIT_PO2)
            .write_slice(input);
        LocalProver::new("eip-0045-locked-alternate-guest-regression")
            .execute(
                builder.build().expect("alternate guest environment"),
                embedded_negative_ancestry_guest_pair()
                    .expect("locked guest pair")
                    .alternate
                    .elf,
            )
            .expect("alternate guest execution")
    }

    #[test]
    fn embedded_guest_provider_is_zero_argument_recomputed_and_distinct() {
        let provider: fn() -> Result<LockedGuestPairV1> = embedded_negative_ancestry_guest_pair;
        let pair = provider().unwrap();

        assert_eq!(
            pair.consumer.image_id,
            compute_image_id(pair.consumer.elf).unwrap()
        );
        assert_eq!(
            pair.alternate.image_id,
            compute_image_id(pair.alternate.elf).unwrap()
        );
        assert_ne!(pair.consumer.image_id, pair.alternate.image_id);
        assert_ne!(pair.consumer.elf, pair.alternate.elf);
    }

    #[cfg(feature = "b4-negative-ancestry-handler")]
    #[test]
    fn source_binding_api_accepts_only_the_opaque_source_authority() {
        let _: fn(&B4NegativeAncestrySourceAuthorityV1) -> Result<()> =
            require_locked_negative_ancestry_source;
        let _: fn(&B4NegativeAncestrySourceAuthorityV2) -> Result<()> =
            require_locked_negative_ancestry_source_v2;
    }

    #[cfg(feature = "b4-negative-ancestry-handler")]
    #[test]
    fn locked_v2_source_has_no_v1_conversion_path() {
        let production = include_str!("locked_negative_ancestry_guest.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in [
            "From<B4NegativeAncestrySourceAuthorityV2",
            "Into<B4NegativeAncestrySourceAuthorityV1",
            "as_v1",
            "into_v1",
        ] {
            assert!(
                !production.contains(forbidden),
                "locked V2 source boundary contains forbidden conversion {forbidden}"
            );
        }
    }

    #[test]
    fn locked_source_binding_rejects_each_guest_identity_fault() {
        let locked = embedded_negative_ancestry_guest_pair().unwrap();
        let consumer_id = digest_bytes(&locked.consumer.image_id).unwrap();
        let alternate_id = digest_bytes(&locked.alternate.image_id).unwrap();
        assert!(
            require_locked_guest_bytes(
                &locked,
                locked.consumer.elf,
                consumer_id,
                locked.alternate.elf,
                alternate_id,
            )
            .is_ok()
        );

        let mut mutated_consumer = locked.consumer.elf.to_vec();
        mutated_consumer[0] ^= 1;
        assert!(
            require_locked_guest_bytes(
                &locked,
                &mutated_consumer,
                consumer_id,
                locked.alternate.elf,
                alternate_id,
            )
            .is_err()
        );

        let mut stale_consumer_id = consumer_id;
        stale_consumer_id[0] ^= 1;
        assert!(
            require_locked_guest_bytes(
                &locked,
                locked.consumer.elf,
                stale_consumer_id,
                locked.alternate.elf,
                alternate_id,
            )
            .is_err()
        );

        let mut mutated_alternate = locked.alternate.elf.to_vec();
        mutated_alternate[0] ^= 1;
        assert!(
            require_locked_guest_bytes(
                &locked,
                locked.consumer.elf,
                consumer_id,
                &mutated_alternate,
                alternate_id,
            )
            .is_err()
        );

        let mut stale_alternate_id = alternate_id;
        stale_alternate_id[0] ^= 1;
        assert!(
            require_locked_guest_bytes(
                &locked,
                locked.consumer.elf,
                consumer_id,
                locked.alternate.elf,
                stale_alternate_id,
            )
            .is_err()
        );

        assert!(
            require_locked_guest_bytes(
                &locked,
                locked.alternate.elf,
                consumer_id,
                locked.alternate.elf,
                alternate_id,
            )
            .is_err()
        );
    }

    #[test]
    fn locked_source_binding_rejects_coordinated_guest_pair_permutation() {
        let locked = embedded_negative_ancestry_guest_pair().unwrap();
        let consumer_id = digest_bytes(&locked.consumer.image_id).unwrap();
        let alternate_id = digest_bytes(&locked.alternate.image_id).unwrap();

        assert_eq!(
            digest_bytes(&compute_image_id(locked.consumer.elf).unwrap()).unwrap(),
            consumer_id
        );
        assert_eq!(
            digest_bytes(&compute_image_id(locked.alternate.elf).unwrap()).unwrap(),
            alternate_id
        );
        require_locked_guest_bytes(
            &locked,
            locked.alternate.elf,
            alternate_id,
            locked.consumer.elf,
            consumer_id,
        )
        .expect_err("coordinated guest-pair permutation must be rejected");
    }

    #[test]
    fn alternate_guest_executes_exact_plain_abi_and_rejects_every_other_mode() {
        let statement = vec![0x5a; GUEST_STATEMENT_CHUNK_BYTES * 2 + 1];
        let plain = GuestInputHeader::new(statement.len(), 7, TEST_WORKLOAD_SEED).unwrap();
        let mut plain_input = plain.encode().to_vec();
        plain_input.extend_from_slice(&statement);
        let plain_session = execute_alternate_guest(&plain_input);
        assert_eq!(plain_session.exit_code, ExitCode::Halted(0));
        assert_eq!(plain_session.journal.bytes, statement);

        let alternate_id = digest_bytes(
            &embedded_negative_ancestry_guest_pair()
                .unwrap()
                .alternate
                .image_id,
        )
        .unwrap();
        let non_plain = [
            (
                GuestMode::VerifyAssumptionZeroRoot,
                GuestInputHeader::new_verifying_zero_root(
                    statement.len(),
                    7,
                    TEST_WORKLOAD_SEED,
                    alternate_id,
                )
                .unwrap(),
            ),
            (
                GuestMode::VerifyAssumptionExplicitRoot,
                GuestInputHeader::new_verifying_explicit_root(
                    statement.len(),
                    7,
                    TEST_WORKLOAD_SEED,
                    alternate_id,
                )
                .unwrap(),
            ),
            (
                GuestMode::VerifyAssumptionExplicitRootTwice,
                GuestInputHeader::new_verifying_explicit_root_twice(
                    statement.len(),
                    7,
                    TEST_WORKLOAD_SEED,
                    alternate_id,
                )
                .unwrap(),
            ),
        ];
        for (mode, header) in non_plain {
            let mut input = header.encode().to_vec();
            input.extend_from_slice(&statement);
            let session = execute_alternate_guest(&input);
            assert_ne!(
                session.exit_code,
                ExitCode::Halted(0),
                "alternate guest accepted non-Plain mode {mode:?}"
            );
            assert!(
                session.journal.bytes.is_empty(),
                "alternate guest committed a journal for non-Plain mode {mode:?}"
            );
        }

        let mut bad_workload = plain.encode().to_vec();
        bad_workload[20] ^= 1;
        bad_workload.extend_from_slice(&statement);
        let bad_workload_session = execute_alternate_guest(&bad_workload);
        assert_ne!(bad_workload_session.exit_code, ExitCode::Halted(0));
        assert!(bad_workload_session.journal.bytes.is_empty());
    }

    #[test]
    fn provider_source_has_no_ambient_guest_selector() {
        let production = include_str!("locked_negative_ancestry_guest.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in [
            "std::env",
            "args_os",
            "var_os",
            "Path",
            "_GUEST_PATH",
            "include_bytes!",
        ] {
            assert!(
                !production.contains(forbidden),
                "locked provider contains forbidden ambient selector {forbidden}"
            );
        }
    }
}
