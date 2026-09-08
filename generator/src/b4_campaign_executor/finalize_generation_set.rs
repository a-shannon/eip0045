//! Descriptor-rooted `finalize-generation-set` coordination.

use anyhow::Result;

/// Invoke the designated finalization callbacks in their affine data order.
///
/// The coordinator guarantees only callback invocation order: the designated
/// staging callback is not invoked until the gate, authority mint, and identity
/// check return successfully. It deliberately makes no claim about arbitrary
/// effects hidden inside caller-supplied callbacks. A concrete Linux handler
/// must bind those callbacks to reviewed custody and create-only capabilities.
pub(super) fn coordinate_finalize_generation_set<
    Validated,
    Authority,
    Staging,
    Written,
    Committed,
    Output,
>(
    authenticate_eleven_case_gate: impl FnOnce() -> Result<Validated>,
    mint_affine_authority: impl FnOnce(Validated) -> Result<Authority>,
    verify_generation_set_identity: impl FnOnce(&Authority) -> Result<()>,
    begin_outer_staging: impl FnOnce() -> Result<Staging>,
    write_generation_set: impl FnOnce(Staging, Authority) -> Result<Written>,
    commit_generation_set: impl FnOnce(Written) -> Result<Committed>,
    reopen_generation_set: impl FnOnce(Committed) -> Result<Output>,
) -> Result<Output> {
    let validated = authenticate_eleven_case_gate()?;
    let authority = mint_affine_authority(validated)?;
    verify_generation_set_identity(&authority)?;
    let staging = begin_outer_staging()?;
    let written = write_generation_set(staging, authority)?;
    let committed = commit_generation_set(written)?;
    reopen_generation_set(committed)
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use anyhow::{Result, bail};

    use super::coordinate_finalize_generation_set;

    #[test]
    fn seven_designated_callbacks_are_invoked_in_exact_data_order() {
        let events = RefCell::new(Vec::new());
        let output = coordinate_finalize_generation_set(
            || {
                events.borrow_mut().push("gate");
                Ok(7_u8)
            },
            |validated| {
                events.borrow_mut().push("mint");
                Ok(validated + 1)
            },
            |authority| {
                events.borrow_mut().push("identity");
                assert_eq!(*authority, 8);
                Ok(())
            },
            || {
                events.borrow_mut().push("stage");
                Ok(9_u8)
            },
            |staging, authority| {
                events.borrow_mut().push("write");
                Ok((staging, authority))
            },
            |written| {
                events.borrow_mut().push("commit");
                Ok(written)
            },
            |committed| {
                events.borrow_mut().push("reopen");
                Ok(committed)
            },
        )
        .unwrap();

        assert_eq!(output, (9, 8));
        assert_eq!(
            events.into_inner(),
            [
                "gate", "mint", "identity", "stage", "write", "commit", "reopen"
            ]
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum OperationFailure {
        Authenticate,
        Mint,
        Identity,
        BeginStaging,
        Write,
        Commit,
        Reopen,
    }

    #[test]
    fn each_callback_failure_prevents_every_later_designated_callback() {
        for failure in [
            OperationFailure::Authenticate,
            OperationFailure::Mint,
            OperationFailure::Identity,
            OperationFailure::BeginStaging,
            OperationFailure::Write,
            OperationFailure::Commit,
            OperationFailure::Reopen,
        ] {
            let events = RefCell::new(Vec::new());
            let result = coordinate_finalize_generation_set(
                || {
                    events.borrow_mut().push("gate");
                    fail_at(failure, OperationFailure::Authenticate)?;
                    Ok(7_u8)
                },
                |validated| {
                    events.borrow_mut().push("mint");
                    fail_at(failure, OperationFailure::Mint)?;
                    Ok(validated + 1)
                },
                |_authority| {
                    events.borrow_mut().push("identity");
                    fail_at(failure, OperationFailure::Identity)
                },
                || {
                    events.borrow_mut().push("stage");
                    fail_at(failure, OperationFailure::BeginStaging)?;
                    Ok(9_u8)
                },
                |staging, authority| {
                    events.borrow_mut().push("write");
                    fail_at(failure, OperationFailure::Write)?;
                    Ok((staging, authority))
                },
                |written| {
                    events.borrow_mut().push("commit");
                    fail_at(failure, OperationFailure::Commit)?;
                    Ok(written)
                },
                |committed| {
                    events.borrow_mut().push("reopen");
                    fail_at(failure, OperationFailure::Reopen)?;
                    Ok(committed)
                },
            );

            assert!(result.is_err(), "{failure:?} unexpectedly passed");
            let expected: &[&str] = match failure {
                OperationFailure::Authenticate => &["gate"],
                OperationFailure::Mint => &["gate", "mint"],
                OperationFailure::Identity => &["gate", "mint", "identity"],
                OperationFailure::BeginStaging => &["gate", "mint", "identity", "stage"],
                OperationFailure::Write => &["gate", "mint", "identity", "stage", "write"],
                OperationFailure::Commit => {
                    &["gate", "mint", "identity", "stage", "write", "commit"]
                }
                OperationFailure::Reopen => &[
                    "gate", "mint", "identity", "stage", "write", "commit", "reopen",
                ],
            };
            assert_eq!(
                &*events.borrow(),
                expected,
                "{failure:?} reached a later callback"
            );
        }
    }

    #[test]
    fn authority_failures_do_not_invoke_the_designated_staging_callback() {
        for failure in [
            OperationFailure::Authenticate,
            OperationFailure::Mint,
            OperationFailure::Identity,
        ] {
            let staging_invoked = Cell::new(false);
            let result = coordinate_finalize_generation_set(
                || {
                    fail_at(failure, OperationFailure::Authenticate)?;
                    Ok(7_u8)
                },
                |validated| {
                    fail_at(failure, OperationFailure::Mint)?;
                    Ok(validated + 1)
                },
                |_authority| fail_at(failure, OperationFailure::Identity),
                || {
                    staging_invoked.set(true);
                    Ok(9_u8)
                },
                |staging, authority| Ok((staging, authority)),
                |written| Ok(written),
                |committed| Ok(committed),
            );

            assert!(result.is_err(), "{failure:?} unexpectedly passed");
            assert!(!staging_invoked.get(), "{failure:?} invoked staging");
        }
    }

    fn fail_at(actual: OperationFailure, injected: OperationFailure) -> Result<()> {
        if actual == injected {
            bail!("injected {actual:?} failure");
        }
        Ok(())
    }

    #[test]
    fn coordinator_source_excludes_cli_process_and_proving_apis() {
        let source = include_str!("finalize_generation_set.rs").replace("\r\n", "\n");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "Command::",
            "LocalProver",
            "risc0_zkvm",
            "std::process",
            "registry",
        ] {
            assert!(
                !production.contains(forbidden),
                "coordinator source contains forbidden surface: {forbidden}"
            );
        }
    }

    #[test]
    fn feature_requests_campaign_support_without_proving_or_embedding() {
        let manifest = include_str!("../../Cargo.toml").replace("\r\n", "\n");
        let feature = manifest
            .split("b4-finalize-generation-set-handler = [")
            .nth(1)
            .unwrap()
            .split("\n]")
            .next()
            .unwrap();
        assert!(feature.contains("b4-campaign-executor"));
        assert!(feature.contains("eip-0045-reproduction/positive-gate"));
        for forbidden in ["embedded-method", "proof-generation", "risc0-zkvm/prove"] {
            assert!(!feature.contains(forbidden), "feature enables {forbidden}");
        }

        // RISC0 verifier crates remain non-optional generator dependencies.
        // This feature is no-proving/no-embedding, not a RISC0-free graph.
        assert!(manifest.contains("\nrisc0-zkvm ="));

        let module = include_str!("mod.rs").replace("\r\n", "\n");
        assert!(module.contains(
            "#[cfg(any(test, feature = \"b4-finalize-generation-set-handler\"))]\nmod finalize_generation_set;"
        ));
    }
}
