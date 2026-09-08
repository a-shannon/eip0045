use anyhow::Result;
use eip_0045_reproduction::{
    b4_campaign_contract::{B4CampaignPrecommitAuthorityV1, B4PositiveGenerationAuthorityV2},
    b4_terminal_source_lineage::{
        B4TerminalSourceLineageAuthorityV1, B4TerminalSourceLineageAuthorityV2,
    },
};
use risc0_zkvm::LocalProver;

use crate::terminal_fixtures::{
    B4AuthenticatedTerminalFixtureSourcesV1, B4GeneratedTerminalFixtureSetV1,
    authenticate_b4_terminal_fixture_sources, compose_authenticated_b4_terminal_fixture_set,
};

pub(crate) struct B4PreparedLineagedTerminalSourcesV1 {
    authenticated: B4AuthenticatedTerminalFixtureSourcesV1,
}

pub(crate) struct B4PreparedLineagedTerminalSourcesV2 {
    authenticated: B4AuthenticatedTerminalFixtureSourcesV1,
}

impl B4PreparedLineagedTerminalSourcesV2 {
    pub(crate) fn sources(&self) -> &B4AuthenticatedTerminalFixtureSourcesV1 {
        &self.authenticated
    }

    pub(crate) fn into_authenticated(self) -> B4AuthenticatedTerminalFixtureSourcesV1 {
        self.authenticated
    }
}

impl B4PreparedLineagedTerminalSourcesV1 {
    pub(crate) fn sources(&self) -> &B4AuthenticatedTerminalFixtureSourcesV1 {
        &self.authenticated
    }

    pub(crate) fn into_authenticated(self) -> B4AuthenticatedTerminalFixtureSourcesV1 {
        self.authenticated
    }
}

pub(crate) fn authenticate_lineaged_b4_terminal_sources(
    lineage: &B4TerminalSourceLineageAuthorityV1,
) -> Result<B4PreparedLineagedTerminalSourcesV1> {
    let source = lineage.producer_source();
    let authenticated = authenticate_b4_terminal_fixture_sources(
        source.guest_elf(),
        source.statement(),
        source.case0_lift15_receipt_oracle(),
        source.case8_terminal_join_recursive_oracle(),
        source.case9_terminal_resolve_recursive_oracle(),
    )?;
    Ok(B4PreparedLineagedTerminalSourcesV1 { authenticated })
}

pub(crate) fn authenticate_lineaged_b4_terminal_sources_v2(
    campaign: &B4CampaignPrecommitAuthorityV1,
    positive: &B4PositiveGenerationAuthorityV2,
    lineage: &B4TerminalSourceLineageAuthorityV2,
) -> Result<B4PreparedLineagedTerminalSourcesV2> {
    lineage.verify_authority_bindings(campaign, positive)?;
    let source = lineage.producer_source();
    let authenticated = authenticate_b4_terminal_fixture_sources(
        source.guest_elf(),
        source.statement(),
        source.case0_lift15_receipt_oracle(),
        source.case8_terminal_join_recursive_oracle(),
        source.case9_terminal_resolve_recursive_oracle(),
    )?;
    Ok(B4PreparedLineagedTerminalSourcesV2 { authenticated })
}

/// Generate the fixed B4 terminal fixture set from authenticated official-lineage sources.
///
/// # Errors
///
/// Returns an error if semantic source authentication or terminal fixture generation fails.
pub fn generate_lineaged_b4_terminal_fixture_set(
    prover: &LocalProver,
    lineage: &B4TerminalSourceLineageAuthorityV1,
) -> Result<B4GeneratedTerminalFixtureSetV1> {
    let prepared = authenticate_lineaged_b4_terminal_sources(lineage)?;
    let composition =
        compose_authenticated_b4_terminal_fixture_set(prover, prepared.into_authenticated())?;
    let (_, generated, _) = composition.into_parts();
    Ok(generated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal_fixtures::{
        B4AuthenticatedTerminalFixtureSourcesV1, B4Case8FinalJoinDirectEvidenceV1,
        B4TerminalFixtureCompositionV1, compose_authenticated_b4_terminal_fixture_set,
    };

    #[test]
    fn enriched_composition_preserves_public_task3_shape() {
        let _: fn(
            &B4TerminalSourceLineageAuthorityV1,
        ) -> anyhow::Result<B4PreparedLineagedTerminalSourcesV1> =
            authenticate_lineaged_b4_terminal_sources;
        let _: fn(
            &B4PreparedLineagedTerminalSourcesV1,
        ) -> &B4AuthenticatedTerminalFixtureSourcesV1 =
            B4PreparedLineagedTerminalSourcesV1::sources;
        let _: fn(B4PreparedLineagedTerminalSourcesV1) -> B4AuthenticatedTerminalFixtureSourcesV1 =
            B4PreparedLineagedTerminalSourcesV1::into_authenticated;
        let _: fn(
            &LocalProver,
            B4AuthenticatedTerminalFixtureSourcesV1,
        ) -> anyhow::Result<B4TerminalFixtureCompositionV1> =
            compose_authenticated_b4_terminal_fixture_set;
        let _: fn(
            B4TerminalFixtureCompositionV1,
        ) -> (
            B4AuthenticatedTerminalFixtureSourcesV1,
            B4GeneratedTerminalFixtureSetV1,
            B4Case8FinalJoinDirectEvidenceV1,
        ) = B4TerminalFixtureCompositionV1::into_parts;
        let _: fn(
            &LocalProver,
            &B4TerminalSourceLineageAuthorityV1,
        ) -> anyhow::Result<B4GeneratedTerminalFixtureSetV1> =
            generate_lineaged_b4_terminal_fixture_set;
    }

    #[test]
    fn v2_authentication_requires_both_live_authorities_without_a_v1_adapter() {
        let _: fn(
            &B4CampaignPrecommitAuthorityV1,
            &B4PositiveGenerationAuthorityV2,
            &B4TerminalSourceLineageAuthorityV2,
        ) -> anyhow::Result<B4PreparedLineagedTerminalSourcesV2> =
            authenticate_lineaged_b4_terminal_sources_v2;
        let _: fn(
            &B4PreparedLineagedTerminalSourcesV2,
        ) -> &B4AuthenticatedTerminalFixtureSourcesV1 =
            B4PreparedLineagedTerminalSourcesV2::sources;
        let _: fn(B4PreparedLineagedTerminalSourcesV2) -> B4AuthenticatedTerminalFixtureSourcesV1 =
            B4PreparedLineagedTerminalSourcesV2::into_authenticated;

        let source = include_str!("terminal_lineage.rs");
        let v2 = source
            .split("pub(crate) fn authenticate_lineaged_b4_terminal_sources_v2(")
            .nth(1)
            .unwrap()
            .split("/// Generate the fixed B4 terminal fixture set")
            .next()
            .unwrap();
        assert!(v2.contains("lineage.verify_authority_bindings(campaign, positive)?"));
        assert!(v2.contains("let source = lineage.producer_source()"));
        assert!(!v2.contains("B4TerminalSourceLineageAuthorityV1"));
        assert!(!v2.contains("B4PositiveGenerationAuthorityV1"));
    }

    #[test]
    fn composition_has_exact_two_argument_shape_and_feature_edges() {
        let _: fn(
            &LocalProver,
            &B4TerminalSourceLineageAuthorityV1,
        ) -> anyhow::Result<B4GeneratedTerminalFixtureSetV1> =
            generate_lineaged_b4_terminal_fixture_set;

        let mut block = Vec::new();
        let mut collecting = false;
        for line in include_str!("../Cargo.toml").lines() {
            if line.starts_with("b4-terminal-source-lineage = [") {
                collecting = true;
            }
            if collecting {
                block.push(line.trim());
                if line.trim() == "]" {
                    break;
                }
            }
        }
        assert_eq!(
            block,
            [
                "b4-terminal-source-lineage = [",
                "\"b4-terminal-fixture-generation\",",
                "\"eip-0045-reproduction/positive-gate\",",
                "]",
            ]
        );
        for forbidden in [
            "negative-materialization",
            "negative-ancestry-publication",
            "publisher",
            "filesystem",
            "renamore",
        ] {
            assert!(
                block.iter().all(|line| !line.contains(forbidden)),
                "terminal-source lineage added forbidden feature edge {forbidden}",
            );
        }
    }
}
