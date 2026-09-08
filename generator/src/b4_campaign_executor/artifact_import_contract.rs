//! Closed role and budget contract for immutable physical artifact imports.

#![allow(
    dead_code,
    reason = "the closed budget contract lands before its descriptor-rooted streaming importers"
)]

use anyhow::{Context as _, Result, bail, ensure};

/// Closed native-ELF policy selected before physical import.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Amd64ElfPolicyV1 {
    Static,
    Runtime,
}

/// Closed JAR policy selected before physical import.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum JvmJarPolicyV1 {
    SourceRead,
    CanonicalExecutable,
}

/// Artifact roles whose physical readers have distinct normative budgets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum B4ImmutableArtifactRoleV1 {
    ReviewedGitBundle,
    OciImageLayoutUstar,
    Risc0GuestElf,
    Amd64Elf(Amd64ElfPolicyV1),
    JvmJar(JvmJarPolicyV1),
}

impl B4ImmutableArtifactRoleV1 {
    /// Closed inventory. Its order is stable but does not imply physical root
    /// topology or multiplicity.
    pub(super) const ALL: [Self; 7] = [
        Self::ReviewedGitBundle,
        Self::OciImageLayoutUstar,
        Self::Risc0GuestElf,
        Self::Amd64Elf(Amd64ElfPolicyV1::Static),
        Self::Amd64Elf(Amd64ElfPolicyV1::Runtime),
        Self::JvmJar(JvmJarPolicyV1::SourceRead),
        Self::JvmJar(JvmJarPolicyV1::CanonicalExecutable),
    ];

    /// Resolve the exact immutable limits for this role. No caller-supplied
    /// root topology, cardinality, or byte limit enters this projection.
    pub(super) const fn limits(self) -> ArtifactImportLimitsV1 {
        match self {
            Self::ReviewedGitBundle => ArtifactImportLimitsV1 {
                minimum_encoded_bytes: 1,
                maximum_encoded_bytes: 1_073_741_824,
                encoded_byte_multiple: None,
                content: ArtifactContentLimitsV1::EncodedOnly,
            },
            Self::OciImageLayoutUstar => ArtifactImportLimitsV1 {
                minimum_encoded_bytes: 6_144,
                maximum_encoded_bytes: 17_179_869_184,
                encoded_byte_multiple: Some(512),
                content: ArtifactContentLimitsV1::Oci(OciArtifactImportLimitsV1 {
                    maximum_outer_ustar_member_payload_bytes: 8_589_934_591,
                    maximum_json_bytes: 1_048_576,
                    layer_stream: OciLayerStreamLimitsV1 {
                        maximum_uncompressed_tar_bytes: 34_359_738_368,
                        maximum_tar_entries: 1_000_000,
                        maximum_regular_file_payload_bytes: 1_073_741_824,
                        maximum_layers: 128,
                    },
                    post_changeset_rootfs: OciPostChangesetRootfsLimitsV1 {
                        maximum_regular_file_bytes: 34_359_738_368,
                        maximum_entries: 1_000_000,
                    },
                }),
            },
            Self::Risc0GuestElf => ArtifactImportLimitsV1 {
                minimum_encoded_bytes: 1,
                maximum_encoded_bytes: 4_194_304,
                encoded_byte_multiple: None,
                content: ArtifactContentLimitsV1::Risc0GuestElf(Risc0GuestElfImportLimitsV1 {
                    maximum_loaded_words: 1_048_576,
                }),
            },
            Self::Amd64Elf(policy) => ArtifactImportLimitsV1 {
                minimum_encoded_bytes: 64,
                maximum_encoded_bytes: 1_073_741_824,
                encoded_byte_multiple: None,
                content: ArtifactContentLimitsV1::Amd64Elf(Amd64ElfImportLimitsV1 {
                    maximum_program_headers: 65_534,
                    maximum_section_headers: 65_279,
                    runtime_linkage: match policy {
                        Amd64ElfPolicyV1::Static => None,
                        Amd64ElfPolicyV1::Runtime => Some(RuntimeAmd64ElfImportLimitsV1 {
                            maximum_dynamic_entries: 65_534,
                            maximum_needed_libraries: 4_096,
                        }),
                    },
                }),
            },
            Self::JvmJar(_) => ArtifactImportLimitsV1 {
                minimum_encoded_bytes: 22,
                maximum_encoded_bytes: 1_073_741_824,
                encoded_byte_multiple: None,
                content: ArtifactContentLimitsV1::JvmJar(JvmJarImportLimitsV1 {
                    maximum_decompressed_regular_file_bytes: 1_073_741_824,
                    maximum_single_decompressed_entry_bytes: 1_073_741_824,
                    maximum_entries: 65_534,
                }),
            },
        }
    }
}

/// Closed nested-budget family selected together with the artifact role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ArtifactContentLimitsV1 {
    EncodedOnly,
    Oci(OciArtifactImportLimitsV1),
    Risc0GuestElf(Risc0GuestElfImportLimitsV1),
    Amd64Elf(Amd64ElfImportLimitsV1),
    JvmJar(JvmJarImportLimitsV1),
}

/// Loader-work budget for one RISC Zero `ProgramBinary`.
///
/// This bounds the aggregate `PT_LOAD` word iterations across its user and
/// kernel ELFs before the pinned image-ID implementation materializes them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Risc0GuestElfImportLimitsV1 {
    maximum_loaded_words: u64,
}

/// Parser-work budgets for one topology-free AMD64 ELF inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Amd64ElfImportLimitsV1 {
    maximum_program_headers: u64,
    maximum_section_headers: u64,
    runtime_linkage: Option<RuntimeAmd64ElfImportLimitsV1>,
}

/// Runtime-linkage work budgets that have no meaning for a static ELF role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RuntimeAmd64ElfImportLimitsV1 {
    maximum_dynamic_entries: u64,
    maximum_needed_libraries: u64,
}

/// Closed per-process work budgets for the static startup-dependency closure.
///
/// These topology budgets are deliberately separate from one ELF artifact's
/// parser-work limits. Callers cannot supply or widen any ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct StartupDependencyClosureLimitsV1 {
    distinct_objects: u64,
    dependency_edges: u64,
    depth: u64,
    aggregate_distinct_object_bytes: u64,
    dynamic_basename_bytes: u64,
    runpath_components: u64,
    runpath_component_bytes: u64,
}

/// Select the one closed startup-dependency policy budget.
pub(super) const fn startup_dependency_closure_limits_v1() -> StartupDependencyClosureLimitsV1 {
    StartupDependencyClosureLimitsV1 {
        distinct_objects: 512,
        dependency_edges: 4_096,
        depth: 64,
        aggregate_distinct_object_bytes: 4_294_967_296,
        dynamic_basename_bytes: 240,
        runpath_components: 16,
        runpath_component_bytes: 240,
    }
}

/// OCI outer-archive, layer-stream, and final-rootfs budgets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OciArtifactImportLimitsV1 {
    maximum_outer_ustar_member_payload_bytes: u64,
    maximum_json_bytes: u64,
    layer_stream: OciLayerStreamLimitsV1,
    post_changeset_rootfs: OciPostChangesetRootfsLimitsV1,
}

/// Monotone aggregate budgets over all decoded OCI layer tar streams.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "the repeated prefix makes every stored ceiling distinct from future measured counters"
)]
pub(super) struct OciLayerStreamLimitsV1 {
    maximum_uncompressed_tar_bytes: u64,
    maximum_tar_entries: u64,
    maximum_regular_file_payload_bytes: u64,
    maximum_layers: u64,
}

/// Budgets over the final rootfs state after all OCI changesets are applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OciPostChangesetRootfsLimitsV1 {
    maximum_regular_file_bytes: u64,
    maximum_entries: u64,
}

/// Monotone expansion budgets for one classic-ZIP JAR archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "the repeated prefix makes every stored ceiling distinct from future measured counters"
)]
pub(super) struct JvmJarImportLimitsV1 {
    maximum_decompressed_regular_file_bytes: u64,
    maximum_single_decompressed_entry_bytes: u64,
    maximum_entries: u64,
}

/// Immutable limits selected solely from a closed artifact role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ArtifactImportLimitsV1 {
    minimum_encoded_bytes: u64,
    maximum_encoded_bytes: u64,
    encoded_byte_multiple: Option<u64>,
    content: ArtifactContentLimitsV1,
}

impl ArtifactImportLimitsV1 {
    pub(super) const fn encoded_byte_range(self) -> (u64, u64) {
        (self.minimum_encoded_bytes, self.maximum_encoded_bytes)
    }

    pub(super) const fn encoded_byte_multiple(self) -> Option<u64> {
        self.encoded_byte_multiple
    }

    /// Reject a physical encoded length before allocation or parsing.
    pub(super) fn validate_encoded_length(self, byte_length: u64, label: &str) -> Result<()> {
        ensure!(
            (self.minimum_encoded_bytes..=self.maximum_encoded_bytes).contains(&byte_length),
            "{label} encoded byte length is outside its role-specific range"
        );
        if let Some(multiple) = self.encoded_byte_multiple {
            ensure!(
                byte_length % multiple == 0,
                "{label} encoded byte length is not a multiple of {multiple}"
            );
        }
        Ok(())
    }

    pub(super) fn require_oci(self, label: &str) -> Result<OciArtifactImportLimitsV1> {
        match self.content {
            ArtifactContentLimitsV1::Oci(limits) => Ok(limits),
            ArtifactContentLimitsV1::EncodedOnly
            | ArtifactContentLimitsV1::Risc0GuestElf(_)
            | ArtifactContentLimitsV1::Amd64Elf(_)
            | ArtifactContentLimitsV1::JvmJar(_) => {
                bail!("{label} role has no OCI nested-budget contract")
            }
        }
    }

    pub(super) fn require_risc0_guest_elf(
        self,
        label: &str,
    ) -> Result<Risc0GuestElfImportLimitsV1> {
        match self.content {
            ArtifactContentLimitsV1::Risc0GuestElf(limits) => Ok(limits),
            ArtifactContentLimitsV1::EncodedOnly
            | ArtifactContentLimitsV1::Oci(_)
            | ArtifactContentLimitsV1::Amd64Elf(_)
            | ArtifactContentLimitsV1::JvmJar(_) => {
                bail!("{label} role has no RISC Zero guest-ELF loader-work contract")
            }
        }
    }

    pub(super) fn require_amd64_elf(self, label: &str) -> Result<Amd64ElfImportLimitsV1> {
        match self.content {
            ArtifactContentLimitsV1::Amd64Elf(limits) => Ok(limits),
            ArtifactContentLimitsV1::EncodedOnly
            | ArtifactContentLimitsV1::Oci(_)
            | ArtifactContentLimitsV1::Risc0GuestElf(_)
            | ArtifactContentLimitsV1::JvmJar(_) => {
                bail!("{label} role has no AMD64-ELF parser-work contract")
            }
        }
    }

    pub(super) fn require_jvm_jar(self, label: &str) -> Result<JvmJarImportLimitsV1> {
        match self.content {
            ArtifactContentLimitsV1::JvmJar(limits) => Ok(limits),
            ArtifactContentLimitsV1::EncodedOnly
            | ArtifactContentLimitsV1::Oci(_)
            | ArtifactContentLimitsV1::Risc0GuestElf(_)
            | ArtifactContentLimitsV1::Amd64Elf(_) => {
                bail!("{label} role has no JVM-JAR nested-budget contract")
            }
        }
    }
}

impl Risc0GuestElfImportLimitsV1 {
    pub(super) const fn maximum_loaded_words(self) -> u64 {
        self.maximum_loaded_words
    }

    pub(super) fn checked_add_loaded_words(
        self,
        current: u64,
        additional: u64,
        label: &str,
    ) -> Result<u64> {
        checked_sum(
            current,
            additional,
            self.maximum_loaded_words,
            "loaded-word",
            label,
        )
    }
}

impl Amd64ElfImportLimitsV1 {
    pub(super) const fn maximum_program_headers(self) -> u64 {
        self.maximum_program_headers
    }

    pub(super) const fn maximum_section_headers(self) -> u64 {
        self.maximum_section_headers
    }

    pub(super) fn require_runtime_linkage(
        self,
        label: &str,
    ) -> Result<RuntimeAmd64ElfImportLimitsV1> {
        self.runtime_linkage
            .with_context(|| format!("{label} role has no runtime-linkage work contract"))
    }

    pub(super) fn validate_program_header_count(self, count: u64, label: &str) -> Result<()> {
        ensure!(
            (1..=self.maximum_program_headers).contains(&count),
            "{label} program-header count is outside its role-specific range"
        );
        Ok(())
    }

    pub(super) fn validate_section_header_count(self, count: u64, label: &str) -> Result<()> {
        ensure!(
            count <= self.maximum_section_headers,
            "{label} section-header count exceeds its role-specific range"
        );
        Ok(())
    }
}

impl RuntimeAmd64ElfImportLimitsV1 {
    pub(super) const fn maximum_dynamic_entries(self) -> u64 {
        self.maximum_dynamic_entries
    }

    pub(super) const fn maximum_needed_libraries(self) -> u64 {
        self.maximum_needed_libraries
    }

    pub(super) fn validate_dynamic_entry_count(self, count: u64, label: &str) -> Result<()> {
        ensure!(
            (1..=self.maximum_dynamic_entries).contains(&count),
            "{label} dynamic-entry count is outside its role-specific range"
        );
        Ok(())
    }

    pub(super) fn validate_needed_library_count(self, count: u64, label: &str) -> Result<()> {
        ensure!(
            count <= self.maximum_needed_libraries,
            "{label} DT_NEEDED count exceeds its role-specific range"
        );
        Ok(())
    }
}

impl StartupDependencyClosureLimitsV1 {
    pub(super) const fn maximum_distinct_objects(self) -> u64 {
        self.distinct_objects
    }

    pub(super) const fn maximum_dependency_edges(self) -> u64 {
        self.dependency_edges
    }

    pub(super) const fn maximum_depth(self) -> u64 {
        self.depth
    }

    pub(super) const fn maximum_aggregate_distinct_object_bytes(self) -> u64 {
        self.aggregate_distinct_object_bytes
    }

    pub(super) const fn maximum_dynamic_basename_bytes(self) -> u64 {
        self.dynamic_basename_bytes
    }

    pub(super) const fn maximum_runpath_components(self) -> u64 {
        self.runpath_components
    }

    pub(super) const fn maximum_runpath_component_bytes(self) -> u64 {
        self.runpath_component_bytes
    }

    pub(super) fn checked_add_distinct_objects(
        self,
        current: u64,
        additional: u64,
        label: &str,
    ) -> Result<u64> {
        checked_sum(
            current,
            additional,
            self.distinct_objects,
            "distinct startup object",
            label,
        )
    }

    pub(super) fn checked_add_dependency_edges(
        self,
        current: u64,
        additional: u64,
        label: &str,
    ) -> Result<u64> {
        checked_sum(
            current,
            additional,
            self.dependency_edges,
            "startup dependency edge",
            label,
        )
    }

    pub(super) fn validate_depth(self, depth: u64, label: &str) -> Result<()> {
        validate_ceiling(depth, self.depth, "startup dependency depth", label)
    }

    pub(super) fn checked_add_distinct_object_bytes(
        self,
        current: u64,
        additional: u64,
        label: &str,
    ) -> Result<u64> {
        checked_sum(
            current,
            additional,
            self.aggregate_distinct_object_bytes,
            "aggregate distinct startup-object byte",
            label,
        )
    }

    pub(super) fn validate_dynamic_basename_bytes(
        self,
        byte_length: u64,
        label: &str,
    ) -> Result<()> {
        ensure!(
            (1..=self.dynamic_basename_bytes).contains(&byte_length),
            "{label} dynamic basename byte length is outside its closed range"
        );
        Ok(())
    }

    pub(super) fn validate_runpath_component_count(self, count: u64, label: &str) -> Result<()> {
        ensure!(
            (1..=self.runpath_components).contains(&count),
            "{label} RUNPATH component count is outside its closed range"
        );
        Ok(())
    }

    pub(super) fn validate_runpath_component_bytes(
        self,
        byte_length: u64,
        label: &str,
    ) -> Result<()> {
        ensure!(
            (1..=self.runpath_component_bytes).contains(&byte_length),
            "{label} RUNPATH component byte length is outside its closed range"
        );
        Ok(())
    }
}

impl OciArtifactImportLimitsV1 {
    pub(super) const fn maximum_outer_ustar_member_payload_bytes(self) -> u64 {
        self.maximum_outer_ustar_member_payload_bytes
    }

    pub(super) const fn maximum_json_bytes(self) -> u64 {
        self.maximum_json_bytes
    }

    pub(super) fn validate_json_bytes(self, byte_length: u64, label: &str) -> Result<()> {
        ensure!(
            (2..=self.maximum_json_bytes).contains(&byte_length),
            "{label} JSON byte length is outside its role-specific range"
        );
        Ok(())
    }

    pub(super) const fn layer_stream(self) -> OciLayerStreamLimitsV1 {
        self.layer_stream
    }

    pub(super) const fn post_changeset_rootfs(self) -> OciPostChangesetRootfsLimitsV1 {
        self.post_changeset_rootfs
    }

    pub(super) fn validate_outer_ustar_member_payload_bytes(
        self,
        byte_length: u64,
        label: &str,
    ) -> Result<()> {
        validate_ceiling(
            byte_length,
            self.maximum_outer_ustar_member_payload_bytes,
            "outer-ustar member payload byte",
            label,
        )
    }
}

impl OciLayerStreamLimitsV1 {
    pub(super) const fn maximum_uncompressed_tar_bytes(self) -> u64 {
        self.maximum_uncompressed_tar_bytes
    }

    pub(super) const fn maximum_tar_entries(self) -> u64 {
        self.maximum_tar_entries
    }

    pub(super) const fn maximum_regular_file_payload_bytes(self) -> u64 {
        self.maximum_regular_file_payload_bytes
    }

    pub(super) const fn maximum_layers(self) -> u64 {
        self.maximum_layers
    }

    pub(super) fn checked_add_uncompressed_tar_bytes(
        self,
        current: u64,
        additional: u64,
        label: &str,
    ) -> Result<u64> {
        checked_sum(
            current,
            additional,
            self.maximum_uncompressed_tar_bytes,
            "uncompressed layer-tar byte",
            label,
        )
    }

    pub(super) fn checked_add_tar_entries(
        self,
        current: u64,
        additional: u64,
        label: &str,
    ) -> Result<u64> {
        checked_sum(
            current,
            additional,
            self.maximum_tar_entries,
            "layer-tar entry",
            label,
        )
    }

    pub(super) fn validate_regular_file_payload_bytes(
        self,
        byte_length: u64,
        label: &str,
    ) -> Result<()> {
        validate_ceiling(
            byte_length,
            self.maximum_regular_file_payload_bytes,
            "layer regular-file payload byte",
            label,
        )
    }

    pub(super) fn checked_add_layer(
        self,
        current: u64,
        additional: u64,
        label: &str,
    ) -> Result<u64> {
        checked_sum(current, additional, self.maximum_layers, "layer", label)
    }
}

impl OciPostChangesetRootfsLimitsV1 {
    pub(super) const fn maximum_regular_file_bytes(self) -> u64 {
        self.maximum_regular_file_bytes
    }

    pub(super) const fn maximum_entries(self) -> u64 {
        self.maximum_entries
    }

    pub(super) fn validate_final_regular_file_bytes(
        self,
        byte_length: u64,
        label: &str,
    ) -> Result<()> {
        validate_ceiling(
            byte_length,
            self.maximum_regular_file_bytes,
            "post-changeset rootfs regular-file byte",
            label,
        )
    }

    pub(super) fn validate_final_entry_count(self, count: u64, label: &str) -> Result<()> {
        validate_ceiling(
            count,
            self.maximum_entries,
            "post-changeset rootfs entry",
            label,
        )
    }
}

impl JvmJarImportLimitsV1 {
    pub(super) const fn maximum_decompressed_regular_file_bytes(self) -> u64 {
        self.maximum_decompressed_regular_file_bytes
    }

    pub(super) const fn maximum_single_decompressed_entry_bytes(self) -> u64 {
        self.maximum_single_decompressed_entry_bytes
    }

    pub(super) const fn maximum_entries(self) -> u64 {
        self.maximum_entries
    }

    pub(super) fn checked_add_decompressed_regular_file_bytes(
        self,
        current: u64,
        additional: u64,
        label: &str,
    ) -> Result<u64> {
        checked_sum(
            current,
            additional,
            self.maximum_decompressed_regular_file_bytes,
            "decompressed regular-file byte",
            label,
        )
    }

    pub(super) fn validate_single_decompressed_entry_bytes(
        self,
        byte_length: u64,
        label: &str,
    ) -> Result<()> {
        validate_ceiling(
            byte_length,
            self.maximum_single_decompressed_entry_bytes,
            "single decompressed entry byte",
            label,
        )
    }

    pub(super) fn checked_add_entry(
        self,
        current: u64,
        additional: u64,
        label: &str,
    ) -> Result<u64> {
        checked_sum(
            current,
            additional,
            self.maximum_entries,
            "JAR entry",
            label,
        )
    }
}

fn validate_ceiling(value: u64, maximum: u64, budget: &str, label: &str) -> Result<()> {
    ensure!(
        value <= maximum,
        "{label} exceeds its role-specific {budget} budget"
    );
    Ok(())
}

fn checked_sum(
    current: u64,
    additional: u64,
    maximum: u64,
    budget: &str,
    label: &str,
) -> Result<u64> {
    let total = current
        .checked_add(additional)
        .with_context(|| format!("{label} {budget} overflow"))?;
    ensure!(
        total <= maximum,
        "{label} exceeds its role-specific {budget} budget"
    );
    Ok(total)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{
        Amd64ElfImportLimitsV1, Amd64ElfPolicyV1, ArtifactContentLimitsV1, ArtifactImportLimitsV1,
        B4ImmutableArtifactRoleV1, JvmJarImportLimitsV1, JvmJarPolicyV1, OciArtifactImportLimitsV1,
        OciLayerStreamLimitsV1, OciPostChangesetRootfsLimitsV1, Risc0GuestElfImportLimitsV1,
        RuntimeAmd64ElfImportLimitsV1, startup_dependency_closure_limits_v1,
    };

    const fn expected_limits(
        minimum_encoded_bytes: u64,
        maximum_encoded_bytes: u64,
        encoded_byte_multiple: Option<u64>,
        content: ArtifactContentLimitsV1,
    ) -> ArtifactImportLimitsV1 {
        ArtifactImportLimitsV1 {
            minimum_encoded_bytes,
            maximum_encoded_bytes,
            encoded_byte_multiple,
            content,
        }
    }

    fn assert_encoded_boundaries(
        role: B4ImmutableArtifactRoleV1,
        minimum: u64,
        maximum: u64,
    ) -> ArtifactImportLimitsV1 {
        let limits = role.limits();
        assert_eq!(limits.encoded_byte_range(), (minimum, maximum));
        limits.validate_encoded_length(minimum, "artifact").unwrap();
        limits.validate_encoded_length(maximum, "artifact").unwrap();
        assert!(
            limits
                .validate_encoded_length(minimum - 1, "artifact")
                .is_err()
        );
        assert!(
            limits
                .validate_encoded_length(maximum + 1, "artifact")
                .is_err()
        );
        limits
    }

    #[test]
    fn closed_inventory_fixes_all_seven_role_policy_combinations() {
        assert_eq!(B4ImmutableArtifactRoleV1::ALL.len(), 7);
        assert_eq!(
            B4ImmutableArtifactRoleV1::ALL,
            [
                B4ImmutableArtifactRoleV1::ReviewedGitBundle,
                B4ImmutableArtifactRoleV1::OciImageLayoutUstar,
                B4ImmutableArtifactRoleV1::Risc0GuestElf,
                B4ImmutableArtifactRoleV1::Amd64Elf(Amd64ElfPolicyV1::Static),
                B4ImmutableArtifactRoleV1::Amd64Elf(Amd64ElfPolicyV1::Runtime),
                B4ImmutableArtifactRoleV1::JvmJar(JvmJarPolicyV1::SourceRead),
                B4ImmutableArtifactRoleV1::JvmJar(JvmJarPolicyV1::CanonicalExecutable),
            ]
        );
    }

    #[test]
    fn every_role_enforces_its_complete_normative_budget_shape() {
        let expected = [
            expected_limits(1, 1_073_741_824, None, ArtifactContentLimitsV1::EncodedOnly),
            expected_limits(
                6_144,
                17_179_869_184,
                Some(512),
                ArtifactContentLimitsV1::Oci(OciArtifactImportLimitsV1 {
                    maximum_outer_ustar_member_payload_bytes: 8_589_934_591,
                    maximum_json_bytes: 1_048_576,
                    layer_stream: OciLayerStreamLimitsV1 {
                        maximum_uncompressed_tar_bytes: 34_359_738_368,
                        maximum_tar_entries: 1_000_000,
                        maximum_regular_file_payload_bytes: 1_073_741_824,
                        maximum_layers: 128,
                    },
                    post_changeset_rootfs: OciPostChangesetRootfsLimitsV1 {
                        maximum_regular_file_bytes: 34_359_738_368,
                        maximum_entries: 1_000_000,
                    },
                }),
            ),
            expected_limits(
                1,
                4_194_304,
                None,
                ArtifactContentLimitsV1::Risc0GuestElf(Risc0GuestElfImportLimitsV1 {
                    maximum_loaded_words: 1_048_576,
                }),
            ),
            expected_limits(
                64,
                1_073_741_824,
                None,
                ArtifactContentLimitsV1::Amd64Elf(Amd64ElfImportLimitsV1 {
                    maximum_program_headers: 65_534,
                    maximum_section_headers: 65_279,
                    runtime_linkage: None,
                }),
            ),
            expected_limits(
                64,
                1_073_741_824,
                None,
                ArtifactContentLimitsV1::Amd64Elf(Amd64ElfImportLimitsV1 {
                    maximum_program_headers: 65_534,
                    maximum_section_headers: 65_279,
                    runtime_linkage: Some(RuntimeAmd64ElfImportLimitsV1 {
                        maximum_dynamic_entries: 65_534,
                        maximum_needed_libraries: 4_096,
                    }),
                }),
            ),
            expected_limits(
                22,
                1_073_741_824,
                None,
                ArtifactContentLimitsV1::JvmJar(JvmJarImportLimitsV1 {
                    maximum_decompressed_regular_file_bytes: 1_073_741_824,
                    maximum_single_decompressed_entry_bytes: 1_073_741_824,
                    maximum_entries: 65_534,
                }),
            ),
            expected_limits(
                22,
                1_073_741_824,
                None,
                ArtifactContentLimitsV1::JvmJar(JvmJarImportLimitsV1 {
                    maximum_decompressed_regular_file_bytes: 1_073_741_824,
                    maximum_single_decompressed_entry_bytes: 1_073_741_824,
                    maximum_entries: 65_534,
                }),
            ),
        ];
        for (role, expected) in B4ImmutableArtifactRoleV1::ALL.into_iter().zip(expected) {
            assert_eq!(role.limits(), expected);
            let (minimum, maximum) = expected.encoded_byte_range();
            assert_encoded_boundaries(role, minimum, maximum);
        }

        let oci = B4ImmutableArtifactRoleV1::OciImageLayoutUstar.limits();
        assert_eq!(oci.encoded_byte_multiple(), Some(512));
        assert!(oci.validate_encoded_length(6_145, "OCI artifact").is_err());
    }

    #[test]
    fn risc0_guest_role_closes_the_loader_work_budget() {
        let guest = B4ImmutableArtifactRoleV1::Risc0GuestElf
            .limits()
            .require_risc0_guest_elf("guest")
            .unwrap();
        assert_eq!(guest.maximum_loaded_words(), 1_048_576);
        assert_eq!(
            guest
                .checked_add_loaded_words(1, 1_048_575, "guest")
                .unwrap(),
            1_048_576
        );
        assert!(
            guest
                .checked_add_loaded_words(1, 1_048_576, "guest")
                .is_err()
        );
        assert!(
            B4ImmutableArtifactRoleV1::ReviewedGitBundle
                .limits()
                .require_risc0_guest_elf("bundle")
                .is_err()
        );
    }

    #[test]
    fn amd64_elf_role_closes_header_and_dynamic_work_budgets() {
        for policy in [Amd64ElfPolicyV1::Static, Amd64ElfPolicyV1::Runtime] {
            let limits = B4ImmutableArtifactRoleV1::Amd64Elf(policy)
                .limits()
                .require_amd64_elf("AMD64 ELF")
                .unwrap();
            assert_eq!(limits.maximum_program_headers(), 65_534);
            assert_eq!(limits.maximum_section_headers(), 65_279);
            assert!(
                limits
                    .validate_program_header_count(0, "AMD64 ELF")
                    .is_err()
            );
            limits
                .validate_program_header_count(65_534, "AMD64 ELF")
                .unwrap();
            assert!(
                limits
                    .validate_program_header_count(65_535, "AMD64 ELF")
                    .is_err()
            );
            limits
                .validate_section_header_count(0, "AMD64 ELF")
                .unwrap();
            limits
                .validate_section_header_count(65_279, "AMD64 ELF")
                .unwrap();
            assert!(
                limits
                    .validate_section_header_count(65_280, "AMD64 ELF")
                    .is_err()
            );
        }

        let static_limits = B4ImmutableArtifactRoleV1::Amd64Elf(Amd64ElfPolicyV1::Static).limits();
        assert!(
            static_limits
                .require_amd64_elf("static AMD64 ELF")
                .unwrap()
                .require_runtime_linkage("static AMD64 ELF")
                .is_err()
        );

        let runtime = B4ImmutableArtifactRoleV1::Amd64Elf(Amd64ElfPolicyV1::Runtime)
            .limits()
            .require_amd64_elf("runtime AMD64 ELF")
            .unwrap()
            .require_runtime_linkage("runtime AMD64 ELF")
            .unwrap();
        assert_eq!(runtime.maximum_dynamic_entries(), 65_534);
        assert_eq!(runtime.maximum_needed_libraries(), 4_096);
        assert!(
            runtime
                .validate_dynamic_entry_count(0, "runtime AMD64 ELF")
                .is_err()
        );
        runtime
            .validate_dynamic_entry_count(65_534, "runtime AMD64 ELF")
            .unwrap();
        assert!(
            runtime
                .validate_dynamic_entry_count(65_535, "runtime AMD64 ELF")
                .is_err()
        );
        runtime
            .validate_needed_library_count(0, "runtime AMD64 ELF")
            .unwrap();
        runtime
            .validate_needed_library_count(4_096, "runtime AMD64 ELF")
            .unwrap();
        assert!(
            runtime
                .validate_needed_library_count(4_097, "runtime AMD64 ELF")
                .is_err()
        );
        assert!(
            B4ImmutableArtifactRoleV1::ReviewedGitBundle
                .limits()
                .require_amd64_elf("Git bundle")
                .is_err()
        );
    }

    #[test]
    fn startup_dependency_contract_closes_graph_and_string_budgets() {
        let limits = startup_dependency_closure_limits_v1();
        assert_eq!(limits.maximum_distinct_objects(), 512);
        assert_eq!(limits.maximum_dependency_edges(), 4_096);
        assert_eq!(limits.maximum_depth(), 64);
        assert_eq!(
            limits.maximum_aggregate_distinct_object_bytes(),
            4_294_967_296
        );
        assert_eq!(limits.maximum_dynamic_basename_bytes(), 240);
        assert_eq!(limits.maximum_runpath_components(), 16);
        assert_eq!(limits.maximum_runpath_component_bytes(), 240);

        assert_eq!(
            limits
                .checked_add_distinct_objects(511, 1, "startup closure")
                .unwrap(),
            512
        );
        assert!(
            limits
                .checked_add_distinct_objects(512, 1, "startup closure")
                .is_err()
        );
        assert_eq!(
            limits
                .checked_add_dependency_edges(4_095, 1, "startup closure")
                .unwrap(),
            4_096
        );
        assert!(
            limits
                .checked_add_dependency_edges(4_096, 1, "startup closure")
                .is_err()
        );
        limits.validate_depth(64, "startup closure").unwrap();
        assert!(limits.validate_depth(65, "startup closure").is_err());
        assert_eq!(
            limits
                .checked_add_distinct_object_bytes(4_294_967_295, 1, "startup closure",)
                .unwrap(),
            4_294_967_296
        );
        assert!(
            limits
                .checked_add_distinct_object_bytes(4_294_967_296, 1, "startup closure")
                .is_err()
        );
        assert!(
            limits
                .checked_add_distinct_object_bytes(u64::MAX, 1, "startup closure")
                .is_err()
        );

        for length in [1, 240] {
            limits
                .validate_dynamic_basename_bytes(length, "startup closure")
                .unwrap();
            limits
                .validate_runpath_component_bytes(length, "startup closure")
                .unwrap();
        }
        for length in [0, 241] {
            assert!(
                limits
                    .validate_dynamic_basename_bytes(length, "startup closure")
                    .is_err()
            );
            assert!(
                limits
                    .validate_runpath_component_bytes(length, "startup closure")
                    .is_err()
            );
        }
        for count in [1, 16] {
            limits
                .validate_runpath_component_count(count, "startup closure")
                .unwrap();
        }
        for count in [0, 17] {
            assert!(
                limits
                    .validate_runpath_component_count(count, "startup closure")
                    .is_err()
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one causal test keeps the independent OCI layer-stream and final-rootfs boundaries visible together"
    )]
    fn oci_counters_keep_layer_stream_and_post_changeset_rootfs_budgets_distinct() {
        let oci = B4ImmutableArtifactRoleV1::OciImageLayoutUstar
            .limits()
            .require_oci("OCI artifact")
            .unwrap();
        assert_eq!(
            oci.maximum_outer_ustar_member_payload_bytes(),
            8_589_934_591
        );
        oci.validate_outer_ustar_member_payload_bytes(8_589_934_591, "OCI member")
            .unwrap();
        assert!(
            oci.validate_outer_ustar_member_payload_bytes(8_589_934_592, "OCI member")
                .is_err()
        );

        let layer_stream = oci.layer_stream();
        assert_eq!(
            layer_stream.maximum_uncompressed_tar_bytes(),
            34_359_738_368
        );
        assert_eq!(
            layer_stream
                .checked_add_uncompressed_tar_bytes(34_359_738_367, 1, "OCI layer streams",)
                .unwrap(),
            34_359_738_368
        );
        assert!(
            layer_stream
                .checked_add_uncompressed_tar_bytes(34_359_738_367, 2, "OCI layer streams",)
                .is_err()
        );
        assert!(
            layer_stream
                .checked_add_uncompressed_tar_bytes(u64::MAX, 1, "OCI layer streams")
                .unwrap_err()
                .to_string()
                .contains("overflow")
        );

        assert_eq!(
            layer_stream.maximum_regular_file_payload_bytes(),
            1_073_741_824
        );
        layer_stream
            .validate_regular_file_payload_bytes(1_073_741_824, "OCI payload")
            .unwrap();
        assert!(
            layer_stream
                .validate_regular_file_payload_bytes(1_073_741_825, "OCI payload")
                .is_err()
        );

        assert_eq!(layer_stream.maximum_tar_entries(), 1_000_000);
        assert_eq!(
            layer_stream
                .checked_add_tar_entries(999_999, 1, "OCI layer entries")
                .unwrap(),
            1_000_000
        );
        assert!(
            layer_stream
                .checked_add_tar_entries(1_000_000, 1, "OCI layer entries")
                .is_err()
        );
        assert!(
            layer_stream
                .checked_add_tar_entries(u64::MAX, 1, "OCI layer entries")
                .unwrap_err()
                .to_string()
                .contains("overflow")
        );

        let rootfs = oci.post_changeset_rootfs();
        assert_eq!(rootfs.maximum_regular_file_bytes(), 34_359_738_368);
        rootfs
            .validate_final_regular_file_bytes(34_359_738_368, "OCI rootfs")
            .unwrap();
        assert!(
            rootfs
                .validate_final_regular_file_bytes(34_359_738_369, "OCI rootfs")
                .is_err()
        );

        assert_eq!(rootfs.maximum_entries(), 1_000_000);
        rootfs
            .validate_final_entry_count(1_000_000, "OCI rootfs")
            .unwrap();
        assert!(
            rootfs
                .validate_final_entry_count(1_000_001, "OCI rootfs")
                .is_err()
        );

        // Overwrites and whiteouts can keep the final rootfs below its ceiling
        // while the independent aggregate layer-stream budget is exceeded.
        rootfs
            .validate_final_entry_count(600_000, "OCI rootfs")
            .unwrap();
        assert!(
            layer_stream
                .checked_add_tar_entries(600_000, 600_000, "OCI layer entries")
                .is_err()
        );

        assert_eq!(layer_stream.maximum_layers(), 128);
        assert_eq!(
            layer_stream
                .checked_add_layer(127, 1, "OCI layers")
                .unwrap(),
            128
        );
        assert!(
            layer_stream
                .checked_add_layer(128, 1, "OCI layers")
                .is_err()
        );
        assert!(
            layer_stream
                .checked_add_layer(u64::MAX, 1, "OCI layers")
                .unwrap_err()
                .to_string()
                .contains("overflow")
        );
    }

    #[test]
    fn jar_counters_are_typed_and_absent_role_budgets_fail_closed() {
        for role in [
            B4ImmutableArtifactRoleV1::JvmJar(JvmJarPolicyV1::SourceRead),
            B4ImmutableArtifactRoleV1::JvmJar(JvmJarPolicyV1::CanonicalExecutable),
        ] {
            let jar = role.limits().require_jvm_jar("JAR artifact").unwrap();
            assert_eq!(jar.maximum_decompressed_regular_file_bytes(), 1_073_741_824);
            assert_eq!(jar.maximum_single_decompressed_entry_bytes(), 1_073_741_824);
            assert_eq!(jar.maximum_entries(), 65_534);
            assert_eq!(
                jar.checked_add_decompressed_regular_file_bytes(1_073_741_823, 1, "JAR expansion",)
                    .unwrap(),
                1_073_741_824
            );
            assert!(
                jar.checked_add_decompressed_regular_file_bytes(1_073_741_824, 1, "JAR expansion",)
                    .is_err()
            );
            jar.validate_single_decompressed_entry_bytes(1_073_741_824, "JAR member")
                .unwrap();
            assert!(
                jar.validate_single_decompressed_entry_bytes(1_073_741_825, "JAR member")
                    .is_err()
            );
            assert_eq!(
                jar.checked_add_entry(65_533, 1, "JAR entries").unwrap(),
                65_534
            );
            assert!(jar.checked_add_entry(65_534, 1, "JAR entries").is_err());
        }

        let git = B4ImmutableArtifactRoleV1::ReviewedGitBundle.limits();
        assert!(git.require_oci("Git bundle").is_err());
        assert!(git.require_jvm_jar("Git bundle").is_err());

        let oci = B4ImmutableArtifactRoleV1::OciImageLayoutUstar.limits();
        assert!(oci.require_jvm_jar("OCI artifact").is_err());
        let jar = B4ImmutableArtifactRoleV1::JvmJar(JvmJarPolicyV1::SourceRead).limits();
        assert!(jar.require_oci("JAR artifact").is_err());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one audit test cross-checks the complete role contract against five schemas"
    )]
    fn role_limits_track_the_machine_readable_finalizer_schemas() {
        fn schema(source: &str) -> Value {
            serde_json::from_str(source).unwrap()
        }

        fn u64_at(schema: &Value, pointer: &str) -> u64 {
            schema.pointer(pointer).and_then(Value::as_u64).unwrap()
        }

        fn str_at<'a>(schema: &'a Value, pointer: &str) -> &'a str {
            schema.pointer(pointer).and_then(Value::as_str).unwrap()
        }

        let campaign = schema(include_str!(
            "../../../reproduction/finalizer-schema/b4-campaign-precommit-v1.schema.json"
        ));
        let input_set = schema(include_str!(
            "../../../reproduction/finalizer-schema/b4-positive-input-set-v1.schema.json"
        ));
        let oci_schema = schema(include_str!(
            "../../../reproduction/finalizer-schema/b4-positive-oci-runner-profile-v1.schema.json"
        ));
        let validator = schema(include_str!(
            "../../../reproduction/finalizer-schema/b4-validator-build-descriptor-v1.schema.json"
        ));
        let jvm_copy = schema(include_str!(
            "../../../reproduction/finalizer-schema/b4-jvm-copy-only-inclusion-manifest-v1.schema.json"
        ));

        let git = B4ImmutableArtifactRoleV1::ReviewedGitBundle.limits();
        assert_eq!(
            git.encoded_byte_range(),
            (
                u64_at(
                    &campaign,
                    "/$defs/IdentityBase/properties/byteLength/minimum"
                ),
                u64_at(
                    &campaign,
                    "/$defs/GitBundleIdentity/allOf/1/properties/byteLength/maximum"
                ),
            )
        );

        let oci_limits = B4ImmutableArtifactRoleV1::OciImageLayoutUstar.limits();
        assert_eq!(
            oci_limits.encoded_byte_range(),
            (
                u64_at(
                    &oci_schema,
                    "/$defs/OciImageArchiveIdentity/properties/byteLength/minimum"
                ),
                u64_at(
                    &oci_schema,
                    "/$defs/OciImageArchiveIdentity/properties/byteLength/maximum"
                ),
            )
        );
        assert_eq!(
            oci_limits.encoded_byte_multiple(),
            Some(u64_at(
                &oci_schema,
                "/$defs/OciImageArchiveIdentity/properties/byteLength/multipleOf"
            ))
        );
        let oci = oci_limits.require_oci("OCI artifact").unwrap();
        assert_eq!(
            oci.maximum_outer_ustar_member_payload_bytes(),
            u64_at(&oci_schema, "/$defs/LayerIdentity/properties/size/maximum")
        );
        assert_eq!(
            oci.maximum_json_bytes(),
            u64_at(
                &oci_schema,
                "/$defs/ManifestDescriptor/properties/size/maximum"
            )
        );
        assert_eq!(
            oci.maximum_json_bytes(),
            u64_at(
                &oci_schema,
                "/$defs/ConfigDescriptor/properties/size/maximum"
            )
        );
        for pointer in [
            "/$defs/ManifestDescriptor/properties/size/minimum",
            "/$defs/ConfigDescriptor/properties/size/minimum",
        ] {
            assert_eq!(u64_at(&oci_schema, pointer), 2);
        }
        for accepted in [2, oci.maximum_json_bytes()] {
            oci.validate_json_bytes(accepted, "OCI JSON").unwrap();
        }
        for rejected in [1, oci.maximum_json_bytes() + 1] {
            assert!(oci.validate_json_bytes(rejected, "OCI JSON").is_err());
        }

        let oci_spec = include_str!("../../../docs/specs/b4-oci-execution-policy-v1.md");
        let layer_stream = oci.layer_stream();
        assert_eq!(
            layer_stream.maximum_uncompressed_tar_bytes(),
            34_359_738_368
        );
        assert!(oci_spec.contains("uncompressed layer lengths is at most 34,359,738,368 bytes."));
        // The per-layer declaration has the same ceiling, but does not replace
        // the independent aggregate-across-layers obligation above.
        assert_eq!(
            layer_stream.maximum_uncompressed_tar_bytes(),
            u64_at(
                &oci_schema,
                "/$defs/LayerIdentity/properties/uncompressedBytes/maximum"
            )
        );

        assert_eq!(layer_stream.maximum_tar_entries(), 1_000_000);
        assert!(oci_spec.contains("across all layers is at most 1,000,000 tar entries"));

        assert_eq!(
            layer_stream.maximum_regular_file_payload_bytes(),
            1_073_741_824
        );
        assert!(oci_spec.contains("one regular-file payload is at most 1,073,741,824 bytes"));

        let rootfs = oci.post_changeset_rootfs();
        assert_eq!(
            rootfs.maximum_regular_file_bytes(),
            u64_at(
                &oci_schema,
                "/$defs/PostChangesetRootfs/properties/regularFileBytes/maximum"
            )
        );
        assert_eq!(
            rootfs.maximum_entries(),
            u64_at(
                &oci_schema,
                "/$defs/PostChangesetRootfs/properties/entryCount/maximum"
            )
        );
        assert_eq!(
            layer_stream.maximum_layers(),
            u64_at(
                &oci_schema,
                "/$defs/OciImageIdentity/properties/layers/maxItems"
            )
        );

        let guest = B4ImmutableArtifactRoleV1::Risc0GuestElf.limits();
        assert_eq!(
            guest.encoded_byte_range(),
            (
                u64_at(
                    &input_set,
                    "/$defs/GuestElfIdentity/properties/byteLength/minimum"
                ),
                u64_at(
                    &input_set,
                    "/$defs/GuestElfIdentity/properties/byteLength/maximum"
                ),
            )
        );

        let static_limits = B4ImmutableArtifactRoleV1::Amd64Elf(Amd64ElfPolicyV1::Static).limits();
        let static_elf = static_limits.encoded_byte_range();
        let static_work = static_limits.require_amd64_elf("static AMD64 ELF").unwrap();
        let validator_static_elf = (
            u64_at(
                &validator,
                "/$defs/NativeArtifactIdentity/properties/byteLength/minimum",
            ),
            u64_at(
                &validator,
                "/$defs/NativeArtifactIdentity/properties/byteLength/maximum",
            ),
        );
        let oci_static_elf = (
            u64_at(
                &oci_schema,
                "/$defs/BinaryIdentity/properties/byteLength/minimum",
            ),
            u64_at(
                &oci_schema,
                "/$defs/BinaryIdentity/properties/byteLength/maximum",
            ),
        );
        assert_eq!(static_elf, validator_static_elf);
        assert_eq!(static_elf, oci_static_elf);
        assert_eq!(
            static_work.maximum_program_headers(),
            u64_at(
                &validator,
                "/$defs/StaticElfInspection/properties/programHeaderCount/maximum",
            )
        );
        assert_eq!(
            static_work.maximum_program_headers(),
            u64_at(
                &oci_schema,
                "/$defs/StaticElfInspection/properties/programHeaderCount/maximum",
            )
        );
        assert_eq!(
            static_work.maximum_section_headers(),
            u64_at(
                &validator,
                "/$defs/StaticElfInspection/properties/sectionHeaderCount/maximum",
            )
        );
        assert_eq!(
            static_work.maximum_section_headers(),
            u64_at(
                &oci_schema,
                "/$defs/StaticElfInspection/properties/sectionHeaderCount/maximum",
            )
        );
        assert!(oci_spec.contains("1 through 65,279 directly"));
        assert_eq!(
            str_at(
                &validator,
                "/$defs/NativeArtifactIdentity/properties/inspectionPolicy/const",
            ),
            "eip0045-b4-elf64-amd64-static-v1"
        );
        assert_eq!(
            str_at(
                &oci_schema,
                "/$defs/BinaryIdentity/properties/inspectionPolicy/const",
            ),
            "eip0045-b4-elf64-amd64-static-v1"
        );

        let runtime_limits =
            B4ImmutableArtifactRoleV1::Amd64Elf(Amd64ElfPolicyV1::Runtime).limits();
        let runtime_elf = runtime_limits.encoded_byte_range();
        let runtime_work = runtime_limits
            .require_amd64_elf("runtime AMD64 ELF")
            .unwrap();
        assert_eq!(
            runtime_work.maximum_program_headers(),
            u64_at(
                &oci_schema,
                "/$defs/RuntimeElfInspection/properties/programHeaderCount/maximum",
            )
        );
        assert_eq!(
            runtime_work.maximum_section_headers(),
            u64_at(
                &oci_schema,
                "/$defs/RuntimeElfInspection/properties/sectionHeaderCount/maximum",
            )
        );
        let runtime_linkage = runtime_work
            .require_runtime_linkage("runtime AMD64 ELF")
            .unwrap();
        assert_eq!(
            runtime_linkage.maximum_dynamic_entries(),
            u64_at(
                &oci_schema,
                "/$defs/RuntimeElfInspection/properties/dynamicEntryCount/maximum",
            )
        );
        assert_eq!(
            runtime_linkage.maximum_needed_libraries(),
            u64_at(
                &oci_schema,
                "/$defs/RuntimeElfInspection/properties/neededLibraryCount/maximum",
            )
        );
        assert!(oci_spec.contains("that count is 1 through 65,534"));
        assert!(oci_spec.contains("neededLibraryCount"));
        assert!(oci_spec.contains("is at most 4,096"));
        for identity in ["ImageJavaBinaryIdentity", "ImageJavacBinaryIdentity"] {
            assert_eq!(
                runtime_elf,
                (
                    u64_at(
                        &oci_schema,
                        &format!("/$defs/{identity}/properties/byteLength/minimum"),
                    ),
                    u64_at(
                        &oci_schema,
                        &format!("/$defs/{identity}/properties/byteLength/maximum"),
                    ),
                )
            );
            assert_eq!(
                str_at(
                    &oci_schema,
                    &format!("/$defs/{identity}/properties/inspectionPolicy/const"),
                ),
                "eip0045-b4-elf64-amd64-runtime-v1"
            );
        }

        let source_jar = B4ImmutableArtifactRoleV1::JvmJar(JvmJarPolicyV1::SourceRead).limits();
        assert_eq!(
            source_jar.encoded_byte_range(),
            (
                u64_at(
                    &jvm_copy,
                    "/$defs/InputArchive/properties/byteLength/minimum"
                ),
                u64_at(
                    &jvm_copy,
                    "/$defs/InputArchive/properties/byteLength/maximum"
                ),
            )
        );
        let executable_jar =
            B4ImmutableArtifactRoleV1::JvmJar(JvmJarPolicyV1::CanonicalExecutable).limits();
        assert_eq!(
            executable_jar.encoded_byte_range(),
            (
                u64_at(
                    &validator,
                    "/$defs/JvmArtifactIdentity/properties/byteLength/minimum"
                ),
                u64_at(
                    &validator,
                    "/$defs/JvmArtifactIdentity/properties/byteLength/maximum"
                ),
            )
        );
        assert_eq!(
            executable_jar
                .require_jvm_jar("canonical executable JAR")
                .unwrap()
                .maximum_decompressed_regular_file_bytes(),
            u64_at(
                &validator,
                "/$defs/JvmJarArchiveInspection/properties/uncompressedByteLength/maximum"
            )
        );
        assert_eq!(
            executable_jar
                .require_jvm_jar("canonical executable JAR")
                .unwrap()
                .maximum_single_decompressed_entry_bytes(),
            u64_at(
                &validator,
                "/$defs/JvmJarArchiveInspection/properties/largestEntryUncompressedByteLength/maximum"
            )
        );
        assert_eq!(
            executable_jar
                .require_jvm_jar("canonical executable JAR")
                .unwrap()
                .maximum_entries(),
            u64_at(
                &validator,
                "/$defs/JvmJarArchiveInspection/properties/entryCount/maximum"
            )
        );

        let source_jar_expansion = source_jar.require_jvm_jar("source-read JAR").unwrap();
        let executable_jar_expansion = executable_jar
            .require_jvm_jar("canonical executable JAR")
            .unwrap();
        assert_eq!(source_jar_expansion, executable_jar_expansion);
        let jvm_spec = include_str!("../../../docs/specs/b4-jvm-artifact-policy-v1.md");
        assert!(jvm_spec.contains("It uses the classic ZIP bounds,"));
        assert!(jvm_spec.contains("The exact archive is at most 1,073,741,824 bytes."));
        assert!(jvm_spec.contains("There are 1 through 65,534 entries."));
        assert!(jvm_spec.contains(
            "The sum of decompressed regular-file sizes is at most 1,073,741,824 bytes."
        ));
        assert!(jvm_spec.contains(
            "One decompressed entry is at most the same 1,073,741,824-byte total bound;"
        ));
    }
}
