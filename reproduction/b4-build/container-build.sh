#!/bin/bash
# B4 guest-build execution body. This file runs *inside* the already pinned image; the
# host runners supply every mount and the network/read-only boundary.
set -Eeuo pipefail
shopt -s inherit_errexit
set -f

if [ "${B4_BUILD_ENV_CLEARED:-}" != "1" ]; then
    exec env -i \
        B4_BUILD_ENV_CLEARED=1 \
        HOME=/home/ergo/eip0045 \
        CARGO_HOME=/home/ergo/eip0045/.cargo \
        RUSTUP_HOME=/opt/eip0045-host-rust/rustup \
        RISC0_HOME=/root/.risc0 \
        HOST_RUST_TOOLCHAIN=/opt/eip0045-host-rust/rustup/toolchains/1.89.0-x86_64-unknown-linux-gnu \
        PATH=/opt/eip0045-host-rust/rustup/toolchains/1.89.0-x86_64-unknown-linux-gnu/bin:/root/.risc0/bin:/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        CARGO_NET_OFFLINE=true \
        CARGO_TARGET_DIR=/target \
        RISC0_BUILD_LOCKED=1 \
        bash "$0" "$@"
fi

label=${1:?missing run label}
diagnostics_helper=/workspace/reproduction/b4-build/diagnostics.sh
[ -f "$diagnostics_helper" ] || {
    printf '%s\n' "B4 build: diagnostics helper is absent: $diagnostics_helper" >&2
    exit 1
}
# shellcheck source=diagnostics.sh
source "$diagnostics_helper"
b4_diag_init /work/diagnostics "$label" || {
    printf '%s\n' 'B4 build: cannot initialize the private work-root diagnostics' >&2
    exit 1
}
readonly expected_commit=227229dc793c215c533cbc0e07911601974a4629
readonly declared_source_tree=a4e8abc0fffa0eab25f66266150f998f581f1cac
readonly expected_source_lock_sha=5a108fef13e051f497679ef07ba887230ba355d281c109691dbcd24d92328382
readonly expected_reproduction_lock_sha=3aa38c8482cfe62afc52320738732bbf5cbf4407a0fa4ff22c4efae651788942
readonly expected_methods_lock_sha=4549d2e5efb2d7a4c593cbe95f227c9403f0907402d81b0b7f25dcf755be91f8
readonly expected_guest_lock_sha=b9a54396d06a116dfe26ed5546c1354f70e22d4b142d4132de786f886c07636f
readonly expected_generator_lock_sha=b3e02a7e3605d723995f0f49c5744907f0b32d317665bfe9676ca9f648a4e495
readonly host_target=x86_64-unknown-linux-gnu
readonly guest_target=riscv32im-risc0-zkvm-elf
readonly embedded_exact_test=recursive::tests::pinned_guest_explicit_root_twice_proves_duplicate_heads_and_lift

fail_with_status() {
    local status=$1 kind=$2 line_number=$3 command_text=$4
    shift 4
    local message=$*
    b4_diag_record_failure "$status" "$line_number" "$kind" "$command_text" "$message" || true
    printf '%s\n' "B4 build: $message" >&2
    exit "$status"
}
die() {
    local line_number=${BASH_LINENO[0]:-$LINENO}
    fail_with_status 1 explicit-die "$line_number" die "$*"
}
# BEGIN EIP0045 PHYSICAL PATH PREDICATE
require_exact_physical_path() {
    local kind=$1 label=$2 path=$3 expected_path=$4 canonical_path link_count
    case $kind in
        directory|regular-file) ;;
        *) die "physical-path predicate kind is not admitted: $kind" ;;
    esac
    [ "$path" = "$expected_path" ] \
        || die "$label is outside its exact required path: $expected_path"
    [ ! -L "$path" ] || die "$label is a symlink"
    canonical_path=$(readlink -f -- "$path") \
        || die "cannot canonicalize $label"
    [ "$canonical_path" = "$expected_path" ] \
        || die "$label is not physically canonical"
    case $kind in
        directory)
            [ -d "$canonical_path" ] || die "$label is not a physical directory"
            ;;
        regular-file)
            [ -f "$canonical_path" ] || die "$label is not a physical regular file"
            link_count=$(stat -c '%h' -- "$canonical_path") \
                || die "cannot inspect $label link count"
            [ "$link_count" = 1 ] || die "$label must have link count 1"
            ;;
    esac
}
# END EIP0045 PHYSICAL PATH PREDICATE
require_exact_physical_path directory CARGO_TARGET_DIR "$CARGO_TARGET_DIR" /target
require_exact_physical_path directory CARGO_MANIFEST_DIR /workspace/methods /workspace/methods
sha256() {
    local output digest
    output=$(sha256sum -- "$1") || return 1
    digest=${output%% *}
    [ "${#digest}" = 64 ] || return 1
    case $digest in *[!0-9a-f]*) return 1 ;; esac
    printf '%s\n' "$digest"
}
extract_generated_guest_path() {
    local symbol=$1 methods_file=$2 declaration count path expected_path
    if ! declaration=$(grep -F "pub const ${symbol}_ELF: &[u8] = include_bytes!(" "$methods_file"); then
        die "generated ${symbol}_ELF declaration is absent"
    fi
    if ! count=$(printf '%s\n' "$declaration" | wc -l | tr -d '[:space:]'); then
        die "cannot count generated ${symbol}_ELF declarations"
    fi
    [ "$count" = 1 ] || die "generated ${symbol}_ELF declaration is not unique"
    if ! path=$(printf '%s\n' "$declaration" \
        | sed -n "s|^pub const ${symbol}_ELF: &\\[u8\\] = include_bytes!(\"\\([^\"]*\\.bin\\)\");\$|\\1|p"); then
        die "cannot parse generated ${symbol}_ELF path"
    fi
    case $symbol in
        EIP_0045_GUEST)
            expected_path=/target/riscv-guest/eip-0045-methods/eip-0045-guest/riscv32im-risc0-zkvm-elf/release/eip-0045-guest.bin
            ;;
        EIP_0045_ALTERNATE_PROGRAM_GUEST)
            expected_path=/target/riscv-guest/eip-0045-methods/eip-0045-guest/riscv32im-risc0-zkvm-elf/release/eip-0045-alternate-program-guest.bin
            ;;
        *) die "generated guest symbol is not admitted: $symbol" ;;
    esac
    require_exact_physical_path regular-file "generated ${symbol}_ELF" "$path" "$expected_path"
    printf '%s\n' "$path"
}
extract_generated_image_id_declaration() {
    local symbol=$1 methods_file=$2 output_file=$3 declaration count
    if ! declaration=$(grep -F "pub const ${symbol}_ID: [u32; 8] = [" "$methods_file"); then
        die "generated ${symbol}_ID declaration is absent"
    fi
    if ! count=$(printf '%s\n' "$declaration" | wc -l | tr -d '[:space:]'); then
        die "cannot count generated ${symbol}_ID declarations"
    fi
    [ "$count" = 1 ] || die "generated ${symbol}_ID declaration is not unique"
    printf '%s\n' "$declaration" | tr -d '[:space:]' > "$output_file"
    grep -F "pubconst${symbol}_ID:[u32;8]=[" "$output_file" >/dev/null \
        || die "generated ${symbol}_ID declaration is malformed"
    grep -F '];' "$output_file" >/dev/null \
        || die "generated ${symbol}_ID declaration has no terminator"
}
require_generated_image_id_matches() {
    local symbol=$1 image_id_file=$2 declaration_file=$3 declaration_words binary_words
    declaration_words=$(sed -n 's/.*=\[\(.*\)\];/\1/p' "$declaration_file")
    binary_words=$(od -An -v -tu4 -w32 "$image_id_file" | awk '{$1=$1; gsub(/ /,","); print}') \
        || die "cannot decode ${symbol}_ID canonical words"
    [ "$declaration_words" = "$binary_words" ] \
        || die "canonical ${symbol}_ID bytes differ from the generated u32 declaration"
}
write_hex_file() {
    hex_input=$1
    hex_output=$2
    [ $(( ${#hex_input} % 2 )) -eq 0 ] || die "hex input has odd length"
    : > "$hex_output"
    for ((hex_offset = 0; hex_offset < ${#hex_input}; hex_offset += 2)); do
        printf '%b' "\\x${hex_input:hex_offset:2}" >> "$hex_output"
    done
}
normalize_host_work_permissions() {
    for cleanup_root in /target /work; do
        [ -d "$cleanup_root" ] || continue
        find "$cleanup_root" -xdev -type d -exec chmod a+rwx {} + 2>/dev/null || true
        find "$cleanup_root" -xdev -type f -exec chmod a+rw {} + 2>/dev/null || true
    done
}
container_exit() {
    local status=$?
    trap - EXIT ERR HUP INT TERM
    set +e
    if [ "$status" -ne 0 ] && [ ! -e "$B4_DIAG_ROOT/failure.txt" ]; then
        b4_diag_record_failure "$status" 0 exit-without-err EXIT '' || true
    fi
    b4_diag_write_exit_state "$status" started || true
    normalize_host_work_permissions
    b4_diag_write_exit_state "$status" complete || true
    exit "$status"
}
trap 'b4_diag_on_err "$?" "$LINENO" "$BASH_COMMAND"' ERR
trap container_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
[ "$BASH_VERSION" = '5.0.17(1)-release' ] || die "unexpected pinned runtime Bash version: $BASH_VERSION"
file_size() { stat -c '%s' -- "$1"; }
write_hash_record() {
    local key=$1
    local path=$2
    local digest
    digest=$(sha256 "$path") || die "cannot hash $path"
    printf '%s=%s\n' "$key" "$digest"
}
write_size_record() {
    local key=$1
    local path=$2
    local size
    size=$(file_size "$path") || die "cannot read size: $path"
    printf '%s=%s\n' "$key" "$size"
}
write_file_manifest_record() {
    record_path=$1
    record_name=$2
    record_mode=$(stat -c '%a' "$record_path") || die "cannot read mode: $record_path"
    record_sha=$(sha256 "$record_path") || die "cannot hash: $record_path"
    record_size=$(file_size "$record_path") || die "cannot read size: $record_path"
    if [ $((0$record_mode & 0111)) -ne 0 ]; then
        record_executable=true
    else
        record_executable=false
    fi
    printf 'file path=%s executable=%s sha256=%s size=%s\n' \
        "$record_name" \
        "$record_executable" \
        "$record_sha" \
        "$record_size"
}
require_hash() {
    actual=$(sha256 "$1") || die "cannot hash $1"
    [ "$actual" = "$2" ] || die "hash mismatch: $1"
}
require_size() {
    actual=$(file_size "$1") || die "cannot stat $1"
    [ "$actual" = "$2" ] || die "size mismatch: $1 (expected $2, got $actual)"
}
reject_special_nodes() {
    local scan_label=$1
    shift
    b4_diag_validate_token "$scan_label" || die "invalid special-node scan label: $scan_label"
    local scan_status line_number=$LINENO
    if b4_diag_reject_special_nodes "$scan_label" "$line_number" "$@"; then
        return 0
    else
        scan_status=$?
    fi
    fail_with_status "$scan_status" "$B4_DIAG_SCAN_KIND" "$line_number" find "$B4_DIAG_SCAN_MESSAGE"
}
reject_hard_links() {
    local scan_label=$1
    shift
    b4_diag_validate_token "$scan_label" || die "invalid hard-link scan label: $scan_label"
    local scan_status line_number=$LINENO
    if b4_diag_reject_hard_links "$scan_label" "$line_number" "$@"; then
        return 0
    else
        scan_status=$?
    fi
    fail_with_status "$scan_status" "$B4_DIAG_SCAN_KIND" "$line_number" find "$B4_DIAG_SCAN_MESSAGE"
}
reject_crlf_paths() {
    local scan_label=$1 root=$2 scan_status line_number=$LINENO
    b4_diag_validate_token "$scan_label" || die "invalid CR/LF scan label: $scan_label"
    if b4_diag_reject_crlf_paths "$scan_label" "$root" "$line_number"; then
        return 0
    else
        scan_status=$?
    fi
    if [ "$scan_status" = 91 ]; then
        fail_with_status "$scan_status" forbidden-path "$line_number" find \
            "path containing CR or LF is not admitted for $scan_label"
    fi
    fail_with_status "$scan_status" enumeration-failure "$line_number" find \
        "path enumeration failed for $scan_label with status $scan_status; stderr retained in work-root diagnostics"
}
write_workspace_manifest() {
    output=$1
    {
        for path in /workspace/Cargo.toml /workspace/Cargo.lock /workspace/rust-toolchain.toml /workspace/Dockerfile.reproduction; do
            [ -f "$path" ] || die "required workspace source is missing: $path"
            write_file_manifest_record "$path" "${path#/workspace/}"
        done
        find /workspace/reproduction /workspace/methods /workspace/generator /workspace/profiles/risc0-v3-succinct -xdev -type f ! -path '*/target/*' ! -path '*/.git/*' -print | LC_ALL=C sort | while IFS= read -r path; do
            write_file_manifest_record "$path" "${path#/workspace/}"
        done
    } | LC_ALL=C sort > "$output"
}
write_materialized_source_manifest() {
    source_root=$1
    output=$2
    (
        cd "$source_root"
        find . -xdev -type f ! -path './.git/*' ! -name .cargo-ok -print | LC_ALL=C sort | while IFS= read -r path; do
            write_file_manifest_record "$path" "${path#./}"
        done
    ) > "$output"
}
normalize_checkout_admin() {
    checkout_root=$1
    case $checkout_root in
        "$CARGO_HOME"/git/checkouts/*/*) ;;
        *) die "refusing to normalize Git administration outside the private Cargo checkout root" ;;
    esac
    [ -d "$checkout_root/.git" ] && [ ! -L "$checkout_root/.git" ] || die "checkout .git is not a physical directory"
    [ -f "$checkout_root/.cargo-ok" ] && [ ! -L "$checkout_root/.cargo-ok" ] || die "checkout .cargo-ok is not a physical regular file"
    [ ! -s "$checkout_root/.cargo-ok" ] || die "checkout .cargo-ok is not empty"

    # Cargo creates checkout-time reflogs and an index containing filesystem
    # timestamps. Neither is required to resolve a locked Git dependency. Drop
    # that volatile administration before compilation; if Cargo recreates any
    # of it, the before/after administration manifest below fails closed.
    rm -rf \
        "$checkout_root/.git/logs" \
        "$checkout_root/.git/hooks" \
        "$checkout_root/.git/info"
    rm -f \
        "$checkout_root/.git/index" \
        "$checkout_root/.git/FETCH_HEAD" \
        "$checkout_root/.git/description"
}
write_checkout_admin_manifest() {
    checkout_root=$1
    output=$2
    [ -d "$checkout_root/.git" ] && [ ! -L "$checkout_root/.git" ] || die "checkout .git is not a physical directory"
    [ -f "$checkout_root/.cargo-ok" ] && [ ! -L "$checkout_root/.cargo-ok" ] || die "checkout .cargo-ok is not a physical regular file"
    reject_special_nodes checkout-administration "$checkout_root/.git" "$checkout_root/.cargo-ok"
    reject_hard_links checkout-administration-hard-links "$checkout_root/.git" "$checkout_root/.cargo-ok"
    (
        cd "$checkout_root"
        find .git .cargo-ok -xdev -type f -print | LC_ALL=C sort | while IFS= read -r path; do
            write_file_manifest_record "$path" "$path"
        done
    ) > "$output"
}
materialize_risc0_checkout() {
    checkout_found=0
    checkout_candidates_unsorted=/work/risc0-checkout-candidates.unsorted
    checkout_candidates=/work/risc0-checkout-candidates.sorted
    find "$CARGO_HOME/git/checkouts" -xdev -type d -print0 > "$checkout_candidates_unsorted" \
        || die "cannot enumerate fresh Cargo checkouts"
    LC_ALL=C sort -z "$checkout_candidates_unsorted" > "$checkout_candidates" \
        || die "cannot sort fresh Cargo checkout paths"
    while IFS= read -r -d '' candidate; do
        [ -f "$candidate/risc0/zkvm/Cargo.toml" ] || continue
        [ -f "$candidate/Cargo.lock" ] || continue
        [ "$checkout_found" = 0 ] || die "more than one pinned RISC Zero checkout was materialized"
        [ -d "$candidate/.git" ] || die "fresh Cargo checkout lacks a physical Git administrative directory"
        reject_special_nodes checkout-initial "$candidate"
        reject_crlf_paths checkout-initial-paths "$candidate"
        require_size "$candidate/.git/HEAD" 23
        require_hash "$candidate/.git/HEAD" f6f2b945f6c411b02ba3da9c7ace88dcf71b6af65ba2e0d89aa82900042b5a10
        require_size "$candidate/.git/refs/heads/master" 41
        require_hash "$candidate/.git/refs/heads/master" dc272acfd1abafa8eb35d2d4e66f13d175cbf27431a8256bfbfb31053f945ff6
        actual_commit=$(cat "$candidate/.git/refs/heads/master") || die "cannot read checkout commit ref"
        [ "$actual_commit" = "$expected_commit" ] || die "fresh Cargo checkout commit mismatch"
        actual_tree=$("$reproduction_cli" git-tree --source-root "$candidate") || die "cannot reconstruct checkout root tree"
        [ "$actual_tree" = "$declared_source_tree" ] || die "fresh Cargo checkout tree mismatch"
        circom_pointer="$candidate/groth16_proof/groth16/stark_verify.circom"
        recursion_pointer="$candidate/risc0/circuit/recursion/src/recursion_zkr.zip"
        require_size "$circom_pointer" 133
        require_hash "$circom_pointer" 80fa1d37ad35395391e8115ea8e26e6f5d2b77a1b2ac321da5068903631a2463
        require_size "$recursion_pointer" 133
        require_hash "$recursion_pointer" 34b81b81bd2664696b3a4ed1fbf385bd40443ca43b125b5eda3f9dc5fc32aceb
        b4_normalize_cargo_checkout_pack_hard_links "$candidate" "$CARGO_HOME/git" \
            || die "fresh Cargo checkout hardlink normalization failed"
        reject_hard_links checkout-initial-hard-links "$candidate"
        normalize_checkout_admin "$candidate"
        write_checkout_admin_manifest "$candidate" /output/source-checkout-admin-manifest-before.txt
        {
            printf 'commit=%s\n' "$actual_commit"
            printf 'tree=%s\n' "$actual_tree"
            printf 'computedCheckoutTreeExact=true\n'
            printf 'excludedCargoMarker=.cargo-ok\n'
            printf 'circomPointerGitBlobSha1=%s\n' 81557c4f15ce43f5c7c840c287e76abd3a676cd5
            printf 'circomPointerByteLength=133\n'
            printf 'circomPointerSha256=%s\n' 80fa1d37ad35395391e8115ea8e26e6f5d2b77a1b2ac321da5068903631a2463
            printf 'recursionPointerGitBlobSha1=%s\n' 78e673e7dcbe0c04d3246db18645ae4b67c03c99
            printf 'recursionPointerByteLength=133\n'
            printf 'recursionPointerSha256=%s\n' 34b81b81bd2664696b3a4ed1fbf385bd40443ca43b125b5eda3f9dc5fc32aceb
        } > /output/source-git-observed.txt
        cp /seed/lfs/a3789471909ba1a13cca783dc5269b25b6d41295abe60234a8075f750017518c "$candidate/groth16_proof/groth16/stark_verify.circom"
        cp /seed/lfs/744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849 "$candidate/risc0/circuit/recursion/src/recursion_zkr.zip"
        require_size "$candidate/Cargo.lock" 243680
        require_hash "$candidate/Cargo.lock" "$expected_source_lock_sha"
        require_size "$candidate/groth16_proof/groth16/stark_verify.circom" 58353446
        require_hash "$candidate/groth16_proof/groth16/stark_verify.circom" a3789471909ba1a13cca783dc5269b25b6d41295abe60234a8075f750017518c
        require_size "$candidate/risc0/circuit/recursion/src/recursion_zkr.zip" 59768781
        require_hash "$candidate/risc0/circuit/recursion/src/recursion_zkr.zip" 744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849
        reject_special_nodes checkout-materialized "$candidate"
        reject_hard_links checkout-materialized-hard-links "$candidate"
        reject_crlf_paths checkout-materialized-paths "$candidate"
        risc0_checkout=$candidate
        write_materialized_source_manifest "$candidate" /output/source-materialized-manifest-before.txt
        checkout_found=1
    done < "$checkout_candidates"
    rm -f "$checkout_candidates_unsorted" "$checkout_candidates"
    [ "$checkout_found" = 1 ] || die "fresh Cargo checkout does not contain the pinned risc0 commit"
}

[ "$(command -v cargo)" = "$HOST_RUST_TOOLCHAIN/bin/cargo" ] || die "cargo is not the pinned direct host toolchain binary"
cargo -vV | grep -F 'release: 1.89.0' >/dev/null || die "unexpected host cargo version"
rustc -vV | grep -F 'release: 1.89.0' >/dev/null || die "unexpected host rustc version"
rustc -vV | grep -F "host: $host_target" >/dev/null || die "unexpected host Rust target"
[ "$(rustc --print sysroot)" = "$HOST_RUST_TOOLCHAIN" ] || die "unexpected host rustc sysroot"
guest_toolchain=/root/.risc0/toolchains/v1.88.0-rust-x86_64-unknown-linux-gnu
guest_cargo="$guest_toolchain/bin/cargo"
guest_rustc="$guest_toolchain/bin/rustc"
[ -x "$guest_cargo" ] && [ -x "$guest_rustc" ] || die "pinned guest toolchain binaries are absent"
"$guest_cargo" -vV | grep -F 'release: 1.88.0' >/dev/null || die "unexpected guest cargo version"
"$guest_rustc" -vV | grep -F 'release: 1.88.0' >/dev/null || die "unexpected guest rustc version"
[ "$("$guest_rustc" --print sysroot)" = "$guest_toolchain" ] || die "unexpected guest rustc sysroot"
"$guest_rustc" --print cfg --target "$guest_target" | grep -F 'target_arch="riscv32"' >/dev/null || die "pinned guest target is unavailable"
[ "$CARGO_HOME" = "$HOME/.cargo" ] || die "Cargo home must equal the default HOME/.cargo path seen after risc0-build sanitization"

observed_nproc=$(nproc) || die "cannot observe container CPU affinity"
[ "$observed_nproc" = 4 ] || die "container CPU affinity is not the frozen four-CPU set"
if [ -f /sys/fs/cgroup/cpuset.cpus.effective ]; then
    observed_cpu_set=$(cat /sys/fs/cgroup/cpuset.cpus.effective)
else
    observed_cpu_set=$(cat /sys/fs/cgroup/cpuset/cpuset.cpus)
fi
[ "$observed_cpu_set" = 0-3 ] || die "container CPU set mismatch"
if [ -f /sys/fs/cgroup/memory.max ]; then
    cgroup_version=2
    [ -f /sys/fs/cgroup/memory.swap.max ] || die "cgroup v2 swap controller is unavailable"
    observed_memory_max=$(cat /sys/fs/cgroup/memory.max)
    observed_swap_field=memorySwapMaxBytes
    observed_swap_limit=$(cat /sys/fs/cgroup/memory.swap.max)
    [ "$observed_memory_max" = 12884901888 ] || die "container memory limit mismatch"
    [ "$observed_swap_limit" = 0 ] || die "container swap limit mismatch"
else
    cgroup_version=1
    [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ] || die "cgroup v1 memory controller is unavailable"
    [ -f /sys/fs/cgroup/memory/memory.memsw.limit_in_bytes ] || die "cgroup v1 memory+swap accounting is unavailable"
    observed_memory_max=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes)
    observed_swap_field=memoryMemswLimitBytes
    observed_swap_limit=$(cat /sys/fs/cgroup/memory/memory.memsw.limit_in_bytes)
    [ "$observed_memory_max" = 12884901888 ] || die "container memory limit mismatch"
    [ "$observed_swap_limit" = 12884901888 ] || die "container memory+swap limit mismatch"
fi

reject_special_nodes input-roots /workspace /seed/cargo /seed/lfs
reject_hard_links input-root-hard-links /workspace /seed/cargo /seed/lfs
reject_crlf_paths input-workspace-paths /workspace
reject_crlf_paths input-seed-cargo-paths /seed/cargo
reject_crlf_paths input-seed-lfs-paths /seed/lfs
mkdir -p /output
write_workspace_manifest /output/workspace-source-manifest-before.txt
{
    cargo -vV
    rustc -vV
    printf 'selectedHostTarget=%s\n' "$host_target"
} > /output/host-toolchain-observed.txt
{
    printf 'guestBuildCargoRole=host-orchestrator\n'
    cargo -vV
    printf 'guestCompilerRole=risc0-rustc\n'
    "$guest_rustc" -vV
    printf 'bundledGuestCargoRole=observed-not-invoked\n'
    "$guest_cargo" -vV
    rzup show
} > /output/guest-toolchain-observed.txt
{
    printf 'hostTarget=%s\n' "$host_target"
    printf 'guestTarget=%s\n' "$guest_target"
    printf 'generatorProfile=release\n'
    printf 'guestProfile=release\n'
    printf 'cargoProfileConfigurationBinding=clean-workspace-git-tree-and-workspace-source-manifest\n'
    printf 'cargoBuildJobs=2\n'
    printf 'cargoBuildJobsEnforcement=config-build.jobs\n'
    printf 'cargoIncremental=disabled\n'
    printf 'cargoIncrementalEnforcement=config-build.incremental\n'
    printf 'containerCpuSet=0-3\n'
    printf 'containerMemoryBytes=12884901888\n'
    printf 'containerSwapBytes=0\n'
    printf 'proofPolicyLifecycle=unexercised-pending-b7\n'
    printf 'plannedLocalProverBackend=risc0-local-in-process\n'
    printf 'plannedLocalProverName=eip-0045-pinned-local\n'
    printf 'candidateExecutorSegmentLimitPo2=23\n'
    printf 'candidateMinSegmentPo2=15\n'
    printf 'candidateMaxSegmentPo2=22\n'
    printf 'plannedReceiptKind=succinct\n'
    printf 'plannedHashSuite=poseidon2\n'
    printf 'plannedDevMode=disabled\n'
    printf 'plannedVerifierDevMode=disabled\n'
    printf 'plannedProveGuestErrors=disabled\n'
} > /output/build-policy.txt
{
    printf 'cgroupVersion=%s\n' "$cgroup_version"
    printf 'nproc=%s\n' "$observed_nproc"
    printf 'cpuSet=%s\n' "$observed_cpu_set"
    printf 'memoryMaxBytes=%s\n' "$observed_memory_max"
    printf '%s=%s\n' "$observed_swap_field" "$observed_swap_limit"
    printf 'additionalSwapBytes=0\n'
} > /output/resource-policy-observed.txt
workspace_cargo_config=$(find /workspace -xdev \( -path '*/.cargo/config' -o -path '*/.cargo/config.toml' \) -print -quit) \
    || die "cannot inspect mounted source Cargo configuration"
if [ -n "$workspace_cargo_config" ]; then
    die "Cargo configuration in the mounted source is not admitted"
fi
# Expanded crates and checkouts are discarded before Cargo runs. Their own
# `.cargo` fixtures are not configuration inputs, so do not reject them before
# deleting them; every retained seed path remains configuration-free.
seed_cargo_config=$(find /seed/cargo -xdev \( -path /seed/cargo/registry/src -o -path /seed/cargo/git/checkouts \) -prune -o \( -path '*/.cargo/config' -o -path '*/.cargo/config.toml' \) -print -quit) \
    || die "cannot inspect retained seed Cargo configuration"
if [ -n "$seed_cargo_config" ]; then
    die "Cargo configuration in a retained seed input is not admitted"
fi
[ ! -e /seed/cargo/config ] && [ ! -e /seed/cargo/config.toml ] || die "seed Cargo home must not provide a Cargo config"

require_size /seed/lfs/a3789471909ba1a13cca783dc5269b25b6d41295abe60234a8075f750017518c 58353446
require_hash /seed/lfs/a3789471909ba1a13cca783dc5269b25b6d41295abe60234a8075f750017518c a3789471909ba1a13cca783dc5269b25b6d41295abe60234a8075f750017518c
require_size /seed/lfs/744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849 59768781
require_hash /seed/lfs/744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849 744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849

require_hash /workspace/methods/Cargo.lock "$expected_methods_lock_sha"
require_hash /workspace/methods/guest/Cargo.lock "$expected_guest_lock_sha"
require_hash /workspace/generator/Cargo.lock "$expected_generator_lock_sha"
require_hash /workspace/Cargo.lock "$expected_reproduction_lock_sha"

mkdir -p "$CARGO_HOME"
# A B4 build seed supplies only content-addressed inputs. Never copy a previously
# unpacked crate or Git checkout into the private home: Cargo must materialize
# both again from registry/cache+index and git/db below.
[ -d /seed/cargo/registry/cache ] && [ -d /seed/cargo/registry/index ] && [ -d /seed/cargo/git/db ] || die "seed lacks Cargo cache, index, or Git database"
mkdir -p "$CARGO_HOME/registry" "$CARGO_HOME/git"
cp -a /seed/cargo/registry/cache /seed/cargo/registry/index "$CARGO_HOME/registry/"
cp -a /seed/cargo/git/db "$CARGO_HOME/git/"
mkdir -p "$CARGO_HOME/registry/src" "$CARGO_HOME/git/checkouts"
cp /workspace/reproduction/cargo-offline-config.toml "$CARGO_HOME/config.toml"
cmp -s "$CARGO_HOME/config.toml" /workspace/reproduction/cargo-offline-config.toml || die "reproduction Cargo config changed while copying"
[ ! -e "$CARGO_HOME/config" ] || die "legacy Cargo config is not admitted"
private_cargo_config=$(find "$CARGO_HOME" -xdev ! -path "$CARGO_HOME/config.toml" \( -path '*/.cargo/config' -o -path '*/.cargo/config.toml' \) -print -quit) \
    || die "cannot inspect private Cargo-home configuration"
if [ -n "$private_cargo_config" ]; then
    die "nested Cargo configuration in private Cargo home is not admitted"
fi

# Capture the three actual target-specific dependency/feature closures. The
# generator and methods build script execute on the pinned Linux host target;
# the guest executes on the exact RISC Zero target.
mkdir -p /work
b4_diag_mark_complete bootstrap
b4_diag_set_phase cargo-metadata
cargo metadata --manifest-path /workspace/generator/Cargo.toml --locked --offline --format-version 1 --filter-platform "$host_target" > /output/cargo-metadata-generator-host.json
cargo metadata --manifest-path /workspace/methods/Cargo.toml --features embed-methods --locked --offline --format-version 1 --filter-platform "$host_target" > /output/cargo-metadata-methods-build.json
cargo metadata --manifest-path /workspace/methods/guest/Cargo.toml --locked --offline --format-version 1 --filter-platform "$guest_target" > /output/cargo-metadata-guest.json
grep -F 'git+https://github.com/a-shannon/risc0?rev=227229dc793c215c533cbc0e07911601974a4629#227229dc793c215c533cbc0e07911601974a4629' /output/cargo-metadata-generator-host.json >/dev/null || die "Cargo metadata does not resolve the pinned risc0 source"
cargo build --manifest-path /workspace/Cargo.toml --bin eip0045-reproduction --no-default-features --features cli --locked --offline
reproduction_cli=/target/debug/eip0045-reproduction
[ -x "$reproduction_cli" ] || die "reproduction validator binary is absent"
"$reproduction_cli" verify-invariants >/output/reproduction-invariants.txt
materialize_risc0_checkout
reject_special_nodes cargo-materialized-roots "$CARGO_HOME/registry/src" "$CARGO_HOME/git/checkouts"
reject_hard_links cargo-materialized-hard-links "$CARGO_HOME/registry/src" "$CARGO_HOME/git/checkouts"
reject_crlf_paths cargo-registry-paths "$CARGO_HOME/registry/src"
reject_crlf_paths cargo-checkouts-paths "$CARGO_HOME/git/checkouts"

for role in generator-host methods-build guest; do
    case $role in
        generator-host) metadata=/output/cargo-metadata-generator-host.json ;;
        methods-build) metadata=/output/cargo-metadata-methods-build.json ;;
        guest) metadata=/output/cargo-metadata-guest.json ;;
        *) die "internal Cargo closure role mismatch" ;;
    esac
    "$reproduction_cli" cargo-closure \
        --metadata "$metadata" \
        --profile-root /workspace \
        --profile-root-identity eip-0045-profile \
        --role "$role" > "/output/cargo-closure-$role.json"
    "$reproduction_cli" canonical-check "/output/cargo-closure-$role.json" >/dev/null
done
RECURSION_SRC_PATH="$risc0_checkout/risc0/circuit/recursion/src/recursion_zkr.zip"
export RECURSION_SRC_PATH
require_hash "$RECURSION_SRC_PATH" 744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849
env | LC_ALL=C sort > /output/build-environment.txt

b4_diag_mark_complete cargo-metadata
b4_diag_set_phase generator-build
cargo build --manifest-path /workspace/generator/Cargo.toml --release --locked --offline
unset RECURSION_SRC_PATH
generator_bin=/target/release/eip-0045-candidate-generator
[ -f "$generator_bin" ] && [ -s "$generator_bin" ] || die "release candidate generator binary is absent"
generator_magic=$(od -An -tx1 -N4 "$generator_bin" | tr -d '[:space:]') \
    || die "cannot inspect release candidate generator magic"
[ "$generator_magic" = 7f454c46 ] || die "release candidate generator is not an ELF binary"
cp "$generator_bin" /output/candidate-generator
b4_diag_mark_complete generator-build
b4_diag_set_phase proof-generation-tests
cargo test --manifest-path /workspace/generator/Cargo.toml --release --lib \
    --no-default-features --features proof-generation --locked --offline --quiet
RECURSION_SRC_PATH="$risc0_checkout/risc0/circuit/recursion/src/recursion_zkr.zip"
export RECURSION_SRC_PATH
embedded_test_listing=$(
    cargo test --manifest-path /workspace/generator/Cargo.toml --release --lib \
        --no-default-features --features embedded-method --locked --offline --quiet \
        "$embedded_exact_test" \
        -- --ignored --exact --list --format terse
) || die "cannot enumerate the exact embedded-method proof test"
[ "$embedded_test_listing" = "$embedded_exact_test: test" ] \
    || die "embedded-method proof selection is not exactly one named test: $embedded_test_listing"
cargo test --manifest-path /workspace/generator/Cargo.toml --release --lib \
    --no-default-features --features embedded-method --locked --offline --quiet \
    "$embedded_exact_test" \
    -- --ignored --exact
unset RECURSION_SRC_PATH
{
    printf 'schema=eip0045-proof-generation-tests-v2\n'
    printf 'status=passed\n'
    printf 'profile=release\n'
    printf 'defaultFeatures=disabled\n'
    printf 'features=proof-generation\n'
    printf 'embeddedMethodFeatures=embedded-method\n'
    printf 'embeddedMethodExactTest=%s\n' "$embedded_exact_test"
    printf 'network=offline\n'
} > /output/proof-generation-tests.txt

b4_diag_mark_complete proof-generation-tests
b4_diag_set_phase post-test-tree-preflight
reject_special_nodes post-test-workspace-checkout /workspace "$risc0_checkout"
reject_hard_links post-test-workspace-hard-links /workspace "$risc0_checkout"
reject_crlf_paths post-test-workspace-paths /workspace
reject_crlf_paths post-test-checkout-paths "$risc0_checkout"
write_workspace_manifest /output/workspace-source-manifest-after.txt
cmp -s /output/workspace-source-manifest-before.txt /output/workspace-source-manifest-after.txt || die "workspace source changed during build"
cp /output/workspace-source-manifest-before.txt /output/workspace-source-manifest.txt
write_materialized_source_manifest "$risc0_checkout" /output/source-materialized-manifest-after.txt
cmp -s /output/source-materialized-manifest-before.txt /output/source-materialized-manifest-after.txt || die "materialized RISC Zero source changed during build"
cp /output/source-materialized-manifest-before.txt /output/source-materialized-manifest.txt
write_checkout_admin_manifest "$risc0_checkout" /output/source-checkout-admin-manifest-after.txt
cmp -s /output/source-checkout-admin-manifest-before.txt /output/source-checkout-admin-manifest-after.txt || die "Cargo checkout administration changed during build"
cp /output/source-checkout-admin-manifest-before.txt /output/source-checkout-admin-manifest.txt
b4_diag_mark_complete post-test-tree-preflight
b4_diag_set_phase source-lock
git_admin_quarantine="$CARGO_HOME/git/eip0045-admin-quarantine"
[ ! -e "$git_admin_quarantine" ] || die "Git administrative quarantine already exists"
mv "$risc0_checkout/.git" "$git_admin_quarantine"
[ ! -e "$risc0_checkout/.git" ] || die "Git administrative metadata remains inside compiled source"
reject_special_nodes checkout-after-admin-quarantine "$risc0_checkout"
reject_hard_links checkout-after-admin-hard-links "$risc0_checkout"
"$reproduction_cli" source-lock --source-root "$risc0_checkout" > /output/candidate-source-lock-first.json
"$reproduction_cli" canonical-check /output/candidate-source-lock-first.json >/dev/null
"$reproduction_cli" source-lock --source-root "$risc0_checkout" > /output/candidate-source-lock-second.json
"$reproduction_cli" canonical-check /output/candidate-source-lock-second.json >/dev/null
cmp -s /output/candidate-source-lock-first.json /output/candidate-source-lock-second.json || die "candidate source lock snapshots disagree"
cp /output/candidate-source-lock-first.json /output/candidate-source-lock.json

b4_diag_mark_complete source-lock
b4_diag_set_phase identity-extraction
methods_rs=$(find /target/release/build -xdev -type f -name methods.rs -print | LC_ALL=C sort) \
    || die "cannot enumerate release-generated methods.rs"
methods_rs_count=$(printf '%s\n' "$methods_rs" | sed '/^$/d' | wc -l | tr -d '[:space:]') \
    || die "cannot count release-generated methods.rs files"
[ "$methods_rs_count" = 1 ] || die "cannot uniquely locate release-generated methods.rs"
guest_bin=$(extract_generated_guest_path EIP_0045_GUEST "$methods_rs")
alternate_program_guest_bin=$(
    extract_generated_guest_path EIP_0045_ALTERNATE_PROGRAM_GUEST "$methods_rs"
)
cp "$guest_bin" /output/guest.elf
cp "$alternate_program_guest_bin" /output/alternate-program-guest.elf
"$generator_bin" artifact-identity --elf-file /output/guest.elf --output-file /output/image-id.bin
"$generator_bin" artifact-identity \
    --elf-file /output/alternate-program-guest.elf \
    --output-file /output/alternate-program-image-id.bin
require_size /output/image-id.bin 32
require_size /output/alternate-program-image-id.bin 32
image_id_hex=$(od -An -v -tx1 /output/image-id.bin | tr -d '[:space:]') \
    || die "cannot encode canonical image ID as hexadecimal"
alternate_program_image_id_hex=$(
    od -An -v -tx1 /output/alternate-program-image-id.bin | tr -d '[:space:]'
) || die "cannot encode alternate-program image ID as hexadecimal"
[ "${#image_id_hex}" = 64 ] || die "canonical image ID hex length mismatch"
[ "${#alternate_program_image_id_hex}" = 64 ] \
    || die "alternate-program image ID hex length mismatch"
case $image_id_hex in *[!0-9a-f]*) die "canonical image ID contains non-lowercase-hex data" ;; esac
case $alternate_program_image_id_hex in
    *[!0-9a-f]*) die "alternate-program image ID contains non-lowercase-hex data" ;;
esac
[ "$image_id_hex" != "$alternate_program_image_id_hex" ] \
    || die "alternate-program image ID equals the consumer image ID"
printf '%s\n' "$image_id_hex" > /output/image-id.hex
printf '%s\n' "$alternate_program_image_id_hex" > /output/alternate-program-image-id.hex

b4_diag_mark_complete identity-extraction
b4_diag_set_phase statement-derivation
statement_input_root=/work/statement-input
[ ! -e "$statement_input_root" ] || die "statement input work root already exists"
mkdir "$statement_input_root"
chain_domain_hex=b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b
payload_hex=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
write_hex_file "$chain_domain_hex" "$statement_input_root/chain-domain-id.bin"
write_hex_file "$payload_hex" "$statement_input_root/application-payload.bin"
require_size "$statement_input_root/chain-domain-id.bin" 32
require_hash "$statement_input_root/chain-domain-id.bin" efc4e16652e5e4da23b8c2f3ce2de61fae9d118b0cf47dd9fde8b3c8d6d9ffce
require_size "$statement_input_root/application-payload.bin" 32
require_hash "$statement_input_root/application-payload.bin" 630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd
require_size /workspace/profiles/risc0-v3-succinct/profile-id.bin 32
require_hash /workspace/profiles/risc0-v3-succinct/profile-id.bin aa144c74a0cb52b3c5a9827f10a264f320820190da14a9bf82dcf3466f41aae1
mkdir /output/statement
"$generator_bin" candidate-statement \
    --profile-dir /workspace/profiles/risc0-v3-succinct \
    --chain-domain-id-file "$statement_input_root/chain-domain-id.bin" \
    --application-payload-file "$statement_input_root/application-payload.bin" \
    --output-root /output/statement > "$statement_input_root/candidate-statement-transcript.txt"
cp "$statement_input_root/chain-domain-id.bin" /output/statement/chain-domain-id.bin
cp "$statement_input_root/application-payload.bin" /output/statement/application-payload.bin
cp /workspace/profiles/risc0-v3-succinct/profile-id.bin /output/statement/profile-id.bin
cp "$statement_input_root/candidate-statement-transcript.txt" /output/statement/candidate-statement-transcript.txt
profile_id_hex=$(od -An -v -tx1 /output/statement/profile-id.bin | tr -d '[:space:]') \
    || die "cannot encode profile ID"
[ "$profile_id_hex" = 23c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383 ] \
    || die "profile ID bytes differ from the fixed B3 profile"
{
    printf 'schema=eip0045-b4-statement-inputs-v1\n'
    printf 'chainDomainIdHex=%s\n' "$chain_domain_hex"
    write_hash_record chainDomainIdSha256 "$statement_input_root/chain-domain-id.bin"
    printf 'applicationPayloadHex=%s\n' "$payload_hex"
    write_hash_record applicationPayloadSha256 "$statement_input_root/application-payload.bin"
    printf 'profileIdHex=%s\n' "$profile_id_hex"
    write_hash_record profileIdSha256 /workspace/profiles/risc0-v3-succinct/profile-id.bin
    write_hash_record profileManifestSha256 /workspace/profiles/risc0-v3-succinct/manifest.json
    write_hash_record generatorBinarySha256 "$generator_bin"
    write_hash_record guestElfSha256 /output/guest.elf
    printf 'imageIdHex=%s\n' "$image_id_hex"
    write_hash_record candidateStatementTranscriptSha256 "$statement_input_root/candidate-statement-transcript.txt"
    printf 'proofGenerated=false\n'
} > /output/statement/inputs.txt

b4_diag_mark_complete statement-derivation
b4_diag_set_phase identity-record
extract_generated_image_id_declaration \
    EIP_0045_GUEST \
    "$methods_rs" \
    /output/image-id-declaration.txt
extract_generated_image_id_declaration \
    EIP_0045_ALTERNATE_PROGRAM_GUEST \
    "$methods_rs" \
    /output/alternate-program-image-id-declaration.txt
require_generated_image_id_matches \
    EIP_0045_GUEST \
    /output/image-id.bin \
    /output/image-id-declaration.txt
require_generated_image_id_matches \
    EIP_0045_ALTERNATE_PROGRAM_GUEST \
    /output/alternate-program-image-id.bin \
    /output/alternate-program-image-id-declaration.txt

guest_sha=$(sha256 /output/guest.elf) || die "cannot hash guest.elf"
image_id_sha=$(sha256 /output/image-id.bin) || die "cannot hash image-id.bin"
image_id_declaration_sha=$(sha256 /output/image-id-declaration.txt) \
    || die "cannot hash image-id-declaration.txt"
alternate_program_guest_sha=$(sha256 /output/alternate-program-guest.elf) \
    || die "cannot hash alternate-program-guest.elf"
alternate_program_image_id_sha=$(sha256 /output/alternate-program-image-id.bin) \
    || die "cannot hash alternate-program-image-id.bin"
alternate_program_image_id_declaration_sha=$(
    sha256 /output/alternate-program-image-id-declaration.txt
) || die "cannot hash alternate-program-image-id-declaration.txt"
{
    printf 'guestElfSha256=%s\n' "$guest_sha"
    write_size_record guestElfByteLength /output/guest.elf
    printf 'imageIdCanonicalHex=%s\n' "$image_id_hex"
    printf 'imageIdCanonicalSha256=%s\n' "$image_id_sha"
    printf 'imageIdDeclarationSha256=%s\n' "$image_id_declaration_sha"
    printf 'alternateProgramGuestElfSha256=%s\n' "$alternate_program_guest_sha"
    write_size_record alternateProgramGuestElfByteLength /output/alternate-program-guest.elf
    printf 'alternateProgramImageIdCanonicalHex=%s\n' "$alternate_program_image_id_hex"
    printf 'alternateProgramImageIdCanonicalSha256=%s\n' "$alternate_program_image_id_sha"
    printf 'alternateProgramImageIdDeclarationSha256=%s\n' \
        "$alternate_program_image_id_declaration_sha"
    printf 'hostRust=1.89.0\n'
    printf 'hostTarget=%s\n' "$host_target"
    printf 'guestBuildCargoObserved=1.89.0\n'
    printf 'guestRustObserved=1.88.0\n'
    printf 'bundledGuestCargoObserved=1.88.0\n'
    printf 'guestTarget=%s\n' "$guest_target"
    printf 'generatorProfile=release\n'
    write_hash_record generatorBinarySha256 /output/candidate-generator
    write_size_record generatorBinaryByteLength /output/candidate-generator
    write_hash_record buildPolicySha256 /output/build-policy.txt
    write_hash_record proofGenerationTestsSha256 /output/proof-generation-tests.txt
    write_hash_record resourcePolicyObservationSha256 /output/resource-policy-observed.txt
    write_hash_record hostToolchainObservationSha256 /output/host-toolchain-observed.txt
    write_hash_record guestToolchainObservationSha256 /output/guest-toolchain-observed.txt
    printf 'sourceCommit=%s\n' "$expected_commit"
    printf 'declaredSourceTree=%s\n' "$declared_source_tree"
    write_hash_record sourceGitObservationSha256 /output/source-git-observed.txt
    printf 'recursionSourceRelativePath=%s\n' 'risc0/circuit/recursion/src/recursion_zkr.zip'
    write_hash_record sourceManifestSha256 /output/source-materialized-manifest.txt
    write_hash_record sourceCheckoutAdminManifestSha256 /output/source-checkout-admin-manifest.txt
    write_hash_record candidateSourceLockSha256 /output/candidate-source-lock.json
    write_hash_record cargoMetadataGeneratorHostSha256 /output/cargo-metadata-generator-host.json
    write_hash_record cargoMetadataMethodsBuildSha256 /output/cargo-metadata-methods-build.json
    write_hash_record cargoMetadataGuestSha256 /output/cargo-metadata-guest.json
    write_hash_record cargoClosureGeneratorHostSha256 /output/cargo-closure-generator-host.json
    write_hash_record cargoClosureMethodsBuildSha256 /output/cargo-closure-methods-build.json
    write_hash_record cargoClosureGuestSha256 /output/cargo-closure-guest.json
    write_hash_record buildEnvironmentSha256 /output/build-environment.txt
    write_hash_record cargoConfigSha256 "$CARGO_HOME/config.toml"
    write_hash_record dockerfileSha256 /workspace/Dockerfile.reproduction
    write_hash_record candidateStatementInputsSha256 /output/statement/inputs.txt
    write_hash_record candidateStatementSha256 /output/statement/candidate-statement.bin
} > /output/identity.txt

b4_diag_mark_complete identity-record
b4_diag_set_phase complete
b4_diag_mark_complete complete
printf 'B4 build %s: fresh consumer and alternate-program guest identities written\n' "$label"
