#!/usr/bin/env bash
# Hermetic B4 guest-build runner for a locally hydrated Docker engine.
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
runtime_image=${B4_BUILD_RUNTIME_IMAGE:?set B4_BUILD_RUNTIME_IMAGE to the pre-hydrated reproduction runtime image}
runtime_manifest='sha256:1aa2ca80b59886af9ab34cf9775a567a80aacb03c0c29176c9120e1f34fcd855'
seed_root=${B4_BUILD_SEED_ROOT:?set B4_BUILD_SEED_ROOT to a directory containing cargo/ and lfs/}
second_seed_root=${B4_BUILD_SECOND_SEED_ROOT:?set B4_BUILD_SECOND_SEED_ROOT to a path-disjoint directory containing cargo/ and lfs/}
second_repo_root=${B4_BUILD_SECOND_REPO_ROOT:?set B4_BUILD_SECOND_REPO_ROOT to a path-disjoint clean checkout}
output_root=${B4_BUILD_OUTPUT_ROOT:?set B4_BUILD_OUTPUT_ROOT to an absent final evidence directory}

die() { printf '%s\n' "B4 build: $*" >&2; exit 1; }
diagnostics_helper="$repo_root/reproduction/b4-build/diagnostics.sh"
[ -f "$diagnostics_helper" ] || die "diagnostics helper is absent: $diagnostics_helper"
# shellcheck source=b4-build/diagnostics.sh
source "$diagnostics_helper"

sha256_file() {
    local output digest
    output=$(sha256sum -- "$1") || return 1
    digest=${output%% *}
    [ "${#digest}" = 64 ] || return 1
    case $digest in *[!0-9a-f]*) return 1 ;; esac
    printf '%s\n' "$digest"
}
file_size() { stat -c '%s' -- "$1"; }
docker_inspect_field() { docker image inspect "$1" --format "$2"; }
require_dir() { [ -d "$1" ] || die "missing directory: $1"; }
reject_mount_unsafe_value() {
    local newline carriage
    newline='
'
    carriage=$(printf '\r')
    case $1 in
        *"$newline"*|*"$carriage"*) die "$2 contains CR or LF" ;;
        *,*) die "$2 contains a comma, which is unsafe in Docker --mount syntax" ;;
    esac
}
canonical_dir() {
    local resolved
    reject_mount_unsafe_value "$1" "$2"
    [ ! -L "$1" ] || die "$2 must not be a symlink: $1"
    require_dir "$1"
    resolved=$(CDPATH= cd -- "$1" && pwd -P) || die "cannot canonicalize $2: $1"
    reject_mount_unsafe_value "$resolved" "$2 canonical path"
    printf '%s\n' "$resolved"
}
canonical_seed_subroot() {
    local parent=$1 name=$2 label=$3 child
    child=$(canonical_dir "$parent/$name" "$label")
    case $child in
        "$parent"/*) ;;
        *) die "$label escaped its canonical seed root: $child" ;;
    esac
    mountpoint -q "$child" && die "$label must not itself be a nested mountpoint: $child"
    printf '%s\n' "$child"
}
paths_overlap() {
    [ "$1" = "$2" ] && return 0
    case $1 in "$2"/*) return 0 ;; esac
    case $2 in "$1"/*) return 0 ;; esac
    return 1
}
assert_disjoint() {
    if paths_overlap "$1" "$3"; then
        die "$2 and $4 must be path-disjoint: $1 ; $3"
    fi
}
reject_tree_special_or_crlf() {
    local root=$1 label=$2 offender
    offender=$(find "$root" -xdev \( -type l -o -type b -o -type c -o -type p -o -type s \) -print -quit) || return 1
    if [ -n "$offender" ]; then
        printf '%s\n' "B4 build: $label contains a symlink or special node: $offender" >&2
        return 1
    fi
    if ! find "$root" -xdev -exec sh -c '
        newline="
"
        carriage=$(printf "\r")
        for path do
            case $path in *"$newline"*|*"$carriage"*) exit 91 ;; esac
        done
    ' sh {} +; then
        printf '%s\n' "B4 build: $label contains a path with CR or LF" >&2
        return 1
    fi
}
reject_descendant_mountpoints() {
    local root=$1 label=$2 offender
    offender=$(find "$root" -xdev -mindepth 1 -exec sh -c '
        for path do
            if mountpoint -q "$path"; then printf "%s\n" "$path"; fi
        done
    ' sh {} +) || {
        printf '%s\n' "B4 build: cannot inspect mount boundaries below $root" >&2
        return 1
    }
    if [ -n "$offender" ]; then
        printf '%s\n' "B4 build: $label contains a nested mountpoint: $offender" >&2
        return 1
    fi
}
preflight_input_tree() {
    local root=$1 label=$2 scan_label=$3 scan_status line_number
    b4_diag_validate_token "$scan_label" || die "invalid host preflight scan label: $scan_label"
    line_number=$LINENO
    if b4_diag_reject_special_nodes "$scan_label-special-nodes" "$line_number" "$root"; then
        :
    else
        scan_status=$?
        die "$label $B4_DIAG_SCAN_KIND with status $scan_status; diagnostics retained at $B4_DIAG_ROOT"
    fi

    if b4_diag_reject_hard_links "$scan_label-hard-links" "$line_number" "$root"; then
        :
    else
        scan_status=$?
        die "$label $B4_DIAG_SCAN_KIND with status $scan_status; diagnostics retained at $B4_DIAG_ROOT"
    fi

    if b4_diag_reject_crlf_paths "$scan_label-paths" "$root" "$line_number"; then
        :
    else
        scan_status=$?
        if [ "$scan_status" = 91 ]; then
            die "$label contains a path with CR or LF; diagnostics retained at $B4_DIAG_ROOT"
        fi
        die "$label path enumeration failed with status $scan_status; diagnostics retained at $B4_DIAG_ROOT"
    fi
    reject_descendant_mountpoints "$1" "$2" || die "$2 failed mount-boundary validation"
}
git_evidence() {
    local run_repo=$1 evidence_path=$2 git_inside git_head git_tree git_status
    b4_git_assert_standalone_checkout "$run_repo" ||
        die "B4 requires a standalone clean Git checkout with a private object store: $run_repo"
    git_inside=$(git -C "$run_repo" rev-parse --is-inside-work-tree) || die "cannot validate workspace Git metadata: $run_repo"
    [ "$git_inside" = true ] || die "workspace Git metadata is not a work tree: $run_repo"
    git_head=$(git -C "$run_repo" rev-parse HEAD) || die "cannot read workspace Git HEAD: $run_repo"
    git_tree=$(git -C "$run_repo" rev-parse HEAD^{tree}) || die "cannot read workspace Git tree: $run_repo"
    git_status=$(git -C "$run_repo" status --porcelain=v1 --untracked-files=all) || die "cannot read workspace Git status: $run_repo"
    [ -z "$git_status" ] || die "B4 requires a clean workspace Git tree: $run_repo"
    {
        printf 'head=%s\n' "$git_head"
        printf 'tree=%s\n' "$git_tree"
        printf 'storage=standalone-private-object-store\n'
        printf 'statusBegin\nstatusEnd\n'
    } > "$evidence_path"
}
git_identity() {
    local run_repo=$1 git_head git_tree git_status
    b4_git_assert_standalone_checkout "$run_repo" ||
        die "B4 requires a standalone clean Git checkout with a private object store: $run_repo"
    git_head=$(git -C "$run_repo" rev-parse HEAD) || die "cannot read workspace Git HEAD: $run_repo"
    git_tree=$(git -C "$run_repo" rev-parse HEAD^{tree}) || die "cannot read workspace Git tree: $run_repo"
    git_status=$(git -C "$run_repo" status --porcelain=v1 --untracked-files=all) || die "cannot read workspace Git status: $run_repo"
    [ -z "$git_status" ] || die "B4 requires a clean workspace Git tree: $run_repo"
    printf '%s %s\n' "$git_head" "$git_tree"
}
write_tree_manifest() {
    local evidence_root=$1 manifest_path=$2 path relative digest size
    (
        cd "$evidence_root"
        find . -xdev -type f -print0 | LC_ALL=C sort -z | while IFS= read -r -d '' path; do
            relative=${path#./}
            case $relative in *$'\r'*|*$'\n'*) die 'generated evidence contains a path with CR or LF' ;; esac
            digest=$(sha256_file "$path") || die "cannot hash evidence file: $relative"
            size=$(file_size "$path") || die "cannot stat evidence file: $relative"
            printf 'file path=%s sha256=%s size=%s\n' "$relative" "$digest" "$size"
        done
    ) > "$manifest_path"
}
safe_remove_transient_root() {
    local path=$1 parent=$2 output_name=$3 kind=$4 actual_parent base
    actual_parent=$(CDPATH= cd -- "$(dirname -- "$path")" && pwd -P) || return 1
    base=$(basename -- "$path") || return 1
    [ "$actual_parent" = "$parent" ] || return 1
    case $base in ".${output_name}.b4-${kind}."*) ;; *) return 1 ;; esac
    [ ! -L "$path" ] || return 1
    reject_tree_special_or_crlf "$path" "$kind transient root" || return 1
    reject_descendant_mountpoints "$path" "$kind transient root" || return 1
    rm -rf --one-file-system -- "$path"
}
run_qualifying_container() {
    local container_name=$1 diagnostic_root=$2 run_status inspect_status log_status
    shift 2
    [ ! -e "$diagnostic_root" ] && [ ! -L "$diagnostic_root" ] || die "host diagnostic root already exists: $diagnostic_root"
    mkdir -- "$diagnostic_root"
    if docker container inspect "$container_name" >/dev/null 2>&1; then
        die "qualifying container name is already occupied: $container_name"
    fi

    b4_host_container_guard_before_run "$container_name" "$diagnostic_root" ||
        die "cannot arm qualifying-container bind-source preservation"
    set +e
    docker run --name "$container_name" "$@"
    run_status=$?
    set -e
    {
        printf 'schema=eip0045-b4-host-container-run-v1\n'
        printf 'containerName=%s\n' "$container_name"
        printf 'exitStatus=%s\n' "$run_status"
    } > "$diagnostic_root/run-status.txt"

    if docker container inspect "$container_name" > "$diagnostic_root/.container-inspect.stdout" 2> "$diagnostic_root/.container-inspect.stderr"; then
        inspect_status=0
        b4_host_container_guard_mark_inspected "$container_name" ||
            die "cannot record the inspected qualifying container"
        mv -- "$diagnostic_root/.container-inspect.stdout" "$diagnostic_root/container-inspect.json"
        rm -f -- "$diagnostic_root/.container-inspect.stderr"
    else
        inspect_status=$?
        b4_host_container_guard_record_uncertainty post-run-inspection-failed || true
        {
            cat -- "$diagnostic_root/.container-inspect.stderr"
            cat -- "$diagnostic_root/.container-inspect.stdout"
        } > "$diagnostic_root/container-inspect-error.txt"
        rm -f -- "$diagnostic_root/.container-inspect.stderr" "$diagnostic_root/.container-inspect.stdout"
    fi
    if docker logs --timestamps "$container_name" > "$diagnostic_root/container-logs.txt" 2>&1; then
        log_status=0
    else
        log_status=$?
        mv -- "$diagnostic_root/container-logs.txt" "$diagnostic_root/container-logs-error.txt"
    fi

    if [ "$run_status" -ne 0 ]; then
        if [ "$inspect_status" = 0 ]; then
            retained_qualifying_container=1
            retained_qualifying_container_name=$container_name
            die "qualifying container $container_name failed with status $run_status and was retained for diagnosis"
        fi
        die "docker run failed with status $run_status and container presence could not be confirmed; original bind sources were preserved"
    fi
    if [ "$inspect_status" -ne 0 ] || [ "$log_status" -ne 0 ]; then
        if [ "$inspect_status" = 0 ]; then
            retained_qualifying_container=1
            retained_qualifying_container_name=$container_name
        fi
        die "successful qualifying container $container_name could not be fully diagnosed; original bind sources were preserved"
    fi
    if ! docker rm -- "$container_name" >/dev/null; then
        retained_qualifying_container=1
        retained_qualifying_container_name=$container_name
        b4_host_container_guard_record_uncertainty removal-not-confirmed || true
        die "successful qualifying container could not be removed: $container_name"
    fi
    b4_host_container_guard_mark_removed "$container_name" ||
        die "qualifying container was removed but its guard state could not be completed"
}

command -v mountpoint >/dev/null 2>&1 || die 'the mountpoint utility is required for fail-closed input-tree preflight'
command -v mv >/dev/null 2>&1 || die 'mv is required for atomic evidence publication'
mv --help 2>&1 | grep -F -- '--no-clobber' >/dev/null || die 'GNU mv --no-clobber is required for create-only evidence publication'
mv --help 2>&1 | grep -F -- '--no-target-directory' >/dev/null || die 'GNU mv --no-target-directory is required for atomic evidence publication'
reject_mount_unsafe_value "$runtime_image" 'runtime image reference'

repo_root=$(canonical_dir "$repo_root" 'primary repository')
second_repo_root=$(canonical_dir "$second_repo_root" 'secondary repository')
seed_root=$(canonical_dir "$seed_root" 'primary seed')
second_seed_root=$(canonical_dir "$second_seed_root" 'secondary seed')
seed_cargo_root=$(canonical_seed_subroot "$seed_root" cargo 'primary Cargo seed')
seed_lfs_root=$(canonical_seed_subroot "$seed_root" lfs 'primary LFS seed')
second_seed_cargo_root=$(canonical_seed_subroot "$second_seed_root" cargo 'secondary Cargo seed')
second_seed_lfs_root=$(canonical_seed_subroot "$second_seed_root" lfs 'secondary LFS seed')
require_dir "$repo_root/profiles/risc0-v3-succinct"
require_dir "$second_repo_root/reproduction"
require_dir "$second_repo_root/methods"
require_dir "$second_repo_root/generator"
require_dir "$second_repo_root/profiles/risc0-v3-succinct"
assert_disjoint "$seed_cargo_root" 'primary Cargo seed' "$seed_lfs_root" 'primary LFS seed'
assert_disjoint "$second_seed_cargo_root" 'secondary Cargo seed' "$second_seed_lfs_root" 'secondary LFS seed'
assert_disjoint "$repo_root" 'primary repository' "$second_repo_root" 'secondary repository'
assert_disjoint "$repo_root" 'primary repository' "$seed_root" 'primary seed'
assert_disjoint "$repo_root" 'primary repository' "$second_seed_root" 'secondary seed'
assert_disjoint "$second_repo_root" 'secondary repository' "$seed_root" 'primary seed'
assert_disjoint "$second_repo_root" 'secondary repository' "$second_seed_root" 'secondary seed'
assert_disjoint "$seed_root" 'primary seed' "$second_seed_root" 'secondary seed'

reject_mount_unsafe_value "$output_root" 'output path'
output_parent=$(canonical_dir "$(dirname -- "$output_root")" 'output parent')
output_name=$(basename -- "$output_root") || die 'cannot determine output directory name'
case $output_name in ''|.|..) die 'output path must name a new directory below an existing parent' ;; esac
output_root="$output_parent/$output_name"
reject_mount_unsafe_value "$output_root" 'output path'
[ ! -e "$output_root" ] && [ ! -L "$output_root" ] || die 'final output directory must not already exist'
assert_disjoint "$output_root" 'final output path' "$repo_root" 'primary repository'
assert_disjoint "$output_root" 'final output path' "$second_repo_root" 'secondary repository'
assert_disjoint "$output_root" 'final output path' "$seed_root" 'primary seed'
assert_disjoint "$output_root" 'final output path' "$second_seed_root" 'secondary seed'

host_preflight_diagnostics=$(mktemp -d "$output_parent/.${output_name}.b4-preflight.XXXXXXXX") \
    || die 'cannot create host preflight diagnostics root'
b4_diag_init "$host_preflight_diagnostics/diagnostics" host-preflight \
    || die "cannot initialize host preflight diagnostics at $host_preflight_diagnostics"
b4_diag_set_phase input-tree-preflight \
    || die "cannot initialize host preflight phase at $host_preflight_diagnostics"
preflight_input_tree "$repo_root" 'primary repository' primary-repository
preflight_input_tree "$second_repo_root" 'secondary repository' secondary-repository
preflight_input_tree "$seed_cargo_root" 'primary Cargo seed' primary-cargo-seed
preflight_input_tree "$seed_lfs_root" 'primary LFS seed' primary-lfs-seed
preflight_input_tree "$second_seed_cargo_root" 'secondary Cargo seed' secondary-cargo-seed
preflight_input_tree "$second_seed_lfs_root" 'secondary LFS seed' secondary-lfs-seed
b4_diag_mark_complete input-tree-preflight \
    || die "cannot complete host preflight diagnostics at $host_preflight_diagnostics"
safe_remove_transient_root "$host_preflight_diagnostics" "$output_parent" "$output_name" preflight \
    || die "validated host preflight diagnostics cleanup failed: $host_preflight_diagnostics"
unset B4_DIAG_ROOT B4_DIAG_RUN_LABEL B4_DIAG_PHASE B4_DIAG_LAST_COMPLETE
primary_git_identity=$(git_identity "$repo_root")
secondary_git_identity=$(git_identity "$second_repo_root")
[ "$primary_git_identity" = "$secondary_git_identity" ] || die 'the clean checkouts do not identify the same Git commit and tree'

guest_ref='risczero/risc0-guest-builder@sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3'
host_ref='rust@sha256:294917190b5a3fed18d3303213943f40ec9b644b3cd6e5cdc8cd029334a770b3'
for ref in "$guest_ref" "$host_ref"; do
    docker image inspect "$ref" >/dev/null 2>&1 || die "exact image is not locally hydrated: $ref"
    docker image inspect "$ref" --format '{{.Os}}/{{.Architecture}} {{json .RepoDigests}}' | grep -F 'linux/amd64' | grep -F "${ref#*@}" >/dev/null || die "local image identity/platform mismatch: $ref"
done
docker image inspect "$runtime_image" >/dev/null 2>&1 || die "pre-hydrated reproduction runtime image is unavailable: $runtime_image"
docker image inspect "$runtime_image" --format '{{.Os}}/{{.Architecture}} {{json .Descriptor}}' | grep -F 'linux/amd64' | grep -F "$runtime_manifest" | grep -F 'sha256:e89c6b7bdb6d5dbf7456f550fd17e8983edba597881a9a8e806b1bc589ac3074' >/dev/null || die 'runtime manifest/config/platform mismatch'
docker image inspect "$runtime_image" --format '{{.Created}}' | grep -Fx '2026-02-03T00:19:36Z' >/dev/null || die 'runtime image Created timestamp mismatch'
runtime_execution_ref=$runtime_manifest
assert_runtime_image() {
    docker image inspect "$runtime_execution_ref" >/dev/null 2>&1 || die 'immutable runtime image is no longer locally available'
    docker image inspect "$runtime_execution_ref" --format '{{.Os}}/{{.Architecture}} {{json .Descriptor}}' | grep -F 'linux/amd64' | grep -F "$runtime_manifest" | grep -F 'sha256:e89c6b7bdb6d5dbf7456f550fd17e8983edba597881a9a8e806b1bc589ac3074' >/dev/null || die 'immutable runtime descriptor changed'
    docker image inspect "$runtime_execution_ref" --format '{{.Created}}' | grep -Fx '2026-02-03T00:19:36Z' >/dev/null || die 'immutable runtime Created timestamp changed'
}
assert_runtime_image

lock_root="$output_parent/.${output_name}.b4.lock"
lock_owned=0
lock_token=''
staging_root=''
work_root=''
published=0
publication_occurred=0
retained_qualifying_container=0
retained_qualifying_container_name=''
b4_host_container_guard_init || die 'host container guard state is already present'
cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [ "$published" = 1 ]; then
        if [ -n "$work_root" ] && [ -e "$work_root" ]; then
            safe_remove_transient_root "$work_root" "$output_parent" "$output_name" work || printf '%s\n' "B4 build: warning: validated work cleanup failed: $work_root" >&2
        fi
    else
        diagnostics_path=''
        if b4_host_container_guard_should_preserve; then
            b4_host_container_guard_record_uncertainty runner-exited-before-removal-confirmed || true
        fi
        if [ -n "$staging_root" ] && [ -d "$staging_root" ] && [ -n "$work_root" ] && [ -d "$work_root" ]; then
            if b4_host_container_guard_should_preserve; then
                diagnostics_path=$staging_root
            elif [ ! -e "$work_root/diagnostics-partial-evidence" ]; then
                diagnostics_path="$work_root/diagnostics-partial-evidence"
                if ! mv -T -- "$staging_root" "$diagnostics_path"; then
                    diagnostics_path=''
                    safe_remove_transient_root "$staging_root" "$output_parent" "$output_name" staging || printf '%s\n' "B4 build: warning: validated staging cleanup failed: $staging_root" >&2
                fi
            fi
        fi
        if [ "$publication_occurred" = 1 ] && [ -d "$output_root" ]; then
            printf '%s\n' "B4 build: published evidence remains at $output_root but post-publication verification failed; treat it as unverified" >&2
        fi
        if [ -n "$work_root" ] && [ -d "$work_root" ]; then
            printf '%s\n' "B4 build: failed; non-evidence diagnostics retained at $work_root" >&2
        fi
        if [ "$retained_qualifying_container" = 1 ]; then
            printf '%s\n' "B4 build: retained qualifying container $retained_qualifying_container_name; its original bind sources were not moved" >&2
        elif b4_host_container_guard_should_preserve; then
            printf '%s\n' "B4 build: qualifying container presence is uncertain; original bind sources were not moved" >&2
        fi
        if [ -n "$diagnostics_path" ] && [ -d "$diagnostics_path" ]; then
            printf '%s\n' "B4 build: partial evidence retained at $diagnostics_path" >&2
        fi
    fi
    if [ "$lock_owned" = 1 ]; then
        observed_lock_token=$(cat "$lock_root/owner-token" 2>/dev/null || true)
        if [ -n "$lock_token" ] && [ "$observed_lock_token" = "$lock_token" ]; then
            rm -- "$lock_root/owner-token" 2>/dev/null || true
            rmdir -- "$lock_root" 2>/dev/null || printf '%s\n' "B4 build: warning: publication lock cleanup failed: $lock_root" >&2
        else
            printf '%s\n' "B4 build: warning: publication lock token changed; refusing cleanup: $lock_root" >&2
        fi
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -- "$lock_root" 2>/dev/null || die "output publication is already active or has an unresolved lock: $lock_root"
lock_owned=1
lock_token=$(printf '%s:%s:%s:%s\n' "$$" "$BASHPID" "$RANDOM" "$(date +%s%N)" | sha256sum)
lock_token=${lock_token%% *}
case $lock_token in ''|*[!0-9a-f]*) die 'cannot create publication lock owner token' ;; esac
(umask 077 && printf '%s\n' "$lock_token" > "$lock_root/owner-token")
[ ! -e "$output_root" ] && [ ! -L "$output_root" ] || die 'final output directory appeared after publication lock acquisition'
work_root=$(mktemp -d "$output_parent/.${output_name}.b4-work.XXXXXXXX") || die 'cannot create unique work root'
staging_root=$(mktemp -d "$output_parent/.${output_name}.b4-staging.XXXXXXXX") || die 'cannot create unique evidence staging root'
reject_mount_unsafe_value "$work_root" 'work root'
reject_mount_unsafe_value "$staging_root" 'evidence staging root'

{
    for item in "guestBuilder|$guest_ref" "hostRust|$host_ref"; do
        label=${item%%|*}
        ref=${item#*|}
        image_platform=$(docker_inspect_field "$ref" '{{.Os}}/{{.Architecture}}') || die "cannot inspect base-image platform: $ref"
        image_id=$(docker_inspect_field "$ref" '{{.Id}}') || die "cannot inspect base-image ID: $ref"
        image_created=$(docker_inspect_field "$ref" '{{.Created}}') || die "cannot inspect base-image Created value: $ref"
        image_descriptor=$(docker_inspect_field "$ref" '{{json .Descriptor}}') || die "cannot inspect base-image descriptor: $ref"
        image_config=$(docker_inspect_field "$ref" '{{json .Config}}') || die "cannot inspect base-image config: $ref"
        image_rootfs=$(docker_inspect_field "$ref" '{{json .RootFS}}') || die "cannot inspect base-image rootfs: $ref"
        printf '%s.reference=%s\n' "$label" "$ref"
        printf '%s.platform=%s\n' "$label" "$image_platform"
        printf '%s.id=%s\n' "$label" "$image_id"
        printf '%s.created=%s\n' "$label" "$image_created"
        printf '%s.descriptor=%s\n' "$label" "$image_descriptor"
        printf '%s.config=%s\n' "$label" "$image_config"
        printf '%s.rootfs=%s\n' "$label" "$image_rootfs"
    done
} > "$staging_root/base-images-inspect.txt"
runtime_platform=$(docker_inspect_field "$runtime_execution_ref" '{{.Os}}/{{.Architecture}}') || die 'cannot inspect runtime-image platform'
runtime_id=$(docker_inspect_field "$runtime_execution_ref" '{{.Id}}') || die 'cannot inspect runtime-image ID'
runtime_created=$(docker_inspect_field "$runtime_execution_ref" '{{.Created}}') || die 'cannot inspect runtime-image Created value'
runtime_descriptor=$(docker_inspect_field "$runtime_execution_ref" '{{json .Descriptor}}') || die 'cannot inspect runtime-image descriptor'
runtime_config=$(docker_inspect_field "$runtime_execution_ref" '{{json .Config}}') || die 'cannot inspect runtime-image config'
runtime_rootfs=$(docker_inspect_field "$runtime_execution_ref" '{{json .RootFS}}') || die 'cannot inspect runtime-image rootfs'
{
    printf 'requestedReference=%s\n' "$runtime_image"
    printf 'executedReference=%s\n' "$runtime_execution_ref"
    printf 'platform=%s\n' "$runtime_platform"
    printf 'id=%s\n' "$runtime_id"
    printf 'created=%s\n' "$runtime_created"
    printf 'descriptor=%s\n' "$runtime_descriptor"
    printf 'config=%s\n' "$runtime_config"
    printf 'rootfs=%s\n' "$runtime_rootfs"
} > "$staging_root/runtime-image-inspect.txt"

run_one() {
    local label=$1 run_seed_cargo=$2 run_seed_lfs=$3 run_repo=$4 artifact target work host_diagnostics container_name
    artifact="$staging_root/$label"
    target="$work_root/$label-target"
    work="$work_root/$label-work"
    host_diagnostics="$work_root/$label-host-diagnostics"
    container_name="eip0045-b4-$label-${lock_token:0:16}"
    mkdir -- "$artifact" "$target" "$work"
    git_evidence "$run_repo" "$artifact/workspace-git-before.txt"
    assert_runtime_image
    run_qualifying_container "$container_name" "$host_diagnostics" \
        --pull=never --network=none --read-only --cap-drop=ALL --security-opt no-new-privileges --pids-limit 512 \
        --cpuset-cpus 0-3 --memory 12g --memory-swap 12g \
        --tmpfs /tmp:rw,nosuid,nodev,noexec,size=1g \
        --tmpfs /home:rw,nosuid,nodev,noexec,size=2g \
        --mount type=bind,src="$run_repo",dst=/workspace,readonly \
        --mount type=bind,src="$run_seed_cargo",dst=/seed/cargo,readonly \
        --mount type=bind,src="$run_seed_lfs",dst=/seed/lfs,readonly \
        --mount type=bind,src="$target",dst=/target \
        --mount type=bind,src="$work",dst=/work \
        --mount type=bind,src="$artifact",dst=/output \
        "$runtime_execution_ref" bash /workspace/reproduction/b4-build/container-build.sh "$label"
    assert_runtime_image
    git_evidence "$run_repo" "$artifact/workspace-git-after.txt"
    cmp "$artifact/workspace-git-before.txt" "$artifact/workspace-git-after.txt" >/dev/null || die 'workspace Git state changed during build'
    cp -- "$artifact/workspace-git-before.txt" "$artifact/workspace-git.txt"
}

run_one run-1 "$seed_cargo_root" "$seed_lfs_root" "$repo_root"
run_one run-2 "$second_seed_cargo_root" "$second_seed_lfs_root" "$second_repo_root"
assert_runtime_image
cmp "$staging_root/run-1/guest.elf" "$staging_root/run-2/guest.elf" || die 'fresh builds produced different guest ELF bytes'
cmp "$staging_root/run-1/image-id.bin" "$staging_root/run-2/image-id.bin" || die 'fresh builds produced different canonical image ID bytes'
cmp "$staging_root/run-1/alternate-program-guest.elf" "$staging_root/run-2/alternate-program-guest.elf" \
    || die 'fresh builds produced different alternate-program guest ELF bytes'
cmp "$staging_root/run-1/alternate-program-image-id.bin" "$staging_root/run-2/alternate-program-image-id.bin" \
    || die 'fresh builds produced different alternate-program image ID bytes'
if cmp -s "$staging_root/run-1/image-id.bin" "$staging_root/run-1/alternate-program-image-id.bin"; then
    die 'consumer and alternate-program image IDs must be distinct'
fi
for evidence in \
    source-materialized-manifest.txt source-checkout-admin-manifest.txt workspace-source-manifest.txt workspace-git.txt \
    candidate-generator image-id.hex image-id-declaration.txt \
    alternate-program-image-id.hex alternate-program-image-id-declaration.txt \
    source-git-observed.txt host-toolchain-observed.txt \
    guest-toolchain-observed.txt build-policy.txt resource-policy-observed.txt build-environment.txt \
    candidate-source-lock.json cargo-metadata-generator-host.json cargo-metadata-methods-build.json cargo-metadata-guest.json \
    cargo-closure-generator-host.json cargo-closure-methods-build.json cargo-closure-guest.json identity.txt
do
    cmp "$staging_root/run-1/$evidence" "$staging_root/run-2/$evidence" || die "fresh builds produced different $evidence evidence"
done
write_tree_manifest "$staging_root/run-1" "$work_root/run-1-evidence-manifest.txt"
write_tree_manifest "$staging_root/run-2" "$work_root/run-2-evidence-manifest.txt"
cmp "$work_root/run-1-evidence-manifest.txt" "$work_root/run-2-evidence-manifest.txt" || die 'fresh builds produced different complete run evidence trees'
cp -- "$work_root/run-1-evidence-manifest.txt" "$staging_root/run-evidence-identity.txt"
assert_runtime_image
reject_tree_special_or_crlf "$staging_root" 'completed evidence staging tree'
write_tree_manifest "$staging_root" "$work_root/evidence-manifest.txt"
mv -- "$work_root/evidence-manifest.txt" "$staging_root/evidence-manifest.txt"
manifest_hash=$(sha256_file "$staging_root/evidence-manifest.txt") || die 'cannot hash evidence manifest'
guest_hash=$(sha256_file "$staging_root/run-1/guest.elf") || die 'cannot hash guest ELF'
image_id_hash=$(sha256_file "$staging_root/run-1/image-id.bin") || die 'cannot hash image ID'
alternate_program_guest_hash=$(sha256_file "$staging_root/run-1/alternate-program-guest.elf") \
    || die 'cannot hash alternate-program guest ELF'
alternate_program_image_id_hash=$(sha256_file "$staging_root/run-1/alternate-program-image-id.bin") \
    || die 'cannot hash alternate-program image ID'
{
    printf 'schema=eip0045-b4-build-completion-v2\n'
    printf 'status=complete\n'
    printf 'runCount=2\n'
    printf 'inputIsolation=path-disjoint-standalone-clean-checkouts-private-object-stores-and-seeds\n'
    printf 'executionIsolation=fresh-home-target-and-work-per-run-same-pinned-runtime\n'
    printf 'runtimeManifest=%s\n' "$runtime_execution_ref"
    printf 'evidenceManifestSha256=%s\n' "$manifest_hash"
    printf 'guestElfSha256=%s\n' "$guest_hash"
    printf 'imageIdSha256=%s\n' "$image_id_hash"
    printf 'alternateProgramGuestElfSha256=%s\n' "$alternate_program_guest_hash"
    printf 'alternateProgramImageIdSha256=%s\n' "$alternate_program_image_id_hash"
} > "$staging_root/B4-COMPLETE"
[ ! -e "$output_root" ] && [ ! -L "$output_root" ] || die 'final output directory appeared before atomic publication'
mv --no-clobber --no-target-directory -- "$staging_root" "$output_root"
[ ! -e "$staging_root" ] && [ -f "$output_root/B4-COMPLETE" ] || die 'create-only atomic evidence publication lost its race'
publication_occurred=1
assert_runtime_image
checker_target="$work_root/run-1-target"
[ -f "$checker_target/debug/eip0045-reproduction" ] || die 'fresh-process B4 checker binary is absent'
checker_container_name="eip0045-b4-checker-${lock_token:0:16}"
checker_host_diagnostics="$work_root/checker-host-diagnostics"
run_qualifying_container "$checker_container_name" "$checker_host_diagnostics" \
    --pull=never --network=none --read-only --cap-drop=ALL --security-opt no-new-privileges --pids-limit 64 \
    --memory 1g --memory-swap 1g --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m \
    --mount type=bind,src="$output_root",dst=/published,readonly \
    --mount type=bind,src="$checker_target",dst=/checker-target,readonly \
    "$runtime_execution_ref" /checker-target/debug/eip0045-reproduction b4-build-check \
    --root /published --allow-unanchored-inspection
assert_runtime_image
published=1
printf '%s\n' "B4 build: path-disjoint clean builds agree; complete evidence published at $output_root"
