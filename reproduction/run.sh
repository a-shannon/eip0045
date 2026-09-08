#!/usr/bin/env sh
set -eu

die() {
    printf '%s\n' "$*" >&2
    exit 1
}

normalize_absolute_path() (
    set -f
    normalize_input=$1
    normalize_result=
    normalize_saved_ifs=$IFS
    IFS=/
    set -- $normalize_input
    IFS=$normalize_saved_ifs
    for normalize_component do
        case "$normalize_component" in
            '' | .)
                ;;
            ..)
                normalize_result=${normalize_result%/*}
                ;;
            *)
                normalize_result=$normalize_result/$normalize_component
                ;;
        esac
    done
    if [ -n "$normalize_result" ]; then
        printf '%s\n' "$normalize_result"
    else
        printf '%s\n' /
    fi
)

canonicalize_path() {
    canonical_input=$1
    case "$canonical_input" in
        /*)
            canonical_probe=$canonical_input
            ;;
        *)
            canonical_probe=$invocation_dir/$canonical_input
            ;;
    esac
    canonical_suffix=
    while [ ! -e "$canonical_probe" ] && [ ! -L "$canonical_probe" ]; do
        canonical_component=${canonical_probe##*/}
        canonical_parent=${canonical_probe%/*}
        if [ -z "$canonical_parent" ]; then
            canonical_parent=/
        fi
        if [ -n "$canonical_suffix" ]; then
            canonical_suffix=$canonical_component/$canonical_suffix
        else
            canonical_suffix=$canonical_component
        fi
        if [ "$canonical_parent" = "$canonical_probe" ]; then
            break
        fi
        canonical_probe=$canonical_parent
    done

    if [ -d "$canonical_probe" ]; then
        canonical_prefix=$(CDPATH= cd -P -- "$canonical_probe" && pwd)
    else
        canonical_parent=${canonical_probe%/*}
        canonical_component=${canonical_probe##*/}
        if [ -z "$canonical_parent" ]; then
            canonical_parent=/
        fi
        canonical_prefix=$(CDPATH= cd -P -- "$canonical_parent" && pwd)
        canonical_prefix=$canonical_prefix/$canonical_component
    fi

    if [ -n "$canonical_suffix" ]; then
        normalize_absolute_path "$canonical_prefix/$canonical_suffix"
    else
        normalize_absolute_path "$canonical_prefix"
    fi
}

paths_overlap() {
    overlap_first=$1
    overlap_second=$2
    if [ "$overlap_first" = / ] || [ "$overlap_second" = / ]; then
        return 0
    fi
    case "$overlap_first" in
        "$overlap_second" | "$overlap_second"/*)
            return 0
            ;;
    esac
    case "$overlap_second" in
        "$overlap_first" | "$overlap_first"/*)
            return 0
            ;;
    esac
    return 1
}

find_synchronized_workspace_root() {
    workspace_candidate=$repo_root
    while :; do
        if [ -f "$workspace_candidate/AGENTS.md" ] && [ -d "$workspace_candidate/.agent" ]; then
            printf '%s\n' "$workspace_candidate"
            return 0
        fi
        workspace_parent=${workspace_candidate%/*}
        if [ -z "$workspace_parent" ]; then
            workspace_parent=/
        fi
        if [ "$workspace_parent" = "$workspace_candidate" ]; then
            break
        fi
        workspace_candidate=$workspace_parent
    done
    printf '%s\n' "$repo_root"
}

assert_outside_synchronized_roots() {
    synchronized_label=$1
    synchronized_candidate=$2

    if paths_overlap "$synchronized_candidate" "$workspace_root"; then
        die "EIP-0045 $synchronized_label overlaps the synchronized repository or workspace: $synchronized_candidate"
    fi

    synchronized_remaining=${EIP0045_FORBIDDEN_SYNC_ROOTS:-}
    if [ -z "$synchronized_remaining" ]; then
        return 0
    fi
    case ":$synchronized_remaining:" in
        *::* )
            die 'EIP0045_FORBIDDEN_SYNC_ROOTS contains an empty path'
            ;;
    esac

    while [ -n "$synchronized_remaining" ]; do
        case "$synchronized_remaining" in
            *:*)
                synchronized_root=${synchronized_remaining%%:*}
                synchronized_remaining=${synchronized_remaining#*:}
                ;;
            *)
                synchronized_root=$synchronized_remaining
                synchronized_remaining=
                ;;
        esac
        if printf '%s' "$synchronized_root" | LC_ALL=C grep '[[:cntrl:]]' >/dev/null 2>&1; then
            die 'a synchronized-root path contains a control character'
        fi
        if [ ! -d "$synchronized_root" ]; then
            die "configured synchronized root is unavailable: $synchronized_root"
        fi
        synchronized_root=$(canonicalize_path "$synchronized_root")
        if paths_overlap "$synchronized_candidate" "$synchronized_root"; then
            die "EIP-0045 $synchronized_label overlaps the synchronized repository or workspace: $synchronized_candidate"
        fi
    done
}

action="${1:-test}"
if [ "$#" -gt 0 ]; then
    shift
fi

case "$action" in
    preflight | build | test | clippy | verify-invariants | preflight-proof-output | manifest-proof-output | guard-candidate)
        ;;
    *)
        printf '%s\n' "unknown action: $action" >&2
        exit 2
        ;;
esac

invocation_dir=$(pwd -P)
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
workspace_root=$(canonicalize_path "$(find_synchronized_workspace_root)")

lane=${EIP0045_TARGET_LANE:-}
if [ -n "$lane" ]; then
    if [ "${#lane}" -gt 32 ]; then
        die 'EIP0045_TARGET_LANE must be empty or match ^[a-z0-9][a-z0-9-]{0,31}$'
    fi
    case "$lane" in
        [a-z0-9]*)
            ;;
        *)
            die 'EIP0045_TARGET_LANE must be empty or match ^[a-z0-9][a-z0-9-]{0,31}$'
            ;;
    esac
    case "$lane" in
        *[!a-z0-9-]*)
            die 'EIP0045_TARGET_LANE must be empty or match ^[a-z0-9][a-z0-9-]{0,31}$'
            ;;
    esac
fi

target_root=${EIP0045_TARGET_DIR:-${TMPDIR:-/tmp}/eip-0045-profile-target}
if [ -n "$lane" ]; then
    target_candidate=$target_root/$lane
    lane_label=$lane
else
    target_candidate=$target_root
    lane_label=shared
fi
eip0045_target=$(canonicalize_path "$target_candidate")

assert_outside_synchronized_roots 'target directory' "$eip0045_target"
if [ -n "${CARGO_HOME:-}" ]; then
    cargo_home=$(canonicalize_path "$CARGO_HOME")
    assert_outside_synchronized_roots 'CARGO_HOME' "$cargo_home"
    CARGO_HOME=$cargo_home
    export CARGO_HOME
fi

minimum_free_gib=${EIP0045_MIN_FREE_GIB:-5}
case "$minimum_free_gib" in
    '' | *[!0-9]*)
        die 'EIP0045_MIN_FREE_GIB must be a non-negative integer no greater than 1048576'
        ;;
esac
minimum_free_gib=$(printf '%s\n' "$minimum_free_gib" | sed 's/^0*//')
if [ -z "$minimum_free_gib" ]; then
    minimum_free_gib=0
fi
if [ "${#minimum_free_gib}" -gt 7 ] || {
    [ "${#minimum_free_gib}" -eq 7 ] && [ "$minimum_free_gib" -gt 1048576 ]
}; then
    die 'EIP0045_MIN_FREE_GIB must be a non-negative integer no greater than 1048576'
fi

mkdir -p "$eip0045_target"
if ! available_free_kib=$(df -Pk "$eip0045_target" 2>/dev/null | awk 'NR == 2 { print $4; found = 1 } END { if (!found) exit 1 }'); then
    die "unable to determine free space for EIP-0045 target directory: $eip0045_target"
fi
case "$available_free_kib" in
    '' | *[!0-9]*)
        die "unable to determine free space for EIP-0045 target directory: $eip0045_target"
        ;;
esac
available_free_bytes=$((available_free_kib * 1024))
minimum_free_kib=$((minimum_free_gib * 1048576))
minimum_free_bytes=$((minimum_free_kib * 1024))
if [ "$available_free_kib" -lt "$minimum_free_kib" ]; then
    die "EIP-0045 target free space is below the configured minimum: $available_free_bytes < $minimum_free_bytes bytes"
fi

export CARGO_TARGET_DIR="$eip0045_target"
lock_path=$eip0045_target/.eip0045-run.lock
lock_held=0

cleanup_lock() {
    cleanup_status=$?
    trap - 0
    if [ "$lock_held" -eq 1 ]; then
        rm -f "$lock_path/owner"
        rmdir "$lock_path" 2>/dev/null || true
        lock_held=0
    fi
    exit "$cleanup_status"
}

trap cleanup_lock 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if ! mkdir "$lock_path" 2>/dev/null; then
    die "EIP-0045 target lane is already in use; select a distinct EIP0045_TARGET_LANE or EIP0045_TARGET_DIR: $lane_label"
fi
lock_held=1
printf 'pid=%s\nlane=%s\n' "$$" "$lane_label" >"$lock_path/owner"

cd "$repo_root"
case "$action" in
    preflight)
        printf '%s\n' 'schema=eip0045-local-run-preflight-v1'
        printf 'lane=%s\n' "$lane_label"
        printf 'targetDir=%s\n' "$eip0045_target"
        printf 'availableFreeBytes=%s\n' "$available_free_bytes"
        printf 'minimumFreeBytes=%s\n' "$minimum_free_bytes"
        ;;
    build)
        cargo +1.89.0 build --workspace --locked "$@"
        ;;
    test)
        cargo +1.89.0 test --workspace --locked "$@"
        ;;
    clippy)
        cargo +1.89.0 clippy --workspace --all-targets --locked -- -D warnings
        ;;
    verify-invariants)
        cargo +1.89.0 run -p eip-0045-reproduction --locked -- verify-invariants "$@"
        ;;
    preflight-proof-output)
        cargo +1.89.0 run -p eip-0045-reproduction --locked -- \
            preflight-proof-output "$@"
        ;;
    manifest-proof-output)
        cargo +1.89.0 run -p eip-0045-reproduction --locked -- \
            manifest-proof-output "$@"
        ;;
    guard-candidate)
        cargo +1.89.0 run -p eip-0045-reproduction --locked -- \
            guard-candidate --repo-root "$repo_root" "$@"
        ;;
esac
