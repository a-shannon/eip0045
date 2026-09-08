#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
helper="$script_dir/diagnostics.sh"
[ -f "$helper" ] || {
    printf '%s\n' "missing B4 diagnostics helper: $helper" >&2
    exit 1
}

test_root=$(mktemp -d)
cleanup() {
    status=$?
    trap - EXIT
    rm -rf -- "$test_root"
    exit "$status"
}
trap cleanup EXIT

run_fault() {
    diagnostic_root=$1
    set +e
    (
        set -Eeuo pipefail
        # shellcheck source=diagnostics.sh
        source "$helper"
        b4_diag_init "$diagnostic_root" fault-run
        fault_exit() {
            exact_status=$?
            trap - EXIT ERR
            set +e
            b4_diag_write_exit_state "$exact_status" started
            b4_diag_write_exit_state "$exact_status" complete
            exit "$exact_status"
        }
        trap 'b4_diag_on_err "$?" "$LINENO" "$BASH_COMMAND"' ERR
        trap fault_exit EXIT
        if env | grep -q '^B4_DIAG_'; then
            printf '%s\n' 'B4 diagnostic state leaked into the child environment' >&2
            exit 98
        fi
        b4_diag_mark_complete bootstrap
        b4_diag_set_phase deterministic-fault
        bash -c 'exit 37'
    )
    observed_status=$?
    set -e
    [ "$observed_status" = 37 ] || {
        printf '%s\n' "ERR trap changed exit status: expected 37, got $observed_status" >&2
        exit 1
    }
}

run_command_substitution_fault() {
    diagnostic_root=$1
    set +e
    (
        set -Eeuo pipefail
        shopt -s inherit_errexit
        # shellcheck source=diagnostics.sh
        source "$helper"
        b4_diag_init "$diagnostic_root" command-substitution-run
        fault_exit() {
            exact_status=$?
            trap - EXIT ERR
            set +e
            b4_diag_write_exit_state "$exact_status" started
            b4_diag_write_exit_state "$exact_status" complete
            exit "$exact_status"
        }
        trap 'b4_diag_on_err "$?" "$LINENO" "$BASH_COMMAND"' ERR
        trap fault_exit EXIT
        b4_diag_mark_complete bootstrap
        b4_diag_set_phase command-substitution-fault
        substituted=$(bash -c 'exit 37'; printf survived)
        printf '%s\n' "unexpected command-substitution continuation: $substituted" >&2
        exit 99
    )
    observed_status=$?
    set -e
    [ "$observed_status" = 37 ] || {
        printf '%s\n' "command substitution changed exit status: expected 37, got $observed_status" >&2
        exit 1
    }
}

run_forbidden_path_fault() {
    run_root=$1
    mkdir -- "$run_root" "$run_root/tree"
    : > "$run_root/tree/"$'forbidden\npath'
    set +e
    (
        cd -- "$run_root"
        set -Eeuo pipefail
        # shellcheck source=diagnostics.sh
        source "$helper"
        b4_diag_init "$run_root/diagnostics" path-fault-run
        fault_exit() {
            exact_status=$?
            trap - EXIT ERR
            set +e
            b4_diag_write_exit_state "$exact_status" started
            b4_diag_write_exit_state "$exact_status" complete
            exit "$exact_status"
        }
        trap 'b4_diag_on_err "$?" "$LINENO" "$BASH_COMMAND"' ERR
        trap fault_exit EXIT
        b4_diag_mark_complete bootstrap
        b4_diag_set_phase path-preflight
        if b4_diag_reject_crlf_paths forbidden-paths tree "$LINENO"; then
            exit 99
        else
            exit "$?"
        fi
    )
    observed_status=$?
    set -e
    [ "$observed_status" = 91 ] || {
        printf '%s\n' "CR/LF scan changed exit status: expected 91, got $observed_status" >&2
        exit 1
    }
}

run_enumeration_fault() {
    run_root=$1
    mkdir -- "$run_root"
    set +e
    (
        cd -- "$run_root"
        set -Eeuo pipefail
        # shellcheck source=diagnostics.sh
        source "$helper"
        b4_diag_init "$run_root/diagnostics" enumeration-fault-run
        fault_exit() {
            exact_status=$?
            trap - EXIT ERR
            set +e
            b4_diag_write_exit_state "$exact_status" started
            b4_diag_write_exit_state "$exact_status" complete
            exit "$exact_status"
        }
        trap 'b4_diag_on_err "$?" "$LINENO" "$BASH_COMMAND"' ERR
        trap fault_exit EXIT
        b4_diag_mark_complete bootstrap
        b4_diag_set_phase path-preflight
        if b4_diag_reject_crlf_paths missing-paths missing-tree "$LINENO"; then
            exit 99
        else
            exit "$?"
        fi
    )
    observed_status=$?
    set -e
    [ "$observed_status" = 1 ] || {
        printf '%s\n' "enumeration scan changed exit status: expected 1, got $observed_status" >&2
        exit 1
    }
}

run_special_node_fault() {
    run_root=$1
    mkdir -- "$run_root" "$run_root/tree"
    mkfifo -- "$run_root/tree/forbidden-fifo"
    set +e
    (
        cd -- "$run_root"
        set -Eeuo pipefail
        # shellcheck source=diagnostics.sh
        source "$helper"
        b4_diag_init "$run_root/diagnostics" special-node-run
        fault_exit() {
            exact_status=$?
            trap - EXIT ERR
            set +e
            b4_diag_write_exit_state "$exact_status" started
            b4_diag_write_exit_state "$exact_status" complete
            exit "$exact_status"
        }
        trap 'b4_diag_on_err "$?" "$LINENO" "$BASH_COMMAND"' ERR
        trap fault_exit EXIT
        b4_diag_mark_complete bootstrap
        b4_diag_set_phase path-preflight
        if b4_diag_reject_special_nodes special-nodes "$LINENO" tree; then
            exit 99
        else
            exit "$?"
        fi
    )
    observed_status=$?
    set -e
    [ "$observed_status" = 1 ] || {
        printf '%s\n' "special-node scan changed exit status: expected 1, got $observed_status" >&2
        exit 1
    }
}

run_special_enumeration_fault() {
    run_root=$1
    mkdir -- "$run_root"
    set +e
    (
        cd -- "$run_root"
        set -Eeuo pipefail
        # shellcheck source=diagnostics.sh
        source "$helper"
        b4_diag_init "$run_root/diagnostics" special-enumeration-run
        fault_exit() {
            exact_status=$?
            trap - EXIT ERR
            set +e
            b4_diag_write_exit_state "$exact_status" started
            b4_diag_write_exit_state "$exact_status" complete
            exit "$exact_status"
        }
        trap 'b4_diag_on_err "$?" "$LINENO" "$BASH_COMMAND"' ERR
        trap fault_exit EXIT
        b4_diag_mark_complete bootstrap
        b4_diag_set_phase path-preflight
        if b4_diag_reject_special_nodes special-enumeration "$LINENO" missing-tree; then
            exit 99
        else
            exit "$?"
        fi
    )
    observed_status=$?
    set -e
    [ "$observed_status" = 1 ] || {
        printf '%s\n' "special-node enumeration changed exit status: expected 1, got $observed_status" >&2
        exit 1
    }
}

run_hard_link_fault() {
    run_root=$1
    mkdir -- "$run_root" "$run_root/tree"
    printf '%s\n' fixture > "$run_root/tree/target"
    ln -- "$run_root/tree/target" "$run_root/tree/alias"
    set +e
    (
        cd -- "$run_root"
        set -Eeuo pipefail
        # shellcheck source=diagnostics.sh
        source "$helper"
        b4_diag_init "$run_root/diagnostics" hard-link-run
        fault_exit() {
            exact_status=$?
            trap - EXIT ERR
            set +e
            b4_diag_write_exit_state "$exact_status" started
            b4_diag_write_exit_state "$exact_status" complete
            exit "$exact_status"
        }
        trap 'b4_diag_on_err "$?" "$LINENO" "$BASH_COMMAND"' ERR
        trap fault_exit EXIT
        b4_diag_mark_complete bootstrap
        b4_diag_set_phase path-preflight
        if b4_diag_reject_hard_links hard-links "$LINENO" tree; then
            exit 99
        else
            exit "$?"
        fi
    )
    observed_status=$?
    set -e
    [ "$observed_status" = 1 ] || {
        printf '%s\n' "hard-link scan changed exit status: expected 1, got $observed_status" >&2
        exit 1
    }
}

run_cargo_checkout_hardlink_normalization() {
    local run_root=$1 cargo_git checkout db pack_stem pack_file index_file pack_mode index_mode
    cargo_git=$run_root/cargo-git
    checkout=$cargo_git/checkouts/risc0-identity/8eb06ab
    db=$cargo_git/db/risc0-identity
    pack_stem=pack-0123456789abcdef0123456789abcdef01234567
    pack_file=$pack_stem.pack
    index_file=$pack_stem.idx

    mkdir -p -- \
        "$checkout/.git/objects/pack" \
        "$db/objects/pack"
    : > "$checkout/.cargo-ok"
    printf '%s\n' 'deterministic pack bytes' > "$db/objects/pack/$pack_file"
    printf '%s\n' 'deterministic index bytes' > "$db/objects/pack/$index_file"
    chmod 0640 -- "$db/objects/pack/$pack_file" "$db/objects/pack/$index_file"
    pack_mode=$(stat -c %a -- "$db/objects/pack/$pack_file")
    index_mode=$(stat -c %a -- "$db/objects/pack/$index_file")
    ln -- "$db/objects/pack/$pack_file" "$checkout/.git/objects/pack/$pack_file"
    ln -- "$db/objects/pack/$index_file" "$checkout/.git/objects/pack/$index_file"

    # shellcheck source=diagnostics.sh
    source "$helper"
    b4_diag_init "$run_root/diagnostics" cargo-hardlink-run
    b4_normalize_cargo_checkout_pack_hard_links "$checkout" "$cargo_git"

    for name in "$pack_file" "$index_file"; do
        local checkout_path=$checkout/.git/objects/pack/$name
        local database_path=$db/objects/pack/$name
        local expected_mode=$pack_mode
        [ "$name" = "$pack_file" ] || expected_mode=$index_mode
        [ "$(stat -c %h -- "$checkout_path")" = 1 ]
        [ "$(stat -c %h -- "$database_path")" = 1 ]
        [ "$(stat -c %a -- "$checkout_path")" = "$expected_mode" ]
        [ "$(stat -c %a -- "$database_path")" = "$expected_mode" ]
        [ "$(stat -c '%d:%i' -- "$checkout_path")" != "$(stat -c '%d:%i' -- "$database_path")" ]
        cmp -s -- "$checkout_path" "$database_path"
    done
    [ -z "$(find "$checkout" -xdev -type f -links +1 -print -quit)" ]

    local checkout_hash
    checkout_hash=$(sha256sum "$checkout/.git/objects/pack/$pack_file")
    printf '%s\n' 'database-only mutation' >> "$db/objects/pack/$pack_file"
    [ "$(sha256sum "$checkout/.git/objects/pack/$pack_file")" = "$checkout_hash" ]
    ! cmp -s -- "$checkout/.git/objects/pack/$pack_file" "$db/objects/pack/$pack_file"

    ln -- "$checkout/.git/objects/pack/$pack_file" "$checkout/reintroduced-alias"
    if b4_diag_reject_hard_links reintroduced-hard-link "$LINENO" "$checkout"; then
        printf '%s\n' 'post-normalization hardlink scan admitted a new alias' >&2
        exit 1
    fi
}

setup_cargo_checkout_pack_pair() {
    local run_root=$1 stem=${2:-pack-0123456789abcdef0123456789abcdef01234567}
    CARGO_PAIR_GIT=$run_root/cargo-git
    CARGO_PAIR_CHECKOUT=$CARGO_PAIR_GIT/checkouts/risc0-identity/8eb06ab
    CARGO_PAIR_DB=$CARGO_PAIR_GIT/db/risc0-identity
    CARGO_PAIR_STEM=$stem
    mkdir -p -- \
        "$CARGO_PAIR_CHECKOUT/.git/objects/pack" \
        "$CARGO_PAIR_DB/objects/pack"
    : > "$CARGO_PAIR_CHECKOUT/.cargo-ok"
    printf '%s\n' 'pack bytes' > "$CARGO_PAIR_DB/objects/pack/$stem.pack"
    printf '%s\n' 'index bytes' > "$CARGO_PAIR_DB/objects/pack/$stem.idx"
    ln -- "$CARGO_PAIR_DB/objects/pack/$stem.pack" "$CARGO_PAIR_CHECKOUT/.git/objects/pack/$stem.pack"
    ln -- "$CARGO_PAIR_DB/objects/pack/$stem.idx" "$CARGO_PAIR_CHECKOUT/.git/objects/pack/$stem.idx"
}

assert_cargo_pair_remains_linked() {
    [ "$(stat -c %h -- "$CARGO_PAIR_CHECKOUT/.git/objects/pack/$CARGO_PAIR_STEM.pack")" = 2 ]
    [ "$(stat -c %h -- "$CARGO_PAIR_DB/objects/pack/$CARGO_PAIR_STEM.pack")" = 2 ]
    [ "$(stat -c %h -- "$CARGO_PAIR_CHECKOUT/.git/objects/pack/$CARGO_PAIR_STEM.idx")" = 2 ]
    [ "$(stat -c %h -- "$CARGO_PAIR_DB/objects/pack/$CARGO_PAIR_STEM.idx")" = 2 ]
}

run_cargo_checkout_noop_case() {
    local run_root=$1 cargo_git checkout db
    cargo_git=$run_root/cargo-git
    checkout=$cargo_git/checkouts/risc0-identity/8eb06ab
    db=$cargo_git/db/risc0-identity
    mkdir -p -- "$checkout/.git/objects/pack" "$db/objects/pack"
    : > "$checkout/.cargo-ok"
    # shellcheck source=diagnostics.sh
    source "$helper"
    b4_diag_init "$run_root/diagnostics" cargo-no-hardlink-run
    b4_normalize_cargo_checkout_pack_hard_links "$checkout" "$cargo_git"
    [ -z "$(find "$checkout" -xdev -type f -links +1 -print -quit)" ]
}

run_cargo_checkout_unexpected_location_cases() {
    local parent_root=$1 case_name run_root offender alias_source observed_status
    for case_name in working-tree cargo-marker git-config git-head git-ref loose-object; do
        run_root=$parent_root/$case_name
        setup_cargo_checkout_pack_pair "$run_root"
        alias_source=$run_root/unexpected-alias-source
        printf '%s\n' "$case_name" > "$alias_source"
        case $case_name in
            working-tree) offender=$CARGO_PAIR_CHECKOUT/src/lib.rs ;;
            cargo-marker) offender=$CARGO_PAIR_CHECKOUT/.cargo-ok; rm -- "$offender" ;;
            git-config) offender=$CARGO_PAIR_CHECKOUT/.git/config ;;
            git-head) offender=$CARGO_PAIR_CHECKOUT/.git/HEAD ;;
            git-ref) offender=$CARGO_PAIR_CHECKOUT/.git/refs/heads/master ;;
            loose-object) offender=$CARGO_PAIR_CHECKOUT/.git/objects/ab/cdef ;;
            *) exit 1 ;;
        esac
        mkdir -p -- "$(dirname -- "$offender")"
        ln -- "$alias_source" "$offender"
        # shellcheck source=diagnostics.sh
        source "$helper"
        b4_diag_init "$run_root/diagnostics" cargo-location-run
        set +e
        b4_normalize_cargo_checkout_pack_hard_links "$CARGO_PAIR_CHECKOUT" "$CARGO_PAIR_GIT" 2>/dev/null
        observed_status=$?
        set -e
        [ "$observed_status" = 1 ]
        assert_cargo_pair_remains_linked
    done
}

run_cargo_checkout_topology_cases() {
    local parent_root=$1 run_root observed_status second_stem outside_source
    local checkout_pack database_pack

    run_root=$parent_root/nested-pack
    setup_cargo_checkout_pack_pair "$run_root"
    mkdir -- "$CARGO_PAIR_CHECKOUT/.git/objects/pack/nested"
    mv -- "$CARGO_PAIR_CHECKOUT/.git/objects/pack/$CARGO_PAIR_STEM.pack" \
        "$CARGO_PAIR_CHECKOUT/.git/objects/pack/nested/$CARGO_PAIR_STEM.pack"
    mv -- "$CARGO_PAIR_CHECKOUT/.git/objects/pack/$CARGO_PAIR_STEM.idx" \
        "$CARGO_PAIR_CHECKOUT/.git/objects/pack/nested/$CARGO_PAIR_STEM.idx"
    # shellcheck source=diagnostics.sh
    source "$helper"
    b4_diag_init "$run_root/diagnostics" cargo-nested-pack-run
    set +e
    b4_normalize_cargo_checkout_pack_hard_links "$CARGO_PAIR_CHECKOUT" "$CARGO_PAIR_GIT" \
        2> "$run_root/rejection.txt"
    observed_status=$?
    set -e
    [ "$observed_status" = 1 ]
    grep -F 'Cargo pack hardlink is not directly below the pack directory' \
        "$run_root/rejection.txt" >/dev/null
    [ "$(stat -c %h -- "$CARGO_PAIR_DB/objects/pack/$CARGO_PAIR_STEM.pack")" = 2 ]
    [ "$(stat -c %h -- "$CARGO_PAIR_DB/objects/pack/$CARGO_PAIR_STEM.idx")" = 2 ]

    run_root=$parent_root/third-alias
    setup_cargo_checkout_pack_pair "$run_root"
    ln -- "$CARGO_PAIR_DB/objects/pack/$CARGO_PAIR_STEM.pack" "$run_root/third-alias"
    # shellcheck source=diagnostics.sh
    source "$helper"
    b4_diag_init "$run_root/diagnostics" cargo-third-alias-run
    set +e
    b4_normalize_cargo_checkout_pack_hard_links "$CARGO_PAIR_CHECKOUT" "$CARGO_PAIR_GIT" 2>/dev/null
    observed_status=$?
    set -e
    [ "$observed_status" = 1 ]
    [ "$(stat -c %h -- "$CARGO_PAIR_DB/objects/pack/$CARGO_PAIR_STEM.pack")" = 3 ]

    run_root=$parent_root/wrong-counterpart
    setup_cargo_checkout_pack_pair "$run_root"
    rm -- "$CARGO_PAIR_CHECKOUT/.git/objects/pack/$CARGO_PAIR_STEM.pack"
    outside_source=$run_root/outside-pack-source
    printf '%s\n' 'outside bytes' > "$outside_source"
    ln -- "$outside_source" "$CARGO_PAIR_CHECKOUT/.git/objects/pack/$CARGO_PAIR_STEM.pack"
    ln -- "$CARGO_PAIR_DB/objects/pack/$CARGO_PAIR_STEM.pack" "$run_root/database-pack-alias"
    b4_diag_init "$run_root/diagnostics" cargo-counterpart-run
    set +e
    b4_normalize_cargo_checkout_pack_hard_links "$CARGO_PAIR_CHECKOUT" "$CARGO_PAIR_GIT" \
        2> "$run_root/rejection.txt"
    observed_status=$?
    set -e
    [ "$observed_status" = 1 ]
    grep -F 'Cargo checkout pack is linked to an unexpected inode' \
        "$run_root/rejection.txt" >/dev/null
    [ "$(stat -c %h -- "$outside_source")" = 2 ]
    [ "$(stat -c %h -- "$CARGO_PAIR_DB/objects/pack/$CARGO_PAIR_STEM.pack")" = 2 ]

    run_root=$parent_root/missing-counterpart
    setup_cargo_checkout_pack_pair "$run_root"
    checkout_pack=$CARGO_PAIR_CHECKOUT/.git/objects/pack/$CARGO_PAIR_STEM.pack
    database_pack=$CARGO_PAIR_DB/objects/pack/$CARGO_PAIR_STEM.pack
    outside_source=$run_root/missing-counterpart-alias
    ln -- "$database_pack" "$outside_source"
    rm -- "$database_pack"
    b4_diag_init "$run_root/diagnostics" cargo-missing-counterpart-run
    set +e
    b4_normalize_cargo_checkout_pack_hard_links "$CARGO_PAIR_CHECKOUT" "$CARGO_PAIR_GIT" \
        2> "$run_root/rejection.txt"
    observed_status=$?
    set -e
    [ "$observed_status" = 1 ]
    grep -F 'Cargo pack hardlink lacks a physical database counterpart' \
        "$run_root/rejection.txt" >/dev/null
    [ "$(stat -c %h -- "$checkout_pack")" = 2 ]
    [ "$(stat -c %h -- "$outside_source")" = 2 ]
    [ "$(stat -c %h -- "$CARGO_PAIR_DB/objects/pack/$CARGO_PAIR_STEM.idx")" = 2 ]

    run_root=$parent_root/symlink-counterpart
    setup_cargo_checkout_pack_pair "$run_root"
    checkout_pack=$CARGO_PAIR_CHECKOUT/.git/objects/pack/$CARGO_PAIR_STEM.pack
    database_pack=$CARGO_PAIR_DB/objects/pack/$CARGO_PAIR_STEM.pack
    outside_source=$run_root/symlink-counterpart-alias
    ln -- "$database_pack" "$outside_source"
    rm -- "$database_pack"
    if ln -s -- "$checkout_pack" "$database_pack" 2>/dev/null && [ -L "$database_pack" ]; then
        b4_diag_init "$run_root/diagnostics" cargo-symlink-counterpart-run
        set +e
        b4_normalize_cargo_checkout_pack_hard_links "$CARGO_PAIR_CHECKOUT" "$CARGO_PAIR_GIT" \
            2> "$run_root/rejection.txt"
        observed_status=$?
        set -e
        [ "$observed_status" = 1 ]
        grep -F 'Cargo pack hardlink lacks a physical database counterpart' \
            "$run_root/rejection.txt" >/dev/null
        [ "$(stat -c %h -- "$checkout_pack")" = 2 ]
        [ "$(stat -c %h -- "$outside_source")" = 2 ]
        [ "$(stat -c %h -- "$CARGO_PAIR_DB/objects/pack/$CARGO_PAIR_STEM.idx")" = 2 ]
    else
        rm -f -- "$database_pack"
    fi

    run_root=$parent_root/mismatched-stems
    setup_cargo_checkout_pack_pair "$run_root"
    second_stem=pack-89abcdef0123456789abcdef0123456789abcdef
    mv -- "$CARGO_PAIR_DB/objects/pack/$CARGO_PAIR_STEM.idx" "$CARGO_PAIR_DB/objects/pack/$second_stem.idx"
    mv -- "$CARGO_PAIR_CHECKOUT/.git/objects/pack/$CARGO_PAIR_STEM.idx" "$CARGO_PAIR_CHECKOUT/.git/objects/pack/$second_stem.idx"
    b4_diag_init "$run_root/diagnostics" cargo-stem-run
    set +e
    b4_normalize_cargo_checkout_pack_hard_links "$CARGO_PAIR_CHECKOUT" "$CARGO_PAIR_GIT" 2>/dev/null
    observed_status=$?
    set -e
    [ "$observed_status" = 1 ]
    [ "$(stat -c %h -- "$CARGO_PAIR_DB/objects/pack/$CARGO_PAIR_STEM.pack")" = 2 ]
    [ "$(stat -c %h -- "$CARGO_PAIR_DB/objects/pack/$second_stem.idx")" = 2 ]

    run_root=$parent_root/noncanonical-name
    setup_cargo_checkout_pack_pair "$run_root"
    second_stem=pack-not-canonical
    mv -- "$CARGO_PAIR_DB/objects/pack/$CARGO_PAIR_STEM.pack" "$CARGO_PAIR_DB/objects/pack/$second_stem.pack"
    mv -- "$CARGO_PAIR_CHECKOUT/.git/objects/pack/$CARGO_PAIR_STEM.pack" \
        "$CARGO_PAIR_CHECKOUT/.git/objects/pack/$second_stem.pack"
    mv -- "$CARGO_PAIR_DB/objects/pack/$CARGO_PAIR_STEM.idx" "$CARGO_PAIR_DB/objects/pack/$second_stem.idx"
    mv -- "$CARGO_PAIR_CHECKOUT/.git/objects/pack/$CARGO_PAIR_STEM.idx" \
        "$CARGO_PAIR_CHECKOUT/.git/objects/pack/$second_stem.idx"
    b4_diag_init "$run_root/diagnostics" cargo-name-run
    set +e
    b4_normalize_cargo_checkout_pack_hard_links "$CARGO_PAIR_CHECKOUT" "$CARGO_PAIR_GIT" \
        2> "$run_root/rejection.txt"
    observed_status=$?
    set -e
    [ "$observed_status" = 1 ]
    grep -F 'unexpected Cargo pack filename' "$run_root/rejection.txt" >/dev/null
    [ "$(stat -c %h -- "$CARGO_PAIR_DB/objects/pack/$second_stem.pack")" = 2 ]
    [ "$(stat -c %h -- "$CARGO_PAIR_DB/objects/pack/$second_stem.idx")" = 2 ]

    run_root=$parent_root/incomplete-pair
    setup_cargo_checkout_pack_pair "$run_root"
    rm -- "$CARGO_PAIR_CHECKOUT/.git/objects/pack/$CARGO_PAIR_STEM.idx"
    b4_diag_init "$run_root/diagnostics" cargo-incomplete-run
    set +e
    b4_normalize_cargo_checkout_pack_hard_links "$CARGO_PAIR_CHECKOUT" "$CARGO_PAIR_GIT" 2>/dev/null
    observed_status=$?
    set -e
    [ "$observed_status" = 1 ]
    [ "$(stat -c %h -- "$CARGO_PAIR_DB/objects/pack/$CARGO_PAIR_STEM.pack")" = 2 ]
}

run_cargo_checkout_copy_and_replace_faults() {
    local parent_root=$1 run_root observed_status FIND_CALL_COUNT MV_CALL_COUNT

    run_root=$parent_root/copy-failure
    setup_cargo_checkout_pack_pair "$run_root"
    # shellcheck source=diagnostics.sh
    source "$helper"
    b4_diag_init "$run_root/diagnostics" cargo-copy-failure-run
    cp() { return 82; }
    set +e
    b4_normalize_cargo_checkout_pack_hard_links "$CARGO_PAIR_CHECKOUT" "$CARGO_PAIR_GIT" \
        2> "$run_root/rejection.txt"
    observed_status=$?
    set -e
    unset -f cp
    [ "$observed_status" = 1 ]
    grep -F 'B4 Cargo checkout normalization copy failed' \
        "$run_root/rejection.txt" >/dev/null
    assert_cargo_pair_remains_linked

    run_root=$parent_root/copy-drift
    setup_cargo_checkout_pack_pair "$run_root"
    b4_diag_init "$run_root/diagnostics" cargo-copy-drift-run
    cp() {
        command cp "$@"
        local destination=${!#}
        printf X | dd of="$destination" bs=1 count=1 conv=notrunc status=none
    }
    set +e
    b4_normalize_cargo_checkout_pack_hard_links "$CARGO_PAIR_CHECKOUT" "$CARGO_PAIR_GIT" \
        2> "$run_root/rejection.txt"
    observed_status=$?
    set -e
    unset -f cp
    [ "$observed_status" = 1 ]
    grep -F 'normalization copy changed pack bytes or metadata' \
        "$run_root/rejection.txt" >/dev/null
    assert_cargo_pair_remains_linked

    run_root=$parent_root/copy-mode-drift
    setup_cargo_checkout_pack_pair "$run_root"
    local mode_probe=$run_root/mode-probe mode_before mode_after
    : > "$mode_probe"
    mode_before=$(stat -c %a -- "$mode_probe")
    chmod a+x -- "$mode_probe"
    mode_after=$(stat -c %a -- "$mode_probe")
    if [ "$mode_before" != "$mode_after" ]; then
        b4_diag_init "$run_root/diagnostics" cargo-mode-drift-run
        cp() {
            command cp "$@"
            local destination=${!#}
            chmod a+x -- "$destination"
        }
        set +e
        b4_normalize_cargo_checkout_pack_hard_links "$CARGO_PAIR_CHECKOUT" "$CARGO_PAIR_GIT" \
            2> "$run_root/rejection.txt"
        observed_status=$?
        set -e
        unset -f cp
        [ "$observed_status" = 1 ]
        grep -F 'normalization copy changed pack bytes or metadata' \
            "$run_root/rejection.txt" >/dev/null
        assert_cargo_pair_remains_linked
    fi

    run_root=$parent_root/temporary-collision
    setup_cargo_checkout_pack_pair "$run_root"
    : > "$CARGO_PAIR_CHECKOUT/.git/objects/pack/$CARGO_PAIR_STEM.idx.eip0045-single-link.tmp"
    b4_diag_init "$run_root/diagnostics" cargo-temp-collision-run
    set +e
    b4_normalize_cargo_checkout_pack_hard_links "$CARGO_PAIR_CHECKOUT" "$CARGO_PAIR_GIT" \
        2> "$run_root/rejection.txt"
    observed_status=$?
    set -e
    [ "$observed_status" = 1 ]
    grep -F 'normalization temporary path exists' "$run_root/rejection.txt" >/dev/null
    assert_cargo_pair_remains_linked

    run_root=$parent_root/replace-failure
    setup_cargo_checkout_pack_pair "$run_root"
    b4_diag_init "$run_root/diagnostics" cargo-replace-run
    mv() { return 83; }
    set +e
    b4_normalize_cargo_checkout_pack_hard_links "$CARGO_PAIR_CHECKOUT" "$CARGO_PAIR_GIT" 2>/dev/null
    observed_status=$?
    set -e
    unset -f mv
    [ "$observed_status" = 1 ]
    assert_cargo_pair_remains_linked

    run_root=$parent_root/replace-false-success
    setup_cargo_checkout_pack_pair "$run_root"
    b4_diag_init "$run_root/diagnostics" cargo-false-replace-run
    mv() { return 0; }
    set +e
    b4_normalize_cargo_checkout_pack_hard_links "$CARGO_PAIR_CHECKOUT" "$CARGO_PAIR_GIT" \
        2> "$run_root/rejection.txt"
    observed_status=$?
    set -e
    unset -f mv
    [ "$observed_status" = 1 ]
    grep -F 'normalization did not isolate pack bytes' \
        "$run_root/rejection.txt" >/dev/null
    assert_cargo_pair_remains_linked

    run_root=$parent_root/late-hardlink
    setup_cargo_checkout_pack_pair "$run_root"
    b4_diag_init "$run_root/diagnostics" cargo-late-hardlink-run
    MV_CALL_COUNT=0
    mv() {
        command mv "$@" || return
        MV_CALL_COUNT=$((MV_CALL_COUNT + 1))
        if [ "$MV_CALL_COUNT" = 2 ]; then
            ln -- "$CARGO_PAIR_CHECKOUT/.cargo-ok" "$CARGO_PAIR_CHECKOUT/late-alias"
        fi
    }
    set +e
    b4_normalize_cargo_checkout_pack_hard_links "$CARGO_PAIR_CHECKOUT" "$CARGO_PAIR_GIT" \
        2> "$run_root/rejection.txt"
    observed_status=$?
    set -e
    unset -f mv
    [ "$observed_status" = 1 ]
    grep -F 'normalization left a multiply linked file' \
        "$run_root/rejection.txt" >/dev/null

    run_root=$parent_root/final-enumeration-failure
    setup_cargo_checkout_pack_pair "$run_root"
    b4_diag_init "$run_root/diagnostics" cargo-final-find-run
    FIND_CALL_COUNT=0
    find() {
        FIND_CALL_COUNT=$((FIND_CALL_COUNT + 1))
        if [ "$FIND_CALL_COUNT" = 2 ]; then
            return 72
        fi
        command find "$@"
    }
    set +e
    b4_normalize_cargo_checkout_pack_hard_links "$CARGO_PAIR_CHECKOUT" "$CARGO_PAIR_GIT" \
        2> "$run_root/rejection.txt"
    observed_status=$?
    set -e
    unset -f find
    [ "$observed_status" = 1 ]
    grep -F 'normalization final hardlink enumeration failed' \
        "$run_root/rejection.txt" >/dev/null
}

run_git_checkout_cases() {
    local run_root=$1 clone worktree alternates
    worktree=$run_root/worktree
    clone=$run_root/standalone
    mkdir -p -- "$clone/.git/objects/info" "$worktree"
    printf '%s\n' 'gitdir: ../standalone/.git/worktrees/worktree' > "$worktree/.git"
    git() {
        local repo
        [ "$1" = -C ] || return 2
        repo=$(CDPATH= cd -- "$2" && pwd -P) || return 2
        shift 2
        case "$*" in
            'rev-parse --show-toplevel') printf '%s\n' "$repo" ;;
            'rev-parse --absolute-git-dir') printf '%s\n' "$repo/.git" ;;
            'rev-parse --path-format=absolute --git-common-dir') printf '%s\n' "$repo/.git" ;;
            'rev-parse --path-format=absolute --git-path objects') printf '%s\n' "$repo/.git/objects" ;;
            *) return 2 ;;
        esac
    }

    # shellcheck source=diagnostics.sh
    source "$helper"
    b4_git_assert_standalone_checkout "$clone"

    if b4_git_assert_standalone_checkout "$worktree" 2>/dev/null; then
        printf '%s\n' 'B4 checkout preflight admitted a linked worktree' >&2
        exit 1
    fi

    alternates=$clone/.git/objects/info/alternates
    : > "$alternates"
    if b4_git_assert_standalone_checkout "$clone" 2>/dev/null; then
        printf '%s\n' 'B4 checkout preflight admitted Git alternates metadata' >&2
        exit 1
    fi
    rm -- "$alternates"

    if GIT_INDEX_FILE=forbidden-index b4_git_assert_standalone_checkout "$clone" 2>/dev/null; then
        printf '%s\n' 'B4 checkout preflight admitted a Git environment override' >&2
        exit 1
    fi
    unset -f git
}

run_container_guard_case() {
    run_root=$1
    mkdir -- "$run_root" "$run_root/diagnostics" "$run_root/staging"
    (
        set -euo pipefail
        # shellcheck source=diagnostics.sh
        source "$helper"
        b4_host_container_guard_init
        b4_host_container_guard_before_run eip0045-guard-fixture "$run_root/diagnostics"
        if b4_host_container_guard_mark_removed eip0045-guard-fixture; then
            printf '%s\n' 'container guard allowed removal before inspection' >&2
            exit 1
        fi
        b4_host_container_guard_record_uncertainty post-run-inspection-failed
        b4_host_container_guard_should_preserve
        [ -d "$run_root/staging" ]
        if env | grep -q '^B4_HOST_CONTAINER_'; then
            printf '%s\n' 'host container guard state leaked into the child environment' >&2
            exit 1
        fi
        b4_host_container_guard_mark_inspected eip0045-guard-fixture
        b4_host_container_guard_should_preserve
        b4_host_container_guard_mark_removed eip0045-guard-fixture
        if b4_host_container_guard_should_preserve; then
            printf '%s\n' 'container guard cleared only after inspect plus remove' >&2
            exit 1
        fi
    )
}

run_container_guard_interruption() {
    run_root=$1
    mkdir -- "$run_root" "$run_root/diagnostics" "$run_root/staging"
    set +e
    (
        set -euo pipefail
        # shellcheck source=diagnostics.sh
        source "$helper"
        b4_host_container_guard_init
        interrupted_cleanup() {
            exact_status=$?
            trap - EXIT
            set +e
            if b4_host_container_guard_should_preserve; then
                b4_host_container_guard_record_uncertainty runner-exited-before-removal-confirmed
            else
                mv -- "$run_root/staging" "$run_root/moved"
            fi
            exit "$exact_status"
        }
        trap interrupted_cleanup EXIT
        b4_host_container_guard_before_run eip0045-guard-interrupt "$run_root/diagnostics"
        exit 130
    )
    observed_status=$?
    set -e
    [ "$observed_status" = 130 ] || {
        printf '%s\n' "container guard interruption changed status: $observed_status" >&2
        exit 1
    }
    [ -d "$run_root/staging" ] && [ ! -e "$run_root/moved" ] || {
        printf '%s\n' 'container guard interruption moved an uncertain bind source' >&2
        exit 1
    }
}

run_fault "$test_root/first"
run_fault "$test_root/second"
diff -ru -- "$test_root/first" "$test_root/second"

run_command_substitution_fault "$test_root/substitution-first"
run_command_substitution_fault "$test_root/substitution-second"
diff -ru -- "$test_root/substitution-first" "$test_root/substitution-second"

run_forbidden_path_fault "$test_root/path-first"
run_forbidden_path_fault "$test_root/path-second"
diff -ru -- "$test_root/path-first/diagnostics" "$test_root/path-second/diagnostics"

run_enumeration_fault "$test_root/enumeration-first"
run_enumeration_fault "$test_root/enumeration-second"
diff -ru -- "$test_root/enumeration-first/diagnostics" "$test_root/enumeration-second/diagnostics"

run_special_node_fault "$test_root/special-first"
run_special_node_fault "$test_root/special-second"
diff -ru -- "$test_root/special-first/diagnostics" "$test_root/special-second/diagnostics"

run_special_enumeration_fault "$test_root/special-enumeration-first"
run_special_enumeration_fault "$test_root/special-enumeration-second"
diff -ru -- "$test_root/special-enumeration-first/diagnostics" "$test_root/special-enumeration-second/diagnostics"

run_hard_link_fault "$test_root/hard-link-first"
run_hard_link_fault "$test_root/hard-link-second"
diff -ru -- "$test_root/hard-link-first/diagnostics" "$test_root/hard-link-second/diagnostics"

run_cargo_checkout_hardlink_normalization "$test_root/cargo-hardlink-normalization"
run_cargo_checkout_noop_case "$test_root/cargo-hardlink-noop"
run_cargo_checkout_unexpected_location_cases "$test_root/cargo-hardlink-locations"
run_cargo_checkout_topology_cases "$test_root/cargo-hardlink-topology"
run_cargo_checkout_copy_and_replace_faults "$test_root/cargo-hardlink-faults"

run_git_checkout_cases "$test_root/git-checkout"

run_container_guard_case "$test_root/guard-first"
run_container_guard_case "$test_root/guard-second"
diff -ru -- "$test_root/guard-first/diagnostics" "$test_root/guard-second/diagnostics"

run_container_guard_interruption "$test_root/guard-interruption"
grep -Fx 'schema=eip0045-b4-host-container-presence-v1' "$test_root/guard-first/diagnostics/container-presence-uncertain.txt" >/dev/null
grep -Fx 'state=possible' "$test_root/guard-first/diagnostics/container-presence-uncertain.txt" >/dev/null
grep -Fx 'reason=post-run-inspection-failed' "$test_root/guard-first/diagnostics/container-presence-uncertain.txt" >/dev/null
grep -Fx 'bindSourcesPreserved=true' "$test_root/guard-interruption/diagnostics/container-presence-uncertain.txt" >/dev/null
grep -Fx 'removalConfirmed=false' "$test_root/guard-interruption/diagnostics/container-presence-uncertain.txt" >/dev/null

grep -Fx 'schema=eip0045-b4-diagnostic-phase-v1' "$test_root/first/current-phase.txt" >/dev/null
grep -Fx 'phase=deterministic-fault' "$test_root/first/current-phase.txt" >/dev/null
grep -Fx 'state=current' "$test_root/first/current-phase.txt" >/dev/null
grep -Fx 'phase=bootstrap' "$test_root/first/last-complete-phase.txt" >/dev/null
grep -Fx 'state=complete' "$test_root/first/last-complete-phase.txt" >/dev/null
grep -Fx 'schema=eip0045-b4-diagnostic-failure-v1' "$test_root/first/failure.txt" >/dev/null
grep -Fx 'phase=deterministic-fault' "$test_root/first/failure.txt" >/dev/null
grep -Fx 'kind=unhandled-command' "$test_root/first/failure.txt" >/dev/null
grep -Fx 'exitStatus=37' "$test_root/first/failure.txt" >/dev/null
grep -Fx 'schema=eip0045-b4-diagnostic-exit-v1' "$test_root/first/exit-status.txt" >/dev/null
grep -Fx 'exitStatus=37' "$test_root/first/exit-status.txt" >/dev/null
grep -Fx 'cleanupState=complete' "$test_root/first/exit-status.txt" >/dev/null

grep -Fx 'phase=command-substitution-fault' "$test_root/substitution-first/failure.txt" >/dev/null
grep -Fx 'kind=unhandled-command' "$test_root/substitution-first/failure.txt" >/dev/null
grep -Fx 'exitStatus=37' "$test_root/substitution-first/failure.txt" >/dev/null
grep -Fx 'exitStatus=37' "$test_root/substitution-first/exit-status.txt" >/dev/null

grep -Fx 'phase=path-preflight' "$test_root/path-first/diagnostics/failure.txt" >/dev/null
grep -Fx 'kind=forbidden-path' "$test_root/path-first/diagnostics/failure.txt" >/dev/null
grep -Fx 'exitStatus=91' "$test_root/path-first/diagnostics/failure.txt" >/dev/null
grep -Fx 'exitStatus=91' "$test_root/path-first/diagnostics/exit-status.txt" >/dev/null
[ -f "$test_root/path-first/diagnostics/scan-forbidden-paths.stderr" ] || {
    printf '%s\n' 'CR/LF scan did not retain its stderr channel' >&2
    exit 1
}

grep -Fx 'kind=enumeration-failure' "$test_root/enumeration-first/diagnostics/failure.txt" >/dev/null
grep -Fx 'exitStatus=1' "$test_root/enumeration-first/diagnostics/failure.txt" >/dev/null
grep -Fx 'exitStatus=1' "$test_root/enumeration-first/diagnostics/exit-status.txt" >/dev/null
[ -s "$test_root/enumeration-first/diagnostics/scan-missing-paths.stderr" ] || {
    printf '%s\n' 'enumeration failure did not retain find stderr' >&2
    exit 1
}

grep -Fx 'kind=forbidden-node' "$test_root/special-first/diagnostics/failure.txt" >/dev/null
grep -Fx 'exitStatus=1' "$test_root/special-first/diagnostics/failure.txt" >/dev/null
[ -f "$test_root/special-first/diagnostics/scan-special-nodes.stderr" ] || {
    printf '%s\n' 'special-node scan did not retain its stderr channel' >&2
    exit 1
}

grep -Fx 'kind=enumeration-failure' "$test_root/special-enumeration-first/diagnostics/failure.txt" >/dev/null
grep -Fx 'exitStatus=1' "$test_root/special-enumeration-first/diagnostics/failure.txt" >/dev/null
[ -s "$test_root/special-enumeration-first/diagnostics/scan-special-enumeration.stderr" ] || {
    printf '%s\n' 'special-node enumeration did not retain find stderr' >&2
    exit 1
}

grep -Fx 'kind=forbidden-hard-link' "$test_root/hard-link-first/diagnostics/failure.txt" >/dev/null
grep -Fx 'exitStatus=1' "$test_root/hard-link-first/diagnostics/exit-status.txt" >/dev/null
[ -f "$test_root/hard-link-first/diagnostics/scan-hard-links.stderr" ] || {
    printf '%s\n' 'hard-link scan did not retain its stderr channel' >&2
    exit 1
}

[ ! -e "$test_root/evidence" ] || {
    printf '%s\n' 'fault diagnostics escaped into an evidence directory' >&2
    exit 1
}

printf '%s\n' 'B4 observability fault injection: passed'
