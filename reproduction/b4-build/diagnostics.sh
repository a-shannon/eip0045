#!/bin/bash
# Sourced by the pinned B4 container body and the Bash host wrapper. Container
# diagnostics stay under /work; host diagnostics stay under the private work
# root. Neither is admissible archive evidence.

b4_diag_validate_token() {
    case ${1-} in ''|*[!a-z0-9-]*) return 1 ;; esac
}

b4_diag_validate_status() {
    case ${1-} in ''|*[!0-9]*) return 1 ;; esac
    [ "$1" -le 255 ]
}

b4_diag_require_single_link_file() {
    local path=$1 links
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    links=$(stat -c %h -- "$path") || return 1
    [ "$links" = 1 ]
}

b4_git_reject_environment_overrides() {
    local name
    for name in \
        GIT_DIR \
        GIT_WORK_TREE \
        GIT_COMMON_DIR \
        GIT_OBJECT_DIRECTORY \
        GIT_ALTERNATE_OBJECT_DIRECTORIES \
        GIT_INDEX_FILE
    do
        if [[ -v $name ]]; then
            printf '%s\n' "B4 Git checkout validation forbids inherited $name" >&2
            return 1
        fi
    done
}

b4_git_assert_standalone_checkout() {
    local repo=$1 canonical_repo git_root expected_git top_level absolute_git common_git objects candidate
    b4_git_reject_environment_overrides || return 1
    command -v git >/dev/null 2>&1 || {
        printf '%s\n' 'git is required to validate standalone B4 checkouts' >&2
        return 1
    }
    [ -d "$repo" ] && [ ! -L "$repo" ] || {
        printf '%s\n' "B4 repository root is not a plain directory: $repo" >&2
        return 1
    }
    canonical_repo=$(CDPATH= cd -- "$repo" && pwd -P) || return 1
    [ -d "$canonical_repo/.git" ] && [ ! -L "$canonical_repo/.git" ] || {
        printf '%s\n' "B4 requires a standalone .git directory, not a worktree or alias: $canonical_repo/.git" >&2
        return 1
    }
    expected_git=$(CDPATH= cd -- "$canonical_repo/.git" && pwd -P) || return 1

    top_level=$(git -C "$canonical_repo" rev-parse --show-toplevel) || return 1
    absolute_git=$(git -C "$canonical_repo" rev-parse --absolute-git-dir) || return 1
    common_git=$(git -C "$canonical_repo" rev-parse --path-format=absolute --git-common-dir) || return 1
    objects=$(git -C "$canonical_repo" rev-parse --path-format=absolute --git-path objects) || return 1
    git_root=$(CDPATH= cd -- "$absolute_git" && pwd -P) || return 1

    [ "$top_level" = "$canonical_repo" ] || {
        printf '%s\n' "B4 checkout work-tree root is not private to the checkout: $top_level" >&2
        return 1
    }
    [ "$git_root" = "$expected_git" ] || {
        printf '%s\n' "B4 checkout administration root is not private to the checkout: $git_root" >&2
        return 1
    }
    [ "$common_git" = "$expected_git" ] || {
        printf '%s\n' "B4 checkout common root is not private to the checkout: $common_git" >&2
        return 1
    }
    [ "$objects" = "$expected_git/objects" ] || {
        printf '%s\n' "B4 checkout object root is not private to the checkout: $objects" >&2
        return 1
    }

    for candidate in \
        "$expected_git/objects/info/alternates" \
        "$expected_git/objects/info/http-alternates"
    do
        if [ -e "$candidate" ] || [ -L "$candidate" ]; then
            printf '%s\n' "B4 checkout contains forbidden Git object alternates metadata: $candidate" >&2
            return 1
        fi
    done
}

b4_host_container_guard_init() {
    [ -z ${B4_HOST_CONTAINER_STATE+x} ] || return 1
    B4_HOST_CONTAINER_STATE=idle
    B4_HOST_CONTAINER_NAME=''
    B4_HOST_CONTAINER_DIAGNOSTIC_ROOT=''
    B4_HOST_CONTAINER_BIND_SOURCES_MUST_REMAIN=0
}

b4_host_container_guard_before_run() {
    local container_name=$1 diagnostic_root=$2
    case ${B4_HOST_CONTAINER_STATE-} in idle|removed) ;; *) return 1 ;; esac
    b4_diag_validate_token $container_name || return 1
    [ -d $diagnostic_root ] && [ ! -L $diagnostic_root ] || return 1
    B4_HOST_CONTAINER_STATE=possible
    B4_HOST_CONTAINER_NAME=$container_name
    B4_HOST_CONTAINER_DIAGNOSTIC_ROOT=$diagnostic_root
    B4_HOST_CONTAINER_BIND_SOURCES_MUST_REMAIN=1
}

b4_host_container_guard_mark_inspected() {
    local container_name=$1
    [ ${B4_HOST_CONTAINER_STATE-} = possible ] || return 1
    [ ${B4_HOST_CONTAINER_NAME-} = $container_name ] || return 1
    B4_HOST_CONTAINER_STATE=observed
}

b4_host_container_guard_mark_removed() {
    local container_name=$1
    [ ${B4_HOST_CONTAINER_STATE-} = observed ] || return 1
    [ ${B4_HOST_CONTAINER_NAME-} = $container_name ] || return 1
    B4_HOST_CONTAINER_STATE=removed
    B4_HOST_CONTAINER_BIND_SOURCES_MUST_REMAIN=0
}

b4_host_container_guard_should_preserve() {
    [ ${B4_HOST_CONTAINER_BIND_SOURCES_MUST_REMAIN-0} = 1 ]
}

b4_host_container_guard_record_uncertainty() {
    local reason=$1 root temporary final
    b4_diag_validate_token $reason || return 1
    b4_host_container_guard_should_preserve || return 0
    case ${B4_HOST_CONTAINER_STATE-} in possible|observed) ;; *) return 1 ;; esac
    root=${B4_HOST_CONTAINER_DIAGNOSTIC_ROOT-}
    [ -d $root ] && [ ! -L $root ] || return 1
    final=$root/container-presence-uncertain.txt
    if [ -e $final ] || [ -L $final ]; then
        b4_diag_require_single_link_file "$final"
        return
    fi
    temporary=$root/.container-presence-uncertain.$$.tmp
    (
        umask 077
        printf '%s\n' \
            'schema=eip0045-b4-host-container-presence-v1' \
            containerName=$B4_HOST_CONTAINER_NAME \
            state=$B4_HOST_CONTAINER_STATE \
            reason=$reason \
            'bindSourcesPreserved=true' \
            'removalConfirmed=false' > $temporary
    ) || return 1
    if ln -- $temporary $final 2>/dev/null; then
        rm -f -- $temporary
        return 0
    fi
    rm -f -- $temporary
    b4_diag_require_single_link_file "$final"
}

b4_diag_escape() {
    local value=${1-}
    value=${value//'%'/'%25'}
    value=${value//$'\r'/'%0D'}
    value=${value//$'\n'/'%0A'}
    printf '%s' "$value"
}

b4_diag_write_lines() {
    local file_name=$1
    shift
    local temporary="$B4_DIAG_ROOT/.${file_name}.tmp"
    : > "$temporary" || return 1
    local line
    for line in "$@"; do
        printf '%s\n' "$line" >> "$temporary" || return 1
    done
    chmod a+rw -- "$temporary" 2>/dev/null || true
    mv -f -- "$temporary" "$B4_DIAG_ROOT/$file_name"
}

b4_diag_write_phase() {
    local file_name=$1 phase=$2 state=$3
    b4_diag_write_lines "$file_name" \
        'schema=eip0045-b4-diagnostic-phase-v1' \
        "runLabel=$B4_DIAG_RUN_LABEL" \
        "phase=$phase" \
        "state=$state"
}

b4_diag_init() {
    local root=$1 run_label=$2
    case $root in /*) ;; *) return 1 ;; esac
    b4_diag_validate_token "$run_label" || return 1
    [ ! -e "$root" ] || return 1
    mkdir -- "$root" || return 1
    chmod a+rwx -- "$root" 2>/dev/null || true
    B4_DIAG_ROOT=$root
    B4_DIAG_RUN_LABEL=$run_label
    B4_DIAG_PHASE=bootstrap
    B4_DIAG_LAST_COMPLETE=none
    b4_diag_write_phase current-phase.txt "$B4_DIAG_PHASE" current
    b4_diag_write_phase last-complete-phase.txt "$B4_DIAG_LAST_COMPLETE" complete
}

b4_diag_set_phase() {
    local phase=$1
    b4_diag_validate_token "$phase" || return 1
    B4_DIAG_PHASE=$phase
    b4_diag_write_phase current-phase.txt "$phase" current
}

b4_diag_mark_complete() {
    local phase=$1
    b4_diag_validate_token "$phase" || return 1
    [ "$phase" = "$B4_DIAG_PHASE" ] || return 1
    B4_DIAG_LAST_COMPLETE=$phase
    b4_diag_write_phase last-complete-phase.txt "$phase" complete
}

b4_diag_record_failure() {
    local status=$1 line_number=$2 kind=$3 command_text=${4-} message=${5-}
    b4_diag_validate_status "$status" || return 1
    case $line_number in ''|*[!0-9]*) return 1 ;; esac
    b4_diag_validate_token "$kind" || return 1
    [ ! -e "$B4_DIAG_ROOT/failure.txt" ] || return 0
    local command_escaped message_escaped
    command_escaped=$(b4_diag_escape "$command_text") || return 1
    message_escaped=$(b4_diag_escape "$message") || return 1
    b4_diag_write_lines failure.txt \
        'schema=eip0045-b4-diagnostic-failure-v1' \
        "runLabel=$B4_DIAG_RUN_LABEL" \
        "phase=$B4_DIAG_PHASE" \
        "lastCompletePhase=$B4_DIAG_LAST_COMPLETE" \
        "kind=$kind" \
        "exitStatus=$status" \
        "line=$line_number" \
        "commandEscaped=$command_escaped" \
        "messageEscaped=$message_escaped"
}

b4_diag_on_err() {
    local status=$1 line_number=$2 command_text=$3
    b4_diag_record_failure "$status" "$line_number" unhandled-command "$command_text" '' || true
    return "$status"
}

b4_diag_write_exit_state() {
    local status=$1 cleanup_state=$2
    b4_diag_validate_status "$status" || return 1
    case $cleanup_state in started|complete) ;; *) return 1 ;; esac
    b4_diag_write_lines exit-status.txt \
        'schema=eip0045-b4-diagnostic-exit-v1' \
        "runLabel=$B4_DIAG_RUN_LABEL" \
        "phase=$B4_DIAG_PHASE" \
        "lastCompletePhase=$B4_DIAG_LAST_COMPLETE" \
        "exitStatus=$status" \
        "cleanupState=$cleanup_state"
}

b4_diag_reject_special_nodes() {
    local scan_label=$1 line_number=$2
    shift 2
    b4_diag_validate_token "$scan_label" || return 1
    case $line_number in ''|*[!0-9]*) return 1 ;; esac
    local stderr_temporary="$B4_DIAG_ROOT/.scan-$scan_label.stderr.tmp"
    local stderr_final="$B4_DIAG_ROOT/scan-$scan_label.stderr"
    local offender scan_status
    B4_DIAG_SCAN_KIND=''
    B4_DIAG_SCAN_MESSAGE=''

    if offender=$(find "$@" -xdev \( -type l -o -type b -o -type c -o -type p -o -type s \) -print -quit 2> "$stderr_temporary"); then
        scan_status=0
    else
        scan_status=$?
    fi
    if [ "$scan_status" -ne 0 ]; then
        chmod a+rw -- "$stderr_temporary" 2>/dev/null || true
        mv -f -- "$stderr_temporary" "$stderr_final" || return 1
        B4_DIAG_SCAN_KIND=enumeration-failure
        B4_DIAG_SCAN_MESSAGE="special-node enumeration failed for $scan_label with status $scan_status; stderr retained in work-root diagnostics"
        b4_diag_record_failure "$scan_status" "$line_number" "$B4_DIAG_SCAN_KIND" find "$B4_DIAG_SCAN_MESSAGE" || true
        return "$scan_status"
    fi
    if [ -n "$offender" ]; then
        chmod a+rw -- "$stderr_temporary" 2>/dev/null || true
        mv -f -- "$stderr_temporary" "$stderr_final" || return 1
        B4_DIAG_SCAN_KIND=forbidden-node
        B4_DIAG_SCAN_MESSAGE="symlink or special node is not admitted for $scan_label: $offender"
        b4_diag_record_failure 1 "$line_number" "$B4_DIAG_SCAN_KIND" find "$B4_DIAG_SCAN_MESSAGE" || true
        return 1
    fi
    rm -f -- "$stderr_temporary"
    return 0
}

b4_diag_reject_hard_links() {
    local scan_label=$1 line_number=$2
    shift 2
    b4_diag_validate_token "$scan_label" || return 1
    case $line_number in ''|*[!0-9]*) return 1 ;; esac
    local stderr_temporary="$B4_DIAG_ROOT/.scan-$scan_label.stderr.tmp"
    local stderr_final="$B4_DIAG_ROOT/scan-$scan_label.stderr"
    local offender scan_status
    B4_DIAG_SCAN_KIND=''
    B4_DIAG_SCAN_MESSAGE=''

    if offender=$(find "$@" -xdev -type f -links +1 -print -quit 2> "$stderr_temporary"); then
        scan_status=0
    else
        scan_status=$?
    fi
    if [ "$scan_status" -ne 0 ]; then
        chmod a+rw -- "$stderr_temporary" 2>/dev/null || true
        mv -f -- "$stderr_temporary" "$stderr_final" || return 1
        B4_DIAG_SCAN_KIND=enumeration-failure
        B4_DIAG_SCAN_MESSAGE="hard-link enumeration failed for $scan_label with status $scan_status; stderr retained in work-root diagnostics"
        b4_diag_record_failure "$scan_status" "$line_number" "$B4_DIAG_SCAN_KIND" find "$B4_DIAG_SCAN_MESSAGE" || true
        return "$scan_status"
    fi
    if [ -n "$offender" ]; then
        chmod a+rw -- "$stderr_temporary" 2>/dev/null || true
        mv -f -- "$stderr_temporary" "$stderr_final" || return 1
        B4_DIAG_SCAN_KIND=forbidden-hard-link
        B4_DIAG_SCAN_MESSAGE="multiply linked file is not admitted for $scan_label: $offender"
        b4_diag_record_failure 1 "$line_number" "$B4_DIAG_SCAN_KIND" find "$B4_DIAG_SCAN_MESSAGE" || true
        return 1
    fi
    rm -f -- "$stderr_temporary"
    return 0
}

b4_normalize_cargo_checkout_pack_hard_links() {
    local checkout_root=${1-} cargo_git_root=${2-}
    local checkout_prefix relative repository_id checkout_id database_root directory list
    local checkout_pack_root database_pack_root unsorted sorted
    local path basename stem extension counterpart links path_identity counterpart_identity
    local count=0 pack_count=0 index_count=0 observed_stem='' validation_error=''

    case $checkout_root in /*) ;; *) return 1 ;; esac
    case $cargo_git_root in /*) ;; *) return 1 ;; esac
    [ -d "$checkout_root" ] && [ ! -L "$checkout_root" ] || return 1
    [ -d "$cargo_git_root" ] && [ ! -L "$cargo_git_root" ] || return 1
    [ -d "${B4_DIAG_ROOT-}" ] && [ ! -L "${B4_DIAG_ROOT-}" ] || return 1

    checkout_prefix=$cargo_git_root/checkouts/
    case $checkout_root in "$checkout_prefix"*) ;; *) return 1 ;; esac
    relative=${checkout_root#"$checkout_prefix"}
    case $relative in */*) ;; *) return 1 ;; esac
    repository_id=${relative%%/*}
    checkout_id=${relative#*/}
    case $repository_id in ''|*/*) return 1 ;; esac
    case $checkout_id in ''|*/*) return 1 ;; esac
    [ "$checkout_root" = "$checkout_prefix$repository_id/$checkout_id" ] || return 1

    database_root=$cargo_git_root/db/$repository_id
    checkout_pack_root=$checkout_root/.git/objects/pack
    database_pack_root=$database_root/objects/pack
    for directory in "$checkout_pack_root" "$database_pack_root"; do
        [ -d "$directory" ] && [ ! -L "$directory" ] || return 1
    done

    unsorted=$B4_DIAG_ROOT/.cargo-checkout-hardlinks.unsorted.tmp
    sorted=$B4_DIAG_ROOT/.cargo-checkout-hardlinks.sorted.tmp
    for list in "$unsorted" "$sorted"; do
        [ ! -e "$list" ] && [ ! -L "$list" ] || return 1
    done
    if ! find "$checkout_root" -xdev -type f -links +1 -print0 > "$unsorted"; then
        rm -f -- "$unsorted" "$sorted"
        return 1
    fi
    if ! LC_ALL=C sort -z "$unsorted" > "$sorted"; then
        rm -f -- "$unsorted" "$sorted"
        return 1
    fi

    while IFS= read -r -d '' path; do
        count=$((count + 1))
        case $path in
            "$checkout_pack_root"/*) ;;
            *)
                validation_error="unexpected checkout hardlink: $path"
                break
                ;;
        esac
        case ${path#"$checkout_pack_root"/} in
            */*)
                validation_error="Cargo pack hardlink is not directly below the pack directory: $path"
                break
                ;;
        esac
        basename=${path##*/}
        if [[ $basename =~ ^(pack-[0-9a-f]{40})\.(pack|idx)$ ]]; then
            stem=${BASH_REMATCH[1]}
            extension=${BASH_REMATCH[2]}
        else
            validation_error="unexpected Cargo pack filename: $basename"
            break
        fi
        if [ -z "$observed_stem" ]; then
            observed_stem=$stem
        elif [ "$observed_stem" != "$stem" ]; then
            validation_error='Cargo checkout pack and index stems differ'
            break
        fi
        case $extension in
            pack) pack_count=$((pack_count + 1)) ;;
            idx) index_count=$((index_count + 1)) ;;
            *) validation_error="unexpected Cargo pack extension: $extension"; break ;;
        esac

        counterpart=$database_pack_root/$basename
        if [ ! -f "$path" ] || [ -L "$path" ] || [ ! -f "$counterpart" ] || [ -L "$counterpart" ]; then
            validation_error="Cargo pack hardlink lacks a physical database counterpart: $basename"
            break
        fi
        links=$(stat -c %h -- "$path") || {
            validation_error="cannot inspect Cargo checkout pack link count: $basename"
            break
        }
        if [ "$links" != 2 ] || [ "$(stat -c %h -- "$counterpart")" != 2 ]; then
            validation_error="Cargo pack hardlink count is not exactly two: $basename"
            break
        fi
        path_identity=$(stat -c '%d:%i' -- "$path") || {
            validation_error="cannot inspect Cargo checkout pack identity: $basename"
            break
        }
        counterpart_identity=$(stat -c '%d:%i' -- "$counterpart") || {
            validation_error="cannot inspect Cargo database pack identity: $basename"
            break
        }
        if [ "$path_identity" != "$counterpart_identity" ]; then
            validation_error="Cargo checkout pack is linked to an unexpected inode: $basename"
            break
        fi
    done < "$sorted"

    if [ -z "$validation_error" ] && [ "$count" -ne 0 ]; then
        if [ "$count" -ne 2 ] || [ "$pack_count" -ne 1 ] || [ "$index_count" -ne 1 ]; then
            validation_error='Cargo checkout hardlinks are not exactly one matching pack/index pair'
        fi
    fi
    if [ -n "$validation_error" ]; then
        printf '%s\n' "B4 Cargo checkout normalization rejected input: $validation_error" >&2
        rm -f -- "$unsorted" "$sorted"
        return 1
    fi
    if [ "$count" -eq 0 ]; then
        rm -f -- "$unsorted" "$sorted"
        return 0
    fi

    while IFS= read -r -d '' path; do
        local temporary before_mode before_size before_identity after_identity
        basename=${path##*/}
        counterpart=$database_pack_root/$basename
        temporary=$path.eip0045-single-link.tmp
        [ ! -e "$temporary" ] && [ ! -L "$temporary" ] || {
            printf '%s\n' "B4 Cargo checkout normalization temporary path exists: $basename" >&2
            rm -f -- "$unsorted" "$sorted"
            return 1
        }
        before_mode=$(stat -c %a -- "$path") || return 1
        before_size=$(stat -c %s -- "$path") || return 1
        before_identity=$(stat -c '%d:%i' -- "$path") || return 1
        if ! cp --reflink=never --preserve=mode,timestamps -- "$path" "$temporary"; then
            printf '%s\n' "B4 Cargo checkout normalization copy failed: $basename" >&2
            rm -f -- "$temporary" "$unsorted" "$sorted"
            return 1
        fi
        if [ ! -f "$temporary" ] || [ -L "$temporary" ] || \
            [ "$(stat -c %h -- "$temporary")" != 1 ] || \
            [ "$(stat -c %a -- "$temporary")" != "$before_mode" ] || \
            [ "$(stat -c %s -- "$temporary")" != "$before_size" ] || \
            ! cmp -s -- "$path" "$temporary"
        then
            printf '%s\n' "B4 Cargo checkout normalization copy changed pack bytes or metadata: $basename" >&2
            rm -f -- "$temporary" "$unsorted" "$sorted"
            return 1
        fi
        if ! mv -f -- "$temporary" "$path"; then
            rm -f -- "$temporary" "$unsorted" "$sorted"
            return 1
        fi
        after_identity=$(stat -c '%d:%i' -- "$path") || return 1
        if [ "$after_identity" = "$before_identity" ] || \
            [ "$after_identity" = "$(stat -c '%d:%i' -- "$counterpart")" ] || \
            [ "$(stat -c %h -- "$path")" != 1 ] || \
            [ "$(stat -c %h -- "$counterpart")" != 1 ] || \
            [ "$(stat -c %a -- "$path")" != "$before_mode" ] || \
            [ "$(stat -c %s -- "$path")" != "$before_size" ] || \
            ! cmp -s -- "$path" "$counterpart"
        then
            printf '%s\n' "B4 Cargo checkout normalization did not isolate pack bytes: $basename" >&2
            rm -f -- "$unsorted" "$sorted"
            return 1
        fi
    done < "$sorted"

    : > "$unsorted" || {
        rm -f -- "$unsorted" "$sorted"
        return 1
    }
    if ! find "$checkout_root" -xdev -type f -links +1 -print0 > "$unsorted"; then
        printf '%s\n' 'B4 Cargo checkout normalization final hardlink enumeration failed' >&2
        rm -f -- "$unsorted" "$sorted"
        return 1
    fi
    if [ -s "$unsorted" ]; then
        printf '%s\n' 'B4 Cargo checkout normalization left a multiply linked file' >&2
        rm -f -- "$unsorted" "$sorted"
        return 1
    fi
    rm -f -- "$unsorted" "$sorted"
    return 0
}

b4_diag_reject_crlf_paths() {
    local scan_label=$1 root=$2 line_number=$3
    b4_diag_validate_token "$scan_label" || return 1
    case $line_number in ''|*[!0-9]*) return 1 ;; esac
    local stderr_file="$B4_DIAG_ROOT/scan-$scan_label.stderr"
    [ ! -e "$stderr_file" ] || return 1
    : > "$stderr_file" || return 1
    chmod a+rw -- "$stderr_file" 2>/dev/null || true

    local scan_status
    if (
        set -o pipefail
        find "$root" -xdev -print0 |
            while IFS= read -r -d '' path; do
                case $path in
                    *$'\r'*|*$'\n'*) exit 91 ;;
                esac
            done
    ) 2> "$stderr_file"; then
        rm -f -- "$stderr_file"
        return 0
    else
        scan_status=$?
    fi

    if [ "$scan_status" = 91 ]; then
        b4_diag_record_failure "$scan_status" "$line_number" forbidden-path find \
            "path containing CR or LF is not admitted for $scan_label" || true
    else
        b4_diag_record_failure "$scan_status" "$line_number" enumeration-failure find \
            "path enumeration failed for $scan_label with status $scan_status; stderr retained in work-root diagnostics" || true
    fi
    return "$scan_status"
}
