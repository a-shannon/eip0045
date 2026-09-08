#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
workspace_root=$repo_root
workspace_candidate=$repo_root
while :; do
    if [ -f "$workspace_candidate/AGENTS.md" ] && [ -d "$workspace_candidate/.agent" ]; then
        workspace_root=$workspace_candidate
        break
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
test_parent=${TMPDIR:-/tmp}
umask 077
test_root=$(mktemp -d "$test_parent/eip0045-run-preflight.XXXXXX")
result_status=0
result_file=
result_counter=0

fail() {
    printf '%s\n' "test failure: $*" >&2
    exit 1
}

cleanup() {
    rm -rf -- "$test_root"
}

trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

next_result_file() {
    result_counter=$((result_counter + 1))
    result_file=$test_root/result-$result_counter.txt
}

invoke_preflight() {
    preflight_target=$1
    preflight_lane=$2
    preflight_minimum=$3
    preflight_cargo_home=${4-__unset__}
    preflight_forbidden_roots=${5-__unset__}
    next_result_file
    set +e
    (
        unset CARGO_HOME EIP0045_TARGET_DIR EIP0045_TARGET_LANE EIP0045_MIN_FREE_GIB
        unset EIP0045_FORBIDDEN_SYNC_ROOTS
        EIP0045_TARGET_DIR=$preflight_target
        EIP0045_TARGET_LANE=$preflight_lane
        EIP0045_MIN_FREE_GIB=$preflight_minimum
        export EIP0045_TARGET_DIR EIP0045_TARGET_LANE EIP0045_MIN_FREE_GIB
        if [ "$preflight_cargo_home" != __unset__ ]; then
            CARGO_HOME=$preflight_cargo_home
            export CARGO_HOME
        fi
        if [ "$preflight_forbidden_roots" != __unset__ ]; then
            EIP0045_FORBIDDEN_SYNC_ROOTS=$preflight_forbidden_roots
            export EIP0045_FORBIDDEN_SYNC_ROOTS
        fi
        sh "$script_dir/run.sh" preflight
    ) >"$result_file" 2>&1
    result_status=$?
    set -e
}

invoke_action() {
    action_name=$1
    shift
    next_result_file
    set +e
    (
        unset CARGO_HOME EIP0045_TARGET_DIR EIP0045_TARGET_LANE EIP0045_MIN_FREE_GIB
        unset EIP0045_FORBIDDEN_SYNC_ROOTS
        PATH=$fake_bin:$PATH
        EIP0045_TARGET_DIR=$action_target_root
        EIP0045_TARGET_LANE=dispatch
        EIP0045_MIN_FREE_GIB=0
        EIP0045_FAKE_CARGO_LOG=$fake_cargo_log
        export PATH EIP0045_TARGET_DIR EIP0045_TARGET_LANE EIP0045_MIN_FREE_GIB
        export EIP0045_FAKE_CARGO_LOG EIP0045_FAKE_CARGO_EXIT
        sh "$script_dir/run.sh" "$action_name" "$@"
    ) >"$result_file" 2>&1
    result_status=$?
    set -e
}

invoke_action_with_relative_cargo_home() {
    relative_invocation_root=$1
    next_result_file
    set +e
    (
        unset CARGO_HOME EIP0045_TARGET_DIR EIP0045_TARGET_LANE EIP0045_MIN_FREE_GIB
        unset EIP0045_FORBIDDEN_SYNC_ROOTS
        cd "$relative_invocation_root"
        PATH=$fake_bin:$PATH
        CARGO_HOME=relative-cargo-home
        EIP0045_TARGET_DIR=$action_target_root
        EIP0045_TARGET_LANE=relative-cargo-home
        EIP0045_MIN_FREE_GIB=0
        EIP0045_FAKE_CARGO_LOG=$fake_cargo_log
        export PATH CARGO_HOME EIP0045_TARGET_DIR EIP0045_TARGET_LANE
        export EIP0045_MIN_FREE_GIB EIP0045_FAKE_CARGO_LOG EIP0045_FAKE_CARGO_EXIT
        sh "$script_dir/run.sh" build
    ) >"$result_file" 2>&1
    result_status=$?
    set -e
}

assert_status() {
    expected_status=$1
    assertion_label=$2
    if [ "$result_status" -ne "$expected_status" ]; then
        printf '%s\n' "$assertion_label returned $result_status, expected $expected_status:" >&2
        sed 's/^/  /' "$result_file" >&2
        exit 1
    fi
}

assert_output_contains() {
    output_needle=$1
    assertion_label=$2
    if ! grep -F -- "$output_needle" "$result_file" >/dev/null 2>&1; then
        printf "%s\n" "$assertion_label did not contain '$output_needle':" >&2
        sed 's/^/  /' "$result_file" >&2
        exit 1
    fi
}

assert_fake_cargo_args() {
    expected_args=$1
    assertion_label=$2
    actual_args=$(sed -n '1p' "$fake_cargo_log")
    if [ "$actual_args" != "$expected_args" ]; then
        fail "$assertion_label dispatched '$actual_args', expected '$expected_args'"
    fi
}

success_root=$test_root/success
invoke_preflight "$success_root" h0-consumer 0
assert_status 0 'successful isolated-lane preflight'
assert_output_contains 'schema=eip0045-local-run-preflight-v1' 'successful preflight'
assert_output_contains 'lane=h0-consumer' 'successful preflight'
assert_output_contains "targetDir=$success_root/h0-consumer" 'successful preflight'
if [ -e "$success_root/h0-consumer/.eip0045-run.lock" ]; then
    fail 'successful preflight did not clean its lane lock'
fi

empty_lane_root=$test_root/empty-lane
invoke_preflight "$empty_lane_root" '' 0
assert_status 0 'empty-lane compatibility preflight'
assert_output_contains 'lane=shared' 'empty-lane compatibility preflight'
assert_output_contains "targetDir=$empty_lane_root" 'empty-lane compatibility preflight'

invoke_preflight "$repo_root/.preflight-test-target" inside 0
assert_status 1 'in-repository target rejection'
assert_output_contains 'target directory overlaps the synchronized repository or workspace' 'in-repository target rejection'

invoke_preflight "$workspace_root/.preflight-test-target" workspace 0
assert_status 1 'synchronized-workspace target rejection'
assert_output_contains 'target directory overlaps the synchronized repository or workspace' 'synchronized-workspace target rejection'

ln -s "$repo_root" "$test_root/repo-link"
invoke_preflight "$test_root/repo-link/target" symlink 0
assert_status 1 'symlinked in-repository target rejection'
assert_output_contains 'target directory overlaps the synchronized repository or workspace' 'symlinked in-repository target rejection'

invoke_preflight "$test_root/cargo-home-target" cargo-home 0 "$workspace_root/.cargo-preflight-test"
assert_status 1 'synchronized-workspace CARGO_HOME rejection'
assert_output_contains 'CARGO_HOME overlaps the synchronized repository or workspace' 'synchronized-workspace CARGO_HOME rejection'

declared_sync_root=$test_root/declared-sync-root
mkdir -p "$declared_sync_root"
invoke_preflight "$declared_sync_root/target" declared-sync 0 __unset__ "$declared_sync_root"
assert_status 1 'declared synchronized-root rejection'
assert_output_contains 'target directory overlaps the synchronized repository or workspace' 'declared synchronized-root rejection'

invoke_preflight "$test_root/invalid-lane" Invalid 0
assert_status 1 'invalid lane rejection'
assert_output_contains 'EIP0045_TARGET_LANE must be empty or match' 'invalid lane rejection'

invoke_preflight "$test_root/invalid-minimum" valid not-a-number
assert_status 1 'invalid minimum rejection'
assert_output_contains 'EIP0045_MIN_FREE_GIB must be a non-negative integer' 'invalid minimum rejection'

invoke_preflight "$test_root/low-capacity" capacity 1048576
assert_status 1 'capacity rejection'
assert_output_contains 'free space is below the configured minimum' 'capacity rejection'

lock_root=$test_root/lock
mkdir -p "$lock_root/same-lane/.eip0045-run.lock"
invoke_preflight "$lock_root" other-lane 0
assert_status 0 'distinct-lane parallel preflight'
assert_output_contains 'lane=other-lane' 'distinct-lane parallel preflight'
invoke_preflight "$lock_root" same-lane 0
assert_status 1 'same-lane contention rejection'
assert_output_contains 'target lane is already in use' 'same-lane contention rejection'

fake_bin=$test_root/fake-bin
fake_cargo_log=$test_root/fake-cargo.log
action_target_root=$test_root/actions
EIP0045_FAKE_CARGO_EXIT=0
mkdir "$fake_bin"
printf '%s\n' \
    '#!/usr/bin/env sh' \
    'printf "%s\n" "$*" > "$EIP0045_FAKE_CARGO_LOG"' \
    'printf "cargo_home=%s\n" "${CARGO_HOME-}" >> "$EIP0045_FAKE_CARGO_LOG"' \
    'exit "${EIP0045_FAKE_CARGO_EXIT:-0}"' \
    >"$fake_bin/cargo"
chmod +x "$fake_bin/cargo"

relative_invocation_root=$test_root/relative-invocation
mkdir "$relative_invocation_root"
invoke_action_with_relative_cargo_home "$relative_invocation_root"
assert_status 0 'relative CARGO_HOME dispatch'
relative_cargo_home=$(sed -n '2s/^cargo_home=//p' "$fake_cargo_log")
expected_cargo_home=$relative_invocation_root/relative-cargo-home
if [ "$relative_cargo_home" != "$expected_cargo_home" ]; then
    fail "relative CARGO_HOME dispatch used '$relative_cargo_home', expected '$expected_cargo_home'"
fi

invoke_action build --release
assert_status 0 'build dispatch'
assert_fake_cargo_args '+1.89.0 build --workspace --locked --release' 'build dispatch'

invoke_action test --lib
assert_status 0 'test dispatch'
assert_fake_cargo_args '+1.89.0 test --workspace --locked --lib' 'test dispatch'

invoke_action clippy
assert_status 0 'clippy dispatch'
assert_fake_cargo_args '+1.89.0 clippy --workspace --all-targets --locked -- -D warnings' 'clippy dispatch'

invoke_action verify-invariants --fixture sample
assert_status 0 'verify-invariants dispatch'
assert_fake_cargo_args '+1.89.0 run -p eip-0045-reproduction --locked -- verify-invariants --fixture sample' 'verify-invariants dispatch'

invoke_action preflight-proof-output proof.bin
assert_status 0 'preflight-proof-output dispatch'
assert_fake_cargo_args '+1.89.0 run -p eip-0045-reproduction --locked -- preflight-proof-output proof.bin' 'preflight-proof-output dispatch'

invoke_action manifest-proof-output proof.bin
assert_status 0 'manifest-proof-output dispatch'
assert_fake_cargo_args '+1.89.0 run -p eip-0045-reproduction --locked -- manifest-proof-output proof.bin' 'manifest-proof-output dispatch'

invoke_action guard-candidate candidate.bin
assert_status 0 'guard-candidate dispatch'
assert_fake_cargo_args "+1.89.0 run -p eip-0045-reproduction --locked -- guard-candidate --repo-root $repo_root candidate.bin" 'guard-candidate dispatch'

EIP0045_FAKE_CARGO_EXIT=7
invoke_action build
assert_status 7 'failing Cargo dispatch'
if [ -e "$action_target_root/dispatch/.eip0045-run.lock" ]; then
    fail 'failing Cargo dispatch did not clean its lane lock'
fi

printf '%s\n' 'eip0045 Unix run preflight tests: 21 passed'
