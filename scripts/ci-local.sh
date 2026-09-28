#!/usr/bin/env bash
# Runs the jobs of .github/workflows/ci.yml locally, while GitHub Actions is
# unavailable (docs/plans/phase-1.md, exit criteria 1 and 3). Keep the two in
# sync: a command added to ci.yml is added here.
#
# Usage: scripts/ci-local.sh [target...]
#   macos          fmt, clippy, tests on this Mac (the `macos` job; macOS host only)
#   linux-arm64    fmt, clippy, release build, tests, bench smoke in Docker
#   linux-x86_64   the same under --platform linux/amd64 (emulated on Apple
#                  Silicon: slow, and timing asserts may flake)
#   docker         the `docker` job: builds deploy/docker/Dockerfile for
#                  linux/amd64, as CI does (emulated on Apple Silicon: slow)
#   all            everything above
# No target: macos (on a macOS host) and linux-arm64.
#
# Jobs run one after another (timing tests share the CPU) and continue after
# a failure, like `fail-fast: false`. Only one run at a time (a lock in $TMPDIR). Logs and the summary go to
# target/ci-local/; paste the summary into the phase plan's session log.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/target/ci-local"
TOOLCHAIN="1.83.0"
IMAGE_PREFIX="nexus-ci:$TOOLCHAIN"
CARGO_VOLUME="nexus-ci-cargo"

# The memory budget CI enforces, read from ci.yml so the two cannot drift.
BUDGET_KB="$(sed -n 's/^ *NEXUS_MEM_BUDGET_KB: *"\([0-9]*\)".*/\1/p' "$ROOT/.github/workflows/ci.yml")"
if [ -z "$BUDGET_KB" ]; then
    echo "ci-local: NEXUS_MEM_BUDGET_KB not found in ci.yml" >&2
    exit 2
fi

# One run at a time: runs share target/ci-local and the Docker target volumes
# (named per architecture, so also across checkouts). A second run would mix
# logs and the summary and fight over the volumes (a false FAIL, 2026-09-28).
# mkdir is atomic; the lock holds the owner's pid, and a lock whose owner is
# gone is taken over.
LOCK="${TMPDIR:-/tmp}/nexus-ci-local.lock"
if ! mkdir "$LOCK" 2>/dev/null; then
    owner="$(cat "$LOCK/pid" 2>/dev/null || true)"
    if [ -n "$owner" ] && kill -0 "$owner" 2>/dev/null; then
        echo "ci-local: another run holds $LOCK (pid $owner); wait for it or stop it" >&2
        exit 2
    fi
    echo "ci-local: taking over a stale lock (pid ${owner:-unknown} is gone)" >&2
    rm -rf "$LOCK"
    if ! mkdir "$LOCK" 2>/dev/null; then
        echo "ci-local: lost the race for $LOCK" >&2
        exit 2
    fi
fi
echo $$ >"$LOCK/pid"
trap 'rm -rf "$LOCK"' EXIT

mkdir -p "$OUT"
SUMMARY="$OUT/summary.txt"
: >"$SUMMARY"
FAILED=0

# Test totals from a log: "<passed> passed, <failed> failed".
test_totals() {
    grep -E '^test result:' "$1" |
        awk '{p += $4; f += $6} END {printf "%d passed, %d failed", p, f}'
}

# Runs one step, logging to $OUT/<job>.log; records PASS/FAIL in the summary.
# Usage: step <job> <description> <command...>
step() {
    local job="$1" what="$2"
    shift 2
    local log="$OUT/$job.log" start end status detail=""
    start=$(date +%s)
    echo "== $job: $what"
    echo "== $what" >>"$log"
    "$@" >>"$log" 2>&1
    status=$?
    end=$(date +%s)
    case "$what" in
    *test*) detail=" ($(test_totals "$log"))" ;;
    esac
    if [ $status -eq 0 ]; then
        printf '%-14s PASS  %-44s %5ss%s\n' "$job" "$what" $((end - start)) "$detail" | tee -a "$SUMMARY"
    else
        printf '%-14s FAIL  %-44s %5ss%s  (see %s)\n' "$job" "$what" $((end - start)) "$detail" \
            "${log#"$ROOT"/}" | tee -a "$SUMMARY"
        FAILED=1
    fi
    return $status
}

run_macos() {
    if [ "$(uname -s)" != "Darwin" ]; then
        echo "ci-local: macos needs a macOS host" >&2
        FAILED=1
        return
    fi
    if ! command -v capnp >/dev/null; then
        echo "ci-local: capnp missing (brew install capnp)" >&2
        FAILED=1
        return
    fi
    : >"$OUT/macos.log"
    cd "$ROOT" || return
    step macos "cargo fmt --check" cargo fmt --all --check
    step macos "clippy" cargo clippy --workspace --all-targets --locked -- -D warnings
    # As the `macos` job: raise the open-file limit (256 by default) for the
    # e2e and loopback tests. Not beyond what this shell may raise it to.
    ulimit -n 4096 2>/dev/null || ulimit -n "$(ulimit -Hn)"
    step macos "cargo test --workspace" cargo test --workspace --locked
}

# The Linux image: the pinned toolchain plus the packages ci.yml installs.
linux_image() {
    local platform="$1" image="$2"
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        echo "== building $image"
        docker build --platform "$platform" -t "$image" - >>"$OUT/image.log" 2>&1 <<EOF || return 1
FROM rust:$TOOLCHAIN-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends capnproto \\
    && rm -rf /var/lib/apt/lists/*
RUN rustup component add rustfmt clippy
EOF
    fi
}

# Runs a command in the Linux container on a fresh copy of the working tree
# (uncommitted changes included; target/ and node_modules/ excluded). The
# target directory is a named volume per architecture.
# shellcheck disable=SC2329 # called through `step`
in_linux() {
    local platform="$1" arch="$2"
    shift 2
    docker run --rm --platform "$platform" \
        -v "$ROOT":/src:ro \
        -v "$CARGO_VOLUME":/usr/local/cargo/registry \
        -v "nexus-ci-target-$arch":/work/target \
        -e CARGO_TERM_COLOR=never \
        "$IMAGE_PREFIX-$arch" bash -c "
            set -eo pipefail
            cd /src
            tar --exclude=./target --exclude='*/node_modules' --exclude=./.git -cf - . |
                (cd /work && tar -xf -)
            cd /work
            $*"
}

run_linux() {
    local arch="$1" platform job="linux-$1"
    case "$arch" in
    arm64) platform="linux/arm64" ;;
    x86_64) platform="linux/amd64" ;;
    esac
    if ! command -v docker >/dev/null || ! docker info >/dev/null 2>&1; then
        echo "ci-local: Docker is not running" >&2
        FAILED=1
        return
    fi
    : >"$OUT/$job.log"
    linux_image "$platform" "$IMAGE_PREFIX-$arch" || {
        printf '%-14s FAIL  %-44s        (see target/ci-local/image.log)\n' "$job" "image" |
            tee -a "$SUMMARY"
        FAILED=1
        return
    }
    step "$job" "cargo fmt --check" in_linux "$platform" "$arch" "cargo fmt --all --check"
    step "$job" "clippy" in_linux "$platform" "$arch" \
        "cargo clippy --workspace --all-targets --locked -- -D warnings"
    step "$job" "release build" in_linux "$platform" "$arch" \
        "cargo build --release --locked --bin nexus-sfu"
    step "$job" "cargo test --workspace" in_linux "$platform" "$arch" \
        "cargo test --workspace --locked"
    step "$job" "bench smoke real_path" in_linux "$platform" "$arch" \
        "cargo bench --locked --bench real_path -- --test"
    step "$job" "bench memory (budget ${BUDGET_KB} KB)" in_linux "$platform" "$arch" \
        "NEXUS_MEM_BUDGET_KB=$BUDGET_KB cargo bench --locked --bench memory"
}

run_docker() {
    : >"$OUT/docker.log"
    # linux/amd64, as the `docker` job on ubuntu-latest (emulated on Apple Silicon).
    step docker "docker build (linux/amd64)" \
        docker build --platform linux/amd64 -f "$ROOT/deploy/docker/Dockerfile" "$ROOT"
}

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
    if [ "$(uname -s)" = "Darwin" ]; then targets=(macos linux-arm64); else targets=(linux-arm64); fi
fi
if [ "${targets[0]}" = "all" ]; then
    targets=(macos linux-arm64 linux-x86_64 docker)
fi

for target in "${targets[@]}"; do
    case "$target" in
    macos) run_macos ;;
    linux-arm64) run_linux arm64 ;;
    linux-x86_64) run_linux x86_64 ;;
    docker) run_docker ;;
    *)
        echo "ci-local: unknown target '$target'" >&2
        exit 2
        ;;
    esac
done

# The tree's state: untracked files count too (they are copied into the Linux jobs).
tree_state() {
    local changes
    changes="$(git -C "$ROOT" status --porcelain | wc -l | tr -d ' ')"
    if [ "$changes" -eq 0 ]; then
        echo "clean"
    else
        echo "$changes uncommitted or untracked paths"
    fi
}

{
    echo "--"
    echo "ci-local $(date '+%Y-%m-%d %H:%M'), $(git -C "$ROOT" rev-parse --short HEAD) ($(tree_state)), targets: ${targets[*]}, budget ${BUDGET_KB} KB: $([ $FAILED -eq 0 ] && echo PASS || echo FAIL)"
} | tee -a "$SUMMARY"
exit $FAILED
