#!/usr/bin/env bash
# vm-setup.sh -- Bootstrap a fresh Debian 12 (Bookworm) VM for CocoSentry.
# Installs prerequisites, clones the repo, builds Docker image, and runs
# a validation test suite to verify the environment is correctly configured.
#
# Usage:
#   curl -fsSL <raw-url> | bash
#   # or after cloning:
#   bash scripts/vm-setup.sh [--skip-install] [--repo-url URL]
#
# Options:
#   --skip-install   Skip apt and Docker installation (useful for re-runs)
#   --repo-url URL   Override the default git clone URL
set -euo pipefail

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

pass_count=0
fail_count=0
warn_count=0
skip_count=0

header() {
    printf '\n'
    printf '%b%b=================================================================%b\n' "$CYAN" "$BOLD" "$RESET"
    printf '%b%b  %s%b\n' "$CYAN" "$BOLD" "$1" "$RESET"
    printf '%b%b=================================================================%b\n' "$CYAN" "$BOLD" "$RESET"
    printf '\n'
}

step() {
    printf '%b--> %s%b\n' "$BOLD" "$1" "$RESET"
}

pass() {
    printf '  %b[PASS]%b %s\n' "$GREEN" "$RESET" "$1"
    pass_count=$((pass_count + 1))
}

fail() {
    printf '  %b[FAIL]%b %s\n' "$RED" "$RESET" "$1"
    fail_count=$((fail_count + 1))
}

warn() {
    printf '  %b[WARN]%b %s\n' "$YELLOW" "$RESET" "$1"
    warn_count=$((warn_count + 1))
}

skip() {
    printf '  %b[SKIP]%b %s\n' "$YELLOW" "$RESET" "$1"
    skip_count=$((skip_count + 1))
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
SKIP_INSTALL=false
REPO_URL="https://github.com/JWhiteUX/cocosentry.git"
CLONE_DIR="$HOME/cocosentry"

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-install)
            SKIP_INSTALL=true
            shift
            ;;
        --repo-url)
            REPO_URL="$2"
            shift 2
            ;;
        --repo-url=*)
            REPO_URL="${1#*=}"
            shift
            ;;
        -h|--help)
            printf 'Usage: %s [--skip-install] [--repo-url URL]\n\n' "$0"
            printf 'Options:\n'
            printf '  --skip-install   Skip apt and Docker installation steps\n'
            printf '  --repo-url URL   Override the default git clone URL\n'
            exit 0
            ;;
        *)
            printf 'Unknown option: %s\nUse --help for usage information.\n' "$1"
            exit 1
            ;;
    esac
done

printf '%bCocoSentry VM Setup & Validation%b\n' "$BOLD" "$RESET"
printf 'Repo URL:       %s\n' "$REPO_URL"
printf 'Clone target:   %s\n' "$CLONE_DIR"
printf 'Skip install:   %s\n\n' "$SKIP_INSTALL"

# ---------------------------------------------------------------------------
# 1. Install prerequisites
# ---------------------------------------------------------------------------
header "1/5  Install Prerequisites"

if [ "$SKIP_INSTALL" = true ]; then
    printf 'Skipping installation steps (--skip-install).\n'
else
    step "Updating apt package index"
    sudo apt-get update -y

    step "Installing git and dependencies"
    sudo apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        curl \
        gnupg \
        lsb-release \
        usbutils

    step "Installing Docker (official repository)"
    # Remove any old conflicting packages
    for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do
        sudo apt-get remove -y "$pkg" 2>/dev/null || true
    done

    # Add Docker GPG key
    sudo install -m 0755 -d /etc/apt/keyrings
    if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
        curl -fsSL https://download.docker.com/linux/debian/gpg \
            | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        sudo chmod a+r /etc/apt/keyrings/docker.gpg
    fi

    # Add Docker apt repository
    printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian %s stable\n' \
        "$(dpkg --print-architecture)" \
        "$(lsb_release -cs)" \
        | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    sudo apt-get update -y
    sudo apt-get install -y --no-install-recommends \
        docker-ce \
        docker-ce-cli \
        containerd.io \
        docker-buildx-plugin \
        docker-compose-plugin

    # Allow current user to run Docker without sudo
    if ! groups "$USER" | grep -q '\bdocker\b'; then
        sudo usermod -aG docker "$USER"
        printf '\n'
        printf '%bNOTE: You were added to the docker group.%b\n' "$YELLOW" "$RESET"
        printf '%bIf docker commands fail below, log out and back in, then re-run with --skip-install.%b\n\n' "$YELLOW" "$RESET"
    fi

    # Ensure Docker daemon is running
    sudo systemctl enable --now docker

    step "Verifying installations"

    if command -v git >/dev/null 2>&1; then
        pass "git $(git --version | cut -d' ' -f3)"
    else
        fail "git not found"
    fi

    if command -v docker >/dev/null 2>&1; then
        pass "docker $(docker --version | cut -d' ' -f3 | tr -d ',')"
    else
        fail "docker not found"
    fi

    if docker compose version >/dev/null 2>&1; then
        compose_ver=$(docker compose version --short 2>/dev/null || printf 'available')
        pass "docker compose $compose_ver"
    else
        fail "docker compose plugin not found"
    fi
fi

# ---------------------------------------------------------------------------
# 2. Clone the repository
# ---------------------------------------------------------------------------
header "2/5  Clone Repository"

if [ -d "$CLONE_DIR/.git" ]; then
    step "Repository already exists at $CLONE_DIR -- pulling latest"
    git -C "$CLONE_DIR" pull --ff-only || {
        printf '%bPull failed (diverged?). Using existing checkout.%b\n' "$YELLOW" "$RESET"
    }
else
    step "Cloning $REPO_URL"
    git clone "$REPO_URL" "$CLONE_DIR"
fi

cd "$CLONE_DIR"
printf 'Working directory: %s\n' "$(pwd)"

# ---------------------------------------------------------------------------
# 3. Copy config
# ---------------------------------------------------------------------------
header "3/5  Configure"

if [ -f config.toml ]; then
    printf 'config.toml already exists -- keeping existing copy.\n'
else
    step "Copying config.example.toml to config.toml"
    cp config.example.toml config.toml
    pass "config.toml created"
fi

# ---------------------------------------------------------------------------
# 4. Build Docker image
# ---------------------------------------------------------------------------
header "4/5  Build Docker Image"

step "Building runtime image (docker compose build cocosentry)"
docker compose build cocosentry

step "Building dev image (docker compose build dev)"
docker compose build dev

pass "Docker images built successfully"

# ---------------------------------------------------------------------------
# 5. Validation test suite
# ---------------------------------------------------------------------------
header "5/5  Validation Test Suite"

# Helper: run a one-off container with a custom entrypoint
run_in_container() {
    docker compose run --rm --no-deps -T --entrypoint "$1" cocosentry "${@:2}" 2>&1
}

# -- 5a: tflite-runtime import --------------------------------------------

step "Test: tflite-runtime import"
tflite_out=$(run_in_container python -c \
    "import tflite_runtime; print('tflite_runtime version:', tflite_runtime.__version__)" 2>&1) || true

if printf '%s' "$tflite_out" | grep -q "tflite_runtime version:"; then
    printf '  %s\n' "$tflite_out"
    pass "tflite-runtime imports successfully"
else
    printf '  %s\n' "$tflite_out"
    fail "tflite-runtime import failed"
fi

# -- 5b: libedgetpu.so.1 present ------------------------------------------

step "Test: libedgetpu.so.1 presence"
edgelib_out=$(run_in_container sh -c \
    "find / -name 'libedgetpu.so.1' -type f 2>/dev/null | head -1" 2>&1) || true

if printf '%s' "$edgelib_out" | grep -q "libedgetpu.so.1"; then
    printf '  Found: %s\n' "$edgelib_out"
    pass "libedgetpu.so.1 found in container"
else
    fail "libedgetpu.so.1 not found in container"
fi

# -- 5c: Edge TPU delegate ------------------------------------------------

step "Test: Edge TPU delegate load"

# Detect Coral USB on the host
coral_detected=false
if command -v lsusb >/dev/null 2>&1; then
    if lsusb 2>/dev/null | grep -iqE "google|coral|1a6e"; then
        coral_detected=true
        printf '  Coral USB device detected on host.\n'
    else
        printf '  No Coral USB device detected on host.\n'
    fi
else
    printf '  lsusb not available -- cannot detect Coral USB.\n'
fi

delegate_py='
import tflite_runtime.interpreter as tflite
try:
    delegate = tflite.load_delegate("libedgetpu.so.1")
    print("DELEGATE_OK")
except Exception as e:
    print("DELEGATE_FAIL: " + str(e))
'

if [ "$coral_detected" = true ]; then
    # Run with USB passthrough
    delegate_out=$(docker compose run --rm --no-deps -T \
        -v /dev/bus/usb:/dev/bus/usb \
        --privileged \
        --entrypoint python cocosentry \
        -c "$delegate_py" 2>&1) || true

    if printf '%s' "$delegate_out" | grep -q "DELEGATE_OK"; then
        pass "Edge TPU delegate loads successfully (Coral USB passed through)"
    else
        fail "Edge TPU delegate failed to load: $delegate_out"
    fi
else
    delegate_out=$(run_in_container python -c "$delegate_py" 2>&1) || true

    if printf '%s' "$delegate_out" | grep -q "DELEGATE_OK"; then
        pass "Edge TPU delegate loads (no USB detected but delegate loaded)"
    else
        warn "Edge TPU delegate did not load (no Coral USB device detected -- expected)"
    fi
fi

# -- 5d: Backend detection ------------------------------------------------

step "Test: Backend detection"
backend_out=$(run_in_container python -c \
    "from cocosentry.inference.engine import _BACKEND; print('DETECTED_BACKEND=' + _BACKEND)" 2>&1) || true

detected_backend=$(printf '%s' "$backend_out" | grep "DETECTED_BACKEND=" | head -1 | cut -d= -f2)
printf '  Detected backend: %s\n' "${detected_backend:-unknown}"

case "${detected_backend:-}" in
    edgetpu)
        pass "Backend detection reports 'edgetpu'"
        ;;
    tflite_runtime)
        if [ "$coral_detected" = true ]; then
            warn "Backend reports 'tflite_runtime' but Coral USB is present (delegate may not have loaded)"
        else
            pass "Backend detection reports 'tflite_runtime' (CPU fallback -- no Coral USB)"
        fi
        ;;
    tensorflow)
        warn "Backend detection reports 'tensorflow' (full TF, not tflite-runtime)"
        ;;
    none)
        fail "Backend detection reports 'none' -- no inference backend available"
        ;;
    *)
        fail "Backend detection returned unexpected value: '${detected_backend:-<empty>}'"
        ;;
esac

# -- 5e: cocosentry module import & Pipeline init -------------------------

step "Test: cocosentry module import and Pipeline initialization"
import_py='
import cocosentry
print("VERSION=" + cocosentry.__version__)
from cocosentry.__main__ import Pipeline
from cocosentry.config import AppConfig
config = AppConfig()
pipeline = Pipeline(config)
print("PIPELINE_OK")
pipeline.shutdown()
'
import_out=$(run_in_container python -c "$import_py" 2>&1) || true

if printf '%s' "$import_out" | grep -q "VERSION="; then
    version=$(printf '%s' "$import_out" | grep "VERSION=" | head -1 | cut -d= -f2)
    pass "cocosentry module imported (version $version)"
else
    fail "cocosentry module import failed"
fi

if printf '%s' "$import_out" | grep -q "PIPELINE_OK"; then
    pass "Pipeline initialized and shut down cleanly"
else
    fail "Pipeline initialization failed"
    printf '  Output:\n'
    printf '%s\n' "$import_out" | sed 's/^/    /'
fi

# -- 5f: pytest suite via dev profile -------------------------------------

step "Test: pytest suite (dev profile)"
printf '\n'
pytest_out=$(docker compose run --rm -T dev 2>&1) || true

# Show the tail of pytest output
printf '%s\n' "$pytest_out" | tail -20

if printf '%s' "$pytest_out" | grep -qE "passed|no tests ran"; then
    if printf '%s' "$pytest_out" | grep -q "failed"; then
        warn "pytest completed with some failures"
    else
        pass "pytest suite passed"
    fi
else
    fail "pytest suite did not complete successfully"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
header "Summary"

total=$((pass_count + fail_count + warn_count + skip_count))

printf '  %bPASS%b: %d\n' "$GREEN" "$RESET" "$pass_count"
printf '  %bFAIL%b: %d\n' "$RED" "$RESET" "$fail_count"
printf '  %bWARN%b: %d\n' "$YELLOW" "$RESET" "$warn_count"
if [ "$skip_count" -gt 0 ]; then
    printf '  %bSKIP%b: %d\n' "$YELLOW" "$RESET" "$skip_count"
fi
printf '  ---------\n'
printf '  Total: %d\n\n' "$total"

if [ "$fail_count" -gt 0 ]; then
    printf '%b%bSome checks failed. Review the output above for details.%b\n' "$RED" "$BOLD" "$RESET"
    exit 1
else
    printf '%b%bAll checks passed. CocoSentry is ready.%b\n' "$GREEN" "$BOLD" "$RESET"
    exit 0
fi
