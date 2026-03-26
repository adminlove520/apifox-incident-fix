#!/usr/bin/env bash

# =============================================================================
# Apifox Incident Fix - Integration Test
#
# Runs in isolated HOME directories, never touches real user data.
# Does NOT use set -euo pipefail — test harness must survive failures
# to report all results and print the summary.
#
# Usage:
#   ./test.sh              # Run all tests
#   ./test.sh --verbose    # Show full script output
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FIX_SCRIPT="$SCRIPT_DIR/dist/fix.sh"
VERBOSE=false
[[ "${1:-}" == "--verbose" ]] && VERBOSE=true

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); echo -e "${GREEN}PASS${NC}: $1"; }
fail() { FAIL=$((FAIL + 1)); echo -e "${RED}FAIL${NC}: $1"; }
skip() { SKIP=$((SKIP + 1)); echo -e "${YELLOW}SKIP${NC}: $1"; }

# --- Detect platform ---
OS_TYPE=""
case "$(uname -s)" in
    Darwin) OS_TYPE="macos" ;;
    Linux)  OS_TYPE="linux" ;;
    *)      OS_TYPE="unknown" ;;
esac

# --- Check if a command exists ---
has_cmd() { command -v "$1" &>/dev/null; }

# --- Create fake SSH keys without ssh-keygen ---
# Writes a minimal PEM-like file that scan_ssh_keys() will recognize
create_fake_key() {
    local path="$1"
    cat > "$path" <<'KEYEOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
KEYEOF
    # Create matching .pub
    echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake test@test" > "${path}.pub"
}

# --- Create isolated test environment ---
# Uses no external tools beyond basic coreutils
setup_test_home() {
    local test_home
    test_home="$(mktemp -d)"

    # SSH keys (fake — no ssh-keygen dependency)
    mkdir -p "$test_home/.ssh"
    create_fake_key "$test_home/.ssh/id_ed25519"
    create_fake_key "$test_home/.ssh/id_rsa_test"
    cat > "$test_home/.ssh/config" <<'SSHEOF'
Host github.com
    IdentityFile ~/.ssh/id_ed25519
    User git

Host gitlab.example.com
    IdentityFile ~/.ssh/id_rsa_test
    User git
SSHEOF

    # Shell history with sensitive content
    cat > "$test_home/.zsh_history" <<'HISTEOF'
ls -la
curl -H 'Authorization: token ghp_fake123' https://api.github.com/user
ngrok config add-authtoken fake_ngrok_token_here
echo hello world
export SECRET=mysecretvalue
kubectl get pods
HISTEOF

    cat > "$test_home/.bash_history" <<'HISTEOF'
git status
curl https://api.example.com?password=abc123
docker ps
HISTEOF

    # Docker config
    mkdir -p "$test_home/.docker"
    cat > "$test_home/.docker/config.json" <<'DOCKEREOF'
{
  "auths": {
    "https://index.docker.io/v1/": {
      "auth": "dGVzdDp0ZXN0"
    },
    "ghcr.io": {
      "auth": "dGVzdDp0ZXN0"
    },
    "harbor.example.com": {
      "auth": "dGVzdDp0ZXN0"
    }
  },
  "credsStore": "osxkeychain"
}
DOCKEREOF

    # Kubeconfig (works even without kubectl installed —
    # the script just checks if the file exists and reads current-context)
    mkdir -p "$test_home/.kube"
    cat > "$test_home/.kube/config" <<'K8SEOF'
apiVersion: v1
kind: Config
current-context: test-cluster
contexts:
- context:
    cluster: test
    user: test-user
  name: test-cluster
clusters:
- cluster:
    server: https://k8s.example.com:6443
  name: test
users:
- name: test-user
  user:
    token: fake-token
K8SEOF

    # .env files
    mkdir -p "$test_home/Code/project-a"
    echo "DB_PASSWORD=secret123" > "$test_home/Code/project-a/.env"
    mkdir -p "$test_home/Code/project-b"
    echo "API_KEY=abc" > "$test_home/Code/project-b/.env.local"

    # Git config (for SSH module email detection)
    cat > "$test_home/.gitconfig" <<'GITEOF'
[user]
    email = test@example.com
    name = Test User
GITEOF

    echo "$test_home"
}

# --- Run fix.sh in isolated env, always capture output, never fail the harness ---
run_fix() {
    local test_home="$1"; shift
    local output
    output="$(HOME="$test_home" bash "$FIX_SCRIPT" "$@" 2>&1)" || true
    if $VERBOSE; then
        echo "$output" >&2
    fi
    echo "$output"
}

# --- Create a stub script that pretends to be a command ---
# Usage: create_stub "$dir" "kubectl" to make a kubectl that reads from stdin config
create_path_stub() {
    local dir="$1" name="$2"
    cat > "$dir/$name" <<STUBEOF
#!/usr/bin/env bash
# Stub for $name — enough to not crash the script
case "\$1" in
    config)
        if [[ "\${2:-}" == "current-context" ]]; then
            echo "test-cluster"
        fi
        ;;
    auth)
        echo "not logged in"
        ;;
    get)
        echo "No resources found"
        ;;
    *)
        exit 0
        ;;
esac
STUBEOF
    chmod +x "$dir/$name"
}

# =============================================================================
# Test Cases
# =============================================================================

echo ""
echo "============================================"
echo "  Apifox Incident Fix - Integration Tests"
echo "  Platform: $OS_TYPE ($(uname -sr))"
echo "============================================"
echo ""

# --- Test 1: Syntax check ---
echo "--- Syntax ---"
if bash -n "$FIX_SCRIPT" 2>/dev/null; then
    pass "bash -n syntax check"
else
    fail "bash -n syntax check"
fi

# --- Test 2: --help ---
echo ""
echo "--- Help ---"
output="$(bash "$FIX_SCRIPT" --help 2>&1)" || true
if echo "$output" | grep -q "Usage:"; then
    pass "--help shows usage"
else
    fail "--help shows usage"
fi

if echo "$output" | grep -q -- "--dry-run"; then
    pass "--help lists --dry-run option"
else
    fail "--help lists --dry-run option"
fi

# --- Test 3: --lang ---
echo ""
echo "--- Language ---"
output="$(bash "$FIX_SCRIPT" --lang en --help 2>&1)" || true
if echo "$output" | grep -q "Apifox Supply Chain Incident Response Tool"; then
    pass "--lang en shows English"
else
    fail "--lang en shows English"
fi

output="$(bash "$FIX_SCRIPT" --lang cn --help 2>&1)" || true
if echo "$output" | grep -q "供应链攻击"; then
    pass "--lang cn shows Chinese"
else
    fail "--lang cn shows Chinese"
fi

# --- Test 4: Argument validation ---
echo ""
echo "--- Argument Validation ---"
output="$(bash "$FIX_SCRIPT" --lang 2>&1)" || true
if echo "$output" | grep -q "requires a value"; then
    pass "--lang without value reports error"
else
    fail "--lang without value reports error"
fi

output="$(bash "$FIX_SCRIPT" --modules 99 2>&1)" || true
if echo "$output" | grep -q "invalid module number"; then
    pass "--modules 99 reports invalid"
else
    fail "--modules 99 reports invalid"
fi

output="$(bash "$FIX_SCRIPT" --bogus 2>&1)" || true
if echo "$output" | grep -q "Unknown option"; then
    pass "unknown option reports error"
else
    fail "unknown option reports error"
fi

# --- Test 5: Dry-run with full mock environment ---
echo ""
echo "--- Dry-Run Full Scan ---"
TEST_HOME="$(setup_test_home)"

# Create stubs for tools that may not be installed
STUB_DIR="$TEST_HOME/.test-stubs"
mkdir -p "$STUB_DIR"
if ! has_cmd kubectl; then
    create_path_stub "$STUB_DIR" "kubectl"
fi

output="$(PATH="$STUB_DIR:$PATH" run_fix "$TEST_HOME" --dry-run --yes --lang en)"

# System scan detections
if echo "$output" | grep -q "SSH Keys:.*2 keys"; then
    pass "scan detects 2 SSH keys"
else
    fail "scan detects 2 SSH keys"
fi

if echo "$output" | grep -q "3 registries"; then
    pass "scan detects 3 Docker registries"
else
    fail "scan detects 3 Docker registries"
fi

if echo "$output" | grep -q "sensitive tokens found"; then
    pass "scan detects sensitive history"
else
    fail "scan detects sensitive history"
fi

if echo "$output" | grep -q "\.env.*found"; then
    pass "scan detects .env files"
else
    fail "scan detects .env files"
fi

# K8s detection: only assert if kubectl is available (real or stub)
if has_cmd kubectl || [[ -f "$STUB_DIR/kubectl" ]]; then
    if echo "$output" | grep -q "test-cluster"; then
        pass "scan detects K8s context"
    else
        fail "scan detects K8s context"
    fi
else
    skip "K8s context detection (kubectl not available)"
fi

# Dry-run markers
if echo "$output" | grep -q "DRY RUN"; then
    pass "dry-run markers present"
else
    fail "dry-run markers present"
fi

# No actual changes
if echo "$output" | grep -qi "Backed up:"; then
    fail "dry-run should not print 'Backed up'"
else
    pass "dry-run does not print false success messages"
fi

# Files unchanged
zsh_lines="$(wc -l < "$TEST_HOME/.zsh_history" | tr -d ' ')"
if [[ "$zsh_lines" == "6" ]]; then
    pass "dry-run did not modify .zsh_history ($zsh_lines lines)"
else
    fail "dry-run modified .zsh_history (expected 6, got $zsh_lines)"
fi

if ls -d "$TEST_HOME"/.ssh/compromised_backup* &>/dev/null; then
    fail "dry-run created SSH backup dir"
else
    pass "dry-run did not create SSH backup dir"
fi

rm -rf "$TEST_HOME"

# --- Test 6: --modules selective execution ---
echo ""
echo "--- Module Selection ---"
TEST_HOME="$(setup_test_home)"
STUB_DIR="$TEST_HOME/.test-stubs"
mkdir -p "$STUB_DIR"
has_cmd kubectl || create_path_stub "$STUB_DIR" "kubectl"

output="$(PATH="$STUB_DIR:$PATH" run_fix "$TEST_HOME" --dry-run --yes --modules 3 --lang en)"

# Only module 3 execution section should appear (prefixed with [i] [N])
# Scan report also lists modules but those lines are indented with spaces
if echo "$output" | grep -qE '^\[i\] \[3\]'; then
    pass "--modules 3 runs module 3"
else
    fail "--modules 3 runs module 3"
fi

if echo "$output" | grep -qE '^\[i\] \[2\]'; then
    fail "--modules 3 should not show module 2 section"
else
    pass "--modules 3 does not show module 2 section"
fi

if echo "$output" | grep -qE '^\[i\] \[6\]'; then
    fail "--modules 3 should not show module 6 section"
else
    pass "--modules 3 does not show module 6 section"
fi

# Summary should only have module 3 items
if echo "$output" | grep -q "Remaining manual"; then
    remaining="$(echo "$output" | sed -n '/Remaining manual/,/^$/p')"
    if echo "$remaining" | grep -q "SSH\|GitHub\|kubeconfig\|Docker\|Keychain"; then
        fail "summary shows items from unselected modules"
    else
        pass "summary only shows selected module items"
    fi
else
    fail "no summary section found"
fi

rm -rf "$TEST_HOME"

# --- Test 7: --modules with spaces ---
echo ""
echo "--- Module Selection Edge Cases ---"
TEST_HOME="$(setup_test_home)"
STUB_DIR="$TEST_HOME/.test-stubs"
mkdir -p "$STUB_DIR"
has_cmd kubectl || create_path_stub "$STUB_DIR" "kubectl"

output="$(PATH="$STUB_DIR:$PATH" run_fix "$TEST_HOME" --dry-run --yes --modules '2, 3' --lang en)"
mod_sections="$(echo "$output" | grep -c '^\[i\] \[[0-9]\]')" || true
if [[ "$mod_sections" == "2" ]]; then
    pass "--modules '2, 3' runs exactly 2 modules"
else
    fail "--modules '2, 3' expected 2 sections, got $mod_sections"
fi

rm -rf "$TEST_HOME"

# --- Test 8: Empty environment (no credentials) ---
echo ""
echo "--- Empty Environment ---"
EMPTY_HOME="$(mktemp -d)"

output="$(run_fix "$EMPTY_HOME" --dry-run --yes --lang en)"
# run_fix always succeeds (|| true), check output for crash signs
if echo "$output" | grep -q "Script execution complete"; then
    pass "empty HOME completes successfully"
else
    fail "empty HOME did not complete"
fi

if echo "$output" | grep -q "SSH Keys:.*Not found"; then
    pass "empty HOME: SSH keys not found"
else
    fail "empty HOME: SSH keys detection"
fi

if echo "$output" | grep -q "no sensitive tokens found"; then
    pass "empty HOME: history clean"
else
    fail "empty HOME: history detection"
fi

# Verify no unbound variable errors leaked into output
if echo "$output" | grep -qi "unbound variable"; then
    fail "empty HOME: unbound variable error in output"
else
    pass "empty HOME: no unbound variable errors"
fi

rm -rf "$EMPTY_HOME"

# --- Test 9: --no-color ---
echo ""
echo "--- No Color ---"
TEST_HOME="$(setup_test_home)"

output="$(run_fix "$TEST_HOME" --dry-run --yes --no-color --lang en)"
# Check for ANSI escape sequences (using $'\033' for portability)
if echo "$output" | grep -q $'\033\['; then
    fail "--no-color still contains ANSI codes"
else
    pass "--no-color strips ANSI codes"
fi

rm -rf "$TEST_HOME"

# --- Test 10: Docker registry parsing (various formats) ---
echo ""
echo "--- Docker Config Parsing ---"

# Compact single-line JSON
TEST_HOME="$(mktemp -d)"
mkdir -p "$TEST_HOME/.docker"
echo '{"auths":{"ghcr.io":{"auth":"x"},"docker.io":{"auth":"y"}},"credsStore":"osxkeychain"}' > "$TEST_HOME/.docker/config.json"

output="$(run_fix "$TEST_HOME" --dry-run --yes --lang en)"
if echo "$output" | grep -q "2 registries"; then
    pass "compact JSON: detects 2 registries"
else
    fail "compact JSON: registry detection"
fi
rm -rf "$TEST_HOME"

# --- Test 11: Platform-specific behavior (native) ---
echo ""
echo "--- Platform-Specific (native: $OS_TYPE) ---"

if [[ "$OS_TYPE" == "macos" ]]; then
    TEST_HOME="$(setup_test_home)"
    output="$(run_fix "$TEST_HOME" --dry-run --yes --modules 7 --lang en)"
    if echo "$output" | grep -q "Keychain"; then
        pass "native macOS: Keychain module runs"
    else
        fail "native macOS: Keychain module"
    fi
    rm -rf "$TEST_HOME"

    TEST_HOME="$(setup_test_home)"
    output="$(run_fix "$TEST_HOME" --dry-run --yes --lang en)"
    if echo "$output" | grep -q "Check macOS Keychain.*applicable"; then
        pass "native macOS: Keychain marked applicable"
    else
        fail "native macOS: Keychain applicable status"
    fi
    rm -rf "$TEST_HOME"
else
    TEST_HOME="$(setup_test_home)"
    output="$(run_fix "$TEST_HOME" --dry-run --yes --lang en)"
    if echo "$output" | grep -q "Check macOS Keychain.*skip"; then
        pass "native Linux: Keychain marked skip"
    else
        fail "native Linux: Keychain skip status"
    fi
    rm -rf "$TEST_HOME"
fi

# --- Test 11b: Cross-platform simulation via OS_TYPE injection ---
# OS_TYPE is injectable — test the OTHER platform's code path
echo ""
echo "--- Platform-Specific (simulated) ---"

# run_fix_as: run fix.sh with OS_TYPE forced to a given platform
run_fix_as() {
    local platform="$1" test_home="$2"; shift 2
    OS_TYPE="$platform" OS_VERSION="Simulated-$platform" \
        HOME="$test_home" bash "$FIX_SCRIPT" "$@" 2>&1 || true
}

# Simulate Linux (even on macOS)
TEST_HOME="$(setup_test_home)"
output="$(run_fix_as linux "$TEST_HOME" --dry-run --yes --lang en)"

if echo "$output" | grep -q "Check macOS Keychain.*skip"; then
    pass "simulated Linux: Keychain marked skip"
else
    fail "simulated Linux: Keychain skip status"
fi

if echo "$output" | grep -q "Simulated-linux"; then
    pass "simulated Linux: platform shows as Linux"
else
    fail "simulated Linux: platform detection"
fi

# Module 7 should not produce a section when simulating Linux
output_mod7="$(run_fix_as linux "$TEST_HOME" --dry-run --yes --modules 7 --lang en)"
if echo "$output_mod7" | grep -qE '^\[i\] \[7\]'; then
    fail "simulated Linux: Keychain module should not run"
else
    pass "simulated Linux: Keychain module correctly skipped"
fi

rm -rf "$TEST_HOME"

# Simulate macOS (even on Linux)
TEST_HOME="$(setup_test_home)"
output="$(run_fix_as macos "$TEST_HOME" --dry-run --yes --lang en)"

if echo "$output" | grep -q "Check macOS Keychain.*applicable"; then
    pass "simulated macOS: Keychain marked applicable"
else
    fail "simulated macOS: Keychain applicable status"
fi

if echo "$output" | grep -q "Simulated-macos"; then
    pass "simulated macOS: platform shows as macOS"
else
    fail "simulated macOS: platform detection"
fi

rm -rf "$TEST_HOME"

# --- Test 11c: Second confirmation before real changes ---
echo ""
echo "--- Second Confirmation ---"

# dry-run should NOT show confirmation warning
TEST_HOME="$(setup_test_home)"
output="$(run_fix "$TEST_HOME" --dry-run --yes --lang en)"
if echo "$output" | grep -q "WARNING.*modify your system"; then
    fail "dry-run should not show confirmation warning"
else
    pass "dry-run skips confirmation"
fi
rm -rf "$TEST_HOME"

# Non-dry-run without --yes: empty input (default N) should abort
TEST_HOME="$(setup_test_home)"
# First \n → module selection (default Y=all), second \n → confirmation (default N=abort)
output="$(printf '\n\n' | HOME="$TEST_HOME" bash "$FIX_SCRIPT" --lang en 2>&1)" || true
if echo "$output" | grep -q "WARNING.*modify your system"; then
    pass "non-dry-run shows confirmation warning"
else
    fail "non-dry-run should show confirmation warning"
fi
if echo "$output" | grep -q "Aborted"; then
    pass "default N aborts execution"
else
    fail "default N should abort execution"
fi
rm -rf "$TEST_HOME"

# Non-dry-run with --yes should skip confirmation and complete
TEST_HOME="$(setup_test_home)"
STUB_DIR="$TEST_HOME/.test-stubs"
mkdir -p "$STUB_DIR"
has_cmd kubectl || create_path_stub "$STUB_DIR" "kubectl"
output="$(PATH="$STUB_DIR:$PATH" HOME="$TEST_HOME" bash "$FIX_SCRIPT" --yes --modules 8 --lang en 2>&1)" || true
if echo "$output" | grep -q "WARNING.*modify your system"; then
    fail "--yes should skip confirmation"
else
    pass "--yes skips confirmation"
fi
if echo "$output" | grep -q "Script execution complete"; then
    pass "--yes completes execution"
else
    fail "--yes should complete execution"
fi
rm -rf "$TEST_HOME"

# --- Test 12: Chinese dry-run ---
echo ""
echo "--- Chinese Language ---"
TEST_HOME="$(setup_test_home)"

output="$(run_fix "$TEST_HOME" --dry-run --yes --lang cn)"
if echo "$output" | grep -q "系统扫描"; then
    pass "--lang cn: scan title in Chinese"
else
    fail "--lang cn: scan title"
fi

if echo "$output" | grep -q "模拟运行"; then
    pass "--lang cn: dry-run prefix in Chinese"
else
    fail "--lang cn: dry-run prefix"
fi

rm -rf "$TEST_HOME"

# --- Test 13: Log file creation ---
echo ""
echo "--- Log File ---"
TEST_HOME="$(setup_test_home)"

run_fix "$TEST_HOME" --dry-run --yes --lang en >/dev/null
log_file="$(ls "$TEST_HOME"/apifox-incident-fix-*.log 2>/dev/null | head -1)" || true
if [[ -n "${log_file:-}" && -f "$log_file" ]]; then
    pass "log file created"
    if [[ -s "$log_file" ]]; then
        pass "log file is non-empty"
    else
        fail "log file is empty"
    fi
else
    fail "log file not created"
fi

rm -rf "$TEST_HOME"

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "============================================"
TOTAL=$((PASS + FAIL + SKIP))
echo -e "  Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${SKIP} skipped${NC} / ${TOTAL} total"
echo "  Platform: $OS_TYPE"
echo "============================================"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
exit 0
