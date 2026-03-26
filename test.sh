#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Apifox Incident Fix - Integration Test
# Runs in an isolated HOME directory, never touches real user data.
# Supports macOS and Linux.
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

pass() { ((PASS++)); echo -e "${GREEN}PASS${NC}: $1"; }
fail() { ((FAIL++)); echo -e "${RED}FAIL${NC}: $1"; }
skip() { ((SKIP++)); echo -e "${YELLOW}SKIP${NC}: $1"; }

# --- Detect platform ---
OS_TYPE=""
case "$(uname -s)" in
    Darwin) OS_TYPE="macos" ;;
    Linux)  OS_TYPE="linux" ;;
    *)      OS_TYPE="unknown" ;;
esac

# --- Create isolated test environment ---
setup_test_home() {
    local test_home
    test_home="$(mktemp -d)"

    # SSH keys
    mkdir -p "$test_home/.ssh"
    ssh-keygen -t ed25519 -f "$test_home/.ssh/id_ed25519" -N "" -q
    ssh-keygen -t rsa -b 2048 -f "$test_home/.ssh/id_rsa_test" -N "" -q
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

    # Kubeconfig
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
    mkdir -p "$test_home/.config/git"
    cat > "$test_home/.gitconfig" <<'GITEOF'
[user]
    email = test@example.com
    name = Test User
GITEOF

    echo "$test_home"
}

# --- Run fix.sh in isolated env ---
run_fix() {
    local test_home="$1"; shift
    local output
    if $VERBOSE; then
        HOME="$test_home" bash "$FIX_SCRIPT" "$@" 2>&1 | tee /dev/stderr
    else
        HOME="$test_home" bash "$FIX_SCRIPT" "$@" 2>&1
    fi
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
if bash -n "$FIX_SCRIPT" 2>&1; then
    pass "bash -n syntax check"
else
    fail "bash -n syntax check"
fi

# --- Test 2: --help ---
echo ""
echo "--- Help ---"
output="$(bash "$FIX_SCRIPT" --help 2>&1)"
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
output="$(bash "$FIX_SCRIPT" --lang en --help 2>&1)"
if echo "$output" | grep -q "Apifox Supply Chain Incident Response Tool"; then
    pass "--lang en shows English"
else
    fail "--lang en shows English"
fi

output="$(bash "$FIX_SCRIPT" --lang cn --help 2>&1)"
if echo "$output" | grep -q "供应链攻击"; then
    pass "--lang cn shows Chinese"
else
    fail "--lang cn shows Chinese"
fi

# --- Test 4: Argument validation ---
echo ""
echo "--- Argument Validation ---"
output="$(bash "$FIX_SCRIPT" --lang 2>&1 || true)"
if echo "$output" | grep -q "requires a value"; then
    pass "--lang without value reports error"
else
    fail "--lang without value reports error"
fi

output="$(bash "$FIX_SCRIPT" --modules 99 2>&1 || true)"
if echo "$output" | grep -q "invalid module number"; then
    pass "--modules 99 reports invalid"
else
    fail "--modules 99 reports invalid"
fi

output="$(bash "$FIX_SCRIPT" --bogus 2>&1 || true)"
if echo "$output" | grep -q "Unknown option"; then
    pass "unknown option reports error"
else
    fail "unknown option reports error"
fi

# --- Test 5: Dry-run with full mock environment ---
echo ""
echo "--- Dry-Run Full Scan ---"
TEST_HOME="$(setup_test_home)"

output="$(run_fix "$TEST_HOME" --dry-run --yes --lang en 2>&1)"

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

if echo "$output" | grep -q "test-cluster"; then
    pass "scan detects K8s context"
else
    fail "scan detects K8s context"
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

if [[ ! -d "$TEST_HOME/.ssh/compromised_backup"* ]] 2>/dev/null; then
    pass "dry-run did not create SSH backup dir"
else
    fail "dry-run created SSH backup dir"
fi

rm -rf "$TEST_HOME"

# --- Test 6: --modules selective execution ---
echo ""
echo "--- Module Selection ---"
TEST_HOME="$(setup_test_home)"

output="$(run_fix "$TEST_HOME" --dry-run --yes --modules 3 --lang en 2>&1)"

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

output="$(run_fix "$TEST_HOME" --dry-run --yes --modules '2, 3' --lang en 2>&1)"
mod_sections="$(echo "$output" | grep -c '^\[i\] \[[0-9]\]' || true)"
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

output="$(run_fix "$EMPTY_HOME" --dry-run --yes --lang en 2>&1)"
exit_code=$?

if [[ $exit_code -eq 0 ]]; then
    pass "empty HOME does not crash (exit 0)"
else
    fail "empty HOME crashed (exit $exit_code)"
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

rm -rf "$EMPTY_HOME"

# --- Test 9: --no-color ---
echo ""
echo "--- No Color ---"
TEST_HOME="$(setup_test_home)"

output="$(run_fix "$TEST_HOME" --dry-run --yes --no-color --lang en 2>&1)"
# Check for ANSI escape sequences
if echo "$output" | grep -qP '\033\[' 2>/dev/null || echo "$output" | grep -q $'\033\[' 2>/dev/null; then
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

output="$(run_fix "$TEST_HOME" --dry-run --yes --lang en 2>&1)"
if echo "$output" | grep -q "2 registries"; then
    pass "compact JSON: detects 2 registries"
else
    fail "compact JSON: registry detection"
fi
rm -rf "$TEST_HOME"

# --- Test 11: Platform-specific (macOS only) ---
echo ""
echo "--- Platform-Specific ---"
if [[ "$OS_TYPE" == "macos" ]]; then
    TEST_HOME="$(setup_test_home)"
    output="$(run_fix "$TEST_HOME" --dry-run --yes --modules 7 --lang en 2>&1)"
    if echo "$output" | grep -q "Keychain"; then
        pass "macOS: Keychain module runs"
    else
        fail "macOS: Keychain module"
    fi
    rm -rf "$TEST_HOME"
else
    skip "macOS Keychain test (running on $OS_TYPE)"
fi

# --- Test 12: Chinese dry-run ---
echo ""
echo "--- Chinese Language ---"
TEST_HOME="$(setup_test_home)"

output="$(run_fix "$TEST_HOME" --dry-run --yes --lang cn 2>&1)"
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

run_fix "$TEST_HOME" --dry-run --yes --lang en >/dev/null 2>&1
log_file="$(ls "$TEST_HOME"/apifox-incident-fix-*.log 2>/dev/null | head -1)"
if [[ -n "$log_file" && -f "$log_file" ]]; then
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
