#!/usr/bin/env bash

# --- Color Setup ---
if [[ "$NO_COLOR" == true ]] || [[ ! -t 1 ]]; then
    RED='' GREEN='' YELLOW='' BLUE='' BOLD='' NC=''
else
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
fi

# --- Logging ---
log()    { echo -e "${GREEN}[✓]${NC} $1" | tee -a "$LOG_FILE"; }
warn()   { echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG_FILE"; }
error()  { echo -e "${RED}[✗]${NC} $1" | tee -a "$LOG_FILE"; }
info()   { echo -e "${BLUE}[i]${NC} $1" | tee -a "$LOG_FILE"; }
manual() { echo -e "${YELLOW}$(msg MANUAL)${NC} $1" | tee -a "$LOG_FILE"; }

# --- Dry Run Wrapper ---
run_or_dry() {
    local desc="$1"; shift
    if [[ "$DRY_RUN" == true ]]; then
        info "$(msg DRY_RUN_PREFIX): $desc"
        return 0
    fi
    "$@"
}

# --- Pause / Confirmation ---
pause() {
    if [[ "$YES_MODE" == true ]]; then
        return 0
    fi
    echo ""
    read -r -p "$(msg PAUSE): " choice || true
    case "${choice:-}" in
        s|S) warn "$(msg SKIPPED)"; return 1 ;;
        q|Q) log "$(msg USER_QUIT) $LOG_FILE"; exit 0 ;;
        *)   return 0 ;;
    esac
}

# --- Normalize and validate --modules input (called once after parsing) ---
validate_selected_modules() {
    if [[ -z "$SELECTED_MODULES" ]]; then
        return
    fi
    # Strip all whitespace
    SELECTED_MODULES="$(echo "$SELECTED_MODULES" | tr -d ' \t')"
    # Validate each number is 0-11
    local any_valid=false
    IFS=',' read -ra nums <<< "$SELECTED_MODULES"
    for n in "${nums[@]}"; do
        [[ -z "$n" ]] && continue
        if ! [[ "$n" =~ ^[0-9]+$ ]] || [[ "$n" -gt 11 ]]; then
            echo "Error: invalid module number '$n' (valid: 0-11)" >&2
            echo "Run with --help for usage information" >&2
            exit 1
        fi
        any_valid=true
    done
    if ! $any_valid; then
        echo "Error: --modules requires at least one valid module number (0-11)" >&2
        exit 1
    fi
}

# --- Module Execution Check ---
should_run_module() {
    local mod_num="$1"
    if [[ -n "$SELECTED_MODULES" ]]; then
        if echo ",$SELECTED_MODULES," | grep -q ",$mod_num,"; then
            return 0
        else
            return 1
        fi
    fi
    return 0
}

# --- Section Header ---
section() {
    local num="$1"
    local name_key="$2"
    echo ""
    echo "=========================================="
    info "[$num] $(msg "$name_key")"
    echo "=========================================="
}

# --- Show Help ---
show_help() {
    cat <<HELPEOF
$(msg BANNER_TITLE) v${VERSION}

Usage: ./fix.sh [OPTIONS]

Options:
  --lang en|cn        Force language (default: auto-detect)
  --scan-dirs DIR     Additional directories to scan for .env files (comma-separated)
  --extra-patterns P  Additional sensitive patterns for history cleanup
  --dry-run           Show what would be done without making changes
  --yes               Skip all confirmations (for CI/automation)
  --modules 1,2,4     Only run specified modules (0-11)
  --no-color          Disable colored output
  --help, -h          Show this help message

Modules:
  0  Forensics & Hosts Block
  1  Kill Apifox Process
  2  Rotate SSH Keys
  3  Clean Shell History (zsh/bash/fish/PowerShell)
  4  Rotate GitHub Token
  5  Rotate K8s Credentials
  6  Rotate Docker Credentials
  7  Check macOS Keychain          (macOS only)
  8  Scan Sensitive Files
  9  Audit Activity
  10 Rotate npm Token
  11 Windows Credential Manager    (Windows only)

Announcement: $ANNOUNCEMENT_URL
Security contact: $SECURITY_EMAIL
HELPEOF
}
