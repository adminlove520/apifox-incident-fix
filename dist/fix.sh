#!/usr/bin/env bash
set -euo pipefail

VERSION="1.0.0"
SCRIPT_NAME="apifox-incident-fix"
RISK_START="2026-03-04"
RISK_END="2026-03-22"
FIX_VERSION="2.8.19"
C2_DOMAIN="apifox.it.com"
ANNOUNCEMENT_URL="https://mp.weixin.qq.com/s/GpACQdnhVNsMn51cm4hZig"
SECURITY_EMAIL="security@apifox.com"

# --- Argument Parsing ---
LANG_FIX=""
SCAN_DIRS=""
EXTRA_PATTERNS=""
DRY_RUN=false
YES_MODE=false
SELECTED_MODULES=""
NO_COLOR=false

require_arg() {
    if [[ $# -lt 2 || -z "$2" ]]; then
        echo "Error: $1 requires a value" >&2
        echo "Run with --help for usage information" >&2
        exit 1
    fi
}

# Like require_arg but also rejects values starting with -- (for enum-like params)
require_enum_arg() {
    require_arg "$@"
    if [[ "$2" == --* ]]; then
        echo "Error: $1 requires a value, got '$2'" >&2
        echo "Run with --help for usage information" >&2
        exit 1
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --lang)
            require_enum_arg "$1" "${2:-}"; LANG_FIX="$2"; shift 2 ;;
        --scan-dirs)
            require_arg "$1" "${2:-}"; SCAN_DIRS="$2"; shift 2 ;;
        --extra-patterns)
            require_arg "$1" "${2:-}"; EXTRA_PATTERNS="$2"; shift 2 ;;
        --dry-run)
            DRY_RUN=true; shift ;;
        --yes)
            YES_MODE=true; shift ;;
        --modules)
            require_enum_arg "$1" "${2:-}"; SELECTED_MODULES="$2"; shift 2 ;;
        --no-color)
            NO_COLOR=true; shift ;;
        --help|-h)
            SHOW_HELP=true; shift ;;
        *)
            echo "Error: Unknown option: $1" >&2
            echo "Run with --help for usage information" >&2
            exit 1 ;;
    esac
done

LOG_FILE="$HOME/${SCRIPT_NAME}-$(date +%Y%m%d_%H%M%S).log"


# --- Language Detection ---
detect_language() {
    if [[ -n "$LANG_FIX" ]]; then
        echo "$LANG_FIX"
        return
    fi
    case "${LANG:-}" in
        zh*) echo "cn" ;;
        *)   echo "en" ;;
    esac
}

CURRENT_LANG="$(detect_language)"

# --- Message Definitions ---
# Format: MSG_<KEY>_EN / MSG_<KEY>_CN
# Usage: msg "KEY"

# -- General --
MSG_BANNER_TITLE_EN="Apifox Supply Chain Incident Response Tool"
MSG_BANNER_TITLE_CN="Apifox 供应链攻击应急响应工具"

MSG_BANNER_VERSION_EN="Version"
MSG_BANNER_VERSION_CN="版本"

MSG_LOG_SAVED_EN="Log saved to"
MSG_LOG_SAVED_CN="日志已保存到"

MSG_PROCEED_ALL_EN="Proceed with all applicable modules? [Y/n/select]"
MSG_PROCEED_ALL_CN="执行所有适用模块？[Y(是)/n(否)/select(选择)]"

MSG_PAUSE_EN="Press Enter to continue, 's' to skip, 'q' to quit"
MSG_PAUSE_CN="按 Enter 继续，输入 s 跳过，输入 q 退出"

MSG_SKIPPED_EN="Skipped"
MSG_SKIPPED_CN="已跳过"

MSG_USER_QUIT_EN="User quit. Log saved to"
MSG_USER_QUIT_CN="用户退出，日志已保存到"

MSG_DRY_RUN_PREFIX_EN="[DRY RUN] Would"
MSG_DRY_RUN_PREFIX_CN="[模拟运行] 将会"

MSG_MANUAL_EN="[Manual]"
MSG_MANUAL_CN="[手动]"

MSG_NOT_APPLICABLE_EN="Not applicable, skipping"
MSG_NOT_APPLICABLE_CN="不适用，跳过"

MSG_SELECT_PROMPT_EN="Enter module numbers (comma-separated, e.g., 1,2,4):"
MSG_SELECT_PROMPT_CN="输入模块编号（逗号分隔，如 1,2,4）："

# -- Scan --
MSG_SCAN_TITLE_EN="System Scan"
MSG_SCAN_TITLE_CN="系统扫描"

MSG_SCAN_PLATFORM_EN="Platform"
MSG_SCAN_PLATFORM_CN="平台"

MSG_SCAN_APIFOX_PROC_EN="Apifox Process"
MSG_SCAN_APIFOX_PROC_CN="Apifox 进程"

MSG_SCAN_RUNNING_EN="RUNNING"
MSG_SCAN_RUNNING_CN="运行中"

MSG_SCAN_NOT_RUNNING_EN="Not running"
MSG_SCAN_NOT_RUNNING_CN="未运行"

MSG_SCAN_LEVELDB_EN="Apifox LevelDB"
MSG_SCAN_LEVELDB_CN="Apifox LevelDB"

MSG_SCAN_MALICIOUS_EN="MALICIOUS MARKERS FOUND"
MSG_SCAN_MALICIOUS_CN="发现恶意标记"

MSG_SCAN_CLEAN_EN="No known markers found"
MSG_SCAN_CLEAN_CN="未发现已知恶意标记"

MSG_SCAN_NOT_FOUND_EN="Not found"
MSG_SCAN_NOT_FOUND_CN="未找到"

MSG_SCAN_VERSION_EN="Apifox Version"
MSG_SCAN_VERSION_CN="Apifox 版本"

MSG_SCAN_OUTDATED_EN="OUTDATED - please upgrade to"
MSG_SCAN_OUTDATED_CN="版本过旧 - 请升级到"

MSG_SCAN_HOSTS_EN="Hosts Block"
MSG_SCAN_HOSTS_CN="Hosts 屏蔽"

MSG_SCAN_HOSTS_BLOCKED_EN="blocked"
MSG_SCAN_HOSTS_BLOCKED_CN="已屏蔽"

MSG_SCAN_HOSTS_NOT_BLOCKED_EN="NOT blocked"
MSG_SCAN_HOSTS_NOT_BLOCKED_CN="未屏蔽"

MSG_SCAN_CREDS_TITLE_EN="Credentials found"
MSG_SCAN_CREDS_TITLE_CN="发现的凭证"

MSG_SCAN_SSH_EN="SSH Keys"
MSG_SCAN_SSH_CN="SSH 密钥"

MSG_SCAN_GITHUB_EN="GitHub CLI"
MSG_SCAN_GITHUB_CN="GitHub CLI"

MSG_SCAN_K8S_EN="Kubernetes"
MSG_SCAN_K8S_CN="Kubernetes"

MSG_SCAN_DOCKER_EN="Docker"
MSG_SCAN_DOCKER_CN="Docker"

MSG_SCAN_HISTORY_EN="Shell History"
MSG_SCAN_HISTORY_CN="Shell History"

MSG_SCAN_HISTORY_SENSITIVE_EN="sensitive tokens found"
MSG_SCAN_HISTORY_SENSITIVE_CN="发现敏感 token"

MSG_SCAN_HISTORY_CLEAN_EN="no sensitive tokens found"
MSG_SCAN_HISTORY_CLEAN_CN="未发现敏感 token"

MSG_SCAN_ENV_EN=".env files"
MSG_SCAN_ENV_CN=".env 文件"

MSG_SCAN_MODULES_TITLE_EN="Modules to run"
MSG_SCAN_MODULES_TITLE_CN="将执行的模块"

MSG_SCAN_APPLICABLE_EN="applicable"
MSG_SCAN_APPLICABLE_CN="适用"

MSG_SCAN_SKIP_EN="skip"
MSG_SCAN_SKIP_CN="跳过"

# -- Module Names --
MSG_MOD0_NAME_EN="Forensics & Hosts Block"
MSG_MOD0_NAME_CN="取证确认 & Hosts 屏蔽"

MSG_MOD1_NAME_EN="Kill Apifox Process"
MSG_MOD1_NAME_CN="终止 Apifox 进程"

MSG_MOD2_NAME_EN="Rotate SSH Keys"
MSG_MOD2_NAME_CN="轮换 SSH 密钥"

MSG_MOD3_NAME_EN="Clean Shell History"
MSG_MOD3_NAME_CN="清理 Shell History"

MSG_MOD4_NAME_EN="Rotate GitHub Token"
MSG_MOD4_NAME_CN="轮换 GitHub Token"

MSG_MOD5_NAME_EN="Rotate K8s Credentials"
MSG_MOD5_NAME_CN="轮换 K8s 凭证"

MSG_MOD6_NAME_EN="Rotate Docker Credentials"
MSG_MOD6_NAME_CN="轮换 Docker 凭证"

MSG_MOD7_NAME_EN="Check macOS Keychain"
MSG_MOD7_NAME_CN="检查 macOS 钥匙串"

MSG_MOD8_NAME_EN="Scan .env Files"
MSG_MOD8_NAME_CN="扫描 .env 文件"

MSG_MOD9_NAME_EN="Audit Activity"
MSG_MOD9_NAME_CN="审计异常活动"

# -- Module 00: Forensics --
MSG_FORENSICS_CHECKING_EN="Checking Apifox LevelDB for malicious markers..."
MSG_FORENSICS_CHECKING_CN="检查 Apifox LevelDB 是否存在恶意标记..."

MSG_FORENSICS_FOUND_EN="Malicious markers found! Matched files:"
MSG_FORENSICS_FOUND_CN="发现恶意载荷痕迹！匹配文件："

MSG_FORENSICS_CLEAN_EN="No known malicious markers found in LevelDB (does not guarantee safety, recommend continuing)"
MSG_FORENSICS_CLEAN_CN="未在 LevelDB 中发现已知恶意标记（但不代表安全，建议继续执行）"

MSG_FORENSICS_NO_DIR_EN="Apifox LevelDB directory not found"
MSG_FORENSICS_NO_DIR_CN="未找到 Apifox LevelDB 目录"

MSG_FORENSICS_HOSTS_PROMPT_EN="Add 127.0.0.1 apifox.it.com to /etc/hosts? (requires sudo) [Y/n]"
MSG_FORENSICS_HOSTS_PROMPT_CN="添加 127.0.0.1 apifox.it.com 到 /etc/hosts？（需要 sudo）[Y/n]"

MSG_FORENSICS_HOSTS_ADDED_EN="Hosts entry added"
MSG_FORENSICS_HOSTS_ADDED_CN="Hosts 条目已添加"

MSG_FORENSICS_HOSTS_EXISTS_EN="apifox.it.com is already blocked in /etc/hosts"
MSG_FORENSICS_HOSTS_EXISTS_CN="apifox.it.com 已在 /etc/hosts 中被屏蔽"

MSG_FORENSICS_VERSION_WARN_EN="Apifox version is below ${FIX_VERSION}. Please upgrade before continuing."
MSG_FORENSICS_VERSION_WARN_CN="Apifox 版本低于 ${FIX_VERSION}，请先升级再继续。"

# -- Module 01: Kill --
MSG_KILL_FOUND_EN="Apifox processes found:"
MSG_KILL_FOUND_CN="发现 Apifox 进程："

MSG_KILL_NONE_EN="No Apifox processes found"
MSG_KILL_NONE_CN="未发现 Apifox 进程"

MSG_KILL_DONE_EN="Apifox processes terminated"
MSG_KILL_DONE_CN="Apifox 进程已终止"

MSG_KILL_FORCE_EN="Processes still running, force killing..."
MSG_KILL_FORCE_CN="进程仍在运行，强制终止..."

# -- Module 02: SSH --
MSG_SSH_SCANNING_EN="Scanning SSH keys in ~/.ssh/..."
MSG_SSH_SCANNING_CN="扫描 ~/.ssh/ 中的 SSH 密钥..."

MSG_SSH_FOUND_EN="SSH keys found:"
MSG_SSH_FOUND_CN="发现 SSH 密钥："

MSG_SSH_NONE_EN="No SSH keys found"
MSG_SSH_NONE_CN="未发现 SSH 密钥"

MSG_SSH_SELECT_EN="Enter key numbers to rotate (comma-separated, or 'all'):"
MSG_SSH_SELECT_CN="输入要轮换的密钥编号（逗号分隔，或 'all'）："

MSG_SSH_BACKUP_EN="Backed up"
MSG_SSH_BACKUP_CN="已备份"

MSG_SSH_GENERATED_EN="New key generated"
MSG_SSH_GENERATED_CN="已生成新密钥"

MSG_SSH_CONFIG_UPDATED_EN="~/.ssh/config updated"
MSG_SSH_CONFIG_UPDATED_CN="~/.ssh/config 已更新"

MSG_SSH_PUBKEY_EN="New public key (add to your platforms):"
MSG_SSH_PUBKEY_CN="新公钥（请添加到对应平台）："

MSG_SSH_PLATFORM_HINT_EN="This key is used for host:"
MSG_SSH_PLATFORM_HINT_CN="此密钥用于主机："

# -- Module 03: History --
MSG_HISTORY_CLEANING_EN="Cleaning sensitive lines from shell history..."
MSG_HISTORY_CLEANING_CN="清理 Shell History 中的敏感信息..."

MSG_HISTORY_CLEANED_EN="cleaned"
MSG_HISTORY_CLEANED_CN="已清理"

MSG_HISTORY_LINES_EN="lines"
MSG_HISTORY_LINES_CN="行"

MSG_HISTORY_BACKUP_EN="backup at"
MSG_HISTORY_BACKUP_CN="备份在"

MSG_HISTORY_NOT_FOUND_EN="not found"
MSG_HISTORY_NOT_FOUND_CN="未找到"

# -- Module 04: GitHub --
MSG_GITHUB_STATUS_EN="Current GitHub CLI status:"
MSG_GITHUB_STATUS_CN="当前 GitHub CLI 状态："

MSG_GITHUB_LOGOUT_EN="Logged out of GitHub CLI"
MSG_GITHUB_LOGOUT_CN="已登出 GitHub CLI"

MSG_GITHUB_LOGIN_EN="Please complete authorization in the browser..."
MSG_GITHUB_LOGIN_CN="请在弹出的浏览器中完成授权..."

MSG_GITHUB_DONE_EN="GitHub CLI re-login complete"
MSG_GITHUB_DONE_CN="GitHub CLI 重新登录完成"

MSG_GITHUB_NO_CLI_EN="gh CLI not installed, please handle GitHub tokens manually"
MSG_GITHUB_NO_CLI_CN="未安装 gh CLI，请手动处理 GitHub Token"

MSG_GITHUB_MANUAL_TOKENS_EN="Go to GitHub → Settings → Developer settings → Personal access tokens to revoke suspicious tokens"
MSG_GITHUB_MANUAL_TOKENS_CN="请前往 GitHub → Settings → Developer settings → Personal access tokens 撤销可疑 token"

MSG_GITHUB_MANUAL_SESSIONS_EN="Check GitHub → Settings → Security → Sessions for unusual logins"
MSG_GITHUB_MANUAL_SESSIONS_CN="请检查 GitHub → Settings → Security → Sessions 是否有异常登录"

# -- Module 05: K8s --
MSG_K8S_FOUND_EN="kubeconfig found, current context:"
MSG_K8S_FOUND_CN="发现 kubeconfig，当前上下文："

MSG_K8S_BACKUP_EN="kubeconfig backed up to"
MSG_K8S_BACKUP_CN="kubeconfig 已备份到"

MSG_K8S_MANUAL_EN="Contact your cluster admin to re-issue kubeconfig credentials"
MSG_K8S_MANUAL_CN="请联系集群管理员重新颁发 kubeconfig 凭证"

MSG_K8S_NONE_EN="~/.kube/config not found"
MSG_K8S_NONE_CN="未找到 ~/.kube/config"

# -- Module 06: Docker --
MSG_DOCKER_REGISTRIES_EN="Docker registries found:"
MSG_DOCKER_REGISTRIES_CN="发现 Docker Registry："

MSG_DOCKER_LOGOUT_EN="Logged out of all Docker registries"
MSG_DOCKER_LOGOUT_CN="已登出所有 Docker Registry"

MSG_DOCKER_MANUAL_EN="Change passwords on the above registries, then run: docker login <registry>"
MSG_DOCKER_MANUAL_CN="请修改以上 Registry 的密码，然后执行: docker login <registry>"

MSG_DOCKER_NO_CLI_EN="Docker not installed"
MSG_DOCKER_NO_CLI_CN="未安装 Docker"

MSG_DOCKER_NO_CONFIG_EN="No Docker config found"
MSG_DOCKER_NO_CONFIG_CN="未找到 Docker 配置"

# -- Module 07: Keychain --
MSG_KEYCHAIN_SEARCHING_EN="Searching Keychain for apifox-related entries..."
MSG_KEYCHAIN_SEARCHING_CN="搜索钥匙串中与 apifox 相关的条目..."

MSG_KEYCHAIN_FOUND_EN="Found apifox-related Keychain entries:"
MSG_KEYCHAIN_FOUND_CN="发现 apifox 相关钥匙串条目："

MSG_KEYCHAIN_NONE_EN="No apifox-related entries found in Keychain"
MSG_KEYCHAIN_NONE_CN="钥匙串中未找到 apifox 相关条目"

MSG_KEYCHAIN_MANUAL_EN="Open Keychain Access.app to manually check GitHub/GitLab/Docker/database entries"
MSG_KEYCHAIN_MANUAL_CN="请打开钥匙串访问.app 手动检查 GitHub/GitLab/Docker/数据库相关条目"

MSG_KEYCHAIN_LINUX_EN="Keychain check is macOS-only. Please manually check your system's keyring (e.g., GNOME Keyring, KDE Wallet)"
MSG_KEYCHAIN_LINUX_CN="钥匙串检查仅适用于 macOS。请手动检查系统密钥管理器（如 GNOME Keyring、KDE Wallet）"

# -- Module 08: Env Scan --
MSG_ENV_SCANNING_EN="Scanning for .env / .key / .pem files..."
MSG_ENV_SCANNING_CN="扫描 .env / .key / .pem 文件..."

MSG_ENV_FOUND_EN="Sensitive files found (check credentials inside):"
MSG_ENV_FOUND_CN="发现以下敏感文件，请逐一检查其中的凭证是否需要轮换："

MSG_ENV_NONE_EN="No sensitive files found"
MSG_ENV_NONE_CN="未找到敏感文件"

# -- Module 09: Audit --
MSG_AUDIT_GITHUB_EN="Check GitHub security log: https://github.com/settings/security-log"
MSG_AUDIT_GITHUB_CN="检查 GitHub 安全日志: https://github.com/settings/security-log"

MSG_AUDIT_GIT_EN="Check git repos for unusual commits since"
MSG_AUDIT_GIT_CN="检查 git 仓库自以下日期起的异常提交："

MSG_AUDIT_K8S_EN="Check Kubernetes events for anomalies"
MSG_AUDIT_K8S_CN="检查 Kubernetes 事件是否有异常"

# -- Confirmation --
MSG_CONFIRM_WARN_EN="WARNING: This will modify your system (rotate keys, clean history, etc.)"
MSG_CONFIRM_WARN_CN="警告：即将修改你的系统（轮换密钥、清理历史记录等）"

MSG_CONFIRM_DRY_RUN_HINT_EN="Run with --dry-run first to preview changes."
MSG_CONFIRM_DRY_RUN_HINT_CN="建议先用 --dry-run 预览变更。"

MSG_CONFIRM_PROMPT_EN="Are you sure you want to proceed? [y/N]"
MSG_CONFIRM_PROMPT_CN="确认要继续吗？[y/N]"

MSG_CONFIRM_ABORTED_EN="Aborted by user."
MSG_CONFIRM_ABORTED_CN="用户已取消。"

# -- Footer --
MSG_COMPLETE_EN="Script execution complete!"
MSG_COMPLETE_CN="脚本执行完成！"

MSG_REMAINING_EN="Remaining manual actions:"
MSG_REMAINING_CN="剩余手动操作："

# --- Message Function ---
msg() {
    local key="$1"
    local var_name="MSG_${key}_$(echo "$CURRENT_LANG" | tr '[:lower:]' '[:upper:]')"
    local value="${!var_name:-}"
    if [[ -z "$value" ]]; then
        # Fallback to English
        var_name="MSG_${key}_EN"
        value="${!var_name:-[missing: $key]}"
    fi
    echo "$value"
}


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
    # Validate each number is 0-9
    local any_valid=false
    IFS=',' read -ra nums <<< "$SELECTED_MODULES"
    for n in "${nums[@]}"; do
        [[ -z "$n" ]] && continue
        if ! [[ "$n" =~ ^[0-9]$ ]]; then
            echo "Error: invalid module number '$n' (valid: 0-9)" >&2
            echo "Run with --help for usage information" >&2
            exit 1
        fi
        any_valid=true
    done
    if ! $any_valid; then
        echo "Error: --modules requires at least one valid module number (0-9)" >&2
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
  --modules 1,2,4     Only run specified modules
  --no-color          Disable colored output
  --help, -h          Show this help message

Announcement: $ANNOUNCEMENT_URL
Security contact: $SECURITY_EMAIL
HELPEOF
}


# --- Platform Detection ---
# OS_TYPE can be overridden via environment variable (useful for testing)
if [[ -z "${OS_TYPE:-}" ]]; then
    case "$(uname -s)" in
        Darwin) OS_TYPE="macos" ;;
        Linux)  OS_TYPE="linux" ;;
        *)      OS_TYPE="unknown" ;;
    esac
fi

OS_VERSION="${OS_VERSION:-$(uname -sr)}"

# --- Tool Detection ---
HAS_GH=false
HAS_DOCKER=false
HAS_KUBECTL=false
HAS_PGREP=false
HAS_SECURITY=false

# --- Apifox Process Pattern ---
# Matches: Apifox.app (macOS), Apifox Electron helpers (--type=), /opt/Apifox/apifox (Linux binary)
# Uses [A] trick to exclude the grep/pgrep command itself from results
APIFOX_PROC_PATTERN='[A]pifox\.app|[A]pifox.*--type=|/[Aa]pifox/[Aa]pifox'

command -v gh       &>/dev/null && HAS_GH=true
command -v docker   &>/dev/null && HAS_DOCKER=true
command -v kubectl  &>/dev/null && HAS_KUBECTL=true
command -v pgrep    &>/dev/null && HAS_PGREP=true
command -v security &>/dev/null && HAS_SECURITY=true

# --- Apifox Data Directory ---
get_apifox_data_dir() {
    if [[ "$OS_TYPE" == "macos" ]]; then
        echo "$HOME/Library/Application Support/apifox"
    else
        if [[ -d "$HOME/.config/apifox" ]]; then
            echo "$HOME/.config/apifox"
        elif [[ -d "$HOME/.local/share/apifox" ]]; then
            echo "$HOME/.local/share/apifox"
        else
            echo ""
        fi
    fi
}

# --- Apifox Version Detection ---
get_apifox_version() {
    local data_dir
    data_dir="$(get_apifox_data_dir)"
    if [[ -z "$data_dir" ]]; then
        echo ""
        return
    fi

    local app_paths=()
    if [[ "$OS_TYPE" == "macos" ]]; then
        app_paths+=("/Applications/Apifox.app/Contents/Resources/app/package.json")
    else
        # Linux: check common install locations
        app_paths+=(
            "/opt/Apifox/resources/app/package.json"
            "/opt/apifox/resources/app/package.json"
            "$HOME/.local/share/apifox/resources/app/package.json"
            "/usr/lib/apifox/resources/app/package.json"
            "/usr/share/apifox/resources/app/package.json"
        )
        # Also check snap and flatpak
        local snap_path
        snap_path="$(find /snap/apifox -name "package.json" -path "*/resources/app/*" 2>/dev/null | head -1)"
        [[ -n "$snap_path" ]] && app_paths+=("$snap_path")
    fi

    for app_path in "${app_paths[@]}"; do
        if [[ -f "$app_path" ]]; then
            grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$app_path" 2>/dev/null | head -1 | grep -o '"[^"]*"$' | tr -d '"' || true
            return
        fi
    done
    echo ""
}

# --- SSH Key Scan ---
scan_ssh_keys() {
    local keys=()
    if [[ -d "$HOME/.ssh" ]]; then
        while IFS= read -r -d '' f; do
            local basename
            basename="$(basename "$f")"
            case "$basename" in
                known_hosts*|config*|authorized_keys*|*.pub|*.bak|*.backup|compromised_backup*|*.old) continue ;;
            esac
            if head -1 "$f" 2>/dev/null | grep -qE '^\-\-\-\-\-BEGIN .* PRIVATE KEY\-\-\-\-\-'; then
                keys+=("$f")
            fi
        done < <(find "$HOME/.ssh" -maxdepth 1 -type f -print0 2>/dev/null)
    fi
    if [[ ${#keys[@]} -gt 0 ]]; then
        printf '%s\n' "${keys[@]}"
    fi
}

# --- SSH Config Host Mapping ---
get_hosts_for_key() {
    local key_path="$1"
    local config="$HOME/.ssh/config"
    if [[ ! -f "$config" ]]; then
        return
    fi
    awk -v key="$key_path" '
        /^Host / { host = $2 }
        /IdentityFile/ && index($0, key) { print host }
    ' "$config"
}

# --- Shell History Scan ---
scan_history_files() {
    local files=()
    [[ -f "$HOME/.zsh_history" ]]   && files+=("$HOME/.zsh_history")
    [[ -f "$HOME/.bash_history" ]]  && files+=("$HOME/.bash_history")
    [[ -f "$HOME/.local/share/fish/fish_history" ]] && files+=("$HOME/.local/share/fish/fish_history")
    if [[ ${#files[@]} -gt 0 ]]; then
        printf '%s\n' "${files[@]}"
    fi
}

has_sensitive_history() {
    local pattern="token|secret|password|key=|credential|auth"
    if [[ -n "${EXTRA_PATTERNS:-}" ]]; then
        pattern="${pattern}|${EXTRA_PATTERNS}"
    fi
    local found=false
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        if grep -qiE "$pattern" "$f" 2>/dev/null; then
            found=true
            break
        fi
    done <<< "$(scan_history_files)"
    $found
}

# --- Docker Registry Scan ---
scan_docker_registries() {
    local config="$HOME/.docker/config.json"
    if [[ ! -f "$config" ]]; then
        return
    fi
    # Extract registry keys directly under "auths" with a small JSON-aware scanner.
    # This avoids false negatives on pretty-printed configs and false positives on nested fields.
    awk '
        BEGIN {
            depth = 0
            in_auths = 0
            auths_depth = 0
            in_string = 0
            escaped = 0
            token = ""
            last_string = ""
            pending_registry = ""
            expect_auths_object = 0
        }
        {
            line = $0 "\n"
            for (i = 1; i <= length(line); i++) {
                c = substr(line, i, 1)

                if (in_string) {
                    if (escaped) {
                        token = token c
                        escaped = 0
                        continue
                    }
                    if (c == "\\") {
                        token = token c
                        escaped = 1
                        continue
                    }
                    if (c == "\"") {
                        in_string = 0
                        last_string = token
                        token = ""
                    } else {
                        token = token c
                    }
                    continue
                }

                if (c == "\"") {
                    in_string = 1
                    token = ""
                    continue
                }

                if (c ~ /[[:space:]]/) {
                    continue
                }

                if (c == ":") {
                    if (!in_auths && depth == 1 && last_string == "auths") {
                        expect_auths_object = 1
                    } else if (in_auths && depth == auths_depth && last_string != "") {
                        pending_registry = last_string
                    }
                    last_string = ""
                    continue
                }

                if (c == "{") {
                    depth++
                    if (expect_auths_object) {
                        in_auths = 1
                        auths_depth = depth
                        expect_auths_object = 0
                    } else if (in_auths && pending_registry != "" && depth == auths_depth + 1) {
                        if (pending_registry ~ /[.\/:]/) {
                            print pending_registry
                        }
                        pending_registry = ""
                    }
                    continue
                }

                if (c == "}") {
                    if (in_auths && depth == auths_depth) {
                        in_auths = 0
                        auths_depth = 0
                    }
                    depth--
                    pending_registry = ""
                    last_string = ""
                    continue
                }

                if (c == ",") {
                    pending_registry = ""
                    last_string = ""
                }
            }
        }
    ' "$config"
}

# --- .env File Scan ---
scan_env_files() {
    local dirs=("$HOME/Projects" "$HOME/Code" "$HOME/Work" "$HOME/Desktop" "$HOME/code" "$HOME/projects" "$HOME/dev" "$HOME/Developer" "$HOME/src")

    if [[ -n "${SCAN_DIRS:-}" ]]; then
        IFS=',' read -ra EXTRA_DIRS <<< "$SCAN_DIRS"
        dirs+=("${EXTRA_DIRS[@]}")
    fi

    local existing_dirs=()
    for d in "${dirs[@]}"; do
        [[ -d "$d" ]] && existing_dirs+=("$d")
    done

    if [[ ${#existing_dirs[@]} -eq 0 ]]; then
        return
    fi

    find "${existing_dirs[@]}" -maxdepth 5 \
        \( -name ".env" -o -name ".env.*" -o -name "*.key" -o -name "*.pem" \) \
        2>/dev/null || true
}

# --- Hosts Check ---
# Matches 127.0.0.1, 0.0.0.0, ::1 with optional trailing comments
is_c2_blocked() {
    grep -qE "^[[:space:]]*(127\.0\.0\.1|0\.0\.0\.0|::1)[[:space:]]+([^#]*[[:space:]]+)*${C2_DOMAIN}([[:space:]]|$)" /etc/hosts 2>/dev/null
}

# --- Module Applicability Array ---
declare -a MODULE_APPLICABLE
for i in {0..9}; do
    MODULE_APPLICABLE[$i]=true
done

# --- Full System Scan & Report ---
run_system_scan() {
    echo ""
    echo "============================================"
    info "  $(msg SCAN_TITLE)"
    echo "============================================"

    # Platform
    printf "  %-20s %s\n" "$(msg SCAN_PLATFORM):" "$OS_VERSION"

    # Apifox process — match Apifox.app or Apifox binary, exclude this script and grep
    local apifox_pids=""
    if $HAS_PGREP; then
        apifox_pids="$(pgrep -f "$APIFOX_PROC_PATTERN" 2>/dev/null || true)"
    fi
    if [[ -n "$apifox_pids" ]]; then
        printf "  %-20s ${RED}%s (PID: %s)${NC}\n" "$(msg SCAN_APIFOX_PROC):" "$(msg SCAN_RUNNING)" "$(echo "$apifox_pids" | tr '\n' ',' | sed 's/,$//')"
        MODULE_APPLICABLE[1]=true
    else
        printf "  %-20s %s\n" "$(msg SCAN_APIFOX_PROC):" "$(msg SCAN_NOT_RUNNING)"
        MODULE_APPLICABLE[1]=false
    fi

    # LevelDB check
    local data_dir
    data_dir="$(get_apifox_data_dir)"
    local leveldb_dir="${data_dir:+${data_dir}/Local Storage/leveldb}"
    LEVELDB_MATCHES=""
    if [[ -n "$leveldb_dir" && -d "$leveldb_dir" ]]; then
        LEVELDB_MATCHES="$(grep -arlE "rl_mc|rl_headers" "$leveldb_dir" 2>/dev/null || true)"
        if [[ -n "$LEVELDB_MATCHES" ]]; then
            printf "  %-20s ${RED}%s${NC}\n" "$(msg SCAN_LEVELDB):" "$(msg SCAN_MALICIOUS)"
        else
            printf "  %-20s %s\n" "$(msg SCAN_LEVELDB):" "$(msg SCAN_CLEAN)"
        fi
    else
        printf "  %-20s %s\n" "$(msg SCAN_LEVELDB):" "$(msg SCAN_NOT_FOUND)"
    fi

    # Version check
    local apifox_ver
    apifox_ver="$(get_apifox_version)"
    if [[ -n "$apifox_ver" ]]; then
        if [[ "$(printf '%s\n' "$FIX_VERSION" "$apifox_ver" | sort -V | head -1)" != "$FIX_VERSION" ]]; then
            printf "  %-20s ${RED}%s (%s ${FIX_VERSION}+)${NC}\n" "$(msg SCAN_VERSION):" "$apifox_ver" "$(msg SCAN_OUTDATED)"
        else
            printf "  %-20s %s\n" "$(msg SCAN_VERSION):" "$apifox_ver"
        fi
    fi

    # Hosts block
    if is_c2_blocked; then
        printf "  %-20s ${GREEN}%s${NC}\n" "$(msg SCAN_HOSTS):" "${C2_DOMAIN} $(msg SCAN_HOSTS_BLOCKED)"
    else
        printf "  %-20s ${RED}%s${NC}\n" "$(msg SCAN_HOSTS):" "${C2_DOMAIN} $(msg SCAN_HOSTS_NOT_BLOCKED)"
    fi

    echo ""
    printf "  ${BOLD}%s:${NC}\n" "$(msg SCAN_CREDS_TITLE)"

    # SSH
    SSH_KEYS="$(scan_ssh_keys)"
    local ssh_count=0
    if [[ -n "$SSH_KEYS" ]]; then
        ssh_count="$(echo "$SSH_KEYS" | wc -l | tr -d ' ')"
    fi
    if [[ "$ssh_count" -gt 0 ]]; then
        local ssh_names
        ssh_names="$(echo "$SSH_KEYS" | xargs -I{} basename {} | tr '\n' ', ' | sed 's/,$//')"
        printf "    %-18s %s (%d keys)\n" "$(msg SCAN_SSH):" "$ssh_names" "$ssh_count"
        MODULE_APPLICABLE[2]=true
    else
        printf "    %-18s %s\n" "$(msg SCAN_SSH):" "$(msg SCAN_NOT_FOUND)"
        MODULE_APPLICABLE[2]=false
    fi

    # GitHub
    if $HAS_GH; then
        local gh_user
        gh_user="$(gh auth status 2>&1 | grep -oE 'account [^ ]+' | head -1 | awk '{print $2}' || true)"
        if [[ -n "$gh_user" ]]; then
            printf "    %-18s logged in as %s\n" "$(msg SCAN_GITHUB):" "$gh_user"
            MODULE_APPLICABLE[4]=true
        else
            printf "    %-18s not logged in\n" "$(msg SCAN_GITHUB):"
            MODULE_APPLICABLE[4]=false
        fi
    else
        printf "    %-18s not installed\n" "$(msg SCAN_GITHUB):"
        MODULE_APPLICABLE[4]=false
    fi

    # K8s
    if [[ -f "$HOME/.kube/config" ]] && $HAS_KUBECTL; then
        local k8s_ctx
        k8s_ctx="$(kubectl config current-context 2>/dev/null || echo 'unknown')"
        printf "    %-18s ~/.kube/config (context: %s)\n" "$(msg SCAN_K8S):" "$k8s_ctx"
        MODULE_APPLICABLE[5]=true
    else
        printf "    %-18s %s\n" "$(msg SCAN_K8S):" "$(msg SCAN_NOT_FOUND)"
        MODULE_APPLICABLE[5]=false
    fi

    # Docker
    DOCKER_REGISTRIES="$(scan_docker_registries)"
    local docker_count=0
    if [[ -n "$DOCKER_REGISTRIES" ]]; then
        docker_count="$(echo "$DOCKER_REGISTRIES" | wc -l | tr -d ' ')"
    fi
    if [[ "$docker_count" -gt 0 ]]; then
        printf "    %-18s %d registries\n" "$(msg SCAN_DOCKER):" "$docker_count"
        MODULE_APPLICABLE[6]=true
    else
        printf "    %-18s %s\n" "$(msg SCAN_DOCKER):" "$(msg SCAN_NOT_FOUND)"
        MODULE_APPLICABLE[6]=false
    fi

    # History
    if has_sensitive_history; then
        printf "    %-18s ${YELLOW}%s${NC}\n" "$(msg SCAN_HISTORY):" "$(msg SCAN_HISTORY_SENSITIVE)"
        MODULE_APPLICABLE[3]=true
    else
        printf "    %-18s %s\n" "$(msg SCAN_HISTORY):" "$(msg SCAN_HISTORY_CLEAN)"
        MODULE_APPLICABLE[3]=false
    fi

    # .env files
    ENV_FILES="$(scan_env_files)"
    local env_count=0
    if [[ -n "$ENV_FILES" ]]; then
        env_count="$(echo "$ENV_FILES" | wc -l | tr -d ' ')"
    fi
    if [[ "$env_count" -gt 0 ]]; then
        printf "    %-18s %d found\n" "$(msg SCAN_ENV):" "$env_count"
        MODULE_APPLICABLE[8]=true
    else
        printf "    %-18s %s\n" "$(msg SCAN_ENV):" "$(msg SCAN_NOT_FOUND)"
        MODULE_APPLICABLE[8]=false
    fi

    # Module 0 (forensics) always applicable
    MODULE_APPLICABLE[0]=true
    # Module 7 (keychain) only on macOS
    if [[ "$OS_TYPE" == "macos" ]]; then
        MODULE_APPLICABLE[7]=true
    else
        MODULE_APPLICABLE[7]=false
    fi
    # Module 9 (audit) always applicable
    MODULE_APPLICABLE[9]=true

    # Module summary
    echo ""
    printf "  ${BOLD}%s:${NC}\n" "$(msg SCAN_MODULES_TITLE)"
    local mod_names=("MOD0_NAME" "MOD1_NAME" "MOD2_NAME" "MOD3_NAME" "MOD4_NAME" "MOD5_NAME" "MOD6_NAME" "MOD7_NAME" "MOD8_NAME" "MOD9_NAME")
    for i in "${!mod_names[@]}"; do
        local status_icon status_text
        if ${MODULE_APPLICABLE[$i]}; then
            status_icon="${GREEN}✓${NC}"
            status_text="$(msg SCAN_APPLICABLE)"
        else
            status_icon="${YELLOW}—${NC}"
            status_text="$(msg SCAN_SKIP)"
        fi
        printf "    [%d] %-35s %b %s\n" "$i" "$(msg "${mod_names[$i]}")" "$status_icon" "$status_text"
    done

    echo ""
}

# --- Module Selection Prompt ---
prompt_module_selection() {
    if [[ -n "$SELECTED_MODULES" ]]; then
        return 0
    fi

    if [[ "$YES_MODE" == true ]]; then
        return 0
    fi

    read -r -p "$(msg PROCEED_ALL) " choice || true
    case "${choice:-Y}" in
        n|N)
            log "$(msg USER_QUIT) $LOG_FILE"
            exit 0
            ;;
        select|SELECT)
            read -r -p "$(msg SELECT_PROMPT) " SELECTED_MODULES
            validate_selected_modules
            ;;
        *)
            # Run all applicable
            ;;
    esac
}


run_module_00() {
    section 0 "MOD0_NAME"

    if ! should_run_module 0; then
        info "$(msg NOT_APPLICABLE)"
        return
    fi

    # --- LevelDB Check ---
    info "$(msg FORENSICS_CHECKING)"
    if [[ -n "$LEVELDB_MATCHES" ]]; then
        error "$(msg FORENSICS_FOUND)"
        echo "$LEVELDB_MATCHES" | tee -a "$LOG_FILE"
    elif [[ -n "$(get_apifox_data_dir)" ]]; then
        info "$(msg FORENSICS_CLEAN)"
    else
        warn "$(msg FORENSICS_NO_DIR)"
    fi

    # --- Version Check ---
    local apifox_ver
    apifox_ver="$(get_apifox_version)"
    if [[ -n "$apifox_ver" ]]; then
        if [[ "$(printf '%s\n' "$FIX_VERSION" "$apifox_ver" | sort -V | head -1)" != "$FIX_VERSION" ]]; then
            warn "$(msg FORENSICS_VERSION_WARN)"
        fi
    fi

    # --- Hosts Block ---
    if is_c2_blocked; then
        log "$(msg FORENSICS_HOSTS_EXISTS)"
    else
        if [[ "$DRY_RUN" == true ]]; then
            info "$(msg DRY_RUN_PREFIX): add 127.0.0.1 ${C2_DOMAIN} to /etc/hosts"
        else
            if [[ "$YES_MODE" == true ]]; then
                local answer="Y"
            else
                read -r -p "$(msg FORENSICS_HOSTS_PROMPT) " answer || true
            fi
            case "${answer:-Y}" in
                n|N) warn "$(msg SKIPPED)" ;;
                *)
                    echo "127.0.0.1 ${C2_DOMAIN}" | sudo tee -a /etc/hosts > /dev/null
                    log "$(msg FORENSICS_HOSTS_ADDED)"
                    ;;
            esac
        fi
    fi
}


run_module_01() {
    section 1 "MOD1_NAME"

    if ! should_run_module 1 || ! ${MODULE_APPLICABLE[1]}; then
        info "$(msg KILL_NONE)"
        return
    fi

    # Use same precise pattern as detection in detect.sh
    local pids
    pids="$(pgrep -f "$APIFOX_PROC_PATTERN" 2>/dev/null || true)"

    if [[ -z "$pids" ]]; then
        log "$(msg KILL_NONE)"
        return
    fi

    warn "$(msg KILL_FOUND)"
    ps -p "$(echo "$pids" | tr '\n' ',' | sed 's/,$//')" -o pid,comm 2>/dev/null || true

    if ! pause; then return; fi

    if [[ "$DRY_RUN" == true ]]; then
        info "$(msg DRY_RUN_PREFIX): kill Apifox processes (PIDs: $(echo "$pids" | tr '\n' ',' | sed 's/,$//'))"
        return
    fi

    # Kill by exact PIDs instead of pattern to avoid collateral
    while IFS= read -r pid; do
        [[ -z "$pid" ]] && continue
        kill "$pid" 2>/dev/null || true
    done <<< "$pids"

    sleep 1

    # Check if any survived, force kill by PID
    local remaining
    remaining="$(pgrep -f "$APIFOX_PROC_PATTERN" 2>/dev/null || true)"
    if [[ -n "$remaining" ]]; then
        warn "$(msg KILL_FORCE)"
        while IFS= read -r pid; do
            [[ -z "$pid" ]] && continue
            kill -9 "$pid" 2>/dev/null || true
        done <<< "$remaining"
    fi
    log "$(msg KILL_DONE)"
}


run_module_02() {
    section 2 "MOD2_NAME"

    if ! should_run_module 2 || ! ${MODULE_APPLICABLE[2]}; then
        info "$(msg SSH_NONE)"
        return
    fi

    info "$(msg SSH_SCANNING)"

    # List keys with numbers
    local keys=()
    local i=1
    while IFS= read -r key; do
        [[ -z "$key" ]] && continue
        keys+=("$key")
        local hosts
        hosts="$(get_hosts_for_key "$key")"
        local host_info=""
        [[ -n "$hosts" ]] && host_info=" → $hosts"
        printf "  [%d] %s%s\n" "$i" "$(basename "$key")" "$host_info"
        ((i++))
    done <<< "$SSH_KEYS"

    if [[ ${#keys[@]} -eq 0 ]]; then
        log "$(msg SSH_NONE)"
        return
    fi

    echo ""
    if [[ "$YES_MODE" == true ]]; then
        local selection="all"
    else
        read -r -p "$(msg SSH_SELECT) " selection || true
    fi

    local selected_keys=()
    if [[ "$selection" == "all" ]]; then
        selected_keys=("${keys[@]}")
    else
        IFS=',' read -ra nums <<< "$selection"
        for n in "${nums[@]}"; do
            n="$(echo "$n" | tr -d ' ')"
            if [[ "$n" =~ ^[0-9]+$ ]] && [[ "$n" -ge 1 ]] && [[ "$n" -le ${#keys[@]} ]]; then
                selected_keys+=("${keys[$((n-1))]}")
            fi
        done
    fi

    if [[ ${#selected_keys[@]} -eq 0 ]]; then
        warn "$(msg SKIPPED)"
        return
    fi

    # Get email for new keys
    local email
    email="$(git config user.email 2>/dev/null || true)"
    if [[ -z "$email" ]]; then
        read -r -p "Email for new SSH keys: " email || true
    fi

    local backup_dir="$HOME/.ssh/compromised_backup_$(date +%Y%m%d_%H%M%S)"
    run_or_dry "create backup dir $backup_dir" mkdir -p "$backup_dir"

    for key in "${selected_keys[@]}"; do
        local keyname
        keyname="$(basename "$key")"

        # Backup
        run_or_dry "backup $keyname" mv "$key" "$backup_dir/"
        if [[ "$DRY_RUN" != true ]]; then
            log "$(msg SSH_BACKUP): $keyname"
        fi
        if [[ -f "${key}.pub" ]]; then
            run_or_dry "backup ${keyname}.pub" mv "${key}.pub" "$backup_dir/"
        fi

        # Generate new ed25519 key at same path
        if [[ "$DRY_RUN" != true ]]; then
            ssh-keygen -t ed25519 -C "$email" -f "$key"
            log "$(msg SSH_GENERATED): $keyname"

            # Show public key
            echo ""
            info "$(msg SSH_PUBKEY)"
            echo "--- $keyname ---"
            cat "${key}.pub"

            # Show host hint
            local hosts
            hosts="$(get_hosts_for_key "$key")"
            if [[ -n "$hosts" ]]; then
                info "$(msg SSH_PLATFORM_HINT) $hosts"
            fi
        else
            info "$(msg DRY_RUN_PREFIX): generate ed25519 key at $key"
        fi
    done

    echo ""
    manual "Update public keys on GitHub / GitLab / other platforms for the rotated keys above"
}


run_module_03() {
    section 3 "MOD3_NAME"

    if ! should_run_module 3 || ! ${MODULE_APPLICABLE[3]}; then
        info "$(msg NOT_APPLICABLE)"
        return
    fi

    info "$(msg HISTORY_CLEANING)"

    local pattern="token|secret|password=|secret=|SECRET=|key=|credential|auth"
    if [[ -n "${EXTRA_PATTERNS:-}" ]]; then
        pattern="${pattern}|${EXTRA_PATTERNS}"
    fi

    if ! pause; then return; fi

    local history_files
    history_files="$(scan_history_files)"
    if [[ -z "$history_files" ]]; then
        info "$(msg HISTORY_NOT_FOUND)"
        return
    fi

    while IFS= read -r hfile; do
        [[ -z "$hfile" ]] && continue
        local fname
        fname="$(basename "$hfile")"
        local backup="${hfile}.backup"

        run_or_dry "backup $fname" cp "$hfile" "$backup"

        if [[ "$DRY_RUN" != true ]]; then
            local before after
            before="$(wc -l < "$hfile" | tr -d ' ')"
            grep -v -iE "$pattern" "$backup" > "$hfile" || true
            after="$(wc -l < "$hfile" | tr -d ' ')"
            log "$fname $(msg HISTORY_CLEANED) (${before} → ${after} $(msg HISTORY_LINES)), $(msg HISTORY_BACKUP) ${backup}"
        else
            info "$(msg DRY_RUN_PREFIX): clean $fname"
        fi
    done <<< "$history_files"

    echo ""
    manual "Rotate any tokens/secrets that appeared in your shell history (ngrok, API keys, etc.)"
}


run_module_04() {
    section 4 "MOD4_NAME"

    if ! should_run_module 4 || ! ${MODULE_APPLICABLE[4]}; then
        if ! $HAS_GH; then
            warn "$(msg GITHUB_NO_CLI)"
        fi
        return
    fi

    info "$(msg GITHUB_STATUS)"
    gh auth status 2>&1 | tee -a "$LOG_FILE" || true

    if ! pause; then return; fi

    if [[ "$DRY_RUN" == true ]]; then
        info "$(msg DRY_RUN_PREFIX): logout and re-login GitHub CLI"
    else
        gh auth logout 2>/dev/null || true
        log "$(msg GITHUB_LOGOUT)"
        echo ""
        info "$(msg GITHUB_LOGIN)"
        gh auth login
        log "$(msg GITHUB_DONE)"
    fi

    echo ""
    manual "$(msg GITHUB_MANUAL_TOKENS)"
    manual "$(msg GITHUB_MANUAL_SESSIONS)"
}


run_module_05() {
    section 5 "MOD5_NAME"

    if ! should_run_module 5 || ! ${MODULE_APPLICABLE[5]}; then
        info "$(msg K8S_NONE)"
        return
    fi

    local ctx
    ctx="$(kubectl config current-context 2>/dev/null || echo 'unknown')"
    info "$(msg K8S_FOUND) $ctx"

    if ! pause; then return; fi

    local backup="$HOME/.kube/config.compromised_backup_$(date +%Y%m%d_%H%M%S)"
    run_or_dry "backup kubeconfig" cp "$HOME/.kube/config" "$backup"
    if [[ "$DRY_RUN" != true ]]; then
        log "$(msg K8S_BACKUP) $backup"
    fi

    echo ""
    manual "$(msg K8S_MANUAL)"
}


run_module_06() {
    section 6 "MOD6_NAME"

    if ! should_run_module 6 || ! ${MODULE_APPLICABLE[6]}; then
        if ! $HAS_DOCKER; then
            info "$(msg DOCKER_NO_CLI)"
        else
            info "$(msg DOCKER_NO_CONFIG)"
        fi
        return
    fi

    info "$(msg DOCKER_REGISTRIES)"
    echo "$DOCKER_REGISTRIES" | tee -a "$LOG_FILE"

    if ! pause; then return; fi

    if [[ "$DRY_RUN" == true ]]; then
        info "$(msg DRY_RUN_PREFIX): logout all Docker registries"
    else
        while IFS= read -r registry; do
            [[ -z "$registry" ]] && continue
            docker logout "$registry" 2>/dev/null || true
        done <<< "$DOCKER_REGISTRIES"
        log "$(msg DOCKER_LOGOUT)"
    fi

    echo ""
    manual "$(msg DOCKER_MANUAL)"
}


run_module_07() {
    section 7 "MOD7_NAME"

    if ! should_run_module 7 || ! ${MODULE_APPLICABLE[7]}; then
        info "$(msg NOT_APPLICABLE)"
        return
    fi

    if [[ "$OS_TYPE" != "macos" ]]; then
        info "$(msg KEYCHAIN_LINUX)"
        return
    fi

    info "$(msg KEYCHAIN_SEARCHING)"
    local items
    items="$(security find-generic-password -l "apifox" 2>&1 || true)"

    if echo "$items" | grep -q "could not be found"; then
        info "$(msg KEYCHAIN_NONE)"
    else
        warn "$(msg KEYCHAIN_FOUND)"
        echo "$items" | tee -a "$LOG_FILE"
    fi

    echo ""
    manual "$(msg KEYCHAIN_MANUAL)"
}


run_module_08() {
    section 8 "MOD8_NAME"

    if ! should_run_module 8 || ! ${MODULE_APPLICABLE[8]}; then
        info "$(msg NOT_APPLICABLE)"
        return
    fi

    info "$(msg ENV_SCANNING)"

    if [[ -n "$ENV_FILES" ]]; then
        warn "$(msg ENV_FOUND)"
        echo "$ENV_FILES" | tee -a "$LOG_FILE"
    else
        info "$(msg ENV_NONE)"
    fi
}


run_module_09() {
    section 9 "MOD9_NAME"

    if ! should_run_module 9; then
        info "$(msg NOT_APPLICABLE)"
        return
    fi

    manual "$(msg AUDIT_GITHUB)"

    echo ""
    manual "$(msg AUDIT_GIT) ${RISK_START}"
    info "  git log --since=\"${RISK_START}\" --oneline"

    if $HAS_KUBECTL && [[ -f "$HOME/.kube/config" ]]; then
        echo ""
        manual "$(msg AUDIT_K8S)"
        if [[ "$DRY_RUN" != true ]]; then
            kubectl get events --sort-by='.lastTimestamp' -A 2>/dev/null | head -20 | tee -a "$LOG_FILE" || true
        fi
    fi
}


# --- Check if module actually ran (selected + applicable) ---
module_ran() {
    local mod_num="$1"
    should_run_module "$mod_num" && ${MODULE_APPLICABLE[$mod_num]}
}

# --- Summary & Manual Checklist ---
print_summary() {
    echo ""
    echo "============================================================"
    log "$(msg COMPLETE)"
    echo "============================================================"
    echo ""
    echo "$(msg LOG_SAVED): $LOG_FILE"
    echo ""
    echo "$(msg REMAINING)"
    # Dynamic checklist based on what actually ran
    if module_ran 2; then
        echo "  □ $(msg SSH_PUBKEY) → GitHub / GitLab"
    fi
    if module_ran 4; then
        echo "  □ $(msg GITHUB_MANUAL_TOKENS)"
        echo "  □ $(msg GITHUB_MANUAL_SESSIONS)"
    fi
    if module_ran 3; then
        echo "  □ Rotate leaked tokens (ngrok, etc.)"
    fi
    if module_ran 5; then
        echo "  □ $(msg K8S_MANUAL)"
    fi
    if module_ran 6; then
        echo "  □ $(msg DOCKER_MANUAL)"
    fi
    if module_ran 7; then
        echo "  □ $(msg KEYCHAIN_MANUAL)"
    fi
    echo ""
}

# --- Main Execution ---
main() {
    # Handle help flag
    if [[ "${SHOW_HELP:-false}" == true ]]; then
        show_help
        exit 0
    fi

    # Validate --modules input early
    validate_selected_modules

    # Banner
    echo "============================================================"
    echo "  $(msg BANNER_TITLE) v${VERSION}"
    echo "  $(date)"
    echo "  $(msg LOG_SAVED): $LOG_FILE"
    echo ""
    echo "  Risk window: ${RISK_START} — ${RISK_END}"
    echo "  Fix version: ${FIX_VERSION}+"
    echo "  Announcement: ${ANNOUNCEMENT_URL}"
    echo "============================================================"

    # System scan
    run_system_scan

    # Module selection
    prompt_module_selection

    # Second confirmation before making real changes
    if [[ "$DRY_RUN" != true && "$YES_MODE" != true ]]; then
        echo ""
        warn "$(msg CONFIRM_WARN)"
        info "$(msg CONFIRM_DRY_RUN_HINT)"
        echo ""
        read -r -p "$(msg CONFIRM_PROMPT) " confirm || true
        case "${confirm:-}" in
            y|Y|yes|YES)
                ;;
            *)
                log "$(msg CONFIRM_ABORTED)"
                exit 0
                ;;
        esac
    fi

    # Execute only selected + applicable modules
    local mod_funcs=(run_module_00 run_module_01 run_module_02 run_module_03 run_module_04 run_module_05 run_module_06 run_module_07 run_module_08 run_module_09)
    for i in "${!mod_funcs[@]}"; do
        if module_ran "$i"; then
            ${mod_funcs[$i]}
        fi
    done

    # Summary
    print_summary
}

main

