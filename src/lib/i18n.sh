#!/usr/bin/env bash

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

MSG_SCAN_HOSTS_ALL_BLOCKED_EN="domains blocked"
MSG_SCAN_HOSTS_ALL_BLOCKED_CN="个域名已屏蔽"

MSG_SCAN_HOSTS_PARTIAL_EN="domains blocked (incomplete)"
MSG_SCAN_HOSTS_PARTIAL_CN="个域名已屏蔽（不完整）"

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

MSG_SCAN_NPMRC_TOKEN_EN="auth token found"
MSG_SCAN_NPMRC_TOKEN_CN="发现认证 token"

MSG_SCAN_NPMRC_NO_TOKEN_EN="no auth token"
MSG_SCAN_NPMRC_NO_TOKEN_CN="无认证 token"

MSG_SCAN_SVN_FOUND_EN="found (credentials may be cached)"
MSG_SCAN_SVN_FOUND_CN="存在（可能缓存了凭证）"

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

MSG_MOD8_NAME_EN="Scan Sensitive Files"
MSG_MOD8_NAME_CN="扫描敏感文件"

MSG_MOD9_NAME_EN="Audit Activity"
MSG_MOD9_NAME_CN="审计异常活动"

MSG_MOD10_NAME_EN="Rotate npm Token"
MSG_MOD10_NAME_CN="轮换 npm Token"

# -- Module 00: Forensics --
MSG_FORENSICS_CHECKING_EN="Checking Apifox LevelDB for malicious markers (_rl_headers, _rl_mc, common.accessToken, af_uuid, etc.)..."
MSG_FORENSICS_CHECKING_CN="检查 Apifox LevelDB 是否存在恶意标记（_rl_headers、_rl_mc、common.accessToken、af_uuid 等）..."

MSG_FORENSICS_FOUND_EN="Malicious markers found! Matched files:"
MSG_FORENSICS_FOUND_CN="发现恶意载荷痕迹！匹配文件："

MSG_FORENSICS_CLEAN_EN="No known malicious markers found in LevelDB (does not guarantee safety, recommend continuing)"
MSG_FORENSICS_CLEAN_CN="未在 LevelDB 中发现已知恶意标记（但不代表安全，建议继续执行）"

MSG_FORENSICS_NO_DIR_EN="Apifox LevelDB directory not found"
MSG_FORENSICS_NO_DIR_CN="未找到 Apifox LevelDB 目录"

MSG_FORENSICS_HOSTS_PROMPT_EN="Add all malicious domains to /etc/hosts? (requires sudo) [Y/n]"
MSG_FORENSICS_HOSTS_PROMPT_CN="添加所有恶意域名到 /etc/hosts？（需要 sudo）[Y/n]"

MSG_FORENSICS_HOSTS_ADDED_EN="Hosts entries added for malicious domains"
MSG_FORENSICS_HOSTS_ADDED_CN="已添加恶意域名的 Hosts 条目"

MSG_FORENSICS_HOSTS_EXISTS_EN="All malicious domains are already blocked in /etc/hosts"
MSG_FORENSICS_HOSTS_EXISTS_CN="所有恶意域名已在 /etc/hosts 中被屏蔽"

MSG_FORENSICS_HOSTS_PARTIAL_EN="Some malicious domains are not yet blocked, adding remaining:"
MSG_FORENSICS_HOSTS_PARTIAL_CN="部分恶意域名尚未屏蔽，正在添加剩余域名："

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
MSG_ENV_SCANNING_EN="Scanning for sensitive files (.env, .key, .pem, credentials)..."
MSG_ENV_SCANNING_CN="扫描敏感文件（.env、.key、.pem、凭证文件）..."

MSG_ENV_FOUND_EN=".env / .key / .pem files found (check credentials inside):"
MSG_ENV_FOUND_CN="发现 .env / .key / .pem 文件，请逐一检查其中的凭证是否需要轮换："

MSG_ENV_NONE_EN="No .env / .key / .pem files found"
MSG_ENV_NONE_CN="未找到 .env / .key / .pem 文件"

MSG_ENV_EXTRA_CHECK_EN="Checking additional files that may have been exfiltrated:"
MSG_ENV_EXTRA_CHECK_CN="检查可能已被窃取的其他敏感文件："

# -- Module 09: Audit --
MSG_AUDIT_GITHUB_EN="Check GitHub security log: https://github.com/settings/security-log"
MSG_AUDIT_GITHUB_CN="检查 GitHub 安全日志: https://github.com/settings/security-log"

MSG_AUDIT_GIT_EN="Check git repos for unusual commits since"
MSG_AUDIT_GIT_CN="检查 git 仓库自以下日期起的异常提交："

MSG_AUDIT_K8S_EN="Check Kubernetes events for anomalies"
MSG_AUDIT_K8S_CN="检查 Kubernetes 事件是否有异常"

MSG_AUDIT_SSH_LOGIN_EN="Check server login logs for anomalous SSH logins (e.g., /var/log/auth.log, last, lastlog)"
MSG_AUDIT_SSH_LOGIN_CN="检查服务器登录日志，排查异常 SSH 登录（如 /var/log/auth.log、last、lastlog）"

MSG_AUDIT_NETWORK_EN="Check network/firewall logs for connections to the malicious domains below"
MSG_AUDIT_NETWORK_CN="检查网络/防火墙日志，排查是否有到以下恶意域名的连接记录"

MSG_AUDIT_C2_DOMAINS_EN="Known malicious domains (block via firewall/DNS):"
MSG_AUDIT_C2_DOMAINS_CN="已知恶意域名（建议通过防火墙/DNS 层面阻断）："

# -- Module 10: npm --
MSG_NPM_FOUND_EN="Found npm auth tokens in ~/.npmrc:"
MSG_NPM_FOUND_CN="在 ~/.npmrc 中发现 npm 认证 token："

MSG_NPM_BACKUP_EN="~/.npmrc backed up to"
MSG_NPM_BACKUP_CN="~/.npmrc 已备份到"

MSG_NPM_MANUAL_EN="Revoke the above npm tokens at https://www.npmjs.com/settings/tokens and re-login with: npm login"
MSG_NPM_MANUAL_CN="请在 https://www.npmjs.com/settings/tokens 撤销上述 token，然后执行 npm login 重新登录"

MSG_NPM_NONE_EN="No npm auth tokens found in ~/.npmrc"
MSG_NPM_NONE_CN="~/.npmrc 中未发现认证 token"

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

# -- Module 11: Windows Credential Manager --
MSG_MOD11_NAME_EN="Windows Credential Manager"
MSG_MOD11_NAME_CN="Windows 凭证管理器"

MSG_WINCRED_SEARCHING_EN="Searching Windows Credential Manager for apifox-related entries..."
MSG_WINCRED_SEARCHING_CN="在 Windows 凭证管理器中搜索 apifox 相关条目..."

MSG_WINCRED_FOUND_EN="Found apifox-related credential entries:"
MSG_WINCRED_FOUND_CN="发现 apifox 相关凭证条目："

MSG_WINCRED_NONE_EN="No apifox-related entries found in Windows Credential Manager"
MSG_WINCRED_NONE_CN="Windows 凭证管理器中未找到 apifox 相关条目"

MSG_WINCRED_REMOVE_HINT_EN="Review and remove suspicious entries:"
MSG_WINCRED_REMOVE_HINT_CN="检查并删除可疑条目："

MSG_WINCRED_GIT_CREDS_EN="Git credentials file found (may have been exfiltrated)"
MSG_WINCRED_GIT_CREDS_CN="发现 Git 凭证文件（可能已被窃取）"

MSG_WINCRED_MANUAL_EN="Open Windows Credential Manager (Control Panel > Credential Manager) to manually review stored credentials"
MSG_WINCRED_MANUAL_CN="请打开 Windows 凭证管理器（控制面板 > 凭证管理器）手动检查存储的凭证"

MSG_WINCRED_WINDOWS_ONLY_EN="Windows Credential Manager check is Windows-only"
MSG_WINCRED_WINDOWS_ONLY_CN="Windows 凭证管理器检查仅适用于 Windows"

MSG_SCAN_WINCRED_EN="Windows Credentials"
MSG_SCAN_WINCRED_CN="Windows 凭证"

MSG_FORENSICS_HOSTS_WIN_ADMIN_EN="Cannot write to hosts file - run as Administrator, or add manually:"
MSG_FORENSICS_HOSTS_WIN_ADMIN_CN="无法写入 hosts 文件 - 请以管理员身份运行，或手动添加："
