#Requires -Version 5.1
<#
.SYNOPSIS
    Apifox Supply Chain Attack Incident Response Tool - Windows Edition

.DESCRIPTION
    Scans your Windows system for signs of the Apifox supply chain incident
    (March 4 - March 22, 2026) and guides you through credential rotation.

.PARAMETER Lang
    Force language: 'en' or 'cn' (default: auto-detect from system locale)

.PARAMETER ScanDirs
    Additional directories to scan for .env files (comma-separated)

.PARAMETER ExtraPatterns
    Additional sensitive regex patterns for history cleanup

.PARAMETER DryRun
    Show what would be done without making changes

.PARAMETER Yes
    Skip all confirmations (for automation)

.PARAMETER Modules
    Only run specified modules, e.g. "1,2,4" (0-11)

.PARAMETER NoColor
    Disable colored output

.EXAMPLE
    .\fix.ps1
    .\fix.ps1 -DryRun
    .\fix.ps1 -Modules "0,1,8" -Yes
    .\fix.ps1 -Lang cn
#>

[CmdletBinding()]
param(
    [string]$Lang = "",
    [string]$ScanDirs = "",
    [string]$ExtraPatterns = "",
    [switch]$DryRun,
    [switch]$Yes,
    [string]$Modules = "",
    [switch]$NoColor
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ============================================================
# Constants
# ============================================================
$VERSION       = "1.0.0"
$SCRIPT_NAME   = "apifox-incident-fix"
$RISK_START    = "2026-03-04"
$RISK_END      = "2026-03-22"
$FIX_VERSION   = [version]"2.8.19"
$C2_DOMAIN     = "apifox.it.com"
$C2_DOMAINS    = @(
    "apifox.it.com"
    "cdn.openroute.dev"
    "upgrade.feishu.it.com"
    "system.toshinkyo.or.jp"
    "panel.feishu.it.com"
    "d.feishu.it.com"
    "api.feishu.it.com"
    "ns.feishu.it.com"
    "ns.openroute.dev"
)
$ANNOUNCEMENT_URL = "https://mp.weixin.qq.com/s/GpACQdnhVNsMn51cm4hZig"
$SECURITY_EMAIL   = "security@apifox.com"
$HOSTS_FILE       = "$env:SystemRoot\System32\drivers\etc\hosts"
$LOG_FILE         = "$env:USERPROFILE\${SCRIPT_NAME}-$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# ============================================================
# Color helpers
# ============================================================
function Write-Log {
    param([string]$Message, [string]$Color = "Green", [string]$Prefix = "[+]")
    if (-not $NoColor) {
        Write-Host "$Prefix $Message" -ForegroundColor $Color
    } else {
        Write-Host "$Prefix $Message"
    }
    Add-Content -Path $LOG_FILE -Value "$Prefix $Message" -Encoding UTF8
}
function Log-OK    { param([string]$m) Write-Log $m "Green"  "[+]" }
function Log-Warn  { param([string]$m) Write-Log $m "Yellow" "[!]" }
function Log-Error { param([string]$m) Write-Log $m "Red"    "[x]" }
function Log-Info  { param([string]$m) Write-Log $m "Cyan"   "[i]" }
function Log-Manual{ param([string]$m) Write-Log $m "Yellow" "[Manual]" }

# ============================================================
# i18n
# ============================================================
$msgs = @{}

# Language detection
if ($Lang -ne "") {
    $LANG = $Lang
} elseif ((Get-Culture).Name -match "^zh") {
    $LANG = "cn"
} else {
    $LANG = "en"
}

$msgs["BANNER_TITLE"]     = @{ en = "Apifox Supply Chain Incident Response Tool"; cn = "Apifox 供应链攻击应急响应工具" }
$msgs["SCAN_TITLE"]       = @{ en = "System Scan"; cn = "系统扫描" }
$msgs["SCAN_PLATFORM"]    = @{ en = "Platform"; cn = "平台" }
$msgs["SCAN_APIFOX_PROC"] = @{ en = "Apifox Process"; cn = "Apifox 进程" }
$msgs["SCAN_RUNNING"]     = @{ en = "RUNNING"; cn = "运行中" }
$msgs["SCAN_NOT_RUNNING"] = @{ en = "Not running"; cn = "未运行" }
$msgs["SCAN_LEVELDB"]     = @{ en = "Apifox LevelDB"; cn = "Apifox LevelDB" }
$msgs["SCAN_MALICIOUS"]   = @{ en = "MALICIOUS MARKERS FOUND"; cn = "发现恶意标记" }
$msgs["SCAN_CLEAN"]       = @{ en = "No known markers found"; cn = "未发现已知恶意标记" }
$msgs["SCAN_NOT_FOUND"]   = @{ en = "Not found"; cn = "未找到" }
$msgs["SCAN_VERSION"]     = @{ en = "Apifox Version"; cn = "Apifox 版本" }
$msgs["SCAN_OUTDATED"]    = @{ en = "OUTDATED - please upgrade to"; cn = "版本过旧 - 请升级到" }
$msgs["SCAN_HOSTS"]       = @{ en = "Hosts Block"; cn = "Hosts 屏蔽" }
$msgs["SCAN_HOSTS_ALL_BLOCKED"] = @{ en = "domains blocked"; cn = "个域名已屏蔽" }
$msgs["SCAN_HOSTS_PARTIAL"]     = @{ en = "domains blocked (incomplete)"; cn = "个域名已屏蔽（不完整）" }
$msgs["SCAN_HOSTS_NOT_BLOCKED"] = @{ en = "NOT blocked"; cn = "未屏蔽" }
$msgs["SCAN_SSH"]         = @{ en = "SSH Keys"; cn = "SSH 密钥" }
$msgs["SCAN_GITHUB"]      = @{ en = "GitHub CLI"; cn = "GitHub CLI" }
$msgs["SCAN_K8S"]         = @{ en = "Kubernetes"; cn = "Kubernetes" }
$msgs["SCAN_DOCKER"]      = @{ en = "Docker"; cn = "Docker" }
$msgs["SCAN_HISTORY"]     = @{ en = "Shell History"; cn = "Shell History" }
$msgs["SCAN_HISTORY_SENSITIVE"] = @{ en = "sensitive tokens found"; cn = "发现敏感 token" }
$msgs["SCAN_HISTORY_CLEAN"]     = @{ en = "no sensitive tokens found"; cn = "未发现敏感 token" }
$msgs["SCAN_ENV"]         = @{ en = ".env files"; cn = ".env 文件" }
$msgs["SCAN_NPMRC_TOKEN"] = @{ en = "auth token found"; cn = "发现认证 token" }
$msgs["SCAN_NPMRC_NO_TOKEN"] = @{ en = "no auth token"; cn = "无认证 token" }
$msgs["SCAN_WINCRED"]     = @{ en = "Windows Credentials"; cn = "Windows 凭证" }
$msgs["SCAN_APPLICABLE"]  = @{ en = "applicable"; cn = "适用" }
$msgs["SCAN_SKIP"]        = @{ en = "skip"; cn = "跳过" }
$msgs["SCAN_MODULES_TITLE"] = @{ en = "Modules to run"; cn = "将执行的模块" }
$msgs["PROCEED_ALL"]      = @{ en = "Proceed with all applicable modules? [Y/n/select]"; cn = "执行所有适用模块？[Y(是)/n(否)/select(选择)]" }
$msgs["SELECT_PROMPT"]    = @{ en = "Enter module numbers (comma-separated, e.g., 1,2,4):"; cn = "输入模块编号（逗号分隔，如 1,2,4）：" }
$msgs["PAUSE"]            = @{ en = "Press Enter to continue, 's' to skip, 'q' to quit"; cn = "按 Enter 继续，输入 s 跳过，输入 q 退出" }
$msgs["SKIPPED"]          = @{ en = "Skipped"; cn = "已跳过" }
$msgs["USER_QUIT"]        = @{ en = "User quit. Log saved to"; cn = "用户退出，日志已保存到" }
$msgs["DRY_RUN_PREFIX"]   = @{ en = "[DRY RUN] Would"; cn = "[模拟运行] 将会" }
$msgs["COMPLETE"]         = @{ en = "Script execution complete!"; cn = "脚本执行完成！" }
$msgs["LOG_SAVED"]        = @{ en = "Log saved to"; cn = "日志已保存到" }
$msgs["REMAINING"]        = @{ en = "Remaining manual actions:"; cn = "剩余手动操作：" }
$msgs["CONFIRM_WARN"]     = @{ en = "WARNING: This will modify your system (rotate keys, clean history, etc.)"; cn = "警告：即将修改你的系统（轮换密钥、清理历史记录等）" }
$msgs["CONFIRM_DRY_RUN_HINT"] = @{ en = "Run with -DryRun first to preview changes."; cn = "建议先用 -DryRun 预览变更。" }
$msgs["CONFIRM_PROMPT"]   = @{ en = "Are you sure you want to proceed? [y/N]"; cn = "确认要继续吗？[y/N]" }
$msgs["CONFIRM_ABORTED"]  = @{ en = "Aborted by user."; cn = "用户已取消。" }

# Module names
$msgs["MOD0_NAME"]  = @{ en = "Forensics & Hosts Block"; cn = "取证确认 & Hosts 屏蔽" }
$msgs["MOD1_NAME"]  = @{ en = "Kill Apifox Process"; cn = "终止 Apifox 进程" }
$msgs["MOD2_NAME"]  = @{ en = "Rotate SSH Keys"; cn = "轮换 SSH 密钥" }
$msgs["MOD3_NAME"]  = @{ en = "Clean Shell History"; cn = "清理 Shell History" }
$msgs["MOD4_NAME"]  = @{ en = "Rotate GitHub Token"; cn = "轮换 GitHub Token" }
$msgs["MOD5_NAME"]  = @{ en = "Rotate K8s Credentials"; cn = "轮换 K8s 凭证" }
$msgs["MOD6_NAME"]  = @{ en = "Rotate Docker Credentials"; cn = "轮换 Docker 凭证" }
$msgs["MOD7_NAME"]  = @{ en = "Check macOS Keychain (N/A on Windows)"; cn = "检查 macOS 钥匙串（Windows 不适用）" }
$msgs["MOD8_NAME"]  = @{ en = "Scan Sensitive Files"; cn = "扫描敏感文件" }
$msgs["MOD9_NAME"]  = @{ en = "Audit Activity"; cn = "审计异常活动" }
$msgs["MOD10_NAME"] = @{ en = "Rotate npm Token"; cn = "轮换 npm Token" }
$msgs["MOD11_NAME"] = @{ en = "Windows Credential Manager"; cn = "Windows 凭证管理器" }

function msg([string]$key) {
    if ($msgs.ContainsKey($key) -and $msgs[$key].ContainsKey($LANG)) {
        return $msgs[$key][$LANG]
    } elseif ($msgs.ContainsKey($key)) {
        return $msgs[$key]["en"]
    }
    return "[missing: $key]"
}

# ============================================================
# Admin check
# ============================================================
$IS_ADMIN = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ============================================================
# Platform detection
# ============================================================
$OS_VERSION = "$([System.Environment]::OSVersion.VersionString)"
$HAS_GH     = $null -ne (Get-Command gh -ErrorAction SilentlyContinue)
$HAS_DOCKER = $null -ne (Get-Command docker -ErrorAction SilentlyContinue)
$HAS_KUBECTL = $null -ne (Get-Command kubectl -ErrorAction SilentlyContinue)

# ============================================================
# Module applicability
# ============================================================
$MODULE_APPLICABLE = @{}
for ($i = 0; $i -le 11; $i++) { $MODULE_APPLICABLE[$i] = $true }
$MODULE_APPLICABLE[7] = $false  # macOS Keychain not applicable on Windows

# ============================================================
# Helpers
# ============================================================
function Get-ApifoxDataDir {
    $candidates = @(
        "$env:APPDATA\apifox",
        "$env:APPDATA\Apifox",
        "$env:LOCALAPPDATA\apifox",
        "$env:LOCALAPPDATA\Apifox"
    )
    foreach ($p in $candidates) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Get-ApifoxVersion {
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\Apifox\resources\app\package.json",
        "$env:LOCALAPPDATA\Apifox\resources\app\package.json",
        "C:\Program Files\Apifox\resources\app\package.json",
        "C:\Program Files (x86)\Apifox\resources\app\package.json"
    )
    foreach ($p in $candidates) {
        if (Test-Path $p) {
            try {
                $pkg = Get-Content $p -Raw | ConvertFrom-Json
                return [version]$pkg.version
            } catch { }
        }
    }
    return $null
}

function Get-ApifoxProcesses {
    return Get-Process -Name "Apifox" -ErrorAction SilentlyContinue
}

function Get-LevelDBMatches {
    $dataDir = Get-ApifoxDataDir
    if (-not $dataDir) { return @() }
    $leveldbDir = Join-Path $dataDir "Local Storage\leveldb"
    if (-not (Test-Path $leveldbDir)) { return @() }

    $patterns = @("_rl_mc", "_rl_headers", "common.accessToken", "af_uuid", "af_os", "af_user", "af_name", "af_apifox_user", "af_apifox_name")
    $matches_ = @()
    Get-ChildItem $leveldbDir -File -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $content = [System.IO.File]::ReadAllText($_.FullName)
            foreach ($p in $patterns) {
                if ($content -match [regex]::Escape($p)) {
                    $matches_ += $_.FullName
                    break
                }
            }
        } catch { }
    }
    return $matches_
}

function Get-BlockedC2Count {
    if (-not (Test-Path $HOSTS_FILE)) { return 0 }
    $hostsContent = Get-Content $HOSTS_FILE -ErrorAction SilentlyContinue
    $blocked = 0
    foreach ($domain in $C2_DOMAINS) {
        $pattern = "^\s*(127\.0\.0\.1|0\.0\.0\.0|::1)\s+.*\b" + [regex]::Escape($domain) + "\b"
        if ($hostsContent -match $pattern) { $blocked++ }
    }
    return $blocked
}

function Get-UnblockedC2Domains {
    $hostsContent = @()
    if (Test-Path $HOSTS_FILE) {
        $hostsContent = Get-Content $HOSTS_FILE -ErrorAction SilentlyContinue
    }
    $unblocked = @()
    foreach ($domain in $C2_DOMAINS) {
        $pattern = "^\s*(127\.0\.0\.1|0\.0\.0\.0|::1)\s+.*\b" + [regex]::Escape($domain) + "\b"
        if (-not ($hostsContent -match $pattern)) {
            $unblocked += $domain
        }
    }
    return $unblocked
}

function Get-SSHKeys {
    $sshDir = "$env:USERPROFILE\.ssh"
    if (-not (Test-Path $sshDir)) { return @() }
    $keys = @()
    Get-ChildItem $sshDir -File | ForEach-Object {
        $name = $_.Name
        # Skip non-key files
        if ($name -match "^(known_hosts|config|authorized_keys)") { return }
        if ($name -match "\.(pub|bak|backup|old)$") { return }
        if ($name -match "^compromised_backup") { return }
        # Check for PEM header or openssh magic
        try {
            $header = Get-Content $_.FullName -TotalCount 3 -ErrorAction SilentlyContinue
            $headerStr = $header -join ""
            if ($headerStr -match "BEGIN .*(PRIVATE KEY|OPENSSH PRIVATE)" -or
                $headerStr -match "openssh-key-v1" -or
                ($name -match "^id_" -and $name -notmatch "\.")) {
                $keys += $_.FullName
            }
        } catch { }
    }
    return $keys
}

function Get-HistoryFiles {
    $files = @()
    # PowerShell history (most common on Windows)
    $psHistory = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $psHistory) { $files += $psHistory }
    # Git Bash history
    $bashHistory = "$env:USERPROFILE\.bash_history"
    if (Test-Path $bashHistory) { $files += $bashHistory }
    return $files
}

function Test-SensitiveHistory {
    $patterns = @("token", "secret", "password", "key=", "credential", "auth")
    if ($ExtraPatterns) { $patterns += $ExtraPatterns -split "," }
    foreach ($f in Get-HistoryFiles) {
        try {
            $content = Get-Content $f -Raw -ErrorAction SilentlyContinue
            foreach ($p in $patterns) {
                if ($content -imatch $p) { return $true }
            }
        } catch { }
    }
    return $false
}

function Get-DockerRegistries {
    $configPath = "$env:USERPROFILE\.docker\config.json"
    if (-not (Test-Path $configPath)) { return @() }
    try {
        $cfg = Get-Content $configPath -Raw | ConvertFrom-Json
        if ($cfg.auths) {
            return $cfg.auths.PSObject.Properties.Name
        }
    } catch { }
    return @()
}

function Get-ScanDirsList {
    $dirs = @(
        "$env:USERPROFILE\Projects", "$env:USERPROFILE\Code", "$env:USERPROFILE\Work",
        "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\code", "$env:USERPROFILE\projects",
        "$env:USERPROFILE\dev", "$env:USERPROFILE\src"
    )
    if ($ScanDirs) {
        $dirs += $ScanDirs -split ","
    }
    return $dirs | Where-Object { Test-Path $_ }
}

function Get-EnvFiles {
    $dirs = Get-ScanDirsList
    if ($dirs.Count -eq 0) { return @() }
    $result = @()
    foreach ($dir in $dirs) {
        $result += Get-ChildItem $dir -Recurse -Depth 5 -Include ".env", ".env.*", "*.key", "*.pem" -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty FullName
    }
    return $result
}

function Invoke-Pause {
    if ($Yes) { return $true }
    Write-Host ""
    $choice = Read-Host (msg "PAUSE")
    if ($choice -eq "s" -or $choice -eq "S") { Log-Warn (msg "SKIPPED"); return $false }
    if ($choice -eq "q" -or $choice -eq "Q") { Log-OK ("$(msg 'USER_QUIT') $LOG_FILE"); exit 0 }
    return $true
}

function Invoke-ShouldRunModule([int]$num) {
    if ($Modules -ne "") {
        $selected = $Modules -split "," | ForEach-Object { $_.Trim() }
        return $selected -contains "$num"
    }
    return $true
}

function Write-Section([int]$num, [string]$key) {
    Write-Host ""
    Write-Host "=========================================="
    Log-Info "[$num] $(msg $key)"
    Write-Host "=========================================="
}

function Invoke-DryRun([string]$desc) {
    if ($DryRun) {
        Log-Info "$(msg 'DRY_RUN_PREFIX'): $desc"
        return $true
    }
    return $false
}

# ============================================================
# System Scan
# ============================================================
function Invoke-SystemScan {
    Write-Host ""
    Write-Host "============================================"
    Log-Info "  $(msg 'SCAN_TITLE')"
    Write-Host "============================================"

    # Platform
    Write-Host ("  {0,-20} {1}" -f "$(msg 'SCAN_PLATFORM'):", $OS_VERSION)
    if ($IS_ADMIN) {
        Write-Host "  [i] Running as Administrator" -ForegroundColor Green
    } else {
        Write-Host "  [!] Not running as Administrator (some operations may fail)" -ForegroundColor Yellow
    }

    # Apifox process
    $apifoxProcs = Get-ApifoxProcesses
    if ($apifoxProcs) {
        $pids = ($apifoxProcs | Select-Object -ExpandProperty Id) -join ", "
        Write-Host ("  {0,-20} " -f "$(msg 'SCAN_APIFOX_PROC'):") -NoNewline
        Write-Host "$(msg 'SCAN_RUNNING') (PID: $pids)" -ForegroundColor Red
        $script:MODULE_APPLICABLE[1] = $true
    } else {
        Write-Host ("  {0,-20} {1}" -f "$(msg 'SCAN_APIFOX_PROC'):", (msg 'SCAN_NOT_RUNNING'))
        $script:MODULE_APPLICABLE[1] = $false
    }

    # LevelDB
    $leveldbMatches = Get-LevelDBMatches
    if ($leveldbMatches.Count -gt 0) {
        Write-Host ("  {0,-20} " -f "$(msg 'SCAN_LEVELDB'):") -NoNewline
        Write-Host (msg 'SCAN_MALICIOUS') -ForegroundColor Red
        $script:LEVELDB_MATCHES = $leveldbMatches
    } elseif (Get-ApifoxDataDir) {
        Write-Host ("  {0,-20} {1}" -f "$(msg 'SCAN_LEVELDB'):", (msg 'SCAN_CLEAN'))
        $script:LEVELDB_MATCHES = @()
    } else {
        Write-Host ("  {0,-20} {1}" -f "$(msg 'SCAN_LEVELDB'):", (msg 'SCAN_NOT_FOUND'))
        $script:LEVELDB_MATCHES = @()
    }

    # Version
    $apifoxVer = Get-ApifoxVersion
    if ($apifoxVer) {
        if ($apifoxVer -lt $FIX_VERSION) {
            Write-Host ("  {0,-20} " -f "$(msg 'SCAN_VERSION'):") -NoNewline
            Write-Host "$apifoxVer ($(msg 'SCAN_OUTDATED') $FIX_VERSION+)" -ForegroundColor Red
        } else {
            Write-Host ("  {0,-20} {1}" -f "$(msg 'SCAN_VERSION'):", $apifoxVer)
        }
    }

    # Hosts block
    $blockedCount = Get-BlockedC2Count
    $totalC2 = $C2_DOMAINS.Count
    if ($blockedCount -eq $totalC2) {
        Write-Host ("  {0,-20} " -f "$(msg 'SCAN_HOSTS'):") -NoNewline
        Write-Host "${blockedCount}/${totalC2} $(msg 'SCAN_HOSTS_ALL_BLOCKED')" -ForegroundColor Green
    } elseif ($blockedCount -gt 0) {
        Write-Host ("  {0,-20} " -f "$(msg 'SCAN_HOSTS'):") -NoNewline
        Write-Host "${blockedCount}/${totalC2} $(msg 'SCAN_HOSTS_PARTIAL')" -ForegroundColor Yellow
    } else {
        Write-Host ("  {0,-20} " -f "$(msg 'SCAN_HOSTS'):") -NoNewline
        Write-Host (msg 'SCAN_HOSTS_NOT_BLOCKED') -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "  Credentials found:" -ForegroundColor White

    # SSH keys
    $script:SSH_KEYS = Get-SSHKeys
    if ($SSH_KEYS.Count -gt 0) {
        $names = ($SSH_KEYS | ForEach-Object { Split-Path $_ -Leaf }) -join ", "
        Write-Host ("    {0,-18} {1} ({2} keys)" -f "$(msg 'SCAN_SSH'):", $names, $SSH_KEYS.Count)
        $script:MODULE_APPLICABLE[2] = $true
    } else {
        Write-Host ("    {0,-18} {1}" -f "$(msg 'SCAN_SSH'):", (msg 'SCAN_NOT_FOUND'))
        $script:MODULE_APPLICABLE[2] = $false
    }

    # GitHub
    if ($HAS_GH) {
        $ghUser = (gh auth status 2>&1 | Select-String "account\s+\S+" | ForEach-Object { $_.Matches[0].Value -replace "account\s+",""} | Select-Object -First 1)
        if ($ghUser) {
            Write-Host ("    {0,-18} logged in as {1}" -f "$(msg 'SCAN_GITHUB'):", $ghUser)
            $script:MODULE_APPLICABLE[4] = $true
        } else {
            Write-Host ("    {0,-18} not logged in" -f "$(msg 'SCAN_GITHUB'):")
            $script:MODULE_APPLICABLE[4] = $false
        }
    } else {
        Write-Host ("    {0,-18} not installed" -f "$(msg 'SCAN_GITHUB'):")
        $script:MODULE_APPLICABLE[4] = $false
    }

    # K8s
    if ((Test-Path "$env:USERPROFILE\.kube\config") -and $HAS_KUBECTL) {
        $ctx = kubectl config current-context 2>/dev/null
        Write-Host ("    {0,-18} ~/.kube/config (context: {1})" -f "$(msg 'SCAN_K8S'):", $ctx)
        $script:MODULE_APPLICABLE[5] = $true
    } else {
        Write-Host ("    {0,-18} {1}" -f "$(msg 'SCAN_K8S'):", (msg 'SCAN_NOT_FOUND'))
        $script:MODULE_APPLICABLE[5] = $false
    }

    # Docker
    $script:DOCKER_REGISTRIES = Get-DockerRegistries
    if ($DOCKER_REGISTRIES.Count -gt 0) {
        Write-Host ("    {0,-18} {1} registries" -f "$(msg 'SCAN_DOCKER'):", $DOCKER_REGISTRIES.Count)
        $script:MODULE_APPLICABLE[6] = $true
    } else {
        Write-Host ("    {0,-18} {1}" -f "$(msg 'SCAN_DOCKER'):", (msg 'SCAN_NOT_FOUND'))
        $script:MODULE_APPLICABLE[6] = $false
    }

    # History
    if (Test-SensitiveHistory) {
        Write-Host ("    {0,-18} " -f "$(msg 'SCAN_HISTORY'):") -NoNewline
        Write-Host (msg 'SCAN_HISTORY_SENSITIVE') -ForegroundColor Yellow
        $script:MODULE_APPLICABLE[3] = $true
    } else {
        Write-Host ("    {0,-18} {1}" -f "$(msg 'SCAN_HISTORY'):", (msg 'SCAN_HISTORY_CLEAN'))
        $script:MODULE_APPLICABLE[3] = $false
    }

    # npm
    $npmrc = "$env:USERPROFILE\.npmrc"
    if (Test-Path $npmrc) {
        $hasToken = (Get-Content $npmrc | Where-Object { $_ -notmatch "^\s*[#;]" } | Where-Object { $_ -match "_authToken=" }).Count -gt 0
        if ($hasToken) {
            Write-Host ("    {0,-18} " -f "npm:") -NoNewline
            Write-Host (msg 'SCAN_NPMRC_TOKEN') -ForegroundColor Yellow
            $script:MODULE_APPLICABLE[10] = $true
        } else {
            Write-Host ("    {0,-18} {1}" -f "npm:", (msg 'SCAN_NPMRC_NO_TOKEN'))
            $script:MODULE_APPLICABLE[10] = $false
        }
    } else {
        Write-Host ("    {0,-18} {1}" -f "npm:", (msg 'SCAN_NOT_FOUND'))
        $script:MODULE_APPLICABLE[10] = $false
    }

    # Windows Credential Manager (always check on Windows)
    Write-Host ("    {0,-18} {1}" -f "$(msg 'SCAN_WINCRED'):", (msg 'SCAN_APPLICABLE'))
    $script:MODULE_APPLICABLE[11] = $true

    # .env files
    $script:ENV_FILES = Get-EnvFiles
    if ($ENV_FILES.Count -gt 0) {
        Write-Host ("    {0,-18} {1} found" -f "$(msg 'SCAN_ENV'):", $ENV_FILES.Count)
        $script:MODULE_APPLICABLE[8] = $true
    } else {
        Write-Host ("    {0,-18} {1}" -f "$(msg 'SCAN_ENV'):", (msg 'SCAN_NOT_FOUND'))
        $script:MODULE_APPLICABLE[8] = (Test-Path "$env:USERPROFILE\.git-credentials") -or
                                        (Test-Path "$env:USERPROFILE\.npmrc")
    }

    $script:MODULE_APPLICABLE[0] = $true   # forensics always
    $script:MODULE_APPLICABLE[7] = $false  # macOS keychain N/A
    $script:MODULE_APPLICABLE[9] = $true   # audit always

    # Module summary
    Write-Host ""
    Write-Host "  $(msg 'SCAN_MODULES_TITLE'):" -ForegroundColor White
    $modNames = @("MOD0_NAME","MOD1_NAME","MOD2_NAME","MOD3_NAME","MOD4_NAME","MOD5_NAME","MOD6_NAME","MOD7_NAME","MOD8_NAME","MOD9_NAME","MOD10_NAME","MOD11_NAME")
    for ($i = 0; $i -lt $modNames.Count; $i++) {
        $icon = if ($MODULE_APPLICABLE[$i]) { "+" } else { "-" }
        $color = if ($MODULE_APPLICABLE[$i]) { "Green" } else { "DarkGray" }
        $status = if ($MODULE_APPLICABLE[$i]) { msg 'SCAN_APPLICABLE' } else { msg 'SCAN_SKIP' }
        Write-Host ("    [{0}] {1,-35} [{2}] {3}" -f $i, (msg $modNames[$i]), $icon, $status) -ForegroundColor $color
    }
    Write-Host ""
}

# ============================================================
# Module 0: Forensics & Hosts Block
# ============================================================
function Invoke-Module00 {
    Write-Section 0 "MOD0_NAME"

    Log-Info "Checking Apifox LevelDB for malicious markers..."
    if ($LEVELDB_MATCHES.Count -gt 0) {
        Log-Error "MALICIOUS MARKERS FOUND in LevelDB:"
        $LEVELDB_MATCHES | ForEach-Object { Log-Error "  $_" }
        $LEVELDB_MATCHES | Add-Content $LOG_FILE
    } elseif (Get-ApifoxDataDir) {
        Log-OK "No known malicious markers found in LevelDB (recommend continuing regardless)"
    } else {
        Log-Warn "Apifox LevelDB directory not found"
    }

    # Version check
    $ver = Get-ApifoxVersion
    if ($ver -and $ver -lt $FIX_VERSION) {
        Log-Warn "Apifox version $ver is below $FIX_VERSION. Please upgrade before continuing."
    }

    # Hosts block
    $unblocked = Get-UnblockedC2Domains
    if ($unblocked.Count -eq 0) {
        Log-OK "All malicious domains are already blocked in hosts file"
    } else {
        if ($DryRun) {
            Log-Info "$(msg 'DRY_RUN_PREFIX'): add $($unblocked.Count) domains to $HOSTS_FILE"
            $unblocked | ForEach-Object { Log-Info "  127.0.0.1 $_" }
        } else {
            Log-Warn "The following malicious domains are not yet blocked:"
            $unblocked | ForEach-Object { Write-Host "  $_" }
            Write-Host ""
            if (-not $Yes) {
                $ans = Read-Host "Add all malicious domains to hosts file? (requires Administrator) [Y/n]"
            } else { $ans = "Y" }

            if ($ans -ne "n" -and $ans -ne "N") {
                if (-not $IS_ADMIN) {
                    Log-Warn "Not running as Administrator. Cannot modify hosts file automatically."
                    Log-Warn "Please run this script as Administrator, or add these lines manually to:"
                    Log-Warn "  $HOSTS_FILE"
                    $unblocked | ForEach-Object { Write-Host "  127.0.0.1 $_" -ForegroundColor Yellow }
                } else {
                    $unblocked | ForEach-Object {
                        Add-Content -Path $HOSTS_FILE -Value "127.0.0.1 $_" -Encoding ASCII
                    }
                    Log-OK "Hosts entries added for malicious domains"
                }
            } else {
                Log-Warn (msg "SKIPPED")
            }
        }
    }
}

# ============================================================
# Module 1: Kill Apifox Process
# ============================================================
function Invoke-Module01 {
    Write-Section 1 "MOD1_NAME"
    $procs = Get-ApifoxProcesses
    if (-not $procs) { Log-OK "No Apifox processes found"; return }

    Log-Warn "Apifox processes found:"
    $procs | Format-Table Id, ProcessName, StartTime -AutoSize | Out-String | ForEach-Object { Write-Host $_ }
    if (-not (Invoke-Pause)) { return }
    if (Invoke-DryRun "kill Apifox.exe (PID: $(($procs|Select-Object -ExpandProperty Id) -join ', '))") { return }

    $procs | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 1
    $remaining = Get-ApifoxProcesses
    if ($remaining) {
        Log-Warn "Some processes still running, force-killing..."
        $remaining | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
    }
    Log-OK "Apifox processes terminated"
}

# ============================================================
# Module 2: SSH Keys
# ============================================================
function Invoke-Module02 {
    Write-Section 2 "MOD2_NAME"
    if ($SSH_KEYS.Count -eq 0) { Log-OK "No SSH keys found"; return }

    Log-Info "SSH keys found in ~/.ssh:"
    for ($i = 0; $i -lt $SSH_KEYS.Count; $i++) {
        Write-Host ("  [{0}] {1}" -f ($i+1), (Split-Path $SSH_KEYS[$i] -Leaf))
    }

    Write-Host ""
    if ($Yes) { $sel = "all" } else {
        $sel = Read-Host "Enter key numbers to rotate (comma-separated, or 'all')"
    }

    $toRotate = @()
    if ($sel -eq "all") { $toRotate = $SSH_KEYS }
    else {
        $sel -split "," | ForEach-Object {
            $n = [int]$_.Trim() - 1
            if ($n -ge 0 -and $n -lt $SSH_KEYS.Count) { $toRotate += $SSH_KEYS[$n] }
        }
    }
    if ($toRotate.Count -eq 0) { Log-Warn (msg "SKIPPED"); return }

    $email = git config user.email 2>/dev/null
    if (-not $email) { $email = Read-Host "Email for new SSH keys" }

    $backupDir = "$env:USERPROFILE\.ssh\compromised_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

    foreach ($key in $toRotate) {
        $keyName = Split-Path $key -Leaf
        if ($DryRun) {
            Log-Info "$(msg 'DRY_RUN_PREFIX'): backup and regenerate $keyName"
            continue
        }
        if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory $backupDir | Out-Null }
        Move-Item $key $backupDir -Force
        $pubKey = "$key.pub"
        if (Test-Path $pubKey) { Move-Item $pubKey $backupDir -Force }
        Log-OK "Backed up $keyName"

        if (Get-Command ssh-keygen -ErrorAction SilentlyContinue) {
            & ssh-keygen -t ed25519 -C $email -f $key -N ""
            Log-OK "New key generated: $keyName"
            Write-Host ""
            Log-Info "New public key (add to GitHub/GitLab/etc.):"
            Write-Host "--- $keyName ---"
            Get-Content "$key.pub"
        } else {
            Log-Warn "ssh-keygen not found. Install OpenSSH or Git for Windows."
            Log-Warn "Backup is at: $backupDir\$keyName"
        }
    }
    Write-Host ""
    Log-Manual "Update public keys on GitHub / GitLab / other platforms for rotated keys"
}

# ============================================================
# Module 3: Shell History
# ============================================================
function Invoke-Module03 {
    Write-Section 3 "MOD3_NAME"
    $histFiles = Get-HistoryFiles
    if ($histFiles.Count -eq 0) { Log-Info "No history files found"; return }

    Log-Info "Cleaning sensitive tokens from history files..."
    if (-not (Invoke-Pause)) { return }

    $patterns = @("token", "secret", "password=", "secret=", "SECRET=", "key=", "credential", "auth")
    if ($ExtraPatterns) { $patterns += $ExtraPatterns -split "," }
    $regex = ($patterns | ForEach-Object { [regex]::Escape($_) }) -join "|"

    foreach ($hfile in $histFiles) {
        $fname = Split-Path $hfile -Leaf
        $backup = "$hfile.backup"
        if (Invoke-DryRun "clean $fname") { continue }
        Copy-Item $hfile $backup -Force
        $before = (Get-Content $hfile).Count
        $cleaned = Get-Content $hfile | Where-Object { $_ -notmatch $regex }
        $cleaned | Set-Content $hfile -Encoding UTF8
        $after = $cleaned.Count
        Log-OK "$fname cleaned (${before} -> ${after} lines), backup at $backup"
    }
    Write-Host ""
    Log-Manual "Rotate any tokens/secrets that appeared in your shell history"
}

# ============================================================
# Module 4: GitHub Token
# ============================================================
function Invoke-Module04 {
    Write-Section 4 "MOD4_NAME"
    if (-not $HAS_GH) { Log-Warn "gh CLI not installed. Please handle GitHub tokens manually."; Log-Manual "Go to GitHub -> Settings -> Developer settings -> Personal access tokens to revoke suspicious tokens"; return }
    if (-not $MODULE_APPLICABLE[4]) { Log-Info "Not logged into GitHub CLI"; return }

    Log-Info "Current GitHub CLI status:"
    gh auth status 2>&1 | ForEach-Object { Write-Host "  $_" }
    if (-not (Invoke-Pause)) { return }
    if (Invoke-DryRun "logout and re-login GitHub CLI") { return }

    gh auth logout 2>&1 | Out-Null
    Log-OK "Logged out of GitHub CLI"
    Log-Info "Please complete authorization in the browser..."
    gh auth login

    Write-Host ""
    Log-Manual "Go to GitHub -> Settings -> Developer settings -> Personal access tokens to revoke suspicious tokens"
    Log-Manual "Check GitHub -> Settings -> Security -> Sessions for unusual logins"
}

# ============================================================
# Module 5: K8s Credentials
# ============================================================
function Invoke-Module05 {
    Write-Section 5 "MOD5_NAME"
    $kubeConfig = "$env:USERPROFILE\.kube\config"
    if (-not (Test-Path $kubeConfig) -or -not $HAS_KUBECTL) { Log-Info "~/.kube/config not found"; return }

    $ctx = kubectl config current-context 2>&1
    Log-Info "kubeconfig found, current context: $ctx"
    if (-not (Invoke-Pause)) { return }

    $backup = "$kubeConfig.compromised_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    if (-not (Invoke-DryRun "backup kubeconfig")) {
        Copy-Item $kubeConfig $backup -Force
        Log-OK "kubeconfig backed up to $backup"
    }
    Write-Host ""
    Log-Manual "Contact your cluster admin to re-issue kubeconfig credentials"
}

# ============================================================
# Module 6: Docker Credentials
# ============================================================
function Invoke-Module06 {
    Write-Section 6 "MOD6_NAME"
    if (-not $HAS_DOCKER) { Log-Info "Docker not installed"; return }
    if ($DOCKER_REGISTRIES.Count -eq 0) { Log-Info "No Docker registries configured"; return }

    Log-Info "Docker registries found:"
    $DOCKER_REGISTRIES | ForEach-Object { Write-Host "  $_" }
    if (-not (Invoke-Pause)) { return }
    if (Invoke-DryRun "logout all Docker registries") { return }

    $DOCKER_REGISTRIES | ForEach-Object { docker logout $_ 2>&1 | Out-Null }
    Log-OK "Logged out of all Docker registries"
    Write-Host ""
    Log-Manual "Change passwords on the above registries, then run: docker login <registry>"
}

# ============================================================
# Module 7: macOS Keychain (N/A on Windows)
# ============================================================
function Invoke-Module07 {
    Write-Section 7 "MOD7_NAME"
    Log-Info "macOS Keychain check is not applicable on Windows."
    Log-Info "Use Module 11 (Windows Credential Manager) instead."
}

# ============================================================
# Module 8: Sensitive File Scan
# ============================================================
function Invoke-Module08 {
    Write-Section 8 "MOD8_NAME"
    Log-Info "Scanning for sensitive files (.env, .key, .pem)..."

    if ($ENV_FILES.Count -gt 0) {
        Log-Warn ".env / .key / .pem files found (check credentials inside):"
        $ENV_FILES | ForEach-Object { Write-Host "  $_"; Add-Content $LOG_FILE "  $_" }
    } else {
        Log-Info "No .env / .key / .pem files found"
    }

    # Additional files
    $extras = @(
        "$env:USERPROFILE\.git-credentials",
        "$env:USERPROFILE\.npmrc",
        "$env:USERPROFILE\.gitconfig"
    )
    $foundExtras = $extras | Where-Object { Test-Path $_ }
    if ($foundExtras) {
        Write-Host ""
        Log-Info "Checking additional files that may have been exfiltrated:"
        $foundExtras | ForEach-Object {
            Log-Warn "  $(Split-Path $_ -Leaf) -> $_"
            Add-Content $LOG_FILE "  $_"
        }
    }
}

# ============================================================
# Module 9: Audit
# ============================================================
function Invoke-Module09 {
    Write-Section 9 "MOD9_NAME"
    Log-Manual "Check GitHub security log: https://github.com/settings/security-log"
    Write-Host ""
    Log-Manual "Check git repos for unusual commits since $RISK_START"
    Log-Info "  git log --since=`"$RISK_START`" --oneline"
    if ($HAS_KUBECTL -and (Test-Path "$env:USERPROFILE\.kube\config")) {
        Write-Host ""
        Log-Manual "Check Kubernetes events for anomalies"
        kubectl get events --sort-by='.lastTimestamp' -A 2>/dev/null | Select-Object -First 20 | Tee-Object -Append -FilePath $LOG_FILE
    }
    Write-Host ""
    Log-Manual "Check Windows Event Log for unusual logins:"
    Log-Info "  Get-WinEvent -LogName Security | Where-Object { `$_.Id -eq 4624 } | Select-Object -First 20"
    Log-Manual "Check network connections for C2 domain traffic:"
    Log-Info "  netstat -an | Select-String '443'"
    Write-Host ""
    Log-Info "Known malicious domains (block via Windows Firewall/DNS):"
    $C2_DOMAINS | ForEach-Object { Log-Info "  - $_" }
}

# ============================================================
# Module 10: npm Token
# ============================================================
function Invoke-Module10 {
    Write-Section 10 "MOD10_NAME"
    $npmrc = "$env:USERPROFILE\.npmrc"
    if (-not (Test-Path $npmrc)) { Log-Info "No npm auth tokens found in ~/.npmrc"; return }

    Log-Info "Found npm auth tokens in ~/.npmrc:"
    Get-Content $npmrc | Where-Object { $_ -notmatch "^\s*[#;]" } | Where-Object { $_ -match "_authToken=" } |
        ForEach-Object { ($_ -replace "(_authToken=).*", '$1****') } |
        Tee-Object -Append -FilePath $LOG_FILE | ForEach-Object { Write-Host "  $_" }

    if (-not (Invoke-Pause)) { return }

    $backup = "$npmrc.compromised_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    if (-not (Invoke-DryRun "backup ~/.npmrc")) {
        Copy-Item $npmrc $backup -Force
        Log-OK "~/.npmrc backed up to $backup"
    }
    Write-Host ""
    Log-Manual "Revoke the above npm tokens at https://www.npmjs.com/settings/tokens and re-login with: npm login"
}

# ============================================================
# Module 11: Windows Credential Manager
# ============================================================
function Invoke-Module11 {
    Write-Section 11 "MOD11_NAME"
    Log-Info "Searching Windows Credential Manager for apifox-related entries..."

    # Use cmdkey to list credentials
    $allCreds = cmdkey /list 2>&1
    $apifoxCreds = $allCreds | Where-Object { $_ -match "apifox" }

    if ($apifoxCreds) {
        Log-Warn "Found apifox-related credential entries:"
        $apifoxCreds | ForEach-Object { Write-Host "  $_"; Add-Content $LOG_FILE "  $_" }
        Write-Host ""
        Log-Info "To remove: cmdkey /delete:<target>"
        if (-not $DryRun) {
            $targets = $allCreds | Where-Object { $_ -match "Target:.*apifox" } |
                ForEach-Object { $_ -replace ".*Target:\s*", "" }
            foreach ($target in $targets) {
                if (-not (Invoke-Pause)) { break }
                cmdkey /delete:$target 2>&1 | Out-Null
                Log-OK "Removed credential: $target"
            }
        }
    } else {
        Log-OK "No apifox-related entries found in Windows Credential Manager"
    }

    # Check Git credentials file
    $gitCred = "$env:USERPROFILE\.git-credentials"
    if (Test-Path $gitCred) {
        Log-Warn "Git credentials file found (may have been exfiltrated): $gitCred"
        Add-Content $LOG_FILE "  $gitCred"
    }

    Write-Host ""
    Log-Manual "Open Windows Credential Manager (Control Panel > Credential Manager) to manually review stored credentials"
    Log-Manual "Also check: Settings > Accounts > Email & accounts for unusual sign-ins"
}

# ============================================================
# Main
# ============================================================
function Main {
    # Validate modules input
    if ($Modules -ne "") {
        $Modules -split "," | ForEach-Object {
            $n = $_.Trim()
            if ($n -notmatch "^\d+$" -or [int]$n -gt 11) {
                Write-Error "Invalid module number: '$n' (valid: 0-11)"; exit 1
            }
        }
    }

    # Banner
    Write-Host "============================================================"
    Write-Host "  $(msg 'BANNER_TITLE') v$VERSION" -ForegroundColor Cyan
    Write-Host "  $(Get-Date)"
    Write-Host "  Log: $LOG_FILE"
    Write-Host ""
    Write-Host "  Risk window : $RISK_START - $RISK_END"
    Write-Host "  Fix version : $FIX_VERSION+"
    Write-Host "  Announcement: $ANNOUNCEMENT_URL"
    Write-Host "============================================================"

    # System scan
    Invoke-SystemScan

    # Module selection
    if ($Modules -eq "" -and -not $Yes) {
        $choice = Read-Host (msg "PROCEED_ALL")
        if ($choice -eq "n" -or $choice -eq "N") {
            Log-OK "$(msg 'USER_QUIT') $LOG_FILE"; exit 0
        } elseif ($choice -eq "select" -or $choice -eq "SELECT") {
            $script:Modules = Read-Host (msg "SELECT_PROMPT")
        }
    }

    # Confirmation
    if (-not $DryRun -and -not $Yes) {
        Write-Host ""
        Log-Warn (msg "CONFIRM_WARN")
        Log-Info (msg "CONFIRM_DRY_RUN_HINT")
        Write-Host ""
        $confirm = Read-Host (msg "CONFIRM_PROMPT")
        if ($confirm -ne "y" -and $confirm -ne "Y" -and $confirm -ne "yes") {
            Log-OK (msg "CONFIRM_ABORTED"); exit 0
        }
    }

    # Execute modules
    $modFuncs = @(
        { Invoke-Module00 }, { Invoke-Module01 }, { Invoke-Module02 }, { Invoke-Module03 },
        { Invoke-Module04 }, { Invoke-Module05 }, { Invoke-Module06 }, { Invoke-Module07 },
        { Invoke-Module08 }, { Invoke-Module09 }, { Invoke-Module10 }, { Invoke-Module11 }
    )

    for ($i = 0; $i -lt $modFuncs.Count; $i++) {
        if ((Invoke-ShouldRunModule $i) -and $MODULE_APPLICABLE[$i]) {
            & $modFuncs[$i]
        }
    }

    # Summary
    Write-Host ""
    Write-Host "============================================================"
    Log-OK (msg "COMPLETE")
    Write-Host "============================================================"
    Write-Host ""
    Write-Host "$(msg 'LOG_SAVED'): $LOG_FILE"
    Write-Host ""
    Write-Host "$(msg 'REMAINING')"
    if ((Invoke-ShouldRunModule 2) -and $MODULE_APPLICABLE[2]) {
        Write-Host "  [ ] Add new SSH public keys to GitHub / GitLab / other platforms"
    }
    if ((Invoke-ShouldRunModule 4) -and $MODULE_APPLICABLE[4]) {
        Write-Host "  [ ] Go to GitHub -> Settings -> Developer settings -> Personal access tokens to revoke suspicious tokens"
        Write-Host "  [ ] Check GitHub -> Settings -> Security -> Sessions for unusual logins"
    }
    if ((Invoke-ShouldRunModule 3) -and $MODULE_APPLICABLE[3]) {
        Write-Host "  [ ] Rotate leaked tokens (ngrok, API keys, etc.)"
    }
    if ((Invoke-ShouldRunModule 5) -and $MODULE_APPLICABLE[5]) {
        Write-Host "  [ ] Contact your cluster admin to re-issue kubeconfig credentials"
    }
    if ((Invoke-ShouldRunModule 6) -and $MODULE_APPLICABLE[6]) {
        Write-Host "  [ ] Change passwords on Docker registries, then run: docker login <registry>"
    }
    if ((Invoke-ShouldRunModule 10) -and $MODULE_APPLICABLE[10]) {
        Write-Host "  [ ] Revoke npm tokens at https://www.npmjs.com/settings/tokens and re-login"
    }
    if ((Invoke-ShouldRunModule 11) -and $MODULE_APPLICABLE[11]) {
        Write-Host "  [ ] Review Windows Credential Manager for any remaining suspicious entries"
    }
    Write-Host ""
}

Main
