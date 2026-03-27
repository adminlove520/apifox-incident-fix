# Apifox Supply Chain Attack Incident Response Tool

[中文文档](README_CN.md)

## Background

Apifox is an API collaboration platform developed by Guangzhou Ruihu Technology Co., Ltd. Its desktop client is built on the Electron framework.

Due to the application not strictly enabling Electron's sandbox security parameter and exposing Node.js API interfaces, attackers hijacked the CDN-hosted `apifox-app-event-tracking.min.js` file (size changed from 34K to 77K), replacing it with a malicious version. The malicious script dynamically loads attack payloads from unofficial domains, collecting SSH keys, Git credentials, shell history, process lists and other sensitive information under certain conditions, and reports them to attacker-controlled servers. It can then pull and execute backdoor programs and attempt lateral movement.

- **Risk Window:** March 4, 2026 – March 22, 2026
- **Affected:** Public SaaS desktop client only (Web version and self-hosted deployments are NOT affected)
- **C2 Domains:** `apifox.it.com`, `cdn.openroute.dev`, `upgrade.feishu.it.com`, `system.toshinkyo.or.jp`, `*.feishu.it.com`, `ns.openroute.dev`
- **Potential Data Exfiltrated:** `~/.ssh/`, `~/.git-credentials`, `~/.zsh_history`, `~/.bash_history`, `~/.kube/*`, `~/.npmrc`, `~/.zshrc`, `~/.subversion/*`
- **Malicious Indicators:** `_rl_headers`, `_rl_mc` keys in localStorage; HTTP headers containing `af_uuid`, `af_os`, `af_user`, `af_name`, `af_apifox_user`, `af_apifox_name`; reading `common.accessToken`; execution of `ps aux` / `tasklist`
- **Fix Version:** 2.8.19+
- **Official Announcement:** https://mp.weixin.qq.com/s/GpACQdnhVNsMn51cm4hZig
- **Security Contact:** security@apifox.com

## Quick Start

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/adminlove520/apifox-incident-fix/main/dist/fix.sh -o fix.sh
chmod +x fix.sh
./fix.sh
```

**Windows (PowerShell — recommended):**
```powershell
# Run PowerShell as Administrator for full functionality (hosts file modification)
irm https://raw.githubusercontent.com/adminlove520/apifox-incident-fix/main/fix.ps1 -OutFile fix.ps1
.\fix.ps1
```

> **Note:** On Windows, run PowerShell as Administrator to allow automatic modification of the hosts file.

**Windows (Git Bash / MSYS2):**
```bash
curl -fsSL https://raw.githubusercontent.com/adminlove520/apifox-incident-fix/main/dist/fix.sh -o fix.sh
chmod +x fix.sh
./fix.sh
```

## What This Tool Does

The tool automatically scans your system and guides you through credential rotation:

| Module | Description |
|--------|-------------|
| 0 - Forensics | Check LevelDB for malicious markers (_rl_headers, _rl_mc, af_uuid, etc.), verify Apifox version, block all C2 domains in /etc/hosts |
| 1 - Kill Process | Terminate running Apifox processes |
| 2 - SSH Keys | Scan, backup, and rotate SSH private keys with platform hints |
| 3 - Shell History | Clean sensitive tokens from zsh/bash/fish history |
| 4 - GitHub Token | Rotate GitHub CLI authentication |
| 5 - K8s Credentials | Backup kubeconfig for re-issuance |
| 6 - Docker Credentials | Logout from all configured Docker registries |
| 7 - macOS Keychain | Check for apifox-related Keychain entries (macOS only) |
| 8 - .env Scan | Find .env, .key, .pem files and check additional exfiltrated files (.git-credentials, .npmrc, .zshrc, .subversion/) |
| 9 - Audit | Guide anomalous activity review (GitHub security log, git history, K8s events, SSH login logs, network traffic to C2 domains) |
| 10 - npm Token | Backup ~/.npmrc and guide npm token rotation |
| 11 - Windows Credential Manager | Search and remove apifox-related entries from Windows Credential Manager **(Windows only)** |

**Important:** For credential files (SSH keys, history, npmrc), backups are always created before any modification. The tool may also terminate Apifox processes, add blocking entries for all known malicious domains to `/etc/hosts` (requires sudo), and rewrite shell history files (after backup). Use `--dry-run` to preview all changes before executing.

## Supported Platforms

| Platform | Script | Notes |
|----------|--------|-------|
| macOS (Intel / Apple Silicon) | `fix.sh` | Full support, incl. Keychain |
| Linux (Debian/Ubuntu, RHEL/CentOS, Arch) | `fix.sh` | Full support |
| **Windows 10/11** | **`fix.ps1`** | PowerShell 5.1+, incl. Credential Manager |
| Windows (Git Bash / MSYS2) | `fix.sh` | Partial support via bash emulation |

## Command Line Options

| Option | Description |
|--------|-------------|
| `--lang en\|cn` | Force language (default: auto-detect from system locale) |
| `--scan-dirs DIR` | Additional directories to scan for .env files (comma-separated) |
| `--extra-patterns P` | Additional sensitive patterns for history cleanup |
| `--dry-run` | Show what would be done without making changes |
| `--yes` | Skip all confirmations (for automation) |
| `--modules 1,2,4` | Only run specified modules |
| `--no-color` | Disable colored output |
| `--help` | Show help message |

## Manual Steps After Running

The tool will print a personalized checklist at the end. Common manual steps include:

- Add new SSH public keys to GitHub / GitLab / other platforms
- Revoke suspicious GitHub Personal Access Tokens
- Regenerate ngrok authtoken and other leaked tokens
- Contact cluster admin to re-issue kubeconfig and rotate OIDC tokens
- Change Docker Hub / Harbor passwords and re-login
- Revoke npm registry tokens and re-login
- Rotate any passwords/tokens/API keys exposed in shell history
- Review macOS Keychain entries
- Review server SSH login logs for anomalous access
- Block all malicious domains via firewall/DNS
- Notify your team

## How It Works

1. **System Scan** — Detects platform (macOS/Linux/Windows), installed tools, existing credentials, and Apifox traces
2. **Diagnostic Report** — Displays findings and marks which modules are applicable
3. **Module Selection** — Run all applicable modules, or select specific ones
4. **Guided Execution** — Each module prompts for confirmation before making changes
5. **Summary** — Prints remaining manual actions and log file path

## Contributing

### Project Structure

```
src/
├── header.sh          # Constants, argument parsing
├── lib/
│   ├── i18n.sh        # Bilingual messages (EN/CN)
│   ├── common.sh      # Logging, colors, utilities
│   └── detect.sh      # Platform detection, system scanning
├── modules/
│   ├── 00-forensics.sh ... 10-npm.sh
└── footer.sh          # Main orchestration
```

### Build

```bash
./build.sh    # Concatenates src/ → dist/fix.sh
```

### Adding a Module

1. Create `src/modules/NN-name.sh` with a `run_module_NN()` function
2. Add message definitions to `src/lib/i18n.sh`
3. Add detection logic to `src/lib/detect.sh` (set `MODULE_APPLICABLE[N]`)
4. Add `run_module_NN` to the `mod_funcs` array in `src/footer.sh`
5. Update `build.sh` FILES array
6. Run `./build.sh` and `./test.sh`

## References

- [Official Announcement (Chinese)](https://mp.weixin.qq.com/s/GpACQdnhVNsMn51cm4hZig)
- Security Contact: security@apifox.com

## License

MIT
