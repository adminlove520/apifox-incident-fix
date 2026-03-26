# Apifox Supply Chain Attack Incident Response Tool

[中文文档](README_CN.md)

## Background

On March 25, 2026, Apifox officially confirmed that their **public SaaS desktop client** was compromised by a supply chain attack. A dynamically loaded external JavaScript file was maliciously tampered with.

- **Risk Window:** March 4, 2026 – March 22, 2026
- **Affected:** Public SaaS desktop client only (Web version and self-hosted deployments are NOT affected)
- **C2 Domain:** `apifox.it.com` (hosted on Cloudflare, active for 18 days, now offline)
- **Potential Data Exfiltrated:** `~/.ssh/`, `~/.zsh_history`, `~/.bash_history`, `~/.git-credentials`
- **Fix Version:** 2.8.19+
- **Official Announcement:** https://mp.weixin.qq.com/s/GpACQdnhVNsMn51cm4hZig
- **Security Contact:** security@apifox.com

## Quick Start

```bash
curl -fsSL https://raw.githubusercontent.com/myxiaoao/apifox-incident-fix/master/dist/fix.sh -o fix.sh
chmod +x fix.sh
./fix.sh
```

## What This Tool Does

The tool automatically scans your system and guides you through credential rotation:

| Module | Description |
|--------|-------------|
| 0 - Forensics | Check LevelDB for malicious markers, verify Apifox version, block C2 domain in /etc/hosts |
| 1 - Kill Process | Terminate running Apifox processes |
| 2 - SSH Keys | Scan, backup, and rotate SSH private keys with platform hints |
| 3 - Shell History | Clean sensitive tokens from zsh/bash/fish history |
| 4 - GitHub Token | Rotate GitHub CLI authentication |
| 5 - K8s Credentials | Backup kubeconfig for re-issuance |
| 6 - Docker Credentials | Logout from all configured Docker registries |
| 7 - macOS Keychain | Check for apifox-related Keychain entries (macOS only) |
| 8 - .env Scan | Find .env, .key, .pem files in common development directories |
| 9 - Audit | Guide anomalous activity review (GitHub security log, git history, K8s events) |

**Important:** This tool only backs up and rotates credentials. It never deletes original files — backups are always created first.

## Supported Platforms

- macOS (Intel / Apple Silicon)
- Linux (Debian/Ubuntu, RHEL/CentOS, Arch)

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
- Contact cluster admin to re-issue kubeconfig
- Change Docker Hub / Harbor passwords and re-login
- Review macOS Keychain entries
- Notify your team

## How It Works

1. **System Scan** — Detects platform (macOS/Linux), installed tools, existing credentials, and Apifox traces
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
│   ├── 00-forensics.sh ... 09-audit.sh
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
4. Add `run_module_NN` call in `src/footer.sh`
5. Update `build.sh` FILES array
6. Run `./build.sh`

## References

- [Official Announcement (Chinese)](https://mp.weixin.qq.com/s/GpACQdnhVNsMn51cm4hZig)
- Security Contact: security@apifox.com

## License

MIT
