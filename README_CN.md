# Apifox 供应链攻击应急响应工具

[English](README.md)

## 背景

Apifox 是一款由广州睿狐科技有限公司研发的 API 一体化协作平台，其桌面客户端基于 Electron 框架开发。

由于应用未严格启用 Electron 的 sandbox 安全参数，并暴露了 Node.js 的 API 接口，攻击者通过劫持官方 CDN 域名（cdn.apifox.com）上托管的 `apifox-app-event-tracking.min.js` 文件，将其替换为恶意版本（大小从正常的 34K 变为 77K）。该恶意脚本会动态加载非官方域名上的攻击载荷，在满足特定条件下采集主机系统的 SSH 密钥、Git 凭证、命令行历史、进程列表等敏感信息，并上报至攻击者控制的服务器，随后可拉取执行后门程序并尝试横向移动。

- **风险时间窗口：** 2026 年 3 月 4 日 至 2026 年 3 月 22 日
- **受影响范围：** 仅公网 SaaS 版桌面客户端（Web 版和私有化部署版不受影响）
- **C2 恶意域名：** `apifox.it.com`、`cdn.openroute.dev`、`upgrade.feishu.it.com`、`system.toshinkyo.or.jp`、`*.feishu.it.com`、`ns.openroute.dev`
- **可能泄露的数据：** `~/.ssh/`、`~/.git-credentials`、`~/.zsh_history`、`~/.bash_history`、`~/.kube/*`、`~/.npmrc`、`~/.zshrc`、`~/.subversion/*`
- **恶意指标：** localStorage 中存在 `_rl_headers`、`_rl_mc` 键；HTTP 请求头中包含 `af_uuid`、`af_os`、`af_user`、`af_name`、`af_apifox_user`、`af_apifox_name`；读取 `common.accessToken` 凭证；执行 `ps aux` / `tasklist` 命令
- **修复版本：** 2.8.19+
- **官方公告：** https://mp.weixin.qq.com/s/GpACQdnhVNsMn51cm4hZig
- **安全联系：** security@apifox.com

## 快速开始

**macOS / Linux：**
```bash
curl -fsSL https://raw.githubusercontent.com/adminlove520/apifox-incident-fix/main/dist/fix.sh -o fix.sh
chmod +x fix.sh
./fix.sh
```

**Windows（PowerShell —— 推荐）：**
```powershell
# 以管理员身份运行 PowerShell 以获得完整功能（hosts 文件修改权限）
irm https://raw.githubusercontent.com/adminlove520/apifox-incident-fix/main/fix.ps1 -OutFile fix.ps1
.\fix.ps1
```

> **提示：** 在 Windows 上，请以管理员身份运行 PowerShell 以允许工具自动修改 hosts 文件。若未提权，工具仍会进行扫描并提供手动操作指引。

**Windows（Git Bash / MSYS2）：**
```bash
curl -fsSL https://raw.githubusercontent.com/adminlove520/apifox-incident-fix/main/dist/fix.sh -o fix.sh
chmod +x fix.sh
./fix.sh
```

## 功能说明

本工具自动扫描系统状态，引导你完成凭证轮换：

| 模块 | 功能 |
|------|------|
| 0 - 取证确认 | 检查 LevelDB 恶意标记（_rl_headers、_rl_mc、af_uuid 等）、验证 Apifox 版本、在 /etc/hosts 中屏蔽所有 C2 域名 |
| 1 - 终止进程 | 终止运行中的 Apifox 进程 |
| 2 - SSH 密钥 | 扫描、备份、轮换 SSH 私钥，并提示对应平台 |
| 3 - Shell History | 清理 zsh/bash/fish 历史记录中的敏感 token |
| 4 - GitHub Token | 轮换 GitHub CLI 认证 |
| 5 - K8s 凭证 | 备份 kubeconfig 以便重新颁发 |
| 6 - Docker 凭证 | 登出所有已配置的 Docker Registry |
| 7 - macOS 钥匙串 | 检查与 apifox 相关的钥匙串条目（仅 macOS） |
| 8 - .env 扫描 | 查找 .env、.key、.pem 文件，并检查其他可能被窃取的文件（.git-credentials、.npmrc、.zshrc、.subversion/） |
| 9 - 审计 | 引导检查异常活动（GitHub 安全日志、git 历史、K8s 事件、SSH 登录日志、网络流量中的 C2 域名） |
| 10 - npm Token | 备份 ~/.npmrc 并引导 npm token 轮换 |
| 11 - Windows 凭证管理器 | 搜索并删除 Windows 凭证管理器中的 apifox 相关条目（仅 Windows） |

**重要提示：** 对凭证文件（SSH 密钥、history、npmrc 等），操作前始终会先创建备份。此外，工具还可能终止 Apifox 进程、向 `/etc/hosts` 添加所有已知恶意域名的屏蔽条目（需要 sudo）、以及重写 shell history 文件（备份后）。建议先用 `--dry-run` 预览所有变更再执行。

## 支持平台

| 平台 | 脚本 | 备注 |
|------|------|------|
| macOS (Intel / Apple Silicon) | `fix.sh` | 完整支持，含钥匙串检查 |
| Linux (Debian/Ubuntu, RHEL/CentOS, Arch) | `fix.sh` | 完整支持 |
| **Windows 10/11** | **`fix.ps1`** | PowerShell 5.1+，含凭证管理器 |
| Windows（Git Bash / MSYS2） | `fix.sh` | 通过 bash 模拟，部分支持 |

## 命令行参数

| 参数 | 说明 |
|------|------|
| `--lang en\|cn` | 强制指定语言（默认：根据系统 locale 自动检测） |
| `--scan-dirs DIR` | 额外的 .env 扫描目录（逗号分隔） |
| `--extra-patterns P` | 额外的 history 敏感词模式 |
| `--dry-run` | 仅展示将执行的操作，不实际修改 |
| `--yes` | 跳过所有确认（用于自动化） |
| `--modules 1,2,4` | 仅执行指定模块 |
| `--no-color` | 禁用彩色输出 |
| `--help` | 显示帮助信息 |

## 运行后的手动操作

工具结束时会打印个性化的待办清单。常见手动操作包括：

- 将新 SSH 公钥添加到 GitHub / GitLab / 其他平台
- 撤销可疑的 GitHub Personal Access Token
- 重新生成 ngrok authtoken 等已泄露的 token
- 联系集群管理员重新颁发 kubeconfig，轮换 OIDC Token
- 修改 Docker Hub / Harbor 密码并重新登录
- 撤销 npm registry Token 并重新登录
- 轮换命令行历史中暴露的所有密码、Token 和 API Key
- 检查 macOS 钥匙串条目
- 审查服务器 SSH 登录日志，排查异常登录
- 通过防火墙或 DNS 阻断所有恶意域名
- 通知团队相关人员
- （Windows）检查 Windows 凭证管理器中的残留条目

## 工作原理

1. **系统扫描** — 检测平台（macOS/Linux/Windows）、已安装工具、现有凭证、Apifox 痕迹
2. **诊断报告** — 展示扫描结果，标记哪些模块适用
3. **模块选择** — 执行所有适用模块，或选择特定模块
4. **引导执行** — 每个模块在执行前询问确认
5. **总结** — 输出剩余手动操作和日志文件路径

## 参与贡献

### 项目结构

```
src/
├── header.sh          # 常量、参数解析
├── lib/
│   ├── i18n.sh        # 双语消息定义（EN/CN）
│   ├── common.sh      # 日志、颜色、工具函数
│   └── detect.sh      # 平台检测、系统扫描
├── modules/
│   ├── 00-forensics.sh ... 10-npm.sh
│   └── 11-wincred.sh    # Windows 凭证管理器（Windows 专属）
└── footer.sh          # 主流程编排
```

### 构建

```bash
./build.sh    # 将 src/ 合并为 dist/fix.sh
```

### 添加新模块

1. 创建 `src/modules/NN-name.sh`，定义 `run_module_NN()` 函数
2. 在 `src/lib/i18n.sh` 中添加消息定义
3. 在 `src/lib/detect.sh` 中添加检测逻辑（设置 `MODULE_APPLICABLE[N]`）
4. 在 `src/footer.sh` 的 `mod_funcs` 数组中添加 `run_module_NN`
5. 更新 `build.sh` 的 FILES 数组
6. 运行 `./build.sh` 和 `./test.sh`

## 参考链接

- [官方公告](https://mp.weixin.qq.com/s/GpACQdnhVNsMn51cm4hZig)
- 安全联系: security@apifox.com

## 许可证

MIT
