# Apifox 供应链攻击应急响应工具

[English](README.md)

## 背景

2026 年 3 月 25 日，Apifox 官方确认其**公网 SaaS 版桌面客户端**遭受供应链攻击。客户端动态加载的一个外部 JavaScript 文件被恶意篡改。

- **风险时间窗口：** 2026 年 3 月 4 日 至 2026 年 3 月 22 日
- **受影响范围：** 仅公网 SaaS 版桌面客户端（Web 版和私有化部署版不受影响）
- **C2 恶意域名：** `apifox.it.com`（托管在 Cloudflare，存活 18 天，目前已下线）
- **可能泄露的数据：** `~/.ssh/`、`~/.zsh_history`、`~/.bash_history`、`~/.git-credentials`
- **修复版本：** 2.8.19+
- **官方公告：** https://mp.weixin.qq.com/s/GpACQdnhVNsMn51cm4hZig
- **安全联系：** security@apifox.com

## 快速开始

```bash
curl -fsSL https://raw.githubusercontent.com/myxiaoao/apifox-incident-fix/master/dist/fix.sh -o fix.sh
chmod +x fix.sh
./fix.sh
```

## 功能说明

本工具自动扫描系统状态，引导你完成凭证轮换：

| 模块 | 功能 |
|------|------|
| 0 - 取证确认 | 检查 LevelDB 恶意标记、验证 Apifox 版本、在 /etc/hosts 中屏蔽 C2 域名 |
| 1 - 终止进程 | 终止运行中的 Apifox 进程 |
| 2 - SSH 密钥 | 扫描、备份、轮换 SSH 私钥，并提示对应平台 |
| 3 - Shell History | 清理 zsh/bash/fish 历史记录中的敏感 token |
| 4 - GitHub Token | 轮换 GitHub CLI 认证 |
| 5 - K8s 凭证 | 备份 kubeconfig 以便重新颁发 |
| 6 - Docker 凭证 | 登出所有已配置的 Docker Registry |
| 7 - macOS 钥匙串 | 检查与 apifox 相关的钥匙串条目（仅 macOS） |
| 8 - .env 扫描 | 在常见开发目录中查找 .env、.key、.pem 文件 |
| 9 - 审计 | 引导检查异常活动（GitHub 安全日志、git 历史、K8s 事件） |

**重要提示：** 本工具仅备份和轮换凭证，不会删除任何原始文件——操作前始终会先创建备份。

## 支持平台

- macOS (Intel / Apple Silicon)
- Linux (Debian/Ubuntu, RHEL/CentOS, Arch)

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
- 联系集群管理员重新颁发 kubeconfig
- 修改 Docker Hub / Harbor 密码并重新登录
- 检查 macOS 钥匙串条目
- 通知团队相关人员

## 工作原理

1. **系统扫描** — 检测平台（macOS/Linux）、已安装工具、现有凭证、Apifox 痕迹
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
│   ├── 00-forensics.sh ... 09-audit.sh
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
4. 在 `src/footer.sh` 中添加 `run_module_NN` 调用
5. 更新 `build.sh` 的 FILES 数组
6. 运行 `./build.sh`

## 参考链接

- [官方公告](https://mp.weixin.qq.com/s/GpACQdnhVNsMn51cm4hZig)
- 安全联系: security@apifox.com

## 许可证

MIT
