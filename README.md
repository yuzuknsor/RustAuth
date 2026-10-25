# RustAuth

![版本](https://img.shields.io/badge/release-v0.1.1-blue) ![许可](https://img.shields.io/badge/license-AGPL--3.0--or--later-green)

Windows 桌面验证器（authenticator）：通用 TOTP、Steam Guard、Battle.net 登录码。
托盘常驻、取码即走、vault 格式公开可迁移。

**Author: [KNSOR](https://github.com/yuzuknsor)**

## 下载

最新版 [RustAuth-v0.1.1-windows-x64.zip](https://github.com/yuzuknsor/winauth/releases/latest)
（免安装，解压即用；或从源码构建：`cargo build --release -p rustauth-gui`）。

> 本仓库为独立 Rust 工程；上游原始 C# 仓库见 [winauth/winauth](https://github.com/winauth/winauth)（已归档）。

## 功能

| 能力 | 说明 |
|---|---|
| 通用 TOTP | RFC 6238，HMAC-SHA1/256/512，6–10 位，步长可配（RFC 官方向量全覆盖测试） |
| Steam Guard | 26 字符表登录码 |
| Battle.net | 8 位登录码（从旧配置迁移导入） |
| Vault 存储 | AES-256-GCM + DPAPI 包裹主密钥 + 可选 argon2id 密码层，[格式公开](docs/vault-format-v1.md) |
| 取码即走 | 托盘驻留 / 全局热键 `Ctrl+Alt+C` / 剪贴板定时自动清除（默认 30s） |
| 导入 | **旧版 WinAuth 配置一键迁移**、otpauth:// URI 直贴、Base32 手输 |
| 管理与防护 | 单实例、关窗驻留、新码自动复制（可选）、密钥输入遮罩、密钥用后内存清零 |

## 快速上手

1. 解压运行 `rustauth.exe`（首启自动创建本地 vault）；
2. 从旧版 WinAuth 迁移：顶栏「导入」→ 默认已填好旧配置路径 → 导入；
3. 点条目「复制」取码，或任何界面按 `Ctrl+Alt+C`。

## 溯源与许可证

RustAuth 是 [winauth/winauth](https://github.com/winauth/winauth)（Copyright (C) 2011
Colin Mackie，GPL-3.0-or-later，已归档停更）的全新 Rust 重写，属其衍生作品。

- 本仓库以 **AGPL-3.0-or-later** 发布——上游为 "GPL-3.0 **或更高版本**"，
  依据 FSF 许可证兼容矩阵（GPLv3 → AGPLv3 单向兼容），衍生作品可选择以
  AGPL-3.0 传播，反向（AGPL → GPL）不允许。
- 详见 [LICENSE](LICENSE) 与 [NOTICE]；上游原始代码见其公开仓库。
- 本项目与 Rust 基金会 / Rust 官方 / 上游 WinAuth 及任何同名项目无关，
  "Rust" 仅作语言描述性使用。

## 构建

依赖：Rust stable（MSVC target，随 [rustup](https://rustup.rs) 默认安装）+ Visual Studio 生成工具（C++ 工作负载）。

```bash
cargo build --release        # 全部
cargo test --workspace       # 算法向量与 vault 测试
cargo clippy --workspace --all-targets -- -D warnings
```

## 安全

验证器是安全敏感软件：请勿在 issue 中粘贴真实密钥或 vault 文件；
漏洞报告方式见 [SECURITY.md](SECURITY.md)。

## 贡献

见 [CONTRIBUTING.md](CONTRIBUTING.md)。提交即表示贡献以 AGPL-3.0-or-later 授权。

---

© 2026 [KNSOR](https://github.com/yuzuknsor) · AGPL-3.0-or-later ·
衍生自 Colin Mackie 的 WinAuth（GPL-3.0-or-later）
