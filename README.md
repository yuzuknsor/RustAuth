# WinAuth (Rust)

Windows 桌面验证器（authenticator）：通用 TOTP、Steam Guard、Battle.net 登录码。
托盘常驻、取码即走、vault 格式公开可迁移。

> **状态**：早期开发（Rust 全新重写进行中），尚无可用发行版。

## 溯源与许可证

本项目是 [winauth/winauth](https://github.com/winauth/winauth)（Copyright (C) 2011
Colin Mackie，GPL-3.0-or-later，已归档停更）的全新 Rust 重写，属其衍生作品。

- 本仓库以 **AGPL-3.0-or-later** 发布——上游为 "GPL-3.0 **或更高版本**"，
  依据 FSF 许可证兼容矩阵（GPLv3 → AGPLv3 单向兼容），衍生作品可选择以
  AGPL-3.0 传播，反向（AGPL → GPL）不允许。
- AGPL 对 GPL 附加了"网络交互也须提供源码"的更强传染性条款；桌面应用场景
  下与 GPL 义务一致：分发二进制时必须提供对应源码（本仓库即源）。
- 详见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)；上游原始代码冻结保留在 `master` 分支。

## 功能目标

| 能力 | 说明 |
|---|---|
| 通用 TOTP | RFC 6238，HMAC-SHA1/256/512，6/8 位，步长可配 |
| Steam Guard | 26 字符表登录码（交易确认为实验特性） |
| Battle.net | 8 位登录码（迁移导入优先，注册 API 为实验特性） |
| Vault 存储 | AES-256-GCM + DPAPI 包裹主密钥，格式公开 |
| 取码即走 | 托盘 / 全局热键 / 剪贴板 30s 自动清除 |
| 迁移 | 旧 WinAuth 配置导入、otpauth:// 导入导出、QR |

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
