# 贡献指南

感谢关注 WinAuth 的 Rust 重写。

## 开发环境

- Rust stable（`rustup default stable-msvc`）
- Visual Studio 生成工具（含 C++ 桌面开发工作负载，提供 MSVC 链接器）
- `cargo build && cargo test --workspace` 通过是提 PR 的最低门槛

## 提交规范

- 消息格式：`类型: 中文或英文短句`，类型取 `feat / fix / chore / docs / test / refactor`
- 每个提交保持可编译、可回退的原子单元

## 代码要求

- `cargo clippy --workspace --all-targets -- -D warnings` 零警告
- `cargo fmt --all` 已格式化
- 新增算法/格式逻辑必须伴随测试（RFC 官方向量优先）
- 新增依赖必须在 `deny.toml` 许可清单允许范围内（宽纵许可；不接受 GPL/AGPL/LGPL 依赖）
- 源文件头部统一携带 SPDX 标识：`SPDX-License-Identifier: AGPL-3.0-or-later`

## 许可

提交贡献即表示同意以 AGPL-3.0-or-later（或更新版本）授权本项目使用你的贡献。
