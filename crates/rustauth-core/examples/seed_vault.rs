// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! 向真实 vault（%APPDATA%\rustauth\vault.bin）写入一条 RFC 6238 官方测试
//! 密钥条目，供 GUI 功能检查使用（公开测试密钥，无安全风险）。
//!
//! 用法：cargo run -p rustauth-core --example seed_vault -- [名称]

use rustauth_core::otp::provider::{CodeConfig, Provider};
use rustauth_core::vault::Vault;

fn main() {
    let name = std::env::args().nth(1).unwrap_or_else(|| "功能测试".into());
    let path = dirs_::vault_path().expect("无法定位 vault 路径");
    let mut vault = if path.exists() {
        Vault::load_from(&path, None).expect("打开 vault 失败")
    } else {
        Vault::new().expect("新建 vault 失败")
    };
    // RFC 6238 附录 B 官方测试密钥（公开值）
    let secret = b"12345678901234567890".to_vec();
    vault
        .add_entry(&name, Provider::Totp(CodeConfig::standard(secret)))
        .expect("写入条目失败");
    vault.save_to(&path).expect("保存失败");
    println!("已写入条目「{name}」→ {}", path.display());
}

/// 避免 core 依赖 dirs：直接复用 GUI 侧的路径规则。
mod dirs_ {
    pub fn vault_path() -> Option<std::path::PathBuf> {
        std::env::var_os("APPDATA").map(|a| {
            std::path::PathBuf::from(a)
                .join("rustauth")
                .join("vault.bin")
        })
    }
}
