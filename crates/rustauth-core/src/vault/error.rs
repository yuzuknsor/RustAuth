// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vault 错误类型。

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// magic 不符
    BadMagic,
    /// 版本高于本实现支持
    UnsupportedVersion(u32),
    /// 结构/长度损坏
    Malformed(&'static str),
    /// DPAPI 解开失败（非本机/本用户创建的 vault）
    UnwrapFailed(String),
    /// 解密失败（GCM 认证不通过 = 篡改或主密钥错误）
    DecryptFailed,
    /// 序列化错误
    Serialize(String),
    /// 条目不存在
    EntryNotFound(String),
    /// 无任何可用的解锁途径
    NoWraps,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => write!(f, "not a RustAuth vault file"),
            Self::UnsupportedVersion(v) => write!(f, "vault version {v} not supported (max 1)"),
            Self::Malformed(m) => write!(f, "vault malformed: {m}"),
            Self::UnwrapFailed(m) => write!(f, "key unwrap failed: {m}"),
            Self::DecryptFailed => write!(f, "vault decrypt failed (tampered or wrong key)"),
            Self::Serialize(m) => write!(f, "vault serialize error: {m}"),
            Self::EntryNotFound(id) => write!(f, "entry {id} not found"),
            Self::NoWraps => write!(f, "no usable key wrap in vault"),
        }
    }
}

impl std::error::Error for VaultError {}
