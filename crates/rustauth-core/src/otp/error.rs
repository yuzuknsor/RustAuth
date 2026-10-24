// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! OTP 错误类型。

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtpError {
    /// 密钥为空
    EmptySecret,
    /// HMAC 算法不支持
    UnsupportedAlgorithm(String),
    /// 参数越界（位数/步长）
    InvalidParameter(String),
    /// URI 解析失败
    InvalidUri(String),
}

impl fmt::Display for OtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySecret => write!(f, "secret key is empty"),
            Self::UnsupportedAlgorithm(a) => write!(f, "unsupported HMAC algorithm: {a}"),
            Self::InvalidParameter(p) => write!(f, "invalid parameter: {p}"),
            Self::InvalidUri(u) => write!(f, "invalid otpauth URI: {u}"),
        }
    }
}

impl std::error::Error for OtpError {}
