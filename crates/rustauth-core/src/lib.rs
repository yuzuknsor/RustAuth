// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! rustauth-core：RustAuth 核心库。
//!
//! 模块：OTP 算法（RFC 4226/6238、Steam、Battle.net）、otpauth:// URI、
//! vault 加密存储、旧版 WinAuth 迁移（M4）。

pub mod base32;
pub mod otp;
pub mod vault;

pub const NAME: &str = "rustauth-core";
