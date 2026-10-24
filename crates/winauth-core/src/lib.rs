// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! winauth-core：WinAuth 重写核心库。
//!
//! M1 起逐步提供：OTP 算法（RFC 4226/6238、Steam、Battle.net）、
//! otpauth:// URI、vault 加密存储与旧版迁移。

pub const NAME: &str = "winauth-core";
