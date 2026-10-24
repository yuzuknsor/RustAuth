// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HOTP/TOTP 算法层：RFC 4226/6238、Steam Guard、Battle.net（T1 显示码）。

pub mod error;
pub mod provider;
pub mod steam;
pub mod totp;

pub use error::OtpError;
pub use provider::{CodeConfig, Provider};
pub use totp::HmacAlgo;
