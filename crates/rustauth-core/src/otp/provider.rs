// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Provider 抽象：enum dispatch（提供商为封闭集，穷举优于动态分发）。

use std::fmt;

use super::error::OtpError;
use super::steam;
use super::totp;
use super::totp::HmacAlgo;

/// 通用码参数（Google/Microsoft/Steam/Battle.net 共用）。
/// Debug 输出对密钥脱敏（authenticator 安全基线）。
#[derive(Clone)]
pub struct CodeConfig {
    pub secret: Vec<u8>,
    pub digits: u32,
    pub period_secs: u32,
    pub hmac: HmacAlgo,
    /// 与本地时钟的偏移（毫秒，>0 表示服务器快于本地）
    pub time_offset_ms: i64,
}

impl fmt::Debug for CodeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodeConfig")
            .field(
                "secret",
                &format_args!("[REDACTED {} bytes]", self.secret.len()),
            )
            .field("digits", &self.digits)
            .field("period_secs", &self.period_secs)
            .field("hmac", &self.hmac)
            .field("time_offset_ms", &self.time_offset_ms)
            .finish()
    }
}

impl CodeConfig {
    pub fn standard(secret: Vec<u8>) -> Self {
        Self {
            secret,
            digits: 6,
            period_secs: 30,
            hmac: HmacAlgo::Sha1,
            time_offset_ms: 0,
        }
    }

    /// Battle.net：8 位，30 秒步长（与原 WinAuth 基类默认一致）。
    pub fn battle_net(secret: Vec<u8>) -> Self {
        Self {
            digits: 8,
            ..Self::standard(secret)
        }
    }
}

/// 验证器类型（封闭集）。
#[derive(Clone)]
pub enum Provider {
    /// 基于时间的标准 OTP（Google 等）
    Totp(CodeConfig),
    /// 基于计数器的 HOTP
    Hotp(CodeConfig, u64),
    /// Steam Guard 登录码
    Steam(CodeConfig),
    /// Battle.net（8 位 TOTP——原实现未重写码生成，即标准 TOTP）
    BattleNet(CodeConfig),
}

/// 内层 CodeConfig 的 Debug 已脱敏，直接透传。
impl fmt::Debug for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Totp(c) => f.debug_tuple("Totp").field(c).finish(),
            Self::Hotp(c, n) => f.debug_tuple("Hotp").field(c).field(n).finish(),
            Self::Steam(c) => f.debug_tuple("Steam").field(c).finish(),
            Self::BattleNet(c) => f.debug_tuple("BattleNet").field(c).finish(),
        }
    }
}

impl Provider {
    /// 给定毫秒时间戳（Hotp 忽略该参数）生成当前码。
    pub fn code_at(&self, unix_ms: i64) -> Result<String, OtpError> {
        match self {
            Self::Totp(c) | Self::BattleNet(c) => {
                totp::validate_params(&c.secret, c.digits, c.period_secs)?;
                Ok(totp::totp_at(
                    &c.secret,
                    unix_ms + c.time_offset_ms,
                    c.period_secs,
                    c.digits,
                    c.hmac,
                ))
            }
            Self::Hotp(c, counter) => {
                totp::validate_params(&c.secret, c.digits, c.period_secs)?;
                Ok(totp::hotp_at_counter(&c.secret, *counter, c.digits, c.hmac))
            }
            Self::Steam(c) => {
                steam::steam_code_at(&c.secret, unix_ms + c.time_offset_ms, c.period_secs)
            }
        }
    }

    /// 当前时间步剩余毫秒（Hotp 无周期，返回 u32::MAX）。
    pub fn remaining_ms(&self, unix_ms: i64) -> u32 {
        match self {
            Self::Totp(c) | Self::BattleNet(c) => totp::remaining_ms(unix_ms, c.period_secs),
            Self::Steam(c) => steam::remaining_ms(unix_ms, c.period_secs),
            Self::Hotp(..) => u32::MAX,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_provider_matches_core() {
        let secret = b"12345678901234567890".to_vec();
        let p = Provider::Totp(CodeConfig::standard(secret));
        assert_eq!(p.code_at(59_000).unwrap(), "287082");
    }

    #[test]
    fn battle_net_is_8_digits() {
        let secret = b"12345678901234567890".to_vec();
        let p = Provider::BattleNet(CodeConfig::battle_net(secret));
        let code = p.code_at(59_000).unwrap();
        assert_eq!(code.len(), 8);
        // RFC 6238 t=59 向量原值（8 位，末 6 位即 287082）
        assert_eq!(code, "94287082");
    }

    #[test]
    fn hotp_ignores_time_and_uses_counter() {
        let secret = b"12345678901234567890".to_vec();
        let p = Provider::Hotp(CodeConfig::standard(secret), 3);
        assert_eq!(p.code_at(0).unwrap(), "969429");
        assert_eq!(p.code_at(999_999_999).unwrap(), "969429");
        assert_eq!(p.remaining_ms(0), u32::MAX);
    }

    #[test]
    fn steam_via_provider() {
        let secret = b"12345678901234567890".to_vec();
        let p = Provider::Steam(CodeConfig::standard(secret));
        let code = p.code_at(1_700_000_000_000).unwrap();
        assert_eq!(code.len(), 5);
    }

    #[test]
    fn time_offset_shifts_result() {
        let secret = b"12345678901234567890".to_vec();
        let base = Provider::Totp(CodeConfig::standard(secret.clone()));
        let shifted = Provider::Totp(CodeConfig {
            time_offset_ms: 30_000,
            ..CodeConfig::standard(secret)
        });
        // +30s 偏移 = 无偏移时的未来一步
        assert_eq!(
            shifted.code_at(59_000).unwrap(),
            base.code_at(89_000).unwrap()
        );
    }
}
