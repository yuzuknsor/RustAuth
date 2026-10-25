// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vault 条目与 Provider 的 serde 映射。
//!
//! 存储格式（entries JSON）与本内存类型解耦：`ProviderSer` 是稳定的磁盘
//! 表示，`Provider` 是内存表示，两者经 `From`/`TryFrom` 转换。

use serde::{Deserialize, Serialize};

use crate::otp::provider::{CodeConfig, Provider};
use crate::otp::totp::HmacAlgo;
use crate::vault::error::VaultError;

/// 磁盘上的 provider 表示（格式见 docs/vault-format-v1.md）。
/// Debug 对密钥脱敏（authenticator 安全基线）。
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderSer {
    pub kind: String,
    pub secret_b32: String,
    pub digits: u32,
    pub period_secs: u32,
    pub algorithm: String,
    #[serde(default)]
    pub time_offset_ms: i64,
    #[serde(default)]
    pub counter: Option<u64>,
}

impl std::fmt::Debug for ProviderSer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderSer")
            .field("kind", &self.kind)
            .field(
                "secret_b32",
                &format_args!("[REDACTED {} chars]", self.secret_b32.len()),
            )
            .field("digits", &self.digits)
            .field("period_secs", &self.period_secs)
            .field("algorithm", &self.algorithm)
            .field("time_offset_ms", &self.time_offset_ms)
            .field("counter", &self.counter)
            .finish()
    }
}

impl TryFrom<&Provider> for ProviderSer {
    type Error = VaultError;

    fn try_from(p: &Provider) -> Result<Self, Self::Error> {
        let (kind, c, counter) = match p {
            Provider::Totp(c) => ("totp", c, None),
            Provider::Steam(c) => ("steam", c, None),
            Provider::BattleNet(c) => ("battle_net", c, None),
            Provider::Hotp(c, n) => ("hotp", c, Some(*n)),
        };
        Ok(Self {
            kind: kind.to_string(),
            secret_b32: crate::base32::encode(&c.secret, false),
            digits: c.digits,
            period_secs: c.period_secs,
            algorithm: c.hmac.label().to_string(),
            time_offset_ms: c.time_offset_ms,
            counter,
        })
    }
}

impl TryFrom<&ProviderSer> for Provider {
    type Error = VaultError;

    fn try_from(s: &ProviderSer) -> Result<Self, Self::Error> {
        let secret = crate::base32::decode(&s.secret_b32)
            .map_err(|e| VaultError::Serialize(format!("bad secret base32: {e}")))?;
        if secret.is_empty() {
            return Err(VaultError::Serialize("empty secret".into()));
        }
        let hmac =
            HmacAlgo::parse(&s.algorithm).map_err(|e| VaultError::Serialize(e.to_string()))?;
        let cfg = CodeConfig {
            secret,
            digits: s.digits,
            period_secs: s.period_secs,
            hmac,
            time_offset_ms: s.time_offset_ms,
        };
        match s.kind.as_str() {
            "totp" => Ok(Provider::Totp(cfg)),
            "steam" => Ok(Provider::Steam(cfg)),
            "battle_net" => Ok(Provider::BattleNet(cfg)),
            "hotp" => Ok(Provider::Hotp(
                cfg,
                s.counter
                    .ok_or_else(|| VaultError::Serialize("hotp missing counter".into()))?,
            )),
            other => Err(VaultError::Serialize(format!(
                "unknown provider kind {other:?}"
            ))),
        }
    }
}

/// 磁盘上的单条目。
/// Debug 透传已脱敏的 ProviderSer。
#[derive(Clone, Serialize, Deserialize)]
pub struct VaultEntrySer {
    pub id: String,
    pub name: String,
    pub created_ms: i64,
    pub provider: ProviderSer,
}

impl std::fmt::Debug for VaultEntrySer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultEntrySer")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("created_ms", &self.created_ms)
            .field("provider", &self.provider)
            .finish()
    }
}

/// base64 编解码助手（供 wrap 层使用）。
pub(crate) mod b64 {
    use base64::Engine as _;
    pub fn encode(data: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(data)
    }
    pub fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
        base64::engine::general_purpose::STANDARD.decode(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ProviderSer {
        ProviderSer {
            kind: "totp".into(),
            secret_b32: "MZXW6YTBOI".into(), // foobar
            digits: 6,
            period_secs: 30,
            algorithm: "SHA1".into(),
            time_offset_ms: 0,
            counter: None,
        }
    }

    #[test]
    fn provider_ser_roundtrip() {
        let ser = sample();
        let p = Provider::try_from(&ser).unwrap();
        let back = ProviderSer::try_from(&p).unwrap();
        assert_eq!(ser, back);
        // Steam 与 battle_net kind 往返
        let mut s2 = sample();
        s2.kind = "steam".into();
        let p2 = Provider::try_from(&s2).unwrap();
        assert!(matches!(p2, Provider::Steam(_)));
        assert_eq!(ProviderSer::try_from(&p2).unwrap(), s2);
        let mut s3 = sample();
        s3.kind = "battle_net".into();
        s3.digits = 8;
        let p3 = Provider::try_from(&s3).unwrap();
        assert!(matches!(p3, Provider::BattleNet(_)));
        assert_eq!(ProviderSer::try_from(&p3).unwrap(), s3);
    }

    #[test]
    fn hotp_requires_counter() {
        let mut s = sample();
        s.kind = "hotp".into();
        assert!(Provider::try_from(&s).is_err());
        s.counter = Some(7);
        let p = Provider::try_from(&s).unwrap();
        assert!(matches!(p, Provider::Hotp(_, 7)));
    }

    #[test]
    fn unknown_kind_rejected() {
        let mut s = sample();
        s.kind = "guild_wars".into();
        assert!(Provider::try_from(&s).is_err());
    }

    #[test]
    fn b64_helper() {
        let enc = b64::encode(&[0, 255, 16]);
        assert_eq!(b64::decode(&enc).unwrap(), vec![0, 255, 16]);
    }
}
