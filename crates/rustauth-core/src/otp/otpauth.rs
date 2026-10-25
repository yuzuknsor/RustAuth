// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! otpauth:// URI 解析与构建（Google Authenticator key URI 格式）。
//!
//! 形如：
//! `otpauth://totp/Issuer:account?secret=BASE32&issuer=Issuer&algorithm=SHA1&digits=6&period=30`
//! `otpauth://hotp/Label?secret=BASE32&counter=10`

use std::fmt;

use super::error::OtpError;
use super::provider::{CodeConfig, Provider};
use super::totp::HmacAlgo;
use crate::base32;

/// URI 解析结果（中间表示，尚未落到 Provider）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpAuthUri {
    /// totp | hotp
    pub kind: OtpKind,
    /// 标签（Issuer:account 原文，可能无 Issuer 前缀）
    pub label: String,
    /// 显式 issuer 参数（与标签前缀可能都有，规范要求一致）
    pub issuer: Option<String>,
    pub secret: Vec<u8>,
    pub digits: u32,
    pub period_secs: u32,
    pub algorithm: HmacAlgo,
    /// hotp 专用计数器
    pub counter: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpKind {
    Totp,
    Hotp,
}

impl OtpKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::Hotp => "hotp",
        }
    }
}

impl fmt::Display for OtpAuthUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "otpauth://{}/{}",
            self.kind.label(),
            percent_encode(&self.label)
        )?;
        let mut params: Vec<String> =
            vec![format!("secret={}", base32::encode(&self.secret, false))];
        if let Some(issuer) = &self.issuer {
            params.push(format!("issuer={}", percent_encode(issuer)));
        }
        if self.algorithm != HmacAlgo::Sha1 {
            params.push(format!("algorithm={}", self.algorithm.label()));
        }
        if self.digits != 6 {
            params.push(format!("digits={}", self.digits));
        }
        if self.period_secs != 30 {
            params.push(format!("period={}", self.period_secs));
        }
        if let Some(c) = self.counter {
            params.push(format!("counter={c}"));
        }
        write!(f, "?{}", params.join("&"))
    }
}

/// 解析 otpauth:// URI。
pub fn parse(uri: &str) -> Result<OtpAuthUri, OtpError> {
    let invalid = |m: &str| Err(OtpError::InvalidUri(m.to_string()));

    let rest = uri
        .strip_prefix("otpauth://")
        .ok_or_else(|| OtpError::InvalidUri("missing otpauth:// scheme".into()))?;
    let (kind_str, rest) = rest
        .split_once('/')
        .ok_or_else(|| OtpError::InvalidUri("missing type/label".into()))?;
    let kind = match kind_str.to_ascii_lowercase().as_str() {
        "totp" => OtpKind::Totp,
        "hotp" => OtpKind::Hotp,
        other => return invalid(&format!("unknown type {other:?}")),
    };
    let (label_raw, query) = rest
        .split_once('?')
        .ok_or_else(|| OtpError::InvalidUri("missing query string".into()))?;
    if label_raw.is_empty() {
        return invalid("empty label");
    }
    let label = percent_decode(label_raw);

    let mut issuer = None;
    let mut secret_b32 = None;
    let mut digits = 6u32;
    let mut period = 30u32;
    let mut algorithm = HmacAlgo::Sha1;
    let mut counter = None;

    for kv in query.split('&') {
        if kv.is_empty() {
            continue;
        }
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| OtpError::InvalidUri(format!("bad query pair {kv:?}")))?;
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret_b32 = Some(v.to_string()),
            "issuer" => issuer = Some(percent_decode(v)),
            "algorithm" => algorithm = HmacAlgo::parse(&percent_decode(v))?,
            "digits" => {
                digits = v
                    .parse()
                    .map_err(|_| OtpError::InvalidUri(format!("bad digits {v:?}")))?;
            }
            "period" => {
                period = v
                    .parse()
                    .map_err(|_| OtpError::InvalidUri(format!("bad period {v:?}")))?;
            }
            "counter" => {
                counter = Some(
                    v.parse()
                        .map_err(|_| OtpError::InvalidUri(format!("bad counter {v:?}")))?,
                );
            }
            _ => {} // 未知参数宽容忽略（前向兼容）
        }
    }

    let secret = base32::decode(
        secret_b32
            .as_deref()
            .ok_or_else(|| OtpError::InvalidUri("missing secret".into()))?,
    )
    .map_err(|e| OtpError::InvalidUri(e.to_string()))?;
    if secret.is_empty() {
        return invalid("empty secret");
    }

    // 标签前缀 issuer 与显式 issuer 参数并存时必须一致（RFC 推荐，宽松取参数）
    if let (Some(prefix), Some(param)) = (label.split_once(':'), issuer.as_ref()) {
        if prefix.0.trim() != param.trim() {
            return invalid("issuer in label and query mismatch");
        }
    }

    Ok(OtpAuthUri {
        kind,
        label,
        issuer,
        secret,
        digits,
        period_secs: period,
        algorithm,
        counter,
    })
}

impl OtpAuthUri {
    /// 落到 Provider（Hotp 必须带 counter）。
    pub fn to_provider(&self) -> Result<Provider, OtpError> {
        let cfg = CodeConfig {
            secret: self.secret.clone(),
            digits: self.digits,
            period_secs: self.period_secs,
            hmac: self.algorithm,
            time_offset_ms: 0,
        };
        match self.kind {
            OtpKind::Totp => Ok(Provider::Totp(cfg)),
            OtpKind::Hotp => Ok(Provider::Hotp(
                cfg,
                self.counter
                    .ok_or_else(|| OtpError::InvalidUri("hotp requires counter".into()))?,
            )),
        }
    }

    /// 从 Provider 构建 URI（Hotp 需要当前计数器）。
    pub fn from_provider(issuer: &str, account: &str, p: &Provider, counter: Option<u64>) -> Self {
        let (kind, cfg) = match p {
            Provider::Totp(c) | Provider::BattleNet(c) => (OtpKind::Totp, c),
            Provider::Steam(c) => (OtpKind::Totp, c),
            Provider::Hotp(c, _) => (OtpKind::Hotp, c),
        };
        let label = if issuer.is_empty() {
            account.to_string()
        } else {
            format!("{issuer}:{account}")
        };
        OtpAuthUri {
            kind,
            label,
            issuer: if issuer.is_empty() {
                None
            } else {
                Some(issuer.to_string())
            },
            secret: cfg.secret.clone(),
            digits: cfg.digits,
            period_secs: cfg.period_secs,
            algorithm: cfg.hmac,
            counter: match p {
                Provider::Hotp(_, c) => Some(*c),
                _ => counter,
            },
        }
    }
}

/// 最小 percent-encode：仅保留 RFC 3986 unreserved 字符。
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// percent-decode；非法序列按字面保留（宽容解析）。
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() + 1 && i + 2 < bytes.len() + 1 {
            let hex = bytes.get(i + 1..i + 3);
            if let Some(hex) = hex {
                if let Ok(v) = u8::from_str_radix(&String::from_utf8_lossy(hex), 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOGLE_EXAMPLE: &str =
        "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";

    #[test]
    fn parse_google_reference() {
        let u = parse(GOOGLE_EXAMPLE).unwrap();
        assert_eq!(u.kind, OtpKind::Totp);
        assert_eq!(u.label, "Example:alice@google.com");
        assert_eq!(u.issuer.as_deref(), Some("Example"));
        // JBSWY3DPEHPK3PXP = "Hello!" + DE AD BE EF
        assert_eq!(u.secret, b"Hello!\xde\xad\xbe\xef");
        assert_eq!(u.digits, 6);
        assert_eq!(u.period_secs, 30);
        assert_eq!(u.algorithm, HmacAlgo::Sha1);
    }

    #[test]
    fn parse_hotp_with_counter() {
        let u = parse("otpauth://hotp/Counter?secret=JBSWY3DPEHPK3PXP&counter=10").unwrap();
        assert_eq!(u.kind, OtpKind::Hotp);
        assert_eq!(u.counter, Some(10));
        let p = u.to_provider().unwrap();
        // HOTP(secret, 10)——RFC 4226 secret "Hello!\xde\xad\xbe\xef" 不在附录 D，
        // 这里验证计数器语义：不同 counter 产生不同码
        let p10 = p.code_at(0).unwrap();
        let Provider::Hotp(cfg, _) = &p else { panic!() };
        let p11 = crate::otp::totp::hotp_at_counter(&cfg.secret, 11, 6, HmacAlgo::Sha1);
        assert_ne!(p10, p11);
    }

    #[test]
    fn parse_percent_encoded_label() {
        let u = parse(
            "otpauth://totp/ACME%20Co:john.doe%40acme.example?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co",
        )
        .unwrap();
        assert_eq!(u.label, "ACME Co:john.doe@acme.example");
        assert_eq!(u.issuer.as_deref(), Some("ACME Co"));
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse("https://example.com").is_err());
        assert!(parse("otpauth://yubi/label?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(parse("otpauth://totp/label").is_err());
        assert!(parse("otpauth://totp/label?secret=!!!").is_err());
        assert!(parse("otpauth://totp/label?secret=").is_err());
    }

    #[test]
    fn issuer_mismatch_rejected() {
        assert!(parse("otpauth://totp/Other:acct?secret=JBSWY3DPEHPK3PXP&issuer=Example").is_err());
    }

    #[test]
    fn build_roundtrip() {
        let u = parse(GOOGLE_EXAMPLE).unwrap();
        let rebuilt = u.to_string();
        let u2 = parse(&rebuilt).unwrap();
        assert_eq!(u, u2, "roundtrip via {rebuilt}");
    }

    #[test]
    fn build_defaults_omitted() {
        // 默认参数（SHA1/6/30）不出现在 URI 中
        let u = parse(GOOGLE_EXAMPLE).unwrap();
        assert!(!u.to_string().contains("algorithm="));
        assert!(!u.to_string().contains("digits="));
        assert!(!u.to_string().contains("period="));
    }

    #[test]
    fn from_provider_and_code_match() {
        let secret = b"12345678901234567890".to_vec();
        let p = Provider::Totp(CodeConfig::standard(secret));
        let u = OtpAuthUri::from_provider("MyIssuer", "me@example.com", &p, None);
        let parsed = parse(&u.to_string()).unwrap();
        let p2 = parsed.to_provider().unwrap();
        assert_eq!(p.code_at(59_000).unwrap(), p2.code_at(59_000).unwrap());
    }
}
