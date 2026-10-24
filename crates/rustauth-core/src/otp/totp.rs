// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HOTP（RFC 4226）与 TOTP（RFC 6238）。
//!
//! 纯函数核心 `hotp_at_counter`；TOTP = HOTP(counter = floor((t-T0)/X))，T0=0。

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use super::error::OtpError;

macro_rules! hmac_of {
    ($hash:ty, $secret:expr, $msg:expr) => {{
        // HMAC 对任意长度密钥均合法；空密钥在入口校验层拒绝
        let mut mac =
            <Hmac<$hash> as Mac>::new_from_slice($secret).expect("HMAC accepts any key length");
        mac.update($msg);
        mac.finalize().into_bytes().to_vec()
    }};
}

/// HMAC 算法选择。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HmacAlgo {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl HmacAlgo {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    pub fn parse(label: &str) -> Result<Self, OtpError> {
        Ok(match label.to_ascii_uppercase().as_str() {
            "SHA1" => Self::Sha1,
            "SHA256" => Self::Sha256,
            "SHA512" => Self::Sha512,
            other => return Err(OtpError::UnsupportedAlgorithm(other.to_string())),
        })
    }

    /// RFC 4226 §5.3 动态截断：末字节低 4 位定偏移，取 4 字节去符号位，31bit 整数。
    pub(crate) fn truncated_u31(mac: &[u8]) -> u64 {
        let offset = (mac[mac.len() - 1] & 0x0f) as usize;
        let bin = u32::from_be_bytes([
            mac[offset],
            mac[offset + 1],
            mac[offset + 2],
            mac[offset + 3],
        ]) & 0x7fff_ffff;
        u64::from(bin)
    }

    /// 截断整数十进制表示（digits 位，前导零填充）。
    pub(crate) fn decimal_code(full: u64, digits: u32) -> String {
        let modulus = 10u64.pow(digits);
        format!("{:0width$}", full % modulus, width = digits as usize)
    }
}

fn compute_mac(secret: &[u8], msg: &[u8], algo: HmacAlgo) -> Vec<u8> {
    match algo {
        HmacAlgo::Sha1 => hmac_of!(Sha1, secret, msg),
        HmacAlgo::Sha256 => hmac_of!(Sha256, secret, msg),
        HmacAlgo::Sha512 => hmac_of!(Sha512, secret, msg),
    }
}

/// 校验公共参数（空密钥 / 位数 6-10 / 步长 > 0）。
pub fn validate_params(secret: &[u8], digits: u32, period_secs: u32) -> Result<(), OtpError> {
    if secret.is_empty() {
        return Err(OtpError::EmptySecret);
    }
    if !(6..=10).contains(&digits) {
        return Err(OtpError::InvalidParameter(format!("digits={digits}")));
    }
    if period_secs == 0 {
        return Err(OtpError::InvalidParameter("period=0".into()));
    }
    Ok(())
}

/// 以指定计数器计算 HOTP 码（RFC 4226）。
pub fn hotp_at_counter(secret: &[u8], counter: u64, digits: u32, algo: HmacAlgo) -> String {
    let msg = counter.to_be_bytes();
    let mac = compute_mac(secret, &msg, algo);
    HmacAlgo::decimal_code(HmacAlgo::truncated_u31(&mac), digits)
}

/// 截断后的 31bit 整数（Steam 字符表编码的输入）。
pub fn hotp_fullcode(secret: &[u8], counter: u64) -> u64 {
    let mac = compute_mac(secret, &counter.to_be_bytes(), HmacAlgo::Sha1);
    HmacAlgo::truncated_u31(&mac)
}

/// 以毫秒 Unix 时间计算 TOTP 码（RFC 6238，T0=0，步长 X 秒）。
///
/// `div_euclid` 保证负时间戳（系统时钟早于 1970 的异常场景）不 panic。
pub fn totp_at(
    secret: &[u8],
    unix_ms: i64,
    period_secs: u32,
    digits: u32,
    algo: HmacAlgo,
) -> String {
    let counter = counter_at(unix_ms, period_secs);
    hotp_at_counter(secret, counter, digits, algo)
}

fn counter_at(unix_ms: i64, period_secs: u32) -> u64 {
    (unix_ms.div_euclid(1000) / period_secs as i64) as u64
}

/// 当前时间步剩余毫秒数（进度条用）。
pub fn remaining_ms(unix_ms: i64, period_secs: u32) -> u32 {
    let p = period_secs as i64 * 1000;
    (p - unix_ms.rem_euclid(p)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4226 附录 D：ASCII secret "12345678901234567890"，6 位
    const HOTP_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc4226_appendix_d_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (i, want) in expected.iter().enumerate() {
            let got = hotp_at_counter(HOTP_SECRET, i as u64, 6, HmacAlgo::Sha1);
            assert_eq!(&got, want, "counter={i}");
        }
    }

    // RFC 6238 附录 B：8 位；SHA1 用 20 字节密钥，SHA256 用 32 字节，SHA512 用 64 字节
    const TOTP8_SHA1: &[u8] = b"12345678901234567890";
    const TOTP8_SHA256: &[u8] = b"12345678901234567890123456789012";
    const TOTP8_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    #[test]
    fn rfc6238_appendix_b_vectors() {
        let cases: &[(i64, &str, &str, &str)] = &[
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (t, want1, want256, want512) in cases {
            assert_eq!(
                totp_at(TOTP8_SHA1, t * 1000, 30, 8, HmacAlgo::Sha1),
                *want1,
                "t={t} sha1"
            );
            assert_eq!(
                totp_at(TOTP8_SHA256, t * 1000, 30, 8, HmacAlgo::Sha256),
                *want256,
                "t={t} sha256"
            );
            assert_eq!(
                totp_at(TOTP8_SHA512, t * 1000, 30, 8, HmacAlgo::Sha512),
                *want512,
                "t={t} sha512"
            );
        }
    }

    #[test]
    fn step_boundaries_and_remaining() {
        assert_eq!(remaining_ms(59_000, 30), 1000);
        assert_eq!(remaining_ms(60_000, 30), 30_000);
        let _ = totp_at(TOTP8_SHA1, -1, 30, 6, HmacAlgo::Sha1); // 负时间戳不 panic
    }

    #[test]
    fn param_validation() {
        assert_eq!(validate_params(b"", 6, 30), Err(OtpError::EmptySecret));
        assert!(validate_params(b"k", 5, 30).is_err());
        assert!(validate_params(b"k", 11, 30).is_err());
        assert!(validate_params(b"k", 6, 0).is_err());
        assert!(validate_params(b"k", 6, 30).is_ok());
    }

    #[test]
    fn algo_parse_roundtrip() {
        assert_eq!(HmacAlgo::parse("sha1").unwrap(), HmacAlgo::Sha1);
        assert_eq!(HmacAlgo::parse("SHA512").unwrap(), HmacAlgo::Sha512);
        for a in [HmacAlgo::Sha1, HmacAlgo::Sha256, HmacAlgo::Sha512] {
            assert_eq!(HmacAlgo::parse(a.label()).unwrap(), a);
        }
        assert!(HmacAlgo::parse("md5").is_err());
    }
}
