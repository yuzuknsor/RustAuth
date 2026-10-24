// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Base32 编解码（RFC 4648，标准字母表，无填充输入亦接受）。

use std::fmt;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Base32Error {
    /// 非法字符（仅允许 A-Z、2-7，空白被忽略）
    InvalidByte(u8),
    /// 输入长度产生的尾部位数不足以构成任何输出字节
    InvalidLength,
}

impl fmt::Display for Base32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidByte(b) => write!(f, "invalid base32 byte {b:#04x} ('{}')", *b as char),
            Self::InvalidLength => write!(f, "invalid base32 length"),
        }
    }
}

impl std::error::Error for Base32Error {}

/// 解码 base32（忽略空白与 `=` 填充，大小写不敏感）。
pub fn decode(input: &str) -> Result<Vec<u8>, Base32Error> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for ch in input.bytes() {
        let v = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a',
            b'2'..=b'7' => ch - b'2' + 26,
            b' ' | b'\t' | b'\r' | b'\n' | b'=' | b'-' => continue,
            other => return Err(Base32Error::InvalidByte(other)),
        };
        buf = (buf << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    // 剩余 1-4 位均为零填充位，RFC 允许；非零属编码错误但解码器宽容处理
    Ok(out)
}

/// 编码为标准 base32（无填充；`pad=true` 时按 RFC 补 `=`）。
pub fn encode(data: &[u8], pad: bool) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    for chunk in data.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let n = u64::from_be_bytes([0, 0, 0, buf[0], buf[1], buf[2], buf[3], buf[4]]);
        let chars = chunk.len() * 8 / 5 + if chunk.len() * 8 % 5 > 0 { 1 } else { 0 };
        for i in 0..8 {
            if i < chars {
                let idx = ((n >> (35 - i * 5)) & 0x1f) as usize;
                out.push(ALPHABET[idx] as char);
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4649_vectors() {
        // RFC 4648 §10 测试向量（base32）
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "MY"),
            (b"fo", "MZXQ"),
            (b"foo", "MZXW6"),
            (b"foob", "MZXW6YQ"),
            (b"fooba", "MZXW6YTB"),
            (b"foobar", "MZXW6YTBOI"),
        ];
        for (raw, enc) in cases {
            assert_eq!(&encode(raw, false), enc, "encode {raw:?}");
            assert_eq!(&decode(enc).unwrap(), raw, "decode {enc}");
        }
    }

    #[test]
    fn decode_tolerates_case_and_spaces() {
        assert_eq!(decode("mzxw6 ytboi").unwrap(), b"foobar");
        assert_eq!(decode("MZxW6YTB==").unwrap(), b"fooba");
    }

    #[test]
    fn rejects_invalid_chars() {
        assert!(decode("MZ1W6").is_err());
        assert!(decode("0OIL").is_err()); // 0/1/8/9 不在字母表
    }
}
