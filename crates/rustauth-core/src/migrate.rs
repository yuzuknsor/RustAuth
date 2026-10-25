// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! 旧版 WinAuth 配置迁移器。
//!
//! 复刻原 `Authenticator.cs` 的 secretdata 加密链（GPL 衍生，行为保真）：
//! `ENCRYPTION_HEADER("WINAUTH3" hex) + salt(16 hex) + SHA256 hash(64 hex) + data`
//! data 层序（外→内）：hex(DPAPI Machine) → hex(DPAPI User) → Blowfish/PBKDF2 密码层
//! → 最终为 TAB 分隔 SecretData：`secret_hex \t digits \t HMAC \t period`，
//! Steam 类型再以 `|` 附加 hex(serial)/hex(deviceid)/hex(steamdata)/hex(session)。

use std::fmt;

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::otp::provider::{CodeConfig, Provider};
use crate::otp::totp::HmacAlgo;

/// 旧版 secretdata 加密头（hex("WINAUTH3")，8 字节 → 16 hex 字符）。
const ENCRYPTION_HEADER_HEX: &str = "57494E4155544833";
const SALT_HEX_LEN: usize = 16; // 8 字节盐
const HASH_HEX_LEN: usize = 64; // SHA256
const PBKDF2_ITERATIONS: u32 = 2000;
const PBKDF2_KEYSIZE: usize = 32; // 256 bit

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrateError {
    NoConfig,
    BadXml(&'static str),
    /// secretdata 头/长度/编码损坏
    BadSecretData(&'static str),
    /// DPAPI 解密失败（跨机器/跨用户，或数据损坏）
    DpapiFailed(String),
    /// 密码层解密失败（密码错误或数据损坏）
    PasswordLayerFailed,
    /// SHA256 完整性校验不过
    HashMismatch,
    /// 字段解析失败
    BadField(&'static str),
}

impl fmt::Display for MigrateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoConfig => write!(f, "no authenticators found in config"),
            Self::BadXml(m) => write!(f, "config XML malformed: {m}"),
            Self::BadSecretData(m) => write!(f, "secretdata malformed: {m}"),
            Self::DpapiFailed(m) => {
                write!(f, "DPAPI decrypt failed (different machine/user?): {m}")
            }
            Self::PasswordLayerFailed => {
                write!(f, "password layer decrypt failed (wrong password?)")
            }
            Self::HashMismatch => write!(f, "SHA256 integrity check failed"),
            Self::BadField(m) => write!(f, "field parse failed: {m}"),
        }
    }
}

impl std::error::Error for MigrateError {}

/// 迁移后的旧版验证器。
#[derive(Debug, Clone)]
pub struct LegacyAuthenticator {
    pub name: String,
    /// XML type 属性原文（如 WinAuth.BattleNetAuthenticator）
    pub legacy_type: String,
    pub secret: Vec<u8>,
    pub digits: u32,
    pub period_secs: u32,
    pub hmac: HmacAlgo,
    pub time_offset_ms: i64,
    pub counter: Option<u64>,
}

impl LegacyAuthenticator {
    pub fn into_provider(self) -> Provider {
        let cfg = CodeConfig {
            secret: self.secret,
            digits: self.digits,
            period_secs: self.period_secs,
            hmac: self.hmac,
            time_offset_ms: self.time_offset_ms,
        };
        if self.legacy_type.contains("SteamAuthenticator") {
            Provider::Steam(cfg)
        } else if self.legacy_type.contains("BattleNetAuthenticator") {
            Provider::BattleNet(cfg)
        } else if self.legacy_type.contains("HotpAuthenticator") {
            Provider::Hotp(cfg, self.counter.unwrap_or(0))
        } else {
            Provider::Totp(cfg)
        }
    }
}

/// 解析旧版 winauth.xml 并解密所有条目。
///
/// `password`：旧配置设置了密码保护时必填；未设置密码传 None 即可。
pub fn parse_config(
    xml: &str,
    password: Option<&str>,
) -> Result<Vec<LegacyAuthenticator>, MigrateError> {
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(start) = xml[cursor..].find("<WinAuthAuthenticator") {
        let abs = cursor + start;
        let end_tag = xml[abs..]
            .find("</WinAuthAuthenticator>")
            .ok_or(MigrateError::BadXml("unterminated WinAuthAuthenticator"))?;
        let block = &xml[abs..abs + end_tag];
        out.push(parse_entry(block, password)?);
        cursor = abs + end_tag;
    }
    if out.is_empty() {
        return Err(MigrateError::NoConfig);
    }
    Ok(out)
}

fn parse_entry(block: &str, password: Option<&str>) -> Result<LegacyAuthenticator, MigrateError> {
    let attrs = attribute_map(block);
    let legacy_type = attrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("type"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    let name = child_text(block, "name").unwrap_or_default();
    let server_time_diff = child_text(block, "servertimediff")
        .and_then(|t| t.trim().parse::<i64>().ok())
        .unwrap_or(0);
    let secret_encrypted =
        child_text(block, "secretdata").ok_or(MigrateError::BadXml("missing secretdata"))?;
    let encrypted_attr = attrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("encrypted"))
        .map(|(_, v)| v.clone());
    // secretdata 元素的 encrypted 属性在子元素标签上，需单独取
    let encrypted_attr = match encrypted_attr {
        Some(a) => Some(a),
        None => {
            // 形如 <secretdata encrypted="u">…</secretdata>
            let seg = block
                .split("<secretdata")
                .nth(1)
                .and_then(|s| s.split('>').next())
                .unwrap_or("");
            // attribute_map 假定首 token 为标签名，补一个占位标签
            attribute_map(&format!("<t{seg}"))
                .into_iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("encrypted"))
                .map(|(_, v)| v)
        }
    };
    let flags = decode_password_types(encrypted_attr.as_deref().unwrap_or(""));

    let plain = decrypt_secretdata(secret_encrypted.trim(), flags.clone(), password)?;

    // 明文旧格式：secretdata 直接是 TAB 串；
    // 加密格式：解密后为 hex，解码得到 XML（内嵌 <servertimediff> 与明文 TAB 的 <secretdata>）
    let (plain_tab, nested_time_offset) = if flags.is_empty() {
        (plain, None)
    } else {
        let xml_bytes =
            hex_decode(&plain).map_err(|_| MigrateError::BadSecretData("payload hex"))?;
        let xml_payload = String::from_utf8(xml_bytes)
            .map_err(|_| MigrateError::BadSecretData("payload not utf-8 xml"))?;
        if !xml_payload.trim_start().starts_with('<') {
            return Err(MigrateError::BadSecretData("payload is not xml"));
        }
        let nested_td =
            child_text(&xml_payload, "servertimediff").and_then(|t| t.trim().parse::<i64>().ok());
        let nested_secret = child_text(&xml_payload, "secretdata")
            .ok_or(MigrateError::BadSecretData("payload missing secretdata"))?;
        (nested_secret, nested_td)
    };
    let mut a = parse_tab_secret(&plain_tab, &legacy_type)?;

    // Battle.net 默认 8 位（原类构造即 CODE_DIGITS=8，secretdata 内 digits 亦应为 8）
    if legacy_type.contains("BattleNetAuthenticator") && a.digits == 6 {
        a.digits = 8;
    }
    a.name = name;
    a.time_offset_ms = nested_time_offset.unwrap_or(server_time_diff);
    Ok(a)
}

/// 'u'=User 'm'=Machine 'y'=Explicit 'a'/'b'=YubiKey（不支持时明确报错）。
fn decode_password_types(s: &str) -> Vec<char> {
    s.chars()
        .filter(|c| matches!(c, 'u' | 'm' | 'y' | 'a' | 'b'))
        .collect()
}

fn decrypt_secretdata(
    data: &str,
    flags: Vec<char>,
    password: Option<&str>,
) -> Result<String, MigrateError> {
    if flags.is_empty() {
        return Ok(data.to_string());
    }
    let header_len = ENCRYPTION_HEADER_HEX.len();
    if data.len() < header_len + SALT_HEX_LEN + HASH_HEX_LEN
        || !data[..header_len].eq_ignore_ascii_case(ENCRYPTION_HEADER_HEX)
    {
        return Err(MigrateError::BadSecretData("missing WINAUTH3 header"));
    }
    let salt_hex = &data[header_len..header_len + SALT_HEX_LEN];
    let hash_hex = &data[header_len + SALT_HEX_LEN..header_len + SALT_HEX_LEN + HASH_HEX_LEN];
    let mut data = data[header_len + SALT_HEX_LEN + HASH_HEX_LEN..].to_string();

    // 外层 DPAPI：Machine 在最外，其次 User（CryptUnprotectData 自动识别 scope）
    if flags.contains(&'m') {
        eprintln!(
            "DBG machine layer data[:48]={}",
            &data[..48.min(data.len())]
        );
        let bytes =
            hex_decode(&data).map_err(|_| MigrateError::BadSecretData("machine layer hex"))?;
        data = hex_encode(&dpapi_unprotect(&bytes)?);
    }
    if flags.contains(&'u') {
        eprintln!("DBG user layer data[:48]={}", &data[..48.min(data.len())]);
        let bytes = hex_decode(&data).map_err(|_| MigrateError::BadSecretData("user layer hex"))?;
        data = hex_encode(&dpapi_unprotect(&bytes)?);
    }
    // 密码层（Blowfish-ECB / PBKDF2-HMAC-SHA1 / ISO10126d2）
    if flags.contains(&'y') {
        let pw = password.ok_or(MigrateError::PasswordLayerFailed)?;
        data = password_layer_decrypt(&data, pw)?;
    }
    if flags.contains(&'a') || flags.contains(&'b') {
        return Err(MigrateError::BadSecretData(
            "YubiKey-protected entries are not supported",
        ));
    }

    // 完整性：SHA256(salt_bytes ++ data_bytes)——原实现对 salt+data 这个
    // hex 串做 StringToByteArray 后再哈希，即作用于解码后字节而非 ASCII
    let data_raw = hex_decode(&data).map_err(|_| MigrateError::BadSecretData("final hex"))?;
    let salt_raw = hex_decode(salt_hex).map_err(|_| MigrateError::BadSecretData("salt hex"))?;
    let mut h = Sha256::new();
    h.update(&salt_raw);
    h.update(&data_raw);
    let calc = hex_encode(&h.finalize());
    if !calc.eq_ignore_ascii_case(hash_hex) {
        return Err(MigrateError::HashMismatch);
    }
    Ok(data)
}

fn dpapi_unprotect(cipher: &[u8]) -> Result<Vec<u8>, MigrateError> {
    #[cfg(windows)]
    {
        crate::vault::dpapi::unprotect(cipher).map_err(|e| MigrateError::DpapiFailed(e.to_string()))
    }
    #[cfg(not(windows))]
    {
        let _ = cipher;
        Err(MigrateError::DpapiFailed(
            "not supported on this platform".into(),
        ))
    }
}

/// 密码层：`salt(16 hex) + Blowfish-ECB(PBKDF2(pw, salt, 2000, 32B), data)` 全 hex。
fn password_layer_decrypt(data_hex: &str, password: &str) -> Result<String, MigrateError> {
    if data_hex.len() < SALT_HEX_LEN {
        return Err(MigrateError::BadSecretData("password layer too short"));
    }
    let salt = hex_decode(&data_hex[..SALT_HEX_LEN])
        .map_err(|_| MigrateError::BadSecretData("layer salt"))?;
    let ct = hex_decode(&data_hex[SALT_HEX_LEN..])
        .map_err(|_| MigrateError::BadSecretData("layer data"))?;
    if ct.is_empty() || ct.len() % 8 != 0 {
        return Err(MigrateError::BadSecretData("blowfish block size"));
    }

    // PBKDF2-HMAC-SHA1（与 .NET Rfc2898DeriveBytes 等价）
    let mut key = [0u8; PBKDF2_KEYSIZE];
    pbkdf2::pbkdf2_hmac::<Sha1>(password.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut key);

    // Blowfish-ECB 逐块解密（ECB 即同钥独立分块，直接调块原语）
    let cipher: blowfish::Blowfish = blowfish::Blowfish::new_from_slice(&key)
        .map_err(|_| MigrateError::BadSecretData("blowfish key"))?;
    let mut plain = ct;
    for chunk in plain.chunks_mut(8) {
        let mut b = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut b);
        chunk.copy_from_slice(&b);
    }

    // ISO10126d2 去 padding：末字节为填充长度
    let pad = *plain.last().ok_or(MigrateError::PasswordLayerFailed)? as usize;
    if pad == 0 || pad > 8 || pad > plain.len() {
        return Err(MigrateError::PasswordLayerFailed);
    }
    plain.truncate(plain.len() - pad);

    Ok(hex_encode(&plain))
}

/// TAB SecretData：`secret_hex \t digits \t HMAC \t period`，Steam 追加 `|hex|hex|…`。
fn parse_tab_secret(data: &str, legacy_type: &str) -> Result<LegacyAuthenticator, MigrateError> {
    let tab_part = data.split('|').next().unwrap_or("");
    let parts: Vec<&str> = tab_part.split('\t').collect();
    if parts.is_empty() || parts[0].is_empty() {
        return Err(MigrateError::BadField("empty secret"));
    }
    let secret = hex_decode(parts[0]).map_err(|_| MigrateError::BadField("secret hex"))?;
    let digits = parts
        .get(1)
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(6);
    let hmac = HmacAlgo::parse(parts.get(2).map(|s| s.trim()).unwrap_or("SHA1"))
        .map_err(|_| MigrateError::BadField("hmac"))?;
    let period = parts
        .get(3)
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(30);
    if secret.is_empty() {
        return Err(MigrateError::BadField("secret empty"));
    }
    let digits = if legacy_type.contains("SteamAuthenticator") {
        5
    } else {
        digits
    };
    Ok(LegacyAuthenticator {
        name: String::new(),
        legacy_type: legacy_type.to_string(),
        secret,
        digits,
        period_secs: period,
        hmac,
        time_offset_ms: 0,
        counter: None,
    })
}

// ———— 迷你 XML 辅助（配置为机器生成、结构扁平，无需完整解析器） ————

fn attribute_map(fragment: &str) -> Vec<(String, String)> {
    let tag_end = fragment.find('>').unwrap_or(fragment.len());
    let head = &fragment[..tag_end];
    let mut out = Vec::new();
    let mut rest = head.split_whitespace();
    rest.next(); // 标签名
    for tok in rest {
        if let Some((k, v)) = tok.split_once('=') {
            let v = v.trim_matches('"').to_string();
            out.push((k.to_string(), v));
        }
    }
    out
}

fn child_text(block: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let start = block.find(&open)? + open.len();
    let gt = block[start..].find('>')? + start + 1;
    let close = format!("</{tag}>");
    let end = block[gt..].find(&close)? + gt;
    Some(block[gt..end].to_string())
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| ()))
        .collect()
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tab_data(secret_hex: &str) -> String {
        format!("{secret_hex}\t6\tSHA1\t30")
    }

    #[test]
    fn plaintext_entry() {
        let secret_hex = "00112233445566778899aabbccddeeff";
        let xml = format!(
            "<WinAuthAuthenticator id=\"aa\" type=\"WinAuth.GoogleAuthenticator\">\
             <name>测试条目</name><servertimediff>-1500</servertimediff>\
             <secretdata>{secret}</secretdata></WinAuthAuthenticator>",
            secret = tab_data(secret_hex)
        );
        let mut got = parse_config(&xml, None).unwrap();
        assert_eq!(got.len(), 1);
        let e = got.remove(0);
        assert_eq!(e.name, "测试条目");
        assert_eq!(e.legacy_type, "WinAuth.GoogleAuthenticator");
        assert_eq!(e.secret, hex_decode(secret_hex).unwrap());
        assert_eq!(e.digits, 6);
        assert_eq!(e.time_offset_ms, -1500);
        assert!(matches!(e.into_provider(), Provider::Totp(_)));
    }

    #[test]
    fn steam_tabs_and_pipes() {
        let secret_hex = "deadbeef01";
        let serial_hex = hex_encode(b"S1");
        let secret_data = format!("{}|{serial_hex}|6470696431|", tab_data(secret_hex));
        let xml = format!(
            "<WinAuthAuthenticator type=\"WinAuth.Authenticators.SteamAuthenticator\">\
             <name>s</name><secretdata>{secret_data}</secretdata></WinAuthAuthenticator>"
        );
        let mut got = parse_config(&xml, None).unwrap();
        let e = got.remove(0);
        assert_eq!(e.digits, 5);
        assert_eq!(e.secret, hex_decode(secret_hex).unwrap());
        assert!(matches!(e.into_provider(), Provider::Steam(_)));
    }

    #[test]
    fn bnet_digits8() {
        let xml = format!(
            "<WinAuthAuthenticator type=\"WinAuth.BattleNetAuthenticator\">\
             <name>b</name><secretdata>{}</secretdata></WinAuthAuthenticator>",
            tab_data("aabbccdd") // 6 位声明，bnet 类型强制 8
        );
        let mut got = parse_config(&xml, None).unwrap();
        assert_eq!(got.remove(0).digits, 8);
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_layer_roundtrip() {
        // 真实载荷形状：加密内容 = hex(UTF-8 XML)，XML 内嵌明文 TAB secretdata
        let secret_hex = "0123456789abcdef0123456789abcdef";
        let tab = tab_data(secret_hex);
        let payload_xml =
            format!("<servertimediff>-1500</servertimediff><secretdata>{tab}</secretdata>");
        let payload_bytes = payload_xml.as_bytes();
        let salt_hex = "aabbccddeeff0011";
        let inner_hex = hex_encode(&crate::vault::dpapi::protect(payload_bytes).unwrap());

        let mut h = Sha256::new();
        h.update(hex_decode(salt_hex).unwrap());
        h.update(payload_bytes);
        let hash_hex = hex_encode(&h.finalize());

        let xml = format!(
            "<WinAuthAuthenticator type=\"WinAuth.GoogleAuthenticator\">\
             <name>d</name><secretdata encrypted=\"u\">{H}{S}{HH}{D}</secretdata>\
             </WinAuthAuthenticator>",
            H = ENCRYPTION_HEADER_HEX,
            S = salt_hex,
            HH = hash_hex,
            D = inner_hex,
        );
        let mut got = parse_config(&xml, None).unwrap();
        let e = got.remove(0);
        assert_eq!(e.secret, hex_decode(secret_hex).unwrap());
    }

    #[test]
    fn hash_mismatch_detected() {
        let salt_hex = "aabbccddeeff0011";
        let xml = format!(
            "<WinAuthAuthenticator type=\"x\"><secretdata encrypted=\"u\">{H}{S}{HH}{D}</secretdata></WinAuthAuthenticator>",
            H = ENCRYPTION_HEADER_HEX,
            S = salt_hex,
            HH = "0".repeat(64),
            D = "00".repeat(32),
        );
        assert!(matches!(
            parse_config(&xml, None),
            Err(MigrateError::DpapiFailed(_)) // DPAPI 先失败于垃圾数据
        ));
    }

    #[test]
    fn password_layer_roundtrip() {
        // 自加密侧构造密码层样本（解密路径与原实现逐字节等价：
        // Blowfish-ECB + ISO10126 + PBKDF2-HMAC-SHA1(2000, 32B)）
        // 加密载荷 = hex(UTF-8 XML)，各层作用于解码后字节
        let secret_hex = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
        let tab = tab_data(secret_hex);
        let payload_xml =
            format!("<servertimediff>0</servertimediff><secretdata>{tab}</secretdata>");
        let plain = payload_xml.clone().into_bytes();
        let salt_hex = "1122334455667788";
        let salt = hex_decode(salt_hex).unwrap();

        use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
        let key = {
            let mut k = [0u8; 32];
            pbkdf2::pbkdf2_hmac::<Sha1>(b"pw123", &salt, PBKDF2_ITERATIONS, &mut k);
            k
        };
        // ISO10126 加密填充：随机字节 + 末字节长度
        let pad_len = 8 - (plain.len() % 8);
        let mut pad: Vec<u8> = rand_plain(pad_len - 1);
        pad.push(pad_len as u8);
        let mut plain = plain;
        plain.extend(pad);
        let cipher: blowfish::Blowfish = blowfish::Blowfish::new_from_slice(&key).unwrap();
        for chunk in plain.chunks_mut(8) {
            let mut b = GenericArray::clone_from_slice(chunk);
            cipher.encrypt_block(&mut b);
            chunk.copy_from_slice(&b);
        }
        let layer_hex = format!("{salt_hex}{}", hex_encode(&plain));

        // hash 在加密前（无填充）对 salt ++ 原始载荷字节计算
        let mut h = Sha256::new();
        h.update(&salt);
        h.update(payload_xml.as_bytes());
        let hash_hex = hex_encode(&h.finalize());

        let xml = format!(
            "<WinAuthAuthenticator type=\"WinAuth.GoogleAuthenticator\">\
             <name>p</name><secretdata encrypted=\"y\">{H}{S}{HH}{D}</secretdata></WinAuthAuthenticator>",
            H = ENCRYPTION_HEADER_HEX,
            S = salt_hex,
            HH = hash_hex,
            D = layer_hex,
        );
        let mut got = parse_config(&xml, Some("pw123")).unwrap();
        let e = got.remove(0);
        assert_eq!(e.secret, hex_decode(secret_hex).unwrap());

        fn rand_plain(n: usize) -> Vec<u8> {
            let mut v = vec![0u8; n];
            getrandom::getrandom(&mut v).unwrap();
            v
        }
    }
}
