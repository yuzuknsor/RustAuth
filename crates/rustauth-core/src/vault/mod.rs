// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vault：单文件加密存储（格式规范 docs/vault-format-v1.md）。
//!
//! 结构：明文 header（元数据 + 主密钥包裹列表）+ AES-256-GCM 密文（条目）。

pub mod dpapi;
pub mod entry;
pub mod error;
pub mod password;

use std::fmt;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::otp::provider::Provider;
use entry::{b64, VaultEntrySer};
use error::VaultError;

pub const MAGIC: &[u8; 7] = b"WVAULT\x00";
pub const VERSION: u32 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MASTER_LEN: usize = 32;
const HEADER_BASE: usize = 7 + 4 + 4; // magic + version + header_len

/// 内存中的单条目。
#[derive(Debug, Clone)]
pub struct VaultEntry {
    pub id: String,
    pub name: String,
    pub created_ms: i64,
    pub provider: Provider,
}

impl VaultEntry {
    /// 当前码（透传 Provider）。
    pub fn code_at(&self, unix_ms: i64) -> Result<String, crate::otp::OtpError> {
        self.provider.code_at(unix_ms)
    }
}

impl fmt::Display for VaultEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}]", self.name, self.id)
    }
}

/// 磁盘 header 的 serde 表示。
#[derive(Debug, Serialize, Deserialize)]
struct HeaderSer {
    created_ms: i64,
    cipher: String,
    wraps: Vec<WrapSer>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WrapSer {
    #[serde(rename = "type")]
    kind: String,
    blob: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    salt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    m_kib: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    t: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    p: Option<u32>,
}

/// 解锁后的 vault（主密钥常驻内存，零化回收）。
pub struct Vault {
    master: Zeroizing<[u8; MASTER_LEN]>,
    created_ms: i64,
    /// 保存时若设置则附加密码层（盐保留以便复用派生参数）
    password_salt: Option<[u8; 16]>,
    password_params: Option<password::PasswordParams>,
    password: Option<Zeroizing<String>>,
    entries: Vec<VaultEntry>,
}

impl fmt::Debug for Vault {
    /// 密钥与密码不进 Debug 输出。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("created_ms", &self.created_ms)
            .field("entries", &self.entries.len())
            .field("has_password", &self.password.is_some())
            .finish()
    }
}

impl Vault {
    /// 新建空 vault（随机主密钥）。
    pub fn new() -> Result<Self, VaultError> {
        let mut master = Zeroizing::new([0u8; MASTER_LEN]);
        getrandom::getrandom(master.as_mut())
            .map_err(|e| VaultError::UnwrapFailed(format!("rng: {e}")))?;
        Ok(Self {
            master,
            created_ms: now_ms(),
            password_salt: None,
            password_params: None,
            password: None,
            entries: Vec::new(),
        })
    }

    /// 设置/更换密码层（保存时生效）。传 None 移除密码层。
    pub fn set_password(&mut self, password: Option<&str>) -> Result<(), VaultError> {
        match password {
            None => {
                self.password_salt = None;
                self.password_params = None;
                self.password = None;
            }
            Some(pw) => {
                let mut salt = [0u8; 16];
                getrandom::getrandom(&mut salt)
                    .map_err(|e| VaultError::UnwrapFailed(format!("rng: {e}")))?;
                self.password_salt = Some(salt);
                self.password_params = Some(password::PasswordParams::production());
                self.password = Some(Zeroizing::new(pw.to_string()));
            }
        }
        Ok(())
    }

    /// 添加条目，返回分配的 id。
    pub fn add_entry(&mut self, name: &str, provider: Provider) -> Result<String, VaultError> {
        let mut id = [0u8; 8];
        getrandom::getrandom(&mut id).map_err(|e| VaultError::UnwrapFailed(format!("rng: {e}")))?;
        let id: String = id.iter().map(|b| format!("{b:02x}")).collect();
        self.entries.push(VaultEntry {
            id: id.clone(),
            name: name.to_string(),
            created_ms: now_ms(),
            provider,
        });
        Ok(id)
    }

    /// 删除条目；返回是否删除了。
    pub fn remove_entry(&mut self, id: &str) -> Result<VaultEntry, VaultError> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.id == id)
            .ok_or_else(|| VaultError::EntryNotFound(id.to_string()))?;
        Ok(self.entries.remove(idx))
    }

    /// 改名。
    pub fn rename_entry(&mut self, id: &str, name: &str) -> Result<(), VaultError> {
        self.entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| VaultError::EntryNotFound(id.to_string()))?
            .name = name.to_string();
        Ok(())
    }

    pub fn entries(&self) -> &[VaultEntry] {
        &self.entries
    }

    pub fn created_ms(&self) -> i64 {
        self.created_ms
    }

    /// 序列化为文件字节。
    ///
    /// 每次保存重新生成 nonce 并重包裹主密钥（DPAPI 输出每次不同，正常现象）。
    pub fn save(&self) -> Result<Vec<u8>, VaultError> {
        self.serialize(true)
    }

    pub(crate) fn serialize(&self, include_dpapi: bool) -> Result<Vec<u8>, VaultError> {
        if self.entries.is_empty() && self.password.is_some() {
            // 空库也允许保存，此处无特殊处理
        }
        let mut wraps: Vec<WrapSer> = Vec::new();
        if include_dpapi {
            let blob = dpapi::protect(self.master.as_ref())?;
            wraps.push(WrapSer {
                kind: "dpapi-user".into(),
                blob: b64::encode(&blob),
                salt: None,
                m_kib: None,
                t: None,
                p: None,
            });
        }
        if let (Some(salt), Some(params), Some(pw)) = (
            self.password_salt,
            self.password_params,
            self.password.as_ref(),
        ) {
            let blob = password::wrap_master(self.master.as_ref(), pw, &salt, params)?;
            wraps.push(WrapSer {
                kind: "argon2id-password".into(),
                blob: b64::encode(&blob),
                salt: Some(b64::encode(&salt)),
                m_kib: Some(params.m_kib),
                t: Some(params.t),
                p: Some(params.p),
            });
        }
        if wraps.is_empty() {
            return Err(VaultError::NoWraps);
        }

        let header = HeaderSer {
            created_ms: self.created_ms,
            cipher: "aes-256-gcm".into(),
            wraps,
        };
        let header_json =
            serde_json::to_vec(&header).map_err(|e| VaultError::Serialize(e.to_string()))?;

        // 条目 → 磁盘表示 → JSON
        let ser_entries: Vec<VaultEntrySer> = self
            .entries
            .iter()
            .map(|e| -> Result<VaultEntrySer, VaultError> {
                Ok(VaultEntrySer {
                    id: e.id.clone(),
                    name: e.name.clone(),
                    created_ms: e.created_ms,
                    provider: entry::ProviderSer::try_from(&e.provider)?,
                })
            })
            .collect::<Result<Vec<_>, VaultError>>()?;
        let plain =
            serde_json::to_vec(&ser_entries).map_err(|e| VaultError::Serialize(e.to_string()))?;

        let cipher = Aes256Gcm::new(self.master.as_ref().into());
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| VaultError::UnwrapFailed(format!("rng: {e}")))?;
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), plain.as_ref())
            .map_err(|_| VaultError::DecryptFailed)?;

        let mut out = Vec::with_capacity(15 + header_json.len() + NONCE_LEN + ct.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
        out.extend_from_slice(&header_json);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct); // 末尾含 16B tag
        Ok(out)
    }

    /// 从文件字节解锁。
    ///
    /// `password`：密码层凭据（None 时跳过密码 wrap）。
    pub fn open(bytes: &[u8], password: Option<&str>) -> Result<Self, VaultError> {
        if bytes.len() < 15 || &bytes[..7] != MAGIC {
            return Err(VaultError::BadMagic);
        }
        let version = u32::from_le_bytes(bytes[7..11].try_into().unwrap());
        if version > VERSION {
            return Err(VaultError::UnsupportedVersion(version));
        }
        if bytes.len() < HEADER_BASE + NONCE_LEN + TAG_LEN {
            return Err(VaultError::Malformed("truncated file"));
        }
        let header_len = u32::from_le_bytes(bytes[11..15].try_into().unwrap()) as usize;
        let header_end = HEADER_BASE + header_len;
        if bytes.len() < header_end + NONCE_LEN + TAG_LEN {
            return Err(VaultError::Malformed("truncated file"));
        }
        let header: HeaderSer = serde_json::from_slice(&bytes[HEADER_BASE..header_end])
            .map_err(|e| VaultError::Serialize(format!("header: {e}")))?;
        if header.cipher != "aes-256-gcm" {
            return Err(VaultError::Malformed("unknown cipher"));
        }

        // 按序尝试所有 wrap，直到解出主密钥
        let mut master: Option<Zeroizing<[u8; MASTER_LEN]>> = None;
        let mut wrap_errs: Vec<String> = Vec::new();
        for w in &header.wraps {
            if master.is_some() {
                break;
            }
            match w.kind.as_str() {
                "dpapi-user" => {
                    #[cfg(windows)]
                    {
                        match b64::decode(&w.blob)
                            .map_err(|_| VaultError::Malformed("dpapi blob b64"))
                            .and_then(|b| dpapi::unprotect(&b))
                        {
                            Ok(m) => master = Some(to_master(&m)?),
                            Err(e) => wrap_errs.push(e.to_string()),
                        }
                    }
                    #[cfg(not(windows))]
                    {
                        wrap_errs.push("dpapi unavailable on this platform".into());
                    }
                }
                "argon2id-password" => {
                    let (Some(pw), Some(salt_s), Some(m), Some(t), Some(p)) =
                        (password, w.salt.as_deref(), w.m_kib, w.t, w.p)
                    else {
                        continue; // 无密码凭据，跳过
                    };
                    match (|| -> Result<Zeroizing<[u8; MASTER_LEN]>, VaultError> {
                        let salt = b64::decode(salt_s)
                            .map_err(|_| VaultError::Malformed("password salt b64"))?;
                        let blob = b64::decode(&w.blob)
                            .map_err(|_| VaultError::Malformed("password blob b64"))?;
                        password::unwrap_master(
                            &blob,
                            pw,
                            &salt,
                            password::PasswordParams { m_kib: m, t, p },
                        )
                    })() {
                        Ok(mk) => master = Some(mk),
                        Err(e) => wrap_errs.push(e.to_string()),
                    }
                }
                other => {
                    // 未知 wrap 类型：跳过（前向兼容）
                    let _ = other;
                }
            }
        }
        let master = master.ok_or_else(|| {
            if wrap_errs.is_empty() {
                VaultError::NoWraps
            } else {
                VaultError::UnwrapFailed(wrap_errs.join("; "))
            }
        })?;

        // 解密条目
        let nonce = &bytes[header_end..header_end + NONCE_LEN];
        let ct = &bytes[header_end + NONCE_LEN..];
        let cipher = Aes256Gcm::new(master.as_ref().into());
        let plain = cipher
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| VaultError::DecryptFailed)?;
        let ser_entries: Vec<VaultEntrySer> = serde_json::from_slice(&plain)
            .map_err(|e| VaultError::Serialize(format!("entries: {e}")))?;
        let entries = ser_entries
            .iter()
            .map(|s| -> Result<VaultEntry, VaultError> {
                Ok(VaultEntry {
                    id: s.id.clone(),
                    name: s.name.clone(),
                    created_ms: s.created_ms,
                    provider: Provider::try_from(&s.provider)?,
                })
            })
            .collect::<Result<Vec<_>, VaultError>>()?;

        // 记住密码凭据（保存时复用）；盐/参数取自首个密码 wrap
        let pw_wrap = header.wraps.iter().find(|w| w.kind == "argon2id-password");
        Ok(Self {
            master,
            created_ms: header.created_ms,
            password_salt: pw_wrap.and_then(|w| w.salt.as_deref()).and_then(|s| {
                let mut arr = [0u8; 16];
                match b64::decode(s) {
                    Ok(v) if v.len() == 16 => {
                        arr.copy_from_slice(&v);
                        Some(arr)
                    }
                    _ => None,
                }
            }),
            password_params: pw_wrap.and_then(|w| {
                Some(password::PasswordParams {
                    m_kib: w.m_kib?,
                    t: w.t?,
                    p: w.p?,
                })
            }),
            password: password.map(|p| Zeroizing::new(p.to_string())),
            entries,
        })
    }

    /// 保存到磁盘。
    pub fn save_to(&self, path: &std::path::Path) -> Result<(), VaultError> {
        let bytes = self.save()?;
        std::fs::write(path, bytes).map_err(|e| VaultError::Serialize(format!("write: {e}")))
    }

    /// 从磁盘加载并解锁。
    pub fn load_from(path: &std::path::Path, password: Option<&str>) -> Result<Self, VaultError> {
        let bytes = std::fs::read(path).map_err(|e| VaultError::Serialize(format!("read: {e}")))?;
        Self::open(&bytes, password)
    }
}

fn to_master(v: &[u8]) -> Result<Zeroizing<[u8; MASTER_LEN]>, VaultError> {
    let arr: [u8; MASTER_LEN] = v
        .try_into()
        .map_err(|_| VaultError::Malformed("unwrap output size"))?;
    Ok(Zeroizing::new(arr))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otp::provider::CodeConfig;

    fn sample_provider() -> Provider {
        Provider::Totp(CodeConfig::standard(b"12345678901234567890".to_vec()))
    }

    #[test]
    fn roundtrip_save_open() {
        let mut v = Vault::new().unwrap();
        let id = v.add_entry("Test TOTP", sample_provider()).unwrap();
        v.add_entry(
            "Steam",
            Provider::Steam(CodeConfig::standard(b"zzzz".to_vec())),
        )
        .unwrap();

        let bytes = v.save().unwrap();
        assert_eq!(&bytes[..7], MAGIC);

        let opened = Vault::open(&bytes, None).unwrap();
        assert_eq!(opened.entries().len(), 2);
        assert_eq!(opened.entries()[0].id, id);
        assert_eq!(opened.entries()[0].name, "Test TOTP");
        // 码在打开前后一致（同一 secret）
        assert_eq!(opened.entries()[0].code_at(59_000).unwrap(), "287082");
    }

    fn save_to_load_from_roundtrip(tmpdir: &std::path::Path) {
        let mut v = Vault::new().unwrap();
        v.add_entry("E1", sample_provider()).unwrap();
        let p = tmpdir.join("test.vault");
        v.save_to(&p).unwrap();
        let loaded = Vault::load_from(&p, None).unwrap();
        assert_eq!(loaded.entries().len(), 1);
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mut v = Vault::new().unwrap();
        v.add_entry("E", sample_provider()).unwrap();
        let mut bytes = v.save().unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert_eq!(
            Vault::open(&bytes, None).unwrap_err(),
            VaultError::DecryptFailed
        );
    }

    #[test]
    fn bad_magic_rejected() {
        assert_eq!(
            Vault::open(b"NOTAVLT!", None).unwrap_err(),
            VaultError::BadMagic
        );
    }

    #[test]
    fn future_version_rejected() {
        let mut v = Vault::new().unwrap();
        v.add_entry("E", sample_provider()).unwrap();
        let mut bytes = v.save().unwrap();
        bytes[7..11].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(
            Vault::open(&bytes, None).unwrap_err(),
            VaultError::UnsupportedVersion(99)
        );
    }

    #[test]
    fn password_layer_unlock() {
        let mut v = Vault::new().unwrap();
        v.add_entry("Secret", sample_provider()).unwrap();
        v.set_password(Some("hunter2!")).unwrap();

        // 带密码打开（DPAPI + 密码双路径都可用）
        let bytes = v.serialize(true).unwrap();
        let opened = Vault::open(&bytes, Some("hunter2!")).unwrap();
        assert_eq!(opened.entries().len(), 1);

        // 仅密码路径：模拟 DPAPI blob 损坏（serialize(false) 无 DPAPI）
        let pw_only = v.serialize(false).unwrap();
        let opened2 = Vault::open(&pw_only, Some("hunter2!")).unwrap();
        assert_eq!(opened2.entries().len(), 1);

        // 无密码凭据 → 无法解锁（DPAPI 被排除）
        assert!(Vault::open(&pw_only, None).is_err());

        // 错误密码
        assert!(Vault::open(&pw_only, Some("wrong")).is_err());
    }

    #[test]
    fn remove_and_rename() {
        let mut v = Vault::new().unwrap();
        let id = v.add_entry("Old", sample_provider()).unwrap();
        v.rename_entry(&id, "New").unwrap();
        assert_eq!(v.entries()[0].name, "New");
        let removed = v.remove_entry(&id).unwrap();
        assert_eq!(removed.name, "New");
        assert!(v.remove_entry(&id).is_err());
    }

    /// 简易临时目录（测试结束自动清理；Windows 下同名冲突概率可忽略）。
    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct TempDirGuard(std::path::PathBuf);

    #[test]
    fn save_to_load_from_with_guard() {
        let dir = std::env::temp_dir().join(format!("rustauth-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let _guard = TempDirGuard(dir.clone());
        save_to_load_from_roundtrip(&dir);
    }
}
