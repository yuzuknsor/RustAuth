// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! 密码层：argon2id 派生密钥 → AES-256-GCM 包裹主密钥。
//!
//! blob 布局 = nonce(12B) || ciphertext(32B) || tag(16B)，参数随 wrap 存储。

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use zeroize::Zeroizing;

use super::error::VaultError;

/// 密码层参数（磁盘可见，允许按条目演进）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordParams {
    /// argon2 内存成本（KiB）
    pub m_kib: u32,
    /// 迭代轮数
    pub t: u32,
    /// 并行度
    pub p: u32,
}

impl PasswordParams {
    /// 生产默认：64 MiB / 3 / 4。
    pub const fn production() -> Self {
        Self {
            m_kib: 65536,
            t: 3,
            p: 4,
        }
    }

    /// 测试参数（快 ~50 倍），仅限测试与低敏感场景。
    pub const fn fast() -> Self {
        Self {
            m_kib: 8192,
            t: 1,
            p: 1,
        }
    }

    pub const fn to_json(self) -> (u32, u32, u32) {
        (self.m_kib, self.t, self.p)
    }
}

/// argon2id 派生 32B 密钥。
pub fn derive_key(
    password: &str,
    salt: &[u8],
    params: PasswordParams,
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let a2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(params.m_kib, params.t, params.p, Some(32))
            .map_err(|e| VaultError::UnwrapFailed(format!("argon2 params: {e}")))?,
    );
    let mut out = Zeroizing::new([0u8; 32]);
    a2.hash_password_into(password.as_bytes(), salt, out.as_mut())
        .map_err(|e| VaultError::UnwrapFailed(format!("argon2 hash: {e}")))?;
    Ok(out)
}

/// 用密码派生钥包裹主密钥，返回 blob。
pub fn wrap_master(
    master: &[u8],
    password: &str,
    salt: &[u8],
    params: PasswordParams,
) -> Result<Vec<u8>, VaultError> {
    let key = derive_key(password, salt, params)?;
    let cipher = Aes256Gcm::new(key.as_ref().into());
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| VaultError::UnwrapFailed(format!("rng: {e}")))?;
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), master.as_ref())
        .map_err(|_| VaultError::DecryptFailed)?;
    let mut blob = nonce_bytes.to_vec();
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// 解开密码层，返回主密钥。
pub fn unwrap_master(
    blob: &[u8],
    password: &str,
    salt: &[u8],
    params: PasswordParams,
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    if blob.len() != 12 + 32 + 16 {
        return Err(VaultError::Malformed("password wrap blob size"));
    }
    let key = derive_key(password, salt, params)?;
    let cipher = Aes256Gcm::new(key.as_ref().into());
    let (nonce, ct) = blob.split_at(12);
    let master = cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| VaultError::UnwrapFailed("wrong password".into()))?;
    let arr: [u8; 32] = master
        .try_into()
        .map_err(|_| VaultError::Malformed("master size"))?;
    Ok(Zeroizing::new(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_wrap_roundtrip() {
        let master: [u8; 32] = core::array::from_fn(|i| i as u8);
        let salt: [u8; 16] = core::array::from_fn(|i| (i ^ 0x5a) as u8);
        let blob = wrap_master(&master, "correct horse", &salt, PasswordParams::fast()).unwrap();
        assert_eq!(blob.len(), 60);
        let got = unwrap_master(&blob, "correct horse", &salt, PasswordParams::fast()).unwrap();
        assert_eq!(got.as_ref(), &master);
    }

    #[test]
    fn wrong_password_rejected() {
        let master: [u8; 32] = core::array::from_fn(|i| i as u8);
        let salt = [7u8; 16];
        let blob = wrap_master(&master, "right", &salt, PasswordParams::fast()).unwrap();
        assert!(unwrap_master(&blob, "wrong", &salt, PasswordParams::fast()).is_err());
    }

    #[test]
    fn tampered_blob_rejected() {
        let master: [u8; 32] = core::array::from_fn(|i| i as u8);
        let salt = [3u8; 16];
        let mut blob = wrap_master(&master, "pw", &salt, PasswordParams::fast()).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(unwrap_master(&blob, "pw", &salt, PasswordParams::fast()).is_err());
    }
}
