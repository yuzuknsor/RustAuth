// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Windows DPAPI（CryptProtectData/CryptUnprotectData）包裹层。
//!
//! 仅 Windows 编译；当前用户域（无 Machine 标志），与格式规范 v1 的
//! `dpapi-user` wrap 对应。非 Windows 平台此模块为空实现并返回错误。

#![cfg(windows)]

use windows::core::PWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
};

use super::error::VaultError;

/// DPAPI 当前用户域加密。
pub fn protect(plain: &[u8]) -> Result<Vec<u8>, VaultError> {
    unsafe {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: plain.len() as u32,
            pbData: plain.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB::default();
        CryptProtectData(&in_blob, PWSTR::null(), None, None, None, 0, &mut out_blob)
            .map_err(|e| VaultError::UnwrapFailed(format!("CryptProtectData: {e}")))?;
        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let out = slice.to_vec();
        // 释放 DPAPI 分配的输出缓冲
        let _ = LocalFree(HLOCAL(out_blob.pbData.cast()));
        Ok(out)
    }
}

/// DPAPI 当前用户域解密。
pub fn unprotect(blob: &[u8]) -> Result<Vec<u8>, VaultError> {
    unsafe {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: blob.len() as u32,
            pbData: blob.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB::default();
        CryptUnprotectData(&in_blob, None, None, None, None, 0, &mut out_blob)
            .map_err(|e| VaultError::UnwrapFailed(format!("CryptUnprotectData: {e}")))?;
        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let out = slice.to_vec();
        let _ = LocalFree(HLOCAL(out_blob.pbData.cast()));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_roundtrip() {
        let secret = b"rustauth-dpapi-test".to_vec();
        let blob = protect(&secret).unwrap();
        assert_ne!(blob, secret);
        assert_eq!(unprotect(&blob).unwrap(), secret);
    }
}
