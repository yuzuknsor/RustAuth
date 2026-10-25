// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! 单实例互斥（Windows 命名 mutex）。非 Windows 平台恒返回 Ok。

#![cfg_attr(not(windows), allow(unused_variables))]

#[derive(Debug)]
pub struct SingleInstance {
    #[cfg(windows)]
    handle: windows::Win32::Foundation::HANDLE,
}

impl SingleInstance {
    /// 尝试持有命名互斥体；已有实例在运行则返回 Err。
    pub fn acquire(name: &str) -> Result<Self, ()> {
        #[cfg(windows)]
        {
            use windows::core::PCWSTR;
            use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS};
            use windows::Win32::System::Threading::CreateMutexW;

            let mut wide: Vec<u16> = name.encode_utf16().collect();
            wide.push(0);
            let handle = unsafe { CreateMutexW(None, false, PCWSTR::from_raw(wide.as_ptr())) }
                .map_err(|_| ())?;
            let already = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
            if already {
                unsafe {
                    let _ = CloseHandle(handle);
                }
                return Err(());
            }
            Ok(Self { handle })
        }
        #[cfg(not(windows))]
        {
            Ok(Self {})
        }
    }
}

#[cfg(windows)]
impl Drop for SingleInstance {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}
