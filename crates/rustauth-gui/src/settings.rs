// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! 应用设置：%APPDATA%\rustauth\settings.json。

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// 关窗即隐藏到托盘（false = 直接退出）
    pub close_to_tray: bool,
    /// 剪贴板自动清除秒数（0 = 不清除）
    pub clipboard_clear_secs: u64,
    /// 是否启用全局热键 Ctrl+Alt+C（复制第一条码）
    pub hotkey_enabled: bool,
    /// 新码自动复制
    pub copy_on_new_code: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            close_to_tray: true,
            clipboard_clear_secs: 30,
            hotkey_enabled: true,
            copy_on_new_code: false,
        }
    }
}

impl Settings {
    pub fn path() -> Option<PathBuf> {
        Some(dirs::data_dir()?.join("rustauth").join("settings.json"))
    }

    pub fn vault_path() -> Option<PathBuf> {
        Some(dirs::data_dir()?.join("rustauth").join("vault.bin"))
    }

    pub fn load() -> Self {
        Self::path()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// 供后续设置 UI 调用
    #[allow(dead_code)]
    pub fn save(&self) {
        if let Some(p) = Self::path() {
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Ok(b) = serde_json::to_vec_pretty(self) {
                let _ = std::fs::write(p, b);
            }
        }
    }
}
