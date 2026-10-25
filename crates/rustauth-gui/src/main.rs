// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! RustAuth 入口：单实例 → 加载/创建 vault → eframe 主循环。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod settings;
mod single_instance;
mod tray;

use rustauth_core::vault::Vault;

fn main() -> eframe::Result<()> {
    let _guard = match single_instance::SingleInstance::acquire("RustAuth-SingleInstance") {
        Ok(g) => g,
        Err(()) => {
            eprintln!("RustAuth 已在运行。");
            return Ok(());
        }
    };

    let settings = settings::Settings::load();
    let vault_path = settings::Settings::vault_path();

    let vault = match &vault_path {
        Some(p) if p.exists() => match Vault::load_from(p, None) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("打开 vault 失败: {e}\n路径: {}", p.display());
                std::process::exit(2);
            }
        },
        Some(p) => {
            let v = Vault::new().expect("vault init");
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Err(e) = v.save_to(p) {
                eprintln!("初始化 vault 失败: {e}");
                std::process::exit(2);
            }
            v
        }
        None => Vault::new().expect("vault init"),
    };

    let native = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([520.0, 420.0])
            .with_min_inner_size([380.0, 260.0])
            .with_icon(load_icon()),
        ..Default::default()
    };

    eframe::run_native(
        "RustAuth",
        native,
        Box::new(move |_cc| {
            Ok(Box::new(app::RustAuthApp::new(
                vault,
                vault_path.clone(),
                settings,
            )))
        }),
    )
}

/// 窗口图标：与托盘同源的程序化图标。
fn load_icon() -> egui::IconData {
    const S: usize = 16;
    let mut rgba = vec![0u8; S * S * 4];
    for y in 0..S {
        for x in 0..S {
            let i = (y * S + x) * 4;
            let dark = (4..12).contains(&y) && (3..12).contains(&x);
            if dark {
                rgba[i..i + 4].copy_from_slice(&[26, 26, 26, 255]);
            } else {
                rgba[i..i + 4].copy_from_slice(&[255, 202, 40, 255]);
            }
        }
    }
    egui::IconData {
        width: S as u32,
        height: S as u32,
        rgba,
    }
}
