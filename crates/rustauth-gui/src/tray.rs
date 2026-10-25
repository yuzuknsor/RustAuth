// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! 托盘图标 + 菜单（tray-icon）。事件经全局 channel 由 egui 帧循环轮询。

use crossbeam_channel::Receiver;
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

/// 托盘菜单命令。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayCommand {
    ShowToggle,
    Quit,
}

pub struct Tray {
    _tray: TrayIcon,
    rx: Receiver<MenuEvent>,
    id_show: MenuId,
    id_quit: MenuId,
}

impl Tray {
    /// 构建托盘（须在主线程调用）。
    pub fn new() -> Result<Self, String> {
        let menu = Menu::new();
        let id_show = MenuId::new("show");
        let id_quit = MenuId::new("quit");
        menu.append_items(&[
            &MenuItem::with_id(id_show.clone(), "显示 / 隐藏", true, None),
            &PredefinedMenuItem::separator(),
            &MenuItem::with_id(id_quit.clone(), "退出", true, None),
        ])
        .map_err(|e| e.to_string())?;

        let rx = MenuEvent::receiver().clone();

        let icon = app_icon()?;
        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("RustAuth")
            .with_icon(icon)
            .build()
            .map_err(|e| e.to_string())?;

        Ok(Self {
            _tray: tray,
            rx,
            id_show,
            id_quit,
        })
    }

    /// 轮询并取出待处理命令。
    pub fn poll(&self) -> Option<TrayCommand> {
        while let Ok(ev) = self.rx.try_recv() {
            if ev.id == self.id_show {
                return Some(TrayCommand::ShowToggle);
            }
            if ev.id == self.id_quit {
                return Some(TrayCommand::Quit);
            }
        }
        None
    }
}

/// 程序化生成 32×32 图标（黄底 + 深色 R 字），避免引入图标资源文件。
fn app_icon() -> Result<Icon, String> {
    const S: usize = 32;
    let mut rgba = vec![0u8; S * S * 4];
    for y in 0..S {
        for x in 0..S {
            let i = (y * S + x) * 4;
            // 简化的 R 字形笔画（坐标为 32×32 网格内范围）
            let dark = match y {
                10 | 11 => (8..23).contains(&x),
                12..=17 => (8..12).contains(&x) || (18..22).contains(&x),
                18..=21 => (8..18).contains(&x),
                22..=24 => (8..12).contains(&x) || (13..18).contains(&x),
                _ => false,
            };
            if dark {
                rgba[i..i + 4].copy_from_slice(&[26, 26, 26, 255]);
            } else {
                rgba[i..i + 4].copy_from_slice(&[255, 202, 40, 255]);
            }
        }
    }
    Icon::from_rgba(rgba, S as u32, S as u32).map_err(|e| e.to_string())
}
