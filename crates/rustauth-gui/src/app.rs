// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! RustAuth GUI 主体（eframe 0.37：logic/ui 双阶段 + egui::Panel 统一面板）。

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eframe::egui;
use global_hotkey::hotkey::{Code, HotKey, Modifiers};
use global_hotkey::{GlobalHotKeyEvent, GlobalHotKeyManager};

use rustauth_core::base32;
use rustauth_core::otp::provider::{CodeConfig, Provider};
use rustauth_core::vault::Vault;

use crate::settings::Settings;
use crate::tray::{Tray, TrayCommand};

pub struct RustAuthApp {
    vault: Vault,
    vault_path: Option<std::path::PathBuf>,
    settings: Settings,
    tray: Option<Tray>,
    /// 仅为保持注册存活（Drop 时注销）
    #[allow(dead_code)]
    hotkey: Option<GlobalHotKeyManager>,
    clipboard: Option<arboard::Clipboard>,
    /// 剪贴板清除时刻（Unix ms）
    clipboard_clear_at: Option<i64>,
    // 添加对话框状态
    add_open: bool,
    add_name: String,
    add_secret: String,
    add_kind: KindChoice,
    add_error: Option<String>,
    // 旧版导入状态
    import_open: bool,
    import_path: String,
    import_password: String,
    import_error: Option<String>,
    // 设置窗口
    settings_open: bool,
    /// 新码自动复制的去重记录
    auto_copy_last: Option<String>,
    // 改名状态
    rename_id: Option<String>,
    rename_text: String,
    /// 待确认删除的条目 id
    confirm_delete: Option<String>,
    /// 状态栏消息（内容, 产生时刻）
    toast: Option<(String, i64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KindChoice {
    Totp,
    Steam,
    BattleNet,
}

impl KindChoice {
    fn label(self) -> &'static str {
        match self {
            Self::Totp => "TOTP（Google 等）",
            Self::Steam => "Steam Guard",
            Self::BattleNet => "Battle.net",
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl RustAuthApp {
    pub fn new(vault: Vault, vault_path: Option<std::path::PathBuf>, settings: Settings) -> Self {
        let hotkey = if settings.hotkey_enabled {
            match GlobalHotKeyManager::new() {
                Ok(m) => {
                    let hk = HotKey::new(Some(Modifiers::CONTROL | Modifiers::ALT), Code::KeyC);
                    if let Err(e) = m.register(hk) {
                        eprintln!("热键注册失败: {e:?}");
                    }
                    Some(m)
                }
                Err(e) => {
                    eprintln!("热键管理器创建失败: {e:?}");
                    None
                }
            }
        } else {
            None
        };
        Self {
            vault,
            vault_path,
            settings,
            tray: Tray::new().ok(),
            hotkey,
            clipboard: None,
            clipboard_clear_at: None,
            add_open: false,
            add_name: String::new(),
            add_secret: String::new(),
            add_kind: KindChoice::Totp,
            add_error: None,
            import_open: false,
            import_path: String::new(),
            import_password: String::new(),
            import_error: None,
            settings_open: false,
            auto_copy_last: None,
            rename_id: None,
            rename_text: String::new(),
            confirm_delete: None,
            toast: None,
        }
    }

    fn persist(&mut self) {
        if let Some(p) = self.vault_path.clone() {
            let res = self.vault.save_to(&p);
            if let Err(e) = res {
                self.set_toast(format!("保存失败: {e}"));
            }
        }
    }

    fn set_toast(&mut self, msg: String) {
        self.toast = Some((msg, now_ms()));
    }

    fn copy_code(&mut self, code: &str) {
        if self.clipboard.is_none() {
            self.clipboard = arboard::Clipboard::new().ok();
        }
        if let Some(cb) = &mut self.clipboard {
            if cb.set_text(code.to_string()).is_ok() {
                let secs = self.settings.clipboard_clear_secs;
                self.clipboard_clear_at = if secs > 0 {
                    Some(now_ms() + (secs as i64) * 1000)
                } else {
                    None
                };
                self.set_toast(if secs > 0 {
                    format!("已复制（{secs}s 后清除）")
                } else {
                    "已复制".into()
                });
            }
        }
    }

    fn copy_first_code(&mut self) {
        let ms = now_ms();
        let first = self
            .vault
            .entries()
            .first()
            .and_then(|e| e.code_at(ms).ok());
        if let Some(code) = first {
            self.copy_code(&code);
        }
    }
}

impl eframe::App for RustAuthApp {
    /// 隐藏到托盘时也会调用：所有非 UI 逻辑集中于此。
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let ms = now_ms();

        // —— 关窗拦截（隐藏到托盘）——
        let close_requested = ctx.input(|i| i.viewport().close_requested());
        if close_requested && self.settings.close_to_tray {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        // —— 托盘菜单 ——
        if let Some(tray) = &self.tray {
            match tray.poll() {
                Some(TrayCommand::Quit) => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                Some(TrayCommand::ShowToggle) => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                None => {}
            }
        }

        // —— 全局热键 ——
        while let Ok(ev) = GlobalHotKeyEvent::receiver().try_recv() {
            if ev.state() == global_hotkey::HotKeyState::Pressed {
                self.copy_first_code();
            }
        }

        // —— 剪贴板定时清除 ——
        if let Some(t) = self.clipboard_clear_at {
            if ms >= t {
                if self.clipboard.is_none() {
                    self.clipboard = arboard::Clipboard::new().ok();
                }
                if let Some(cb) = &mut self.clipboard {
                    let _ = cb.set_text(String::new());
                }
                self.clipboard_clear_at = None;
            }
        }

        // —— toast 过期 ——
        if let Some((_, t)) = &self.toast {
            if ms - t > 2500 {
                self.toast = None;
            }
        }

        // —— 新码自动复制（第一条目，WinAuth 同款行为）——
        if self.settings.copy_on_new_code {
            if let Some(first) = self.vault.entries().first() {
                if let Ok(code) = first.code_at(ms) {
                    if self.auto_copy_last.as_deref() != Some(code.as_str()) {
                        self.auto_copy_last = Some(code.clone());
                        self.copy_code(&code);
                    }
                }
            }
        }

        // 码与进度条实时性
        ctx.request_repaint_after(Duration::from_millis(250));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let ms = now_ms();

        egui::Panel::top("top").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("RustAuth");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("⚙").clicked() {
                        self.settings_open = true;
                    }
                    if ui.button("导入").clicked() {
                        self.import_open = true;
                        self.import_error = None;
                        if self.import_path.is_empty() {
                            if let Some(p) = dirs::data_dir() {
                                self.import_path =
                                    p.join("WinAuth").join("winauth.xml").display().to_string();
                            }
                        }
                    }
                    if ui.button("＋ 添加").clicked() {
                        self.add_open = true;
                        self.add_error = None;
                    }
                });
            });
        });

        egui::Panel::bottom("bottom").show(ui, |ui| {
            ui.horizontal(|ui| {
                if let Some((msg, _)) = &self.toast {
                    ui.colored_label(egui::Color32::from_rgb(80, 180, 80), msg);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.small(format!("{} 个条目", self.vault.entries().len()));
                });
            });
        });

        egui::CentralPanel::default().show(ui, |ui| {
            let ids: Vec<String> = self.vault.entries().iter().map(|e| e.id.clone()).collect();
            egui::ScrollArea::vertical().show(ui, |ui| {
                if ids.is_empty() {
                    ui.vertical_centered(|ui| {
                        ui.add_space(60.0);
                        ui.label("暂无条目——点击右上角「＋ 添加」导入第一个验证器");
                    });
                }
                for id in &ids {
                    let Some(e) = self.vault.entries().iter().find(|e| e.id == *id) else {
                        continue;
                    };
                    let (name, code, remaining, provider_label) = {
                        let code = e.code_at(ms).unwrap_or_else(|_| "—".into());
                        let rem = e.provider.remaining_ms(ms);
                        let pl = match &e.provider {
                            Provider::Totp(_) => "TOTP",
                            Provider::Hotp(..) => "HOTP",
                            Provider::Steam(_) => "Steam",
                            Provider::BattleNet(_) => "Battle.net",
                        };
                        (e.name.clone(), code, rem, pl)
                    };

                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.strong(&name);
                            ui.small(provider_label);
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("⋯").clicked() {
                                self.rename_id = Some(id.clone());
                                self.rename_text = name.clone();
                            }
                            if ui.button("复制").clicked() {
                                self.copy_code(&code);
                            }
                            ui.add_space(8.0);
                            let rich = egui::RichText::new(&code).monospace().size(22.0).strong();
                            ui.label(rich);
                            // 周期进度条（Hotp 无周期不显示）
                            if remaining != u32::MAX {
                                let period = 30.0 * 1000.0;
                                let frac = 1.0 - (remaining as f32 / period).clamp(0.0, 1.0);
                                let (bar, _) = ui.allocate_exact_size(
                                    egui::vec2(60.0, 6.0),
                                    egui::Sense::hover(),
                                );
                                ui.painter()
                                    .rect_filled(bar, 3.0, egui::Color32::from_gray(60));
                                ui.painter().rect_filled(
                                    egui::Rect::from_min_size(
                                        bar.min,
                                        egui::vec2(bar.width() * frac, 6.0),
                                    ),
                                    3.0,
                                    egui::Color32::from_rgb(255, 202, 40),
                                );
                            }
                        });
                    });
                    ui.separator();
                }
            });
        });

        // —— 添加窗口 ——（借用镜像：egui 的 open() 持有 &mut bool 期间不能碰 self）
        if self.add_open {
            let mut win_open = true;
            let mut close = false;
            egui::Window::new("添加验证器")
                .open(&mut win_open)
                .collapsible(false)
                .show(&ctx, |ui| {
                    egui::ComboBox::from_label("类型")
                        .selected_text(self.add_kind.label())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.add_kind,
                                KindChoice::Totp,
                                KindChoice::Totp.label(),
                            );
                            ui.selectable_value(
                                &mut self.add_kind,
                                KindChoice::Steam,
                                KindChoice::Steam.label(),
                            );
                            ui.selectable_value(
                                &mut self.add_kind,
                                KindChoice::BattleNet,
                                KindChoice::BattleNet.label(),
                            );
                        });
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label("名称：");
                        ui.text_edit_singleline(&mut self.add_name);
                    });
                    ui.horizontal(|ui| {
                        ui.label("密钥：");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.add_secret)
                                .desired_width(300.0)
                                .hint_text("Base32，如 JBSWY3DPEHPK3PXP"),
                        );
                    });
                    ui.small("密钥只保存在本机 vault（AES-256-GCM 加密）");
                    if let Some(err) = &self.add_error {
                        ui.colored_label(egui::Color32::from_rgb(220, 80, 80), err);
                    }
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("保存").clicked() {
                            match self.try_add() {
                                Ok(()) => close = true,
                                Err(e) => self.add_error = Some(e),
                            }
                        }
                        if ui.button("取消").clicked() {
                            close = true;
                        }
                    });
                });
            if !win_open || close {
                self.add_open = false;
                self.add_name.clear();
                self.add_secret.clear();
                self.add_error = None;
            }
        }

        // —— 改名/删除窗口 ——
        if let Some(id) = self.rename_id.clone() {
            let mut win_open = true;
            let mut keep_open = true;
            egui::Window::new("条目操作")
                .open(&mut win_open)
                .collapsible(false)
                .show(&ctx, |ui| {
                    ui.text_edit_singleline(&mut self.rename_text);
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("改名").clicked() {
                            let name = self.rename_text.trim().to_string();
                            if !name.is_empty() {
                                if self.vault.rename_entry(&id, &name).is_ok() {
                                    self.persist();
                                    self.set_toast("已改名".into());
                                }
                                keep_open = false;
                            }
                        }
                        if ui.button("删除…").clicked() {
                            self.confirm_delete = Some(id.clone());
                        }
                    });
                    if let Some(del_id) = self.confirm_delete.clone() {
                        if del_id == id {
                            ui.separator();
                            ui.horizontal(|ui| {
                                ui.label("确定删除？（密钥将从 vault 移除）");
                                if ui.button("确认删除").clicked() {
                                    if self.vault.remove_entry(&del_id).is_ok() {
                                        self.persist();
                                        self.set_toast("已删除".into());
                                    }
                                    self.confirm_delete = None;
                                    keep_open = false;
                                }
                                if ui.button("取消").clicked() {
                                    self.confirm_delete = None;
                                }
                            });
                        }
                    }
                });
            if !win_open || !keep_open {
                self.rename_id = None;
            }
        }

        // —— 旧版导入窗口 ——
        if self.import_open {
            let mut win_open = true;
            let mut close = false;
            egui::Window::new("从旧版 WinAuth 导入")
                .open(&mut win_open)
                .collapsible(false)
                .show(&ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("配置文件：");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.import_path).desired_width(280.0),
                        );
                        if ui.button("浏览…").clicked() {
                            if let Some(p) = rfd::FileDialog::new()
                                .add_filter("WinAuth 配置", &["xml"])
                                .pick_file()
                            {
                                self.import_path = p.display().to_string();
                            }
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("配置密码：");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.import_password)
                                .password(true)
                                .desired_width(200.0),
                        );
                        ui.small("未设密码可留空");
                    });
                    ui.small("支持 Google/Battle.net/Steam 条目；YubiKey 加密条目不支持");
                    if let Some(err) = &self.import_error {
                        ui.colored_label(egui::Color32::from_rgb(220, 80, 80), err);
                    }
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("导入").clicked() {
                            match self.try_import() {
                                Ok(n) => {
                                    self.set_toast(format!("导入 {n} 个条目"));
                                    close = true;
                                }
                                Err(e) => self.import_error = Some(e),
                            }
                        }
                        if ui.button("取消").clicked() {
                            close = true;
                        }
                    });
                });
            if !win_open || close {
                self.import_open = false;
                self.import_password.clear();
                self.import_error = None;
            }
        }

        // —— 设置窗口 ——
        if self.settings_open {
            let mut win_open = true;
            egui::Window::new("设置")
                .open(&mut win_open)
                .collapsible(false)
                .show(&ctx, |ui| {
                    let mut dirty = false;
                    if ui
                        .checkbox(&mut self.settings.close_to_tray, "关闭窗口时驻留托盘")
                        .changed()
                    {
                        dirty = true;
                    }
                    if ui
                        .checkbox(
                            &mut self.settings.hotkey_enabled,
                            "全局热键 Ctrl+Alt+C 复制",
                        )
                        .changed()
                    {
                        self.apply_hotkey_setting();
                        dirty = true;
                    }
                    if ui
                        .checkbox(&mut self.settings.copy_on_new_code, "新码自动复制")
                        .changed()
                    {
                        dirty = true;
                    }
                    ui.horizontal(|ui| {
                        ui.label("剪贴板清除：");
                        let mut secs = self.settings.clipboard_clear_secs as f32;
                        let slider = ui.add(
                            egui::Slider::new(&mut secs, 0.0..=120.0)
                                .suffix("s")
                                .text("0 = 不清除"),
                        );
                        if slider.changed() {
                            self.settings.clipboard_clear_secs = secs as u64;
                            dirty = true;
                        }
                    });
                    if dirty {
                        self.settings.save();
                        self.set_toast("设置已保存".into());
                    }
                });
            if !win_open {
                self.settings_open = false;
            }
        }
    }
}

impl RustAuthApp {
    /// 从旧版配置导入。
    fn try_import(&mut self) -> Result<usize, String> {
        let path = self.import_path.trim().to_string();
        if path.is_empty() {
            return Err("请填写配置文件路径".into());
        }
        let xml = std::fs::read_to_string(&path).map_err(|e| format!("读取失败: {e}"))?;
        let pw = if self.import_password.is_empty() {
            None
        } else {
            Some(self.import_password.as_str())
        };
        let legacy = rustauth_core::migrate::parse_config(&xml, pw).map_err(|e| e.to_string())?;
        let mut count = 0usize;
        for l in legacy {
            let name = if l.name.is_empty() {
                "导入条目".to_string()
            } else {
                l.name.clone()
            };
            let provider = l.into_provider();
            self.vault
                .add_entry(&name, provider)
                .map_err(|e| e.to_string())?;
            count += 1;
        }
        self.persist();
        Ok(count)
    }

    /// 热键开关即时生效（重建管理器，Drop 注销旧注册）。
    fn apply_hotkey_setting(&mut self) {
        self.hotkey = None;
        if self.settings.hotkey_enabled {
            if let Ok(m) = GlobalHotKeyManager::new() {
                let hk = HotKey::new(Some(Modifiers::CONTROL | Modifiers::ALT), Code::KeyC);
                if let Err(e) = m.register(hk) {
                    eprintln!("热键注册失败: {e:?}");
                }
                self.hotkey = Some(m);
            }
        }
    }

    fn try_add(&mut self) -> Result<(), String> {
        let name = self.add_name.trim().to_string();
        let raw = self.add_secret.trim().to_string();

        // otpauth:// URI 直贴
        if raw.starts_with("otpauth://") {
            let uri =
                rustauth_core::otp::otpauth::parse(&raw).map_err(|e| format!("URI 无效: {e}"))?;
            let provider = uri.to_provider().map_err(|e| e.to_string())?;
            let name = if name.is_empty() {
                uri.issuer
                    .clone()
                    .or_else(|| uri.label.split(':').next().map(|s| s.to_string()))
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "导入条目".to_string())
            } else {
                name
            };
            self.vault
                .add_entry(&name, provider)
                .map_err(|e| e.to_string())?;
            self.persist();
            self.set_toast(format!("已添加「{name}」"));
            return Ok(());
        }

        if name.is_empty() {
            return Err("名称不能为空".into());
        }
        let cleaned: String = raw
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        let secret = base32::decode(&cleaned).map_err(|e| format!("密钥 Base32 无效: {e}"))?;
        if secret.is_empty() {
            return Err("密钥不能为空".into());
        }
        let cfg = CodeConfig::standard(secret);
        let provider = match self.add_kind {
            KindChoice::Totp => Provider::Totp(cfg),
            KindChoice::Steam => Provider::Steam(cfg),
            KindChoice::BattleNet => Provider::BattleNet(CodeConfig::battle_net(cfg.secret)),
        };
        self.vault
            .add_entry(&name, provider)
            .map_err(|e| e.to_string())?;
        self.persist();
        self.set_toast(format!("已添加「{name}」"));
        Ok(())
    }
}
