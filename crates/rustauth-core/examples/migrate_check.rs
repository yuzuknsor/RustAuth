// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! 真实旧版配置迁移验证工具。
//!
//! 用法：cargo run -p rustauth-core --example migrate_check -- <winauth.xml 路径> [密码]
//!
//! 输出条目元数据与当前验证码（不打印密钥本体）。

use std::time::{SystemTime, UNIX_EPOCH};

use rustauth_core::migrate::parse_config;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("用法: migrate_check <winauth.xml 路径> [密码]");
        std::process::exit(1);
    }
    let xml = std::fs::read_to_string(&args[1]).expect("读取配置失败");
    let password = args.get(2).map(|s| s.as_str());

    match parse_config(&xml, password) {
        Ok(entries) => {
            let ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            println!("迁移条目数: {}", entries.len());
            for e in &entries {
                let code = e.clone().into_provider().code_at(ms).unwrap_or_else(|e| format!("ERR {e}"));
                println!(
                    "  名称={:?} 类型={} 位数={} 周期={}s 偏移={}ms 密钥={}字节",
                    e.name,
                    e.legacy_type,
                    e.digits,
                    e.period_secs,
                    e.time_offset_ms,
                    e.secret.len()
                );
                println!("  当前验证码: {code}");
            }
        }
        Err(e) => {
            eprintln!("迁移失败: {e}");
            std::process::exit(2);
        }
    }
}
