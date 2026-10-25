// SPDX-FileCopyrightText: 2026 KNSOR
// SPDX-License-Identifier: AGPL-3.0-or-later

//! 端到端核验：真实旧配置 → vault 写入 → 重开 → 码一致性。
//!
//! 用法：cargo run -p rustauth-core --example vault_import_check -- <winauth.xml> <固定Unix秒>

use std::time::{SystemTime, UNIX_EPOCH};

use rustauth_core::migrate::parse_config;
use rustauth_core::vault::Vault;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("用法: vault_import_check <winauth.xml> <固定Unix秒> [密码]");
        std::process::exit(1);
    }
    let xml = std::fs::read_to_string(&args[1]).expect("读取配置失败");
    let t = args[2].parse::<i64>().unwrap() * 1000;
    let password = args.get(3).filter(|s| !s.is_empty()).map(|s| s.as_str());

    // 1) 迁移解析
    let legacy = parse_config(&xml, password).expect("解析失败");

    // 2) 入库并落盘
    let mut vault = Vault::new().unwrap();
    for l in &legacy {
        let name = if l.name.is_empty() { "导入".into() } else { l.name.clone() };
        vault.add_entry(&name, l.clone().into_provider()).unwrap();
    }
    let path = std::env::temp_dir().join("rustauth-verify.vault");
    vault.save_to(&path).unwrap();

    // 3) 重新解锁并比对
    let reopened = Vault::load_from(&path, None).unwrap();
    let _ = std::fs::remove_file(&path);
    let mut all_match = true;
    for (i, e) in reopened.entries().iter().enumerate() {
        let via_vault = e.code_at(t).unwrap();
        let direct = legacy[i].clone().into_provider().code_at(t).unwrap();
        let ok = via_vault == direct;
        all_match &= ok;
        println!(
            "  {:?} vault={via_vault} 直算={direct} {}",
            e.name,
            if ok { "✅" } else { "❌" }
        );
    }
    if all_match {
        println!("vault 集成往返核验通过");
    } else {
        std::process::exit(2);
    }
}
