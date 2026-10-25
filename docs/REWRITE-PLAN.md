# RustAuth（WinAuth Rust 重写）总体规划

> 版本 v1.1 · 2026-10-24 · 奠基于原仓库 master（commit 2018-10-12）实测
> 决策前提：全新 Rust 重写 · 独立产品 · **AGPL-3.0-or-later**（依据 FSF 单向兼容自上游 GPL-3.0-or-later，见 NOTICE）· B+C 路线（重写核心+精简范围）

---

## 1. 现状全景（全部为实测事实）

| 指标 | 值 |
|---|---|
| 原仓库 | winauth/winauth fork，GPL-3.0，archived，末次提交 2018-10-12，175 open issues |
| 总量 | C# 37,122 行 = 核心库 Authenticator/ 7,492 + UI 壳 WinAuth/ 29,630（此前"1.78M 行"说法错误，差 48 倍） |
| 算法核心 | RFC 6238 基类 `CalculateCode`（HMAC-SHA1/256/512+动态截断，~100 行）；Steam 码 ~30 行（26 字符表 `23456789BCDFGHJKMNPQRTVWXY`）；Battle.net **无码生成重写**（纯基类 8 位 TOTP） |
| 私货部分 | Steam 注册/交易确认（`SteamClient` 正则刮 HTML，脆弱）；Battle.net 注册/恢复（RSA 挑战 + `mobile-service.blizzard.com` 私有端点）；分区时间同步 |
| 存储 | XML + 分层加密：DPAPI(User+Machine) → 可选密码 → 可选 YubiKey，SHA1 盐哈希校验；格式未文档化 |
| UI 依赖 | MetroFramework（WinForms 皮肤）、InputSimulator（热键）；主窗体 `WinAuthForm.cs` 2,801 行 |
| 原版功能清单（表单/菜单实测） | 条目列表、右键（CopyCode/新码自动复制/改名/删除/Steam 交易确认）、改密码、加密导出（含 PGP）、YubiKey 解锁、全局热键、自更新检查、多提供商（Google/Battle.net/Steam/GW2/Trion/Microsoft/Okta） |

## 2. 产品定义

**一句话**：Windows 桌面 TOTP/Steam/Battle.net 认证器——托盘常驻、取码即走、vault 格式公开可迁移。

- **目标用户**：自己（主）→ 开源社区（次）。
- **非目标**：跨平台（Core 纯库不封路，但 v1 不做 Linux/macOS 壳）；GW2/Trion/Okta 等死协议提供商；移动端；浏览器扩展。

### 功能去向表

| 原版功能 | 去向 | 说明 |
|---|---|---|
| 条目列表/码自动刷新 | ✅ 移植 | M3 核心 |
| 复制码 + 新码自动复制 | ✅ 移植 | M3 |
| 剪贴板 30s 自动清除 | ✅ 新增（原版无） | 安全卖点 |
| 全局热键 | ✅ 移植 | global-hotkey crate |
| 托盘常驻 | ✅ 移植 | 重点修复原版 issue #658 类"图标消失" |
| 加密导出 | ✅ 简化 | 明文 otpauth 列表导出+警示；PGP 砍掉 |
| otpauth:// 与 QR | ✅ 新增 | 原版没有，行业标准格式 |
| 旧版配置导入 | ✅ 新增 | M4 旗舰功能 |
| Google/通用 TOTP | ✅ | M1 |
| Steam 登录码 | ✅ | M1 |
| Battle.net 显示码(T1) | ✅ | M1（迁移路径优先，不碰注册 API） |
| 改密码 | ⚠️ 后置 | vault 支持密码层即可，UI 后补 |
| Steam 交易确认 | 🔬 实验 M5 | HTML 刮屏已死风险 |
| Steam/Bnet 新注册 | 🔬 实验 M5 | 私有 API |
| YubiKey | ❌ 砍掉 | 硬件依赖小众；YubiKey 加密的旧配置**明确不支持迁移** |
| GW2/Trion/Okta/Microsoft | ❌ 砍掉 | 死协议无人验证 |
| 自更新检查 | ❌ 砍掉 | cargo-dist + GitHub Release 即可 |
| 密码保护 vault | ⚠️ v1.1 | DPAPI 免密先行，密码层 M2 内实现 UI 后补 |

## 3. 架构设计

### 3.1 Cargo Workspace

```
rustauth/
├── crates/
│   ├── rustauth-core/      # 纯算法+格式，零网络、零UI（feature "enroll" 才引 reqwest）
│   │   ├── src/otp/       # base32, hotp, totp, steam, bnet(T1)
│   │   ├── src/otpauth/   # URI 解析/构建
│   │   ├── src/vault/     # 格式 v1、DPAPI、aes-gcm、argon2(可选层)
│   │   └── src/migrate/   # 旧 WinAuth XML 解析+解密（M4）
│   ├── rustauth-gui/       # eframe(egui) + tray-icon + global-hotkey + arboard
│   └── rustauth-cli/       # M5 可选，clap
├── docs/                  # vault-format-v1.md（公开格式规范）、本规划
└── .github/workflows/     # ci.yml(test+clippy+fmt)、release.yml(cargo-dist)
```

依赖预算：core 仅 RustCrypto 系（hmac/sha1/sha2/aes-gcm/argon2）+ base32 + serde + cbor + zeroize + secrecy + thiserror + windows(DPAPI)；gui 另加 eframe/tray-icon/global-hotkey/arboard/qrcode+rqrr。

### 3.2 Provider 抽象

**ADR-2：enum dispatch 优先于 trait**——提供商种类封闭（4 种），穷举 match 比 trait object 更 Rust 味、零开销：

```rust
pub enum Provider {
    Totp(CodeConfig),        // Google 等，6/8位，SHA1/256/512
    Hotp(CodeConfig, u64),   // 计数器
    Steam(CodeConfig),       // 5字符×26表
    BattleNet(CodeConfig),   // 8位+分区偏移
}

pub struct CodeConfig {
    pub secret: SecretBuf,   // zeroize+secrecy 包装
    pub digits: u8,
    pub period_secs: u32,
    pub hmac: HmacAlgo,
    pub time_offset_ms: i64, // bnet 区域/服务器偏移
}

impl Provider {
    pub fn code_at(&self, unix_ms: i64) -> String;
    pub fn remaining_secs(&self, unix_ms: i64) -> u32;
}
```

网络能力（注册/恢复）不进此 enum——独立 `enroll` 模块 + feature flag，core 保持离线纯净。

### 3.3 Vault 格式 v1（核心资产，字节级规范）

```
rustauth.vault（小端）
offset size  field
0      8     magic  "WVAULT\x00" + version(1)
8      4     header_len (u32)
12     h     header: JSON（明文元数据）
             { "created": ..., "cipher": "aes-256-gcm",
               "wraps": [ {"type":"dpapi-user","blob":<b64>} ,          // 恒有
                          {"type":"argon2id-password","params":{...},"blob":<b64>} ] }  // 可选
12+h   12    nonce
+      ?     ciphertext = AES-256-GCM(master_key, entries_cbor)
+      16    GCM tag

entries_cbor: [ { id: uuid, name, provider: Provider, serial?, restore_code?, created, sort } ]
```

- 主密钥 32B 随机；DPAPI(User) 恒包裹一份（本机免密解锁）；密码层为**第二把包裹**（argon2id: m=64MiB, t=3, p=4），加密码不删 DPAPI 份。
- 兼容规则：version 不变时可加字段（cbor 自描述）；破坏性变更 bump version + 迁移函数。
- 规范全文独立成 `docs/vault-format-v1.md` 对外公开——这是对原版"黑箱格式"的正面卖点。
- 防篡改：GCM 认证整段密文；magic/version 明文可检。

### 3.4 时间同步

TOTP 失败首因是时钟。设计：本地时钟为真（Windows 已 NTP 同步）；每 provider 可存 `time_offset_ms`（bnet 区域常数表内置）；M4 起提供"校准"工具（HTTP Date 头比对，`ureq`/`reqwest` blocking，不引 async）。

### 3.5 GUI 架构

- eframe 单窗；状态 = `Vec<EntryState>` + 1Hz tick 重算码与进度环。
- 托盘（tray-icon）：菜单【显示/复制第一个码/退出】；关窗=最小化到托盘；单实例 named mutex。
- 热键（global-hotkey）：默认 `Ctrl+Alt+C` 复制激活条目，可改。
- 剪贴板（arboard）：复制即起 30s 清除定时器（可配关闭）。
- 设置：`%APPDATA%\rustauth\settings.json`（热键/清除时长/启动项）。

## 4. 里程碑（任务级分解）

### M0 · 工具链与骨架（0.5 人日）
- [ ] rustup 安装（MSVC target，本机 VS2022 工具链已就绪）
- [ ] workspace 三 crate 空壳 + rustfmt.toml + clippy `-D warnings`
- [ ] LICENSE(GPL-3.0 原文) + README 重写说明 + 本文档入库
- **DoD**：`cargo build && cargo test && cargo clippy` 三绿。

### M1 · Core 算法层（3-4 人日）
- [ ] base32 编解码（RFC 4648）+ 测试
- [ ] HOTP（RFC 4226 附录 D 全向量）/ TOTP（RFC 6238 附录 B 全向量：SHA1/256/512 × 6/8位）
- [ ] Provider enum + Steam（26 字符表）+ BattleNet T1（8 位 + US/EU/KR/CN 偏移表）
- [ ] otpauth:// 解析与构建（type/label/secret/digits/period/algorithm/issuer）+ 测试
- [ ] thiserror 错误体系；Steam/Bnet 自造固定向量（固定 secret+时间步）
- **DoD**：两组 RFC 官方向量全绿；clippy 零警告；core 无网络依赖。
- 知识点：所有权/借用、模块树、单元测试、枚举穷举。

### M2 · Vault 层（2 人日）
- [ ] windows crate DPAPI CryptProtectData/UnprotectData（User 域）
- [ ] 格式 v1 读写（serde+cbor）+ argon2 密码包裹层
- [ ] zeroize/secrecy 全程包裹密钥
- [ ] 测试：roundtrip / 篡改单字节必报错 / 错误密钥必报错 / 加密码后双路径解锁 / 版本前向检查
- [ ] `docs/vault-format-v1.md` 定稿入库
- **DoD**：上述测试全绿；格式文档与实现一字不差。
- 知识点：serde、FFI 与 unsafe 边界、安全编码实践。

### M3 · GUI 主体（6-8 人日，最大不确定在此）
- [ ] eframe 主窗：条目列表（名称/码/环形进度）、添加/编辑/删除/改名
- [ ] 添加三通道：手输 secret / 粘贴 otpauth:// / QR 图片文件（rqrr 解码）
- [ ] 托盘集成 + 关窗隐藏 + 单实例互斥
- [ ] 全局热键复制 + 新码自动复制选项
- [ ] arboard 剪贴板 + 30s 清除
- [ ] settings.json 读写
- [ ] 手动冒烟清单（见 §5）逐条过
- **DoD**：连续日常使用 3 天无功能性 bug。
- 知识点：事件循环、闭包、内部可变性（RefCell/Rc/Arc/Mutex）、Send/Sync。
- 风险预案：tray-icon × eframe 事件循环打通若超 2 人日，降级为先"常驻窗口+置顶"。

### M4 · 迁移与互通（3 人日）
- [ ] 旧 WinAuth XML 解析（版本/authenticator 节点/加密层链）
- [ ] 复刻解密链：DPAPI(User/Machine)→密码→OTP 层（对照原 `Authenticator.cs` 逐层）；YubiKey 层明确报"不支持"
- [ ] Google/Bnet/Steam 字段映射 → Provider；导入后即出码验证
- [ ] otpauth:// 批量导出 + QR 码图导出（qrcode crate）
- **DoD**：真实旧配置（自造含 DPAPI+密码双层样本）导入成功且码与原版一致。
- 知识点：真实协议逆向移植、防御式解析。

### M5 · 可选池（不排期，按需取用）
CLI(clap) · bnet 恢复/注册(T2/T3) · Steam 交易确认（实验） · vault 密码 UI/改密 · Windows Hello 解锁 · 自动锁定 · i18n · 开机自启

**合计：M0-M4 ≈ 15-17 人日；业余节奏约 3 周出 MVP。**

## 5. 测试策略

| 层 | 手段 |
|---|---|
| 算法 | RFC 4226 附录 D + RFC 6238 附录 B 官方向量；Steam/Bnet 固定向量 |
| Vault | roundtrip、位翻转篡改、错钥、双解锁路径、版本演进 |
| 迁移 | 构造含全部加密层组合的旧格式样本库；码一致性对拍 |
| GUI | 手动冒烟清单：添加/删除/改名/复制/热键/托盘/剪贴板清除/重启持久化/双开互斥/时钟偏差提示 |
| CI | 每次 push：test+clippy+fmt；tag：cargo-dist 出 Release |

## 6. 风险登记册

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| tray-icon×eframe 集成踩坑 | 高 | M3 延期 | 预设降级方案；先做最小托盘原型（M3 首日） |
| 私有 API（bnet 注册/Steam 确认）随时死 | 高 | M5 功能失效 | 全部隔离在实验层，不入 MVP 承诺 |
| 旧格式迁移边角（YubiKey/老版本 XML） | 中 | 部分用户无法迁移 | 明确不支持清单+报错文案 |
| Rust 学习曲线拖慢 M1 | 中 | 延期 1-2 天 | 已计入估时；clippy 当导师 |
| DPAPI FFI 细节 | 中 | M2 卡顿 | windows crate 官方样例为纲 |
| GPL/AGPL 合规疏漏 | 低 | 法律风险 | LICENSE(AGPL)+NOTICE 溯源（Colin Mackie, GPL-3.0-or-later）已入库；依赖仅 MIT/Apache 系，deny.toml+CI 自动审计拒绝 copyleft 依赖 |
| 范围蔓延（想支持的提供商越加越多） | 高 | 全线延期 | 功能去向表为宪法，新增一律进 M5 池 |

## 7. Git 与发布

- 分支：单分支 `rewrite` 开发（上游代码不进入本仓库，溯源见 NOTICE）；首个可用版 `v0.1.0`。
- 提交规范：沿用 `feat:/fix:/chore:/docs:` + 中文短句。
- CI：`ci.yml`（push：test/clippy/fmt）；`release.yml`（tag `v*`：cargo-dist 构建 MSVC 单文件 EXE → GitHub Release，对位 FRecorder 已验证的 tag 触发模式）。
- 版本：SemVer；0.x 期格式变更允许 bump minor 并带迁移函数。

## 8. Rust 学习地图（里程碑 → 知识点）

| 里程碑 | 主修 | 附带 |
|---|---|---|
| M0 | cargo/workspace/工具链 | rustfmt/clippy |
| M1 | 所有权·借用·生命周期 | 枚举穷举、测试组织、thiserror |
| M2 | serde 数据建模 | FFI/unsafe 边界、zeroize 安全编码 |
| M3 | 事件循环与状态 | RefCell/Rc/Arc、闭包、Send/Sync |
| M4 | 协议移植 | 防御式解析、集成测试 |
| M5 | （按内容）宏/HTTP 客户端 | — |
| 刻意不学 | async/tokio | 本项目全程同步，引入即负资产 |

## 9. 决策记录（ADR）

1. **Rust 全量重写**：语言学习为主目标之一，C# 方案已弃。
1b. **协议进化 AGPL-3.0-or-later**：上游为 GPL-3.0-or-later，"or later" + FSF 矩阵（GPLv3→AGPLv3 单向）允许衍生作品以 AGPL 传播；反向不允许。社区规范全套（NOTICE/CONTRIBUTING/SECURITY/COC/模板/CI 许可审计）随 M0 落库。
2. **enum 优先 trait**：提供商封闭集，穷举优于动态分发。
3. **同步优先**：无 tokio；网络需求用 blocking 客户端。
4. **egui 而非 Tauri**：100% Rust，最大化技能积累。
5. **vault 单文件 + 双包裹**：DPAPI 免密恒有，密码层可选叠加。
6. **迁移优先于注册**：bnet/steam 新注册全部实验化，显示码走导入路径。
7. **旧库解密复刻而非调用**：迁移器在 Rust 内重实现解密链，不依赖 .NET 运行时。

## 10. 开放决策（开工前拍板）

| # | 问题 | 建议 |
|---|---|---|
| 1 | UI 语言 | 中文优先（自用），i18n 留 M5 |
| 2 | 默认热键 | `Ctrl+Alt+C` |
| 3 | v1 是否开机自启 | 不做，M5 |
| 4 | vault 密码层 UI | v1.1（格式 M2 已支持，只欠 UI） |
