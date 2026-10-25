# RustAuth Vault 格式规范 v1

> 状态：稳定（v1 变更仅允许追加字段）· 本文档与实现一同测试

## 设计目标

1. **可迁移**：任何第三方按本文档即可读写 vault，杜绝原版 WinAuth 的黑箱格式。
2. **本机免密 + 可选密码层**：DPAPI（当前 Windows 用户）包裹主密钥开箱即用；
   密码层作为第二把包裹叠加，两者独立可解锁。
3. **防篡改**：AES-256-GCM 提供机密性与完整性，任何字节翻转导致解密失败。

## 字节布局（小端）

```
偏移    长度   字段
0       7     magic:   "WVAULT\x00"（7 字节）
7       4     version: u32 LE = 1
11      4     header_len: u32 LE
11+h    ?     header:  UTF-8 JSON（明文元数据）
+h      12    nonce:   AES-GCM 随机 nonce
+h+12   n     ciphertext: AES-256-GCM(master_key, entries_json)
+h+12+n 16    tag:     GCM 认证标签
```

`h = header_len`，`n = 文件总长 - (15 + h + 28)`（固定开销 15 = 7+4+4，尾部 28 = nonce 12 + tag 16）。

## Header JSON

```json
{
  "created_ms": 1730000000000,
  "cipher": "aes-256-gcm",
  "wraps": [
    { "type": "dpapi-user", "blob": "<base64 标准字母表>" }
  ]
}
```

- `wraps[].type` 取值：
  - `dpapi-user` — Windows DPAPI 当前用户域包裹（恒存在，本机免密解锁）
  - `argon2id-password` — 密码层包裹：
    `{"type":"argon2id-password","salt":"<b64 16B>","m_kib":65536,"t":3,"p":4,"blob":"<b64>"}`
    （blob = AES-256-GCM(password_key, master_key) 的 nonce(12B)||ct||tag）
- 解锁顺序任意；至少一把能解开 master key。
- 未知的 `type` 必须**跳过**（前向兼容），不得报错。

## 主密钥与加密

- master key：32 字节 CSPRNG 随机，永不明文落盘。
- 密文明文为 **entries JSON（UTF-8）**：

```json
[
  {
    "id": "hex16",
    "name": "显示名",
    "created_ms": 1730000000000,
    "provider": {
      "kind": "totp",            // totp | hotp | steam | battle_net
      "secret_b32": "JBSWY3DP...",  // 标准 base32 无填充
      "digits": 6,
      "period_secs": 30,
      "algorithm": "SHA1",       // SHA1 | SHA256 | SHA512
      "time_offset_ms": 0,
      "counter": null             // hotp: u64，其余 null
    }
  }
]
```

- 未知 `kind` 视为错误（数据完整性受损）；未知**顶层**字段忽略。

## 版本策略

- v1 内：只允许追加（header/entry 新字段、wraps 新类型）；读取端必须宽容。
- 破坏性变更：version 递增并携带迁移函数；读取端拒绝更高主版本。

