name: Bug 报告
description: 报告功能缺陷
labels: ["bug"]
body:
  - type: markdown
    attributes:
      value: |
        ⚠️ 请勿粘贴真实密钥、vault 文件或验证码截图——用测试账号/RFC 测试密钥复现。
  - type: input
    id: version
    attributes:
      label: 版本 / commit
      placeholder: "v0.1.0 或 commit hash"
    validations:
      required: true
  - type: dropdown
    id: os
    attributes:
      label: 操作系统
      options:
        - Windows 11
        - Windows 10
        - 其他
    validations:
      required: true
  - type: textarea
    id: what-happened
    attributes:
      label: 问题描述
      description: 预期行为 vs 实际行为，复现步骤
    validations:
      required: true
  - type: textarea
    id: logs
    attributes:
      label: 日志/截图（脱敏）
      required: false
