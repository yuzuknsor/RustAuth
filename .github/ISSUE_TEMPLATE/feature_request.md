name: 功能建议
description: 提出新功能或改进
labels: ["enhancement"]
body:
  - type: textarea
    id: problem
    attributes:
      label: 要解决什么问题
    validations:
      required: true
  - type: textarea
    id: solution
    attributes:
      label: 期望的方案
      description: 如有备选方案请一并说明取舍
    validations:
      required: true
