# 参考标准与依赖说明

## 项目性质

`hmac-mbt` 是原创 MoonBit 项目，实现 HMAC-SHA256 的组合逻辑、key 规范化、pad 派生、tag 验证和测试覆盖。

## 参考标准

- RFC 2104: HMAC: Keyed-Hashing for Message Authentication。
- RFC 4231: HMAC-SHA 系列测试向量。

## 第三方依赖

- `gmlewis/sha256@0.17.31`
  - 用途：提供 SHA256 digest 实现。
  - 来源：MoonBit 包管理生态。
  - 项目中的 HMAC 组合逻辑由 `hmac-mbt` 自行实现。

## 许可证

项目许可证为 MIT。第三方依赖保留其各自许可证和版权声明。
