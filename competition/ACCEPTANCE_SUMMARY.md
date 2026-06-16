# hmac-mbt 阶段性验收说明

## 当前状态

项目已完成 MVP 主体能力：围绕 HMAC-SHA256 提供计算函数、十六进制输出、恒定时间验证函数、RFC 测试向量和可复现文档。

## 已完成能力

- MoonBit 包元数据和 GitHub 仓库地址。
- 竞赛材料目录和 20 个 commit 开发路线。
- HMAC-SHA256 主流程：`SHA256(opad || SHA256(ipad || message))`。
- 短 key、block-sized key、长 key 规范化。
- inner pad 和 outer pad 生成。
- `verify` 验证函数和恒定时间比较辅助函数。
- `hmac_sha256_hex` 和 `to_hex` 展示辅助函数。
- README API 文档、示例、验证命令和项目限制说明。
- GitHub Actions CI 配置，覆盖 `moon check` 和 `moon test`。

## 待完成能力

- 许可证文件和第三方依赖说明。
- Python 对照示例和互操作说明。
- 申报前最终自查。

## 验证记录

- 2026-06-01：本地执行 `moon check` 通过。
- 2026-06-01：本地执行 `moon test` 通过，测试结果为 23 passed, 0 failed。
- 2026-06-01：完成 20 个有效 commits 的申报前自查记录。
