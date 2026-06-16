# hmac-mbt 检查清单

## 申报前

- [ ] 项目名称、简介和适用场景清晰。
- [ ] GitHub 仓库公开可访问。
- [ ] Gitlink 仓库与 GitHub 同步。
- [ ] 仓库保留 10-20 个有效 commits。
- [ ] README 说明项目目标、用法、限制和许可证。
- [x] 说明项目性质为原创 MoonBit 实现，参考标准为 RFC 2104。

## 开发期

- [x] 实现字节异或和 key 规范化辅助函数。
- [x] 实现 HMAC-SHA256 核心算法。
- [x] 实现恒定时间比较。
- [x] 增加 RFC 或公开来源测试向量。
- [x] 增加边界测试：空 key、空 message、长 key、tag 长度不一致。
- [x] 每次提交前运行 `moon check`。
- [x] 每次提交前运行 `moon test`。

## 验收前

- [x] README 示例可复现。
- [x] `moon check` 通过。
- [x] `moon test` 通过。
- [x] CI 覆盖 check 和 test。
- [x] `competition/ACCEPTANCE_SUMMARY.md` 更新到最新能力。
- [x] 增加 Python 对照和互操作说明。
- [x] 完成申报前最终自查记录。
