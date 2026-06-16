# 申报前最终自查

## 仓库状态

- GitHub remote: `https://github.com/Guan0310/hmac-mbt.git`
- 当前分支：`master`
- 当前有效 commit 数：20
- 项目性质：原创 MoonBit HMAC-SHA256 库，SHA256 digest 依赖 `gmlewis/sha256`

## 功能自查

- [x] HMAC-SHA256 主流程已实现。
- [x] 支持短 key、block-sized key、长 key。
- [x] 支持原始 bytes tag 输出。
- [x] 支持 lowercase hex tag 输出。
- [x] 支持 tag 验证。
- [x] tag 比较使用恒定时间比较辅助函数。
- [x] RFC 4231 测试向量已覆盖。
- [x] 空 key、空 message、长 key、tag 长度不一致已覆盖。

## 工程自查

- [x] README 包含项目目标、API、示例、验证命令和限制说明。
- [x] `competition/` 包含项目定位、路线、验收记录、参考说明和互操作说明。
- [x] GitHub Actions CI 覆盖 `moon check` 和 `moon test`。
- [x] LICENSE 文件已添加。
- [x] `.gitignore` 已排除构建产物和依赖缓存。

## 本地验证

- `moon check`：通过。
- `moon test`：通过，23 passed, 0 failed。

## 后续注意事项

- 若赛事群更新模板或截止时间，应同步更新 `competition/` 材料。
- 若同步 Gitlink，应确认 GitHub 与 Gitlink 内容一致。
- 若继续扩展能力，优先考虑流式输入或更多 hash 算法，但不要扩大申报 MVP 承诺。
