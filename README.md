# hmac-mbt

基于 RFC 2104 的 HMAC-SHA256 MoonBit 实现。

`hmac-mbt` 使用 SHA-256 作为底层哈希函数，实现了 RFC 2104 定义的 HMAC 消息认证码。

## 功能

- 计算 HMAC-SHA256 标签（`Bytes` 格式）
- 计算小写十六进制 HMAC-SHA256 标签
- 使用恒定时间比较验证标签
- 支持短 key、block-size key 以及超过 SHA-256 block size 的长 key
- 包含 RFC 4231 测试向量和边界测试

## API

```moonbit
pub fn hmac_sha256(key : Bytes, message : Bytes) -> Bytes
pub fn hmac_sha256_hex(key : Bytes, message : Bytes) -> String
pub fn verify(key : Bytes, message : Bytes, tag : Bytes) -> Bool
pub fn constant_time_equal(left : Bytes, right : Bytes) -> Bool
pub fn to_hex(input : Bytes) -> String
```

## 示例

```moonbit
test {
  let tag = hmac_sha256_hex(
    b"key",
    b"The quick brown fox jumps over the lazy dog",
  )
  inspect(
    tag,
    content="f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
  )
}
```

## 本地验证

```powershell
moon check
moon test
```

## 项目范围

当前仅支持 HMAC-SHA256，暂不提供泛型多算法 HMAC 接口或流式增量输入 API。

## 参考

- RFC 2104：HMAC：密钥哈希消息认证
- RFC 4231：HMAC-SHA-224/256/384/512 标识符与测试向量
- Python 标准库：`hmac.new(key, message, hashlib.sha256)`

## 许可

MIT

本仓库的 HMAC 构造由 `hmac-mbt` 实现，SHA-256 摘要计算由 MoonBit 包 `gmlewis/sha256` 提供。
