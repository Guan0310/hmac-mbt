# Python 对照与互操作说明

## 目标

`hmac-mbt` 的输出应与 Python 标准库 `hmac` 在 HMAC-SHA256 场景下保持一致。

## Python 对照代码

```python
import hashlib
import hmac

tag = hmac.new(
    b"key",
    b"The quick brown fox jumps over the lazy dog",
    hashlib.sha256,
).hexdigest()

print(tag)
```

期望输出：

```text
f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
```

## MoonBit 对照

```moonbit
test {
  inspect(
    hmac_sha256_hex(b"key", b"The quick brown fox jumps over the lazy dog"),
    content="f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
  )
}
```

## 已覆盖的互操作场景

- 普通 ASCII key 和 message。
- 空 key 和空 message。
- 长度超过 SHA256 block size 的 key。
- RFC 4231 HMAC-SHA256 测试向量。
- tag 长度不一致时验证失败。

## 注意事项

`verify` 接收原始 `Bytes` tag。如果外部系统传入十六进制字符串，需要先转换为 bytes 后再验证，或直接比较 `hmac_sha256_hex` 的结果。
