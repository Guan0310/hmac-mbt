/// SHA-256 摘要大小（字节数）。
pub let sha256_digest_size : Int = 32

/// SHA-256 块大小（字节数），用于 HMAC key 填充。
pub let sha256_block_size : Int = 64

/// 返回两个等长字节串的按位 XOR 结果。
pub fn xor_bytes(left : Bytes, right : Bytes) -> Bytes {
  guard left.length() == right.length() else {
    abort("xor_bytes requires equal-length inputs")
  }
  Bytes::makei(left.length(), i => left[i] ^ right[i])
}
