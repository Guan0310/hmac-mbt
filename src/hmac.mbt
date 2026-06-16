/// SHA-256 摘要大小（字节数）。
pub let sha256_digest_size : Int = 32

/// SHA-256 块大小（字节数），用于 HMAC key 填充。
pub let sha256_block_size : Int = 64

/// 将 HMAC key 归一化至恰好一个 SHA-256 block 长度。
pub fn normalize_key_for_sha256(key : Bytes) -> Bytes {
  let base_key = if key.length() > sha256_block_size {
    sha256_digest(key)
  } else {
    key
  }
  zero_pad_to(base_key, sha256_block_size)
}

fn hmac_pad(key : Bytes, pad_byte : Byte) -> Bytes {
  xor_bytes(normalize_key_for_sha256(key), Bytes::make(sha256_block_size, pad_byte))
}

/// 返回 HMAC-SHA256 的 inner pad。
pub fn inner_pad_for_sha256(key : Bytes) -> Bytes {
  hmac_pad(key, b'\x36')
}

/// 返回 HMAC-SHA256 的 outer pad。
pub fn outer_pad_for_sha256(key : Bytes) -> Bytes {
  hmac_pad(key, b'\x5c')
}

/// 验证 HMAC-SHA256 标签。
pub fn verify(key : Bytes, message : Bytes, tag : Bytes) -> Bool {
  constant_time_equal(hmac_sha256(key, message), tag)
}

test "xor_bytes" {
  inspect(
    xor_bytes(b"\x0f\xf0", b"\xf0\x0f"),
    content=(
      #|b"\xff\xff"
    ),
  )
}

test "bytes_from_hex" {
  inspect(
    bytes_from_hex("0aFF"),
    content=(
      #|b"\x0a\xff"
    ),
  )
}

test "to_hex" {
  inspect(to_hex(b"\x00\x0f\x10\xff"), content="000f10ff")
}

test "zero_pad_to" {
  inspect(
    zero_pad_to(b"key", 5),
    content=(
      #|b"key\x00\x00"
    ),
  )
}

test "sha256_digest" {
  inspect(
    sha256_digest_hex(b"abc"),
    content="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
}

test "hmac_sha256_hex" {
  inspect(
    hmac_sha256_hex(b"key", b"The quick brown fox jumps over the lazy dog"),
    content="f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
  )
}

test "hmac_sha256_known_digest" {
  inspect(
    hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog") ==
    bytes_from_hex(
      "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
    ),
    content="true",
  )
}

test "rfc_4231_case_1" {
  inspect(
    hmac_sha256(Bytes::make(20, b'\x0b'), b"Hi There") ==
    bytes_from_hex(
      "b0344c61d8db38535ca8afceaf0bf12b" +
      "881dc200c9833da726e9376c2e32cff7",
    ),
    content="true",
  )
}

test "rfc_4231_case_2" {
  inspect(
    hmac_sha256(b"Jefe", b"what do ya want for nothing?") ==
    bytes_from_hex(
      "5bdcc146bf60754e6a042426089575c7" +
      "5a003f089d2739839dec58b964ec3843",
    ),
    content="true",
  )
}

test "rfc_4231_case_3" {
  inspect(
    hmac_sha256(Bytes::make(20, b'\xaa'), Bytes::make(50, b'\xdd')) ==
    bytes_from_hex(
      "773ea91e36800e46854db8ebd09181a7" +
      "2959098b3ef8c122d9635514ced565fe",
    ),
    content="true",
  )
}

test "normalize_short_key" {
  let normalized = normalize_key_for_sha256(b"key")
  inspect(normalized.length(), content="64")
  inspect(normalized[3], content="b'\\x00'")
}

test "normalize_block_key" {
  let key = Bytes::make(sha256_block_size, b'\x01')
  let normalized = normalize_key_for_sha256(key)
  inspect(normalized.length(), content="64")
  inspect(normalized[63], content="b'\\x01'")
}

test "normalize_long_key" {
  let key = Bytes::make(65, b'a')
  let normalized = normalize_key_for_sha256(key)
  inspect(normalized.length(), content="64")
  inspect(normalized[32], content="b'\\x00'")
}

test "inner_pad" {
  let pad = inner_pad_for_sha256(b"\x0f")
  inspect(pad.length(), content="64")
  inspect(pad[0], content="b'\\x39'")
}

test "outer_pad" {
  let pad = outer_pad_for_sha256(b"\x0f")
  inspect(pad.length(), content="64")
  inspect(pad[0], content="b'\\x53'")
}

test "empty_key_and_message" {
  inspect(
    hmac_sha256(b"", b"") ==
    bytes_from_hex(
      "b613679a0814d9ec772f95d778c35fc5" +
      "ff1697c493715653c6c712144292c5ad",
    ),
    content="true",
  )
}

test "empty_message" {
  inspect(
    hmac_sha256(b"key", b"") ==
    bytes_from_hex(
      "5d5d139563c95b5967b9bd9a8c9b233a" +
      "9dedb45072794cd232dc1b74832607d0",
    ),
    content="true",
  )
}

test "verify_match_and_reject" {
  let tag = hmac_sha256(b"key", b"message")
  inspect(verify(b"key", b"message", tag), content="true")
  inspect(verify(b"key", b"message!", tag), content="false")
}

test "verify_truncated_and_extended" {
  let tag = hmac_sha256(b"key", b"message")
  let truncated = Bytes::from_array(tag[:31].to_array())
  inspect(verify(b"key", b"message", truncated), content="false")
  inspect(verify(b"key", b"message", tag + b"\x00"), content="false")
}

test "rfc_4231_long_key" {
  inspect(
    hmac_sha256(Bytes::make(131, b'\xaa'), b"Test Using Larger Than Block-Size Key - Hash Key First") ==
    bytes_from_hex(
      "60e431591ee0b67f0d8a26aacbf5b77f" +
      "8e0bc6213728c5140546040f0ee37f54",
    ),
    content="true",
  )
}

test "long_key_long_data" {
  inspect(
    hmac_sha256(
      Bytes::make(131, b'\xaa'),
      b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
    ) ==
    bytes_from_hex(
      "9b09ffa71b942fcb27635fbcd5b0e944" +
      "bfdc63644f0713938a7f51535c3a35e2",
    ),
    content="true",
  )
}

test "constant_time_equal_match" {
  inspect(constant_time_equal(b"abc", b"abc"), content="true")
  inspect(constant_time_equal(b"abc", b"abd"), content="false")
  inspect(constant_time_equal(b"abc", b"abcd"), content="false")
}

test "constant_time_equal_empty" {
  inspect(constant_time_equal(b"", b"\x00"), content="false")
  inspect(constant_time_equal(b"\x00", b""), content="false")
  inspect(constant_time_equal(b"abc", b"abc\x00"), content="false")
}

/// 计算 HMAC-SHA256 标签。
pub fn hmac_sha256(key : Bytes, message : Bytes) -> Bytes {
  let inner_hash = sha256_digest(inner_pad_for_sha256(key) + message)
  sha256_digest(outer_pad_for_sha256(key) + inner_hash)
}

/// 返回两个等长字节串的按位 XOR 结果。
pub fn xor_bytes(left : Bytes, right : Bytes) -> Bytes {
  guard left.length() == right.length() else {
    abort("xor_bytes requires equal-length inputs")
  }
  Bytes::makei(left.length(), i => left[i] ^ right[i])
}

/// 恒定时间比较两个标签，不提前退出。
///
/// 对不同长度的输入，扫描较长者并将缺失字节视为零。
pub fn constant_time_equal(left : Bytes, right : Bytes) -> Bool {
  let max_len = if left.length() > right.length() {
    left.length()
  } else {
    right.length()
  }
  let mut diff = left.length() ^ right.length()
  for i in 0..<max_len {
    let left_byte = match left.get(i) {
      Some(byte) => byte.to_int()
      None => 0
    }
    let right_byte = match right.get(i) {
      Some(byte) => byte.to_int()
      None => 0
    }
    diff = diff | (left_byte ^ right_byte)
  }
  diff == 0
}

/// 用零字节右填充字节串至 `size` 长度。
pub fn zero_pad_to(input : Bytes, size : Int) -> Bytes {
  guard input.length() <= size else { abort("input is longer than target size") }
  input + Bytes::make(size - input.length(), b'\x00')
}

fn hex_char(value : Int) -> Char {
  if value < 10 {
    Int::unsafe_to_char(value + b'0'.to_int())
  } else {
    Int::unsafe_to_char(value - 10 + b'a'.to_int())
  }
}

/// 计算 HMAC-SHA256 标签并以小写十六进制形式返回。
pub fn hmac_sha256_hex(key : Bytes, message : Bytes) -> String {
  to_hex(hmac_sha256(key, message))
}

/// 将字节编码为小写十六进制字符串。
pub fn to_hex(input : Bytes) -> String {
  let output = Buffer(size_hint=input.length() * 2)
  for byte in input {
    let value = byte.to_int()
    output.write_char_utf16le(hex_char((value >> 4) & 0x0f))
    output.write_char_utf16le(hex_char(value & 0x0f))
  }
  output.contents().to_unchecked_string()
}

fn sha256_digest_hex(input : Bytes) -> String {
  let digest = @sha256.Digest::new()
  for byte in input {
    digest.write(byte)
  }
  digest.check_sum()
}

fn sha256_digest(input : Bytes) -> Bytes {
  bytes_from_hex(sha256_digest_hex(input))
}

fn hex_nibble(ch : UInt16) -> Int {
  let code = ch.to_int()
  if code >= b'0'.to_int() && code <= b'9'.to_int() {
    code - b'0'.to_int()
  } else if code >= b'a'.to_int() && code <= b'f'.to_int() {
    code - b'a'.to_int() + 10
  } else if code >= b'A'.to_int() && code <= b'F'.to_int() {
    code - b'A'.to_int() + 10
  } else {
    abort("invalid hex character")
  }
}

fn bytes_from_hex(hex : String) -> Bytes {
  guard hex.length() % 2 == 0 else { abort("hex string must have even length") }
  Bytes::makei(hex.length() / 2, i => {
    let hi = hex_nibble(hex.unsafe_get(i * 2))
    let lo = hex_nibble(hex.unsafe_get(i * 2 + 1))
    ((hi << 4) | lo).to_byte()
  })
}
