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
