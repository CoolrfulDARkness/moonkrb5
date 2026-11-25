///|
fn nibble_to_hex(n : Int32) -> Char {
  if n < 10 {
    Int32::unsafe_to_char(0x30 + n)
  } else {
    Int32::unsafe_to_char(0x61 + (n - 10))
  }
}

///|
fn hex_char_to_nibble(c : Int32) -> Int32 raise DerError {
  if c >= 0x30 && c <= 0x39 {
    c - 0x30
  } else if c >= 0x61 && c <= 0x66 {
    c - 0x61 + 10
  } else if c >= 0x41 && c <= 0x46 {
    c - 0x41 + 10
  } else {
    raise DerError::InvalidValue("invalid hex character code: \{c}")
  }
}

///|
/// Encode bytes as a lowercase hexadecimal string.
pub fn hex_encode(data : Bytes) -> String {
  let sb = StringBuilder()
  for i = 0; i < data.length(); i = i + 1 {
    let b = data[i].to_int()
    sb.write_char(nibble_to_hex((b >> 4) & 0x0F))
    sb.write_char(nibble_to_hex(b & 0x0F))
  }
  sb.to_string()
}

///|
/// Decode a hexadecimal string (ignoring ASCII whitespace) into `Bytes`.
pub fn hex_decode(hex : String) -> Bytes raise DerError {
  let nibbles : Array[Int32] = []
  for i = 0; i < hex.length(); i = i + 1 {
    let c = hex[i].to_int()
    if c == 0x20 || c == 0x0A || c == 0x0D || c == 0x09 {
      continue
    }
    nibbles.push(hex_char_to_nibble(c))
  }
  if nibbles.length() % 2 != 0 {
    raise DerError::InvalidValue("hex string has odd number of digits")
  }
  let out_len = nibbles.length() / 2
  Bytes::makei(out_len, fn(i) {
    ((nibbles[i * 2] << 4) | nibbles[i * 2 + 1]).to_byte()
  })
}
