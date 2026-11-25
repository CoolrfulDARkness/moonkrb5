///|
fn gcd(a : Int32, b : Int32) -> Int32 {
  let mut x = a
  let mut y = b
  while y != 0 {
    let t = x % y
    x = y
    y = t
  }
  x
}

///|
/// RFC 3961 §5.1 n-fold operation: stretches or folds `input` to `out_bits` bits.
/// `out_bits` must be a positive multiple of 8; returns empty bytes if invalid.
pub fn n_fold(input : Bytes, out_bits : Int32) -> Bytes {
  let in_len = input.length()
  if out_bits <= 0 || out_bits % 8 != 0 {
    return Bytes::make(0, b'\x00')
  }
  let out_len = out_bits / 8
  if in_len == 0 {
    return Bytes::make(out_len, b'\x00')
  }
  let in_bits = in_len * 8
  let lcm_bytes = in_len / gcd(in_len, out_len) * out_len
  let acc = FixedArray::make(out_len, 0)
  let chunk = FixedArray::make(out_len, 0)
  let num_chunks = lcm_bytes / out_len
  for c = 0; c < num_chunks; c = c + 1 {
    let chunk_start = c * out_len
    for j = 0; j < out_len; j = j + 1 {
      let pos = chunk_start + j
      let rep = pos / in_len
      let off = pos % in_len
      // Right rotation of `input` by (13 * rep) bits:
      // byte at `off` in rotated input starts at bit `(off * 8 - 13 * rep) mod in_bits`
      let rot_bits = 13 * rep % in_bits
      let src_bit = (off * 8 - rot_bits + in_bits) % in_bits
      let src_byte = src_bit / 8
      let bit_off = src_bit % 8
      let b0 = input[src_byte].to_int()
      let b1 = input[(src_byte + 1) % in_len].to_int()
      chunk[j] = ((b0 << bit_off) | (b1 >> (8 - bit_off))) & 0xFF
    }
    // 1's-complement addition: acc = acc +_1 chunk
    let mut carry = 0
    for j = out_len - 1; j >= 0; j = j - 1 {
      let sum = acc[j] + chunk[j] + carry
      acc[j] = sum & 0xFF
      carry = sum >> 8
    }
    while carry != 0 {
      for j = out_len - 1; j >= 0; j = j - 1 {
        let sum = acc[j] + carry
        acc[j] = sum & 0xFF
        carry = sum >> 8
        if carry == 0 {
          break
        }
      }
    }
  }
  Bytes::makei(out_len, fn(i) { acc[i].to_byte() })
}

///|
/// RFC 3961 §5.1 `DR(Key, Constant)` for RFC 3962 AES encryption types.
pub fn derive_random(
  etype : Enctype,
  base_key : Bytes,
  constant : Bytes,
) -> Bytes raise CryptoError {
  match etype {
    Aes128CtsHmacSha1_96 | Aes256CtsHmacSha1_96 => ()
    Aes128CtsHmacSha256_128 | Aes256CtsHmacSha384_192 =>
      raise UnsupportedEnctype(etype.to_int())
  }
  let ksize = etype.key_size()
  if base_key.length() != ksize {
    raise InvalidKeyLength(expected=ksize, got=base_key.length())
  }
  if constant.length() == 0 {
    raise InvalidInput("constant must not be empty")
  }
  let aes = aes_expand_key(base_key)
  let folded = if constant.length() == 16 {
    constant
  } else {
    n_fold(constant, 128)
  }
  let cur = FixedArray::make(16, 0)
  for i = 0; i < 16; i = i + 1 {
    cur[i] = folded[i].to_int()
  }
  let nxt = FixedArray::make(16, 0)
  let out = FixedArray::make(ksize, b'\x00')
  let mut produced = 0
  while produced < ksize {
    aes_encrypt_block(aes, cur, nxt)
    let take = if produced + 16 <= ksize { 16 } else { ksize - produced }
    for i = 0; i < take; i = i + 1 {
      out[produced + i] = nxt[i].to_byte()
    }
    for i = 0; i < 16; i = i + 1 {
      cur[i] = nxt[i]
    }
    produced = produced + take
  }
  fixed_to_bytes(out, ksize)
}

///|
/// RFC 3961 §5.1 `DK(Key, Constant)` for RFC 3962 AES encryption types.
/// For AES, `random-to-key` is the identity function.
pub fn derive_key(
  etype : Enctype,
  base_key : Bytes,
  constant : Bytes,
) -> Bytes raise CryptoError {
  derive_random(etype, base_key, constant)
}

///|
/// RFC 8009 §3 SP 800-108 Counter Mode KDF-HMAC-SHA2.
/// Computes `k-truncate(HMAC(base_key, 0x00000001 || label || 0x00 || [context ||] be32(out_bits)))`.
pub fn kdf_hmac_sha2(
  etype : Enctype,
  base_key : Bytes,
  label : Bytes,
  context : Bytes?,
  out_bits : Int32,
) -> Bytes raise CryptoError {
  let max_bits = match etype {
    Aes128CtsHmacSha256_128 => 256
    Aes256CtsHmacSha384_192 => 384
    Aes128CtsHmacSha1_96 | Aes256CtsHmacSha1_96 =>
      raise UnsupportedEnctype(etype.to_int())
  }
  let ksize = etype.key_size()
  if base_key.length() != ksize {
    raise InvalidKeyLength(expected=ksize, got=base_key.length())
  }
  if out_bits <= 0 || out_bits % 8 != 0 || out_bits > max_bits {
    raise InvalidInput(
      "out_bits must be a positive multiple of 8 within hash output size",
    )
  }
  let label_len = label.length()
  let ctx_len = match context {
    Some(c) => c.length()
    None => 0
  }
  // 4 (counter=1) + label_len + 1 (0x00) + ctx_len + 4 (k = out_bits)
  let msg_len = 4 + label_len + 1 + ctx_len + 4
  let msg = FixedArray::make(msg_len, b'\x00')
  write_be_u32(msg, 0, 1U)
  for i = 0; i < label_len; i = i + 1 {
    msg[4 + i] = label[i]
  }
  msg[4 + label_len] = b'\x00'
  match context {
    Some(c) =>
      for i = 0; i < ctx_len; i = i + 1 {
        msg[5 + label_len + i] = c[i]
      }
    None => ()
  }
  write_be_u32(msg, 5 + label_len + ctx_len, out_bits.reinterpret_as_uint())
  let msg_bytes = fixed_to_bytes(msg, msg_len)
  let mac = match etype {
    Aes128CtsHmacSha256_128 => hmac_sha256(base_key, msg_bytes)
    Aes256CtsHmacSha384_192 => hmac_sha384(base_key, msg_bytes)
    _ => raise UnsupportedEnctype(etype.to_int())
  }
  bytes_slice(mac, 0, out_bits / 8)
}

///|
fn parse_s2k_iterations(
  etype : Enctype,
  s2kparams : Bytes?,
) -> Int32 raise CryptoError {
  match s2kparams {
    None =>
      match etype {
        Aes128CtsHmacSha1_96 | Aes256CtsHmacSha1_96 => 4096
        Aes128CtsHmacSha256_128 | Aes256CtsHmacSha384_192 => 32768
      }
    Some(params) => {
      if params.length() != 4 {
        raise InvalidS2kParams("s2kparams must be exactly 4 bytes")
      }
      let iter_u = read_be_u32(params, 0)
      // RFC 3962 §4: 0x00000000 means 2^32 iterations (unbounded DoS); enforce safe upper bound >= 50,000.
      if iter_u == 0U || iter_u > 10_000_000U {
        raise InvalidIterationCount
      }
      iter_u.reinterpret_as_int()
    }
  }
}

///|
/// RFC 3962 §4 and RFC 8009 §4 string-to-key function.
pub fn string_to_key(
  etype : Enctype,
  password : Bytes,
  salt : Bytes,
  s2kparams : Bytes?,
) -> Bytes raise CryptoError {
  let iter_count = parse_s2k_iterations(etype, s2kparams)
  let ksize = etype.key_size()
  let kerberos_label = b"kerberos"
  match etype {
    Aes128CtsHmacSha1_96 | Aes256CtsHmacSha1_96 => {
      let tkey = pbkdf2_hmac_sha1(password, salt, iter_count, ksize)
      derive_key(etype, tkey, kerberos_label)
    }
    Aes128CtsHmacSha256_128 => {
      let name_bytes = ascii_string_to_bytes(etype.name())
      let saltp = bytes_concat(bytes_concat(name_bytes, b"\x00"), salt)
      let tkey = pbkdf2_hmac_sha256(password, saltp, iter_count, 16)
      kdf_hmac_sha2(etype, tkey, kerberos_label, None, 128)
    }
    Aes256CtsHmacSha384_192 => {
      let name_bytes = ascii_string_to_bytes(etype.name())
      let saltp = bytes_concat(bytes_concat(name_bytes, b"\x00"), salt)
      let tkey = pbkdf2_hmac_sha384(password, saltp, iter_count, 32)
      kdf_hmac_sha2(etype, tkey, kerberos_label, None, 256)
    }
  }
}

///|
fn make_usage_constant(usage : Int32, tag : Byte) -> Bytes {
  let buf = FixedArray::make(5, b'\x00')
  write_be_u32(buf, 0, usage.reinterpret_as_uint())
  buf[4] = tag
  fixed_to_bytes(buf, 5)
}

///|
/// Kerberos 5 authenticated encryption (RFC 3962 Encrypt-and-MAC & RFC 8009 Encrypt-then-MAC).
pub fn encrypt(
  etype : Enctype,
  key : Bytes,
  usage : Int32,
  plaintext : Bytes,
  confounder : Bytes,
) -> Bytes raise CryptoError {
  let ksize = etype.key_size()
  if key.length() != ksize {
    raise InvalidKeyLength(expected=ksize, got=key.length())
  }
  if confounder.length() != 16 {
    raise InvalidConfounderLength(expected=16, got=confounder.length())
  }
  let zero_iv = Bytes::make(16, b'\x00')
  let plain_with_conf = bytes_concat(confounder, plaintext)
  let ke_label = make_usage_constant(usage, b'\xAA')
  let ki_label = make_usage_constant(usage, b'\x55')
  match etype {
    Aes128CtsHmacSha1_96 | Aes256CtsHmacSha1_96 => {
      // RFC 3961/3962 Simplified Profile: Encrypt-and-MAC over (confounder || plaintext)
      let ke = derive_key(etype, key, ke_label)
      let ki = derive_key(etype, key, ki_label)
      let c1 = aes_cts_encrypt(ke, zero_iv, plain_with_conf)
      let h1 = bytes_slice(hmac_sha1(ki, plain_with_conf), 0, 12)
      bytes_concat(c1, h1)
    }
    Aes128CtsHmacSha256_128 => {
      // RFC 8009: Encrypt-then-MAC over (IV || C)
      let ke = kdf_hmac_sha2(etype, key, ke_label, None, 128)
      let ki = kdf_hmac_sha2(etype, key, ki_label, None, 128)
      let c1 = aes_cts_encrypt(ke, zero_iv, plain_with_conf)
      let mac_input = bytes_concat(zero_iv, c1)
      let h1 = bytes_slice(hmac_sha256(ki, mac_input), 0, 16)
      bytes_concat(c1, h1)
    }
    Aes256CtsHmacSha384_192 => {
      // RFC 8009: Encrypt-then-MAC over (IV || C), Ki is 192 bits
      let ke = kdf_hmac_sha2(etype, key, ke_label, None, 256)
      let ki = kdf_hmac_sha2(etype, key, ki_label, None, 192)
      let c1 = aes_cts_encrypt(ke, zero_iv, plain_with_conf)
      let mac_input = bytes_concat(zero_iv, c1)
      let h1 = bytes_slice(hmac_sha384(ki, mac_input), 0, 24)
      bytes_concat(c1, h1)
    }
  }
}

///|
/// Kerberos 5 authenticated decryption (RFC 3962 & RFC 8009).
/// Always verifies MAC in constant time; raises `IntegrityCheckFailed` on mismatch.
pub fn decrypt(
  etype : Enctype,
  key : Bytes,
  usage : Int32,
  ciphertext : Bytes,
) -> Bytes raise CryptoError {
  let ksize = etype.key_size()
  if key.length() != ksize {
    raise InvalidKeyLength(expected=ksize, got=key.length())
  }
  let mac_len = etype.mac_size()
  let ct_len = ciphertext.length()
  if ct_len < 16 + mac_len {
    raise CiphertextTooShort
  }
  let zero_iv = Bytes::make(16, b'\x00')
  let c1_len = ct_len - mac_len
  let c1 = bytes_slice(ciphertext, 0, c1_len)
  let h1 = bytes_slice(ciphertext, c1_len, mac_len)
  let ke_label = make_usage_constant(usage, b'\xAA')
  let ki_label = make_usage_constant(usage, b'\x55')
  match etype {
    Aes128CtsHmacSha1_96 | Aes256CtsHmacSha1_96 => {
      let ke = derive_key(etype, key, ke_label)
      let ki = derive_key(etype, key, ki_label)
      let plain_with_conf = aes_cts_decrypt(ke, zero_iv, c1)
      let expected_h1 = bytes_slice(hmac_sha1(ki, plain_with_conf), 0, 12)
      if !ct_eq(h1, expected_h1) {
        raise IntegrityCheckFailed
      }
      bytes_slice(plain_with_conf, 16, plain_with_conf.length() - 16)
    }
    Aes128CtsHmacSha256_128 => {
      // RFC 8009: verify MAC before decrypting
      let ke = kdf_hmac_sha2(etype, key, ke_label, None, 128)
      let ki = kdf_hmac_sha2(etype, key, ki_label, None, 128)
      let mac_input = bytes_concat(zero_iv, c1)
      let expected_h1 = bytes_slice(hmac_sha256(ki, mac_input), 0, 16)
      if !ct_eq(h1, expected_h1) {
        raise IntegrityCheckFailed
      }
      let plain_with_conf = aes_cts_decrypt(ke, zero_iv, c1)
      bytes_slice(plain_with_conf, 16, plain_with_conf.length() - 16)
    }
    Aes256CtsHmacSha384_192 => {
      // RFC 8009: verify MAC before decrypting
      let ke = kdf_hmac_sha2(etype, key, ke_label, None, 256)
      let ki = kdf_hmac_sha2(etype, key, ki_label, None, 192)
      let mac_input = bytes_concat(zero_iv, c1)
      let expected_h1 = bytes_slice(hmac_sha384(ki, mac_input), 0, 24)
      if !ct_eq(h1, expected_h1) {
        raise IntegrityCheckFailed
      }
      let plain_with_conf = aes_cts_decrypt(ke, zero_iv, c1)
      bytes_slice(plain_with_conf, 16, plain_with_conf.length() - 16)
    }
  }
}

///|
/// Compute a Kerberos 5 keyed checksum (RFC 3962 §6 & RFC 8009 §6).
pub fn make_checksum(
  cksum_type : ChecksumType,
  key : Bytes,
  usage : Int32,
  data : Bytes,
) -> Bytes raise CryptoError {
  let kc_label = make_usage_constant(usage, b'\x99')
  match cksum_type {
    HmacSha1_96Aes128 => {
      if key.length() != 16 {
        raise InvalidKeyLength(expected=16, got=key.length())
      }
      let kc = derive_key(Aes128CtsHmacSha1_96, key, kc_label)
      bytes_slice(hmac_sha1(kc, data), 0, 12)
    }
    HmacSha1_96Aes256 => {
      if key.length() != 32 {
        raise InvalidKeyLength(expected=32, got=key.length())
      }
      let kc = derive_key(Aes256CtsHmacSha1_96, key, kc_label)
      bytes_slice(hmac_sha1(kc, data), 0, 12)
    }
    HmacSha256_128Aes128 => {
      if key.length() != 16 {
        raise InvalidKeyLength(expected=16, got=key.length())
      }
      let kc = kdf_hmac_sha2(Aes128CtsHmacSha256_128, key, kc_label, None, 128)
      bytes_slice(hmac_sha256(kc, data), 0, 16)
    }
    HmacSha384_192Aes256 => {
      if key.length() != 32 {
        raise InvalidKeyLength(expected=32, got=key.length())
      }
      let kc = kdf_hmac_sha2(Aes256CtsHmacSha384_192, key, kc_label, None, 192)
      bytes_slice(hmac_sha384(kc, data), 0, 24)
    }
  }
}

///|
/// Verify a Kerberos 5 keyed checksum in constant time.
pub fn verify_checksum(
  cksum_type : ChecksumType,
  key : Bytes,
  usage : Int32,
  data : Bytes,
  expected : Bytes,
) -> Bool raise CryptoError {
  let actual = make_checksum(cksum_type, key, usage, data)
  ct_eq(actual, expected)
}
