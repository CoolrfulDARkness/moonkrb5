///|
fn rotl32(x : UInt32, n : Int32) -> UInt32 {
  (x << n) | (x >> (32 - n))
}

///|
/// Compress a single 64-byte block (already loaded into w[0..15]) into `h[0..4]`.
fn sha1_compress_w(h : FixedArray[UInt32], w : FixedArray[UInt32]) -> Unit {
  for i = 16; i < 80; i = i + 1 {
    w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
  }
  let mut a = h[0]
  let mut b = h[1]
  let mut c = h[2]
  let mut d = h[3]
  let mut e = h[4]
  for i = 0; i < 20; i = i + 1 {
    let f = d ^ (b & (c ^ d))
    let t = rotl32(a, 5) + f + e + 0x5A827999U + w[i]
    e = d
    d = c
    c = rotl32(b, 30)
    b = a
    a = t
  }
  for i = 20; i < 40; i = i + 1 {
    let f = b ^ c ^ d
    let t = rotl32(a, 5) + f + e + 0x6ED9EBA1U + w[i]
    e = d
    d = c
    c = rotl32(b, 30)
    b = a
    a = t
  }
  for i = 40; i < 60; i = i + 1 {
    let f = (b & c) | (d & (b | c))
    let t = rotl32(a, 5) + f + e + 0x8F1BBCDCU + w[i]
    e = d
    d = c
    c = rotl32(b, 30)
    b = a
    a = t
  }
  for i = 60; i < 80; i = i + 1 {
    let f = b ^ c ^ d
    let t = rotl32(a, 5) + f + e + 0xCA62C1D6U + w[i]
    e = d
    d = c
    c = rotl32(b, 30)
    b = a
    a = t
  }
  h[0] = h[0] + a
  h[1] = h[1] + b
  h[2] = h[2] + c
  h[3] = h[3] + d
  h[4] = h[4] + e
}

///|
fn sha1_load_block(
  w : FixedArray[UInt32],
  block : FixedArray[Byte],
  off : Int32,
) -> Unit {
  for i = 0; i < 16; i = i + 1 {
    let j = off + i * 4
    w[i] = (block[j].to_uint() << 24) |
      (block[j + 1].to_uint() << 16) |
      (block[j + 2].to_uint() << 8) |
      block[j + 3].to_uint()
  }
}

///|
fn sha1_init_state(h : FixedArray[UInt32]) -> Unit {
  h[0] = 0x67452301U
  h[1] = 0xEFCDAB89U
  h[2] = 0x98BADCFEU
  h[3] = 0x10325476U
  h[4] = 0xC3D2E1F0U
}

///|
fn sha1_finish_from_state(
  h : FixedArray[UInt32],
  w : FixedArray[UInt32],
  data : Bytes,
  prefix_bytes : UInt64,
) -> Unit {
  let len = data.length()
  let mut off = 0
  while len - off >= 64 {
    for i = 0; i < 16; i = i + 1 {
      w[i] = read_be_u32(data, off + i * 4)
    }
    sha1_compress_w(h, w)
    off = off + 64
  }
  let rem = len - off
  let tail = FixedArray::make(64, b'\x00')
  for i = 0; i < rem; i = i + 1 {
    tail[i] = data[off + i]
  }
  tail[rem] = b'\x80'
  if rem >= 56 {
    sha1_load_block(w, tail, 0)
    sha1_compress_w(h, w)
    for i = 0; i < 64; i = i + 1 {
      tail[i] = b'\x00'
    }
  }
  let total_bits : UInt64 = (prefix_bytes + len.to_uint64()) * 8UL
  write_be_u64(tail, 56, total_bits)
  sha1_load_block(w, tail, 0)
  sha1_compress_w(h, w)
}

///|
/// Compute the 20-byte SHA-1 digest of `data` (FIPS 180-4).
pub fn sha1(data : Bytes) -> Bytes {
  let h = FixedArray::make(5, 0U)
  let w = FixedArray::make(80, 0U)
  sha1_init_state(h)
  sha1_finish_from_state(h, w, data, 0UL)
  let out = FixedArray::make(20, b'\x00')
  for i = 0; i < 5; i = i + 1 {
    write_be_u32(out, i * 4, h[i])
  }
  fixed_to_bytes(out, 20)
}

///|
fn hmac_sha1_prepare_states(
  key : Bytes,
  ipad_state : FixedArray[UInt32],
  opad_state : FixedArray[UInt32],
  w : FixedArray[UInt32],
) -> Unit {
  let kbuf = FixedArray::make(64, b'\x00')
  if key.length() > 64 {
    let hk = sha1(key)
    for i = 0; i < 20; i = i + 1 {
      kbuf[i] = hk[i]
    }
  } else {
    for i = 0; i < key.length(); i = i + 1 {
      kbuf[i] = key[i]
    }
  }
  let pad = FixedArray::make(64, b'\x00')
  for i = 0; i < 64; i = i + 1 {
    pad[i] = (kbuf[i].to_int() ^ 0x36).to_byte()
  }
  sha1_init_state(ipad_state)
  sha1_load_block(w, pad, 0)
  sha1_compress_w(ipad_state, w)
  for i = 0; i < 64; i = i + 1 {
    pad[i] = (kbuf[i].to_int() ^ 0x5C).to_byte()
  }
  sha1_init_state(opad_state)
  sha1_load_block(w, pad, 0)
  sha1_compress_w(opad_state, w)
}

///|
/// Compute the 20-byte HMAC-SHA1 of `data` under `key` (RFC 2104).
pub fn hmac_sha1(key : Bytes, data : Bytes) -> Bytes {
  let ipad_state = FixedArray::make(5, 0U)
  let opad_state = FixedArray::make(5, 0U)
  let w = FixedArray::make(80, 0U)
  hmac_sha1_prepare_states(key, ipad_state, opad_state, w)
  sha1_finish_from_state(ipad_state, w, data, 64UL)
  // Outer hash over 20-byte inner digest (total 84 bytes = 672 bits)
  w[0] = ipad_state[0]
  w[1] = ipad_state[1]
  w[2] = ipad_state[2]
  w[3] = ipad_state[3]
  w[4] = ipad_state[4]
  w[5] = 0x80000000U
  for i = 6; i < 15; i = i + 1 {
    w[i] = 0U
  }
  w[15] = 672U
  sha1_compress_w(opad_state, w)
  let out = FixedArray::make(20, b'\x00')
  for i = 0; i < 5; i = i + 1 {
    write_be_u32(out, i * 4, opad_state[i])
  }
  fixed_to_bytes(out, 20)
}

///|
/// Compute PBKDF2-HMAC-SHA1 (RFC 2898) with zero-allocation inner loop.
pub fn pbkdf2_hmac_sha1(
  password : Bytes,
  salt : Bytes,
  iterations : Int32,
  dk_len : Int32,
) -> Bytes raise CryptoError {
  if iterations <= 0 {
    raise InvalidIterationCount
  }
  if dk_len <= 0 {
    raise InvalidInput("dk_len must be positive")
  }
  let ipad_base = FixedArray::make(5, 0U)
  let opad_base = FixedArray::make(5, 0U)
  let w = FixedArray::make(80, 0U)
  hmac_sha1_prepare_states(password, ipad_base, opad_base, w)
  let h = FixedArray::make(5, 0U)
  let u = FixedArray::make(5, 0U)
  let t = FixedArray::make(5, 0U)
  let blocks = (dk_len - 1) / 20 + 1
  let out = FixedArray::make(dk_len, b'\x00')
  let salt_len = salt.length()
  let salt_block = FixedArray::make(salt_len + 4, b'\x00')
  for i = 0; i < salt_len; i = i + 1 {
    salt_block[i] = salt[i]
  }
  let tmp20 = FixedArray::make(20, b'\x00')
  for blk = 1; blk <= blocks; blk = blk + 1 {
    write_be_u32(salt_block, salt_len, blk.reinterpret_as_uint())
    let salt_i = fixed_to_bytes(salt_block, salt_len + 4)
    // U_1 = HMAC(password, salt || INT_32_BE(blk))
    for k = 0; k < 5; k = k + 1 {
      h[k] = ipad_base[k]
    }
    sha1_finish_from_state(h, w, salt_i, 64UL)
    w[0] = h[0]
    w[1] = h[1]
    w[2] = h[2]
    w[3] = h[3]
    w[4] = h[4]
    w[5] = 0x80000000U
    for k = 6; k < 15; k = k + 1 {
      w[k] = 0U
    }
    w[15] = 672U
    for k = 0; k < 5; k = k + 1 {
      u[k] = opad_base[k]
    }
    sha1_compress_w(u, w)
    for k = 0; k < 5; k = k + 1 {
      t[k] = u[k]
    }
    // U_2 .. U_c (zero allocations!)
    for _iter = 1; _iter < iterations; _iter = _iter + 1 {
      // Inner: compress u (20 bytes) starting from ipad_base
      w[0] = u[0]
      w[1] = u[1]
      w[2] = u[2]
      w[3] = u[3]
      w[4] = u[4]
      w[5] = 0x80000000U
      w[6] = 0U
      w[7] = 0U
      w[8] = 0U
      w[9] = 0U
      w[10] = 0U
      w[11] = 0U
      w[12] = 0U
      w[13] = 0U
      w[14] = 0U
      w[15] = 672U
      h[0] = ipad_base[0]
      h[1] = ipad_base[1]
      h[2] = ipad_base[2]
      h[3] = ipad_base[3]
      h[4] = ipad_base[4]
      sha1_compress_w(h, w)
      // Outer: compress h (20 bytes) starting from opad_base
      w[0] = h[0]
      w[1] = h[1]
      w[2] = h[2]
      w[3] = h[3]
      w[4] = h[4]
      w[5] = 0x80000000U
      w[6] = 0U
      w[7] = 0U
      w[8] = 0U
      w[9] = 0U
      w[10] = 0U
      w[11] = 0U
      w[12] = 0U
      w[13] = 0U
      w[14] = 0U
      w[15] = 672U
      u[0] = opad_base[0]
      u[1] = opad_base[1]
      u[2] = opad_base[2]
      u[3] = opad_base[3]
      u[4] = opad_base[4]
      sha1_compress_w(u, w)
      t[0] = t[0] ^ u[0]
      t[1] = t[1] ^ u[1]
      t[2] = t[2] ^ u[2]
      t[3] = t[3] ^ u[3]
      t[4] = t[4] ^ u[4]
    }
    for k = 0; k < 5; k = k + 1 {
      write_be_u32(tmp20, k * 4, t[k])
    }
    let base_off = (blk - 1) * 20
    let take = if dk_len - base_off >= 20 { 20 } else { dk_len - base_off }
    for k = 0; k < take; k = k + 1 {
      out[base_off + k] = tmp20[k]
    }
  }
  fixed_to_bytes(out, dk_len)
}
