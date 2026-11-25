///|
let sha256_k : FixedArray[UInt32] = [
  0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
  0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
  0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
  0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
  0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
  0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
  0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
  0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
  0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
  0xc67178f2U,
]

///|
fn rotr32(x : UInt32, n : Int32) -> UInt32 {
  (x >> n) | (x << (32 - n))
}

///|
fn sha256_init_state(h : FixedArray[UInt32]) -> Unit {
  h[0] = 0x6a09e667U
  h[1] = 0xbb67ae85U
  h[2] = 0x3c6ef372U
  h[3] = 0xa54ff53aU
  h[4] = 0x510e527fU
  h[5] = 0x9b05688cU
  h[6] = 0x1f83d9abU
  h[7] = 0x5be0cd19U
}

///|
fn sha256_compress_w(h : FixedArray[UInt32], w : FixedArray[UInt32]) -> Unit {
  for i = 16; i < 64; i = i + 1 {
    let w15 = w[i - 15]
    let w2 = w[i - 2]
    let s0 = rotr32(w15, 7) ^ rotr32(w15, 18) ^ (w15 >> 3)
    let s1 = rotr32(w2, 17) ^ rotr32(w2, 19) ^ (w2 >> 10)
    w[i] = w[i - 16] + s0 + w[i - 7] + s1
  }
  let mut a = h[0]
  let mut b = h[1]
  let mut c = h[2]
  let mut d = h[3]
  let mut e = h[4]
  let mut f = h[5]
  let mut g = h[6]
  let mut hh = h[7]
  for i = 0; i < 64; i = i + 1 {
    let s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
    let ch = g ^ (e & (f ^ g))
    let t1 = hh + s1 + ch + sha256_k[i] + w[i]
    let s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
    let maj = (a & b) | (c & (a | b))
    let t2 = s0 + maj
    hh = g
    g = f
    f = e
    e = d + t1
    d = c
    c = b
    b = a
    a = t1 + t2
  }
  h[0] = h[0] + a
  h[1] = h[1] + b
  h[2] = h[2] + c
  h[3] = h[3] + d
  h[4] = h[4] + e
  h[5] = h[5] + f
  h[6] = h[6] + g
  h[7] = h[7] + hh
}

///|
fn sha256_load_block(
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
fn sha256_finish_from_state(
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
    sha256_compress_w(h, w)
    off = off + 64
  }
  let rem = len - off
  let tail = FixedArray::make(64, b'\x00')
  for i = 0; i < rem; i = i + 1 {
    tail[i] = data[off + i]
  }
  tail[rem] = b'\x80'
  if rem >= 56 {
    sha256_load_block(w, tail, 0)
    sha256_compress_w(h, w)
    for i = 0; i < 64; i = i + 1 {
      tail[i] = b'\x00'
    }
  }
  let total_bits : UInt64 = (prefix_bytes + len.to_uint64()) * 8UL
  write_be_u64(tail, 56, total_bits)
  sha256_load_block(w, tail, 0)
  sha256_compress_w(h, w)
}

///|
/// Compute the 32-byte SHA-256 digest of `data` (FIPS 180-4).
pub fn sha256(data : Bytes) -> Bytes {
  let h = FixedArray::make(8, 0U)
  let w = FixedArray::make(64, 0U)
  sha256_init_state(h)
  sha256_finish_from_state(h, w, data, 0UL)
  let out = FixedArray::make(32, b'\x00')
  for i = 0; i < 8; i = i + 1 {
    write_be_u32(out, i * 4, h[i])
  }
  fixed_to_bytes(out, 32)
}

///|
fn hmac_sha256_prepare_states(
  key : Bytes,
  ipad_state : FixedArray[UInt32],
  opad_state : FixedArray[UInt32],
  w : FixedArray[UInt32],
) -> Unit {
  let kbuf = FixedArray::make(64, b'\x00')
  if key.length() > 64 {
    let hk = sha256(key)
    for i = 0; i < 32; i = i + 1 {
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
  sha256_init_state(ipad_state)
  sha256_load_block(w, pad, 0)
  sha256_compress_w(ipad_state, w)
  for i = 0; i < 64; i = i + 1 {
    pad[i] = (kbuf[i].to_int() ^ 0x5C).to_byte()
  }
  sha256_init_state(opad_state)
  sha256_load_block(w, pad, 0)
  sha256_compress_w(opad_state, w)
}

///|
/// Compute the 32-byte HMAC-SHA256 of `data` under `key` (RFC 2104).
pub fn hmac_sha256(key : Bytes, data : Bytes) -> Bytes {
  let ipad_state = FixedArray::make(8, 0U)
  let opad_state = FixedArray::make(8, 0U)
  let w = FixedArray::make(64, 0U)
  hmac_sha256_prepare_states(key, ipad_state, opad_state, w)
  sha256_finish_from_state(ipad_state, w, data, 64UL)
  // Outer hash over 32-byte inner digest (total 96 bytes = 768 bits)
  for i = 0; i < 8; i = i + 1 {
    w[i] = ipad_state[i]
  }
  w[8] = 0x80000000U
  w[9] = 0U
  w[10] = 0U
  w[11] = 0U
  w[12] = 0U
  w[13] = 0U
  w[14] = 0U
  w[15] = 768U
  sha256_compress_w(opad_state, w)
  let out = FixedArray::make(32, b'\x00')
  for i = 0; i < 8; i = i + 1 {
    write_be_u32(out, i * 4, opad_state[i])
  }
  fixed_to_bytes(out, 32)
}

///|
/// Compute PBKDF2-HMAC-SHA256 (RFC 2898) with zero-allocation inner loop.
pub fn pbkdf2_hmac_sha256(
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
  let ipad_base = FixedArray::make(8, 0U)
  let opad_base = FixedArray::make(8, 0U)
  let w = FixedArray::make(64, 0U)
  hmac_sha256_prepare_states(password, ipad_base, opad_base, w)
  let h = FixedArray::make(8, 0U)
  let u = FixedArray::make(8, 0U)
  let t = FixedArray::make(8, 0U)
  let blocks = (dk_len - 1) / 32 + 1
  let out = FixedArray::make(dk_len, b'\x00')
  let salt_len = salt.length()
  let salt_block = FixedArray::make(salt_len + 4, b'\x00')
  for i = 0; i < salt_len; i = i + 1 {
    salt_block[i] = salt[i]
  }
  let tmp32 = FixedArray::make(32, b'\x00')
  for blk = 1; blk <= blocks; blk = blk + 1 {
    write_be_u32(salt_block, salt_len, blk.reinterpret_as_uint())
    let salt_i = fixed_to_bytes(salt_block, salt_len + 4)
    for k = 0; k < 8; k = k + 1 {
      h[k] = ipad_base[k]
    }
    sha256_finish_from_state(h, w, salt_i, 64UL)
    for k = 0; k < 8; k = k + 1 {
      w[k] = h[k]
      u[k] = opad_base[k]
    }
    w[8] = 0x80000000U
    w[9] = 0U
    w[10] = 0U
    w[11] = 0U
    w[12] = 0U
    w[13] = 0U
    w[14] = 0U
    w[15] = 768U
    sha256_compress_w(u, w)
    for k = 0; k < 8; k = k + 1 {
      t[k] = u[k]
    }
    for _iter = 1; _iter < iterations; _iter = _iter + 1 {
      w[0] = u[0]
      w[1] = u[1]
      w[2] = u[2]
      w[3] = u[3]
      w[4] = u[4]
      w[5] = u[5]
      w[6] = u[6]
      w[7] = u[7]
      w[8] = 0x80000000U
      w[9] = 0U
      w[10] = 0U
      w[11] = 0U
      w[12] = 0U
      w[13] = 0U
      w[14] = 0U
      w[15] = 768U
      h[0] = ipad_base[0]
      h[1] = ipad_base[1]
      h[2] = ipad_base[2]
      h[3] = ipad_base[3]
      h[4] = ipad_base[4]
      h[5] = ipad_base[5]
      h[6] = ipad_base[6]
      h[7] = ipad_base[7]
      sha256_compress_w(h, w)
      w[0] = h[0]
      w[1] = h[1]
      w[2] = h[2]
      w[3] = h[3]
      w[4] = h[4]
      w[5] = h[5]
      w[6] = h[6]
      w[7] = h[7]
      w[8] = 0x80000000U
      w[9] = 0U
      w[10] = 0U
      w[11] = 0U
      w[12] = 0U
      w[13] = 0U
      w[14] = 0U
      w[15] = 768U
      u[0] = opad_base[0]
      u[1] = opad_base[1]
      u[2] = opad_base[2]
      u[3] = opad_base[3]
      u[4] = opad_base[4]
      u[5] = opad_base[5]
      u[6] = opad_base[6]
      u[7] = opad_base[7]
      sha256_compress_w(u, w)
      t[0] = t[0] ^ u[0]
      t[1] = t[1] ^ u[1]
      t[2] = t[2] ^ u[2]
      t[3] = t[3] ^ u[3]
      t[4] = t[4] ^ u[4]
      t[5] = t[5] ^ u[5]
      t[6] = t[6] ^ u[6]
      t[7] = t[7] ^ u[7]
    }
    for k = 0; k < 8; k = k + 1 {
      write_be_u32(tmp32, k * 4, t[k])
    }
    let base_off = (blk - 1) * 32
    let take = if dk_len - base_off >= 32 { 32 } else { dk_len - base_off }
    for k = 0; k < take; k = k + 1 {
      out[base_off + k] = tmp32[k]
    }
  }
  fixed_to_bytes(out, dk_len)
}
