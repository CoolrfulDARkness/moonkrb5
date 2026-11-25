///|
let sha384_k : FixedArray[UInt64] = [
  0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
  0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
  0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
  0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
  0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
  0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
  0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
  0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
  0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
  0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
  0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
  0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
  0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
  0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
  0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
  0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
  0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
  0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
  0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
  0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL,
]

///|
fn rotr64(x : UInt64, n : Int32) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

///|
fn read_be_u64(b : Bytes, off : Int32) -> UInt64 {
  (b[off].to_uint64() << 56) |
  (b[off + 1].to_uint64() << 48) |
  (b[off + 2].to_uint64() << 40) |
  (b[off + 3].to_uint64() << 32) |
  (b[off + 4].to_uint64() << 24) |
  (b[off + 5].to_uint64() << 16) |
  (b[off + 6].to_uint64() << 8) |
  b[off + 7].to_uint64()
}

///|
fn sha384_init_state(h : FixedArray[UInt64]) -> Unit {
  h[0] = 0xcbbb9d5dc1059ed8UL
  h[1] = 0x629a292a367cd507UL
  h[2] = 0x9159015a3070dd17UL
  h[3] = 0x152fecd8f70e5939UL
  h[4] = 0x67332667ffc00b31UL
  h[5] = 0x8eb44a8768581511UL
  h[6] = 0xdb0c2e0d64f98fa7UL
  h[7] = 0x47b5481dbefa4fa4UL
}

///|
fn sha384_compress_w(h : FixedArray[UInt64], w : FixedArray[UInt64]) -> Unit {
  for i = 16; i < 80; i = i + 1 {
    let w15 = w[i - 15]
    let w2 = w[i - 2]
    let s0 = rotr64(w15, 1) ^ rotr64(w15, 8) ^ (w15 >> 7)
    let s1 = rotr64(w2, 19) ^ rotr64(w2, 61) ^ (w2 >> 6)
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
  for i = 0; i < 80; i = i + 1 {
    let s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)
    let ch = g ^ (e & (f ^ g))
    let t1 = hh + s1 + ch + sha384_k[i] + w[i]
    let s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)
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
fn sha384_load_block(
  w : FixedArray[UInt64],
  block : FixedArray[Byte],
  off : Int32,
) -> Unit {
  for i = 0; i < 16; i = i + 1 {
    let j = off + i * 8
    w[i] = (block[j].to_uint64() << 56) |
      (block[j + 1].to_uint64() << 48) |
      (block[j + 2].to_uint64() << 40) |
      (block[j + 3].to_uint64() << 32) |
      (block[j + 4].to_uint64() << 24) |
      (block[j + 5].to_uint64() << 16) |
      (block[j + 6].to_uint64() << 8) |
      block[j + 7].to_uint64()
  }
}

///|
fn sha384_finish_from_state(
  h : FixedArray[UInt64],
  w : FixedArray[UInt64],
  data : Bytes,
  prefix_bytes : UInt64,
) -> Unit {
  let len = data.length()
  let mut off = 0
  while len - off >= 128 {
    for i = 0; i < 16; i = i + 1 {
      w[i] = read_be_u64(data, off + i * 8)
    }
    sha384_compress_w(h, w)
    off = off + 128
  }
  let rem = len - off
  let tail = FixedArray::make(128, b'\x00')
  for i = 0; i < rem; i = i + 1 {
    tail[i] = data[off + i]
  }
  tail[rem] = b'\x80'
  if rem >= 112 {
    sha384_load_block(w, tail, 0)
    sha384_compress_w(h, w)
    for i = 0; i < 128; i = i + 1 {
      tail[i] = b'\x00'
    }
  }
  let total_bits : UInt64 = (prefix_bytes + len.to_uint64()) * 8UL
  // Upper 64 bits of 128-bit length are zero (tail[112..119] = 0)
  write_be_u64(tail, 120, total_bits)
  sha384_load_block(w, tail, 0)
  sha384_compress_w(h, w)
}

///|
/// Compute the 48-byte SHA-384 digest of `data` (FIPS 180-4).
pub fn sha384(data : Bytes) -> Bytes {
  let h = FixedArray::make(8, 0UL)
  let w = FixedArray::make(80, 0UL)
  sha384_init_state(h)
  sha384_finish_from_state(h, w, data, 0UL)
  let out = FixedArray::make(48, b'\x00')
  for i = 0; i < 6; i = i + 1 {
    write_be_u64(out, i * 8, h[i])
  }
  fixed_to_bytes(out, 48)
}

///|
fn hmac_sha384_prepare_states(
  key : Bytes,
  ipad_state : FixedArray[UInt64],
  opad_state : FixedArray[UInt64],
  w : FixedArray[UInt64],
) -> Unit {
  let kbuf = FixedArray::make(128, b'\x00')
  if key.length() > 128 {
    let hk = sha384(key)
    for i = 0; i < 48; i = i + 1 {
      kbuf[i] = hk[i]
    }
  } else {
    for i = 0; i < key.length(); i = i + 1 {
      kbuf[i] = key[i]
    }
  }
  let pad = FixedArray::make(128, b'\x00')
  for i = 0; i < 128; i = i + 1 {
    pad[i] = (kbuf[i].to_int() ^ 0x36).to_byte()
  }
  sha384_init_state(ipad_state)
  sha384_load_block(w, pad, 0)
  sha384_compress_w(ipad_state, w)
  for i = 0; i < 128; i = i + 1 {
    pad[i] = (kbuf[i].to_int() ^ 0x5C).to_byte()
  }
  sha384_init_state(opad_state)
  sha384_load_block(w, pad, 0)
  sha384_compress_w(opad_state, w)
}

///|
/// Compute the 48-byte HMAC-SHA384 of `data` under `key` (RFC 2104).
pub fn hmac_sha384(key : Bytes, data : Bytes) -> Bytes {
  let ipad_state = FixedArray::make(8, 0UL)
  let opad_state = FixedArray::make(8, 0UL)
  let w = FixedArray::make(80, 0UL)
  hmac_sha384_prepare_states(key, ipad_state, opad_state, w)
  sha384_finish_from_state(ipad_state, w, data, 128UL)
  // Outer hash over 48-byte inner digest (total 176 bytes = 1408 bits)
  for i = 0; i < 6; i = i + 1 {
    w[i] = ipad_state[i]
  }
  w[6] = 0x8000000000000000UL
  for i = 7; i < 15; i = i + 1 {
    w[i] = 0UL
  }
  w[15] = 1408UL
  sha384_compress_w(opad_state, w)
  let out = FixedArray::make(48, b'\x00')
  for i = 0; i < 6; i = i + 1 {
    write_be_u64(out, i * 8, opad_state[i])
  }
  fixed_to_bytes(out, 48)
}

///|
/// Compute PBKDF2-HMAC-SHA384 (RFC 2898) with zero-allocation inner loop.
pub fn pbkdf2_hmac_sha384(
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
  let ipad_base = FixedArray::make(8, 0UL)
  let opad_base = FixedArray::make(8, 0UL)
  let w = FixedArray::make(80, 0UL)
  hmac_sha384_prepare_states(password, ipad_base, opad_base, w)
  let h = FixedArray::make(8, 0UL)
  let u = FixedArray::make(8, 0UL)
  let t = FixedArray::make(6, 0UL)
  let blocks = (dk_len - 1) / 48 + 1
  let out = FixedArray::make(dk_len, b'\x00')
  let salt_len = salt.length()
  let salt_block = FixedArray::make(salt_len + 4, b'\x00')
  for i = 0; i < salt_len; i = i + 1 {
    salt_block[i] = salt[i]
  }
  let tmp48 = FixedArray::make(48, b'\x00')
  for blk = 1; blk <= blocks; blk = blk + 1 {
    write_be_u32(salt_block, salt_len, blk.reinterpret_as_uint())
    let salt_i = fixed_to_bytes(salt_block, salt_len + 4)
    for k = 0; k < 8; k = k + 1 {
      h[k] = ipad_base[k]
    }
    sha384_finish_from_state(h, w, salt_i, 128UL)
    for k = 0; k < 6; k = k + 1 {
      w[k] = h[k]
    }
    w[6] = 0x8000000000000000UL
    for k = 7; k < 15; k = k + 1 {
      w[k] = 0UL
    }
    w[15] = 1408UL
    for k = 0; k < 8; k = k + 1 {
      u[k] = opad_base[k]
    }
    sha384_compress_w(u, w)
    for k = 0; k < 6; k = k + 1 {
      t[k] = u[k]
    }
    for _iter = 1; _iter < iterations; _iter = _iter + 1 {
      w[0] = u[0]
      w[1] = u[1]
      w[2] = u[2]
      w[3] = u[3]
      w[4] = u[4]
      w[5] = u[5]
      w[6] = 0x8000000000000000UL
      w[7] = 0UL
      w[8] = 0UL
      w[9] = 0UL
      w[10] = 0UL
      w[11] = 0UL
      w[12] = 0UL
      w[13] = 0UL
      w[14] = 0UL
      w[15] = 1408UL
      h[0] = ipad_base[0]
      h[1] = ipad_base[1]
      h[2] = ipad_base[2]
      h[3] = ipad_base[3]
      h[4] = ipad_base[4]
      h[5] = ipad_base[5]
      h[6] = ipad_base[6]
      h[7] = ipad_base[7]
      sha384_compress_w(h, w)
      w[0] = h[0]
      w[1] = h[1]
      w[2] = h[2]
      w[3] = h[3]
      w[4] = h[4]
      w[5] = h[5]
      w[6] = 0x8000000000000000UL
      w[7] = 0UL
      w[8] = 0UL
      w[9] = 0UL
      w[10] = 0UL
      w[11] = 0UL
      w[12] = 0UL
      w[13] = 0UL
      w[14] = 0UL
      w[15] = 1408UL
      u[0] = opad_base[0]
      u[1] = opad_base[1]
      u[2] = opad_base[2]
      u[3] = opad_base[3]
      u[4] = opad_base[4]
      u[5] = opad_base[5]
      u[6] = opad_base[6]
      u[7] = opad_base[7]
      sha384_compress_w(u, w)
      t[0] = t[0] ^ u[0]
      t[1] = t[1] ^ u[1]
      t[2] = t[2] ^ u[2]
      t[3] = t[3] ^ u[3]
      t[4] = t[4] ^ u[4]
      t[5] = t[5] ^ u[5]
    }
    for k = 0; k < 6; k = k + 1 {
      write_be_u64(tmp48, k * 8, t[k])
    }
    let base_off = (blk - 1) * 48
    let take = if dk_len - base_off >= 48 { 48 } else { dk_len - base_off }
    for k = 0; k < take; k = k + 1 {
      out[base_off + k] = tmp48[k]
    }
  }
  fixed_to_bytes(out, dk_len)
}
