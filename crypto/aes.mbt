///|
let aes_sbox : FixedArray[Int32] = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
  0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
  0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5,
  0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
  0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e,
  0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
  0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef,
  0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
  0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
  0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
  0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
  0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e,
  0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
  0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55,
  0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
  0xb0, 0x54, 0xbb, 0x16,
]

///|
let aes_inv_sbox : FixedArray[Int32] = [
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3,
  0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44,
  0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c,
  0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
  0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68,
  0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
  0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8,
  0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13,
  0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce,
  0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
  0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
  0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2,
  0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33,
  0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51,
  0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53,
  0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
  0x55, 0x21, 0x0c, 0x7d,
]

///|
let aes_rcon : FixedArray[Int32] = [
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
]

///|
fn xtime(a : Int32) -> Int32 {
  let shifted = a << 1
  if (a & 0x80) != 0 {
    (shifted ^ 0x1b) & 0xFF
  } else {
    shifted & 0xFF
  }
}

///|
fn gmul(a : Int32, b : Int32) -> Int32 {
  let mut p = 0
  let mut aa = a
  let mut bb = b
  for _i = 0; _i < 8; _i = _i + 1 {
    if (bb & 1) != 0 {
      p = p ^ aa
    }
    aa = xtime(aa)
    bb = bb >> 1
  }
  p
}

///|
priv struct AesKey {
  nr : Int32
  rk : FixedArray[Int32]
}

///|
fn aes_expand_key(key : Bytes) -> AesKey raise CryptoError {
  let klen = key.length()
  if klen != 16 && klen != 32 {
    raise InvalidKeyLength(expected=16, got=klen)
  }
  let nk = klen / 4
  let nr = nk + 6
  let total_words = 4 * (nr + 1)
  let rk = FixedArray::make(total_words * 4, 0)
  for i = 0; i < klen; i = i + 1 {
    rk[i] = key[i].to_int()
  }
  let mut i = nk
  while i < total_words {
    let prev = (i - 1) * 4
    let mut t0 = rk[prev]
    let mut t1 = rk[prev + 1]
    let mut t2 = rk[prev + 2]
    let mut t3 = rk[prev + 3]
    if i % nk == 0 {
      let tmp = t0
      t0 = aes_sbox[t1] ^ aes_rcon[i / nk]
      t1 = aes_sbox[t2]
      t2 = aes_sbox[t3]
      t3 = aes_sbox[tmp]
    } else if nk > 6 && i % nk == 4 {
      t0 = aes_sbox[t0]
      t1 = aes_sbox[t1]
      t2 = aes_sbox[t2]
      t3 = aes_sbox[t3]
    }
    let src = (i - nk) * 4
    let dst = i * 4
    rk[dst] = rk[src] ^ t0
    rk[dst + 1] = rk[src + 1] ^ t1
    rk[dst + 2] = rk[src + 2] ^ t2
    rk[dst + 3] = rk[src + 3] ^ t3
    i = i + 1
  }
  { nr, rk, }
}

///|
fn aes_encrypt_block(
  aes : AesKey,
  in_blk : FixedArray[Int32],
  out_blk : FixedArray[Int32],
) -> Unit {
  let rk = aes.rk
  let s = FixedArray::make(16, 0)
  for i = 0; i < 16; i = i + 1 {
    s[i] = in_blk[i] ^ rk[i]
  }
  let t = FixedArray::make(16, 0)
  for round = 1; round < aes.nr; round = round + 1 {
    // SubBytes + ShiftRows
    t[0] = aes_sbox[s[0]]
    t[1] = aes_sbox[s[5]]
    t[2] = aes_sbox[s[10]]
    t[3] = aes_sbox[s[15]]
    t[4] = aes_sbox[s[4]]
    t[5] = aes_sbox[s[9]]
    t[6] = aes_sbox[s[14]]
    t[7] = aes_sbox[s[3]]
    t[8] = aes_sbox[s[8]]
    t[9] = aes_sbox[s[13]]
    t[10] = aes_sbox[s[2]]
    t[11] = aes_sbox[s[7]]
    t[12] = aes_sbox[s[12]]
    t[13] = aes_sbox[s[1]]
    t[14] = aes_sbox[s[6]]
    t[15] = aes_sbox[s[11]]
    // MixColumns + AddRoundKey
    let rbase = round * 16
    for c = 0; c < 4; c = c + 1 {
      let idx = c * 4
      let a0 = t[idx]
      let a1 = t[idx + 1]
      let a2 = t[idx + 2]
      let a3 = t[idx + 3]
      let xor_all = a0 ^ a1 ^ a2 ^ a3
      s[idx] = a0 ^ xtime(a0 ^ a1) ^ xor_all ^ rk[rbase + idx]
      s[idx + 1] = a1 ^ xtime(a1 ^ a2) ^ xor_all ^ rk[rbase + idx + 1]
      s[idx + 2] = a2 ^ xtime(a2 ^ a3) ^ xor_all ^ rk[rbase + idx + 2]
      s[idx + 3] = a3 ^ xtime(a3 ^ a0) ^ xor_all ^ rk[rbase + idx + 3]
    }
  }
  // Final round (SubBytes + ShiftRows + AddRoundKey)
  let rbase = aes.nr * 16
  out_blk[0] = aes_sbox[s[0]] ^ rk[rbase]
  out_blk[1] = aes_sbox[s[5]] ^ rk[rbase + 1]
  out_blk[2] = aes_sbox[s[10]] ^ rk[rbase + 2]
  out_blk[3] = aes_sbox[s[15]] ^ rk[rbase + 3]
  out_blk[4] = aes_sbox[s[4]] ^ rk[rbase + 4]
  out_blk[5] = aes_sbox[s[9]] ^ rk[rbase + 5]
  out_blk[6] = aes_sbox[s[14]] ^ rk[rbase + 6]
  out_blk[7] = aes_sbox[s[3]] ^ rk[rbase + 7]
  out_blk[8] = aes_sbox[s[8]] ^ rk[rbase + 8]
  out_blk[9] = aes_sbox[s[13]] ^ rk[rbase + 9]
  out_blk[10] = aes_sbox[s[2]] ^ rk[rbase + 10]
  out_blk[11] = aes_sbox[s[7]] ^ rk[rbase + 11]
  out_blk[12] = aes_sbox[s[12]] ^ rk[rbase + 12]
  out_blk[13] = aes_sbox[s[1]] ^ rk[rbase + 13]
  out_blk[14] = aes_sbox[s[6]] ^ rk[rbase + 14]
  out_blk[15] = aes_sbox[s[11]] ^ rk[rbase + 15]
}

///|
fn aes_decrypt_block(
  aes : AesKey,
  in_blk : FixedArray[Int32],
  out_blk : FixedArray[Int32],
) -> Unit {
  let rk = aes.rk
  let s = FixedArray::make(16, 0)
  let last_base = aes.nr * 16
  for i = 0; i < 16; i = i + 1 {
    s[i] = in_blk[i] ^ rk[last_base + i]
  }
  let t = FixedArray::make(16, 0)
  for round = aes.nr - 1; round >= 1; round = round - 1 {
    // InvShiftRows + InvSubBytes
    t[0] = aes_inv_sbox[s[0]]
    t[1] = aes_inv_sbox[s[13]]
    t[2] = aes_inv_sbox[s[10]]
    t[3] = aes_inv_sbox[s[7]]
    t[4] = aes_inv_sbox[s[4]]
    t[5] = aes_inv_sbox[s[1]]
    t[6] = aes_inv_sbox[s[14]]
    t[7] = aes_inv_sbox[s[11]]
    t[8] = aes_inv_sbox[s[8]]
    t[9] = aes_inv_sbox[s[5]]
    t[10] = aes_inv_sbox[s[2]]
    t[11] = aes_inv_sbox[s[15]]
    t[12] = aes_inv_sbox[s[12]]
    t[13] = aes_inv_sbox[s[9]]
    t[14] = aes_inv_sbox[s[6]]
    t[15] = aes_inv_sbox[s[3]]
    // AddRoundKey
    let rbase = round * 16
    for i = 0; i < 16; i = i + 1 {
      t[i] = t[i] ^ rk[rbase + i]
    }
    // InvMixColumns
    for c = 0; c < 4; c = c + 1 {
      let idx = c * 4
      let a0 = t[idx]
      let a1 = t[idx + 1]
      let a2 = t[idx + 2]
      let a3 = t[idx + 3]
      s[idx] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9)
      s[idx + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13)
      s[idx + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11)
      s[idx + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14)
    }
  }
  // Final InvShiftRows + InvSubBytes + AddRoundKey(0)
  out_blk[0] = aes_inv_sbox[s[0]] ^ rk[0]
  out_blk[1] = aes_inv_sbox[s[13]] ^ rk[1]
  out_blk[2] = aes_inv_sbox[s[10]] ^ rk[2]
  out_blk[3] = aes_inv_sbox[s[7]] ^ rk[3]
  out_blk[4] = aes_inv_sbox[s[4]] ^ rk[4]
  out_blk[5] = aes_inv_sbox[s[1]] ^ rk[5]
  out_blk[6] = aes_inv_sbox[s[14]] ^ rk[6]
  out_blk[7] = aes_inv_sbox[s[11]] ^ rk[7]
  out_blk[8] = aes_inv_sbox[s[8]] ^ rk[8]
  out_blk[9] = aes_inv_sbox[s[5]] ^ rk[9]
  out_blk[10] = aes_inv_sbox[s[2]] ^ rk[10]
  out_blk[11] = aes_inv_sbox[s[15]] ^ rk[11]
  out_blk[12] = aes_inv_sbox[s[12]] ^ rk[12]
  out_blk[13] = aes_inv_sbox[s[9]] ^ rk[13]
  out_blk[14] = aes_inv_sbox[s[6]] ^ rk[14]
  out_blk[15] = aes_inv_sbox[s[3]] ^ rk[15]
}

///|
/// AES-CBC-CS3 (Ciphertext Stealing) encryption per RFC 3962 / RFC 8009.
/// Requires `key` of 16 or 32 bytes, `iv` of 16 bytes, and `plaintext` of >= 16 bytes.
pub fn aes_cts_encrypt(
  key : Bytes,
  iv : Bytes,
  plaintext : Bytes,
) -> Bytes raise CryptoError {
  let aes = aes_expand_key(key)
  if iv.length() != 16 {
    raise InvalidInput("IV must be 16 bytes")
  }
  let len = plaintext.length()
  if len < 16 {
    raise InvalidInput("AES-CTS plaintext must be at least 16 bytes")
  }
  let prev = FixedArray::make(16, 0)
  for i = 0; i < 16; i = i + 1 {
    prev[i] = iv[i].to_int()
  }
  let inp = FixedArray::make(16, 0)
  let out_blk = FixedArray::make(16, 0)
  let out = FixedArray::make(len, b'\x00')
  if len == 16 {
    for i = 0; i < 16; i = i + 1 {
      inp[i] = plaintext[i].to_int() ^ prev[i]
    }
    aes_encrypt_block(aes, inp, out_blk)
    for i = 0; i < 16; i = i + 1 {
      out[i] = out_blk[i].to_byte()
    }
    return fixed_to_bytes(out, 16)
  }
  // len > 16: express len = 16 * k + r with k >= 1 and 1 <= r <= 16
  let k = (len - 1) / 16
  let r = len - 16 * k
  // Normal CBC for blocks 0 .. k-2
  for blk = 0; blk < k - 1; blk = blk + 1 {
    let base = blk * 16
    for i = 0; i < 16; i = i + 1 {
      inp[i] = plaintext[base + i].to_int() ^ prev[i]
    }
    aes_encrypt_block(aes, inp, out_blk)
    for i = 0; i < 16; i = i + 1 {
      prev[i] = out_blk[i]
      out[base + i] = out_blk[i].to_byte()
    }
  }
  // Second-to-last block P_{k-1}
  let penult_base = (k - 1) * 16
  for i = 0; i < 16; i = i + 1 {
    inp[i] = plaintext[penult_base + i].to_int() ^ prev[i]
  }
  let e_penult = FixedArray::make(16, 0)
  aes_encrypt_block(aes, inp, e_penult)
  // Last block P_k (r bytes, zero-padded to 16) XOR e_penult
  let last_base = k * 16
  for i = 0; i < r; i = i + 1 {
    inp[i] = plaintext[last_base + i].to_int() ^ e_penult[i]
  }
  for i = r; i < 16; i = i + 1 {
    inp[i] = e_penult[i]
  }
  aes_encrypt_block(aes, inp, out_blk)
  // Output: C_{k-1} = out_blk (16 bytes), C_k = e_penult[0..r]
  for i = 0; i < 16; i = i + 1 {
    out[penult_base + i] = out_blk[i].to_byte()
  }
  for i = 0; i < r; i = i + 1 {
    out[last_base + i] = e_penult[i].to_byte()
  }
  fixed_to_bytes(out, len)
}

///|
/// AES-CBC-CS3 (Ciphertext Stealing) decryption per RFC 3962 / RFC 8009.
/// Requires `key` of 16 or 32 bytes, `iv` of 16 bytes, and `ciphertext` of >= 16 bytes.
pub fn aes_cts_decrypt(
  key : Bytes,
  iv : Bytes,
  ciphertext : Bytes,
) -> Bytes raise CryptoError {
  let aes = aes_expand_key(key)
  if iv.length() != 16 {
    raise InvalidInput("IV must be 16 bytes")
  }
  let len = ciphertext.length()
  if len < 16 {
    raise InvalidInput("AES-CTS ciphertext must be at least 16 bytes")
  }
  let prev = FixedArray::make(16, 0)
  for i = 0; i < 16; i = i + 1 {
    prev[i] = iv[i].to_int()
  }
  let inp = FixedArray::make(16, 0)
  let out_blk = FixedArray::make(16, 0)
  let out = FixedArray::make(len, b'\x00')
  if len == 16 {
    for i = 0; i < 16; i = i + 1 {
      inp[i] = ciphertext[i].to_int()
    }
    aes_decrypt_block(aes, inp, out_blk)
    for i = 0; i < 16; i = i + 1 {
      out[i] = (out_blk[i] ^ prev[i]).to_byte()
    }
    return fixed_to_bytes(out, 16)
  }
  let k = (len - 1) / 16
  let r = len - 16 * k
  // Normal CBC decrypt for blocks 0 .. k-2
  for blk = 0; blk < k - 1; blk = blk + 1 {
    let base = blk * 16
    for i = 0; i < 16; i = i + 1 {
      inp[i] = ciphertext[base + i].to_int()
    }
    aes_decrypt_block(aes, inp, out_blk)
    for i = 0; i < 16; i = i + 1 {
      out[base + i] = (out_blk[i] ^ prev[i]).to_byte()
      prev[i] = inp[i]
    }
  }
  // Decrypt penultimate ciphertext block C_{k-1} -> D_n = P_k_padded XOR E_{k-1}
  let penult_base = (k - 1) * 16
  let last_base = k * 16
  for i = 0; i < 16; i = i + 1 {
    inp[i] = ciphertext[penult_base + i].to_int()
  }
  let dn = FixedArray::make(16, 0)
  aes_decrypt_block(aes, inp, dn)
  // Recover P_k (r bytes) and reconstruct full E_{k-1}
  let e_penult = FixedArray::make(16, 0)
  for i = 0; i < r; i = i + 1 {
    let c_last_i = ciphertext[last_base + i].to_int()
    out[last_base + i] = (dn[i] ^ c_last_i).to_byte()
    e_penult[i] = c_last_i
  }
  for i = r; i < 16; i = i + 1 {
    e_penult[i] = dn[i]
  }
  // Decrypt E_{k-1} and XOR with prev to get P_{k-1}
  aes_decrypt_block(aes, e_penult, out_blk)
  for i = 0; i < 16; i = i + 1 {
    out[penult_base + i] = (out_blk[i] ^ prev[i]).to_byte()
  }
  fixed_to_bytes(out, len)
}
