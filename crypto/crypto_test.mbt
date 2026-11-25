///|
fn hex_nibble(c : Int32) -> Int32 {
  if c >= 48 && c <= 57 {
    c - 48
  } else if c >= 97 && c <= 102 {
    c - 97 + 10
  } else if c >= 65 && c <= 70 {
    c - 65 + 10
  } else {
    -1
  }
}

///|
fn from_hex(s : String) -> Bytes {
  let buf : Array[Byte] = []
  let mut hi = -1
  for i = 0; i < s.length(); i = i + 1 {
    let v = hex_nibble(s.code_unit_at(i).to_int())
    if v >= 0 {
      if hi < 0 {
        hi = v
      } else {
        buf.push(((hi << 4) | v).to_byte())
        hi = -1
      }
    }
  }
  Bytes::makei(buf.length(), fn(i) { buf[i] })
}

///|
fn u32_be_bytes(v : Int32) -> Bytes {
  let b0 = ((v >> 24) & 0xFF).to_byte()
  let b1 = ((v >> 16) & 0xFF).to_byte()
  let b2 = ((v >> 8) & 0xFF).to_byte()
  let b3 = (v & 0xFF).to_byte()
  Bytes::from_array([b0, b1, b2, b3])
}

///|
fn flip_bit(data : Bytes, byte_idx : Int32, bit_mask : Int32) -> Bytes {
  Bytes::makei(data.length(), fn(i) {
    if i == byte_idx {
      (data[i].to_int() ^ bit_mask).to_byte()
    } else {
      data[i]
    }
  })
}

///|
test "hash and hmac primitives (FIPS 180-4 / RFC 2104)" {
  // SHA-1("abc")
  assert_eq(
    @crypto.sha1(b"abc"),
    from_hex("a9993e364706816aba3e25717850c26c9cd0d89d"),
  )
  // SHA-1("")
  assert_eq(
    @crypto.sha1(b""),
    from_hex("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
  )
  // SHA-256("abc")
  assert_eq(
    @crypto.sha256(b"abc"),
    from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
  )
  // SHA-256("")
  assert_eq(
    @crypto.sha256(b""),
    from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
  )
  // SHA-384("abc")
  assert_eq(
    @crypto.sha384(b"abc"),
    from_hex(
      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    ),
  )
  // SHA-384("")
  assert_eq(
    @crypto.sha384(b""),
    from_hex(
      "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    ),
  )
  // RFC 2202 HMAC-SHA1 Test Case 1 & Test Case 6 (key > 64 bytes)
  assert_eq(
    @crypto.hmac_sha1(
      from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
      b"Hi There",
    ),
    from_hex("b617318655057264e28bc0b6fb378c8ef146be00"),
  )
  assert_eq(
    @crypto.hmac_sha1(
      Bytes::make(80, b'\xaa'),
      b"Test Using Larger Than Block-Size Key - Hash Key First",
    ),
    from_hex("aa4ae5e15272d00e95705637ce8a3b55ed402112"),
  )
  // RFC 4231 HMAC-SHA256 & HMAC-SHA384 Test Case 2 ("Jefe" / "what do ya want for nothing?")
  assert_eq(
    @crypto.hmac_sha256(b"Jefe", b"what do ya want for nothing?"),
    from_hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
  )
  assert_eq(
    @crypto.hmac_sha384(b"Jefe", b"what do ya want for nothing?"),
    from_hex(
      "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
    ),
  )
  // RFC 4231 Test Case 6 (key length 131 > 128 block size)
  assert_eq(
    @crypto.hmac_sha384(
      Bytes::make(131, b'\xaa'),
      b"Test Using Larger Than Block-Size Key - Hash Key First",
    ),
    from_hex(
      "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
    ),
  )
}

///|
test "RFC 3961 Appendix A.1 n-fold all 11 official test vectors" {
  assert_eq(@crypto.n_fold(b"012345", 64), from_hex("be072631276b1955"))
  assert_eq(@crypto.n_fold(b"password", 56), from_hex("78a07b6caf85fa"))
  assert_eq(
    @crypto.n_fold(b"Rough Consensus, and Running Code", 64),
    from_hex("bb6ed30870b7f0e0"),
  )
  assert_eq(
    @crypto.n_fold(b"password", 168),
    from_hex("59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e"),
  )
  assert_eq(
    @crypto.n_fold(b"MASSACHVSETTS INSTITVTE OF TECHNOLOGY", 192),
    from_hex("db3b0d8f0b061e603282b308a50841229ad798fab9540c1b"),
  )
  assert_eq(
    @crypto.n_fold(b"Q", 168),
    from_hex("518a54a2 15a8452a 518a54a2 15a8452a 518a54a2 15"),
  )
  assert_eq(
    @crypto.n_fold(b"ba", 168),
    from_hex("fb25d531 ae897449 9f52fd92 ea9857c4 ba24cf29 7e"),
  )
  assert_eq(@crypto.n_fold(b"kerberos", 64), from_hex("6b657262 65726f73"))
  assert_eq(
    @crypto.n_fold(b"kerberos", 128),
    from_hex("6b657262 65726f73 7b9b5b2b 93132b93"),
  )
  assert_eq(
    @crypto.n_fold(b"kerberos", 168),
    from_hex("8372c236 344e5f15 50cd0747 e15d62ca 7a5a3bce a4"),
  )
  assert_eq(
    @crypto.n_fold(b"kerberos", 256),
    from_hex(
      "6b657262 65726f73 7b9b5b2b 93132b93 5c9bdcda d95c9899 c4cae4de e6d6cae4",
    ),
  )
}

///|
test "RFC 3962 Appendix B PBKDF2 + DR/DK + AES128/AES256 string_to_key all vectors" {
  // Vector 1: iter=1, password="password", salt="ATHENA.MIT.EDUraeburn"
  let p1 = b"password"
  let s1 = b"ATHENA.MIT.EDUraeburn"
  let pb1_128 = from_hex("cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15")
  let k1_128 = from_hex("42 26 3c 6e 89 f4 fc 28 b8 df 68 ee 09 79 9f 15")
  let pb1_256 = from_hex(
    "cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15 0a d1 f7 a0 4b b9 f3 a3 33 ec c0 e2 e1 f7 08 37",
  )
  let k1_256 = from_hex(
    "fe 69 7b 52 bc 0d 3c e1 44 32 ba 03 6a 92 e6 5b bb 52 28 09 90 a2 fa 27 88 39 98 d7 2a f3 01 61",
  )
  assert_eq(@crypto.pbkdf2_hmac_sha1(p1, s1, 1, 16), pb1_128)
  assert_eq(@crypto.pbkdf2_hmac_sha1(p1, s1, 1, 32), pb1_256)
  assert_eq(
    @crypto.derive_random(@crypto.Aes128CtsHmacSha1_96, pb1_128, b"kerberos"),
    k1_128,
  )
  assert_eq(
    @crypto.derive_key(@crypto.Aes256CtsHmacSha1_96, pb1_256, b"kerberos"),
    k1_256,
  )
  assert_eq(
    @crypto.string_to_key(
      @crypto.Aes128CtsHmacSha1_96,
      p1,
      s1,
      Some(u32_be_bytes(1)),
    ),
    k1_128,
  )
  assert_eq(
    @crypto.string_to_key(
      @crypto.Aes256CtsHmacSha1_96,
      p1,
      s1,
      Some(u32_be_bytes(1)),
    ),
    k1_256,
  )

  // Vector 2: iter=2
  let pb2_128 = from_hex("01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d")
  let k2_128 = from_hex("c6 51 bf 29 e2 30 0a c2 7f a4 69 d6 93 bd da 13")
  let pb2_256 = from_hex(
    "01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d a0 53 78 b9 32 44 ec 8f 48 a9 9e 61 ad 79 9d 86",
  )
  let k2_256 = from_hex(
    "a2 e1 6d 16 b3 60 69 c1 35 d5 e9 d2 e2 5f 89 61 02 68 56 18 b9 59 14 b4 67 c6 76 22 22 58 24 ff",
  )
  assert_eq(@crypto.pbkdf2_hmac_sha1(p1, s1, 2, 16), pb2_128)
  assert_eq(@crypto.pbkdf2_hmac_sha1(p1, s1, 2, 32), pb2_256)
  assert_eq(
    @crypto.string_to_key(
      @crypto.Aes128CtsHmacSha1_96,
      p1,
      s1,
      Some(u32_be_bytes(2)),
    ),
    k2_128,
  )
  assert_eq(
    @crypto.string_to_key(
      @crypto.Aes256CtsHmacSha1_96,
      p1,
      s1,
      Some(u32_be_bytes(2)),
    ),
    k2_256,
  )

  // Vector 3: iter=1200
  let pb3_128 = from_hex("5c 08 eb 61 fd f7 1e 4e 4e c3 cf 6b a1 f5 51 2b")
  let k3_128 = from_hex("4c 01 cd 46 d6 32 d0 1e 6d be 23 0a 01 ed 64 2a")
  let pb3_256 = from_hex(
    "5c 08 eb 61 fd f7 1e 4e 4e c3 cf 6b a1 f5 51 2b a7 e5 2d db c5 e5 14 2f 70 8a 31 e2 e6 2b 1e 13",
  )
  let k3_256 = from_hex(
    "55 a6 ac 74 0a d1 7b 48 46 94 10 51 e1 e8 b0 a7 54 8d 93 b0 ab 30 a8 bc 3f f1 62 80 38 2b 8c 2a",
  )
  assert_eq(@crypto.pbkdf2_hmac_sha1(p1, s1, 1200, 16), pb3_128)
  assert_eq(@crypto.pbkdf2_hmac_sha1(p1, s1, 1200, 32), pb3_256)
  assert_eq(
    @crypto.string_to_key(
      @crypto.Aes128CtsHmacSha1_96,
      p1,
      s1,
      Some(u32_be_bytes(1200)),
    ),
    k3_128,
  )
  assert_eq(
    @crypto.string_to_key(
      @crypto.Aes256CtsHmacSha1_96,
      p1,
      s1,
      Some(u32_be_bytes(1200)),
    ),
    k3_256,
  )

  // Vector 4: iter=5, salt=0x1234567878563412
  let s4 = from_hex("1234567878563412")
  assert_eq(
    @crypto.pbkdf2_hmac_sha1(p1, s4, 5, 16),
    from_hex("d1 da a7 86 15 f2 87 e6 a1 c8 b1 20 d7 06 2a 49"),
  )
  assert_eq(
    @crypto.string_to_key(
      @crypto.Aes128CtsHmacSha1_96,
      p1,
      s4,
      Some(u32_be_bytes(5)),
    ),
    from_hex("e9 b2 3d 52 27 37 47 dd 5c 35 cb 55 be 61 9d 8e"),
  )
  assert_eq(
    @crypto.pbkdf2_hmac_sha1(p1, s4, 5, 32),
    from_hex(
      "d1 da a7 86 15 f2 87 e6 a1 c8 b1 20 d7 06 2a 49 3f 98 d2 03 e6 be 49 a6 ad f4 fa 57 4b 6e 64 ee",
    ),
  )
  assert_eq(
    @crypto.string_to_key(
      @crypto.Aes256CtsHmacSha1_96,
      p1,
      s4,
      Some(u32_be_bytes(5)),
    ),
    from_hex(
      "97 a4 e7 86 be 20 d8 1a 38 2d 5e bc 96 d5 90 9c ab cd ad c8 7c a4 8f 57 45 04 15 9f 16 c3 6e 31",
    ),
  )

  // Vector 5: iter=1200, 64 'X's
  let p64 = Bytes::make(64, b'X')
  let s64 = b"pass phrase equals block size"
  assert_eq(
    @crypto.pbkdf2_hmac_sha1(p64, s64, 1200, 16),
    from_hex("13 9c 30 c0 96 6b c3 2b a5 5f db f2 12 53 0a c9"),
  )
  assert_eq(
    @crypto.string_to_key(
      @crypto.Aes128CtsHmacSha1_96,
      p64,
      s64,
      Some(u32_be_bytes(1200)),
    ),
    from_hex("59 d1 bb 78 9a 82 8b 1a a5 4e f9 c2 88 3f 69 ed"),
  )
  assert_eq(
    @crypto.pbkdf2_hmac_sha1(p64, s64, 1200, 32),
    from_hex(
      "13 9c 30 c0 96 6b c3 2b a5 5f db f2 12 53 0a c9 c5 ec 59 f1 a4 52 f5 cc 9a d9 40 fe a0 59 8e d1",
    ),
  )
  assert_eq(
    @crypto.string_to_key(
      @crypto.Aes256CtsHmacSha1_96,
      p64,
      s64,
      Some(u32_be_bytes(1200)),
    ),
    from_hex(
      "89 ad ee 36 08 db 8b c7 1f 1b fb fe 45 94 86 b0 56 18 b7 0c ba e2 20 92 53 4e 56 c5 53 ba 4b 34",
    ),
  )

  // Vector 6: iter=1200, 65 'X's (exceeds SHA-1 block size)
  let p65 = Bytes::make(65, b'X')
  let s65 = b"pass phrase exceeds block size"
  assert_eq(
    @crypto.pbkdf2_hmac_sha1(p65, s65, 1200, 16),
    from_hex("9c ca d6 d4 68 77 0c d5 1b 10 e6 a6 87 21 be 61"),
  )
  assert_eq(
    @crypto.string_to_key(
      @crypto.Aes128CtsHmacSha1_96,
      p65,
      s65,
      Some(u32_be_bytes(1200)),
    ),
    from_hex("cb 80 05 dc 5f 90 17 9a 7f 02 10 4c 00 18 75 1d"),
  )
  assert_eq(
    @crypto.pbkdf2_hmac_sha1(p65, s65, 1200, 32),
    from_hex(
      "9c ca d6 d4 68 77 0c d5 1b 10 e6 a6 87 21 be 61 1a 8b 4d 28 26 01 db 3b 36 be 92 46 91 5e c8 2a",
    ),
  )
  assert_eq(
    @crypto.string_to_key(
      @crypto.Aes256CtsHmacSha1_96,
      p65,
      s65,
      Some(u32_be_bytes(1200)),
    ),
    from_hex(
      "d7 8c 5c 9c b8 72 a8 c9 da d4 69 7f 0b b5 b2 d2 14 96 c8 2b eb 2c ae da 21 12 fc ee a0 57 40 1b",
    ),
  )

  // Vector 7: iter=50, UTF-8 g-clef (0xf09d849e), salt="EXAMPLE.COMpianist"
  let p_clef = from_hex("f09d849e")
  let s_clef = b"EXAMPLE.COMpianist"
  assert_eq(
    @crypto.pbkdf2_hmac_sha1(p_clef, s_clef, 50, 16),
    from_hex("6b 9c f2 6d 45 45 5a 43 a5 b8 bb 27 6a 40 3b 39"),
  )
  assert_eq(
    @crypto.string_to_key(
      @crypto.Aes128CtsHmacSha1_96,
      p_clef,
      s_clef,
      Some(u32_be_bytes(50)),
    ),
    from_hex("f1 49 c1 f2 e1 54 a7 34 52 d4 3e 7f e6 2a 56 e5"),
  )
  assert_eq(
    @crypto.pbkdf2_hmac_sha1(p_clef, s_clef, 50, 32),
    from_hex(
      "6b 9c f2 6d 45 45 5a 43 a5 b8 bb 27 6a 40 3b 39 e7 fe 37 a0 c4 1e 02 c2 81 ff 30 69 e1 e9 4f 52",
    ),
  )
  assert_eq(
    @crypto.string_to_key(
      @crypto.Aes256CtsHmacSha1_96,
      p_clef,
      s_clef,
      Some(u32_be_bytes(50)),
    ),
    from_hex(
      "4b 6d 98 39 f8 44 06 df 1f 09 cc 16 6d b4 b8 3c 57 18 48 b7 84 a3 d6 bd c3 46 58 9a 3e 39 3f 9e",
    ),
  )

  // Default s2kparams (None => iter=4096) matches explicit 4096
  assert_eq(
    @crypto.string_to_key(@crypto.Aes128CtsHmacSha1_96, p1, s1, None),
    @crypto.string_to_key(
      @crypto.Aes128CtsHmacSha1_96,
      p1,
      s1,
      Some(u32_be_bytes(4096)),
    ),
  )
  assert_eq(
    @crypto.string_to_key(@crypto.Aes256CtsHmacSha1_96, p1, s1, None),
    @crypto.string_to_key(
      @crypto.Aes256CtsHmacSha1_96,
      p1,
      s1,
      Some(u32_be_bytes(4096)),
    ),
  )
}

///|
test "RFC 3962 Appendix B AES-128-CTS all 6 official vectors (17B, 31B, 32B, 47B, 48B, 64B)" {
  let key = from_hex("63 68 69 63 6b 65 6e 20 74 65 72 69 79 61 6b 69")
  let iv = Bytes::make(16, b'\x00')

  // 17 bytes
  let pt17 = from_hex("49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65 20")
  let ct17 = from_hex("c6 35 35 68 f2 bf 8c b4 d8 a5 80 36 2d a7 ff 7f 97")
  assert_eq(@crypto.aes_cts_encrypt(key, iv, pt17), ct17)
  assert_eq(@crypto.aes_cts_decrypt(key, iv, ct17), pt17)

  // 31 bytes
  let pt31 = from_hex(
    "49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65 20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20",
  )
  let ct31 = from_hex(
    "fc 00 78 3e 0e fd b2 c1 d4 45 d4 c8 ef f7 ed 22 97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5",
  )
  assert_eq(@crypto.aes_cts_encrypt(key, iv, pt31), ct31)
  assert_eq(@crypto.aes_cts_decrypt(key, iv, ct31), pt31)

  // 32 bytes
  let pt32 = from_hex(
    "49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65 20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43",
  )
  let ct32 = from_hex(
    "39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8 97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84",
  )
  assert_eq(@crypto.aes_cts_encrypt(key, iv, pt32), ct32)
  assert_eq(@crypto.aes_cts_decrypt(key, iv, ct32), pt32)

  // 47 bytes
  let pt47 = from_hex(
    "49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65 20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43 68 69 63 6b 65 6e 2c 20 70 6c 65 61 73 65 2c",
  )
  let ct47 = from_hex(
    "97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84 b3 ff fd 94 0c 16 a1 8c 1b 55 49 d2 f8 38 02 9e 39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5",
  )
  assert_eq(@crypto.aes_cts_encrypt(key, iv, pt47), ct47)
  assert_eq(@crypto.aes_cts_decrypt(key, iv, ct47), pt47)

  // 48 bytes
  let pt48 = from_hex(
    "49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65 20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43 68 69 63 6b 65 6e 2c 20 70 6c 65 61 73 65 2c 20",
  )
  let ct48 = from_hex(
    "97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84 9d ad 8b bb 96 c4 cd c0 3b c1 03 e1 a1 94 bb d8 39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8",
  )
  assert_eq(@crypto.aes_cts_encrypt(key, iv, pt48), ct48)
  assert_eq(@crypto.aes_cts_decrypt(key, iv, ct48), pt48)

  // 64 bytes
  let pt64 = from_hex(
    "49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65 20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43 68 69 63 6b 65 6e 2c 20 70 6c 65 61 73 65 2c 20 61 6e 64 20 77 6f 6e 74 6f 6e 20 73 6f 75 70 2e",
  )
  let ct64 = from_hex(
    "97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84 39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8 48 07 ef e8 36 ee 89 a5 26 73 0d bc 2f 7b c8 40 9d ad 8b bb 96 c4 cd c0 3b c1 03 e1 a1 94 bb d8",
  )
  assert_eq(@crypto.aes_cts_encrypt(key, iv, pt64), ct64)
  assert_eq(@crypto.aes_cts_decrypt(key, iv, ct64), pt64)

  // Single 16-byte block matches first CBC block
  let pt16 = from_hex("49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65")
  let ct16 = from_hex("97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84")
  assert_eq(@crypto.aes_cts_encrypt(key, iv, pt16), ct16)
  assert_eq(@crypto.aes_cts_decrypt(key, iv, ct16), pt16)

  // < 16 bytes raises InvalidInput
  let short_res : Result[Bytes, @crypto.CryptoError] = Ok(
    @crypto.aes_cts_encrypt(key, iv, b"too short"),
  ) catch {
    e => Err(e)
  }
  assert_true(short_res is Err(InvalidInput(_)))
}

///|
test "RFC 8009 Appendix A String-to-Key (iter=32768) for AES128-SHA256 & AES256-SHA384" {
  // Salt = random 16-byte valid UTF-8 sequence | "ATHENA.MIT.EDUraeburn"
  let salt = from_hex(
    "10 DF 9D D7 83 E5 BC 8A CE A1 73 0E 74 35 5F 61 41 54 48 45 4E 41 2E 4D 49 54 2E 45 44 55 72 61 65 62 75 72 6E",
  )
  let pass = b"password"
  let key128 = @crypto.string_to_key(
    @crypto.Aes128CtsHmacSha256_128,
    pass,
    salt,
    None,
  )
  assert_eq(key128, from_hex("08 9B CA 48 B1 05 EA 6E A7 7C A5 D2 F3 9D C5 E7"))
  let key256 = @crypto.string_to_key(
    @crypto.Aes256CtsHmacSha384_192,
    pass,
    salt,
    None,
  )
  assert_eq(
    key256,
    from_hex(
      "45 BD 80 6D BF 6A 83 3A 9C FF C1 C9 45 89 A2 22 36 7A 79 BC 21 C4 13 71 89 06 E9 F5 78 A7 84 67",
    ),
  )
}

///|
test "RFC 8009 Appendix A Key Derivation (Kc/Ke/Ki), Encrypt/Decrypt, Checksum, PRF all vectors" {
  // --- aes128-cts-hmac-sha256-128 ---
  let base128 = from_hex("37 05 D9 60 80 C1 77 28 A0 E8 00 EA B6 E0 D2 3C")
  let kc128_exp = from_hex("B3 1A 01 8A 48 F5 47 76 F4 03 E9 A3 96 32 5D C3")
  let ke128_exp = from_hex("9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E")
  let ki128_exp = from_hex("9F DA 0E 56 AB 2D 85 E1 56 9A 68 86 96 C2 6A 6C")
  assert_eq(
    @crypto.kdf_hmac_sha2(
      @crypto.Aes128CtsHmacSha256_128,
      base128,
      from_hex("0000000299"),
      None,
      128,
    ),
    kc128_exp,
  )
  assert_eq(
    @crypto.kdf_hmac_sha2(
      @crypto.Aes128CtsHmacSha256_128,
      base128,
      from_hex("00000002AA"),
      None,
      128,
    ),
    ke128_exp,
  )
  assert_eq(
    @crypto.kdf_hmac_sha2(
      @crypto.Aes128CtsHmacSha256_128,
      base128,
      from_hex("0000000255"),
      None,
      128,
    ),
    ki128_exp,
  )

  // Sample 1: empty plaintext
  let c128_0 = @crypto.encrypt(
    @crypto.Aes128CtsHmacSha256_128,
    base128,
    @crypto.KU_TICKET,
    b"",
    from_hex("7E 58 95 EA F2 67 24 35 BA D8 17 F5 45 A3 71 48"),
  )
  assert_eq(
    c128_0,
    from_hex(
      "EF 85 FB 89 0B B8 47 2F 4D AB 20 39 4D CA 78 1D AD 87 7E DA 39 D5 0C 87 0C 0D 5A 0A 8E 48 C7 18",
    ),
  )
  assert_eq(
    @crypto.decrypt(
      @crypto.Aes128CtsHmacSha256_128,
      base128,
      @crypto.KU_TICKET,
      c128_0,
    ),
    b"",
  )

  // Sample 2: 6 bytes (< block size)
  let pt6 = from_hex("00 01 02 03 04 05")
  let c128_6 = @crypto.encrypt(
    @crypto.Aes128CtsHmacSha256_128,
    base128,
    2,
    pt6,
    from_hex("7B CA 28 5E 2F D4 13 0F B5 5B 1A 5C 83 BC 5B 24"),
  )
  assert_eq(
    c128_6,
    from_hex(
      "84 D7 F3 07 54 ED 98 7B AB 0B F3 50 6B EB 09 CF B5 54 02 CE F7 E6 87 7C E9 9E 24 7E 52 D1 6E D4 42 1D FD F8 97 6C",
    ),
  )
  assert_eq(
    @crypto.decrypt(@crypto.Aes128CtsHmacSha256_128, base128, 2, c128_6),
    pt6,
  )

  // Sample 3: 16 bytes (== block size)
  let pt16 = from_hex("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F")
  let c128_16 = @crypto.encrypt(
    @crypto.Aes128CtsHmacSha256_128,
    base128,
    2,
    pt16,
    from_hex("56 AB 21 71 3F F6 2C 0A 14 57 20 0F 6F A9 94 8F"),
  )
  assert_eq(
    c128_16,
    from_hex(
      "35 17 D6 40 F5 0D DC 8A D3 62 87 22 B3 56 9D 2A E0 74 93 FA 82 63 25 40 80 EA 65 C1 00 8E 8F C2 95 FB 48 52 E7 D8 3E 1E 7C 48 C3 7E EB E6 B0 D3",
    ),
  )
  assert_eq(
    @crypto.decrypt(@crypto.Aes128CtsHmacSha256_128, base128, 2, c128_16),
    pt16,
  )

  // Sample 4: 21 bytes (> block size)
  let pt21 = from_hex(
    "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14",
  )
  let c128_21 = @crypto.encrypt(
    @crypto.Aes128CtsHmacSha256_128,
    base128,
    2,
    pt21,
    from_hex("A7 A4 E2 9A 47 28 CE 10 66 4F B6 4E 49 AD 3F AC"),
  )
  assert_eq(
    c128_21,
    from_hex(
      "72 0F 73 B1 8D 98 59 CD 6C CB 43 46 11 5C D3 36 C7 0F 58 ED C0 C4 43 7C 55 73 54 4C 31 C8 13 BC E1 E6 D0 72 C1 86 B3 9A 41 3C 2F 92 CA 9B 83 34 A2 87 FF CB FC",
    ),
  )
  assert_eq(
    @crypto.decrypt(@crypto.Aes128CtsHmacSha256_128, base128, 2, c128_21),
    pt21,
  )

  // Sample checksum: hmac-sha256-128-aes128
  let ck128 = @crypto.make_checksum(
    @crypto.HmacSha256_128Aes128,
    base128,
    2,
    pt21,
  )
  assert_eq(ck128, from_hex("D7 83 67 18 66 43 D6 7B 41 1C BA 91 39 FC 1D EE"))
  assert_true(
    @crypto.verify_checksum(
      @crypto.HmacSha256_128Aes128,
      base128,
      2,
      pt21,
      ck128,
    ),
  )
  assert_false(
    @crypto.verify_checksum(
      @crypto.HmacSha256_128Aes128,
      base128,
      2,
      pt21,
      flip_bit(ck128, 0, 1),
    ),
  )

  // Sample PRF: aes128-cts-hmac-sha256-128
  assert_eq(
    @crypto.kdf_hmac_sha2(
      @crypto.Aes128CtsHmacSha256_128,
      base128,
      b"prf",
      Some(b"test"),
      256,
    ),
    from_hex(
      "9D 18 86 16 F6 38 52 FE 86 91 5B B8 40 B4 A8 86 FF 3E 6B B0 F8 19 B4 9B 89 33 93 D3 93 85 42 95",
    ),
  )

  // --- aes256-cts-hmac-sha384-192 ---
  let base256 = from_hex(
    "6D 40 4D 37 FA F7 9F 9D F0 D3 35 68 D3 20 66 98 00 EB 48 36 47 2E A8 A0 26 D1 6B 71 82 46 0C 52",
  )
  let kc256_exp = from_hex(
    "EF 57 18 BE 86 CC 84 96 3D 8B BB 50 31 E9 F5 C4 BA 41 F2 8F AF 69 E7 3D",
  )
  let ke256_exp = from_hex(
    "56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7 A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49",
  )
  let ki256_exp = from_hex(
    "69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F",
  )
  assert_eq(
    @crypto.kdf_hmac_sha2(
      @crypto.Aes256CtsHmacSha384_192,
      base256,
      from_hex("0000000299"),
      None,
      192,
    ),
    kc256_exp,
  )
  assert_eq(
    @crypto.kdf_hmac_sha2(
      @crypto.Aes256CtsHmacSha384_192,
      base256,
      from_hex("00000002AA"),
      None,
      256,
    ),
    ke256_exp,
  )
  assert_eq(
    @crypto.kdf_hmac_sha2(
      @crypto.Aes256CtsHmacSha384_192,
      base256,
      from_hex("0000000255"),
      None,
      192,
    ),
    ki256_exp,
  )

  // Sample 1: empty plaintext
  let c256_0 = @crypto.encrypt(
    @crypto.Aes256CtsHmacSha384_192,
    base256,
    2,
    b"",
    from_hex("F7 64 E9 FA 15 C2 76 47 8B 2C 7D 0C 4E 5F 58 E4"),
  )
  assert_eq(
    c256_0,
    from_hex(
      "41 F5 3F A5 BF E7 02 6D 91 FA F9 BE 95 91 95 A0 58 70 72 73 A9 6A 40 F0 A0 19 60 62 1A C6 12 74 8B 9B BF BE 7E B4 CE 3C",
    ),
  )
  assert_eq(
    @crypto.decrypt(@crypto.Aes256CtsHmacSha384_192, base256, 2, c256_0),
    b"",
  )

  // Sample 2: 6 bytes
  let c256_6 = @crypto.encrypt(
    @crypto.Aes256CtsHmacSha384_192,
    base256,
    2,
    pt6,
    from_hex("B8 0D 32 51 C1 F6 47 14 94 25 6F FE 71 2D 0B 9A"),
  )
  assert_eq(
    c256_6,
    from_hex(
      "4E D7 B3 7C 2B CA C8 F7 4F 23 C1 CF 07 E6 2B C7 B7 5F B3 F6 37 B9 F5 59 C7 F6 64 F6 9E AB 7B 60 92 23 75 26 EA 0D 1F 61 CB 20 D6 9D 10 F2",
    ),
  )
  assert_eq(
    @crypto.decrypt(@crypto.Aes256CtsHmacSha384_192, base256, 2, c256_6),
    pt6,
  )

  // Sample 3: 16 bytes
  let c256_16 = @crypto.encrypt(
    @crypto.Aes256CtsHmacSha384_192,
    base256,
    2,
    pt16,
    from_hex("53 BF 8A 0D 10 52 65 D4 E2 76 42 86 24 CE 5E 63"),
  )
  assert_eq(
    c256_16,
    from_hex(
      "BC 47 FF EC 79 98 EB 91 E8 11 5C F8 D1 9D AC 4B BB E2 E1 63 E8 7D D3 7F 49 BE CA 92 02 77 64 F6 8C F5 1F 14 D7 98 C2 27 3F 35 DF 57 4D 1F 93 2E 40 C4 FF 25 5B 36 A2 66",
    ),
  )
  assert_eq(
    @crypto.decrypt(@crypto.Aes256CtsHmacSha384_192, base256, 2, c256_16),
    pt16,
  )

  // Sample 4: 21 bytes
  let c256_21 = @crypto.encrypt(
    @crypto.Aes256CtsHmacSha384_192,
    base256,
    2,
    pt21,
    from_hex("76 3E 65 36 7E 86 4F 02 F5 51 53 C7 E3 B5 8A F1"),
  )
  assert_eq(
    c256_21,
    from_hex(
      "40 01 3E 2D F5 8E 87 51 95 7D 28 78 BC D2 D6 FE 10 1C CF D5 56 CB 1E AE 79 DB 3C 3E E8 64 29 F2 B2 A6 02 AC 86 FE F6 EC B6 47 D6 29 5F AE 07 7A 1F EB 51 75 08 D2 C1 6B 41 92 E0 1F 62",
    ),
  )
  assert_eq(
    @crypto.decrypt(@crypto.Aes256CtsHmacSha384_192, base256, 2, c256_21),
    pt21,
  )

  // Sample checksum: hmac-sha384-192-aes256
  let ck256 = @crypto.make_checksum(
    @crypto.HmacSha384_192Aes256,
    base256,
    2,
    pt21,
  )
  assert_eq(
    ck256,
    from_hex(
      "45 EE 79 15 67 EE FC A3 7F 4A C1 E0 22 2D E8 0D 43 C3 BF A0 66 99 67 2A",
    ),
  )
  assert_true(
    @crypto.verify_checksum(
      @crypto.HmacSha384_192Aes256,
      base256,
      2,
      pt21,
      ck256,
    ),
  )

  // Sample PRF: aes256-cts-hmac-sha384-192
  assert_eq(
    @crypto.kdf_hmac_sha2(
      @crypto.Aes256CtsHmacSha384_192,
      base256,
      b"prf",
      Some(b"test"),
      384,
    ),
    from_hex(
      "98 01 F6 9A 36 8C 2B F6 75 E5 95 21 E1 77 D9 A0 7F 67 EF E1 CF DE 8D 3C 8D 6F 6A 02 56 E3 B1 7D B3 C1 B6 2A D1 B8 55 33 60 D1 73 67 EB 15 14 D2",
    ),
  )
}

///|
test "all 4 enctypes round-trip, tamper rejection, wrong usage, truncation, checksums" {
  let rng = @crypto.DeterministicRng::new(b"moonkrb5-test-seed")
  let enctypes : Array[@crypto.Enctype] = [
    @crypto.Aes128CtsHmacSha1_96,
    @crypto.Aes256CtsHmacSha1_96,
    @crypto.Aes128CtsHmacSha256_128,
    @crypto.Aes256CtsHmacSha384_192,
  ]
  let lengths : Array[Int32] = [0, 1, 15, 16, 17, 31, 32, 33, 64, 100]
  for i = 0; i < enctypes.length(); i = i + 1 {
    let et = enctypes[i]
    let key = rng.next_bytes(et.key_size())
    let cksum_type = et.default_checksum_type()
    assert_eq(cksum_type.mac_size(), et.mac_size())
    for j = 0; j < lengths.length(); j = j + 1 {
      let pt = rng.next_bytes(lengths[j])
      let conf = rng.next_bytes(et.confounder_size())
      let ct = @crypto.encrypt(et, key, @crypto.KU_AP_REQ_AUTH, pt, conf)
      assert_eq(ct.length(), 16 + pt.length() + et.mac_size())
      assert_eq(@crypto.decrypt(et, key, @crypto.KU_AP_REQ_AUTH, ct), pt)

      // Single-bit tamper in ciphertext body (first byte)
      let bad_first : Result[Bytes, @crypto.CryptoError] = Ok(
        @crypto.decrypt(et, key, @crypto.KU_AP_REQ_AUTH, flip_bit(ct, 0, 0x01)),
      ) catch {
        e => Err(e)
      }
      assert_true(bad_first is Err(IntegrityCheckFailed))

      // Single-bit tamper in MAC (last byte)
      let bad_last : Result[Bytes, @crypto.CryptoError] = Ok(
        @crypto.decrypt(
          et,
          key,
          @crypto.KU_AP_REQ_AUTH,
          flip_bit(ct, ct.length() - 1, 0x80),
        ),
      ) catch {
        e => Err(e)
      }
      assert_true(bad_last is Err(IntegrityCheckFailed))

      // Wrong KeyUsage rejected
      let bad_usage : Result[Bytes, @crypto.CryptoError] = Ok(
        @crypto.decrypt(et, key, @crypto.KU_AP_REP_ENCPART, ct),
      ) catch {
        e => Err(e)
      }
      assert_true(bad_usage is Err(IntegrityCheckFailed))
    }

    // Truncated ciphertext rejected
    let short_ct = rng.next_bytes(16 + et.mac_size() - 1)
    let trunc_res : Result[Bytes, @crypto.CryptoError] = Ok(
      @crypto.decrypt(et, key, @crypto.KU_TICKET, short_ct),
    ) catch {
      e => Err(e)
    }
    assert_true(trunc_res is Err(CiphertextTooShort))

    // Checksum round-trip and tamper rejection
    let msg = b"kerberos authenticator checksum payload"
    let mac = @crypto.make_checksum(
      cksum_type,
      key,
      @crypto.KU_AP_REQ_AUTH_CKSUM,
      msg,
    )
    assert_eq(mac.length(), cksum_type.mac_size())
    assert_true(
      @crypto.verify_checksum(
        cksum_type,
        key,
        @crypto.KU_AP_REQ_AUTH_CKSUM,
        msg,
        mac,
      ),
    )
    assert_false(
      @crypto.verify_checksum(
        cksum_type,
        key,
        @crypto.KU_TGS_REQ_AUTH_CKSUM,
        msg,
        mac,
      ),
    )
    assert_false(
      @crypto.verify_checksum(
        cksum_type,
        key,
        @crypto.KU_AP_REQ_AUTH_CKSUM,
        msg,
        flip_bit(mac, mac.length() - 1, 0x01),
      ),
    )
  }
}

///|
test "Enctype, ChecksumType, KeyUsage, ct_eq, error handling, DeterministicRng" {
  assert_eq(@crypto.Enctype::from_int(17), @crypto.Aes128CtsHmacSha1_96)
  assert_eq(@crypto.Enctype::from_int(18), @crypto.Aes256CtsHmacSha1_96)
  assert_eq(@crypto.Enctype::from_int(19), @crypto.Aes128CtsHmacSha256_128)
  assert_eq(@crypto.Enctype::from_int(20), @crypto.Aes256CtsHmacSha384_192)
  assert_eq(@crypto.Aes128CtsHmacSha1_96.to_int(), 17)
  assert_eq(@crypto.Aes256CtsHmacSha1_96.to_int(), 18)
  assert_eq(@crypto.Aes128CtsHmacSha256_128.to_int(), 19)
  assert_eq(@crypto.Aes256CtsHmacSha384_192.to_int(), 20)
  assert_eq(@crypto.Aes128CtsHmacSha1_96.name(), "aes128-cts-hmac-sha1-96")
  assert_eq(@crypto.Aes256CtsHmacSha1_96.name(), "aes256-cts-hmac-sha1-96")
  assert_eq(
    @crypto.Aes128CtsHmacSha256_128.name(),
    "aes128-cts-hmac-sha256-128",
  )
  assert_eq(
    @crypto.Aes256CtsHmacSha384_192.name(),
    "aes256-cts-hmac-sha384-192",
  )
  let bad_et : Result[@crypto.Enctype, @crypto.CryptoError] = Ok(
    @crypto.Enctype::from_int(23),
  ) catch {
    e => Err(e)
  }
  assert_true(bad_et is Err(UnsupportedEnctype(23)))

  assert_eq(@crypto.ChecksumType::from_int(15), @crypto.HmacSha1_96Aes128)
  assert_eq(@crypto.ChecksumType::from_int(16), @crypto.HmacSha1_96Aes256)
  assert_eq(@crypto.ChecksumType::from_int(19), @crypto.HmacSha256_128Aes128)
  assert_eq(@crypto.ChecksumType::from_int(20), @crypto.HmacSha384_192Aes256)
  assert_eq(@crypto.HmacSha1_96Aes128.to_int(), 15)
  assert_eq(@crypto.HmacSha1_96Aes256.to_int(), 16)
  assert_eq(@crypto.HmacSha256_128Aes128.to_int(), 19)
  assert_eq(@crypto.HmacSha384_192Aes256.to_int(), 20)
  let bad_ck : Result[@crypto.ChecksumType, @crypto.CryptoError] = Ok(
    @crypto.ChecksumType::from_int(99),
  ) catch {
    e => Err(e)
  }
  assert_true(bad_ck is Err(UnsupportedChecksumType(99)))

  // KeyUsage constants sanity
  assert_eq(@crypto.KU_AS_REQ_PA_ENC_TIMESTAMP, 1)
  assert_eq(@crypto.KU_TICKET, 2)
  assert_eq(@crypto.KU_AS_REP_ENCPART, 3)
  assert_eq(@crypto.KU_TGS_REQ_KDC_REQ_BODY_AD, 4)
  assert_eq(@crypto.KU_TGS_REQ_KDC_REQ_BODY_AD_SUBKEY, 5)
  assert_eq(@crypto.KU_TGS_REQ_AUTH_CKSUM, 6)
  assert_eq(@crypto.KU_TGS_REQ_AUTH, 7)
  assert_eq(@crypto.KU_TGS_REP_ENCPART_SESSION_KEY, 8)
  assert_eq(@crypto.KU_TGS_REP_ENCPART_AUTH_SUBKEY, 9)
  assert_eq(@crypto.KU_AP_REQ_AUTH_CKSUM, 10)
  assert_eq(@crypto.KU_AP_REQ_AUTH, 11)
  assert_eq(@crypto.KU_AP_REP_ENCPART, 12)
  assert_eq(@crypto.KU_KRB_PRIV, 13)
  assert_eq(@crypto.KU_KRB_CRED, 14)
  assert_eq(@crypto.KU_KRB_SAFE, 15)

  // ct_eq
  assert_true(@crypto.ct_eq(b"hello", b"hello"))
  assert_false(@crypto.ct_eq(b"hello", b"hellp"))
  assert_false(@crypto.ct_eq(b"hello", b"hell"))

  // Error checks: invalid key length, invalid confounder, invalid s2kparams, zero iter
  let bad_key : Result[Bytes, @crypto.CryptoError] = Ok(
    @crypto.encrypt(
      @crypto.Aes128CtsHmacSha1_96,
      b"short",
      2,
      b"msg",
      Bytes::make(16, b'\x00'),
    ),
  ) catch {
    e => Err(e)
  }
  assert_true(bad_key is Err(InvalidKeyLength(expected=16, got=5)))

  let bad_conf : Result[Bytes, @crypto.CryptoError] = Ok(
    @crypto.encrypt(
      @crypto.Aes128CtsHmacSha1_96,
      Bytes::make(16, b'\x01'),
      2,
      b"msg",
      b"short",
    ),
  ) catch {
    e => Err(e)
  }
  assert_true(bad_conf is Err(InvalidConfounderLength(expected=16, got=5)))

  let bad_s2k : Result[Bytes, @crypto.CryptoError] = Ok(
    @crypto.string_to_key(
      @crypto.Aes128CtsHmacSha1_96,
      b"pw",
      b"salt",
      Some(b"\x00\x01"),
    ),
  ) catch {
    e => Err(e)
  }
  assert_true(bad_s2k is Err(InvalidS2kParams(_)))

  let zero_iter : Result[Bytes, @crypto.CryptoError] = Ok(
    @crypto.string_to_key(
      @crypto.Aes128CtsHmacSha1_96,
      b"pw",
      b"salt",
      Some(b"\x00\x00\x00\x00"),
    ),
  ) catch {
    e => Err(e)
  }
  assert_true(zero_iter is Err(InvalidIterationCount))

  // DeterministicRng: identical seeds produce identical streams, independent of chunking
  let r1 = @crypto.DeterministicRng::new(b"seed-42")
  let r2 = @crypto.DeterministicRng::new(b"seed-42")
  let full = r1.next_bytes(48)
  let a = r2.next_bytes(13)
  let b = r2.next_bytes(35)
  assert_eq(full.length(), 48)
  let combined = Bytes::makei(48, fn(i) {
    if i < 13 {
      a[i]
    } else {
      b[i - 13]
    }
  })
  assert_eq(full, combined)
  let u1 = r1.next_u32()
  let u2 = r2.next_u32()
  assert_eq(u1, u2)
}

///|
test "AES-256-CTS non-zero IV round-trip and KDF error boundaries" {
  let rng = @crypto.DeterministicRng::new(b"aes256-cts-iv-test")
  let key256 = rng.next_bytes(32)
  let iv = rng.next_bytes(16)
  let lens : Array[Int32] = [16, 17, 31, 32, 33, 47, 48, 64, 79]
  for i = 0; i < lens.length(); i = i + 1 {
    let pt = rng.next_bytes(lens[i])
    let ct = @crypto.aes_cts_encrypt(key256, iv, pt)
    assert_eq(ct.length(), pt.length())
    assert_eq(@crypto.aes_cts_decrypt(key256, iv, ct), pt)
  }
  // derive_key rejects RFC 8009 enctypes; kdf_hmac_sha2 rejects RFC 3962 enctypes
  let bad_dr : Result[Bytes, @crypto.CryptoError] = Ok(
    @crypto.derive_key(
      @crypto.Aes128CtsHmacSha256_128,
      rng.next_bytes(16),
      b"kerberos",
    ),
  ) catch {
    e => Err(e)
  }
  assert_true(bad_dr is Err(UnsupportedEnctype(19)))
  let bad_kdf : Result[Bytes, @crypto.CryptoError] = Ok(
    @crypto.kdf_hmac_sha2(
      @crypto.Aes128CtsHmacSha1_96,
      rng.next_bytes(16),
      b"kerberos",
      None,
      128,
    ),
  ) catch {
    e => Err(e)
  }
  assert_true(bad_kdf is Err(UnsupportedEnctype(17)))
  let bad_bits : Result[Bytes, @crypto.CryptoError] = Ok(
    @crypto.kdf_hmac_sha2(
      @crypto.Aes128CtsHmacSha256_128,
      rng.next_bytes(16),
      b"kerberos",
      None,
      384,
    ),
  ) catch {
    e => Err(e)
  }
  assert_true(bad_bits is Err(InvalidInput(_)))
}
