///|
fn make_bytes(xs : Array[Int32]) -> Bytes {
  Bytes::from_array(xs.map(fn(x) { (x & 0xFF).to_byte() }))
}

///|
fn push_u16_be(buf : Array[Byte], v : Int32) -> Unit {
  buf.push(((v >> 8) & 0xFF).to_byte())
  buf.push((v & 0xFF).to_byte())
}

///|
fn push_u32_be(buf : Array[Byte], v : UInt32) -> Unit {
  buf.push(((v >> 24) & 0xFFU).to_byte())
  buf.push(((v >> 16) & 0xFFU).to_byte())
  buf.push(((v >> 8) & 0xFFU).to_byte())
  buf.push((v & 0xFFU).to_byte())
}

///|
fn push_ascii_counted(buf : Array[Byte], s : String) -> Unit {
  push_u16_be(buf, s.length())
  for ch in s {
    buf.push(ch.to_int().to_byte())
  }
}

///|
test "empty keytab v2 round-trip" {
  let kt = @keytab.Keytab::new()
  assert_eq(kt.version, 0x0502)
  assert_eq(kt.entries.length(), 0)
  let encoded = kt.encode()
  assert_eq(encoded, make_bytes([0x05, 0x02]))
  let decoded = @keytab.Keytab::decode(encoded)
  assert_eq(decoded, kt)
}

///|
test "v2 single entry SPN HTTP/web.example.com@EXAMPLE.COM round-trip" {
  let kt = @keytab.Keytab::new()
  let key18 = make_bytes([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  ])
  let entry : @keytab.KeytabEntry = {
    realm: "EXAMPLE.COM",
    components: ["HTTP", "web.example.com"],
    name_type: 2,
    timestamp: 1700000000U,
    kvno: 3U,
    etype: 18,
    key: key18,
  }
  kt.add_entry(entry)
  let encoded = kt.encode()
  let decoded = @keytab.Keytab::decode(encoded)
  assert_eq(decoded, kt)
  assert_eq(decoded.entries.length(), 1)
  assert_eq(decoded.entries[0], entry)
}

///|
test "v2 multi-entry multi-etype 17/18/19/20 and multi-kvno round-trip" {
  let kt = @keytab.Keytab::new()
  let key16 = make_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
  let key32 = make_bytes([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
    23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
  ])
  kt.add_entry({
    realm: "EXAMPLE.COM",
    components: ["HTTP", "web.example.com"],
    name_type: 2,
    timestamp: 1700000100U,
    kvno: 1U,
    etype: 17,
    key: key16,
  })
  kt.add_entry({
    realm: "EXAMPLE.COM",
    components: ["HTTP", "web.example.com"],
    name_type: 2,
    timestamp: 1700000200U,
    kvno: 2U,
    etype: 18,
    key: key32,
  })
  kt.add_entry({
    realm: "EXAMPLE.COM",
    components: ["HTTP", "web.example.com"],
    name_type: 2,
    timestamp: 1700000300U,
    kvno: 5U,
    etype: 19,
    key: key16,
  })
  kt.add_entry({
    realm: "EXAMPLE.COM",
    components: ["HTTP", "web.example.com"],
    name_type: 2,
    timestamp: 1700000400U,
    kvno: 7U,
    etype: 20,
    key: key32,
  })
  kt.add_entry({
    realm: "CORP.LOCAL",
    components: ["alice"],
    name_type: 1,
    timestamp: 1700000500U,
    kvno: 255U,
    etype: 18,
    key: key32,
  })
  let encoded = kt.encode()
  let decoded = @keytab.Keytab::decode(encoded)
  assert_eq(decoded, kt)
}

///|
test "v2 UTF-8 multibyte realm and components round-trip" {
  let kt = @keytab.Keytab::new()
  kt.add_entry({
    realm: "测试.EXAMPLE.ORG",
    components: ["svc-αβ", "host-🚀"],
    name_type: 1,
    timestamp: 1712345678U,
    kvno: 4U,
    etype: 18,
    key: make_bytes([0xde, 0xad, 0xbe, 0xef]),
  })
  let encoded = kt.encode()
  let decoded = @keytab.Keytab::decode(encoded)
  assert_eq(decoded, kt)
}

///|
test "extended 32-bit kvno encode and decode (1024U and 0x123456U)" {
  let kt = @keytab.Keytab::new()
  let e1 : @keytab.KeytabEntry = {
    realm: "EXAMPLE.COM",
    components: ["krbtgt", "EXAMPLE.COM"],
    name_type: 2,
    timestamp: 1700001000U,
    kvno: 1024U,
    etype: 18,
    key: make_bytes([0xaa, 0xbb, 0xcc, 0xdd]),
  }
  let e2 : @keytab.KeytabEntry = {
    realm: "EXAMPLE.COM",
    components: ["HTTP", "api.example.com"],
    name_type: 2,
    timestamp: 1700002000U,
    kvno: 0x123456U,
    etype: 20,
    key: make_bytes([0x11, 0x22, 0x33, 0x44, 0x55]),
  }
  let e3 : @keytab.KeytabEntry = {
    realm: "EXAMPLE.COM",
    components: ["maxkvno"],
    name_type: 1,
    timestamp: 0xFFFF_FFFFU,
    kvno: 0xFFFF_FFFFU,
    etype: 17,
    key: make_bytes([0x99]),
  }
  kt.add_entry(e1)
  kt.add_entry(e2)
  kt.add_entry(e3)
  let encoded = kt.encode()
  // Verify first entry wire layout has vno8 == 0 and trailing 4-byte 0x00000400
  let entry1_size = (encoded[2].to_int() << 24) |
    (encoded[3].to_int() << 16) |
    (encoded[4].to_int() << 8) |
    encoded[5].to_int()
  let entry1_end = 6 + entry1_size
  assert_eq(encoded[entry1_end - 4], b'\x00')
  assert_eq(encoded[entry1_end - 3], b'\x00')
  assert_eq(encoded[entry1_end - 2], b'\x04')
  assert_eq(encoded[entry1_end - 1], b'\x00')
  let decoded = @keytab.Keytab::decode(encoded)
  assert_eq(decoded, kt)
}

///|
test "extended 32-bit vno zero falls back to vno8 when vno8 != 0" {
  // Construct a v2 entry with vno8 = 9 and trailing 4-byte vno32 = 0
  let body : Array[Byte] = []
  push_u16_be(body, 1) // num_components
  push_ascii_counted(body, "EXAMPLE.COM")
  push_ascii_counted(body, "alice")
  push_u32_be(body, 1U) // name_type
  push_u32_be(body, 123456U) // timestamp
  body.push(b'\x09') // vno8 = 9
  push_u16_be(body, 18) // etype
  push_u16_be(body, 2) // key_len
  body.push(b'\xca')
  body.push(b'\xfe')
  push_u32_be(body, 0U) // trailing vno32 = 0 -> keep vno8 = 9
  let raw : Array[Byte] = []
  push_u16_be(raw, 0x0502)
  push_u32_be(raw, body.length().reinterpret_as_uint())
  for b in body {
    raw.push(b)
  }
  let decoded = @keytab.Keytab::decode(Bytes::from_array(raw))
  assert_eq(decoded.entries.length(), 1)
  assert_eq(decoded.entries[0].kvno, 9U)
}

///|
test "v1 (0x0501) compatibility decode and encode" {
  // Hand-crafted MIT keytab v1 record:
  // num_components includes realm (so 1 realm + 2 components = 3), NO name_type field.
  let body : Array[Byte] = []
  push_u16_be(body, 3) // 1 (realm) + 2 (components)
  push_ascii_counted(body, "ATHENA.MIT.EDU")
  push_ascii_counted(body, "host")
  push_ascii_counted(body, "kdc.mit.edu")
  // No name_type in v1
  push_u32_be(body, 946684800U) // timestamp
  body.push(b'\x02') // vno8 = 2
  push_u16_be(body, 17) // etype
  push_u16_be(body, 4) // key_len
  body.push(b'\x10')
  body.push(b'\x20')
  body.push(b'\x30')
  body.push(b'\x40')
  let raw : Array[Byte] = []
  push_u16_be(raw, 0x0501)
  push_u32_be(raw, body.length().reinterpret_as_uint())
  for b in body {
    raw.push(b)
  }
  let raw_bytes = Bytes::from_array(raw)
  let decoded = @keytab.Keytab::decode(raw_bytes)
  assert_eq(decoded.version, 0x0501)
  assert_eq(decoded.entries.length(), 1)
  let e = decoded.entries[0]
  assert_eq(e.realm, "ATHENA.MIT.EDU")
  assert_eq(e.components, ["host", "kdc.mit.edu"])
  assert_eq(e.name_type, 1) // default NT_PRINCIPAL
  assert_eq(e.timestamp, 946684800U)
  assert_eq(e.kvno, 2U)
  assert_eq(e.etype, 17)
  assert_eq(e.key, make_bytes([0x10, 0x20, 0x30, 0x40]))
  // Re-encoding v1 should match exact bytes
  let reencoded = decoded.encode()
  assert_eq(reencoded, raw_bytes)
}

///|
test "deleted entry holes (negative entry_size) are skipped cleanly" {
  let e1 : @keytab.KeytabEntry = {
    realm: "EXAMPLE.COM",
    components: ["alice"],
    name_type: 1,
    timestamp: 100U,
    kvno: 1U,
    etype: 17,
    key: make_bytes([1, 2, 3]),
  }
  let e2 : @keytab.KeytabEntry = {
    realm: "EXAMPLE.COM",
    components: ["bob"],
    name_type: 1,
    timestamp: 200U,
    kvno: 2U,
    etype: 18,
    key: make_bytes([4, 5, 6, 7]),
  }
  let kt1 = @keytab.Keytab::new()
  kt1.add_entry(e1)
  let b1 = kt1.encode()
  let kt2 = @keytab.Keytab::new()
  kt2.add_entry(e2)
  let b2 = kt2.encode()
  // Assemble: header + hole(10) + entry1 + hole(6) + entry2 + trailing hole(3)
  let raw : Array[Byte] = []
  push_u16_be(raw, 0x0502)
  // Hole of 10 bytes: entry_size = -10
  push_u32_be(raw, (-10).reinterpret_as_uint())
  for i = 0; i < 10; i = i + 1 {
    raw.push(b'\xFF')
  }
  // Entry 1 (skip 2-byte header)
  for i = 2; i < b1.length(); i = i + 1 {
    raw.push(b1[i])
  }
  // Hole of 6 bytes: entry_size = -6
  push_u32_be(raw, (-6).reinterpret_as_uint())
  for i = 0; i < 6; i = i + 1 {
    raw.push(b'\x00')
  }
  // Entry 2 (skip 2-byte header)
  for i = 2; i < b2.length(); i = i + 1 {
    raw.push(b2[i])
  }
  // Trailing hole of 3 bytes: entry_size = -3
  push_u32_be(raw, (-3).reinterpret_as_uint())
  raw.push(b'\xAA')
  raw.push(b'\xBB')
  raw.push(b'\xCC')
  let decoded = @keytab.Keytab::decode(Bytes::from_array(raw))
  assert_eq(decoded.entries, [e1, e2])
}

///|
test "find_key highest kvno selection, exact kvno lookup, and find_all_for_principal" {
  let kt = @keytab.Keytab::new()
  let k1 : @keytab.KeytabEntry = {
    realm: "EXAMPLE.COM",
    components: ["HTTP", "web.example.com"],
    name_type: 2,
    timestamp: 1000U,
    kvno: 2U,
    etype: 18,
    key: make_bytes([0x02]),
  }
  let k2 : @keytab.KeytabEntry = {
    realm: "EXAMPLE.COM",
    components: ["HTTP", "web.example.com"],
    name_type: 2,
    timestamp: 3000U,
    kvno: 500U,
    etype: 18,
    key: make_bytes([0x50]),
  }
  let k3 : @keytab.KeytabEntry = {
    realm: "EXAMPLE.COM",
    components: ["HTTP", "web.example.com"],
    name_type: 2,
    timestamp: 2000U,
    kvno: 10U,
    etype: 18,
    key: make_bytes([0x10]),
  }
  let k4 : @keytab.KeytabEntry = {
    realm: "EXAMPLE.COM",
    components: ["HTTP", "web.example.com"],
    name_type: 2,
    timestamp: 4000U,
    kvno: 3U,
    etype: 17,
    key: make_bytes([0x17]),
  }
  let other : @keytab.KeytabEntry = {
    realm: "OTHER.COM",
    components: ["HTTP", "web.example.com"],
    name_type: 2,
    timestamp: 5000U,
    kvno: 999U,
    etype: 18,
    key: make_bytes([0x99]),
  }
  kt.add_entry(k1)
  kt.add_entry(k2)
  kt.add_entry(k3)
  kt.add_entry(k4)
  kt.add_entry(other)
  // Auto-select highest kvno for etype 18
  assert_eq(
    kt.find_key("EXAMPLE.COM", ["HTTP", "web.example.com"], 18),
    Some(k2),
  )
  // Exact kvno lookups
  assert_eq(
    kt.find_key("EXAMPLE.COM", ["HTTP", "web.example.com"], 18, kvno=2U),
    Some(k1),
  )
  assert_eq(
    kt.find_key("EXAMPLE.COM", ["HTTP", "web.example.com"], 18, kvno=10U),
    Some(k3),
  )
  assert_eq(
    kt.find_key("EXAMPLE.COM", ["HTTP", "web.example.com"], 18, kvno=99U),
    None,
  )
  // Different etype
  assert_eq(
    kt.find_key("EXAMPLE.COM", ["HTTP", "web.example.com"], 17),
    Some(k4),
  )
  assert_eq(kt.find_key("EXAMPLE.COM", ["HTTP", "web.example.com"], 20), None)
  // Different realm
  assert_eq(
    kt.find_key("OTHER.COM", ["HTTP", "web.example.com"], 18),
    Some(other),
  )
  // find_all_for_principal
  assert_eq(
    kt.find_all_for_principal("EXAMPLE.COM", ["HTTP", "web.example.com"]),
    [k1, k2, k3, k4],
  )
  assert_eq(kt.find_all_for_principal("MISSING.COM", ["nobody"]), [])
}

///|
test "malformed: empty and 1-byte input raise UnexpectedEof" {
  let r0 = Ok(@keytab.Keytab::decode(make_bytes([]))) catch { e => Err(e) }
  assert_true(r0 is Err(@keytab.KeytabError::UnexpectedEof))
  let r1 = Ok(@keytab.Keytab::decode(make_bytes([0x05]))) catch { e => Err(e) }
  assert_true(r1 is Err(@keytab.KeytabError::UnexpectedEof))
}

///|
test "malformed: unsupported version 0x0503 raises UnsupportedVersion" {
  let r = Ok(@keytab.Keytab::decode(make_bytes([0x05, 0x03]))) catch {
    e => Err(e)
  }
  assert_true(r is Err(@keytab.KeytabError::UnsupportedVersion(0x0503)))
  let bad_kt : @keytab.Keytab = { version: 0x0503, entries: [], }
  let re = Ok(bad_kt.encode()) catch { e => Err(e) }
  assert_true(re is Err(@keytab.KeytabError::UnsupportedVersion(0x0503)))
}

///|
test "malformed: entry_size == 0 raises InvalidEntrySize(0)" {
  let r = Ok(
    @keytab.Keytab::decode(make_bytes([0x05, 0x02, 0x00, 0x00, 0x00, 0x00])),
  ) catch {
    e => Err(e)
  }
  assert_true(r is Err(@keytab.KeytabError::InvalidEntrySize(0)))
}

///|
test "malformed: truncated entry_size prefix raises UnexpectedEof" {
  let r = Ok(@keytab.Keytab::decode(make_bytes([0x05, 0x02, 0x00, 0x00]))) catch {
    e => Err(e)
  }
  assert_true(r is Err(@keytab.KeytabError::UnexpectedEof))
}

///|
test "malformed: truncated positive entry raises TruncatedEntry" {
  // Claims entry_size = 20, but only 3 bytes remain
  let r = Ok(
    @keytab.Keytab::decode(
      make_bytes([0x05, 0x02, 0x00, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00]),
    ),
  ) catch {
    e => Err(e)
  }
  assert_true(r is Err(@keytab.KeytabError::TruncatedEntry))
  // Entry length matches buffer, but inner key_len exceeds entry boundary
  let body : Array[Byte] = []
  push_u16_be(body, 0) // num_components
  push_ascii_counted(body, "R")
  push_u32_be(body, 1U) // name_type
  push_u32_be(body, 0U) // timestamp
  body.push(b'\x01') // vno8
  push_u16_be(body, 18) // etype
  push_u16_be(body, 16) // key_len = 16, but only 2 key bytes provided
  body.push(b'\xaa')
  body.push(b'\xbb')
  let raw : Array[Byte] = []
  push_u16_be(raw, 0x0502)
  push_u32_be(raw, body.length().reinterpret_as_uint())
  for b in body {
    raw.push(b)
  }
  let r2 = Ok(@keytab.Keytab::decode(Bytes::from_array(raw))) catch {
    e => Err(e)
  }
  assert_true(r2 is Err(@keytab.KeytabError::TruncatedEntry))
}

///|
test "malformed: negative hole out of bounds and Int32::min overflow protection" {
  // Hole of -10 when only 4 bytes remain
  let r1 = Ok(
    @keytab.Keytab::decode(
      make_bytes([0x05, 0x02, 0xFF, 0xFF, 0xFF, 0xF6, 0x01, 0x02, 0x03, 0x04]),
    ),
  ) catch {
    e => Err(e)
  }
  assert_true(r1 is Err(@keytab.KeytabError::TruncatedEntry))
  // Int32::min (-2147483648 = 0x80000000) must not overflow and must raise TruncatedEntry
  let r2 = Ok(
    @keytab.Keytab::decode(
      make_bytes([0x05, 0x02, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00]),
    ),
  ) catch {
    e => Err(e)
  }
  assert_true(r2 is Err(@keytab.KeytabError::TruncatedEntry))
}

///|
test "malformed: invalid UTF-8 in realm or component raises InvalidUtf8" {
  // Invalid UTF-8 bytes 0xFF 0xFE in realm
  let body : Array[Byte] = []
  push_u16_be(body, 0) // num_components
  push_u16_be(body, 2) // realm len
  body.push(b'\xFF')
  body.push(b'\xFE')
  push_u32_be(body, 1U)
  push_u32_be(body, 0U)
  body.push(b'\x01')
  push_u16_be(body, 18)
  push_u16_be(body, 0)
  let raw : Array[Byte] = []
  push_u16_be(raw, 0x0502)
  push_u32_be(raw, body.length().reinterpret_as_uint())
  for b in body {
    raw.push(b)
  }
  let r1 = Ok(@keytab.Keytab::decode(Bytes::from_array(raw))) catch {
    e => Err(e)
  }
  assert_true(r1 is Err(@keytab.KeytabError::InvalidUtf8))
  // Overlong UTF-8 encoding of '/' (0xC0 0xAF) in component
  let body2 : Array[Byte] = []
  push_u16_be(body2, 1) // num_components
  push_ascii_counted(body2, "EXAMPLE.COM")
  push_u16_be(body2, 2) // component len
  body2.push(b'\xC0')
  body2.push(b'\xAF')
  push_u32_be(body2, 1U)
  push_u32_be(body2, 0U)
  body2.push(b'\x01')
  push_u16_be(body2, 18)
  push_u16_be(body2, 0)
  let raw2 : Array[Byte] = []
  push_u16_be(raw2, 0x0502)
  push_u32_be(raw2, body2.length().reinterpret_as_uint())
  for b in body2 {
    raw2.push(b)
  }
  let r2 = Ok(@keytab.Keytab::decode(Bytes::from_array(raw2))) catch {
    e => Err(e)
  }
  assert_true(r2 is Err(@keytab.KeytabError::InvalidUtf8))
  // UTF-16 surrogate U+D800 (0xED 0xA0 0x80) in realm
  let body3 : Array[Byte] = []
  push_u16_be(body3, 0)
  push_u16_be(body3, 3)
  body3.push(b'\xED')
  body3.push(b'\xA0')
  body3.push(b'\x80')
  push_u32_be(body3, 1U)
  push_u32_be(body3, 0U)
  body3.push(b'\x01')
  push_u16_be(body3, 18)
  push_u16_be(body3, 0)
  let raw3 : Array[Byte] = []
  push_u16_be(raw3, 0x0502)
  push_u32_be(raw3, body3.length().reinterpret_as_uint())
  for b in body3 {
    raw3.push(b)
  }
  let r3 = Ok(@keytab.Keytab::decode(Bytes::from_array(raw3))) catch {
    e => Err(e)
  }
  assert_true(r3 is Err(@keytab.KeytabError::InvalidUtf8))
}

///|
test "malformed: v1 with num_components == 0 raises TruncatedEntry" {
  let body : Array[Byte] = []
  push_u16_be(body, 0) // invalid in v1 (must be >= 1)
  push_ascii_counted(body, "EXAMPLE.COM")
  push_u32_be(body, 0U)
  body.push(b'\x01')
  push_u16_be(body, 18)
  push_u16_be(body, 0)
  let raw : Array[Byte] = []
  push_u16_be(raw, 0x0501)
  push_u32_be(raw, body.length().reinterpret_as_uint())
  for b in body {
    raw.push(b)
  }
  let r = Ok(@keytab.Keytab::decode(Bytes::from_array(raw))) catch {
    e => Err(e)
  }
  assert_true(r is Err(@keytab.KeytabError::TruncatedEntry))
}

///|
test "encode validation: FieldTooLarge for key, realm, component, etype" {
  let huge_key = Bytes::make(65536, b'\x00')
  let kt1 = @keytab.Keytab::new()
  kt1.add_entry({
    realm: "EXAMPLE.COM",
    components: ["alice"],
    name_type: 1,
    timestamp: 0U,
    kvno: 1U,
    etype: 18,
    key: huge_key,
  })
  let r1 = Ok(kt1.encode()) catch { e => Err(e) }
  assert_true(r1 is Err(@keytab.KeytabError::FieldTooLarge("key")))
  let kt2 = @keytab.Keytab::new()
  kt2.add_entry({
    realm: "EXAMPLE.COM",
    components: ["alice"],
    name_type: 1,
    timestamp: 0U,
    kvno: 1U,
    etype: 70000,
    key: make_bytes([1]),
  })
  let r2 = Ok(kt2.encode()) catch { e => Err(e) }
  assert_true(r2 is Err(@keytab.KeytabError::FieldTooLarge("etype")))
  let sb = StringBuilder()
  for _i = 0; _i < 65536; _i = _i + 1 {
    sb.write_char('A')
  }
  let huge_str = sb.to_string()
  let kt3 = @keytab.Keytab::new()
  kt3.add_entry({
    realm: huge_str,
    components: ["alice"],
    name_type: 1,
    timestamp: 0U,
    kvno: 1U,
    etype: 18,
    key: make_bytes([1]),
  })
  let r3 = Ok(kt3.encode()) catch { e => Err(e) }
  assert_true(r3 is Err(@keytab.KeytabError::FieldTooLarge("realm")))
  let kt4 = @keytab.Keytab::new()
  kt4.add_entry({
    realm: "EXAMPLE.COM",
    components: [huge_str],
    name_type: 1,
    timestamp: 0U,
    kvno: 1U,
    etype: 18,
    key: make_bytes([1]),
  })
  let r4 = Ok(kt4.encode()) catch { e => Err(e) }
  assert_true(r4 is Err(@keytab.KeytabError::FieldTooLarge("component")))
}

///|
test "get_key returns entry or raises KeyNotFound" {
  let kt = @keytab.Keytab::new()
  let entry : @keytab.KeytabEntry = {
    realm: "EXAMPLE.COM",
    components: ["HTTP", "web.example.com"],
    name_type: 2,
    timestamp: 1700000000U,
    kvno: 5U,
    etype: 18,
    key: make_bytes([0xde, 0xad, 0xbe, 0xef]),
  }
  kt.add_entry(entry)
  assert_eq(kt.get_key("EXAMPLE.COM", ["HTTP", "web.example.com"], 18), entry)
  assert_eq(
    kt.get_key("EXAMPLE.COM", ["HTTP", "web.example.com"], 18, kvno=5U),
    entry,
  )
  let missing = Ok(kt.get_key("EXAMPLE.COM", ["HTTP", "web.example.com"], 17)) catch {
    e => Err(e)
  }
  assert_true(missing is Err(@keytab.KeytabError::KeyNotFound))
  let wrong_kvno = Ok(
    kt.get_key("EXAMPLE.COM", ["HTTP", "web.example.com"], 18, kvno=99U),
  ) catch {
    e => Err(e)
  }
  assert_true(wrong_kvno is Err(@keytab.KeytabError::KeyNotFound))
}

///|
test "Show formatting works for Keytab, KeytabEntry, and KeytabError" {
  let kt = @keytab.Keytab::new()
  let entry : @keytab.KeytabEntry = {
    realm: "EXAMPLE.COM",
    components: ["HTTP", "web.example.com"],
    name_type: 2,
    timestamp: 1700000000U,
    kvno: 5U,
    etype: 18,
    key: make_bytes([1, 2, 3, 4]),
  }
  kt.add_entry(entry)
  assert_eq(
    Show::to_string(entry),
    "KeytabEntry(HTTP/web.example.com@EXAMPLE.COM, kvno=5, etype=18, key_len=4)",
  )
  assert_eq(Show::to_string(kt), "Keytab(version=1282, entries=1)")
  let err_str = try {
    ignore(@keytab.Keytab::decode(make_bytes([0x05, 0x03])))
    ""
  } catch {
    e => Show::to_string(e)
  }
  assert_eq(err_str, "UnsupportedVersion(1283)")
}

///|
test "malformed: additional strict RFC 3629 UTF-8 edge cases" {
  let bad_sequences : Array[Array[Int32]] = [
    [0x80], // lone continuation byte
    [0xC2], // truncated 2-byte
    [0xE2, 0x82], // truncated 3-byte
    [0xF0, 0x9F, 0x98], // truncated 4-byte
    [0xE0, 0x80, 0xAF], // overlong 3-byte
    [0xF0, 0x80, 0x80, 0xAF], // overlong 4-byte
    [0xF4, 0x90, 0x80, 0x80], // > U+10FFFF
  ]
  for seq in bad_sequences {
    let body : Array[Byte] = []
    push_u16_be(body, 0)
    push_u16_be(body, seq.length())
    for b in seq {
      body.push((b & 0xFF).to_byte())
    }
    push_u32_be(body, 1U)
    push_u32_be(body, 0U)
    body.push(b'\x01')
    push_u16_be(body, 18)
    push_u16_be(body, 0)
    let raw : Array[Byte] = []
    push_u16_be(raw, 0x0502)
    push_u32_be(raw, body.length().reinterpret_as_uint())
    for b in body {
      raw.push(b)
    }
    let r = Ok(@keytab.Keytab::decode(Bytes::from_array(raw))) catch {
      e => Err(e)
    }
    assert_true(r is Err(@keytab.KeytabError::InvalidUtf8))
  }
}

///|
test "trailing extension bytes (32-bit vno + flags) and vno8 override" {
  // Entry with vno8 = 5, vno32 = 261 (0x00000105), plus 4-byte MIT flags = 0x00000001
  let body : Array[Byte] = []
  push_u16_be(body, 1)
  push_ascii_counted(body, "EXAMPLE.COM")
  push_ascii_counted(body, "svc")
  push_u32_be(body, 1U)
  push_u32_be(body, 1700000000U)
  body.push(b'\x05') // vno8 = 5
  push_u16_be(body, 18)
  push_u16_be(body, 2)
  body.push(b'\xab')
  body.push(b'\xcd')
  push_u32_be(body, 261U) // vno32 != 0 overrides vno8
  push_u32_be(body, 1U) // extra MIT flags bytes ignored cleanly
  let raw : Array[Byte] = []
  push_u16_be(raw, 0x0502)
  push_u32_be(raw, body.length().reinterpret_as_uint())
  for b in body {
    raw.push(b)
  }
  let decoded = @keytab.Keytab::decode(Bytes::from_array(raw))
  assert_eq(decoded.entries.length(), 1)
  assert_eq(decoded.entries[0].kvno, 261U)
  assert_eq(decoded.entries[0].key, make_bytes([0xab, 0xcd]))
}

///|
test "encode validation: negative etype raises FieldTooLarge" {
  let kt = @keytab.Keytab::new()
  kt.add_entry({
    realm: "EXAMPLE.COM",
    components: ["alice"],
    name_type: 1,
    timestamp: 0U,
    kvno: 1U,
    etype: -1,
    key: make_bytes([1]),
  })
  let r = Ok(kt.encode()) catch { e => Err(e) }
  assert_true(r is Err(@keytab.KeytabError::FieldTooLarge("etype")))
}
