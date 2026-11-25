///|
fn write_base128(out : Array[Byte], value : Int32) -> Unit {
  if value < 0 {
    // Emit a deliberately non-canonical leading 0x80 sequence so negative
    // values can never be silently truncated into valid small tags or OID arcs.
    out.push(b'\x80')
    out.push(b'\x00')
    return
  }
  if value < 0x80 {
    out.push(value.to_byte())
    return
  }
  let tmp : Array[Int32] = []
  let mut v = value
  while v > 0 {
    tmp.push(v & 0x7F)
    v = v >> 7
  }
  let mut i = tmp.length() - 1
  while i >= 0 {
    let b = if i > 0 { tmp[i] | 0x80 } else { tmp[i] }
    out.push(b.to_byte())
    i -= 1
  }
}

///|
fn write_tag(
  out : Array[Byte],
  class : TagClass,
  constructed : Bool,
  number : Int32,
) -> Unit {
  let cls_bits = match class {
    Universal => 0x00
    Application => 0x40
    ContextSpecific => 0x80
    Private => 0xC0
  }
  let pc_bit = if constructed { 0x20 } else { 0x00 }
  if number >= 0 && number < 31 {
    out.push((cls_bits | pc_bit | number).to_byte())
  } else {
    out.push((cls_bits | pc_bit | 0x1F).to_byte())
    write_base128(out, number)
  }
}

///|
fn write_length(out : Array[Byte], len : Int32) -> Unit {
  if len < 0x80 {
    out.push(len.to_byte())
  } else if len <= 0xFF {
    out.push(b'\x81')
    out.push(len.to_byte())
  } else if len <= 0xFFFF {
    out.push(b'\x82')
    out.push(((len >> 8) & 0xFF).to_byte())
    out.push((len & 0xFF).to_byte())
  } else if len <= 0xFF_FFFF {
    out.push(b'\x83')
    out.push(((len >> 16) & 0xFF).to_byte())
    out.push(((len >> 8) & 0xFF).to_byte())
    out.push((len & 0xFF).to_byte())
  } else {
    out.push(b'\x84')
    out.push(((len >> 24) & 0xFF).to_byte())
    out.push(((len >> 16) & 0xFF).to_byte())
    out.push(((len >> 8) & 0xFF).to_byte())
    out.push((len & 0xFF).to_byte())
  }
}

///|
fn write_bytes(out : Array[Byte], data : Bytes) -> Unit {
  for i = 0; i < data.length(); i = i + 1 {
    out.push(data[i])
  }
}

///|
fn encode_utf8(s : String) -> Array[Byte] {
  let out : Array[Byte] = []
  for c in s {
    let cp = c.to_int()
    if cp <= 0x7F {
      out.push(cp.to_byte())
    } else if cp <= 0x7FF {
      out.push((0xC0 | (cp >> 6)).to_byte())
      out.push((0x80 | (cp & 0x3F)).to_byte())
    } else if cp <= 0xFFFF {
      out.push((0xE0 | (cp >> 12)).to_byte())
      out.push((0x80 | ((cp >> 6) & 0x3F)).to_byte())
      out.push((0x80 | (cp & 0x3F)).to_byte())
    } else {
      out.push((0xF0 | (cp >> 18)).to_byte())
      out.push((0x80 | ((cp >> 12) & 0x3F)).to_byte())
      out.push((0x80 | ((cp >> 6) & 0x3F)).to_byte())
      out.push((0x80 | (cp & 0x3F)).to_byte())
    }
  }
  out
}

///|
fn write_der_into(out : Array[Byte], val : DerValue) -> Unit {
  match val {
    Boolean(b) => {
      write_tag(out, Universal, false, TAG_BOOLEAN)
      write_length(out, 1)
      out.push(if b { b'\xFF' } else { b'\x00' })
    }
    Integer(raw) => {
      write_tag(out, Universal, false, TAG_INTEGER)
      write_length(out, raw.length())
      write_bytes(out, raw)
    }
    BitString(unused, data) => {
      write_tag(out, Universal, false, TAG_BIT_STRING)
      write_length(out, 1 + data.length())
      out.push((unused & 0xFF).to_byte())
      write_bytes(out, data)
    }
    OctetString(data) => {
      write_tag(out, Universal, false, TAG_OCTET_STRING)
      write_length(out, data.length())
      write_bytes(out, data)
    }
    Null => {
      write_tag(out, Universal, false, TAG_NULL)
      write_length(out, 0)
    }
    Oid(arcs) => {
      let body : Array[Byte] = []
      if arcs.length() >= 2 {
        let first_sub = arcs[0].to_int64() * 40L + arcs[1].to_int64()
        if arcs[0] < 0 || arcs[1] < 0 || first_sub > 2147483647L {
          write_base128(body, -1)
        } else {
          write_base128(body, first_sub.to_int())
        }
        for i = 2; i < arcs.length(); i = i + 1 {
          write_base128(body, arcs[i])
        }
      }
      write_tag(out, Universal, false, TAG_OID)
      write_length(out, body.length())
      for b in body {
        out.push(b)
      }
    }
    GeneralString(s) => {
      let encoded = encode_utf8(s)
      write_tag(out, Universal, false, TAG_GENERAL_STRING)
      write_length(out, encoded.length())
      for b in encoded {
        out.push(b)
      }
    }
    GeneralizedTime(s) => {
      let encoded = encode_utf8(s)
      write_tag(out, Universal, false, TAG_GENERALIZED_TIME)
      write_length(out, encoded.length())
      for b in encoded {
        out.push(b)
      }
    }
    Sequence(items) => {
      let body : Array[Byte] = []
      for item in items {
        write_der_into(body, item)
      }
      write_tag(out, Universal, true, TAG_SEQUENCE)
      write_length(out, body.length())
      for b in body {
        out.push(b)
      }
    }
    Set(items) => {
      let body : Array[Byte] = []
      for item in items {
        write_der_into(body, item)
      }
      write_tag(out, Universal, true, TAG_SET)
      write_length(out, body.length())
      for b in body {
        out.push(b)
      }
    }
    Application(tag_num, inner) => {
      let body : Array[Byte] = []
      write_der_into(body, inner)
      write_tag(out, Application, true, tag_num)
      write_length(out, body.length())
      for b in body {
        out.push(b)
      }
    }
    Context(tag_num, inner) => {
      let body : Array[Byte] = []
      write_der_into(body, inner)
      write_tag(out, ContextSpecific, true, tag_num)
      write_length(out, body.length())
      for b in body {
        out.push(b)
      }
    }
    Raw(tag, data) => {
      write_tag(out, tag.class, tag.constructed, tag.number)
      write_length(out, data.length())
      write_bytes(out, data)
    }
  }
}

///|
fn compare_bytes_lex(a : Array[Byte], b : Array[Byte]) -> Int32 {
  let alen = a.length()
  let blen = b.length()
  let min_len = if alen < blen { alen } else { blen }
  for i = 0; i < min_len; i = i + 1 {
    let ba = a[i].to_int()
    let bb = b[i].to_int()
    if ba != bb {
      return ba - bb
    }
  }
  alen - blen
}

///|
fn write_der_strict_into(
  out : Array[Byte],
  val : DerValue,
) -> Unit raise DerError {
  match val {
    Boolean(b) => {
      write_tag(out, Universal, false, TAG_BOOLEAN)
      write_length(out, 1)
      out.push(if b { b'\xFF' } else { b'\x00' })
    }
    Integer(raw) => {
      validate_canonical_integer(raw)
      write_tag(out, Universal, false, TAG_INTEGER)
      write_length(out, raw.length())
      write_bytes(out, raw)
    }
    BitString(unused, data) => {
      validate_bit_string(unused, data)
      write_tag(out, Universal, false, TAG_BIT_STRING)
      write_length(out, 1 + data.length())
      out.push((unused & 0xFF).to_byte())
      write_bytes(out, data)
    }
    OctetString(data) => {
      write_tag(out, Universal, false, TAG_OCTET_STRING)
      write_length(out, data.length())
      write_bytes(out, data)
    }
    Null => {
      write_tag(out, Universal, false, TAG_NULL)
      write_length(out, 0)
    }
    Oid(arcs) => {
      if arcs.length() < 2 {
        raise DerError::InvalidValue("OID must have at least 2 arcs")
      }
      let a0 = arcs[0]
      let a1 = arcs[1]
      if a0 < 0 || a0 > 2 {
        raise DerError::InvalidValue("OID first arc must be 0, 1, or 2: \{a0}")
      }
      if a1 < 0 {
        raise DerError::InvalidValue("OID arc must be non-negative: \{a1}")
      }
      if a0 < 2 && a1 >= 40 {
        raise DerError::InvalidValue(
          "OID second arc must be < 40 when first arc is \{a0}: \{a1}",
        )
      }
      let first_sub = a0.to_int64() * 40L + a1.to_int64()
      if first_sub > 2147483647L {
        raise DerError::InvalidValue("OID first subidentifier overflow")
      }
      let body : Array[Byte] = []
      write_base128(body, first_sub.to_int())
      for i = 2; i < arcs.length(); i = i + 1 {
        if arcs[i] < 0 {
          raise DerError::InvalidValue(
            "OID arc must be non-negative: \{arcs[i]}",
          )
        }
        write_base128(body, arcs[i])
      }
      write_tag(out, Universal, false, TAG_OID)
      write_length(out, body.length())
      for b in body {
        out.push(b)
      }
    }
    GeneralString(s) => {
      let encoded = encode_utf8(s)
      write_tag(out, Universal, false, TAG_GENERAL_STRING)
      write_length(out, encoded.length())
      for b in encoded {
        out.push(b)
      }
    }
    GeneralizedTime(s) => {
      validate_generalized_time(s)
      let encoded = encode_utf8(s)
      write_tag(out, Universal, false, TAG_GENERALIZED_TIME)
      write_length(out, encoded.length())
      for b in encoded {
        out.push(b)
      }
    }
    Sequence(items) => {
      let body : Array[Byte] = []
      for item in items {
        write_der_strict_into(body, item)
      }
      write_tag(out, Universal, true, TAG_SEQUENCE)
      write_length(out, body.length())
      for b in body {
        out.push(b)
      }
    }
    Set(items) => {
      let encoded_items : Array[Array[Byte]] = []
      for item in items {
        let item_buf : Array[Byte] = []
        write_der_strict_into(item_buf, item)
        encoded_items.push(item_buf)
      }
      encoded_items.sort_by(compare_bytes_lex)
      let body : Array[Byte] = []
      for item_buf in encoded_items {
        for b in item_buf {
          body.push(b)
        }
      }
      write_tag(out, Universal, true, TAG_SET)
      write_length(out, body.length())
      for b in body {
        out.push(b)
      }
    }
    Application(tag_num, inner) => {
      if tag_num < 0 {
        raise DerError::InvalidTag(
          "negative APPLICATION tag number: \{tag_num}",
        )
      }
      let body : Array[Byte] = []
      write_der_strict_into(body, inner)
      write_tag(out, Application, true, tag_num)
      write_length(out, body.length())
      for b in body {
        out.push(b)
      }
    }
    Context(tag_num, inner) => {
      if tag_num < 0 {
        raise DerError::InvalidTag("negative CONTEXT tag number: \{tag_num}")
      }
      let body : Array[Byte] = []
      write_der_strict_into(body, inner)
      write_tag(out, ContextSpecific, true, tag_num)
      write_length(out, body.length())
      for b in body {
        out.push(b)
      }
    }
    Raw(tag, data) => {
      if tag.number < 0 {
        raise DerError::InvalidTag("negative tag number: \{tag.number}")
      }
      write_tag(out, tag.class, tag.constructed, tag.number)
      write_length(out, data.length())
      write_bytes(out, data)
    }
  }
}

///|
/// Encode a `DerValue` into canonical ASN.1 DER bytes.
pub fn encode_der(val : DerValue) -> Bytes {
  let out : Array[Byte] = []
  write_der_into(out, val)
  Bytes::from_array(out)
}

///|
/// Strictly validate and encode a `DerValue` into canonical ASN.1 DER bytes.
/// Rejects negative tag numbers, invalid/overflowing OIDs, non-canonical
/// integers/bit strings/timestamps, and sorts `SET` elements in DER byte order.
pub fn encode_der_strict(val : DerValue) -> Bytes raise DerError {
  let out : Array[Byte] = []
  write_der_strict_into(out, val)
  Bytes::from_array(out)
}

///|
/// Encode an explicit `[APPLICATION app_tag]` wrapper around `inner`.
pub fn encode_application(app_tag : Int32, inner : DerValue) -> Bytes {
  encode_der(DerValue::Application(app_tag, inner))
}

///|
/// Encode a signed 64-bit integer into canonical minimal two's-complement DER `Integer`.
pub fn encode_int64(v : Int64) -> DerValue {
  let buf : FixedArray[Byte] = FixedArray::make(8, b'\x00')
  buf[0] = ((v >> 56) & 0xFFL).to_byte()
  buf[1] = ((v >> 48) & 0xFFL).to_byte()
  buf[2] = ((v >> 40) & 0xFFL).to_byte()
  buf[3] = ((v >> 32) & 0xFFL).to_byte()
  buf[4] = ((v >> 24) & 0xFFL).to_byte()
  buf[5] = ((v >> 16) & 0xFFL).to_byte()
  buf[6] = ((v >> 8) & 0xFFL).to_byte()
  buf[7] = (v & 0xFFL).to_byte()
  let mut start = 0
  while start < 7 {
    let cur = buf[start]
    let next_high = (buf[start + 1].to_int() & 0x80) != 0
    if cur == b'\x00' && !next_high {
      start += 1
    } else if cur == b'\xFF' && next_high {
      start += 1
    } else {
      break
    }
  }
  let len = 8 - start
  DerValue::Integer(Bytes::makei(len, fn(i) { buf[start + i] }))
}

///|
/// Encode a signed 32-bit `Int` into canonical DER `Integer`.
pub fn encode_int(v : Int32) -> DerValue {
  encode_int64(v.to_int64())
}

///|
/// Encode an unsigned 32-bit `UInt` (`0..4294967295`) into canonical DER `Integer`.
pub fn encode_uint32(v : UInt32) -> DerValue {
  encode_int64(v.to_uint64().reinterpret_as_int64())
}

///|
/// Wrap a string as `DerValue::GeneralString`.
pub fn encode_general_string(s : String) -> DerValue {
  DerValue::GeneralString(s)
}

///|
/// Wrap bytes as `DerValue::OctetString`.
pub fn encode_octet_string(b : Bytes) -> DerValue {
  DerValue::OctetString(b)
}

///|
/// Encode RFC 4120 §5.2.8 `KerberosFlags` as a 32-bit big-endian `BIT STRING`
/// with 0 unused bits (bit 0 is MSB of byte 0).
pub fn encode_kerberos_flags(flags : UInt32) -> DerValue {
  let bytes = Bytes::from_array([
    ((flags >> 24) & 0xFFU).to_byte(),
    ((flags >> 16) & 0xFFU).to_byte(),
    ((flags >> 8) & 0xFFU).to_byte(),
    (flags & 0xFFU).to_byte(),
  ])
  DerValue::BitString(0, bytes)
}

///|
fn is_leap_year(year : Int32) -> Bool {
  (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

///|
fn days_in_month(year : Int32, month : Int32) -> Int32 {
  match month {
    1 | 3 | 5 | 7 | 8 | 10 | 12 => 31
    4 | 6 | 9 | 11 => 30
    2 => if is_leap_year(year) { 29 } else { 28 }
    _ => 0
  }
}

///|
fn parse_ascii_digit(code : Int32) -> Int32 raise DerError {
  if code >= 0x30 && code <= 0x39 {
    code - 0x30
  } else {
    raise DerError::InvalidGeneralizedTime(
      "expected ASCII digit in GeneralizedTime",
    )
  }
}

///|
/// Strictly validate an RFC 4120 `KerberosTime` (`GeneralizedTime`):
/// - Exactly 15 characters: `YYYYMMDDHHMMSSZ`
/// - No fractional seconds, must end with `'Z'`
/// - Valid Gregorian calendar date (including leap years) and 24-hour UTC time.
pub fn validate_generalized_time(s : String) -> Unit raise DerError {
  if s.length() != 15 {
    raise DerError::InvalidGeneralizedTime(
      "GeneralizedTime must be 15 chars YYYYMMDDHHMMSSZ, got length \{s.length()}",
    )
  }
  if s[14] != 0x5A {
    raise DerError::InvalidGeneralizedTime("GeneralizedTime must end with 'Z'")
  }
  let d0 = parse_ascii_digit(s[0].to_int())
  let d1 = parse_ascii_digit(s[1].to_int())
  let d2 = parse_ascii_digit(s[2].to_int())
  let d3 = parse_ascii_digit(s[3].to_int())
  let d4 = parse_ascii_digit(s[4].to_int())
  let d5 = parse_ascii_digit(s[5].to_int())
  let d6 = parse_ascii_digit(s[6].to_int())
  let d7 = parse_ascii_digit(s[7].to_int())
  let d8 = parse_ascii_digit(s[8].to_int())
  let d9 = parse_ascii_digit(s[9].to_int())
  let d10 = parse_ascii_digit(s[10].to_int())
  let d11 = parse_ascii_digit(s[11].to_int())
  let d12 = parse_ascii_digit(s[12].to_int())
  let d13 = parse_ascii_digit(s[13].to_int())
  let year = d0 * 1000 + d1 * 100 + d2 * 10 + d3
  let month = d4 * 10 + d5
  let day = d6 * 10 + d7
  let hour = d8 * 10 + d9
  let minute = d10 * 10 + d11
  let second = d12 * 10 + d13
  if month < 1 || month > 12 {
    raise DerError::InvalidGeneralizedTime("invalid month: \{month}")
  }
  let max_day = days_in_month(year, month)
  if day < 1 || day > max_day {
    raise DerError::InvalidGeneralizedTime(
      "invalid day \{day} for \{year}-\{month}",
    )
  }
  if hour > 23 {
    raise DerError::InvalidGeneralizedTime("invalid hour: \{hour}")
  }
  if minute > 59 {
    raise DerError::InvalidGeneralizedTime("invalid minute: \{minute}")
  }
  if second > 59 {
    raise DerError::InvalidGeneralizedTime("invalid second: \{second}")
  }
}

///|
/// Validate and wrap a `YYYYMMDDHHMMSSZ` timestamp as `DerValue::GeneralizedTime`.
pub fn encode_generalized_time(s : String) -> DerValue raise DerError {
  validate_generalized_time(s)
  DerValue::GeneralizedTime(s)
}

///|
/// Construct an explicit `[tag]` context-specific wrapper.
pub fn context_field(tag : Int32, val : DerValue) -> DerValue {
  DerValue::Context(tag, val)
}
