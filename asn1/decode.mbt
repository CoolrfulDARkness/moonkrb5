///|
fn slice_bytes(data : Bytes, start : Int32, len : Int32) -> Bytes {
  Bytes::makei(len, fn(i) { data[start + i] })
}

///|
fn validate_canonical_integer(raw : Bytes) -> Unit raise DerError {
  let len = raw.length()
  if len == 0 {
    raise DerError::NonCanonicalInteger
  }
  if len >= 2 {
    let b0 = raw[0]
    let b1_high = (raw[1].to_int() & 0x80) != 0
    if b0 == b'\x00' && !b1_high {
      raise DerError::NonCanonicalInteger
    }
    if b0 == b'\xFF' && b1_high {
      raise DerError::NonCanonicalInteger
    }
  }
}

///|
fn validate_bit_string(unused : Int32, data : Bytes) -> Unit raise DerError {
  if unused < 0 || unused > 7 {
    raise DerError::InvalidBitString("unused bits out of range 0..7: \{unused}")
  }
  if data.length() == 0 {
    if unused != 0 {
      raise DerError::InvalidBitString(
        "non-zero unused bits in empty BIT STRING",
      )
    }
    return
  }
  if unused > 0 {
    let mask = (1 << unused) - 1
    let last = data[data.length() - 1].to_int()
    if (last & mask) != 0 {
      raise DerError::InvalidBitString("non-zero padding bits in BIT STRING")
    }
  }
}

///|
fn decode_utf8(
  data : Bytes,
  start : Int32,
  end : Int32,
) -> String raise DerError {
  let sb = StringBuilder()
  let mut i = start
  while i < end {
    let b0 = data[i].to_int()
    if b0 <= 0x7F {
      sb.write_char(Int32::unsafe_to_char(b0))
      i += 1
    } else if b0 >= 0xC2 && b0 <= 0xDF {
      if i + 1 >= end {
        raise DerError::InvalidValue("truncated UTF-8 2-byte sequence")
      }
      let b1 = data[i + 1].to_int()
      if (b1 & 0xC0) != 0x80 {
        raise DerError::InvalidValue("invalid UTF-8 continuation byte")
      }
      let cp = ((b0 & 0x1F) << 6) | (b1 & 0x3F)
      sb.write_char(Int32::unsafe_to_char(cp))
      i += 2
    } else if b0 >= 0xE0 && b0 <= 0xEF {
      if i + 2 >= end {
        raise DerError::InvalidValue("truncated UTF-8 3-byte sequence")
      }
      let b1 = data[i + 1].to_int()
      let b2 = data[i + 2].to_int()
      if (b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 {
        raise DerError::InvalidValue("invalid UTF-8 continuation byte")
      }
      if b0 == 0xE0 && b1 < 0xA0 {
        raise DerError::InvalidValue("overlong UTF-8 3-byte sequence")
      }
      if b0 == 0xED && b1 >= 0xA0 {
        raise DerError::InvalidValue("UTF-8 encoded surrogate code point")
      }
      let cp = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F)
      sb.write_char(Int32::unsafe_to_char(cp))
      i += 3
    } else if b0 >= 0xF0 && b0 <= 0xF4 {
      if i + 3 >= end {
        raise DerError::InvalidValue("truncated UTF-8 4-byte sequence")
      }
      let b1 = data[i + 1].to_int()
      let b2 = data[i + 2].to_int()
      let b3 = data[i + 3].to_int()
      if (b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80 {
        raise DerError::InvalidValue("invalid UTF-8 continuation byte")
      }
      if b0 == 0xF0 && b1 < 0x90 {
        raise DerError::InvalidValue("overlong UTF-8 4-byte sequence")
      }
      if b0 == 0xF4 && b1 > 0x8F {
        raise DerError::InvalidValue("UTF-8 code point exceeds U+10FFFF")
      }
      let cp = ((b0 & 0x07) << 18) |
        ((b1 & 0x3F) << 12) |
        ((b2 & 0x3F) << 6) |
        (b3 & 0x3F)
      sb.write_char(Int32::unsafe_to_char(cp))
      i += 4
    } else {
      raise DerError::InvalidValue("invalid UTF-8 leading byte")
    }
  }
  sb.to_string()
}

///|
fn read_tag(
  data : Bytes,
  pos : Int32,
  end : Int32,
) -> (Tag, Int32) raise DerError {
  if pos >= end {
    raise DerError::UnexpectedEof
  }
  let b0 = data[pos].to_int()
  let class = match (b0 >> 6) & 0x03 {
    0 => TagClass::Universal
    1 => TagClass::Application
    2 => TagClass::ContextSpecific
    _ => TagClass::Private
  }
  let constructed = (b0 & 0x20) != 0
  let low = b0 & 0x1F
  if low < 31 {
    return ({ class, constructed, number: low, }, pos + 1)
  }
  // High-tag-number form (X.690 §8.1.2.4)
  let mut cursor = pos + 1
  if cursor >= end {
    raise DerError::UnexpectedEof
  }
  let first_sub = data[cursor].to_int()
  if first_sub == 0x80 {
    raise DerError::InvalidTag("non-canonical high tag number: leading 0x80")
  }
  let mut num = 0
  while true {
    if cursor >= end {
      raise DerError::UnexpectedEof
    }
    let b = data[cursor].to_int()
    cursor += 1
    if num > 0x00FF_FFFF {
      raise DerError::InvalidTag("high tag number overflow")
    }
    num = (num << 7) | (b & 0x7F)
    if (b & 0x80) == 0 {
      break
    }
  }
  if num < 31 {
    raise DerError::InvalidTag("non-canonical high tag number < 31: \{num}")
  }
  ({ class, constructed, number: num, }, cursor)
}

///|
fn read_length(
  data : Bytes,
  pos : Int32,
  end : Int32,
) -> (Int32, Int32) raise DerError {
  if pos >= end {
    raise DerError::UnexpectedEof
  }
  let b0 = data[pos].to_int()
  if b0 < 0x80 {
    let content_start = pos + 1
    if b0 > end - content_start {
      raise DerError::UnexpectedEof
    }
    return (b0, content_start)
  }
  if b0 == 0x80 {
    raise DerError::IndefiniteLength
  }
  if b0 == 0xFF {
    raise DerError::InvalidLength("reserved length byte 0xFF")
  }
  let num_octets = b0 & 0x7F
  let octets_start = pos + 1
  if num_octets > end - octets_start {
    raise DerError::UnexpectedEof
  }
  if data[octets_start] == b'\x00' {
    raise DerError::NonCanonicalLength
  }
  if num_octets > 4 {
    raise DerError::InvalidLength("length exceeds 4 octets")
  }
  let mut len = 0
  for i = 0; i < num_octets; i = i + 1 {
    let b = data[octets_start + i].to_int()
    if i == 0 && num_octets == 4 && (b & 0x80) != 0 {
      raise DerError::InvalidLength("length overflows signed 32-bit Int")
    }
    len = (len << 8) | b
  }
  if len < 0x80 {
    raise DerError::NonCanonicalLength
  }
  let content_start = octets_start + num_octets
  if len > end - content_start {
    raise DerError::UnexpectedEof
  }
  (len, content_start)
}

///|
fn decode_oid(
  data : Bytes,
  start : Int32,
  end : Int32,
) -> Array[Int32] raise DerError {
  if start >= end {
    raise DerError::InvalidValue("empty OBJECT IDENTIFIER")
  }
  let arcs : Array[Int32] = []
  let mut cursor = start
  let mut first = true
  while cursor < end {
    if data[cursor] == b'\x80' {
      raise DerError::InvalidValue("non-canonical OID subidentifier")
    }
    let mut sub = 0
    let mut terminated = false
    while cursor < end {
      let b = data[cursor].to_int()
      cursor += 1
      if sub > 0x00FF_FFFF {
        raise DerError::InvalidValue("OID subidentifier overflow")
      }
      sub = (sub << 7) | (b & 0x7F)
      if (b & 0x80) == 0 {
        terminated = true
        break
      }
    }
    if !terminated {
      raise DerError::InvalidValue("truncated OID subidentifier")
    }
    if first {
      first = false
      if sub < 40 {
        arcs.push(0)
        arcs.push(sub)
      } else if sub < 80 {
        arcs.push(1)
        arcs.push(sub - 40)
      } else {
        arcs.push(2)
        arcs.push(sub - 80)
      }
    } else {
      arcs.push(sub)
    }
  }
  arcs
}

///|
fn decode_tlv(
  data : Bytes,
  pos : Int32,
  end : Int32,
  depth : Int32,
) -> (DerValue, Int32) raise DerError {
  if depth > MAX_DEPTH {
    raise DerError::MaxDepthExceeded
  }
  let (tag, len_pos) = read_tag(data, pos, end)
  let (content_len, content_start) = read_length(data, len_pos, end)
  let content_end = content_start + content_len
  let value : DerValue = match tag.class {
    Universal =>
      match tag.number {
        TAG_BOOLEAN => {
          if tag.constructed {
            raise DerError::InvalidTag("BOOLEAN must be primitive")
          }
          if content_len != 1 {
            raise DerError::NonCanonicalBoolean
          }
          match data[content_start] {
            b'\x00' => DerValue::Boolean(false)
            b'\xFF' => DerValue::Boolean(true)
            _ => raise DerError::NonCanonicalBoolean
          }
        }
        TAG_INTEGER => {
          if tag.constructed {
            raise DerError::InvalidTag("INTEGER must be primitive")
          }
          let raw = slice_bytes(data, content_start, content_len)
          validate_canonical_integer(raw)
          DerValue::Integer(raw)
        }
        TAG_BIT_STRING => {
          if tag.constructed {
            raise DerError::InvalidTag("BIT STRING must be primitive")
          }
          if content_len < 1 {
            raise DerError::InvalidBitString("empty BIT STRING content")
          }
          let unused = data[content_start].to_int()
          let payload = slice_bytes(data, content_start + 1, content_len - 1)
          validate_bit_string(unused, payload)
          DerValue::BitString(unused, payload)
        }
        TAG_OCTET_STRING => {
          if tag.constructed {
            raise DerError::InvalidTag("OCTET STRING must be primitive")
          }
          DerValue::OctetString(slice_bytes(data, content_start, content_len))
        }
        TAG_NULL => {
          if tag.constructed {
            raise DerError::InvalidTag("NULL must be primitive")
          }
          if content_len != 0 {
            raise DerError::InvalidLength("NULL must have length 0")
          }
          DerValue::Null
        }
        TAG_OID => {
          if tag.constructed {
            raise DerError::InvalidTag("OBJECT IDENTIFIER must be primitive")
          }
          DerValue::Oid(decode_oid(data, content_start, content_end))
        }
        TAG_SEQUENCE => {
          if !tag.constructed {
            raise DerError::InvalidTag("SEQUENCE must be constructed")
          }
          if depth >= MAX_DEPTH {
            raise DerError::MaxDepthExceeded
          }
          let items : Array[DerValue] = []
          let mut cursor = content_start
          while cursor < content_end {
            let (child, next_cursor) = decode_tlv(
              data,
              cursor,
              content_end,
              depth + 1,
            )
            items.push(child)
            cursor = next_cursor
          }
          DerValue::Sequence(items)
        }
        TAG_SET => {
          if !tag.constructed {
            raise DerError::InvalidTag("SET must be constructed")
          }
          if depth >= MAX_DEPTH {
            raise DerError::MaxDepthExceeded
          }
          let items : Array[DerValue] = []
          let mut cursor = content_start
          while cursor < content_end {
            let (child, next_cursor) = decode_tlv(
              data,
              cursor,
              content_end,
              depth + 1,
            )
            items.push(child)
            cursor = next_cursor
          }
          DerValue::Set(items)
        }
        TAG_GENERALIZED_TIME => {
          if tag.constructed {
            raise DerError::InvalidTag("GeneralizedTime must be primitive")
          }
          if content_len != 15 {
            raise DerError::InvalidGeneralizedTime("expected 15 bytes")
          }
          let sb = StringBuilder()
          for i = content_start; i < content_end; i = i + 1 {
            let b = data[i].to_int()
            if b > 0x7F {
              raise DerError::InvalidGeneralizedTime(
                "non-ASCII byte in GeneralizedTime",
              )
            }
            sb.write_char(Int32::unsafe_to_char(b))
          }
          let s = sb.to_string()
          validate_generalized_time(s)
          DerValue::GeneralizedTime(s)
        }
        TAG_GENERAL_STRING => {
          if tag.constructed {
            raise DerError::InvalidTag("GeneralString must be primitive")
          }
          DerValue::GeneralString(decode_utf8(data, content_start, content_end))
        }
        _ => DerValue::Raw(tag, slice_bytes(data, content_start, content_len))
      }
    Application =>
      if tag.constructed {
        if depth >= MAX_DEPTH {
          raise DerError::MaxDepthExceeded
        }
        let (inner, next_cursor) = decode_tlv(
          data,
          content_start,
          content_end,
          depth + 1,
        )
        if next_cursor != content_end {
          raise DerError::TrailingBytes(content_end - next_cursor)
        }
        DerValue::Application(tag.number, inner)
      } else {
        DerValue::Raw(tag, slice_bytes(data, content_start, content_len))
      }
    ContextSpecific =>
      if tag.constructed {
        if depth >= MAX_DEPTH {
          raise DerError::MaxDepthExceeded
        }
        let (inner, next_cursor) = decode_tlv(
          data,
          content_start,
          content_end,
          depth + 1,
        )
        if next_cursor != content_end {
          raise DerError::TrailingBytes(content_end - next_cursor)
        }
        DerValue::Context(tag.number, inner)
      } else {
        DerValue::Raw(tag, slice_bytes(data, content_start, content_len))
      }
    Private => DerValue::Raw(tag, slice_bytes(data, content_start, content_len))
  }
  (value, content_end)
}

///|
/// Strictly decode a single ASN.1 DER value from `data`.
/// Rejects trailing bytes, non-canonical lengths/integers/booleans, indefinite
/// lengths, malformed bit strings, invalid generalized times, and nesting > 64.
pub fn decode_der(data : Bytes) -> DerValue raise DerError {
  let (val, next_pos) = decode_tlv(data, 0, data.length(), 0)
  if next_pos != data.length() {
    raise DerError::TrailingBytes(data.length() - next_pos)
  }
  val
}

///|
/// Decode an explicit `[APPLICATION expected_tag]` DER message and return its inner value.
pub fn decode_application(
  data : Bytes,
  expected_tag : Int32,
) -> DerValue raise DerError {
  let val = decode_der(data)
  match val {
    Application(tag, inner) =>
      if tag == expected_tag {
        inner
      } else {
        raise DerError::TagMismatch(
          expected="APPLICATION[\{expected_tag}]",
          got="APPLICATION[\{tag}]",
        )
      }
    _ =>
      raise DerError::TagMismatch(
        expected="APPLICATION[\{expected_tag}]",
        got=describe_der_tag(val),
      )
  }
}

///|
/// Inspect the leading constructed `[APPLICATION n]` tag number without decoding
/// the full message body.
pub fn peek_application_tag(data : Bytes) -> Int32 raise DerError {
  let (tag, _) = read_tag(data, 0, data.length())
  if tag.class == TagClass::Application && tag.constructed {
    tag.number
  } else {
    raise DerError::TagMismatch(
      expected="APPLICATION(constructed)",
      got=describe_tag(tag),
    )
  }
}

///|
/// Decode a DER `Integer` into a signed 64-bit `Int64`.
pub fn decode_int64(v : DerValue) -> Int64 raise DerError {
  match v {
    Integer(raw) => {
      validate_canonical_integer(raw)
      if raw.length() > 8 {
        raise DerError::InvalidValue("INTEGER overflows Int64")
      }
      let mut acc : Int64 = if (raw[0].to_int() & 0x80) != 0 { -1L } else { 0L }
      for i = 0; i < raw.length(); i = i + 1 {
        acc = (acc << 8) | raw[i].to_int().to_int64()
      }
      acc
    }
    _ =>
      raise DerError::TagMismatch(expected="INTEGER", got=describe_der_tag(v))
  }
}

///|
/// Decode a DER `Integer` into a signed 32-bit `Int`.
pub fn decode_int(v : DerValue) -> Int32 raise DerError {
  let val = decode_int64(v)
  if val < -2147483648L || val > 2147483647L {
    raise DerError::InvalidValue("INTEGER out of Int32 range: \{val}")
  }
  val.to_int()
}

///|
/// Decode a DER `Integer` into an unsigned 32-bit `UInt` (`0..4294967295`).
pub fn decode_uint32(v : DerValue) -> UInt32 raise DerError {
  let val = decode_int64(v)
  if val < 0L || val > 4294967295L {
    raise DerError::InvalidValue("INTEGER out of UInt32 range: \{val}")
  }
  val.reinterpret_as_uint64().to_uint()
}

///|
/// Extract a `String` from `DerValue::GeneralString`.
pub fn decode_general_string(v : DerValue) -> String raise DerError {
  match v {
    GeneralString(s) => s
    _ =>
      raise DerError::TagMismatch(
        expected="GeneralString",
        got=describe_der_tag(v),
      )
  }
}

///|
/// Extract `Bytes` from `DerValue::OctetString`.
pub fn decode_octet_string(v : DerValue) -> Bytes raise DerError {
  match v {
    OctetString(b) => b
    _ =>
      raise DerError::TagMismatch(
        expected="OCTET STRING",
        got=describe_der_tag(v),
      )
  }
}

///|
/// Decode RFC 4120 §5.2.8 `KerberosFlags` (`BIT STRING (SIZE (32..MAX))`).
/// Supports bit strings of >= 32 bits and returns the first 32 bits MSB-first.
pub fn decode_kerberos_flags(v : DerValue) -> UInt32 raise DerError {
  match v {
    BitString(unused, data) => {
      validate_bit_string(unused, data)
      if data.length() < 4 || (data.length() == 4 && unused != 0) {
        let total_bits = data.length() * 8 - unused
        raise DerError::InvalidBitString(
          "KerberosFlags requires at least 32 bits, got \{total_bits}",
        )
      }
      (data[0].to_uint() << 24) |
      (data[1].to_uint() << 16) |
      (data[2].to_uint() << 8) |
      data[3].to_uint()
    }
    _ =>
      raise DerError::TagMismatch(
        expected="BIT STRING",
        got=describe_der_tag(v),
      )
  }
}

///|
/// Extract and validate a `YYYYMMDDHHMMSSZ` timestamp from `DerValue::GeneralizedTime`.
pub fn decode_generalized_time(v : DerValue) -> String raise DerError {
  match v {
    GeneralizedTime(s) => {
      validate_generalized_time(s)
      s
    }
    _ =>
      raise DerError::TagMismatch(
        expected="GeneralizedTime",
        got=describe_der_tag(v),
      )
  }
}

///|
/// Sequential reader for RFC 4120 `SEQUENCE` structures with ascending explicit
/// `[0..n]` context-specific tags. Rejects out-of-order, duplicate, non-context,
/// and unknown trailing fields.
pub struct SeqReader {
  priv items : Array[DerValue]
  priv mut pos : Int32
  priv mut last_tag : Int32
}

///|
/// Create a `SeqReader` over a `DerValue::Sequence`.
pub fn SeqReader::new(val : DerValue) -> SeqReader raise DerError {
  match val {
    Sequence(items) => { items, pos: 0, last_tag: -1, }
    _ =>
      raise DerError::TagMismatch(
        expected="SEQUENCE",
        got=describe_der_tag(val),
      )
  }
}

///|
/// Read a required explicit `[tag]` field in strictly ascending tag order.
pub fn SeqReader::read_required(
  self : SeqReader,
  tag : Int32,
) -> DerValue raise DerError {
  if tag <= self.last_tag {
    raise DerError::InvalidValue(
      "SeqReader tags must be strictly ascending: got [\{tag}] after [\{self.last_tag}]",
    )
  }
  if self.pos >= self.items.length() {
    raise DerError::MissingField("missing required field [\{tag}]")
  }
  match self.items[self.pos] {
    Context(t, inner) =>
      if t == tag {
        self.pos += 1
        self.last_tag = tag
        inner
      } else if t > tag {
        raise DerError::MissingField("missing required field [\{tag}]")
      } else {
        raise DerError::TagMismatch(
          expected="CONTEXT[\{tag}]",
          got="CONTEXT[\{t}]",
        )
      }
    other =>
      raise DerError::TagMismatch(
        expected="CONTEXT[\{tag}]",
        got=describe_der_tag(other),
      )
  }
}

///|
/// Read an optional explicit `[tag]` field in strictly ascending tag order.
pub fn SeqReader::read_optional(
  self : SeqReader,
  tag : Int32,
) -> DerValue? raise DerError {
  if tag <= self.last_tag {
    raise DerError::InvalidValue(
      "SeqReader tags must be strictly ascending: got [\{tag}] after [\{self.last_tag}]",
    )
  }
  if self.pos >= self.items.length() {
    self.last_tag = tag
    return None
  }
  match self.items[self.pos] {
    Context(t, inner) =>
      if t == tag {
        self.pos += 1
        self.last_tag = tag
        Some(inner)
      } else if t > tag {
        self.last_tag = tag
        None
      } else {
        raise DerError::TagMismatch(
          expected="CONTEXT[>=\{tag}]",
          got="CONTEXT[\{t}]",
        )
      }
    other =>
      raise DerError::TagMismatch(
        expected="CONTEXT[\{tag}]",
        got=describe_der_tag(other),
      )
  }
}

///|
/// Verify all fields in the `SEQUENCE` have been consumed; rejects unknown or
/// out-of-order trailing fields.
pub fn SeqReader::finish(self : SeqReader) -> Unit raise DerError {
  if self.pos < self.items.length() {
    raise DerError::TagMismatch(
      expected="end of SEQUENCE",
      got=describe_der_tag(self.items[self.pos]),
    )
  }
}
