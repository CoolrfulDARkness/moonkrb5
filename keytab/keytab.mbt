///|
/// MIT Kerberos `.keytab` binary format version constants.
const KEYTAB_VERSION_V1 : Int32 = 0x0501

///|
const KEYTAB_VERSION_V2 : Int32 = 0x0502

///|
/// Default Kerberos principal name type (`KRB5_NT_PRINCIPAL`) used for v1 entries.
const NT_PRINCIPAL : Int32 = 1

///|
/// Maximum length representable by a 16-bit unsigned length prefix.
const MAX_UINT16 : Int32 = 65535

///|
/// Maximum signed 32-bit positive integer for `entry_size`.
const MAX_INT32 : Int64 = 2147483647L

///|
/// Errors raised while encoding or decoding MIT Kerberos keytab files.
#derive(Eq, Debug)
pub suberror KeytabError {
  UnexpectedEof
  UnsupportedVersion(Int32)
  InvalidEntrySize(Int32)
  InvalidUtf8
  TruncatedEntry
  FieldTooLarge(String)
  KeyNotFound
}

///|
pub impl Show for KeytabError with fn output(self, logger) {
  match self {
    UnexpectedEof => logger.write_string("UnexpectedEof")
    UnsupportedVersion(v) => {
      logger.write_string("UnsupportedVersion(")
      logger.write_string(v.to_string())
      logger.write_string(")")
    }
    InvalidEntrySize(sz) => {
      logger.write_string("InvalidEntrySize(")
      logger.write_string(sz.to_string())
      logger.write_string(")")
    }
    InvalidUtf8 => logger.write_string("InvalidUtf8")
    TruncatedEntry => logger.write_string("TruncatedEntry")
    FieldTooLarge(name) => {
      logger.write_string("FieldTooLarge(")
      logger.write_string(name)
      logger.write_string(")")
    }
    KeyNotFound => logger.write_string("KeyNotFound")
  }
}

///|
/// A single key entry stored in a MIT Kerberos keytab file.
#derive(Eq, Debug)
pub(all) struct KeytabEntry {
  realm : String
  components : Array[String]
  name_type : Int32
  timestamp : UInt32
  kvno : UInt32
  etype : Int32
  key : Bytes
}

///|
pub impl Show for KeytabEntry with fn output(self, logger) {
  logger.write_string("KeytabEntry(")
  for i = 0; i < self.components.length(); i = i + 1 {
    if i > 0 {
      logger.write_string("/")
    }
    logger.write_string(self.components[i])
  }
  logger.write_string("@")
  logger.write_string(self.realm)
  logger.write_string(", kvno=")
  logger.write_string(self.kvno.to_string())
  logger.write_string(", etype=")
  logger.write_string(self.etype.to_string())
  logger.write_string(", key_len=")
  logger.write_string(self.key.length().to_string())
  logger.write_string(")")
}

///|
/// A decoded or in-memory MIT Kerberos keytab file (`0x0502` or `0x0501`).
#derive(Eq, Debug)
pub(all) struct Keytab {
  version : Int32
  entries : Array[KeytabEntry]
}

///|
pub impl Show for Keytab with fn output(self, logger) {
  logger.write_string("Keytab(version=")
  logger.write_string(self.version.to_string())
  logger.write_string(", entries=")
  logger.write_string(self.entries.length().to_string())
  logger.write_string(")")
}

///|
/// Create a new empty keytab with default MIT format version `0x0502`.
pub fn Keytab::new() -> Keytab {
  { version: KEYTAB_VERSION_V2, entries: [], }
}

///|
/// Append a `KeytabEntry` to this keytab.
pub fn Keytab::add_entry(self : Keytab, entry : KeytabEntry) -> Unit {
  self.entries.push(entry)
}

///|
fn write_u16_be(out : Array[Byte], value : Int32) -> Unit {
  out.push(((value >> 8) & 0xFF).to_byte())
  out.push((value & 0xFF).to_byte())
}

///|
fn write_u32_be(out : Array[Byte], value : UInt32) -> Unit {
  out.push(((value >> 24) & 0xFFU).to_byte())
  out.push(((value >> 16) & 0xFFU).to_byte())
  out.push(((value >> 8) & 0xFFU).to_byte())
  out.push((value & 0xFFU).to_byte())
}

///|
fn read_u16_be(data : Bytes, offset : Int32) -> Int32 {
  (data[offset].to_int() << 8) | data[offset + 1].to_int()
}

///|
fn read_u32_be(data : Bytes, offset : Int32) -> UInt32 {
  (data[offset].to_uint() << 24) |
  (data[offset + 1].to_uint() << 16) |
  (data[offset + 2].to_uint() << 8) |
  data[offset + 3].to_uint()
}

///|
fn read_i32_be(data : Bytes, offset : Int32) -> Int32 {
  read_u32_be(data, offset).reinterpret_as_int()
}

///|
fn encode_utf8(s : String) -> Array[Byte] {
  let out : Array[Byte] = []
  for ch in s {
    let cp = ch.to_int()
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
fn decode_utf8(
  data : Bytes,
  start : Int32,
  len : Int32,
) -> String raise KeytabError {
  let end = start + len
  let sb = StringBuilder()
  let mut i = start
  while i < end {
    let b0 = data[i].to_int()
    if b0 <= 0x7F {
      sb.write_char(b0.unsafe_to_char())
      i += 1
    } else if b0 >= 0xC2 && b0 <= 0xDF {
      if i + 1 >= end {
        raise InvalidUtf8
      }
      let b1 = data[i + 1].to_int()
      if b1 < 0x80 || b1 > 0xBF {
        raise InvalidUtf8
      }
      let cp = ((b0 & 0x1F) << 6) | (b1 & 0x3F)
      sb.write_char(cp.unsafe_to_char())
      i += 2
    } else if b0 >= 0xE0 && b0 <= 0xEF {
      if i + 2 >= end {
        raise InvalidUtf8
      }
      let b1 = data[i + 1].to_int()
      let b2 = data[i + 2].to_int()
      if b2 < 0x80 || b2 > 0xBF {
        raise InvalidUtf8
      }
      if b0 == 0xE0 {
        if b1 < 0xA0 || b1 > 0xBF {
          raise InvalidUtf8
        }
      } else if b0 == 0xED {
        if b1 < 0x80 || b1 > 0x9F {
          raise InvalidUtf8
        }
      } else if b1 < 0x80 || b1 > 0xBF {
        raise InvalidUtf8
      }
      let cp = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F)
      sb.write_char(cp.unsafe_to_char())
      i += 3
    } else if b0 >= 0xF0 && b0 <= 0xF4 {
      if i + 3 >= end {
        raise InvalidUtf8
      }
      let b1 = data[i + 1].to_int()
      let b2 = data[i + 2].to_int()
      let b3 = data[i + 3].to_int()
      if b2 < 0x80 || b2 > 0xBF || b3 < 0x80 || b3 > 0xBF {
        raise InvalidUtf8
      }
      if b0 == 0xF0 {
        if b1 < 0x90 || b1 > 0xBF {
          raise InvalidUtf8
        }
      } else if b0 == 0xF4 {
        if b1 < 0x80 || b1 > 0x8F {
          raise InvalidUtf8
        }
      } else if b1 < 0x80 || b1 > 0xBF {
        raise InvalidUtf8
      }
      let cp = ((b0 & 0x07) << 18) |
        ((b1 & 0x3F) << 12) |
        ((b2 & 0x3F) << 6) |
        (b3 & 0x3F)
      sb.write_char(cp.unsafe_to_char())
      i += 4
    } else {
      raise InvalidUtf8
    }
  }
  sb.to_string()
}

///|
fn write_counted_octet_string(
  out : Array[Byte],
  bytes : Array[Byte],
  field_name : String,
) -> Unit raise KeytabError {
  let len = bytes.length()
  if len > MAX_UINT16 {
    raise FieldTooLarge(field_name)
  }
  write_u16_be(out, len)
  for b in bytes {
    out.push(b)
  }
}

///|
fn read_counted_octet_string(
  data : Bytes,
  cur : Int32,
  entry_end : Int32,
) -> (String, Int32) raise KeytabError {
  if entry_end - cur < 2 {
    raise TruncatedEntry
  }
  let len = read_u16_be(data, cur)
  let str_start = cur + 2
  if entry_end - str_start < len {
    raise TruncatedEntry
  }
  let s = decode_utf8(data, str_start, len)
  (s, str_start + len)
}

///|
/// Encode this `Keytab` into MIT Kerberos binary format (`0x0502` or `0x0501`).
pub fn Keytab::encode(self : Keytab) -> Bytes raise KeytabError {
  if self.version != KEYTAB_VERSION_V2 && self.version != KEYTAB_VERSION_V1 {
    raise UnsupportedVersion(self.version)
  }
  let out : Array[Byte] = []
  write_u16_be(out, self.version)
  for entry in self.entries {
    let body : Array[Byte] = []
    let num_components = if self.version == KEYTAB_VERSION_V1 {
      entry.components.length() + 1
    } else {
      entry.components.length()
    }
    if num_components > MAX_UINT16 {
      raise FieldTooLarge("components")
    }
    write_u16_be(body, num_components)
    let realm_bytes = encode_utf8(entry.realm)
    write_counted_octet_string(body, realm_bytes, "realm")
    for comp in entry.components {
      let comp_bytes = encode_utf8(comp)
      write_counted_octet_string(body, comp_bytes, "component")
    }
    if self.version == KEYTAB_VERSION_V2 {
      write_u32_be(body, entry.name_type.reinterpret_as_uint())
    }
    write_u32_be(body, entry.timestamp)
    if entry.kvno > 255U {
      body.push(b'\x00')
    } else {
      body.push(entry.kvno.to_byte())
    }
    if entry.etype < 0 || entry.etype > MAX_UINT16 {
      raise FieldTooLarge("etype")
    }
    write_u16_be(body, entry.etype)
    let key_len = entry.key.length()
    if key_len > MAX_UINT16 {
      raise FieldTooLarge("key")
    }
    write_u16_be(body, key_len)
    for i = 0; i < key_len; i = i + 1 {
      body.push(entry.key[i])
    }
    if entry.kvno > 255U {
      write_u32_be(body, entry.kvno)
    }
    let body_len = body.length()
    if body_len.to_int64() > MAX_INT32 {
      raise FieldTooLarge("entry")
    }
    write_u32_be(out, body_len.reinterpret_as_uint())
    for b in body {
      out.push(b)
    }
  }
  Bytes::from_array(out)
}

///|
fn decode_entry(
  data : Bytes,
  version : Int32,
  start : Int32,
  entry_end : Int32,
) -> KeytabEntry raise KeytabError {
  let mut cur = start
  if entry_end - cur < 2 {
    raise TruncatedEntry
  }
  let raw_num_components = read_u16_be(data, cur)
  cur += 2
  let num_components = if version == KEYTAB_VERSION_V1 {
    if raw_num_components == 0 {
      raise TruncatedEntry
    }
    raw_num_components - 1
  } else {
    raw_num_components
  }
  let (realm, next_cur) = read_counted_octet_string(data, cur, entry_end)
  cur = next_cur
  let components : Array[String] = []
  for _i = 0; _i < num_components; _i = _i + 1 {
    let (comp, comp_next) = read_counted_octet_string(data, cur, entry_end)
    components.push(comp)
    cur = comp_next
  }
  let name_type = if version == KEYTAB_VERSION_V2 {
    if entry_end - cur < 4 {
      raise TruncatedEntry
    }
    let nt = read_i32_be(data, cur)
    cur += 4
    nt
  } else {
    NT_PRINCIPAL
  }
  if entry_end - cur < 4 {
    raise TruncatedEntry
  }
  let timestamp = read_u32_be(data, cur)
  cur += 4
  if entry_end - cur < 1 {
    raise TruncatedEntry
  }
  let vno8 = data[cur].to_uint()
  cur += 1
  if entry_end - cur < 4 {
    raise TruncatedEntry
  }
  let etype = read_u16_be(data, cur)
  cur += 2
  let key_len = read_u16_be(data, cur)
  cur += 2
  if entry_end - cur < key_len {
    raise TruncatedEntry
  }
  let key_arr : Array[Byte] = Array(capacity=key_len)
  for i = 0; i < key_len; i = i + 1 {
    key_arr.push(data[cur + i])
  }
  cur += key_len
  let mut kvno = vno8
  if entry_end - cur >= 4 {
    let vno32 = read_u32_be(data, cur)
    if vno32 != 0U || vno8 == 0U {
      kvno = vno32
    }
  }
  {
    realm,
    components,
    name_type,
    timestamp,
    kvno,
    etype,
    key: Bytes::from_array(key_arr),
  }
}

///|
/// Decode a MIT Kerberos `.keytab` binary buffer (`0x0502` or `0x0501`).
pub fn Keytab::decode(data : Bytes) -> Keytab raise KeytabError {
  let total_len = data.length()
  if total_len < 2 {
    raise UnexpectedEof
  }
  let version = read_u16_be(data, 0)
  if version != KEYTAB_VERSION_V2 && version != KEYTAB_VERSION_V1 {
    raise UnsupportedVersion(version)
  }
  let entries : Array[KeytabEntry] = []
  let mut pos = 2
  while pos < total_len {
    if total_len - pos < 4 {
      raise UnexpectedEof
    }
    let entry_size = read_i32_be(data, pos)
    pos += 4
    if entry_size == 0 {
      raise InvalidEntrySize(0)
    } else if entry_size < 0 {
      let hole_len = -entry_size.to_int64()
      let remaining = (total_len - pos).to_int64()
      if hole_len > remaining {
        raise TruncatedEntry
      }
      pos += hole_len.to_int()
    } else {
      let entry_len = entry_size.to_int64()
      let remaining = (total_len - pos).to_int64()
      if entry_len > remaining {
        raise TruncatedEntry
      }
      let entry_end = pos + entry_size
      let entry = decode_entry(data, version, pos, entry_end)
      entries.push(entry)
      pos = entry_end
    }
  }
  { version, entries, }
}

///|
/// Return all keytab entries matching the given `realm` and `components`.
pub fn Keytab::find_all_for_principal(
  self : Keytab,
  realm : String,
  components : Array[String],
) -> Array[KeytabEntry] {
  let matched : Array[KeytabEntry] = []
  for entry in self.entries {
    if entry.realm == realm && entry.components == components {
      matched.push(entry)
    }
  }
  matched
}

///|
/// Find a key entry matching `realm`, `components`, and `etype`.
/// When `kvno` is omitted, selects the matching entry with the highest `kvno`.
pub fn Keytab::find_key(
  self : Keytab,
  realm : String,
  components : Array[String],
  etype : Int32,
  kvno? : UInt32,
) -> KeytabEntry? {
  match kvno {
    Some(target_kvno) => {
      for entry in self.entries {
        if entry.realm == realm &&
          entry.components == components &&
          entry.etype == etype &&
          entry.kvno == target_kvno {
          return Some(entry)
        }
      }
      None
    }
    None => {
      let mut best : KeytabEntry? = None
      for entry in self.entries {
        if entry.realm == realm &&
          entry.components == components &&
          entry.etype == etype {
          match best {
            None => best = Some(entry)
            Some(prev) => if entry.kvno > prev.kvno { best = Some(entry) }
          }
        }
      }
      best
    }
  }
}

///|
/// Find a key entry matching `realm`, `components`, and `etype`, raising
/// `KeyNotFound` if no matching entry exists.
pub fn Keytab::get_key(
  self : Keytab,
  realm : String,
  components : Array[String],
  etype : Int32,
  kvno? : UInt32,
) -> KeytabEntry raise KeytabError {
  let found = match kvno {
    Some(k) => self.find_key(realm, components, etype, kvno=k)
    None => self.find_key(realm, components, etype)
  }
  match found {
    Some(entry) => entry
    None => raise KeyNotFound
  }
}
