///|
/// Cryptographic errors returned by RFC 3961 / RFC 3962 / RFC 8009 operations.
#derive(Eq, Debug)
pub suberror CryptoError {
  UnsupportedEnctype(Int32)
  UnsupportedChecksumType(Int32)
  InvalidKeyLength(expected~ : Int32, got~ : Int32)
  InvalidConfounderLength(expected~ : Int32, got~ : Int32)
  CiphertextTooShort
  IntegrityCheckFailed
  InvalidS2kParams(String)
  InvalidIterationCount
  InvalidInput(String)
}

///|
pub impl Show for CryptoError with fn output(self, logger) {
  match self {
    UnsupportedEnctype(n) => logger.write_string("UnsupportedEnctype(\{n})")
    UnsupportedChecksumType(n) =>
      logger.write_string("UnsupportedChecksumType(\{n})")
    InvalidKeyLength(expected~, got~) =>
      logger.write_string("InvalidKeyLength(expected=\{expected}, got=\{got})")
    InvalidConfounderLength(expected~, got~) =>
      logger.write_string(
        "InvalidConfounderLength(expected=\{expected}, got=\{got})",
      )
    CiphertextTooShort => logger.write_string("CiphertextTooShort")
    IntegrityCheckFailed => logger.write_string("IntegrityCheckFailed")
    InvalidS2kParams(msg) => logger.write_string("InvalidS2kParams(\{msg})")
    InvalidIterationCount => logger.write_string("InvalidIterationCount")
    InvalidInput(msg) => logger.write_string("InvalidInput(\{msg})")
  }
}

///|
/// Supported Kerberos 5 encryption types (RFC 3962 & RFC 8009).
#derive(Eq, Debug)
pub(all) enum Enctype {
  Aes128CtsHmacSha1_96
  Aes256CtsHmacSha1_96
  Aes128CtsHmacSha256_128
  Aes256CtsHmacSha384_192
}

///|
pub impl Show for Enctype with fn output(self, logger) {
  match self {
    Aes128CtsHmacSha1_96 => logger.write_string("Aes128CtsHmacSha1_96")
    Aes256CtsHmacSha1_96 => logger.write_string("Aes256CtsHmacSha1_96")
    Aes128CtsHmacSha256_128 => logger.write_string("Aes128CtsHmacSha256_128")
    Aes256CtsHmacSha384_192 => logger.write_string("Aes256CtsHmacSha384_192")
  }
}

///|
/// Supported Kerberos 5 keyed checksum types (RFC 3962 & RFC 8009).
#derive(Eq, Debug)
pub(all) enum ChecksumType {
  HmacSha1_96Aes128
  HmacSha1_96Aes256
  HmacSha256_128Aes128
  HmacSha384_192Aes256
}

///|
pub impl Show for ChecksumType with fn output(self, logger) {
  match self {
    HmacSha1_96Aes128 => logger.write_string("HmacSha1_96Aes128")
    HmacSha1_96Aes256 => logger.write_string("HmacSha1_96Aes256")
    HmacSha256_128Aes128 => logger.write_string("HmacSha256_128Aes128")
    HmacSha384_192Aes256 => logger.write_string("HmacSha384_192Aes256")
  }
}

///|
/// RFC 4120 §7.5.1 Key Usage numbers.
pub const KU_AS_REQ_PA_ENC_TIMESTAMP : Int32 = 1

///|
pub const KU_TICKET : Int32 = 2

///|
pub const KU_AS_REP_ENCPART : Int32 = 3

///|
pub const KU_TGS_REQ_KDC_REQ_BODY_AD : Int32 = 4

///|
pub const KU_TGS_REQ_KDC_REQ_BODY_AD_SUBKEY : Int32 = 5

///|
pub const KU_TGS_REQ_AUTH_CKSUM : Int32 = 6

///|
pub const KU_TGS_REQ_AUTH : Int32 = 7

///|
pub const KU_TGS_REP_ENCPART_SESSION_KEY : Int32 = 8

///|
pub const KU_TGS_REP_ENCPART_AUTH_SUBKEY : Int32 = 9

///|
pub const KU_AP_REQ_AUTH_CKSUM : Int32 = 10

///|
pub const KU_AP_REQ_AUTH : Int32 = 11

///|
pub const KU_AP_REP_ENCPART : Int32 = 12

///|
pub const KU_KRB_PRIV : Int32 = 13

///|
pub const KU_KRB_CRED : Int32 = 14

///|
pub const KU_KRB_SAFE : Int32 = 15

///|
pub fn Enctype::to_int(self : Enctype) -> Int32 {
  match self {
    Aes128CtsHmacSha1_96 => 17
    Aes256CtsHmacSha1_96 => 18
    Aes128CtsHmacSha256_128 => 19
    Aes256CtsHmacSha384_192 => 20
  }
}

///|
pub fn Enctype::from_int(n : Int32) -> Enctype raise CryptoError {
  match n {
    17 => Aes128CtsHmacSha1_96
    18 => Aes256CtsHmacSha1_96
    19 => Aes128CtsHmacSha256_128
    20 => Aes256CtsHmacSha384_192
    _ => raise UnsupportedEnctype(n)
  }
}

///|
pub fn Enctype::key_size(self : Enctype) -> Int32 {
  match self {
    Aes128CtsHmacSha1_96 | Aes128CtsHmacSha256_128 => 16
    Aes256CtsHmacSha1_96 | Aes256CtsHmacSha384_192 => 32
  }
}

///|
pub fn Enctype::mac_size(self : Enctype) -> Int32 {
  match self {
    Aes128CtsHmacSha1_96 | Aes256CtsHmacSha1_96 => 12
    Aes128CtsHmacSha256_128 => 16
    Aes256CtsHmacSha384_192 => 24
  }
}

///|
pub fn Enctype::confounder_size(self : Enctype) -> Int32 {
  match self {
    Aes128CtsHmacSha1_96
    | Aes256CtsHmacSha1_96
    | Aes128CtsHmacSha256_128
    | Aes256CtsHmacSha384_192 => 16
  }
}

///|
pub fn Enctype::default_checksum_type(self : Enctype) -> ChecksumType {
  match self {
    Aes128CtsHmacSha1_96 => HmacSha1_96Aes128
    Aes256CtsHmacSha1_96 => HmacSha1_96Aes256
    Aes128CtsHmacSha256_128 => HmacSha256_128Aes128
    Aes256CtsHmacSha384_192 => HmacSha384_192Aes256
  }
}

///|
pub fn Enctype::name(self : Enctype) -> String {
  match self {
    Aes128CtsHmacSha1_96 => "aes128-cts-hmac-sha1-96"
    Aes256CtsHmacSha1_96 => "aes256-cts-hmac-sha1-96"
    Aes128CtsHmacSha256_128 => "aes128-cts-hmac-sha256-128"
    Aes256CtsHmacSha384_192 => "aes256-cts-hmac-sha384-192"
  }
}

///|
pub fn ChecksumType::to_int(self : ChecksumType) -> Int32 {
  match self {
    HmacSha1_96Aes128 => 15
    HmacSha1_96Aes256 => 16
    HmacSha256_128Aes128 => 19
    HmacSha384_192Aes256 => 20
  }
}

///|
pub fn ChecksumType::from_int(n : Int32) -> ChecksumType raise CryptoError {
  match n {
    15 => HmacSha1_96Aes128
    16 => HmacSha1_96Aes256
    19 => HmacSha256_128Aes128
    20 => HmacSha384_192Aes256
    _ => raise UnsupportedChecksumType(n)
  }
}

///|
pub fn ChecksumType::mac_size(self : ChecksumType) -> Int32 {
  match self {
    HmacSha1_96Aes128 | HmacSha1_96Aes256 => 12
    HmacSha256_128Aes128 => 16
    HmacSha384_192Aes256 => 24
  }
}

///|
/// Return the Kerberos 5 encryption type required for this keyed checksum type
/// per RFC 3962 §6 and RFC 8009 §6.
pub fn ChecksumType::required_enctype(self : ChecksumType) -> Enctype {
  match self {
    HmacSha1_96Aes128 => Aes128CtsHmacSha1_96
    HmacSha1_96Aes256 => Aes256CtsHmacSha1_96
    HmacSha256_128Aes128 => Aes128CtsHmacSha256_128
    HmacSha384_192Aes256 => Aes256CtsHmacSha384_192
  }
}

///|
/// Constant-time equality comparison for byte slices to mitigate timing side channels.
pub fn ct_eq(a : Bytes, b : Bytes) -> Bool {
  let len = a.length()
  if len != b.length() {
    return false
  }
  let mut diff : Int32 = 0
  for i = 0; i < len; i = i + 1 {
    diff = diff | (a[i].to_int() ^ b[i].to_int())
  }
  diff == 0
}

///|
fn read_be_u32(b : Bytes, off : Int32) -> UInt32 {
  (b[off].to_uint() << 24) |
  (b[off + 1].to_uint() << 16) |
  (b[off + 2].to_uint() << 8) |
  b[off + 3].to_uint()
}

///|
fn write_be_u32(buf : FixedArray[Byte], off : Int32, v : UInt32) -> Unit {
  buf[off] = ((v >> 24) & 0xFFU).to_byte()
  buf[off + 1] = ((v >> 16) & 0xFFU).to_byte()
  buf[off + 2] = ((v >> 8) & 0xFFU).to_byte()
  buf[off + 3] = (v & 0xFFU).to_byte()
}

///|
fn write_be_u64(buf : FixedArray[Byte], off : Int32, v : UInt64) -> Unit {
  buf[off] = ((v >> 56) & 0xFFUL).to_byte()
  buf[off + 1] = ((v >> 48) & 0xFFUL).to_byte()
  buf[off + 2] = ((v >> 40) & 0xFFUL).to_byte()
  buf[off + 3] = ((v >> 32) & 0xFFUL).to_byte()
  buf[off + 4] = ((v >> 24) & 0xFFUL).to_byte()
  buf[off + 5] = ((v >> 16) & 0xFFUL).to_byte()
  buf[off + 6] = ((v >> 8) & 0xFFUL).to_byte()
  buf[off + 7] = (v & 0xFFUL).to_byte()
}

///|
fn fixed_to_bytes(arr : FixedArray[Byte], len : Int32) -> Bytes {
  Bytes::makei(len, fn(i) { arr[i] })
}

///|
fn bytes_concat(a : Bytes, b : Bytes) -> Bytes {
  let alen = a.length()
  let blen = b.length()
  Bytes::makei(alen + blen, fn(i) { if i < alen { a[i] } else { b[i - alen] } })
}

///|
fn bytes_slice(a : Bytes, start : Int32, len : Int32) -> Bytes {
  Bytes::makei(len, fn(i) { a[start + i] })
}

///|
fn ascii_string_to_bytes(s : String) -> Bytes {
  let len = s.length()
  Bytes::makei(len, fn(i) { (s.code_unit_at(i).to_int() & 0xFF).to_byte() })
}
