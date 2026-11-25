///|
/// Maximum Unix timestamp representable as 4-digit year (`9999-12-31T23:59:59Z`).
const MAX_KERBEROS_EPOCH_SECS : Int64 = 253402300799L

///|
const SECS_PER_DAY : Int64 = 86400L

///|
fn write_2digits(sb : StringBuilder, n : Int32) -> Unit {
  sb.write_char(Int32::unsafe_to_char(0x30 + n / 10))
  sb.write_char(Int32::unsafe_to_char(0x30 + n % 10))
}

///|
fn write_4digits(sb : StringBuilder, n : Int32) -> Unit {
  sb.write_char(Int32::unsafe_to_char(0x30 + n / 1000))
  sb.write_char(Int32::unsafe_to_char(0x30 + n / 100 % 10))
  sb.write_char(Int32::unsafe_to_char(0x30 + n / 10 % 10))
  sb.write_char(Int32::unsafe_to_char(0x30 + n % 10))
}

///|
/// Convert Unix epoch seconds (`1970-01-01T00:00:00Z` .. `9999-12-31T23:59:59Z`)
/// into an RFC 4120 `KerberosTime` (`YYYYMMDDHHMMSSZ`) using pure Gregorian
/// calendar arithmetic (zero FFI).
pub fn unix_to_kerberos_time(epoch_secs : Int64) -> String raise @asn1.DerError {
  if epoch_secs < 0L || epoch_secs > MAX_KERBEROS_EPOCH_SECS {
    raise @asn1.DerError::InvalidGeneralizedTime(
      "epoch_secs out of 1970..9999 range: \{epoch_secs}",
    )
  }
  let days = epoch_secs / SECS_PER_DAY
  let rem = (epoch_secs % SECS_PER_DAY).to_int()
  let hour = rem / 3600
  let minute = rem % 3600 / 60
  let second = rem % 60
  // Civil date from days since 1970-01-01 (Howard Hinnant's proleptic Gregorian algorithm).
  let z = days + 719468L
  let era = (if z >= 0L { z } else { z - 146096L }) / 146097L
  let doe = z - era * 146097L
  let yoe = (doe - doe / 1460L + doe / 36524L - doe / 146096L) / 365L
  let y = yoe + era * 400L
  let doy = doe - (365L * yoe + yoe / 4L - yoe / 100L)
  let mp = (5L * doy + 2L) / 153L
  let day = (doy - (153L * mp + 2L) / 5L + 1L).to_int()
  let month = (mp + (if mp < 10L { 3L } else { -9L })).to_int()
  let year = (y + (if month <= 2 { 1L } else { 0L })).to_int()
  let sb = StringBuilder()
  write_4digits(sb, year)
  write_2digits(sb, month)
  write_2digits(sb, day)
  write_2digits(sb, hour)
  write_2digits(sb, minute)
  write_2digits(sb, second)
  sb.write_char('Z')
  sb.to_string()
}

///|
/// Strictly validate an RFC 4120 `KerberosTime` (`YYYYMMDDHHMMSSZ`) and convert
/// it to Unix epoch seconds.
pub fn kerberos_time_to_unix(s : String) -> Int64 raise @asn1.DerError {
  @asn1.validate_generalized_time(s)
  let d = fn(idx : Int32) -> Int32 { s[idx].to_int() - 0x30 }
  let year = d(0) * 1000 + d(1) * 100 + d(2) * 10 + d(3)
  let month = d(4) * 10 + d(5)
  let day = d(6) * 10 + d(7)
  let hour = d(8) * 10 + d(9)
  let minute = d(10) * 10 + d(11)
  let second = d(12) * 10 + d(13)
  let y = year.to_int64() - (if month <= 2 { 1L } else { 0L })
  let era = (if y >= 0L { y } else { y - 399L }) / 400L
  let yoe = y - era * 400L
  let m_adj = month.to_int64() + (if month > 2 { -3L } else { 9L })
  let doy = (153L * m_adj + 2L) / 5L + day.to_int64() - 1L
  let doe = yoe * 365L + yoe / 4L - yoe / 100L + doy
  let days = era * 146097L + doe - 719468L
  days * SECS_PER_DAY +
  hour.to_int64() * 3600L +
  minute.to_int64() * 60L +
  second.to_int64()
}

///|
/// RFC 4120 §7.2.2 TCP record framing: prepend a 4-byte big-endian unsigned
/// length prefix to `payload`.
pub fn encode_tcp_frame(payload : Bytes) -> Bytes {
  let len = payload.length()
  Bytes::makei(4 + len, fn(i) {
    if i == 0 {
      ((len >> 24) & 0x7F).to_byte()
    } else if i == 1 {
      ((len >> 16) & 0xFF).to_byte()
    } else if i == 2 {
      ((len >> 8) & 0xFF).to_byte()
    } else if i == 3 {
      (len & 0xFF).to_byte()
    } else {
      payload[i - 4]
    }
  })
}

///|
/// RFC 4120 §7.2.2 TCP record deframing: decode a single length-prefixed
/// Kerberos message from `frame`, returning `(payload, total_consumed)`.
/// Rejects reserved high-bit-set lengths and truncated frames.
pub fn decode_tcp_frame(frame : Bytes) -> (Bytes, Int32) raise @asn1.DerError {
  if frame.length() < 4 {
    raise @asn1.DerError::UnexpectedEof
  }
  let b0 = frame[0].to_int()
  if (b0 & 0x80) != 0 {
    raise @asn1.DerError::InvalidLength(
      "TCP frame length high bit is reserved and must be 0",
    )
  }
  let len = (b0 << 24) |
    (frame[1].to_int() << 16) |
    (frame[2].to_int() << 8) |
    frame[3].to_int()
  if len > frame.length() - 4 {
    raise @asn1.DerError::UnexpectedEof
  }
  let payload = Bytes::makei(len, fn(i) { frame[4 + i] })
  (payload, 4 + len)
}
