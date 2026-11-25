///|
/// Encode a MoonBit String into UTF-8 Bytes (pure implementation, zero FFI).
fn utf8_encode(s : String) -> Bytes {
  let out : Array[Byte] = []
  for ch in s {
    let cp = ch.to_int()
    if cp < 0x80 {
      out.push(cp.to_byte())
    } else if cp < 0x800 {
      out.push((0xC0 | (cp >> 6)).to_byte())
      out.push((0x80 | (cp & 0x3F)).to_byte())
    } else if cp < 0x10000 {
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
  Bytes::from_array(out)
}

///|
/// RFC 4120 default salt: realm + components concatenated without separator.
fn default_salt(realm : String, name : @types.PrincipalName) -> String {
  let buf = StringBuilder()
  buf.write_string(realm)
  for comp in name.name_string {
    buf.write_string(comp)
  }
  buf.to_string()
}

///|
/// RFC 4120 §6.2 principal equality compares name components regardless of `name_type`.
fn principal_names_equal(
  a : @types.PrincipalName,
  b : @types.PrincipalName,
) -> Bool {
  a.name_string == b.name_string
}

///|
/// Collision-free canonical lookup key for a principal's components.
fn principal_lookup_key(name : @types.PrincipalName) -> String {
  let buf = StringBuilder()
  buf.write_string(name.name_string.length().to_string())
  for comp in name.name_string {
    buf.write_string("|")
    buf.write_string(comp.length().to_string())
    buf.write_string(":")
    buf.write_string(comp)
  }
  buf.to_string()
}

///|
fn abs_i64(x : Int64) -> Int64 {
  if x < 0L {
    -x
  } else {
    x
  }
}

///|
fn map_crypto_error(e : @crypto.CryptoError) -> ProtocolError {
  match e {
    @crypto.CryptoError::UnsupportedEnctype(et) =>
      ProtocolError::UnsupportedEnctype(et)
    other => ProtocolError::Crypto(other)
  }
}

///|
fn enctype_from_int(et : Int32) -> @crypto.Enctype raise ProtocolError {
  @crypto.Enctype::from_int(et) catch {
    e => raise map_crypto_error(e)
  }
}

///|
fn derive_string_to_key(
  etype : @crypto.Enctype,
  password : Bytes,
  salt : String,
  s2kparams : Bytes?,
) -> Bytes raise ProtocolError {
  let salt_bytes = utf8_encode(salt)
  @crypto.string_to_key(etype, password, salt_bytes, s2kparams) catch {
    e => raise map_crypto_error(e)
  }
}

///|
fn encrypt_data(
  etype : @crypto.Enctype,
  key : Bytes,
  kvno : UInt32?,
  usage : Int32,
  plaintext : Bytes,
  rng : @crypto.DeterministicRng,
) -> @types.EncryptedData raise ProtocolError {
  let confounder = rng.next_bytes(etype.confounder_size())
  let cipher = @crypto.encrypt(etype, key, usage, plaintext, confounder) catch {
    e => raise map_crypto_error(e)
  }
  { etype: etype.to_int(), kvno, cipher, }
}

///|
fn decrypt_data(
  enc : @types.EncryptedData,
  key : Bytes,
  usage : Int32,
) -> Bytes raise ProtocolError {
  let etype = enctype_from_int(enc.etype)
  @crypto.decrypt(etype, key, usage, enc.cipher) catch {
    e => raise map_crypto_error(e)
  }
}

///|
fn unix_to_ktime(epoch_secs : Int64) -> String raise ProtocolError {
  @types.unix_to_kerberos_time(epoch_secs) catch {
    e => raise ProtocolError::Der(e)
  }
}

///|
fn ktime_to_unix(s : String) -> Int64 raise ProtocolError {
  @types.kerberos_time_to_unix(s) catch {
    e => raise ProtocolError::Der(e)
  }
}

///|
fn next_nonce(rng : @crypto.DeterministicRng) -> UInt32 {
  rng.next_u32() & 0x7FFFFFFFU
}
