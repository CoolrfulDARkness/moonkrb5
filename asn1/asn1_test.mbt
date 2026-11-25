///|
fn must_hex(s : String) -> Bytes {
  @asn1.hex_decode(s) catch {
    e => abort("invalid test hex: \{e}")
  }
}

///|
fn[T] expect_err(f : () -> T raise @asn1.DerError) -> @asn1.DerError raise {
  let caught : @asn1.DerError? = try {
    ignore(f())
    None
  } catch {
    e => Some(e)
  }
  match caught {
    Some(e) => e
    None => fail("expected DerError, but succeeded")
  }
}

///|
test "integer boundaries and exact DER wire encodings" {
  let cases : Array[(Int32, String)] = [
    (0, "020100"),
    (1, "020101"),
    (-1, "0201ff"),
    (127, "02017f"),
    (128, "02020080"),
    (-128, "020180"),
    (-129, "0202ff7f"),
    (255, "020200ff"),
    (256, "02020100"),
    (-256, "0202ff00"),
    (32767, "02027fff"),
    (32768, "0203008000"),
    (-32768, "02028000"),
    (-32769, "0203ff7fff"),
    (2147483647, "02047fffffff"),
    (-2147483648, "020480000000"),
  ]
  for pair in cases {
    let (v, expected_hex) = pair
    let encoded = @asn1.encode_der(@asn1.encode_int(v))
    assert_eq(@asn1.hex_encode(encoded), expected_hex)
    let decoded = @asn1.decode_der(encoded)
    assert_eq(@asn1.decode_int(decoded), v)
    assert_eq(@asn1.decode_int64(decoded), v.to_int64())
  }
}

///|
test "uint32 and int64 boundaries and overflow rejections" {
  let u32_cases : Array[(UInt32, String)] = [
    (0U, "020100"),
    (1U, "020101"),
    (127U, "02017f"),
    (128U, "02020080"),
    (0x7FFF_FFFFU, "02047fffffff"),
    (0x8000_0000U, "02050080000000"),
    (0xFFFF_FFFFU, "020500ffffffff"),
  ]
  for pair in u32_cases {
    let (v, expected_hex) = pair
    let encoded = @asn1.encode_der(@asn1.encode_uint32(v))
    assert_eq(@asn1.hex_encode(encoded), expected_hex)
    let decoded = @asn1.decode_der(encoded)
    assert_eq(@asn1.decode_uint32(decoded), v)
  }

  let i64_cases : Array[(Int64, String)] = [
    (0L, "020100"),
    (-1L, "0201ff"),
    (2147483648L, "02050080000000"),
    (-2147483649L, "0205ff7fffffff"),
    (4294967296L, "02050100000000"),
    (9223372036854775807L, "02087fffffffffffffff"),
    (-9223372036854775808L, "02088000000000000000"),
  ]
  for pair in i64_cases {
    let (v, expected_hex) = pair
    let encoded = @asn1.encode_der(@asn1.encode_int64(v))
    assert_eq(@asn1.hex_encode(encoded), expected_hex)
    let decoded = @asn1.decode_der(encoded)
    assert_eq(@asn1.decode_int64(decoded), v)
  }

  // Overflow checks for decode_int, decode_uint32, decode_int64
  assert_true(
    expect_err(() => @asn1.decode_int(@asn1.encode_int64(2147483648L)))
    is @asn1.DerError::InvalidValue(_),
  )
  assert_true(
    expect_err(() => @asn1.decode_int(@asn1.encode_int64(-2147483649L)))
    is @asn1.DerError::InvalidValue(_),
  )
  assert_true(
    expect_err(() => @asn1.decode_uint32(@asn1.encode_int(-1)))
    is @asn1.DerError::InvalidValue(_),
  )
  assert_true(
    expect_err(() => @asn1.decode_uint32(@asn1.encode_int64(4294967296L)))
    is @asn1.DerError::InvalidValue(_),
  )
  let big9 = @asn1.decode_der(must_hex("0209010000000000000000"))
  assert_true(
    expect_err(() => @asn1.decode_int64(big9))
    is @asn1.DerError::InvalidValue(_),
  )
  // TagMismatch on wrong DER type
  assert_true(
    expect_err(() => @asn1.decode_int(@asn1.DerValue::Null))
    is @asn1.DerError::TagMismatch(..),
  )
}

///|
test "all RFC 4120 APPLICATION tags 1..30 and high-tag-number encoding" {
  let app_tags : Array[Int32] = [
    @asn1.APP_TICKET,
    @asn1.APP_AUTHENTICATOR,
    @asn1.APP_ENC_TICKET_PART,
    @asn1.APP_AS_REQ,
    @asn1.APP_AS_REP,
    @asn1.APP_TGS_REQ,
    @asn1.APP_TGS_REP,
    @asn1.APP_AP_REQ,
    @asn1.APP_AP_REP,
    @asn1.APP_KRB_SAFE,
    @asn1.APP_KRB_PRIV,
    @asn1.APP_KRB_CRED,
    @asn1.APP_ENC_AS_REP_PART,
    @asn1.APP_ENC_TGS_REP_PART,
    @asn1.APP_ENC_AP_REP_PART,
    @asn1.APP_ENC_KRB_PRIV_PART,
    @asn1.APP_ENC_KRB_CRED_PART,
    @asn1.APP_KRB_ERROR,
  ]
  assert_eq(app_tags.length(), 18)
  for tag_num in app_tags {
    let inner = @asn1.DerValue::Sequence([
      @asn1.context_field(0, @asn1.encode_int(5)),
      @asn1.context_field(1, @asn1.encode_int(tag_num)),
    ])
    let wire = @asn1.encode_application(tag_num, inner)
    assert_eq(wire[0].to_int(), 0x60 | tag_num)
    assert_eq(@asn1.peek_application_tag(wire), tag_num)
    let unwrapped = @asn1.decode_application(wire, tag_num)
    assert_eq(unwrapped, inner)
    let wrong = if tag_num == @asn1.APP_KRB_ERROR {
      @asn1.APP_TICKET
    } else {
      @asn1.APP_KRB_ERROR
    }
    assert_true(
      expect_err(() => @asn1.decode_application(wire, wrong))
      is @asn1.DerError::TagMismatch(..),
    )
  }

  // High-tag-number APPLICATION (>= 31) and CONTEXT (>= 31)
  let hi_app31 = @asn1.encode_application(31, @asn1.DerValue::Null)
  assert_eq(@asn1.hex_encode(hi_app31), "7f1f020500")
  assert_eq(@asn1.peek_application_tag(hi_app31), 31)
  assert_eq(@asn1.decode_application(hi_app31, 31), @asn1.DerValue::Null)

  let hi_app128 = @asn1.encode_application(128, @asn1.DerValue::Null)
  assert_eq(@asn1.hex_encode(hi_app128), "7f8100020500")
  assert_eq(@asn1.peek_application_tag(hi_app128), 128)
  assert_eq(@asn1.decode_application(hi_app128, 128), @asn1.DerValue::Null)

  let hi_ctx16384 = @asn1.encode_der(
    @asn1.context_field(16384, @asn1.encode_int(42)),
  )
  assert_eq(@asn1.hex_encode(hi_ctx16384), "bf8180000302012a")
  assert_eq(
    @asn1.decode_der(hi_ctx16384),
    @asn1.context_field(16384, @asn1.encode_int(42)),
  )

  // peek_application_tag rejects non-APPLICATION and empty
  assert_true(
    expect_err(() => {
      @asn1.peek_application_tag(@asn1.encode_der(@asn1.DerValue::Sequence([])))
    })
    is @asn1.DerError::TagMismatch(..),
  )
  assert_true(
    expect_err(() => @asn1.peek_application_tag(b""))
    is @asn1.DerError::UnexpectedEof,
  )
}

///|
test "SeqReader context [0..12] sequential consumption and rejections" {
  // KRB-ERROR style SEQUENCE with tags 0..12, omitting optionals 2,3,7,8,11
  let seq = @asn1.DerValue::Sequence([
    @asn1.context_field(0, @asn1.encode_int(5)),
    @asn1.context_field(1, @asn1.encode_int(30)),
    @asn1.context_field(4, @asn1.encode_generalized_time("20261126020000Z")),
    @asn1.context_field(5, @asn1.encode_int(123456)),
    @asn1.context_field(6, @asn1.encode_int(6)),
    @asn1.context_field(9, @asn1.encode_general_string("EXAMPLE.COM")),
    @asn1.context_field(10, @asn1.encode_general_string("krbtgt")),
    @asn1.context_field(12, @asn1.encode_octet_string(b"\xde\xad\xbe\xef")),
  ])
  let roundtrip = @asn1.decode_der(@asn1.encode_der(seq))
  assert_eq(roundtrip, seq)

  let r = @asn1.SeqReader::new(roundtrip)
  assert_eq(@asn1.decode_int(r.read_required(0)), 5)
  assert_eq(@asn1.decode_int(r.read_required(1)), 30)
  assert_eq(r.read_optional(2), None)
  assert_eq(r.read_optional(3), None)
  assert_eq(
    @asn1.decode_generalized_time(r.read_required(4)),
    "20261126020000Z",
  )
  assert_eq(@asn1.decode_int(r.read_required(5)), 123456)
  assert_eq(@asn1.decode_int(r.read_required(6)), 6)
  assert_eq(r.read_optional(7), None)
  assert_eq(r.read_optional(8), None)
  assert_eq(@asn1.decode_general_string(r.read_required(9)), "EXAMPLE.COM")
  assert_eq(@asn1.decode_general_string(r.read_required(10)), "krbtgt")
  assert_eq(r.read_optional(11), None)
  let edata = r.read_optional(12)
  assert_true(edata is Some(_))
  match edata {
    Some(v) => assert_eq(@asn1.decode_octet_string(v), b"\xde\xad\xbe\xef")
    None => fail("expected e-data")
  }
  r.finish()

  // KDC-REQ style starting at [1]
  let kdc_req = @asn1.DerValue::Sequence([
    @asn1.context_field(1, @asn1.encode_int(5)),
    @asn1.context_field(2, @asn1.encode_int(10)),
    @asn1.context_field(4, @asn1.DerValue::Sequence([])),
  ])
  let r2 = @asn1.SeqReader::new(kdc_req)
  assert_eq(@asn1.decode_int(r2.read_required(1)), 5)
  assert_eq(@asn1.decode_int(r2.read_required(2)), 10)
  assert_eq(r2.read_optional(3), None)
  assert_eq(r2.read_required(4), @asn1.DerValue::Sequence([]))
  r2.finish()

  // Missing required field (skipped)
  let missing_seq = @asn1.DerValue::Sequence([
    @asn1.context_field(0, @asn1.encode_int(5)),
    @asn1.context_field(2, @asn1.encode_int(9)),
  ])
  let rm = @asn1.SeqReader::new(missing_seq)
  assert_eq(@asn1.decode_int(rm.read_required(0)), 5)
  assert_true(
    expect_err(() => rm.read_required(1)) is @asn1.DerError::MissingField(_),
  )

  // Missing required field at EOF
  let rm2 = @asn1.SeqReader::new(@asn1.DerValue::Sequence([]))
  assert_true(
    expect_err(() => rm2.read_required(0)) is @asn1.DerError::MissingField(_),
  )

  // Out-of-order fields [1], [0] rejected by finish()
  let ooo_seq = @asn1.DerValue::Sequence([
    @asn1.context_field(1, @asn1.encode_int(1)),
    @asn1.context_field(0, @asn1.encode_int(0)),
  ])
  let ro = @asn1.SeqReader::new(ooo_seq)
  assert_eq(ro.read_optional(0), None)
  assert_eq(@asn1.decode_int(ro.read_required(1)), 1)
  assert_true(expect_err(() => ro.finish()) is @asn1.DerError::TagMismatch(..))

  // Duplicate tag [0], [0] rejected on next read
  let dup_seq = @asn1.DerValue::Sequence([
    @asn1.context_field(0, @asn1.encode_int(1)),
    @asn1.context_field(0, @asn1.encode_int(2)),
  ])
  let rd = @asn1.SeqReader::new(dup_seq)
  assert_eq(@asn1.decode_int(rd.read_required(0)), 1)
  assert_true(
    expect_err(() => rd.read_optional(1)) is @asn1.DerError::TagMismatch(..),
  )

  // Unknown trailing field [13] rejected by finish()
  let extra_seq = @asn1.DerValue::Sequence([
    @asn1.context_field(0, @asn1.encode_int(5)),
    @asn1.context_field(13, @asn1.encode_int(99)),
  ])
  let re = @asn1.SeqReader::new(extra_seq)
  assert_eq(@asn1.decode_int(re.read_required(0)), 5)
  assert_true(expect_err(() => re.finish()) is @asn1.DerError::TagMismatch(..))

  // Non-context element in SEQUENCE rejected
  let bad_elem = @asn1.DerValue::Sequence([@asn1.encode_int(5)])
  let rb = @asn1.SeqReader::new(bad_elem)
  assert_true(
    expect_err(() => rb.read_required(0)) is @asn1.DerError::TagMismatch(..),
  )

  // Non-SEQUENCE passed to SeqReader::new
  assert_true(
    expect_err(() => @asn1.SeqReader::new(@asn1.DerValue::Null))
    is @asn1.DerError::TagMismatch(..),
  )
}

///|
test "KerberosFlags RFC 4120 section 5.2.8 MSB-first encoding and >=32-bit decoding" {
  // Bit 0 (reserved) = 0x8000_0000, Bit 1 (forwardable) = 0x4000_0000, Bit 31 (validate) = 0x0000_0001
  let f1 = @asn1.encode_der(@asn1.encode_kerberos_flags(0x8000_0000U))
  assert_eq(@asn1.hex_encode(f1), "03050080000000")
  assert_eq(@asn1.decode_kerberos_flags(@asn1.decode_der(f1)), 0x8000_0000U)

  let f2 = @asn1.encode_der(@asn1.encode_kerberos_flags(0x4080_0010U))
  assert_eq(@asn1.hex_encode(f2), "03050040800010")
  assert_eq(@asn1.decode_kerberos_flags(@asn1.decode_der(f2)), 0x4080_0010U)

  let f3 = @asn1.encode_der(@asn1.encode_kerberos_flags(0x0000_0001U))
  assert_eq(@asn1.hex_encode(f3), "03050000000001")
  assert_eq(@asn1.decode_kerberos_flags(@asn1.decode_der(f3)), 0x0000_0001U)

  assert_eq(
    @asn1.decode_kerberos_flags(
      @asn1.decode_der(@asn1.encode_der(@asn1.encode_kerberos_flags(0U))),
    ),
    0U,
  )
  assert_eq(
    @asn1.decode_kerberos_flags(
      @asn1.decode_der(
        @asn1.encode_der(@asn1.encode_kerberos_flags(0xFFFF_FFFFU)),
      ),
    ),
    0xFFFF_FFFFU,
  )

  // Extended >32-bit BIT STRING (5 bytes = 40 bits, and 5 bytes with 4 unused bits = 36 bits)
  let ext40 = @asn1.decode_der(must_hex("03060012345678ab"))
  assert_eq(@asn1.decode_kerberos_flags(ext40), 0x1234_5678U)
  let ext36 = @asn1.decode_der(must_hex("030604deadbeef80"))
  assert_eq(@asn1.decode_kerberos_flags(ext36), 0xDEAD_BEEFU)

  // Reject < 32 bits
  let short3 = @asn1.decode_der(must_hex("030400123456"))
  assert_true(
    expect_err(() => @asn1.decode_kerberos_flags(short3))
    is @asn1.DerError::InvalidBitString(_),
  )

  // 4 bytes with 1 unused bit = 31 bits -> must be rejected
  let bits31 = @asn1.decode_der(must_hex("03050112345678"))
  assert_true(
    expect_err(() => @asn1.decode_kerberos_flags(bits31))
    is @asn1.DerError::InvalidBitString(_),
  )

  // Wrong tag
  assert_true(
    expect_err(() => @asn1.decode_kerberos_flags(@asn1.encode_int(0)))
    is @asn1.DerError::TagMismatch(..),
  )
}

///|
test "GeneralizedTime strict validation including leap years and invalid dates" {
  let valid = [
    "19700101000000Z", "20000229120000Z", // divisible by 400 -> leap year
     "20240229235959Z", // divisible by 4 -> leap year
     "20261126021530Z", "20991231235959Z", "00000229000000Z", // year 0 divisible by 400
  ]
  for ts in valid {
    @asn1.validate_generalized_time(ts)
    let encoded = @asn1.encode_der(@asn1.encode_generalized_time(ts))
    assert_eq(encoded[0], b'\x18')
    let decoded = @asn1.decode_der(encoded)
    assert_eq(@asn1.decode_generalized_time(decoded), ts)
  }

  let invalid = [
    "", "20240101000000", // missing Z
     "20240101000000z", // lowercase z
     "20240101000000.0Z", // fractional seconds
     "20240101000000+0000", // timezone offset
     "202401010000Z", // missing seconds
     "19000229000000Z", // century non-leap year
     "21000229000000Z", // century non-leap year
     "20230229000000Z", // non-leap year Feb 29
     "20240230000000Z", // Feb 30
     "20240431000000Z", // April 31
     "20240015000000Z", // month 00
     "20241301000000Z", // month 13
     "20240100000000Z", // day 00
     "20240132000000Z", // day 32
     "20240101240000Z", // hour 24
     "20240101006000Z", // minute 60
     "20240101000060Z", // second 60
     "202a0101000000Z", // non-digit
  ]
  for bad in invalid {
    assert_true(
      expect_err(() => @asn1.validate_generalized_time(bad))
      is @asn1.DerError::InvalidGeneralizedTime(_),
    )
    assert_true(
      expect_err(() => @asn1.encode_generalized_time(bad))
      is @asn1.DerError::InvalidGeneralizedTime(_),
    )
    let raw_wire = @asn1.encode_der(@asn1.DerValue::GeneralizedTime(bad))
    assert_true(
      expect_err(() => @asn1.decode_der(raw_wire))
      is @asn1.DerError::InvalidGeneralizedTime(_),
    )
  }

  // Non-ASCII byte inside GeneralizedTime wire TLV
  assert_true(
    expect_err(() => {
      @asn1.decode_der(must_hex("180f32303234303130313030303030ff5a"))
    })
    is @asn1.DerError::InvalidGeneralizedTime(_),
  )
}

///|
test "universal primitives, OID, UTF-8 GeneralString, long lengths, Set and Raw" {
  // Boolean
  assert_eq(
    @asn1.hex_encode(@asn1.encode_der(@asn1.DerValue::Boolean(false))),
    "010100",
  )
  assert_eq(
    @asn1.hex_encode(@asn1.encode_der(@asn1.DerValue::Boolean(true))),
    "0101ff",
  )
  assert_eq(
    @asn1.decode_der(must_hex("010100")),
    @asn1.DerValue::Boolean(false),
  )
  assert_eq(@asn1.decode_der(must_hex("0101ff")), @asn1.DerValue::Boolean(true))

  // Null
  assert_eq(@asn1.hex_encode(@asn1.encode_der(@asn1.DerValue::Null)), "0500")
  assert_eq(@asn1.decode_der(must_hex("0500")), @asn1.DerValue::Null)

  // OctetString with long-form lengths (128 bytes -> 0x81 0x80, 256 bytes -> 0x82 0x01 0x00)
  let b128 = Bytes::make(128, b'\xAA')
  let e128 = @asn1.encode_der(@asn1.encode_octet_string(b128))
  assert_eq(e128[0], b'\x04')
  assert_eq(e128[1], b'\x81')
  assert_eq(e128[2], b'\x80')
  assert_eq(@asn1.decode_octet_string(@asn1.decode_der(e128)), b128)

  let b256 = Bytes::make(256, b'\x55')
  let e256 = @asn1.encode_der(@asn1.encode_octet_string(b256))
  assert_eq(e256[0], b'\x04')
  assert_eq(e256[1], b'\x82')
  assert_eq(e256[2], b'\x01')
  assert_eq(e256[3], b'\x00')
  assert_eq(@asn1.decode_octet_string(@asn1.decode_der(e256)), b256)

  // OID (id-krb5 = 1.3.6.1.5.2, Kerberos GSS OID = 1.2.840.113554.1.2.2, arc-2 large = 2.999.3)
  let krb5_oid = @asn1.DerValue::Oid([1, 3, 6, 1, 5, 2])
  let krb5_oid_der = @asn1.encode_der(krb5_oid)
  assert_eq(@asn1.hex_encode(krb5_oid_der), "06052b06010502")
  assert_eq(@asn1.decode_der(krb5_oid_der), krb5_oid)

  let gss_krb5_oid = @asn1.DerValue::Oid([1, 2, 840, 113554, 1, 2, 2])
  let gss_der = @asn1.encode_der(gss_krb5_oid)
  assert_eq(@asn1.hex_encode(gss_der), "06092a864886f712010202")
  assert_eq(@asn1.decode_der(gss_der), gss_krb5_oid)

  let arc2_oid = @asn1.DerValue::Oid([2, 999, 3])
  assert_eq(@asn1.decode_der(@asn1.encode_der(arc2_oid)), arc2_oid)

  // GeneralString ASCII + UTF-8 (2-byte, 3-byte, 4-byte scalar values)
  let s_ascii = "EXAMPLE.COM"
  assert_eq(
    @asn1.decode_general_string(
      @asn1.decode_der(@asn1.encode_der(@asn1.encode_general_string(s_ascii))),
    ),
    s_ascii,
  )
  let s_utf8 = "café-测试-🔐"
  assert_eq(
    @asn1.decode_general_string(
      @asn1.decode_der(@asn1.encode_der(@asn1.encode_general_string(s_utf8))),
    ),
    s_utf8,
  )
  // Invalid overlong UTF-8 in GeneralString rejected
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("1b02c0af")))
    is @asn1.DerError::InvalidValue(_),
  )
  // UTF-8 encoded surrogate U+D800 rejected
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("1b03eda080")))
    is @asn1.DerError::InvalidValue(_),
  )

  // Set
  let set_val = @asn1.DerValue::Set([@asn1.encode_int(1), @asn1.encode_int(2)])
  let set_der = @asn1.encode_der(set_val)
  assert_eq(set_der[0], b'\x31')
  assert_eq(@asn1.decode_der(set_der), set_val)

  // Raw: primitive context-specific, private class, unknown universal tag
  let raw_prim_ctx = @asn1.DerValue::Raw(
    { class: @asn1.TagClass::ContextSpecific, constructed: false, number: 2, },
    b"\x01\x02",
  )
  assert_eq(@asn1.hex_encode(@asn1.encode_der(raw_prim_ctx)), "82020102")
  assert_eq(@asn1.decode_der(@asn1.encode_der(raw_prim_ctx)), raw_prim_ctx)

  let raw_priv = @asn1.DerValue::Raw(
    { class: @asn1.TagClass::Private, constructed: false, number: 7, },
    b"\xaa",
  )
  assert_eq(@asn1.hex_encode(@asn1.encode_der(raw_priv)), "c701aa")
  assert_eq(@asn1.decode_der(@asn1.encode_der(raw_priv)), raw_priv)

  let raw_printable = @asn1.DerValue::Raw(
    { class: @asn1.TagClass::Universal, constructed: false, number: 19, },
    b"abc",
  )
  assert_eq(@asn1.decode_der(@asn1.encode_der(raw_printable)), raw_printable)
}

///|
test "strict DER adversarial rejections: lengths, integers, booleans, bitstrings, tags" {
  // Non-canonical lengths
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("048101aa")))
    is @asn1.DerError::NonCanonicalLength,
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("048100")))
    is @asn1.DerError::NonCanonicalLength,
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("04820080")))
    is @asn1.DerError::NonCanonicalLength,
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("04820001aa")))
    is @asn1.DerError::NonCanonicalLength,
  )

  // Indefinite length (0x80)
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("30800000")))
    is @asn1.DerError::IndefiniteLength,
  )

  // Reserved length byte 0xFF and >4-byte length
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("04ff")))
    is @asn1.DerError::InvalidLength(_),
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("04850100000000")))
    is @asn1.DerError::InvalidLength(_),
  )

  // Non-canonical integers (empty, leading 0x00, leading 0xFF)
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("0200")))
    is @asn1.DerError::NonCanonicalInteger,
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("02020000")))
    is @asn1.DerError::NonCanonicalInteger,
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("0202007f")))
    is @asn1.DerError::NonCanonicalInteger,
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("0202ff80")))
    is @asn1.DerError::NonCanonicalInteger,
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("0202ffff")))
    is @asn1.DerError::NonCanonicalInteger,
  )

  // Non-canonical booleans
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("010101")))
    is @asn1.DerError::NonCanonicalBoolean,
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("01017f")))
    is @asn1.DerError::NonCanonicalBoolean,
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("0100")))
    is @asn1.DerError::NonCanonicalBoolean,
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("0102ffff")))
    is @asn1.DerError::NonCanonicalBoolean,
  )

  // Invalid BitStrings
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("0300")))
    is @asn1.DerError::InvalidBitString(_),
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("03020800")))
    is @asn1.DerError::InvalidBitString(_),
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("030101")))
    is @asn1.DerError::InvalidBitString(_),
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("030203ff")))
    is @asn1.DerError::InvalidBitString(_),
  )
  // Valid BitString with unused=3 and low 3 bits zero (0xF8 = 11111000)
  assert_eq(
    @asn1.decode_der(must_hex("030203f8")),
    @asn1.DerValue::BitString(3, b"\xf8"),
  )
  // Valid empty BitString with unused=0
  assert_eq(
    @asn1.decode_der(must_hex("030100")),
    @asn1.DerValue::BitString(0, b""),
  )

  // Constructed primitive / primitive constructed tags rejected
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("220100")))
    is @asn1.DerError::InvalidTag(_),
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("2400")))
    is @asn1.DerError::InvalidTag(_),
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("1000")))
    is @asn1.DerError::InvalidTag(_),
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("1100")))
    is @asn1.DerError::InvalidTag(_),
  )

  // Non-canonical NULL length
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("050100")))
    is @asn1.DerError::InvalidLength(_),
  )

  // Non-canonical high tag numbers (< 31 or leading 0x80)
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("7f1e020500")))
    is @asn1.DerError::InvalidTag(_),
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("7f801f020500")))
    is @asn1.DerError::InvalidTag(_),
  )

  // Non-canonical & truncated OID
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("0600")))
    is @asn1.DerError::InvalidValue(_),
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("06032b8001")))
    is @asn1.DerError::InvalidValue(_),
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("06022b81")))
    is @asn1.DerError::InvalidValue(_),
  )
}

///|
test "depth bomb protection (max depth 64) and trailing garbage / EOF" {
  // 64 nested SEQUENCEs around Null -> allowed
  let mut v64 = @asn1.DerValue::Null
  for i = 0; i < 64; i = i + 1 {
    let _ = i
    v64 = @asn1.DerValue::Sequence([v64])
  }
  let enc64 = @asn1.encode_der(v64)
  assert_eq(@asn1.decode_der(enc64), v64)

  // 65 nested SEQUENCEs around Null -> MaxDepthExceeded
  let v65 = @asn1.DerValue::Sequence([v64])
  let enc65 = @asn1.encode_der(v65)
  assert_true(
    expect_err(() => @asn1.decode_der(enc65))
    is @asn1.DerError::MaxDepthExceeded,
  )

  // 65 nested empty SEQUENCEs -> MaxDepthExceeded
  let mut e65 = @asn1.DerValue::Sequence([])
  for i = 0; i < 64; i = i + 1 {
    let _ = i
    e65 = @asn1.DerValue::Sequence([e65])
  }
  assert_true(
    expect_err(() => @asn1.decode_der(@asn1.encode_der(e65)))
    is @asn1.DerError::MaxDepthExceeded,
  )

  // 65 nested Context wrappers -> MaxDepthExceeded
  let mut c65 = @asn1.DerValue::Null
  for i = 0; i < 65; i = i + 1 {
    c65 = @asn1.context_field(i % 10, c65)
  }
  assert_true(
    expect_err(() => @asn1.decode_der(@asn1.encode_der(c65)))
    is @asn1.DerError::MaxDepthExceeded,
  )

  // 65 nested Application wrappers -> MaxDepthExceeded
  let mut a65 = @asn1.DerValue::Null
  for i = 0; i < 65; i = i + 1 {
    let _ = i
    a65 = @asn1.DerValue::Application(@asn1.APP_TICKET, a65)
  }
  assert_true(
    expect_err(() => @asn1.decode_der(@asn1.encode_der(a65)))
    is @asn1.DerError::MaxDepthExceeded,
  )

  // Trailing garbage at top level and inside explicit wrappers
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("0500aabb")))
    is @asn1.DerError::TrailingBytes(2),
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("610405000500")))
    is @asn1.DerError::TrailingBytes(2),
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("a00405000500")))
    is @asn1.DerError::TrailingBytes(2),
  )

  // Truncated / UnexpectedEof cases
  assert_true(
    expect_err(() => @asn1.decode_der(b"")) is @asn1.DerError::UnexpectedEof,
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("02")))
    is @asn1.DerError::UnexpectedEof,
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("02050102")))
    is @asn1.DerError::UnexpectedEof,
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("7f")))
    is @asn1.DerError::UnexpectedEof,
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("6100")))
    is @asn1.DerError::UnexpectedEof,
  )
  assert_true(
    expect_err(() => @asn1.decode_der(must_hex("a000")))
    is @asn1.DerError::UnexpectedEof,
  )
}

///|
test "realistic RFC 4120 Ticket DER round-trip and hex helpers" {
  // Ticket ::= [APPLICATION 1] SEQUENCE {
  //   tkt-vno  [0] INTEGER (5),
  //   realm    [1] Realm,
  //   sname    [2] PrincipalName,
  //   enc-part [3] EncryptedData
  // }
  let principal = @asn1.DerValue::Sequence([
    @asn1.context_field(0, @asn1.encode_int(2)),
    @asn1.context_field(
      1,
      @asn1.DerValue::Sequence([
        @asn1.encode_general_string("krbtgt"),
        @asn1.encode_general_string("EXAMPLE.COM"),
      ]),
    ),
  ])
  let enc_data = @asn1.DerValue::Sequence([
    @asn1.context_field(0, @asn1.encode_int(18)),
    @asn1.context_field(1, @asn1.encode_uint32(1U)),
    @asn1.context_field(
      2,
      @asn1.encode_octet_string(b"\x01\x02\x03\x04\x05\x06\x07\x08"),
    ),
  ])
  let ticket_body = @asn1.DerValue::Sequence([
    @asn1.context_field(0, @asn1.encode_int(5)),
    @asn1.context_field(1, @asn1.encode_general_string("EXAMPLE.COM")),
    @asn1.context_field(2, principal),
    @asn1.context_field(3, enc_data),
  ])
  let wire = @asn1.encode_application(@asn1.APP_TICKET, ticket_body)
  assert_eq(@asn1.peek_application_tag(wire), @asn1.APP_TICKET)
  let decoded_body = @asn1.decode_application(wire, @asn1.APP_TICKET)
  let r = @asn1.SeqReader::new(decoded_body)
  assert_eq(@asn1.decode_int(r.read_required(0)), 5)
  assert_eq(@asn1.decode_general_string(r.read_required(1)), "EXAMPLE.COM")
  assert_eq(r.read_required(2), principal)
  assert_eq(r.read_required(3), enc_data)
  r.finish()

  // Hex helpers
  assert_eq(@asn1.hex_encode(b""), "")
  assert_eq(@asn1.hex_decode(""), b"")
  assert_eq(@asn1.hex_decode(" 0A ff \n 1b\t2C "), b"\x0a\xff\x1b\x2c")
  assert_true(
    expect_err(() => @asn1.hex_decode("abc")) is @asn1.DerError::InvalidValue(_),
  )
  assert_true(
    expect_err(() => @asn1.hex_decode("0g")) is @asn1.DerError::InvalidValue(_),
  )
}
