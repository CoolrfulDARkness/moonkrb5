///|
fn[T] capture_err(f : () -> T raise @asn1.DerError) -> @asn1.DerError? {
  try {
    ignore(f())
    None
  } catch {
    e => Some(e)
  }
}

///|
fn make_sample_encrypted_data(with_kvno : Bool) -> @types.EncryptedData {
  {
    etype: 18,
    kvno: if with_kvno {
      Some(3U)
    } else {
      None
    },
    cipher: b"\xDE\xAD\xBE\xEF\x01\x02\x03\x04",
  }
}

///|
fn make_sample_ticket() -> @types.Ticket {
  {
    tkt_vno: @types.KRB5_PVNO,
    realm: "EXAMPLE.COM",
    sname: @types.PrincipalName::service("krbtgt", "EXAMPLE.COM"),
    enc_part: make_sample_encrypted_data(true),
  }
}

///|
fn make_sample_key() -> @types.EncryptionKey {
  {
    keytype: 18,
    keyvalue: b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
  }
}

///|
fn make_sample_host_addrs() -> Array[@types.HostAddress] {
  [
    { addr_type: 2, address: b"\x7F\x00\x00\x01", },
    {
      addr_type: 24,
      address: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
    },
  ]
}

///|
fn make_sample_authz_data() -> Array[@types.AuthorizationDataEntry] {
  [
    { ad_type: 1, ad_data: b"\x30\x00", },
    { ad_type: 128, ad_data: b"\xCA\xFE\xBA\xBE", },
  ]
}

///|
test "constants sanity" {
  assert_eq(@types.KRB5_PVNO, 5)
  assert_eq(@types.MSG_AS_REQ, 10)
  assert_eq(@types.MSG_AS_REP, 11)
  assert_eq(@types.MSG_TGS_REQ, 12)
  assert_eq(@types.MSG_TGS_REP, 13)
  assert_eq(@types.MSG_AP_REQ, 14)
  assert_eq(@types.MSG_AP_REP, 15)
  assert_eq(@types.MSG_KRB_SAFE, 20)
  assert_eq(@types.MSG_KRB_PRIV, 21)
  assert_eq(@types.MSG_KRB_CRED, 22)
  assert_eq(@types.MSG_KRB_ERROR, 30)
  assert_eq(@types.NT_UNKNOWN, 0)
  assert_eq(@types.NT_PRINCIPAL, 1)
  assert_eq(@types.NT_SRV_INST, 2)
  assert_eq(@types.NT_SRV_HST, 3)
  assert_eq(@types.NT_SRV_XHST, 4)
  assert_eq(@types.NT_UID, 5)
  assert_eq(@types.NT_ENTERPRISE, 10)
  assert_eq(@types.PA_TGS_REQ, 1)
  assert_eq(@types.PA_ENC_TIMESTAMP, 2)
  assert_eq(@types.PA_PW_SALT, 3)
  assert_eq(@types.PA_ETYPE_INFO, 11)
  assert_eq(@types.PA_ETYPE_INFO2, 19)
  assert_eq(@types.TKT_FLAG_FORWARDABLE, 0x40000000U)
  assert_eq(@types.TKT_FLAG_FORWARDED, 0x20000000U)
  assert_eq(@types.TKT_FLAG_PROXIABLE, 0x10000000U)
  assert_eq(@types.TKT_FLAG_PROXY, 0x08000000U)
  assert_eq(@types.TKT_FLAG_MAY_POSTDATE, 0x04000000U)
  assert_eq(@types.TKT_FLAG_POSTDATED, 0x02000000U)
  assert_eq(@types.TKT_FLAG_INVALID, 0x01000000U)
  assert_eq(@types.TKT_FLAG_RENEWABLE, 0x00800000U)
  assert_eq(@types.TKT_FLAG_INITIAL, 0x00400000U)
  assert_eq(@types.TKT_FLAG_PRE_AUTHENT, 0x00200000U)
  assert_eq(@types.TKT_FLAG_HW_AUTHENT, 0x00100000U)
  assert_eq(@types.KDC_OPT_FORWARDABLE, 0x40000000U)
  assert_eq(@types.KDC_OPT_PROXIABLE, 0x10000000U)
  assert_eq(@types.KDC_OPT_ALLOW_POSTDATE, 0x04000000U)
  assert_eq(@types.KDC_OPT_RENEWABLE, 0x00800000U)
  assert_eq(@types.KDC_OPT_CANONICALIZE, 0x00010000U)
  assert_eq(@types.KDC_OPT_RENEWABLE_OK, 0x00000010U)
  assert_eq(@types.KDC_OPT_ENC_TKT_IN_SKEY, 0x00000008U)
  assert_eq(@types.KDC_OPT_RENEW, 0x00000002U)
  assert_eq(@types.KDC_OPT_VALIDATE, 0x00000001U)
  assert_eq(@types.AP_OPT_USE_SESSION_KEY, 0x40000000U)
  assert_eq(@types.AP_OPT_MUTUAL_REQUIRED, 0x20000000U)
  assert_eq(@types.KDC_ERR_NONE, 0)
  assert_eq(@types.KDC_ERR_PREAUTH_REQUIRED, 25)
  assert_eq(@types.KRB_AP_ERR_BAD_INTEGRITY, 31)
  assert_eq(@types.KRB_AP_ERR_MUT_FAIL, 46)
  assert_eq(@types.KRB_ERR_GENERIC, 60)
}

///|
test "unix_to_kerberos_time and kerberos_time_to_unix round-trip including leap years" {
  let cases : Array[(Int64, String)] = [
    (0L, "19700101000000Z"),
    (951782400L, "20000229000000Z"),
    (951868799L, "20000229235959Z"),
    (951868800L, "20000301000000Z"),
    (1709164800L, "20240229000000Z"),
    (1709210096L, "20240229123456Z"),
    (1709251200L, "20240301000000Z"),
    (1795659740L, "20261126022220Z"),
    (2147483647L, "20380119031407Z"),
    (2147483648L, "20380119031408Z"),
    (4107542399L, "21000228235959Z"),
    (4107542400L, "21000301000000Z"),
    (253402300799L, "99991231235959Z"),
  ]
  for pair in cases {
    let (epoch, expected) = pair
    assert_eq(@types.unix_to_kerberos_time(epoch), expected)
    assert_eq(@types.kerberos_time_to_unix(expected), epoch)
  }
}

///|
test "kerberos time rejects out of range and invalid dates" {
  assert_true(
    capture_err(() => @types.unix_to_kerberos_time(-1L))
    is Some(@asn1.DerError::InvalidGeneralizedTime(_)),
  )
  assert_true(
    capture_err(() => @types.unix_to_kerberos_time(253402300800L))
    is Some(@asn1.DerError::InvalidGeneralizedTime(_)),
  )
  // 2100 is NOT a leap year
  assert_true(
    capture_err(() => @types.kerberos_time_to_unix("21000229000000Z"))
    is Some(@asn1.DerError::InvalidGeneralizedTime(_)),
  )
  // 2026 is NOT a leap year
  assert_true(
    capture_err(() => @types.kerberos_time_to_unix("20260229000000Z"))
    is Some(@asn1.DerError::InvalidGeneralizedTime(_)),
  )
  // Fractional seconds / missing Z / bad hour
  assert_true(
    capture_err(() => @types.kerberos_time_to_unix("20260101000000.0Z"))
    is Some(@asn1.DerError::InvalidGeneralizedTime(_)),
  )
  assert_true(
    capture_err(() => @types.kerberos_time_to_unix("20260101000000"))
    is Some(@asn1.DerError::InvalidGeneralizedTime(_)),
  )
  assert_true(
    capture_err(() => @types.kerberos_time_to_unix("20260101240000Z"))
    is Some(@asn1.DerError::InvalidGeneralizedTime(_)),
  )
}

///|
test "tcp framing encode and decode" {
  let payload = b"\x6A\x03\x30\x01\x00"
  let framed = @types.encode_tcp_frame(payload)
  assert_eq(framed, b"\x00\x00\x00\x05\x6A\x03\x30\x01\x00")
  let (decoded, consumed) = @types.decode_tcp_frame(framed)
  assert_eq(decoded, payload)
  assert_eq(consumed, 9)

  // Empty payload round-trip
  let empty_framed = @types.encode_tcp_frame(b"")
  assert_eq(empty_framed, b"\x00\x00\x00\x00")
  let (empty_dec, empty_consumed) = @types.decode_tcp_frame(empty_framed)
  assert_eq(empty_dec, b"")
  assert_eq(empty_consumed, 4)

  // Stream with trailing next frame
  let combined = b"\x00\x00\x00\x02\xAA\xBB\x00\x00\x00\x01\xCC"
  let (first, c1) = @types.decode_tcp_frame(combined)
  assert_eq(first, b"\xAA\xBB")
  assert_eq(c1, 6)
  let rest = Bytes::makei(combined.length() - c1, fn(i) { combined[c1 + i] })
  let (second, c2) = @types.decode_tcp_frame(rest)
  assert_eq(second, b"\xCC")
  assert_eq(c2, 5)

  // Boundary rejections
  assert_true(
    capture_err(() => @types.decode_tcp_frame(b""))
    is Some(@asn1.DerError::UnexpectedEof),
  )
  assert_true(
    capture_err(() => @types.decode_tcp_frame(b"\x00\x00\x01"))
    is Some(@asn1.DerError::UnexpectedEof),
  )
  assert_true(
    capture_err(() => @types.decode_tcp_frame(b"\x00\x00\x00\x04\x01\x02"))
    is Some(@asn1.DerError::UnexpectedEof),
  )
  assert_true(
    capture_err(() => @types.decode_tcp_frame(b"\x80\x00\x00\x01\xFF"))
    is Some(@asn1.DerError::InvalidLength(_)),
  )
  assert_true(
    capture_err(() => @types.decode_tcp_frame(b"\xFF\xFF\xFF\xFF"))
    is Some(@asn1.DerError::InvalidLength(_)),
  )
}

///|
test "primitive structs round-trip and helpers" {
  let u = @types.PrincipalName::user("alice")
  assert_eq(u.name_type, @types.NT_PRINCIPAL)
  assert_eq(u.to_display(), "alice")
  assert_eq(
    @types.PrincipalName::from_der(
      @asn1.decode_der(@asn1.encode_der(u.to_der())),
    ),
    u,
  )

  let s = @types.PrincipalName::service("HTTP", "web.example.com")
  assert_eq(s.name_type, @types.NT_SRV_INST)
  assert_eq(s.to_display(), "HTTP/web.example.com")
  assert_eq(
    @types.PrincipalName::from_der(
      @asn1.decode_der(@asn1.encode_der(s.to_der())),
    ),
    s,
  )

  let custom = @types.PrincipalName::new(@types.NT_SRV_HST, [
    "host", "a.b.c", "extra",
  ])
  assert_eq(custom.to_display(), "host/a.b.c/extra")
  assert_eq(@types.PrincipalName::from_der(custom.to_der()), custom)

  let ha : @types.HostAddress = { addr_type: 2, address: b"\x0A\x00\x00\x01", }
  assert_eq(
    @types.HostAddress::from_der(
      @asn1.decode_der(@asn1.encode_der(ha.to_der())),
    ),
    ha,
  )

  let ed_min = make_sample_encrypted_data(false)
  assert_eq(
    @types.EncryptedData::from_der(
      @asn1.decode_der(@asn1.encode_der(ed_min.to_der())),
    ),
    ed_min,
  )
  let ed_max : @types.EncryptedData = {
    etype: 17,
    kvno: Some(0xFFFF_FFFFU),
    cipher: b"\x01",
  }
  assert_eq(
    @types.EncryptedData::from_der(
      @asn1.decode_der(@asn1.encode_der(ed_max.to_der())),
    ),
    ed_max,
  )

  let key = make_sample_key()
  assert_eq(
    @types.EncryptionKey::from_der(
      @asn1.decode_der(@asn1.encode_der(key.to_der())),
    ),
    key,
  )

  let cksum : @types.Checksum = {
    cksumtype: 16,
    checksum: b"\x01\x02\x03\x04\x05\x06",
  }
  assert_eq(
    @types.Checksum::from_der(
      @asn1.decode_der(@asn1.encode_der(cksum.to_der())),
    ),
    cksum,
  )

  let tr : @types.TransitedEncoding = {
    tr_type: 1,
    contents: b"SUB.EXAMPLE.COM",
  }
  assert_eq(
    @types.TransitedEncoding::from_der(
      @asn1.decode_der(@asn1.encode_der(tr.to_der())),
    ),
    tr,
  )

  let ad : @types.AuthorizationDataEntry = { ad_type: 1, ad_data: b"\x11\x22", }
  assert_eq(
    @types.AuthorizationDataEntry::from_der(
      @asn1.decode_der(@asn1.encode_der(ad.to_der())),
    ),
    ad,
  )

  let lr : @types.LastReqEntry = { lr_type: 0, lr_value: "20261126020000Z", }
  assert_eq(
    @types.LastReqEntry::from_der(
      @asn1.decode_der(@asn1.encode_der(lr.to_der())),
    ),
    lr,
  )

  // PA-DATA must use context tags [1] and [2]
  let pa : @types.PaData = {
    padata_type: @types.PA_ENC_TIMESTAMP,
    padata_value: b"\xAA\xBB",
  }
  let pa_der = pa.to_der()
  match pa_der {
    Sequence([Context(1, _), Context(2, _)]) => ()
    _ => fail("PA-DATA must use context tags [1] and [2]")
  }
  assert_eq(
    @types.PaData::from_der(@asn1.decode_der(@asn1.encode_der(pa_der))),
    pa,
  )
  // Reject PA-DATA mistakenly using [0] and [1]
  let bad_pa = @asn1.DerValue::Sequence([
    @asn1.context_field(0, @asn1.encode_int(2)),
    @asn1.context_field(1, @asn1.encode_octet_string(b"\xAA")),
  ])
  assert_true(
    capture_err(() => @types.PaData::from_der(bad_pa))
    is Some(@asn1.DerError::TagMismatch(..)),
  )

  // PA-ENC-TS-ENC minimal & maximal
  let ts_min : @types.PaEncTsEnc = {
    patimestamp: "20261126020000Z",
    pausec: None,
  }
  assert_eq(@types.PaEncTsEnc::decode(ts_min.encode()), ts_min)
  let ts_max : @types.PaEncTsEnc = {
    patimestamp: "20261126020000Z",
    pausec: Some(999999),
  }
  assert_eq(@types.PaEncTsEnc::decode(ts_max.encode()), ts_max)
  let ts_bad : @types.PaEncTsEnc = {
    patimestamp: "20261126020000Z",
    pausec: Some(1000000),
  }
  assert_true(
    capture_err(() => ts_bad.encode()) is Some(@asn1.DerError::InvalidValue(_)),
  )

  // ETYPE-INFO2 minimal, maximal, and empty rejection
  let ei_list : Array[@types.EtypeInfo2Entry] = [
    { etype: 18, salt: None, s2kparams: None, },
    {
      etype: 17,
      salt: Some("EXAMPLE.COMalice"),
      s2kparams: Some(b"\x00\x00\x10\x00"),
    },
  ]
  assert_eq(
    @types.decode_etype_info2(@types.encode_etype_info2(ei_list)),
    ei_list,
  )
  assert_true(
    capture_err(() => @types.decode_etype_info2(@types.encode_etype_info2([])))
    is Some(@asn1.DerError::InvalidValue(_)),
  )

  // METHOD-DATA
  let md : Array[@types.PaData] = [
    {
      padata_type: @types.PA_ETYPE_INFO2,
      padata_value: @types.encode_etype_info2(ei_list),
    },
    { padata_type: @types.PA_ENC_TIMESTAMP, padata_value: b"", },
  ]
  assert_eq(@types.decode_method_data(@types.encode_method_data(md)), md)
  assert_eq(@types.decode_method_data(@types.encode_method_data([])), [])
}

///|
test "Ticket round-trip and validation" {
  let tkt = make_sample_ticket()
  let wire = tkt.encode()
  assert_eq(@asn1.peek_application_tag(wire), @asn1.APP_TICKET)
  assert_eq(@types.Ticket::decode(wire), tkt)
  assert_eq(@types.Ticket::from_der(tkt.to_der()), tkt)

  // Bad tkt_vno rejected on encode
  let bad_vno : @types.Ticket = { ..tkt, tkt_vno: 4, }
  assert_true(
    capture_err(() => bad_vno.encode()) is Some(@asn1.DerError::InvalidValue(_)),
  )

  // Bad tkt_vno rejected on wire decode
  let bad_wire = @asn1.encode_application(
    @asn1.APP_TICKET,
    @asn1.DerValue::Sequence([
      @asn1.context_field(0, @asn1.encode_int(4)),
      @asn1.context_field(1, @asn1.encode_general_string("EXAMPLE.COM")),
      @asn1.context_field(2, tkt.sname.to_der()),
      @asn1.context_field(3, tkt.enc_part.to_der()),
    ]),
  )
  assert_true(
    capture_err(() => @types.Ticket::decode(bad_wire))
    is Some(@asn1.DerError::InvalidValue(_)),
  )

  // Missing required field rejected
  let missing_enc = @asn1.encode_application(
    @asn1.APP_TICKET,
    @asn1.DerValue::Sequence([
      @asn1.context_field(0, @asn1.encode_int(5)),
      @asn1.context_field(1, @asn1.encode_general_string("EXAMPLE.COM")),
      @asn1.context_field(2, tkt.sname.to_der()),
    ]),
  )
  assert_true(
    capture_err(() => @types.Ticket::decode(missing_enc))
    is Some(@asn1.DerError::MissingField(_)),
  )
}

///|
test "Authenticator round-trip minimal and maximal" {
  let auth_min : @types.Authenticator = {
    authenticator_vno: @types.KRB5_PVNO,
    crealm: "EXAMPLE.COM",
    cname: @types.PrincipalName::user("alice"),
    cksum: None,
    cusec: 0,
    ctime: "20261126020000Z",
    subkey: None,
    seq_number: None,
    authorization_data: None,
  }
  let wire_min = auth_min.encode()
  assert_eq(@asn1.peek_application_tag(wire_min), @asn1.APP_AUTHENTICATOR)
  assert_eq(@types.Authenticator::decode(wire_min), auth_min)

  let auth_max : @types.Authenticator = {
    authenticator_vno: @types.KRB5_PVNO,
    crealm: "EXAMPLE.COM",
    cname: @types.PrincipalName::user("alice"),
    cksum: Some({ cksumtype: 16, checksum: b"\x11\x22\x33\x44", }),
    cusec: 123456,
    ctime: "20261126020000Z",
    subkey: Some(make_sample_key()),
    seq_number: Some(0x8000_0001U),
    authorization_data: Some(make_sample_authz_data()),
  }
  let wire_max = auth_max.encode()
  assert_eq(@types.Authenticator::decode(wire_max), auth_max)

  // Reject invalid authenticator_vno and out-of-range cusec
  assert_true(
    capture_err(() => { ..auth_min, authenticator_vno: 6, }.encode())
    is Some(@asn1.DerError::InvalidValue(_)),
  )
  assert_true(
    capture_err(() => { ..auth_min, cusec: -1, }.encode())
    is Some(@asn1.DerError::InvalidValue(_)),
  )
  assert_true(
    capture_err(() => { ..auth_min, cusec: 1000000, }.encode())
    is Some(@asn1.DerError::InvalidValue(_)),
  )
}

///|
test "EncTicketPart round-trip minimal and maximal" {
  let min : @types.EncTicketPart = {
    flags: @types.TKT_FLAG_INITIAL | @types.TKT_FLAG_PRE_AUTHENT,
    key: make_sample_key(),
    crealm: "EXAMPLE.COM",
    cname: @types.PrincipalName::user("alice"),
    transited: { tr_type: 1, contents: b"", },
    authtime: "20261126020000Z",
    starttime: None,
    endtime: "20261126120000Z",
    renew_till: None,
    caddr: None,
    authorization_data: None,
  }
  let wire_min = min.encode()
  assert_eq(@asn1.peek_application_tag(wire_min), @asn1.APP_ENC_TICKET_PART)
  assert_eq(@types.EncTicketPart::decode(wire_min), min)

  let max : @types.EncTicketPart = {
    flags: @types.TKT_FLAG_FORWARDABLE |
    @types.TKT_FLAG_RENEWABLE |
    @types.TKT_FLAG_INITIAL,
    key: make_sample_key(),
    crealm: "EXAMPLE.COM",
    cname: @types.PrincipalName::user("alice"),
    transited: { tr_type: 1, contents: b"A.EXAMPLE.COM,B.EXAMPLE.COM", },
    authtime: "20261126020000Z",
    starttime: Some("20261126020100Z"),
    endtime: "20261126120000Z",
    renew_till: Some("20261203020000Z"),
    caddr: Some(make_sample_host_addrs()),
    authorization_data: Some(make_sample_authz_data()),
  }
  assert_eq(@types.EncTicketPart::decode(max.encode()), max)
}

///|
test "KdcReqBody and KdcReq AS-REQ / TGS-REQ round-trip" {
  let body_min : @types.KdcReqBody = {
    kdc_options: @types.KDC_OPT_FORWARDABLE | @types.KDC_OPT_RENEWABLE,
    cname: None,
    realm: "EXAMPLE.COM",
    sname: None,
    from: None,
    till: "20261126120000Z",
    rtime: None,
    nonce: 0x12345678U,
    etype: [18, 17],
    addresses: None,
    enc_authorization_data: None,
    additional_tickets: None,
  }
  assert_eq(@types.KdcReqBody::decode(body_min.encode()), body_min)

  let body_max : @types.KdcReqBody = {
    kdc_options: @types.KDC_OPT_FORWARDABLE |
    @types.KDC_OPT_PROXIABLE |
    @types.KDC_OPT_CANONICALIZE |
    @types.KDC_OPT_ENC_TKT_IN_SKEY,
    cname: Some(@types.PrincipalName::user("alice")),
    realm: "EXAMPLE.COM",
    sname: Some(@types.PrincipalName::service("krbtgt", "EXAMPLE.COM")),
    from: Some("20261126020000Z"),
    till: "20261126120000Z",
    rtime: Some("20261203020000Z"),
    nonce: 0xFFFF_FFFEU,
    etype: [18, 17, 16],
    addresses: Some(make_sample_host_addrs()),
    enc_authorization_data: Some(make_sample_encrypted_data(true)),
    additional_tickets: Some([make_sample_ticket()]),
  }
  assert_eq(@types.KdcReqBody::decode(body_max.encode()), body_max)

  // AS-REQ minimal & maximal
  let as_req_min : @types.KdcReq = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_AS_REQ,
    padata: None,
    req_body: body_min,
  }
  let as_wire_min = as_req_min.encode_as_req()
  assert_eq(@asn1.peek_application_tag(as_wire_min), @asn1.APP_AS_REQ)
  assert_eq(@types.KdcReq::decode_as_req(as_wire_min), as_req_min)
  // Verify KDC-REQ starts at context tag [1], NOT [0]
  match @asn1.decode_application(as_wire_min, @asn1.APP_AS_REQ) {
    Sequence([Context(1, _), Context(2, _), Context(4, _)]) => ()
    _ => fail("KDC-REQ without padata must have context tags [1], [2], [4]")
  }

  let as_req_max : @types.KdcReq = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_AS_REQ,
    padata: Some([
      { padata_type: @types.PA_ENC_TIMESTAMP, padata_value: b"\x01\x02", },
    ]),
    req_body: body_max,
  }
  assert_eq(
    @types.KdcReq::decode_as_req(as_req_max.encode_as_req()),
    as_req_max,
  )

  // TGS-REQ minimal & maximal
  let tgs_req_min : @types.KdcReq = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_TGS_REQ,
    padata: None,
    req_body: body_min,
  }
  let tgs_wire_min = tgs_req_min.encode_tgs_req()
  assert_eq(@asn1.peek_application_tag(tgs_wire_min), @asn1.APP_TGS_REQ)
  assert_eq(@types.KdcReq::decode_tgs_req(tgs_wire_min), tgs_req_min)

  let tgs_req_max : @types.KdcReq = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_TGS_REQ,
    padata: Some([
      { padata_type: @types.PA_TGS_REQ, padata_value: b"\x6E\x00", },
    ]),
    req_body: body_max,
  }
  assert_eq(
    @types.KdcReq::decode_tgs_req(tgs_req_max.encode_tgs_req()),
    tgs_req_max,
  )

  // Cross-decode tag mismatch rejection
  assert_true(
    capture_err(() => @types.KdcReq::decode_tgs_req(as_wire_min))
    is Some(@asn1.DerError::TagMismatch(..)),
  )
  assert_true(
    capture_err(() => @types.KdcReq::decode_as_req(tgs_wire_min))
    is Some(@asn1.DerError::TagMismatch(..)),
  )

  // Wrong pvno / msg_type rejected on encode
  assert_true(
    capture_err(() => as_req_min.encode_tgs_req())
    is Some(@asn1.DerError::InvalidValue(_)),
  )
  assert_true(
    capture_err(() => tgs_req_min.encode_as_req())
    is Some(@asn1.DerError::InvalidValue(_)),
  )
  assert_true(
    capture_err(() => { ..as_req_min, pvno: 4, }.encode_as_req())
    is Some(@asn1.DerError::InvalidValue(_)),
  )

  // Wrong msg_type on wire rejected on decode
  let bad_as_req_wire = @asn1.encode_application(
    @asn1.APP_AS_REQ,
    @asn1.DerValue::Sequence([
      @asn1.context_field(1, @asn1.encode_int(5)),
      @asn1.context_field(2, @asn1.encode_int(@types.MSG_TGS_REQ)),
      @asn1.context_field(4, body_min.to_der()),
    ]),
  )
  assert_true(
    capture_err(() => @types.KdcReq::decode_as_req(bad_as_req_wire))
    is Some(@asn1.DerError::InvalidValue(_)),
  )

  // KDC-REQ starting at [0] rejected
  let bad_tag_as_req = @asn1.encode_application(
    @asn1.APP_AS_REQ,
    @asn1.DerValue::Sequence([
      @asn1.context_field(0, @asn1.encode_int(5)),
      @asn1.context_field(1, @asn1.encode_int(@types.MSG_AS_REQ)),
      @asn1.context_field(3, body_min.to_der()),
    ]),
  )
  assert_true(
    capture_err(() => @types.KdcReq::decode_as_req(bad_tag_as_req))
    is Some(@asn1.DerError::TagMismatch(..)),
  )
}

///|
test "KdcRep AS-REP / TGS-REP and EncKdcRepPart round-trip" {
  let as_rep_min : @types.KdcRep = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_AS_REP,
    padata: None,
    crealm: "EXAMPLE.COM",
    cname: @types.PrincipalName::user("alice"),
    ticket: make_sample_ticket(),
    enc_part: make_sample_encrypted_data(false),
  }
  let as_rep_wire = as_rep_min.encode_as_rep()
  assert_eq(@asn1.peek_application_tag(as_rep_wire), @asn1.APP_AS_REP)
  assert_eq(@types.KdcRep::decode_as_rep(as_rep_wire), as_rep_min)

  let tgs_rep_max : @types.KdcRep = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_TGS_REP,
    padata: Some([
      { padata_type: @types.PA_ETYPE_INFO2, padata_value: b"\x30\x00", },
    ]),
    crealm: "EXAMPLE.COM",
    cname: @types.PrincipalName::user("alice"),
    ticket: make_sample_ticket(),
    enc_part: make_sample_encrypted_data(true),
  }
  let tgs_rep_wire = tgs_rep_max.encode_tgs_rep()
  assert_eq(@asn1.peek_application_tag(tgs_rep_wire), @asn1.APP_TGS_REP)
  assert_eq(@types.KdcRep::decode_tgs_rep(tgs_rep_wire), tgs_rep_max)

  // Cross-decode tag mismatch rejection
  assert_true(
    capture_err(() => @types.KdcRep::decode_tgs_rep(as_rep_wire))
    is Some(@asn1.DerError::TagMismatch(..)),
  )
  assert_true(
    capture_err(() => @types.KdcRep::decode_as_rep(tgs_rep_wire))
    is Some(@asn1.DerError::TagMismatch(..)),
  )
  // Wrong msg_type / pvno on encode
  assert_true(
    capture_err(() => as_rep_min.encode_tgs_rep())
    is Some(@asn1.DerError::InvalidValue(_)),
  )
  assert_true(
    capture_err(() => { ..as_rep_min, pvno: 4, }.encode_as_rep())
    is Some(@asn1.DerError::InvalidValue(_)),
  )

  // EncKdcRepPart minimal & maximal
  let enc_min : @types.EncKdcRepPart = {
    key: make_sample_key(),
    last_req: [{ lr_type: 0, lr_value: "19700101000000Z", }],
    nonce: 42U,
    key_expiration: None,
    flags: @types.TKT_FLAG_INITIAL,
    authtime: "20261126020000Z",
    starttime: None,
    endtime: "20261126120000Z",
    renew_till: None,
    srealm: "EXAMPLE.COM",
    sname: @types.PrincipalName::service("krbtgt", "EXAMPLE.COM"),
    caddr: None,
  }
  let enc_as_wire = enc_min.encode_enc_as_rep_part()
  assert_eq(@asn1.peek_application_tag(enc_as_wire), @asn1.APP_ENC_AS_REP_PART)
  assert_eq(@types.EncKdcRepPart::decode_enc_as_rep_part(enc_as_wire), enc_min)

  let enc_max : @types.EncKdcRepPart = {
    key: make_sample_key(),
    last_req: [
      { lr_type: 1, lr_value: "20261125000000Z", },
      { lr_type: 2, lr_value: "20261126010000Z", },
    ],
    nonce: 0xDEAD_BEEFU,
    key_expiration: Some("20271126000000Z"),
    flags: @types.TKT_FLAG_FORWARDABLE | @types.TKT_FLAG_RENEWABLE,
    authtime: "20261126020000Z",
    starttime: Some("20261126020000Z"),
    endtime: "20261126120000Z",
    renew_till: Some("20261203020000Z"),
    srealm: "EXAMPLE.COM",
    sname: @types.PrincipalName::service("HTTP", "app.example.com"),
    caddr: Some(make_sample_host_addrs()),
  }
  let enc_tgs_wire = enc_max.encode_enc_tgs_rep_part()
  assert_eq(
    @asn1.peek_application_tag(enc_tgs_wire),
    @asn1.APP_ENC_TGS_REP_PART,
  )
  assert_eq(
    @types.EncKdcRepPart::decode_enc_tgs_rep_part(enc_tgs_wire),
    enc_max,
  )

  // Cross-decode mismatch
  assert_true(
    capture_err(() => @types.EncKdcRepPart::decode_enc_tgs_rep_part(enc_as_wire))
    is Some(@asn1.DerError::TagMismatch(..)),
  )
  assert_true(
    capture_err(() => @types.EncKdcRepPart::decode_enc_as_rep_part(enc_tgs_wire))
    is Some(@asn1.DerError::TagMismatch(..)),
  )
}

///|
test "ApReq, ApRep, and EncApRepPart round-trip and validation" {
  let ap_req : @types.ApReq = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_AP_REQ,
    ap_options: @types.AP_OPT_MUTUAL_REQUIRED,
    ticket: make_sample_ticket(),
    authenticator: make_sample_encrypted_data(false),
  }
  let ap_req_wire = ap_req.encode()
  assert_eq(@asn1.peek_application_tag(ap_req_wire), @asn1.APP_AP_REQ)
  assert_eq(@types.ApReq::decode(ap_req_wire), ap_req)
  assert_true(
    capture_err(() => { ..ap_req, pvno: 4, }.encode())
    is Some(@asn1.DerError::InvalidValue(_)),
  )
  assert_true(
    capture_err(() => { ..ap_req, msg_type: 15, }.encode())
    is Some(@asn1.DerError::InvalidValue(_)),
  )

  let ap_rep : @types.ApRep = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_AP_REP,
    enc_part: make_sample_encrypted_data(false),
  }
  let ap_rep_wire = ap_rep.encode()
  assert_eq(@asn1.peek_application_tag(ap_rep_wire), @asn1.APP_AP_REP)
  assert_eq(@types.ApRep::decode(ap_rep_wire), ap_rep)
  assert_true(
    capture_err(() => { ..ap_rep, pvno: 4, }.encode())
    is Some(@asn1.DerError::InvalidValue(_)),
  )
  assert_true(
    capture_err(() => { ..ap_rep, msg_type: 14, }.encode())
    is Some(@asn1.DerError::InvalidValue(_)),
  )

  // Tag mismatches
  assert_true(
    capture_err(() => @types.ApReq::decode(ap_rep_wire))
    is Some(@asn1.DerError::TagMismatch(..)),
  )
  assert_true(
    capture_err(() => @types.ApRep::decode(ap_req_wire))
    is Some(@asn1.DerError::TagMismatch(..)),
  )

  // EncApRepPart minimal & maximal
  let enc_ap_min : @types.EncApRepPart = {
    ctime: "20261126020000Z",
    cusec: 0,
    subkey: None,
    seq_number: None,
  }
  let enc_ap_wire = enc_ap_min.encode()
  assert_eq(@asn1.peek_application_tag(enc_ap_wire), @asn1.APP_ENC_AP_REP_PART)
  assert_eq(@types.EncApRepPart::decode(enc_ap_wire), enc_ap_min)

  let enc_ap_max : @types.EncApRepPart = {
    ctime: "20261126020000Z",
    cusec: 654321,
    subkey: Some(make_sample_key()),
    seq_number: Some(0x11223344U),
  }
  assert_eq(@types.EncApRepPart::decode(enc_ap_max.encode()), enc_ap_max)
  assert_true(
    capture_err(() => { ..enc_ap_min, cusec: 1000000, }.encode())
    is Some(@asn1.DerError::InvalidValue(_)),
  )
}

///|
test "KrbError round-trip minimal and maximal plus validation" {
  let err_min : @types.KrbError = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_KRB_ERROR,
    ctime: None,
    cusec: None,
    stime: "20261126020000Z",
    susec: 500,
    error_code: @types.KDC_ERR_PREAUTH_REQUIRED,
    crealm: None,
    cname: None,
    realm: "EXAMPLE.COM",
    sname: @types.PrincipalName::service("krbtgt", "EXAMPLE.COM"),
    e_text: None,
    e_data: None,
  }
  let wire_min = err_min.encode()
  assert_eq(@asn1.peek_application_tag(wire_min), @asn1.APP_KRB_ERROR)
  assert_eq(@types.KrbError::decode(wire_min), err_min)

  let method_data = @types.encode_method_data([
    {
      padata_type: @types.PA_ETYPE_INFO2,
      padata_value: @types.encode_etype_info2([
        { etype: 18, salt: Some("EXAMPLE.COMalice"), s2kparams: None, },
      ]),
    },
  ])
  let err_max : @types.KrbError = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_KRB_ERROR,
    ctime: Some("20261126015959Z"),
    cusec: Some(987654),
    stime: "20261126020000Z",
    susec: 123456,
    error_code: @types.KDC_ERR_PREAUTH_REQUIRED,
    crealm: Some("EXAMPLE.COM"),
    cname: Some(@types.PrincipalName::user("alice")),
    realm: "EXAMPLE.COM",
    sname: @types.PrincipalName::service("krbtgt", "EXAMPLE.COM"),
    e_text: Some("Additional pre-authentication required"),
    e_data: Some(method_data),
  }
  let wire_max = err_max.encode()
  assert_eq(@types.KrbError::decode(wire_max), err_max)

  // Validation rejections
  assert_true(
    capture_err(() => { ..err_min, pvno: 4, }.encode())
    is Some(@asn1.DerError::InvalidValue(_)),
  )
  assert_true(
    capture_err(() => { ..err_min, msg_type: 11, }.encode())
    is Some(@asn1.DerError::InvalidValue(_)),
  )
  assert_true(
    capture_err(() => { ..err_min, susec: 1000000, }.encode())
    is Some(@asn1.DerError::InvalidValue(_)),
  )
  assert_true(
    capture_err(() => { ..err_min, cusec: Some(-1), }.encode())
    is Some(@asn1.DerError::InvalidValue(_)),
  )

  // Wire decode rejects wrong msg_type
  let bad_wire = @asn1.encode_application(
    @asn1.APP_KRB_ERROR,
    @asn1.DerValue::Sequence([
      @asn1.context_field(0, @asn1.encode_int(5)),
      @asn1.context_field(1, @asn1.encode_int(14)),
      @asn1.context_field(4, @asn1.encode_generalized_time("20261126020000Z")),
      @asn1.context_field(5, @asn1.encode_int(0)),
      @asn1.context_field(6, @asn1.encode_int(60)),
      @asn1.context_field(9, @asn1.encode_general_string("EXAMPLE.COM")),
      @asn1.context_field(
        10,
        @types.PrincipalName::service("krbtgt", "EXAMPLE.COM").to_der(),
      ),
    ]),
  )
  assert_true(
    capture_err(() => @types.KrbError::decode(bad_wire))
    is Some(@asn1.DerError::InvalidValue(_)),
  )

  // Trailing unknown field rejected
  let extra_field = @asn1.encode_application(
    @asn1.APP_KRB_ERROR,
    @asn1.DerValue::Sequence([
      @asn1.context_field(0, @asn1.encode_int(5)),
      @asn1.context_field(1, @asn1.encode_int(30)),
      @asn1.context_field(4, @asn1.encode_generalized_time("20261126020000Z")),
      @asn1.context_field(5, @asn1.encode_int(0)),
      @asn1.context_field(6, @asn1.encode_int(60)),
      @asn1.context_field(9, @asn1.encode_general_string("EXAMPLE.COM")),
      @asn1.context_field(
        10,
        @types.PrincipalName::service("krbtgt", "EXAMPLE.COM").to_der(),
      ),
      @asn1.context_field(13, @asn1.encode_int(1)),
    ]),
  )
  assert_true(
    capture_err(() => @types.KrbError::decode(extra_field))
    is Some(@asn1.DerError::TagMismatch(..)),
  )

  // Trailing bytes rejected
  let with_trailing = Bytes::makei(wire_min.length() + 1, fn(i) {
    if i < wire_min.length() {
      wire_min[i]
    } else {
      b'\x00'
    }
  })
  assert_true(
    capture_err(() => @types.KrbError::decode(with_trailing))
    is Some(@asn1.DerError::TrailingBytes(1)),
  )

  // Show sanity (non-empty strings for PDUs)
  assert_true(Show::to_string(err_max).length() > 0)
  assert_true(Show::to_string(make_sample_ticket()).length() > 0)
}

///|
test "KdcReq::decode_tgs_req_with_raw_body preserves exact raw wire DER req_body" {
  let req_body : @types.KdcReqBody = {
    kdc_options: @types.KDC_OPT_FORWARDABLE | @types.KDC_OPT_RENEWABLE,
    cname: None,
    realm: "EXAMPLE.COM",
    sname: Some(@types.PrincipalName::service("HTTP", "web.example.com")),
    from: None,
    till: "20300101000000Z",
    rtime: None,
    nonce: 0x13579BDFU,
    etype: [20, 19, 18, 17],
    addresses: None,
    enc_authorization_data: None,
    additional_tickets: None,
  }
  let tgs_req : @types.KdcReq = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_TGS_REQ,
    padata: Some([
      { padata_type: @types.PA_TGS_REQ, padata_value: b"\xAA\xBB", },
    ]),
    req_body,
  }
  let encoded = tgs_req.encode_tgs_req()
  let (decoded, raw_body) = @types.KdcReq::decode_tgs_req_with_raw_body(encoded)
  assert_eq(decoded, tgs_req)
  assert_eq(raw_body, req_body.encode())
}
