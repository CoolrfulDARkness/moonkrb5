///|
const REALM : String = "EXAMPLE.COM"

///|
const BASE_TIME : Int64 = 1700000000L

///|
fn all_etypes() -> Array[@crypto.Enctype] {
  [
    @crypto.Enctype::Aes128CtsHmacSha1_96,
    @crypto.Enctype::Aes256CtsHmacSha1_96,
    @crypto.Enctype::Aes128CtsHmacSha256_128,
    @crypto.Enctype::Aes256CtsHmacSha384_192,
  ]
}

///|
fn fast_s2k() -> Bytes? {
  // 1-iteration s2kparams to exercise full RFC 3962 / RFC 8009 string_to_key quickly.
  Some(b"\x00\x00\x00\x01")
}

///|
fn flip_bit(data : Bytes, idx : Int32, mask : Byte) -> Bytes {
  Bytes::makei(data.length(), fn(i) {
    if i == idx {
      (data[i].to_int() ^ mask.to_int()).to_byte()
    } else {
      data[i]
    }
  })
}

///|
fn slice_bytes(data : Bytes, start : Int32, len : Int32) -> Bytes {
  Bytes::makei(len, fn(i) { data[start + i] })
}

///|
fn make_enc_data(
  etype : @crypto.Enctype,
  key : Bytes,
  kvno : UInt32?,
  usage : Int32,
  plaintext : Bytes,
  rng : @crypto.DeterministicRng,
) -> @types.EncryptedData raise {
  let conf = rng.next_bytes(etype.confounder_size())
  let cipher = @crypto.encrypt(etype, key, usage, plaintext, conf)
  { etype: etype.to_int(), kvno, cipher, }
}

///|
priv struct SecEnv {
  kdc : @protocol.Kdc
  client : @protocol.Client
  service : @protocol.Service
  alice : @types.PrincipalName
  http_svc : @types.PrincipalName
  rng : @crypto.DeterministicRng
  etype : @crypto.Enctype
  alice_key : Bytes
  svc_key : Bytes
}

///|
fn setup_sec_env(
  etype : @crypto.Enctype,
  seed : Bytes,
  require_preauth~ : Bool = true,
  default_lifetime_secs~ : Int64 = 36000L,
  max_skew_secs~ : Int64 = 300L,
  svc_kvno~ : UInt32 = 3U,
) -> SecEnv raise {
  let rng = @crypto.DeterministicRng::new(seed)
  let krbtgt_key = rng.next_bytes(etype.key_size())
  let krbtgt_pk : @protocol.PrincipalKey = {
    etype,
    key: krbtgt_key,
    salt: REALM + "krbtgt" + REALM,
    s2kparams: fast_s2k(),
  }
  let kdc = @protocol.Kdc::new(
    REALM,
    [krbtgt_pk],
    require_preauth~,
    max_skew_secs~,
    default_lifetime_secs~,
  )
  let alice = @types.PrincipalName::user("alice")
  let http_svc = @types.PrincipalName::service("HTTP", "web.example.com")
  let alice_pw = b"alice-security-test-pw!"
  let svc_pw = b"service-security-test-pw!"
  kdc.add_principal_with_password(
    alice,
    alice_pw,
    [etype],
    kvno=2U,
    s2kparams=fast_s2k(),
  )
  kdc.add_principal_with_password(
    http_svc,
    svc_pw,
    [etype],
    kvno=svc_kvno,
    s2kparams=fast_s2k(),
  )
  let alice_salt = Bytes::makei((REALM + "alice").length(), fn(i) {
    (REALM + "alice")[i].to_byte()
  })
  let svc_salt_str = REALM + "HTTPweb.example.com"
  let svc_salt = Bytes::makei(svc_salt_str.length(), fn(i) {
    svc_salt_str[i].to_byte()
  })
  let alice_key = @crypto.string_to_key(etype, alice_pw, alice_salt, fast_s2k())
  let svc_key = @crypto.string_to_key(etype, svc_pw, svc_salt, fast_s2k())
  let kt = kdc.export_keytab(http_svc, timestamp=1700000000U)
  let kt_decoded = @keytab.Keytab::decode(kt.encode())
  let service = @protocol.Service::new(
    REALM,
    http_svc,
    kt_decoded,
    max_skew_secs~,
  )
  let client = @protocol.Client::new(
    alice,
    REALM,
    alice_pw,
    preferred_etypes=[etype],
    min_s2k_iterations=1U,
  )
  { kdc, client, service, alice, http_svc, rng, etype, alice_key, svc_key, }
}

///|
fn run_as_exchange(env : SecEnv, now : Int64) -> @protocol.Credential raise {
  let as_req1 = env.client.build_as_req(now, env.rng)
  let as_resp1 = env.kdc.handle_message(now, 100, env.rng, as_req1)
  match env.client.handle_as_response(now + 1L, 200, env.rng, as_resp1) {
    @protocol.AsStepResult::GotTgt(cred) => cred
    @protocol.AsStepResult::NeedPreauthRetry(as_req2) => {
      let as_resp2 = env.kdc.handle_message(now + 1L, 300, env.rng, as_req2)
      match env.client.handle_as_response(now + 1L, 400, env.rng, as_resp2) {
        @protocol.AsStepResult::GotTgt(cred) => cred
        @protocol.AsStepResult::NeedPreauthRetry(_) =>
          fail("unexpected second preauth retry")
      }
    }
  }
}

///|
fn run_tgs_exchange(
  env : SecEnv,
  svc : @types.PrincipalName,
  now : Int64,
  usec : Int32,
) -> @protocol.Credential raise {
  let tgs_req = env.client.build_tgs_req(svc, now, usec, env.rng)
  let tgs_resp = env.kdc.handle_message(now, usec + 1, env.rng, tgs_req)
  env.client.handle_tgs_response(tgs_resp)
}

///|
fn build_custom_ap_req(
  etype : @crypto.Enctype,
  svc_key : Bytes,
  svc_kvno : UInt32,
  sname : @types.PrincipalName,
  enc_ticket_part : @types.EncTicketPart,
  tkt_usage : Int32,
  auth : @types.Authenticator,
  auth_usage : Int32,
  rng : @crypto.DeterministicRng,
) -> Bytes raise {
  let tkt_enc = make_enc_data(
    etype,
    svc_key,
    Some(svc_kvno),
    tkt_usage,
    enc_ticket_part.encode(),
    rng,
  )
  let ticket : @types.Ticket = {
    tkt_vno: @types.KRB5_PVNO,
    realm: REALM,
    sname,
    enc_part: tkt_enc,
  }
  let auth_enc = make_enc_data(
    etype,
    enc_ticket_part.key.keyvalue,
    None,
    auth_usage,
    auth.encode(),
    rng,
  )
  let ap_req : @types.ApReq = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_AP_REQ,
    ap_options: 0U,
    ticket,
    authenticator: auth_enc,
  }
  ap_req.encode()
}

///|
test "sec_01: expired TGT rejected by KDC at TGS-REQ with KRB_AP_ERR_TKT_EXPIRED" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_01_seed",
    default_lifetime_secs=600L,
  )
  let _ = run_as_exchange(env, BASE_TIME)
  let expired_time = BASE_TIME + 602L
  let tgs_req = env.client.build_tgs_req(
    env.http_svc,
    expired_time,
    10,
    env.rng,
  )
  let resp = env.kdc.handle_message(expired_time, 11, env.rng, tgs_req)
  assert_eq(@asn1.peek_application_tag(resp), @asn1.APP_KRB_ERROR)
  let krb_err = @types.KrbError::decode(resp)
  assert_eq(krb_err.error_code, @types.KRB_AP_ERR_TKT_EXPIRED)
  let mut got_expected = false
  try {
    let _ = env.client.handle_tgs_response(resp)
  } catch {
    @protocol.ProtocolError::KrbErrorReceived(code~, ..) =>
      got_expected = code == @types.KRB_AP_ERR_TKT_EXPIRED
    _ => ()
  }
  assert_true(got_expected)
}

///|
test "sec_02: expired Service Ticket rejected by Service with TicketExpired" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_02_seed",
    default_lifetime_secs=600L,
  )
  let _ = run_as_exchange(env, BASE_TIME)
  let svc_cred = run_tgs_exchange(env, env.http_svc, BASE_TIME + 5L, 100)
  let expired_time = BASE_TIME + 605L
  let ap_req = env.client.build_ap_req(svc_cred, expired_time, 50, env.rng)
  let mut got_expired = false
  try {
    let _ = env.service.verify_ap_req(expired_time, env.rng, ap_req)
  } catch {
    @protocol.ProtocolError::TicketExpired => got_expired = true
    _ => ()
  }
  assert_true(got_expired)
}

///|
test "sec_03: not-yet-valid Service Ticket rejected with TicketNotYetValid" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes128CtsHmacSha256_128,
    b"sec_03_seed",
  )
  let sess_key : @types.EncryptionKey = {
    keytype: env.etype.to_int(),
    keyvalue: env.rng.next_bytes(env.etype.key_size()),
  }
  let enc_tkt : @types.EncTicketPart = {
    flags: @types.TKT_FLAG_PRE_AUTHENT,
    key: sess_key,
    crealm: REALM,
    cname: env.alice,
    transited: { tr_type: 1, contents: b"", },
    authtime: @types.unix_to_kerberos_time(BASE_TIME),
    starttime: Some(@types.unix_to_kerberos_time(BASE_TIME + 1000L)),
    endtime: @types.unix_to_kerberos_time(BASE_TIME + 5000L),
    renew_till: None,
    caddr: None,
    authorization_data: None,
  }
  let auth : @types.Authenticator = {
    authenticator_vno: @types.KRB5_PVNO,
    crealm: REALM,
    cname: env.alice,
    cksum: None,
    cusec: 42,
    ctime: @types.unix_to_kerberos_time(BASE_TIME),
    subkey: None,
    seq_number: None,
    authorization_data: None,
  }
  let ap_req_der = build_custom_ap_req(
    env.etype,
    env.svc_key,
    3U,
    env.http_svc,
    enc_tkt,
    @crypto.KU_TICKET,
    auth,
    @crypto.KU_AP_REQ_AUTH,
    env.rng,
  )
  let mut got_nyv = false
  try {
    let _ = env.service.verify_ap_req(BASE_TIME, env.rng, ap_req_der)
  } catch {
    @protocol.ProtocolError::TicketNotYetValid => got_nyv = true
    _ => ()
  }
  assert_true(got_nyv)
}

///|
test "sec_04: ticket with TKT_FLAG_INVALID rejected with TicketInvalidFlag" {
  let env = setup_sec_env(@crypto.Enctype::Aes256CtsHmacSha1_96, b"sec_04_seed")
  let sess_key : @types.EncryptionKey = {
    keytype: env.etype.to_int(),
    keyvalue: env.rng.next_bytes(env.etype.key_size()),
  }
  let enc_tkt : @types.EncTicketPart = {
    flags: @types.TKT_FLAG_INVALID | @types.TKT_FLAG_POSTDATED,
    key: sess_key,
    crealm: REALM,
    cname: env.alice,
    transited: { tr_type: 1, contents: b"", },
    authtime: @types.unix_to_kerberos_time(BASE_TIME),
    starttime: Some(@types.unix_to_kerberos_time(BASE_TIME)),
    endtime: @types.unix_to_kerberos_time(BASE_TIME + 3600L),
    renew_till: None,
    caddr: None,
    authorization_data: None,
  }
  let auth : @types.Authenticator = {
    authenticator_vno: @types.KRB5_PVNO,
    crealm: REALM,
    cname: env.alice,
    cksum: None,
    cusec: 77,
    ctime: @types.unix_to_kerberos_time(BASE_TIME),
    subkey: None,
    seq_number: None,
    authorization_data: None,
  }
  let ap_req_der = build_custom_ap_req(
    env.etype,
    env.svc_key,
    3U,
    env.http_svc,
    enc_tkt,
    @crypto.KU_TICKET,
    auth,
    @crypto.KU_AP_REQ_AUTH,
    env.rng,
  )
  let mut got_invalid_flag = false
  try {
    let _ = env.service.verify_ap_req(BASE_TIME, env.rng, ap_req_der)
  } catch {
    @protocol.ProtocolError::TicketInvalidFlag => got_invalid_flag = true
    _ => ()
  }
  assert_true(got_invalid_flag)
}

///|
test "sec_05: replayed AP-REQ Authenticator rejected by Service with ReplayDetected" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_05_seed",
  )
  let _ = run_as_exchange(env, BASE_TIME)
  let svc_cred = run_tgs_exchange(env, env.http_svc, BASE_TIME + 5L, 100)
  let ap_req = env.client.build_ap_req(svc_cred, BASE_TIME + 10L, 555, env.rng)
  let verified = env.service.verify_ap_req(BASE_TIME + 10L, env.rng, ap_req)
  assert_eq(verified.client, env.alice)
  let mut got_replay = false
  try {
    let _ = env.service.verify_ap_req(BASE_TIME + 12L, env.rng, ap_req)
  } catch {
    @protocol.ProtocolError::ReplayDetected => got_replay = true
    _ => ()
  }
  assert_true(got_replay)
}

///|
test "sec_06: replayed TGS-REQ Authenticator rejected by KDC with KRB_AP_ERR_REPEAT" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes128CtsHmacSha256_128,
    b"sec_06_seed",
  )
  let _ = run_as_exchange(env, BASE_TIME)
  let tgs_req = env.client.build_tgs_req(
    env.http_svc,
    BASE_TIME + 5L,
    700,
    env.rng,
  )
  let resp1 = env.kdc.handle_message(BASE_TIME + 5L, 701, env.rng, tgs_req)
  assert_eq(@asn1.peek_application_tag(resp1), @asn1.APP_TGS_REP)
  let resp2 = env.kdc.handle_message(BASE_TIME + 6L, 702, env.rng, tgs_req)
  assert_eq(@asn1.peek_application_tag(resp2), @asn1.APP_KRB_ERROR)
  let krb_err = @types.KrbError::decode(resp2)
  assert_eq(krb_err.error_code, @types.KRB_AP_ERR_REPEAT)
}

///|
test "sec_07: replayed PA-ENC-TIMESTAMP preauth rejected by KDC" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_07_seed",
  )
  let as_req1 = env.client.build_as_req(BASE_TIME, env.rng)
  let as_resp1 = env.kdc.handle_message(BASE_TIME, 100, env.rng, as_req1)
  let as_req2 = match
    env.client.handle_as_response(BASE_TIME + 1L, 200, env.rng, as_resp1) {
    @protocol.AsStepResult::NeedPreauthRetry(der) => der
    @protocol.AsStepResult::GotTgt(_) => fail("expected preauth retry")
  }
  let ok_resp = env.kdc.handle_message(BASE_TIME + 1L, 201, env.rng, as_req2)
  assert_eq(@asn1.peek_application_tag(ok_resp), @asn1.APP_AS_REP)
  let replay_resp = env.kdc.handle_message(
    BASE_TIME + 2L,
    202,
    env.rng,
    as_req2,
  )
  assert_eq(@asn1.peek_application_tag(replay_resp), @asn1.APP_KRB_ERROR)
  let krb_err = @types.KrbError::decode(replay_resp)
  assert_eq(krb_err.error_code, @types.KRB_AP_ERR_REPEAT)
}

///|
test "sec_08: bit-flipped Ticket enc_part ciphertext rejected across all 4 etypes" {
  let etypes = all_etypes()
  for i = 0; i < etypes.length(); i = i + 1 {
    let et = etypes[i]
    let seed = Bytes::makei(8, fn(j) { (0x80 + i * 13 + j).to_byte() })
    let env = setup_sec_env(et, seed)
    let _ = run_as_exchange(env, BASE_TIME)
    let svc_cred = run_tgs_exchange(env, env.http_svc, BASE_TIME + 5L, 100)
    let ap_req_der = env.client.build_ap_req(
      svc_cred,
      BASE_TIME + 10L,
      200,
      env.rng,
    )
    let ap_req = @types.ApReq::decode(ap_req_der)
    let orig_cipher = ap_req.ticket.enc_part.cipher
    // Flip a bit in the encrypted payload and in the trailing MAC tag
    let positions = [0, orig_cipher.length() / 2, orig_cipher.length() - 1]
    for pos in positions {
      let tampered_enc : @types.EncryptedData = {
        etype: ap_req.ticket.enc_part.etype,
        kvno: ap_req.ticket.enc_part.kvno,
        cipher: flip_bit(orig_cipher, pos, b'\x01'),
      }
      let tampered_tkt : @types.Ticket = {
        tkt_vno: ap_req.ticket.tkt_vno,
        realm: ap_req.ticket.realm,
        sname: ap_req.ticket.sname,
        enc_part: tampered_enc,
      }
      let tampered_ap_req : @types.ApReq = {
        pvno: ap_req.pvno,
        msg_type: ap_req.msg_type,
        ap_options: ap_req.ap_options,
        ticket: tampered_tkt,
        authenticator: ap_req.authenticator,
      }
      let mut got_integrity_err = false
      try {
        let _ = env.service.verify_ap_req(
          BASE_TIME + 10L,
          env.rng,
          tampered_ap_req.encode(),
        )
      } catch {
        @protocol.ProtocolError::Crypto(
          @crypto.CryptoError::IntegrityCheckFailed,
        ) => got_integrity_err = true
        _ => ()
      }
      assert_true(got_integrity_err)
    }
  }
}

///|
test "sec_09: bit-flipped AP-REQ Authenticator ciphertext rejected" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_09_seed",
  )
  let _ = run_as_exchange(env, BASE_TIME)
  let svc_cred = run_tgs_exchange(env, env.http_svc, BASE_TIME + 5L, 100)
  let ap_req_der = env.client.build_ap_req(
    svc_cred,
    BASE_TIME + 10L,
    200,
    env.rng,
  )
  let ap_req = @types.ApReq::decode(ap_req_der)
  let tampered_auth : @types.EncryptedData = {
    etype: ap_req.authenticator.etype,
    kvno: ap_req.authenticator.kvno,
    cipher: flip_bit(ap_req.authenticator.cipher, 5, b'\x80'),
  }
  let tampered_ap_req : @types.ApReq = {
    pvno: ap_req.pvno,
    msg_type: ap_req.msg_type,
    ap_options: ap_req.ap_options,
    ticket: ap_req.ticket,
    authenticator: tampered_auth,
  }
  let mut got_integrity_err = false
  try {
    let _ = env.service.verify_ap_req(
      BASE_TIME + 10L,
      env.rng,
      tampered_ap_req.encode(),
    )
  } catch {
    @protocol.ProtocolError::Crypto(@crypto.CryptoError::IntegrityCheckFailed) =>
      got_integrity_err = true
    _ => ()
  }
  assert_true(got_integrity_err)
}

///|
test "sec_10: bit-flipped AS-REP enc_part ciphertext rejected by Client" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_10_seed",
  )
  let as_req1 = env.client.build_as_req(BASE_TIME, env.rng)
  let as_resp1 = env.kdc.handle_message(BASE_TIME, 100, env.rng, as_req1)
  let as_req2 = match
    env.client.handle_as_response(BASE_TIME + 1L, 200, env.rng, as_resp1) {
    @protocol.AsStepResult::NeedPreauthRetry(der) => der
    @protocol.AsStepResult::GotTgt(_) => fail("expected preauth retry")
  }
  let as_resp2 = env.kdc.handle_message(BASE_TIME + 1L, 300, env.rng, as_req2)
  let rep = @types.KdcRep::decode_as_rep(as_resp2)
  let tampered_rep : @types.KdcRep = {
    pvno: rep.pvno,
    msg_type: rep.msg_type,
    padata: rep.padata,
    crealm: rep.crealm,
    cname: rep.cname,
    ticket: rep.ticket,
    enc_part: {
      etype: rep.enc_part.etype,
      kvno: rep.enc_part.kvno,
      cipher: flip_bit(rep.enc_part.cipher, 10, b'\x04'),
    },
  }
  let mut got_integrity_err = false
  try {
    let _ = env.client.handle_as_response(
      BASE_TIME + 1L,
      400,
      env.rng,
      tampered_rep.encode_as_rep(),
    )
  } catch {
    @protocol.ProtocolError::Crypto(@crypto.CryptoError::IntegrityCheckFailed) =>
      got_integrity_err = true
    _ => ()
  }
  assert_true(got_integrity_err)
}

///|
test "sec_11: tampered TGS-REQ req_body sname rejected by KDC with KRB_AP_ERR_MODIFIED" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_11_seed",
  )
  let admin_svc = @types.PrincipalName::service("HTTP", "admin.example.com")
  env.kdc.add_principal_with_password(
    admin_svc,
    b"admin-service-password!",
    [env.etype],
    kvno=1U,
    s2kparams=fast_s2k(),
  )
  let _ = run_as_exchange(env, BASE_TIME)
  let tgs_req_der = env.client.build_tgs_req(
    env.http_svc,
    BASE_TIME + 5L,
    100,
    env.rng,
  )
  let tgs_req = @types.KdcReq::decode_tgs_req(tgs_req_der)
  let tampered_body : @types.KdcReqBody = {
    kdc_options: tgs_req.req_body.kdc_options,
    cname: tgs_req.req_body.cname,
    realm: tgs_req.req_body.realm,
    sname: Some(admin_svc),
    from: tgs_req.req_body.from,
    till: tgs_req.req_body.till,
    rtime: tgs_req.req_body.rtime,
    nonce: tgs_req.req_body.nonce,
    etype: tgs_req.req_body.etype,
    addresses: tgs_req.req_body.addresses,
    enc_authorization_data: tgs_req.req_body.enc_authorization_data,
    additional_tickets: tgs_req.req_body.additional_tickets,
  }
  let tampered_req : @types.KdcReq = {
    pvno: tgs_req.pvno,
    msg_type: tgs_req.msg_type,
    padata: tgs_req.padata,
    req_body: tampered_body,
  }
  let resp = env.kdc.handle_message(
    BASE_TIME + 5L,
    101,
    env.rng,
    tampered_req.encode_tgs_req(),
  )
  assert_eq(@asn1.peek_application_tag(resp), @asn1.APP_KRB_ERROR)
  let krb_err = @types.KrbError::decode(resp)
  assert_eq(krb_err.error_code, @types.KRB_AP_ERR_MODIFIED)
}

///|
test "sec_12: KeyUsage confusion KU_AP_REQ_AUTH instead of KU_TICKET rejected" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_12_seed",
  )
  let sess_key : @types.EncryptionKey = {
    keytype: env.etype.to_int(),
    keyvalue: env.rng.next_bytes(env.etype.key_size()),
  }
  let enc_tkt : @types.EncTicketPart = {
    flags: @types.TKT_FLAG_PRE_AUTHENT,
    key: sess_key,
    crealm: REALM,
    cname: env.alice,
    transited: { tr_type: 1, contents: b"", },
    authtime: @types.unix_to_kerberos_time(BASE_TIME),
    starttime: Some(@types.unix_to_kerberos_time(BASE_TIME)),
    endtime: @types.unix_to_kerberos_time(BASE_TIME + 3600L),
    renew_till: None,
    caddr: None,
    authorization_data: None,
  }
  let auth : @types.Authenticator = {
    authenticator_vno: @types.KRB5_PVNO,
    crealm: REALM,
    cname: env.alice,
    cksum: None,
    cusec: 10,
    ctime: @types.unix_to_kerberos_time(BASE_TIME),
    subkey: None,
    seq_number: None,
    authorization_data: None,
  }
  let bad_ap_req = build_custom_ap_req(
    env.etype,
    env.svc_key,
    3U,
    env.http_svc,
    enc_tkt,
    @crypto.KU_AP_REQ_AUTH,
    auth,
    @crypto.KU_AP_REQ_AUTH,
    env.rng,
  )
  let mut got_integrity_err = false
  try {
    let _ = env.service.verify_ap_req(BASE_TIME, env.rng, bad_ap_req)
  } catch {
    @protocol.ProtocolError::Crypto(@crypto.CryptoError::IntegrityCheckFailed) =>
      got_integrity_err = true
    _ => ()
  }
  assert_true(got_integrity_err)
}

///|
test "sec_13: KeyUsage confusion KU_TGS_REQ_AUTH submitted to Service rejected" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes128CtsHmacSha256_128,
    b"sec_13_seed",
  )
  let _ = run_as_exchange(env, BASE_TIME)
  let svc_cred = run_tgs_exchange(env, env.http_svc, BASE_TIME + 5L, 100)
  let auth : @types.Authenticator = {
    authenticator_vno: @types.KRB5_PVNO,
    crealm: svc_cred.crealm,
    cname: svc_cred.client,
    cksum: None,
    cusec: 25,
    ctime: @types.unix_to_kerberos_time(BASE_TIME + 10L),
    subkey: None,
    seq_number: None,
    authorization_data: None,
  }
  let wrong_usage_auth = make_enc_data(
    env.etype,
    svc_cred.session_key.keyvalue,
    None,
    @crypto.KU_TGS_REQ_AUTH,
    auth.encode(),
    env.rng,
  )
  let ap_req : @types.ApReq = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_AP_REQ,
    ap_options: 0U,
    ticket: svc_cred.ticket,
    authenticator: wrong_usage_auth,
  }
  let mut got_integrity_err = false
  try {
    let _ = env.service.verify_ap_req(BASE_TIME + 10L, env.rng, ap_req.encode())
  } catch {
    @protocol.ProtocolError::Crypto(@crypto.CryptoError::IntegrityCheckFailed) =>
      got_integrity_err = true
    _ => ()
  }
  assert_true(got_integrity_err)
}

///|
test "sec_14: KeyUsage confusion KU_AS_REP_ENCPART in PA-ENC-TIMESTAMP rejected by KDC" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_14_seed",
  )
  let ts : @types.PaEncTsEnc = {
    patimestamp: @types.unix_to_kerberos_time(BASE_TIME),
    pausec: Some(123),
  }
  let wrong_usage_ts = make_enc_data(
    env.etype,
    env.alice_key,
    None,
    @crypto.KU_AS_REP_ENCPART,
    ts.encode(),
    env.rng,
  )
  let req_body : @types.KdcReqBody = {
    kdc_options: @types.KDC_OPT_FORWARDABLE,
    cname: Some(env.alice),
    realm: REALM,
    sname: Some(@types.PrincipalName::service("krbtgt", REALM)),
    from: None,
    till: @types.unix_to_kerberos_time(BASE_TIME + 3600L),
    rtime: None,
    nonce: 0x12345678U,
    etype: [env.etype.to_int()],
    addresses: None,
    enc_authorization_data: None,
    additional_tickets: None,
  }
  let as_req : @types.KdcReq = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_AS_REQ,
    padata: Some([
      {
        padata_type: @types.PA_ENC_TIMESTAMP,
        padata_value: @asn1.encode_der(wrong_usage_ts.to_der()),
      },
    ]),
    req_body,
  }
  let resp = env.kdc.handle_as_req(
    BASE_TIME,
    124,
    env.rng,
    as_req.encode_as_req(),
  )
  assert_eq(@asn1.peek_application_tag(resp), @asn1.APP_KRB_ERROR)
  let krb_err = @types.KrbError::decode(resp)
  assert_eq(krb_err.error_code, @types.KDC_ERR_PREAUTH_FAILED)
}

///|
test "sec_15: full KeyUsage isolation matrix across all 4 etypes (17/18/19/20)" {
  let usages = [
    @crypto.KU_AS_REQ_PA_ENC_TIMESTAMP,
    @crypto.KU_TICKET,
    @crypto.KU_AS_REP_ENCPART,
    @crypto.KU_TGS_REQ_AUTH,
    @crypto.KU_TGS_REP_ENCPART_SESSION_KEY,
    @crypto.KU_TGS_REP_ENCPART_AUTH_SUBKEY,
    @crypto.KU_AP_REQ_AUTH,
    @crypto.KU_AP_REP_ENCPART,
  ]
  let rng = @crypto.DeterministicRng::new(b"sec_15_matrix_seed")
  let plaintext = b"Kerberos-5-KeyUsage-Domain-Separation-Matrix-Payload"
  for et in all_etypes() {
    let key = rng.next_bytes(et.key_size())
    for u_enc in usages {
      let conf = rng.next_bytes(et.confounder_size())
      let ct = @crypto.encrypt(et, key, u_enc, plaintext, conf)
      assert_eq(@crypto.decrypt(et, key, u_enc, ct), plaintext)
      for u_dec in usages {
        if u_dec != u_enc {
          let mut rejected = false
          try {
            let _ = @crypto.decrypt(et, key, u_dec, ct)
          } catch {
            @crypto.CryptoError::IntegrityCheckFailed => rejected = true
            _ => ()
          }
          assert_true(rejected)
        }
      }
    }
  }
}

///|
test "sec_16: principal substitution between Authenticator and EncTicketPart rejected" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_16_seed",
  )
  let _ = run_as_exchange(env, BASE_TIME)
  let svc_cred = run_tgs_exchange(env, env.http_svc, BASE_TIME + 5L, 100)
  // Case A: forged cname = "bob"
  let bob_auth : @types.Authenticator = {
    authenticator_vno: @types.KRB5_PVNO,
    crealm: REALM,
    cname: @types.PrincipalName::user("bob"),
    cksum: None,
    cusec: 10,
    ctime: @types.unix_to_kerberos_time(BASE_TIME + 10L),
    subkey: None,
    seq_number: None,
    authorization_data: None,
  }
  let ap_req_a : @types.ApReq = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_AP_REQ,
    ap_options: 0U,
    ticket: svc_cred.ticket,
    authenticator: make_enc_data(
      env.etype,
      svc_cred.session_key.keyvalue,
      None,
      @crypto.KU_AP_REQ_AUTH,
      bob_auth.encode(),
      env.rng,
    ),
  }
  let mut got_mismatch_a = false
  try {
    let _ = env.service.verify_ap_req(
      BASE_TIME + 10L,
      env.rng,
      ap_req_a.encode(),
    )
  } catch {
    @protocol.ProtocolError::PrincipalMismatch(_) => got_mismatch_a = true
    _ => ()
  }
  assert_true(got_mismatch_a)
  // Case B: forged crealm = "EVIL.COM"
  let evil_realm_auth : @types.Authenticator = {
    authenticator_vno: @types.KRB5_PVNO,
    crealm: "EVIL.COM",
    cname: env.alice,
    cksum: None,
    cusec: 11,
    ctime: @types.unix_to_kerberos_time(BASE_TIME + 10L),
    subkey: None,
    seq_number: None,
    authorization_data: None,
  }
  let ap_req_b : @types.ApReq = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_AP_REQ,
    ap_options: 0U,
    ticket: svc_cred.ticket,
    authenticator: make_enc_data(
      env.etype,
      svc_cred.session_key.keyvalue,
      None,
      @crypto.KU_AP_REQ_AUTH,
      evil_realm_auth.encode(),
      env.rng,
    ),
  }
  let mut got_mismatch_b = false
  try {
    let _ = env.service.verify_ap_req(
      BASE_TIME + 10L,
      env.rng,
      ap_req_b.encode(),
    )
  } catch {
    @protocol.ProtocolError::PrincipalMismatch(_) => got_mismatch_b = true
    _ => ()
  }
  assert_true(got_mismatch_b)
}

///|
test "sec_17: ticket for HTTP/a.example.com delivered to HTTP/b.example.com rejected" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_17_seed",
  )
  let svc_a = @types.PrincipalName::service("HTTP", "a.example.com")
  let svc_b = @types.PrincipalName::service("HTTP", "b.example.com")
  env.kdc.add_principal_with_password(
    svc_a,
    b"svc-a-pw!",
    [env.etype],
    kvno=1U,
    s2kparams=fast_s2k(),
  )
  env.kdc.add_principal_with_password(
    svc_b,
    b"svc-b-pw!",
    [env.etype],
    kvno=1U,
    s2kparams=fast_s2k(),
  )
  let kt_b = env.kdc.export_keytab(svc_b)
  let service_b = @protocol.Service::new(REALM, svc_b, kt_b)
  let _ = run_as_exchange(env, BASE_TIME)
  let cred_a = run_tgs_exchange(env, svc_a, BASE_TIME + 5L, 100)
  let ap_req_a = env.client.build_ap_req(cred_a, BASE_TIME + 10L, 200, env.rng)
  let mut got_wrong_service = false
  try {
    let _ = service_b.verify_ap_req(BASE_TIME + 10L, env.rng, ap_req_a)
  } catch {
    @protocol.ProtocolError::WrongService(_) => got_wrong_service = true
    _ => ()
  }
  assert_true(got_wrong_service)
}

///|
test "sec_18: Authenticator clock skew >300s ahead and behind rejected with ClockSkew" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_18_seed",
    max_skew_secs=300L,
  )
  let _ = run_as_exchange(env, BASE_TIME)
  let svc_cred = run_tgs_exchange(env, env.http_svc, BASE_TIME + 5L, 100)
  // Ahead by 301s
  let ap_req_future = env.client.build_ap_req(
    svc_cred,
    BASE_TIME + 311L,
    1,
    env.rng,
    mutual_required=false,
  )
  let mut got_skew_future = false
  try {
    let _ = env.service.verify_ap_req(BASE_TIME + 10L, env.rng, ap_req_future)
  } catch {
    @protocol.ProtocolError::ClockSkew(diff) => got_skew_future = diff == -301L
    _ => ()
  }
  assert_true(got_skew_future)
  // Behind by 301s
  let ap_req_past = env.client.build_ap_req(
    svc_cred,
    BASE_TIME - 291L,
    2,
    env.rng,
    mutual_required=false,
  )
  let mut got_skew_past = false
  try {
    let _ = env.service.verify_ap_req(BASE_TIME + 10L, env.rng, ap_req_past)
  } catch {
    @protocol.ProtocolError::ClockSkew(diff) => got_skew_past = diff == 301L
    _ => ()
  }
  assert_true(got_skew_past)
}

///|
test "sec_19: wrong password / forged PA-ENC-TIMESTAMP rejected with KDC_ERR_PREAUTH_FAILED" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_19_seed",
  )
  let bad_client = @protocol.Client::new(
    env.alice,
    REALM,
    b"totally-wrong-password!",
    preferred_etypes=[env.etype],
    min_s2k_iterations=1U,
  )
  let as_req1 = bad_client.build_as_req(BASE_TIME, env.rng)
  let as_resp1 = env.kdc.handle_message(BASE_TIME, 100, env.rng, as_req1)
  let as_req2 = match
    bad_client.handle_as_response(BASE_TIME + 1L, 200, env.rng, as_resp1) {
    @protocol.AsStepResult::NeedPreauthRetry(der) => der
    @protocol.AsStepResult::GotTgt(_) => fail("expected NeedPreauthRetry")
  }
  let as_resp2 = env.kdc.handle_message(BASE_TIME + 1L, 300, env.rng, as_req2)
  assert_eq(@asn1.peek_application_tag(as_resp2), @asn1.APP_KRB_ERROR)
  let krb_err = @types.KrbError::decode(as_resp2)
  assert_eq(krb_err.error_code, @types.KDC_ERR_PREAUTH_FAILED)
  let mut client_got_preauth_failed = false
  try {
    let _ = bad_client.handle_as_response(
      BASE_TIME + 1L,
      400,
      env.rng,
      as_resp2,
    )
  } catch {
    @protocol.ProtocolError::PreauthFailed(_) =>
      client_got_preauth_failed = true
    _ => ()
  }
  assert_true(client_got_preauth_failed)
}

///|
test "sec_20: etype downgrade and unsupported etype rejected with KDC_ERR_ETYPE_NOSUPP" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_20_seed",
  )
  // Case A: legacy weak etypes (DES-CBC-CRC=1, DES-CBC-MD5=3, RC4-HMAC=23)
  let weak_req_body : @types.KdcReqBody = {
    kdc_options: @types.KDC_OPT_FORWARDABLE,
    cname: Some(env.alice),
    realm: REALM,
    sname: Some(@types.PrincipalName::service("krbtgt", REALM)),
    from: None,
    till: @types.unix_to_kerberos_time(BASE_TIME + 3600L),
    rtime: None,
    nonce: 0xABCDEF01U,
    etype: [1, 3, 23],
    addresses: None,
    enc_authorization_data: None,
    additional_tickets: None,
  }
  let weak_as_req : @types.KdcReq = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_AS_REQ,
    padata: None,
    req_body: weak_req_body,
  }
  let resp_a = env.kdc.handle_message(
    BASE_TIME,
    10,
    env.rng,
    weak_as_req.encode_as_req(),
  )
  assert_eq(@asn1.peek_application_tag(resp_a), @asn1.APP_KRB_ERROR)
  assert_eq(
    @types.KrbError::decode(resp_a).error_code,
    @types.KDC_ERR_ETYPE_NOSUPP,
  )
  // Case B: valid etype 17 requested when KDC only holds etype 20 keys
  let mismatch_client = @protocol.Client::new(
    env.alice,
    REALM,
    b"alice-security-test-pw!",
    preferred_etypes=[@crypto.Enctype::Aes128CtsHmacSha1_96],
  )
  let as_req_b = mismatch_client.build_as_req(BASE_TIME, env.rng)
  let resp_b = env.kdc.handle_message(BASE_TIME, 20, env.rng, as_req_b)
  assert_eq(@asn1.peek_application_tag(resp_b), @asn1.APP_KRB_ERROR)
  assert_eq(
    @types.KrbError::decode(resp_b).error_code,
    @types.KDC_ERR_ETYPE_NOSUPP,
  )
}

///|
test "sec_21: keytab BadKeyVersion and unknown principal KeyNotFound rejected" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_21_seed",
    svc_kvno=5U,
  )
  let _ = run_as_exchange(env, BASE_TIME)
  let svc_cred = run_tgs_exchange(env, env.http_svc, BASE_TIME + 5L, 100)
  let ap_req = env.client.build_ap_req(svc_cred, BASE_TIME + 10L, 200, env.rng)
  // Case A: keytab has same principal & etype but older kvno=3 instead of 5 -> BadKeyVersion
  let stale_kt = @keytab.Keytab::new()
  stale_kt.add_entry({
    realm: REALM,
    components: env.http_svc.name_string.copy(),
    name_type: env.http_svc.name_type,
    timestamp: 1700000000U,
    kvno: 3U,
    etype: env.etype.to_int(),
    key: env.svc_key,
  })
  let stale_service = @protocol.Service::new(REALM, env.http_svc, stale_kt)
  let mut got_bad_kvno = false
  try {
    let _ = stale_service.verify_ap_req(BASE_TIME + 10L, env.rng, ap_req)
  } catch {
    @protocol.ProtocolError::BadKeyVersion => got_bad_kvno = true
    _ => ()
  }
  assert_true(got_bad_kvno)
  // Case B: keytab lacks the service principal entirely -> KeyNotFound
  let empty_kt = @keytab.Keytab::new()
  let nokey_service = @protocol.Service::new(REALM, env.http_svc, empty_kt)
  let mut got_key_not_found = false
  try {
    let _ = nokey_service.verify_ap_req(BASE_TIME + 10L, env.rng, ap_req)
  } catch {
    @protocol.ProtocolError::KeyNotFound(_) => got_key_not_found = true
    _ => ()
  }
  assert_true(got_key_not_found)
}

///|
test "sec_22: forged AP-REP ctime or cusec rejected by Client with MutualAuthFailed" {
  // Case A: forged ctime (+1s)
  let env_a = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_22_a_seed",
  )
  let _ = run_as_exchange(env_a, BASE_TIME)
  let cred_a = run_tgs_exchange(env_a, env_a.http_svc, BASE_TIME + 5L, 100)
  let _ = env_a.client.build_ap_req(
    cred_a,
    BASE_TIME + 10L,
    4321,
    env_a.rng,
    mutual_required=true,
  )
  let forged_part_a : @types.EncApRepPart = {
    ctime: @types.unix_to_kerberos_time(BASE_TIME + 11L),
    cusec: 4321,
    subkey: None,
    seq_number: None,
  }
  let forged_ap_rep_a : @types.ApRep = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_AP_REP,
    enc_part: make_enc_data(
      env_a.etype,
      cred_a.session_key.keyvalue,
      None,
      @crypto.KU_AP_REP_ENCPART,
      forged_part_a.encode(),
      env_a.rng,
    ),
  }
  let mut got_mut_fail_a = false
  try {
    let _ = env_a.client.handle_ap_rep(forged_ap_rep_a.encode())
  } catch {
    @protocol.ProtocolError::MutualAuthFailed(_) => got_mut_fail_a = true
    _ => ()
  }
  assert_true(got_mut_fail_a)
  // Case B: forged cusec (+1)
  let env_b = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_22_b_seed",
  )
  let _ = run_as_exchange(env_b, BASE_TIME)
  let cred_b = run_tgs_exchange(env_b, env_b.http_svc, BASE_TIME + 5L, 100)
  let _ = env_b.client.build_ap_req(
    cred_b,
    BASE_TIME + 10L,
    4321,
    env_b.rng,
    mutual_required=true,
  )
  let forged_part_b : @types.EncApRepPart = {
    ctime: @types.unix_to_kerberos_time(BASE_TIME + 10L),
    cusec: 4322,
    subkey: None,
    seq_number: None,
  }
  let forged_ap_rep_b : @types.ApRep = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_AP_REP,
    enc_part: make_enc_data(
      env_b.etype,
      cred_b.session_key.keyvalue,
      None,
      @crypto.KU_AP_REP_ENCPART,
      forged_part_b.encode(),
      env_b.rng,
    ),
  }
  let mut got_mut_fail_b = false
  try {
    let _ = env_b.client.handle_ap_rep(forged_ap_rep_b.encode())
  } catch {
    @protocol.ProtocolError::MutualAuthFailed(_) => got_mut_fail_b = true
    _ => ()
  }
  assert_true(got_mut_fail_b)
}

///|
test "sec_23: MITM Nonce mismatch in AS-REP and TGS-REP rejected with NonceMismatch" {
  // Case A: AS-REP nonce mismatch
  let env_a = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_23_as_seed",
  )
  let as_req1 = env_a.client.build_as_req(BASE_TIME, env_a.rng)
  let as_resp1 = env_a.kdc.handle_message(BASE_TIME, 100, env_a.rng, as_req1)
  let as_req2 = match
    env_a.client.handle_as_response(BASE_TIME + 1L, 200, env_a.rng, as_resp1) {
    @protocol.AsStepResult::NeedPreauthRetry(der) => der
    @protocol.AsStepResult::GotTgt(_) => fail("expected preauth retry")
  }
  let as_resp2 = env_a.kdc.handle_message(
    BASE_TIME + 1L,
    300,
    env_a.rng,
    as_req2,
  )
  let rep_a = @types.KdcRep::decode_as_rep(as_resp2)
  let plain_a = @crypto.decrypt(
    env_a.etype,
    env_a.alice_key,
    @crypto.KU_AS_REP_ENCPART,
    rep_a.enc_part.cipher,
  )
  let enc_as = @types.EncKdcRepPart::decode_enc_as_rep_part(plain_a)
  let mutated_as : @types.EncKdcRepPart = {
    key: enc_as.key,
    last_req: enc_as.last_req,
    nonce: enc_as.nonce ^ 1U,
    key_expiration: enc_as.key_expiration,
    flags: enc_as.flags,
    authtime: enc_as.authtime,
    starttime: enc_as.starttime,
    endtime: enc_as.endtime,
    renew_till: enc_as.renew_till,
    srealm: enc_as.srealm,
    sname: enc_as.sname,
    caddr: enc_as.caddr,
  }
  let forged_as_rep : @types.KdcRep = {
    pvno: rep_a.pvno,
    msg_type: rep_a.msg_type,
    padata: rep_a.padata,
    crealm: rep_a.crealm,
    cname: rep_a.cname,
    ticket: rep_a.ticket,
    enc_part: make_enc_data(
      env_a.etype,
      env_a.alice_key,
      rep_a.enc_part.kvno,
      @crypto.KU_AS_REP_ENCPART,
      mutated_as.encode_enc_as_rep_part(),
      env_a.rng,
    ),
  }
  let mut got_as_nonce_err = false
  try {
    let _ = env_a.client.handle_as_response(
      BASE_TIME + 1L,
      400,
      env_a.rng,
      forged_as_rep.encode_as_rep(),
    )
  } catch {
    @protocol.ProtocolError::NonceMismatch => got_as_nonce_err = true
    _ => ()
  }
  assert_true(got_as_nonce_err)
  // Case B: TGS-REP nonce mismatch
  let env_b = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_23_tgs_seed",
  )
  let tgt = run_as_exchange(env_b, BASE_TIME)
  let tgs_req = env_b.client.build_tgs_req(
    env_b.http_svc,
    BASE_TIME + 5L,
    100,
    env_b.rng,
  )
  let tgs_resp = env_b.kdc.handle_message(
    BASE_TIME + 5L,
    101,
    env_b.rng,
    tgs_req,
  )
  let rep_b = @types.KdcRep::decode_tgs_rep(tgs_resp)
  let plain_b = @crypto.decrypt(
    env_b.etype,
    tgt.session_key.keyvalue,
    @crypto.KU_TGS_REP_ENCPART_SESSION_KEY,
    rep_b.enc_part.cipher,
  )
  let enc_tgs = @types.EncKdcRepPart::decode_enc_tgs_rep_part(plain_b)
  let mutated_tgs : @types.EncKdcRepPart = {
    key: enc_tgs.key,
    last_req: enc_tgs.last_req,
    nonce: enc_tgs.nonce ^ 1U,
    key_expiration: enc_tgs.key_expiration,
    flags: enc_tgs.flags,
    authtime: enc_tgs.authtime,
    starttime: enc_tgs.starttime,
    endtime: enc_tgs.endtime,
    renew_till: enc_tgs.renew_till,
    srealm: enc_tgs.srealm,
    sname: enc_tgs.sname,
    caddr: enc_tgs.caddr,
  }
  let forged_tgs_rep : @types.KdcRep = {
    pvno: rep_b.pvno,
    msg_type: rep_b.msg_type,
    padata: rep_b.padata,
    crealm: rep_b.crealm,
    cname: rep_b.cname,
    ticket: rep_b.ticket,
    enc_part: make_enc_data(
      env_b.etype,
      tgt.session_key.keyvalue,
      None,
      @crypto.KU_TGS_REP_ENCPART_SESSION_KEY,
      mutated_tgs.encode_enc_tgs_rep_part(),
      env_b.rng,
    ),
  }
  let mut got_tgs_nonce_err = false
  try {
    let _ = env_b.client.handle_tgs_response(forged_tgs_rep.encode_tgs_rep())
  } catch {
    @protocol.ProtocolError::NonceMismatch => got_tgs_nonce_err = true
    _ => ()
  }
  assert_true(got_tgs_nonce_err)
}

///|
test "sec_24: malformed ASN.1 DER attack suite strictly rejected" {
  // 1. Non-canonical length (long form for len=1, and leading 0x00 in length)
  let mut err_noncanon_len1 = false
  try {
    let _ = @asn1.decode_der(b"\x04\x81\x01\xAA")
  } catch {
    @asn1.DerError::NonCanonicalLength => err_noncanon_len1 = true
    _ => ()
  }
  assert_true(err_noncanon_len1)
  let mut err_noncanon_len2 = false
  let padded_len_payload = Bytes::makei(132, fn(i) {
    if i == 0 {
      b'\x04'
    } else if i == 1 {
      b'\x82'
    } else if i == 2 {
      b'\x00'
    } else if i == 3 {
      b'\x80'
    } else {
      b'\x41'
    }
  })
  try {
    let _ = @asn1.decode_der(padded_len_payload)
  } catch {
    @asn1.DerError::NonCanonicalLength => err_noncanon_len2 = true
    _ => ()
  }
  assert_true(err_noncanon_len2)
  // 2. Indefinite length 0x80
  let mut err_indef = false
  try {
    let _ = @asn1.decode_der(b"\x30\x80\x00\x00")
  } catch {
    @asn1.DerError::IndefiniteLength => err_indef = true
    _ => ()
  }
  assert_true(err_indef)
  // 3. Non-canonical two's-complement INTEGER (redundant 0x00 and redundant 0xFF)
  let mut err_int_pos = false
  try {
    let _ = @asn1.decode_der(b"\x02\x02\x00\x01")
  } catch {
    @asn1.DerError::NonCanonicalInteger => err_int_pos = true
    _ => ()
  }
  assert_true(err_int_pos)
  let mut err_int_neg = false
  try {
    let _ = @asn1.decode_der(b"\x02\x02\xFF\x80")
  } catch {
    @asn1.DerError::NonCanonicalInteger => err_int_neg = true
    _ => ()
  }
  assert_true(err_int_neg)
  // 4. Non-canonical BOOLEAN 0x01
  let mut err_bool = false
  try {
    let _ = @asn1.decode_der(b"\x01\x01\x01")
  } catch {
    @asn1.DerError::NonCanonicalBoolean => err_bool = true
    _ => ()
  }
  assert_true(err_bool)
  // 5. 65-level nesting depth bomb -> MaxDepthExceeded
  let mut nested : @asn1.DerValue = @asn1.DerValue::Null
  for _i = 0; _i < 65; _i = _i + 1 {
    nested = @asn1.DerValue::Sequence([nested])
  }
  let bomb_bytes = @asn1.encode_der(nested)
  let mut err_depth = false
  try {
    let _ = @asn1.decode_der(bomb_bytes)
  } catch {
    @asn1.DerError::MaxDepthExceeded => err_depth = true
    _ => ()
  }
  assert_true(err_depth)
  // 6. Trailing bytes
  let mut err_trailing = false
  try {
    let _ = @asn1.decode_der(b"\x02\x01\x05\xDE\xAD")
  } catch {
    @asn1.DerError::TrailingBytes(2) => err_trailing = true
    _ => ()
  }
  assert_true(err_trailing)
  // 7. Wrong [APPLICATION N] tag
  let wrong_app_bytes = @asn1.encode_application(
    @asn1.APP_AS_REQ,
    @asn1.DerValue::Sequence([]),
  )
  let mut err_wrong_app = false
  try {
    let _ = @types.Ticket::decode(wrong_app_bytes)
  } catch {
    @asn1.DerError::TagMismatch(..) => err_wrong_app = true
    _ => ()
  }
  assert_true(err_wrong_app)
  // 8. Out-of-order Context [0..12] fields in KdcReqBody
  let out_of_order_seq = @asn1.DerValue::Sequence([
    @asn1.context_field(2, @asn1.encode_general_string(REALM)),
    @asn1.context_field(0, @asn1.encode_kerberos_flags(0U)),
    @asn1.context_field(5, @asn1.encode_generalized_time("20300101000000Z")),
    @asn1.context_field(7, @asn1.encode_uint32(1U)),
    @asn1.context_field(8, @asn1.DerValue::Sequence([@asn1.encode_int(20)])),
  ])
  let mut err_out_of_order = false
  try {
    let _ = @types.KdcReqBody::from_der(out_of_order_seq)
  } catch {
    @asn1.DerError::MissingField(_) | @asn1.DerError::TagMismatch(..) =>
      err_out_of_order = true
    _ => ()
  }
  assert_true(err_out_of_order)
}

///|
test "sec_25: malformed .keytab binary attack suite strictly rejected" {
  // 1. Empty file
  let mut err_empty = false
  try {
    let _ = @keytab.Keytab::decode(b"")
  } catch {
    @keytab.KeytabError::UnexpectedEof => err_empty = true
    _ => ()
  }
  assert_true(err_empty)
  // 2. Unsupported version 0x0503
  let mut err_ver = false
  try {
    let _ = @keytab.Keytab::decode(b"\x05\x03")
  } catch {
    @keytab.KeytabError::UnsupportedVersion(0x0503) => err_ver = true
    _ => ()
  }
  assert_true(err_ver)
  // 3. Zero-length record
  let mut err_zero = false
  try {
    let _ = @keytab.Keytab::decode(b"\x05\x02\x00\x00\x00\x00")
  } catch {
    @keytab.KeytabError::InvalidEntrySize(0) => err_zero = true
    _ => ()
  }
  assert_true(err_zero)
  // 4. Int32::min (-2147483648 = 0x80000000) negative hole overflow guard
  let mut err_i32_min = false
  try {
    let _ = @keytab.Keytab::decode(b"\x05\x02\x80\x00\x00\x00\x00\x00")
  } catch {
    @keytab.KeytabError::TruncatedEntry => err_i32_min = true
    _ => ()
  }
  assert_true(err_i32_min)
  // 5. Out-of-bounds negative hole (-16 = 0xFFFFFFF0, only 2 bytes follow)
  let mut err_oob_hole = false
  try {
    let _ = @keytab.Keytab::decode(b"\x05\x02\xFF\xFF\xFF\xF0\xAA\xBB")
  } catch {
    @keytab.KeytabError::TruncatedEntry => err_oob_hole = true
    _ => ()
  }
  assert_true(err_oob_hole)
  // 6. Truncated key payload
  let valid_kt = @keytab.Keytab::new()
  valid_kt.add_entry({
    realm: REALM,
    components: ["HTTP", "web.example.com"],
    name_type: @types.NT_SRV_HST,
    timestamp: 1700000000U,
    kvno: 1U,
    etype: 20,
    key: Bytes::make(32, b'\x5A'),
  })
  let valid_bytes = valid_kt.encode()
  let truncated_bytes = slice_bytes(valid_bytes, 0, valid_bytes.length() - 10)
  let mut err_trunc_key = false
  try {
    let _ = @keytab.Keytab::decode(truncated_bytes)
  } catch {
    @keytab.KeytabError::TruncatedEntry => err_trunc_key = true
    _ => ()
  }
  assert_true(err_trunc_key)
  // 7. Invalid UTF-8 in realm string
  // Header 0x0502, entry_size=26 (0x1A), num_components=0, realm_len=2, realm=0xFF 0xFE,
  // name_type=1 (4B), timestamp=0 (4B), vno8=1 (1B), etype=17 (2B), key_len=7 (2B), key=7B
  let bad_utf8_kt = b"\x05\x02\x00\x00\x00\x1A\x00\x00\x00\x02\xFF\xFE\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x11\x00\x07\x01\x02\x03\x04\x05\x06\x07"
  let mut err_utf8 = false
  try {
    let _ = @keytab.Keytab::decode(bad_utf8_kt)
  } catch {
    @keytab.KeytabError::InvalidUtf8 => err_utf8 = true
    _ => ()
  }
  assert_true(err_utf8)
}

///|
test "sec_26: truncated and sub-MAC ciphertexts rejected across all 4 etypes" {
  let rng = @crypto.DeterministicRng::new(b"sec_26_trunc_seed")
  let plaintext = b"Kerberos-5-Truncation-Defense-Test-Message-64-Bytes-Long-1234567"
  for et in all_etypes() {
    let key = rng.next_bytes(et.key_size())
    let conf = rng.next_bytes(et.confounder_size())
    let mac_len = et.mac_size()
    let min_len = 16 + mac_len
    let short_lens = [0, 1, mac_len - 1, mac_len, min_len - 1]
    for slen in short_lens {
      let short_ct = Bytes::make(slen, b'\xCC')
      let mut got_short = false
      try {
        let _ = @crypto.decrypt(et, key, @crypto.KU_TICKET, short_ct)
      } catch {
        @crypto.CryptoError::CiphertextTooShort => got_short = true
        _ => ()
      }
      assert_true(got_short)
    }
    // Truncated valid ciphertexts that remain >= 16 + mac_len must fail MAC check
    let full_ct = @crypto.encrypt(et, key, @crypto.KU_TICKET, plaintext, conf)
    let trunc_cuts = [1, 4, mac_len]
    for cut in trunc_cuts {
      let trunc_ct = slice_bytes(full_ct, 0, full_ct.length() - cut)
      assert_true(trunc_ct.length() >= min_len)
      let mut got_integrity = false
      try {
        let _ = @crypto.decrypt(et, key, @crypto.KU_TICKET, trunc_ct)
      } catch {
        @crypto.CryptoError::IntegrityCheckFailed => got_integrity = true
        _ => ()
      }
      assert_true(got_integrity)
    }
  }
}

///|
test "sec_27: MITM forged PA-ETYPE-INFO2 PBKDF2 1-iter downgrade and DoS rejected by Client" {
  let etype = @crypto.Enctype::Aes256CtsHmacSha384_192
  let rng = @crypto.DeterministicRng::new(b"sec_27_s2k_downgrade")
  let alice = @types.PrincipalName::user("alice")
  let alice_pw = b"alice-strong-pw!"
  // Case A: Default Client (min=4096U, max=500_000U) rejects 1-iteration downgrade
  let client_low = @protocol.Client::new(alice, REALM, alice_pw, preferred_etypes=[
    etype,
  ])
  let _ = client_low.build_as_req(BASE_TIME, rng)
  let info2_1iter = @types.encode_etype_info2([
    {
      etype: etype.to_int(),
      salt: Some(REALM + "alice"),
      s2kparams: Some(b"\x00\x00\x00\x01"),
    },
  ])
  let method_1iter = @types.encode_method_data([
    { padata_type: @types.PA_ETYPE_INFO2, padata_value: info2_1iter, },
  ])
  let mitm_err_low : @types.KrbError = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_KRB_ERROR,
    ctime: None,
    cusec: None,
    stime: @types.unix_to_kerberos_time(BASE_TIME),
    susec: 0,
    error_code: @types.KDC_ERR_PREAUTH_REQUIRED,
    crealm: Some(REALM),
    cname: Some(alice),
    realm: REALM,
    sname: @types.PrincipalName::service("krbtgt", REALM),
    e_text: Some("Preauth required"),
    e_data: Some(method_1iter),
  }
  let mut rejected_low = false
  try {
    let _ = client_low.handle_as_response(
      BASE_TIME + 1L,
      10,
      rng,
      mitm_err_low.encode(),
    )
  } catch {
    @protocol.ProtocolError::PreauthFailed(_) => rejected_low = true
    _ => ()
  }
  assert_true(rejected_low)
  // Case B: Default Client rejects excessive iteration count (1_000_000 = 0x000F4240) DoS
  let client_high = @protocol.Client::new(alice, REALM, alice_pw, preferred_etypes=[
    etype,
  ])
  let _ = client_high.build_as_req(BASE_TIME, rng)
  let info2_dos = @types.encode_etype_info2([
    {
      etype: etype.to_int(),
      salt: Some(REALM + "alice"),
      s2kparams: Some(b"\x00\x0F\x42\x40"),
    },
  ])
  let method_dos = @types.encode_method_data([
    { padata_type: @types.PA_ETYPE_INFO2, padata_value: info2_dos, },
  ])
  let mitm_err_high : @types.KrbError = {
    ..mitm_err_low,
    e_data: Some(method_dos),
  }
  let mut rejected_high = false
  try {
    let _ = client_high.handle_as_response(
      BASE_TIME + 1L,
      11,
      rng,
      mitm_err_high.encode(),
    )
  } catch {
    @protocol.ProtocolError::PreauthFailed(_) => rejected_high = true
    _ => ()
  }
  assert_true(rejected_high)
}

///|
test "sec_28: MITM tampered outer AS-REP.ticket or switched etype rejected by Client" {
  // Case A: Outer AS-REP.ticket.sname tampered by MITM
  let env_a = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_28_a_seed",
  )
  let as_req1 = env_a.client.build_as_req(BASE_TIME, env_a.rng)
  let as_resp1 = env_a.kdc.handle_message(BASE_TIME, 100, env_a.rng, as_req1)
  let as_req2 = match
    env_a.client.handle_as_response(BASE_TIME + 1L, 200, env_a.rng, as_resp1) {
    @protocol.AsStepResult::NeedPreauthRetry(der) => der
    @protocol.AsStepResult::GotTgt(_) => fail("expected preauth retry")
  }
  let as_resp2 = env_a.kdc.handle_message(
    BASE_TIME + 1L,
    300,
    env_a.rng,
    as_req2,
  )
  let rep_a = @types.KdcRep::decode_as_rep(as_resp2)
  let tampered_sname_rep : @types.KdcRep = {
    ..rep_a,
    ticket: {
      ..rep_a.ticket,
      sname: @types.PrincipalName::service("HTTP", "evil.example.com"),
    },
  }
  let mut rejected_sname = false
  try {
    let _ = env_a.client.handle_as_response(
      BASE_TIME + 1L,
      400,
      env_a.rng,
      tampered_sname_rep.encode_as_rep(),
    )
  } catch {
    @protocol.ProtocolError::WrongService(_) => rejected_sname = true
    _ => ()
  }
  assert_true(rejected_sname)
  // Case B: Outer AS-REP.ticket.realm tampered by MITM
  let tampered_realm_rep : @types.KdcRep = {
    ..rep_a,
    ticket: { ..rep_a.ticket, realm: "EVIL.COM", },
  }
  let mut rejected_realm = false
  try {
    let _ = env_a.client.handle_as_response(
      BASE_TIME + 1L,
      401,
      env_a.rng,
      tampered_realm_rep.encode_as_rep(),
    )
  } catch {
    @protocol.ProtocolError::WrongService(_) => rejected_realm = true
    _ => ()
  }
  assert_true(rejected_realm)
  // Case C: MITM switches AS-REP enc_part.etype away from pre-authenticated etype
  let switched_et_rep : @types.KdcRep = {
    ..rep_a,
    enc_part: {
      ..rep_a.enc_part,
      etype: @crypto.Enctype::Aes128CtsHmacSha256_128.to_int(),
    },
  }
  let mut rejected_switch = false
  try {
    let _ = env_a.client.handle_as_response(
      BASE_TIME + 1L,
      402,
      env_a.rng,
      switched_et_rep.encode_as_rep(),
    )
  } catch {
    @protocol.ProtocolError::UnsupportedEnctype(_)
    | @protocol.ProtocolError::PreauthFailed(_) => rejected_switch = true
    _ => ()
  }
  assert_true(rejected_switch)
}

///|
test "sec_29: MITM tampered outer TGS-REP.ticket or wrong EncTgsRepPart sname rejected by Client" {
  // Case A: Outer TGS-REP.ticket.sname tampered by MITM
  let env_a = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_29_a_seed",
  )
  let tgt_a = run_as_exchange(env_a, BASE_TIME)
  let tgs_req_a = env_a.client.build_tgs_req(
    env_a.http_svc,
    BASE_TIME + 5L,
    100,
    env_a.rng,
  )
  let tgs_resp_a = env_a.kdc.handle_message(
    BASE_TIME + 5L,
    101,
    env_a.rng,
    tgs_req_a,
  )
  let rep_a = @types.KdcRep::decode_tgs_rep(tgs_resp_a)
  let tampered_outer : @types.KdcRep = {
    ..rep_a,
    ticket: {
      ..rep_a.ticket,
      sname: @types.PrincipalName::service("HTTP", "spoofed.example.com"),
    },
  }
  let mut rejected_outer = false
  try {
    let _ = env_a.client.handle_tgs_response(tampered_outer.encode_tgs_rep())
  } catch {
    @protocol.ProtocolError::WrongService(_) => rejected_outer = true
    _ => ()
  }
  assert_true(rejected_outer)
  // Case B: EncTgsRepPart.sname does not match requested service
  let plain_a = @crypto.decrypt(
    env_a.etype,
    tgt_a.session_key.keyvalue,
    @crypto.KU_TGS_REP_ENCPART_SESSION_KEY,
    rep_a.enc_part.cipher,
  )
  let enc_tgs = @types.EncKdcRepPart::decode_enc_tgs_rep_part(plain_a)
  let wrong_svc = @types.PrincipalName::service("HTTP", "wrong.example.com")
  let forged_enc : @types.EncKdcRepPart = { ..enc_tgs, sname: wrong_svc, }
  let forged_rep : @types.KdcRep = {
    ..rep_a,
    ticket: { ..rep_a.ticket, sname: wrong_svc, },
    enc_part: make_enc_data(
      env_a.etype,
      tgt_a.session_key.keyvalue,
      None,
      @crypto.KU_TGS_REP_ENCPART_SESSION_KEY,
      forged_enc.encode_enc_tgs_rep_part(),
      env_a.rng,
    ),
  }
  let mut rejected_wrong_svc = false
  try {
    let _ = env_a.client.handle_tgs_response(forged_rep.encode_tgs_rep())
  } catch {
    @protocol.ProtocolError::WrongService(_) => rejected_wrong_svc = true
    _ => ()
  }
  assert_true(rejected_wrong_svc)
}

///|
test "sec_30: MITM tampered TGS-REQ req_body does NOT poison KDC ReplayCache" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_30_seed",
  )
  let other_svc = @types.PrincipalName::service("HTTP", "admin.example.com")
  env.kdc.add_principal_with_password(
    other_svc,
    b"admin-pw!",
    [env.etype],
    kvno=1U,
    s2kparams=fast_s2k(),
  )
  let _ = run_as_exchange(env, BASE_TIME)
  let legit_tgs_req_der = env.client.build_tgs_req(
    env.http_svc,
    BASE_TIME + 5L,
    555,
    env.rng,
  )
  // MITM intercepts legit_tgs_req_der and modifies req_body.sname before KDC sees it
  let decoded = @types.KdcReq::decode_tgs_req(legit_tgs_req_der)
  let tampered_req : @types.KdcReq = {
    ..decoded,
    req_body: { ..decoded.req_body, sname: Some(other_svc), },
  }
  let mitm_resp = env.kdc.handle_message(
    BASE_TIME + 5L,
    556,
    env.rng,
    tampered_req.encode_tgs_req(),
  )
  assert_eq(@asn1.peek_application_tag(mitm_resp), @asn1.APP_KRB_ERROR)
  assert_eq(
    @types.KrbError::decode(mitm_resp).error_code,
    @types.KRB_AP_ERR_MODIFIED,
  )
  // Now the legitimate TGS-REQ (with the exact same Authenticator) arrives and MUST succeed!
  let legit_resp = env.kdc.handle_message(
    BASE_TIME + 5L,
    557,
    env.rng,
    legit_tgs_req_der,
  )
  assert_eq(@asn1.peek_application_tag(legit_resp), @asn1.APP_TGS_REP)
  let svc_cred = env.client.handle_tgs_response(legit_resp)
  assert_eq(svc_cred.server, env.http_svc)
}

///|
test "sec_31: Service rejects AP_OPT_USE_SESSION_KEY and KDC rejects unsupported kdc_options" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_31_seed",
  )
  let _ = run_as_exchange(env, BASE_TIME)
  let svc_cred = run_tgs_exchange(env, env.http_svc, BASE_TIME + 5L, 100)
  // Part A: Service rejects AP_OPT_USE_SESSION_KEY
  let ap_req_der = env.client.build_ap_req(
    svc_cred,
    BASE_TIME + 10L,
    200,
    env.rng,
    mutual_required=false,
  )
  let ap_req = @types.ApReq::decode(ap_req_der)
  let bad_opt_ap_req : @types.ApReq = {
    ..ap_req,
    ap_options: @types.AP_OPT_USE_SESSION_KEY,
  }
  let mut svc_rejected = false
  try {
    let _ = env.service.verify_ap_req(
      BASE_TIME + 10L,
      env.rng,
      bad_opt_ap_req.encode(),
    )
  } catch {
    @protocol.ProtocolError::UnexpectedMessage(_) => svc_rejected = true
    _ => ()
  }
  assert_true(svc_rejected)
  // Part B: KDC rejects unsupported kdc_options with KDC_ERR_BADOPTION (13)
  let unsupported_opts = [
    @types.KDC_OPT_ALLOW_POSTDATE,
    @types.KDC_OPT_RENEW,
    @types.KDC_OPT_VALIDATE,
    @types.KDC_OPT_ENC_TKT_IN_SKEY,
  ]
  for i = 0; i < unsupported_opts.length(); i = i + 1 {
    let opt = unsupported_opts[i]
    let bad_as_body : @types.KdcReqBody = {
      kdc_options: opt,
      cname: Some(env.alice),
      realm: REALM,
      sname: Some(@types.PrincipalName::service("krbtgt", REALM)),
      from: None,
      till: @types.unix_to_kerberos_time(BASE_TIME + 3600L),
      rtime: None,
      nonce: 0x3100U + i.reinterpret_as_uint(),
      etype: [env.etype.to_int()],
      addresses: None,
      enc_authorization_data: None,
      additional_tickets: None,
    }
    let bad_as_req : @types.KdcReq = {
      pvno: @types.KRB5_PVNO,
      msg_type: @types.MSG_AS_REQ,
      padata: None,
      req_body: bad_as_body,
    }
    let resp = env.kdc.handle_message(
      BASE_TIME + 10L,
      300 + i,
      env.rng,
      bad_as_req.encode_as_req(),
    )
    assert_eq(@asn1.peek_application_tag(resp), @asn1.APP_KRB_ERROR)
    assert_eq(
      @types.KrbError::decode(resp).error_code,
      @types.KDC_ERR_BADOPTION,
    )
  }
}

///|
test "sec_32: same-timestamp AS-REQ and TGS-REQ do not collide in KDC replay cache" {
  let env = setup_sec_env(
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    b"sec_32_seed",
  )
  let shared_ts = BASE_TIME + 1L
  let shared_usec = 777
  let as_req1 = env.client.build_as_req(BASE_TIME, env.rng)
  let as_resp1 = env.kdc.handle_message(BASE_TIME, 100, env.rng, as_req1)
  let as_req2 = match
    env.client.handle_as_response(shared_ts, shared_usec, env.rng, as_resp1) {
    @protocol.AsStepResult::NeedPreauthRetry(der) => der
    @protocol.AsStepResult::GotTgt(_) => fail("expected preauth retry")
  }
  let as_resp2 = env.kdc.handle_message(shared_ts, 300, env.rng, as_req2)
  assert_eq(@asn1.peek_application_tag(as_resp2), @asn1.APP_AS_REP)
  let _ = env.client.handle_as_response(shared_ts, 400, env.rng, as_resp2)
  // Issue TGS-REQ with the EXACT SAME (ctime, cusec) as the PA-ENC-TIMESTAMP above!
  let tgs_req = env.client.build_tgs_req(
    env.http_svc,
    shared_ts,
    shared_usec,
    env.rng,
  )
  let tgs_resp = env.kdc.handle_message(shared_ts, 500, env.rng, tgs_req)
  assert_eq(@asn1.peek_application_tag(tgs_resp), @asn1.APP_TGS_REP)
  let svc_cred = env.client.handle_tgs_response(tgs_resp)
  assert_eq(svc_cred.server, env.http_svc)
}
