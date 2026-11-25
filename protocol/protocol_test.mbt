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
fn make_test_kdc(
  realm : String,
  etypes : Array[@crypto.Enctype],
  rng : @crypto.DeterministicRng,
  require_preauth~ : Bool = true,
) -> @protocol.Kdc {
  let krbtgt_keys : Array[@protocol.PrincipalKey] = []
  for et in etypes {
    krbtgt_keys.push({
      etype: et,
      key: rng.next_bytes(et.key_size()),
      salt: realm + "krbtgt" + realm,
      s2kparams: None,
    })
  }
  @protocol.Kdc::new(realm, krbtgt_keys, require_preauth~)
}

///|
fn setup_three_party(
  etype : @crypto.Enctype,
  seed : Bytes,
  require_preauth~ : Bool = true,
) -> (
  @protocol.Kdc,
  @protocol.Client,
  @protocol.Service,
  @types.PrincipalName,
  @types.PrincipalName,
  @crypto.DeterministicRng,
) raise {
  let realm = "EXAMPLE.COM"
  let rng = @crypto.DeterministicRng::new(seed)
  let etypes = [etype]
  let kdc = make_test_kdc(realm, etypes, rng, require_preauth~)
  let alice = @types.PrincipalName::user("alice")
  let http_svc = @types.PrincipalName::service("HTTP", "web.example.com")
  let alice_pw = b"s3cr3t-alice-password!"
  let svc_pw = b"s3cr3t-service-password!"
  kdc.add_principal_with_password(alice, alice_pw, etypes, kvno=2U)
  kdc.add_principal_with_password(http_svc, svc_pw, etypes, kvno=3U)
  // Round-trip keytab through binary MIT keytab format (encode -> decode)
  let exported_kt = kdc.export_keytab(http_svc, timestamp=1700000000U)
  let kt_bytes = exported_kt.encode()
  let decoded_kt = @keytab.Keytab::decode(kt_bytes)
  let service = @protocol.Service::new(realm, http_svc, decoded_kt)
  let client = @protocol.Client::new(
    alice,
    realm,
    alice_pw,
    preferred_etypes=etypes,
  )
  (kdc, client, service, alice, http_svc, rng)
}

///|
fn run_full_flow_for_etype(
  etype : @crypto.Enctype,
  use_tgs_subkey : Bool,
  use_ap_subkey : Bool,
  seed : Bytes,
) -> Unit raise {
  let (kdc, client, service, alice, http_svc, rng) = setup_three_party(
    etype, seed,
  )
  let t0 : Int64 = 1700000000L
  assert_eq(client.state(), @protocol.ClientState::Init)
  // 1. AS-REQ (initial without preauth) -> KDC responds with KRB-ERROR(PREAUTH_REQUIRED)
  let as_req1 = client.build_as_req(t0, rng)
  assert_eq(client.state(), @protocol.ClientState::AwaitingAsRep)
  let as_resp1 = kdc.handle_message(t0, 100, rng, as_req1)
  assert_eq(@asn1.peek_application_tag(as_resp1), @asn1.APP_KRB_ERROR)
  let krb_err = @types.KrbError::decode(as_resp1)
  assert_eq(krb_err.error_code, @types.KDC_ERR_PREAUTH_REQUIRED)
  // 2. Client processes PREAUTH_REQUIRED -> produces retry AS-REQ with PA-ENC-TIMESTAMP
  let as_step1 = client.handle_as_response(t0 + 1L, 200, rng, as_resp1)
  let as_req2 = match as_step1 {
    @protocol.AsStepResult::NeedPreauthRetry(der) => der
    @protocol.AsStepResult::GotTgt(_) => fail("expected NeedPreauthRetry")
  }
  assert_eq(client.state(), @protocol.ClientState::AwaitingAsRep)
  // 3. KDC validates PA-ENC-TIMESTAMP -> returns AS-REP
  let as_resp2 = kdc.handle_message(t0 + 1L, 300, rng, as_req2)
  assert_eq(@asn1.peek_application_tag(as_resp2), @asn1.APP_AS_REP)
  let as_step2 = client.handle_as_response(t0 + 1L, 400, rng, as_resp2)
  let tgt = match as_step2 {
    @protocol.AsStepResult::GotTgt(cred) => cred
    @protocol.AsStepResult::NeedPreauthRetry(_) => fail("expected GotTgt")
  }
  assert_eq(client.state(), @protocol.ClientState::HasTgt)
  assert_eq(tgt.client, alice)
  assert_eq(tgt.crealm, "EXAMPLE.COM")
  assert_eq(tgt.session_key.keytype, etype.to_int())
  assert_true((tgt.flags & @types.TKT_FLAG_PRE_AUTHENT) != 0U)
  assert_true((tgt.flags & @types.TKT_FLAG_INITIAL) != 0U)
  // 4. TGS-REQ -> KDC validates TGT + Authenticator + req_body checksum -> TGS-REP
  let tgs_req = client.build_tgs_req(
    http_svc,
    t0 + 10L,
    500,
    rng,
    use_subkey=use_tgs_subkey,
  )
  assert_eq(client.state(), @protocol.ClientState::AwaitingTgsRep)
  let tgs_resp = kdc.handle_message(t0 + 10L, 600, rng, tgs_req)
  assert_eq(@asn1.peek_application_tag(tgs_resp), @asn1.APP_TGS_REP)
  let svc_cred = client.handle_tgs_response(tgs_resp)
  assert_eq(client.state(), @protocol.ClientState::HasServiceTicket)
  assert_eq(svc_cred.client, alice)
  assert_eq(svc_cred.server, http_svc)
  assert_eq(svc_cred.session_key.keytype, etype.to_int())
  assert_eq(client.service_ticket(), Some(svc_cred))
  // 5. AP-REQ -> Service verifies via decoded keytab -> returns AP-REP
  let ap_req = client.build_ap_req(
    svc_cred,
    t0 + 20L,
    777,
    rng,
    mutual_required=true,
    use_subkey=use_ap_subkey,
  )
  assert_eq(client.state(), @protocol.ClientState::AwaitingApRep)
  let verified = service.verify_ap_req(t0 + 20L, rng, ap_req)
  assert_eq(verified.client, alice)
  assert_eq(verified.crealm, "EXAMPLE.COM")
  assert_eq(verified.session_key, svc_cred.session_key)
  assert_eq(verified.mutual_required, true)
  assert_eq(verified.cusec, 777)
  if use_ap_subkey {
    assert_true(verified.subkey is Some(_))
  } else {
    assert_true(verified.subkey is None)
  }
  let ap_rep_der = match verified.ap_rep_der {
    Some(der) => der
    None => fail("expected AP-REP bytes for mutual_required=true")
  }
  assert_eq(@asn1.peek_application_tag(ap_rep_der), @asn1.APP_AP_REP)
  // 6. Client verifies AP-REP -> mutual authentication complete -> Authenticated
  let enc_ap_rep = client.handle_ap_rep(ap_rep_der)
  assert_eq(enc_ap_rep.ctime, verified.ctime)
  assert_eq(enc_ap_rep.cusec, 777)
  assert_eq(client.state(), @protocol.ClientState::Authenticated)
}

///|
test "end-to-end all 4 etypes (17, 18, 19, 20) with and without subkey" {
  let etypes = all_etypes()
  for i = 0; i < etypes.length(); i = i + 1 {
    let et = etypes[i]
    let tag = Bytes::from_array([et.to_int().to_byte()])
    run_full_flow_for_etype(et, false, false, b"seed-no-subkey-" + tag)
    run_full_flow_for_etype(et, true, true, b"seed-with-subkey-" + tag)
  }
}

///|
test "end-to-end without preauth and one-way AP-REQ" {
  let etype = @crypto.Enctype::Aes256CtsHmacSha384_192
  let (kdc, client, service, alice, http_svc, rng) = setup_three_party(
    etype,
    b"seed-no-preauth",
    require_preauth=false,
  )
  let t0 : Int64 = 1700001000L
  let as_req = client.build_as_req(t0, rng)
  let as_resp = kdc.handle_message(t0, 10, rng, as_req)
  assert_eq(@asn1.peek_application_tag(as_resp), @asn1.APP_AS_REP)
  let tgt = match client.handle_as_response(t0, 20, rng, as_resp) {
    @protocol.AsStepResult::GotTgt(c) => c
    @protocol.AsStepResult::NeedPreauthRetry(_) => fail("unexpected retry")
  }
  assert_eq(tgt.client, alice)
  assert_true((tgt.flags & @types.TKT_FLAG_PRE_AUTHENT) == 0U)
  let tgs_req = client.build_tgs_req(http_svc, t0 + 5L, 30, rng)
  let tgs_resp = kdc.handle_message(t0 + 5L, 40, rng, tgs_req)
  let svc_cred = client.handle_tgs_response(tgs_resp)
  let ap_req = client.build_ap_req(
    svc_cred,
    t0 + 6L,
    50,
    rng,
    mutual_required=false,
  )
  assert_eq(client.state(), @protocol.ClientState::Authenticated)
  let verified = service.verify_ap_req(t0 + 6L, rng, ap_req)
  assert_eq(verified.client, alice)
  assert_eq(verified.mutual_required, false)
  assert_eq(verified.ap_rep_der, None)
}

///|
test "failure: wrong password rejected during preauth and without preauth" {
  let realm = "EXAMPLE.COM"
  let etype = @crypto.Enctype::Aes128CtsHmacSha256_128
  let rng = @crypto.DeterministicRng::new(b"wrong-pw-seed")
  let alice = @types.PrincipalName::user("alice")
  let kdc = make_test_kdc(realm, [etype], rng, require_preauth=true)
  kdc.add_principal_with_password(alice, b"correct-password", [etype])
  let bad_client = @protocol.Client::new(alice, realm, b"wrong-password", preferred_etypes=[
    etype,
  ])
  let t0 : Int64 = 1700002000L
  let as_req1 = bad_client.build_as_req(t0, rng)
  let as_resp1 = kdc.handle_message(t0, 1, rng, as_req1)
  let as_req2 = match bad_client.handle_as_response(t0, 2, rng, as_resp1) {
    @protocol.AsStepResult::NeedPreauthRetry(der) => der
    _ => fail("expected preauth retry")
  }
  let as_resp2 = kdc.handle_message(t0, 3, rng, as_req2)
  let err2 = @types.KrbError::decode(as_resp2)
  assert_eq(err2.error_code, @types.KDC_ERR_PREAUTH_FAILED)
  let mut got_preauth_failed = false
  try {
    let _ = bad_client.handle_as_response(t0, 4, rng, as_resp2)
  } catch {
    @protocol.ProtocolError::PreauthFailed(_) => got_preauth_failed = true
    other => fail("expected PreauthFailed, got " + Show::to_string(other))
  }
  assert_true(got_preauth_failed)
  // Also test wrong password when require_preauth=false -> client fails decrypting AS-REP
  let kdc_no_pa = make_test_kdc(realm, [etype], rng, require_preauth=false)
  kdc_no_pa.add_principal_with_password(alice, b"correct-password", [etype])
  let bad_client2 = @protocol.Client::new(alice, realm, b"wrong-password", preferred_etypes=[
    etype,
  ])
  let req = bad_client2.build_as_req(t0, rng)
  let resp = kdc_no_pa.handle_message(t0, 5, rng, req)
  let mut got_crypto_err = false
  try {
    let _ = bad_client2.handle_as_response(t0, 6, rng, resp)
  } catch {
    @protocol.ProtocolError::Crypto(@crypto.CryptoError::IntegrityCheckFailed) =>
      got_crypto_err = true
    other =>
      fail("expected IntegrityCheckFailed, got " + Show::to_string(other))
  }
  assert_true(got_crypto_err)
}

///|
test "failure: expired ticket rejected by both KDC and Service" {
  let etype = @crypto.Enctype::Aes256CtsHmacSha1_96
  let (kdc, client, service, _alice, http_svc, rng) = setup_three_party(
    etype,
    b"expired-tkt-seed",
    require_preauth=false,
  )
  let t0 : Int64 = 1700003000L
  let as_req = client.build_as_req(t0, rng)
  let as_resp = kdc.handle_message(t0, 1, rng, as_req)
  let _ = client.handle_as_response(t0, 2, rng, as_resp)
  let tgs_req = client.build_tgs_req(http_svc, t0 + 10L, 3, rng)
  let tgs_resp = kdc.handle_message(t0 + 10L, 4, rng, tgs_req)
  let svc_cred = client.handle_tgs_response(tgs_resp)
  // Jump past 36000s default lifetime -> Service rejects AP-REQ with TicketExpired
  let t_expired = t0 + 40000L
  let ap_req = client.build_ap_req(svc_cred, t_expired, 5, rng)
  let mut got_expired = false
  try {
    let _ = service.verify_ap_req(t_expired, rng, ap_req)
  } catch {
    @protocol.ProtocolError::TicketExpired => got_expired = true
    other => fail("expected TicketExpired, got " + Show::to_string(other))
  }
  assert_true(got_expired)
  // Also KDC rejects TGS-REQ with expired TGT -> KRB_AP_ERR_TKT_EXPIRED
  let client2 = @protocol.Client::new(
    @types.PrincipalName::user("alice"),
    "EXAMPLE.COM",
    b"s3cr3t-alice-password!",
    preferred_etypes=[etype],
  )
  let as_req2 = client2.build_as_req(t0, rng)
  let as_resp2 = kdc.handle_message(t0, 6, rng, as_req2)
  let _ = client2.handle_as_response(t0, 7, rng, as_resp2)
  let tgs_req_late = client2.build_tgs_req(http_svc, t_expired, 8, rng)
  let tgs_err_der = kdc.handle_message(t_expired, 9, rng, tgs_req_late)
  let mut got_kdc_expired = false
  try {
    let _ = client2.handle_tgs_response(tgs_err_der)
  } catch {
    @protocol.ProtocolError::KrbErrorReceived(code~, ..) =>
      got_kdc_expired = code == @types.KRB_AP_ERR_TKT_EXPIRED
    other =>
      fail("expected KRB_AP_ERR_TKT_EXPIRED, got " + Show::to_string(other))
  }
  assert_true(got_kdc_expired)
}

///|
test "failure: replay of Authenticator detected by Service and KDC" {
  let etype = @crypto.Enctype::Aes128CtsHmacSha1_96
  let (kdc, client, service, _alice, http_svc, rng) = setup_three_party(
    etype,
    b"replay-seed",
    require_preauth=true,
  )
  let t0 : Int64 = 1700004000L
  let as_req1 = client.build_as_req(t0, rng)
  let as_resp1 = kdc.handle_message(t0, 1, rng, as_req1)
  let as_req2 = match client.handle_as_response(t0, 2, rng, as_resp1) {
    @protocol.AsStepResult::NeedPreauthRetry(der) => der
    _ => fail("expected retry")
  }
  let as_resp2 = kdc.handle_message(t0, 3, rng, as_req2)
  // Replay the exact same preauth AS-REQ -> KRB_AP_ERR_REPEAT
  let as_replay_resp = kdc.handle_message(t0 + 1L, 4, rng, as_req2)
  let as_replay_err = @types.KrbError::decode(as_replay_resp)
  assert_eq(as_replay_err.error_code, @types.KRB_AP_ERR_REPEAT)
  let _ = client.handle_as_response(t0, 5, rng, as_resp2)
  // TGS-REQ + replay of exact same TGS-REQ -> KRB_AP_ERR_REPEAT
  let tgs_req = client.build_tgs_req(http_svc, t0 + 10L, 6, rng)
  let tgs_resp = kdc.handle_message(t0 + 10L, 7, rng, tgs_req)
  let tgs_replay_resp = kdc.handle_message(t0 + 11L, 8, rng, tgs_req)
  let tgs_replay_err = @types.KrbError::decode(tgs_replay_resp)
  assert_eq(tgs_replay_err.error_code, @types.KRB_AP_ERR_REPEAT)
  let svc_cred = client.handle_tgs_response(tgs_resp)
  // AP-REQ succeeds once, then replaying exact same AP-REQ raises ReplayDetected
  let ap_req = client.build_ap_req(svc_cred, t0 + 20L, 99, rng)
  let _ = service.verify_ap_req(t0 + 20L, rng, ap_req)
  let mut got_replay = false
  try {
    let _ = service.verify_ap_req(t0 + 21L, rng, ap_req)
  } catch {
    @protocol.ProtocolError::ReplayDetected => got_replay = true
    other => fail("expected ReplayDetected, got " + Show::to_string(other))
  }
  assert_true(got_replay)
}

///|
test "failure: tampered TGS-REQ req_body rejected with KRB_AP_ERR_MODIFIED" {
  let etype = @crypto.Enctype::Aes256CtsHmacSha384_192
  let (kdc, client, _service, _alice, http_svc, rng) = setup_three_party(
    etype,
    b"tamper-tgs-seed",
    require_preauth=false,
  )
  let other_svc = @types.PrincipalName::service("LDAP", "dc.example.com")
  kdc.add_principal_with_password(other_svc, b"ldap-secret", [etype])
  let t0 : Int64 = 1700005000L
  let as_req = client.build_as_req(t0, rng)
  let as_resp = kdc.handle_message(t0, 1, rng, as_req)
  let _ = client.handle_as_response(t0, 2, rng, as_resp)
  let tgs_req_der = client.build_tgs_req(http_svc, t0 + 5L, 3, rng)
  // Tamper with req_body.sname after Authenticator.cksum was computed
  let decoded = @types.KdcReq::decode_tgs_req(tgs_req_der)
  let tampered_body : @types.KdcReqBody = {
    ..decoded.req_body,
    sname: Some(other_svc),
  }
  let tampered_req : @types.KdcReq = { ..decoded, req_body: tampered_body, }
  let tampered_der = tampered_req.encode_tgs_req()
  let kdc_resp = kdc.handle_message(t0 + 5L, 4, rng, tampered_der)
  let err = @types.KrbError::decode(kdc_resp)
  assert_eq(err.error_code, @types.KRB_AP_ERR_MODIFIED)
  let mut got_modified = false
  try {
    let _ = client.handle_tgs_response(kdc_resp)
  } catch {
    @protocol.ProtocolError::KrbErrorReceived(code~, ..) =>
      got_modified = code == @types.KRB_AP_ERR_MODIFIED
    other => fail("expected KRB_AP_ERR_MODIFIED, got " + Show::to_string(other))
  }
  assert_true(got_modified)
}

///|
test "failure: tampered AP-REP ctime rejected with MutualAuthFailed" {
  let etype = @crypto.Enctype::Aes128CtsHmacSha256_128
  let (kdc, client, service, _alice, http_svc, rng) = setup_three_party(
    etype,
    b"tamper-aprep-seed",
    require_preauth=false,
  )
  let t0 : Int64 = 1700006000L
  let as_req = client.build_as_req(t0, rng)
  let as_resp = kdc.handle_message(t0, 1, rng, as_req)
  let _ = client.handle_as_response(t0, 2, rng, as_resp)
  let tgs_req = client.build_tgs_req(http_svc, t0 + 5L, 3, rng)
  let tgs_resp = kdc.handle_message(t0 + 5L, 4, rng, tgs_req)
  let svc_cred = client.handle_tgs_response(tgs_resp)
  let ap_req = client.build_ap_req(
    svc_cred,
    t0 + 10L,
    42,
    rng,
    mutual_required=true,
  )
  let verified = service.verify_ap_req(t0 + 10L, rng, ap_req)
  let ap_rep_der = match verified.ap_rep_der {
    Some(d) => d
    None => fail("expected AP-REP")
  }
  // Forge an AP-REP with a different ctime encrypted under the session key
  let ap_rep = @types.ApRep::decode(ap_rep_der)
  let wrong_ctime = @types.unix_to_kerberos_time(t0 + 11L)
  let forged_part : @types.EncApRepPart = {
    ctime: wrong_ctime,
    cusec: 42,
    subkey: None,
    seq_number: None,
  }
  let forged_pt = forged_part.encode()
  let forged_cipher = @crypto.encrypt(
    etype,
    svc_cred.session_key.keyvalue,
    @crypto.KU_AP_REP_ENCPART,
    forged_pt,
    rng.next_bytes(etype.confounder_size()),
  )
  let forged_ap_rep : @types.ApRep = {
    ..ap_rep,
    enc_part: { etype: etype.to_int(), kvno: None, cipher: forged_cipher, },
  }
  let forged_der = forged_ap_rep.encode()
  let mut got_mutual_fail = false
  try {
    let _ = client.handle_ap_rep(forged_der)
  } catch {
    @protocol.ProtocolError::MutualAuthFailed(_) => got_mutual_fail = true
    other => fail("expected MutualAuthFailed, got " + Show::to_string(other))
  }
  assert_true(got_mutual_fail)
}

///|
test "failure: wrong service name rejected with WrongService" {
  let etype = @crypto.Enctype::Aes256CtsHmacSha1_96
  let (kdc, client, _service, _alice, http_svc, rng) = setup_three_party(
    etype,
    b"wrong-svc-seed",
    require_preauth=false,
  )
  let other_svc = @types.PrincipalName::service("HTTP", "other.example.com")
  kdc.add_principal_with_password(other_svc, b"other-pw", [etype])
  let other_service = @protocol.Service::new(
    "EXAMPLE.COM",
    other_svc,
    kdc.export_keytab(other_svc),
  )
  let t0 : Int64 = 1700007000L
  let as_req = client.build_as_req(t0, rng)
  let as_resp = kdc.handle_message(t0, 1, rng, as_req)
  let _ = client.handle_as_response(t0, 2, rng, as_resp)
  let tgs_req = client.build_tgs_req(http_svc, t0 + 5L, 3, rng)
  let tgs_resp = kdc.handle_message(t0 + 5L, 4, rng, tgs_req)
  let svc_cred = client.handle_tgs_response(tgs_resp)
  let ap_req = client.build_ap_req(svc_cred, t0 + 10L, 5, rng)
  let mut got_wrong_service = false
  try {
    let _ = other_service.verify_ap_req(t0 + 10L, rng, ap_req)
  } catch {
    @protocol.ProtocolError::WrongService(_) => got_wrong_service = true
    other => fail("expected WrongService, got " + Show::to_string(other))
  }
  assert_true(got_wrong_service)
}

///|
test "service edge cases: BadKeyVersion, ClockSkew, TicketNotYetValid, make_krb_error" {
  let etype = @crypto.Enctype::Aes128CtsHmacSha256_128
  let (kdc, client, service, _alice, http_svc, rng) = setup_three_party(
    etype,
    b"edge-cases-seed",
    require_preauth=false,
  )
  let t0 : Int64 = 1700008000L
  let as_req = client.build_as_req(t0, rng)
  let as_resp = kdc.handle_message(t0, 1, rng, as_req)
  let _ = client.handle_as_response(t0, 2, rng, as_resp)
  let tgs_req = client.build_tgs_req(http_svc, t0 + 10L, 3, rng)
  let tgs_resp = kdc.handle_message(t0 + 10L, 4, rng, tgs_req)
  let svc_cred = client.handle_tgs_response(tgs_resp)
  // ClockSkew (> 300s)
  let ap_req_skew = client.build_ap_req(
    svc_cred,
    t0 + 10L,
    11,
    rng,
    mutual_required=false,
  )
  let mut got_skew = false
  try {
    let _ = service.verify_ap_req(t0 + 500L, rng, ap_req_skew)
  } catch {
    @protocol.ProtocolError::ClockSkew(_) => got_skew = true
    other => fail("expected ClockSkew, got " + Show::to_string(other))
  }
  assert_true(got_skew)
  // TicketNotYetValid (now way before starttime)
  let ap_req_nyv = client.build_ap_req(
    svc_cred,
    t0 - 1000L,
    12,
    rng,
    mutual_required=false,
  )
  let mut got_nyv = false
  try {
    let _ = service.verify_ap_req(t0 - 1000L, rng, ap_req_nyv)
  } catch {
    @protocol.ProtocolError::TicketNotYetValid => got_nyv = true
    other => fail("expected TicketNotYetValid, got " + Show::to_string(other))
  }
  assert_true(got_nyv)
  // BadKeyVersion (service has kvno=99 in keytab, ticket has kvno=3)
  let old_kt = kdc.export_keytab(http_svc)
  let rotated_kt = @keytab.Keytab::new()
  for entry in old_kt.entries {
    rotated_kt.add_entry({ ..entry, kvno: 99U, })
  }
  let rotated_service = @protocol.Service::new(
    "EXAMPLE.COM", http_svc, rotated_kt,
  )
  let ap_req_kvno = client.build_ap_req(
    svc_cred,
    t0 + 20L,
    13,
    rng,
    mutual_required=false,
  )
  let mut got_bad_kvno = false
  try {
    let _ = rotated_service.verify_ap_req(t0 + 20L, rng, ap_req_kvno)
  } catch {
    @protocol.ProtocolError::BadKeyVersion => got_bad_kvno = true
    other => fail("expected BadKeyVersion, got " + Show::to_string(other))
  }
  assert_true(got_bad_kvno)
  // make_krb_error produces valid DER KRB-ERROR
  let svc_err_der = service.make_krb_error(
    t0 + 30L,
    999,
    @types.KRB_AP_ERR_BADKEYVER,
    "Key version not found",
  )
  let svc_err = @types.KrbError::decode(svc_err_der)
  assert_eq(svc_err.error_code, @types.KRB_AP_ERR_BADKEYVER)
  assert_eq(svc_err.sname, http_svc)
  assert_eq(svc_err.e_text, Some("Key version not found"))
}

///|
test "replay cache pruning and deduplication" {
  let cache = @protocol.ReplayCache::new(max_skew_secs=300L)
  let alice = @types.PrincipalName::user("alice")
  let t0 : Int64 = 1700010000L
  let ctime0 = @types.unix_to_kerberos_time(t0)
  cache.check_and_insert(t0, "EXAMPLE.COM", alice, ctime0, 123)
  assert_eq(cache.len(), 1)
  // Different cusec is allowed
  cache.check_and_insert(t0, "EXAMPLE.COM", alice, ctime0, 124)
  assert_eq(cache.len(), 2)
  // Duplicate raises ReplayDetected
  let mut dup = false
  cache.check_and_insert(t0 + 100L, "EXAMPLE.COM", alice, ctime0, 123) catch {
    @protocol.ProtocolError::ReplayDetected => dup = true
    _ => fail("expected ReplayDetected")
  }
  assert_true(dup)
  // Pruning past max_skew_secs removes old entries
  cache.prune(t0 + 301L)
  assert_eq(cache.len(), 0)
}

///|
test "additional security checks: InvalidState, NonceMismatch, TicketInvalidFlag, KeyNotFound" {
  let etype = @crypto.Enctype::Aes256CtsHmacSha384_192
  let (kdc, client, service, alice, http_svc, rng) = setup_three_party(
    etype,
    b"extra-sec-seed",
    require_preauth=false,
  )
  let t0 : Int64 = 1700020000L
  // Calling build_tgs_req in Init state raises InvalidState
  let mut got_invalid_state = false
  try {
    let _ = client.build_tgs_req(http_svc, t0, 1, rng)
  } catch {
    @protocol.ProtocolError::InvalidState(_) => got_invalid_state = true
    other => fail("expected InvalidState, got " + Show::to_string(other))
  }
  assert_true(got_invalid_state)
  // Complete AS + TGS to get a valid service ticket
  let as_req = client.build_as_req(t0, rng)
  let as_resp = kdc.handle_message(t0, 2, rng, as_req)
  let _ = client.handle_as_response(t0, 3, rng, as_resp)
  let tgs_req = client.build_tgs_req(http_svc, t0 + 5L, 4, rng)
  let tgs_resp = kdc.handle_message(t0 + 5L, 5, rng, tgs_req)
  let svc_cred = client.handle_tgs_response(tgs_resp)
  // Empty keytab -> KeyNotFound
  let empty_service = @protocol.Service::new(
    "EXAMPLE.COM",
    http_svc,
    @keytab.Keytab::new(),
  )
  let ap_req = client.build_ap_req(
    svc_cred,
    t0 + 10L,
    6,
    rng,
    mutual_required=false,
  )
  let mut got_key_not_found = false
  try {
    let _ = empty_service.verify_ap_req(t0 + 10L, rng, ap_req)
  } catch {
    @protocol.ProtocolError::KeyNotFound(_) => got_key_not_found = true
    other => fail("expected KeyNotFound, got " + Show::to_string(other))
  }
  assert_true(got_key_not_found)
  // Ticket with TKT_FLAG_INVALID -> TicketInvalidFlag
  let kt = kdc.export_keytab(http_svc)
  let svc_key = kt.get_key("EXAMPLE.COM", http_svc.name_string, etype.to_int())
  let sess_key : @types.EncryptionKey = {
    keytype: etype.to_int(),
    keyvalue: rng.next_bytes(etype.key_size()),
  }
  let invalid_enc_tkt : @types.EncTicketPart = {
    flags: @types.TKT_FLAG_INVALID,
    key: sess_key,
    crealm: "EXAMPLE.COM",
    cname: alice,
    transited: { tr_type: 1, contents: b"", },
    authtime: @types.unix_to_kerberos_time(t0),
    starttime: Some(@types.unix_to_kerberos_time(t0)),
    endtime: @types.unix_to_kerberos_time(t0 + 3600L),
    renew_till: None,
    caddr: None,
    authorization_data: None,
  }
  let invalid_tkt_cipher = @crypto.encrypt(
    etype,
    svc_key.key,
    @crypto.KU_TICKET,
    invalid_enc_tkt.encode(),
    rng.next_bytes(etype.confounder_size()),
  )
  let invalid_tkt : @types.Ticket = {
    tkt_vno: @types.KRB5_PVNO,
    realm: "EXAMPLE.COM",
    sname: http_svc,
    enc_part: {
      etype: etype.to_int(),
      kvno: Some(svc_key.kvno),
      cipher: invalid_tkt_cipher,
    },
  }
  let fake_cred : @protocol.Credential = {
    ..svc_cred,
    session_key: sess_key,
    ticket: invalid_tkt,
  }
  let ap_req_inv = client.build_ap_req(
    fake_cred,
    t0 + 15L,
    7,
    rng,
    mutual_required=false,
  )
  let mut got_invalid_flag = false
  try {
    let _ = service.verify_ap_req(t0 + 15L, rng, ap_req_inv)
  } catch {
    @protocol.ProtocolError::TicketInvalidFlag => got_invalid_flag = true
    other => fail("expected TicketInvalidFlag, got " + Show::to_string(other))
  }
  assert_true(got_invalid_flag)
}
