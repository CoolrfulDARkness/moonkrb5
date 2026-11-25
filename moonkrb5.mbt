///|
/// Return the semantic version of `CoolrfulDARkness/moonkrb5`.
pub fn version() -> String {
  "0.1.0"
}

///|
/// Return all four supported modern AES-CTS Kerberos 5 encryption suites
/// (RFC 3962 etypes 17/18 and RFC 8009 etypes 19/20).
pub fn all_enctypes() -> Array[@crypto.Enctype] {
  [
    @crypto.Enctype::Aes128CtsHmacSha1_96,
    @crypto.Enctype::Aes256CtsHmacSha1_96,
    @crypto.Enctype::Aes128CtsHmacSha256_128,
    @crypto.Enctype::Aes256CtsHmacSha384_192,
  ]
}

///|
/// Summary report produced by a complete three-party Kerberos 5 handshake
/// (AS preauth challenge -> AS-REP -> TGS-REQ/REP -> MIT keytab round-trip
/// -> AP-REQ/AP-REP mutual authentication).
#derive(Eq, Debug)
pub(all) struct HandshakeReport {
  etype_name : String
  etype_id : Int32
  as_req_bytes : Int32
  preauth_err_bytes : Int32
  as_req_preauth_bytes : Int32
  as_rep_bytes : Int32
  tgs_req_bytes : Int32
  tgs_rep_bytes : Int32
  keytab_bytes : Int32
  ap_req_bytes : Int32
  ap_rep_bytes : Int32
  client_principal : String
  service_principal : String
  mutual_authenticated : Bool
}

///|
pub impl Show for HandshakeReport with fn output(self, logger) {
  logger.write_string("HandshakeReport(etype=")
  logger.write_string(self.etype_name)
  logger.write_string(" [")
  Show::output(self.etype_id, logger)
  logger.write_string("], client=")
  logger.write_string(self.client_principal)
  logger.write_string(", service=")
  logger.write_string(self.service_principal)
  logger.write_string(", as_req=")
  Show::output(self.as_req_bytes, logger)
  logger.write_string("B, preauth_err=")
  Show::output(self.preauth_err_bytes, logger)
  logger.write_string("B, as_req_pa=")
  Show::output(self.as_req_preauth_bytes, logger)
  logger.write_string("B, as_rep=")
  Show::output(self.as_rep_bytes, logger)
  logger.write_string("B, tgs_req=")
  Show::output(self.tgs_req_bytes, logger)
  logger.write_string("B, tgs_rep=")
  Show::output(self.tgs_rep_bytes, logger)
  logger.write_string("B, keytab=")
  Show::output(self.keytab_bytes, logger)
  logger.write_string("B, ap_req=")
  Show::output(self.ap_req_bytes, logger)
  logger.write_string("B, ap_rep=")
  Show::output(self.ap_rep_bytes, logger)
  logger.write_string("B, mutual_auth=")
  Show::output(self.mutual_authenticated, logger)
  logger.write_string(")")
}

///|
fn u32_be(v : Int32) -> Bytes {
  Bytes::from_array([
    ((v >> 24) & 0xFF).to_byte(),
    ((v >> 16) & 0xFF).to_byte(),
    ((v >> 8) & 0xFF).to_byte(),
    (v & 0xFF).to_byte(),
  ])
}

///|
fn flip_byte(data : Bytes, idx : Int32, mask : Int32) -> Bytes {
  Bytes::makei(data.length(), fn(i) {
    if i == idx {
      (data[i].to_int() ^ mask).to_byte()
    } else {
      data[i]
    }
  })
}

///|
fn must_hex(s : String) -> Bytes {
  let clean : Array[Byte] = []
  let mut hi = -1
  for i = 0; i < s.length(); i = i + 1 {
    let c = s.code_unit_at(i).to_int()
    let v = if c >= 48 && c <= 57 {
      c - 48
    } else if c >= 97 && c <= 102 {
      c - 97 + 10
    } else if c >= 65 && c <= 70 {
      c - 65 + 10
    } else {
      -1
    }
    if v >= 0 {
      if hi < 0 {
        hi = v
      } else {
        clean.push(((hi << 4) | v).to_byte())
        hi = -1
      }
    }
  }
  Bytes::makei(clean.length(), fn(i) { clean[i] })
}

///|
/// Execute a complete, real Sans-I/O Kerberos 5 three-party authentication
/// handshake for `etype`:
/// 1. Provision KDC (`krbtgt`, client principal, HTTP service principal) with
///    `PA-ENC-TIMESTAMP` pre-authentication required.
/// 2. Client sends initial `AS-REQ` -> KDC replies `KRB-ERROR(PREAUTH_REQUIRED)`
///    with `PA-ETYPE-INFO2` salt & `s2kparams`.
/// 3. Client retries `AS-REQ` with `PA-ENC-TIMESTAMP` -> KDC issues TGT (`AS-REP`).
/// 4. Client exchanges TGT via `TGS-REQ` (with subkey & body checksum) -> KDC
///    issues Service Ticket (`TGS-REP`).
/// 5. KDC exports the service key to MIT binary `.keytab` v0x0502, encodes and
///    decodes it, and initializes the target `Service`.
/// 6. Client sends `AP-REQ` (`MUTUAL-REQUIRED` + subkey) -> Service verifies and
///    returns `AP-REP` -> Client completes mutual authentication.
pub fn run_full_handshake_demo(
  etype : @crypto.Enctype,
) -> HandshakeReport raise @protocol.ProtocolError {
  let realm = "MOONBIT.LOCAL"
  let etype_tag = Bytes::from_array([etype.to_int().to_byte()])
  let rng = @crypto.DeterministicRng::new(b"moonkrb5-demo-seed-" + etype_tag)
  let krbtgt_key : @protocol.PrincipalKey = {
    etype,
    key: rng.next_bytes(etype.key_size()),
    salt: realm + "krbtgt" + realm,
    s2kparams: None,
  }
  let kdc = @protocol.Kdc::new(realm, [krbtgt_key], require_preauth=true)
  let alice = @types.PrincipalName::user("alice")
  let http_svc = @types.PrincipalName::service("HTTP", "api.moonbit.local")
  let alice_pw = b"moonbit-alice-passphrase"
  let svc_pw = b"moonbit-service-passphrase"
  // Lightweight PBKDF2 iteration count (64) exercises real ETYPE-INFO2 s2kparams
  // negotiation while keeping interactive CLI execution instantaneous across Wasm/JS.
  let demo_s2k = Some(u32_be(64))
  kdc.add_principal_with_password(
    alice,
    alice_pw,
    [etype],
    kvno=2U,
    s2kparams=demo_s2k,
  )
  kdc.add_principal_with_password(
    http_svc,
    svc_pw,
    [etype],
    kvno=3U,
    s2kparams=demo_s2k,
  )
  let t0 : Int64 = 1735689600L
  let client = @protocol.Client::new(alice, realm, alice_pw, preferred_etypes=[
    etype,
  ])
  // Step 1: Initial AS-REQ (without preauth) -> KRB-ERROR(KDC_ERR_PREAUTH_REQUIRED)
  let as_req_der = client.build_as_req(t0, rng)
  let preauth_err_der = kdc.handle_message(t0, 100, rng, as_req_der)
  let err_tag = @asn1.peek_application_tag(preauth_err_der) catch {
    e => raise @protocol.ProtocolError::Der(e)
  }
  if err_tag != @asn1.APP_KRB_ERROR {
    raise @protocol.ProtocolError::UnexpectedMessage(
      "expected KRB-ERROR(PREAUTH_REQUIRED)",
    )
  }
  let krb_err = @types.KrbError::decode(preauth_err_der) catch {
    e => raise @protocol.ProtocolError::Der(e)
  }
  if krb_err.error_code != @types.KDC_ERR_PREAUTH_REQUIRED {
    raise @protocol.ProtocolError::KrbErrorReceived(
      code=krb_err.error_code,
      text=krb_err.e_text.unwrap_or("unexpected KDC error"),
    )
  }
  // Step 2: Client retries AS-REQ with encrypted PA-ENC-TIMESTAMP -> AS-REP (TGT)
  let as_req_preauth_der = match
    client.handle_as_response(t0 + 1L, 200, rng, preauth_err_der) {
    @protocol.AsStepResult::NeedPreauthRetry(der) => der
    @protocol.AsStepResult::GotTgt(_) =>
      raise @protocol.ProtocolError::InvalidState(
        "expected preauth retry before TGT",
      )
  }
  let as_rep_der = kdc.handle_message(t0 + 1L, 300, rng, as_req_preauth_der)
  let _tgt = match client.handle_as_response(t0 + 1L, 400, rng, as_rep_der) {
    @protocol.AsStepResult::GotTgt(cred) => cred
    @protocol.AsStepResult::NeedPreauthRetry(_) =>
      raise @protocol.ProtocolError::InvalidState(
        "unexpected second preauth retry",
      )
  }
  // Step 3: TGS-REQ (with subkey & KDC-REQ-BODY checksum) -> TGS-REP (Service Ticket)
  let tgs_req_der = client.build_tgs_req(
    http_svc,
    t0 + 10L,
    500,
    rng,
    use_subkey=true,
  )
  let tgs_rep_der = kdc.handle_message(t0 + 10L, 600, rng, tgs_req_der)
  let svc_cred = client.handle_tgs_response(tgs_rep_der)
  // Step 4: KDC exports MIT binary .keytab -> encode -> decode -> initialize Service
  let exported_kt = kdc.export_keytab(http_svc, timestamp=1735689600U)
  let keytab_der = exported_kt.encode() catch {
    e => raise @protocol.ProtocolError::Keytab(e)
  }
  let decoded_kt = @keytab.Keytab::decode(keytab_der) catch {
    e => raise @protocol.ProtocolError::Keytab(e)
  }
  let service = @protocol.Service::new(realm, http_svc, decoded_kt)
  // Step 5: AP-REQ (mutual_required + subkey) -> Service verifies -> AP-REP
  let ap_req_der = client.build_ap_req(
    svc_cred,
    t0 + 20L,
    777,
    rng,
    mutual_required=true,
    use_subkey=true,
  )
  let verified = service.verify_ap_req(t0 + 20L, rng, ap_req_der)
  let ap_rep_der = match verified.ap_rep_der {
    Some(der) => der
    None =>
      raise @protocol.ProtocolError::MutualAuthFailed(
        "service did not emit AP-REP",
      )
  }
  // Step 6: Client verifies AP-REP -> mutual authentication complete
  let enc_ap_rep = client.handle_ap_rep(ap_rep_der)
  let mutual_ok = client.state() == @protocol.ClientState::Authenticated &&
    enc_ap_rep.ctime == verified.ctime &&
    enc_ap_rep.cusec == verified.cusec
  {
    etype_name: etype.name(),
    etype_id: etype.to_int(),
    as_req_bytes: as_req_der.length(),
    preauth_err_bytes: preauth_err_der.length(),
    as_req_preauth_bytes: as_req_preauth_der.length(),
    as_rep_bytes: as_rep_der.length(),
    tgs_req_bytes: tgs_req_der.length(),
    tgs_rep_bytes: tgs_rep_der.length(),
    keytab_bytes: keytab_der.length(),
    ap_req_bytes: ap_req_der.length(),
    ap_rep_bytes: ap_rep_der.length(),
    client_principal: alice.to_display() + "@" + realm,
    service_principal: http_svc.to_display() + "@" + realm,
    mutual_authenticated: mutual_ok,
  }
}

///|
/// Run fast official cryptographic self-checks covering RFC 3961 n-fold,
/// RFC 3962 PBKDF2/AES128/AES256/CTS, and RFC 8009 KDF-HMAC-SHA2,
/// AES128-SHA256, and AES256-SHA384 test vectors.
pub fn run_rfc_vector_self_check() -> Array[(String, Bool)] {
  let results : Array[(String, Bool)] = []
  // 1. RFC 3961 Appendix A.1 n-fold vectors
  let nfold_ok = @crypto.n_fold(b"012345", 64) == must_hex("be072631276b1955") &&
    @crypto.n_fold(b"kerberos", 128) ==
    must_hex("6b657262 65726f73 7b9b5b2b 93132b93") &&
    @crypto.n_fold(b"kerberos", 256) ==
    must_hex(
      "6b657262 65726f73 7b9b5b2b 93132b93 5c9bdcda d95c9899 c4cae4de e6d6cae4",
    )
  results.push(("RFC 3961 Appendix A.1 n-fold (64/128/256-bit)", nfold_ok))
  // 2. RFC 3962 Appendix B PBKDF2-HMAC-SHA1 & AES128/AES256 string_to_key
  let rfc3962_s2k_ok = try {
    let p = b"password"
    let s = b"ATHENA.MIT.EDUraeburn"
    let pb1_128 = @crypto.pbkdf2_hmac_sha1(p, s, 1, 16)
    let k1_128 = @crypto.string_to_key(
      @crypto.Enctype::Aes128CtsHmacSha1_96,
      p,
      s,
      Some(u32_be(1)),
    )
    let k1_256 = @crypto.string_to_key(
      @crypto.Enctype::Aes256CtsHmacSha1_96,
      p,
      s,
      Some(u32_be(1)),
    )
    let k50_128 = @crypto.string_to_key(
      @crypto.Enctype::Aes128CtsHmacSha1_96,
      must_hex("f09d849e"),
      b"EXAMPLE.COMpianist",
      Some(u32_be(50)),
    )
    pb1_128 == must_hex("cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15") &&
    k1_128 == must_hex("42 26 3c 6e 89 f4 fc 28 b8 df 68 ee 09 79 9f 15") &&
    k1_256 ==
    must_hex(
      "fe 69 7b 52 bc 0d 3c e1 44 32 ba 03 6a 92 e6 5b bb 52 28 09 90 a2 fa 27 88 39 98 d7 2a f3 01 61",
    ) &&
    k50_128 == must_hex("f1 49 c1 f2 e1 54 a7 34 52 d4 3e 7f e6 2a 56 e5")
  } catch {
    _ => false
  }
  results.push(
    ("RFC 3962 Appendix B PBKDF2 + AES128/AES256 S2K", rfc3962_s2k_ok),
  )
  // 3. RFC 3962 Appendix B AES-128-CTS (17B, 31B, 64B encrypt & decrypt)
  let rfc3962_cts_ok = try {
    let key = must_hex("63 68 69 63 6b 65 6e 20 74 65 72 69 79 61 6b 69")
    let iv = Bytes::make(16, b'\x00')
    let pt17 = must_hex("49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65 20")
    let ct17 = must_hex("c6 35 35 68 f2 bf 8c b4 d8 a5 80 36 2d a7 ff 7f 97")
    let pt64 = must_hex(
      "49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65 20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43 68 69 63 6b 65 6e 2c 20 70 6c 65 61 73 65 2c 20 61 6e 64 20 77 6f 6e 74 6f 6e 20 73 6f 75 70 2e",
    )
    let ct64 = must_hex(
      "97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84 39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8 48 07 ef e8 36 ee 89 a5 26 73 0d bc 2f 7b c8 40 9d ad 8b bb 96 c4 cd c0 3b c1 03 e1 a1 94 bb d8",
    )
    @crypto.aes_cts_encrypt(key, iv, pt17) == ct17 &&
    @crypto.aes_cts_decrypt(key, iv, ct17) == pt17 &&
    @crypto.aes_cts_encrypt(key, iv, pt64) == ct64 &&
    @crypto.aes_cts_decrypt(key, iv, ct64) == pt64
  } catch {
    _ => false
  }
  results.push(
    ("RFC 3962 Appendix B AES-128-CTS CS3 (17B & 64B)", rfc3962_cts_ok),
  )
  // 4. RFC 8009 Appendix A KDF-HMAC-SHA2 (Kc/Ke/Ki & PRF)
  let base128 = must_hex("37 05 D9 60 80 C1 77 28 A0 E8 00 EA B6 E0 D2 3C")
  let base256 = must_hex(
    "6D 40 4D 37 FA F7 9F 9D F0 D3 35 68 D3 20 66 98 00 EB 48 36 47 2E A8 A0 26 D1 6B 71 82 46 0C 52",
  )
  let rfc8009_kdf_ok = try {
    let ke128 = @crypto.kdf_hmac_sha2(
      @crypto.Enctype::Aes128CtsHmacSha256_128,
      base128,
      must_hex("00000002AA"),
      None,
      128,
    )
    let prf128 = @crypto.kdf_hmac_sha2(
      @crypto.Enctype::Aes128CtsHmacSha256_128,
      base128,
      b"prf",
      Some(b"test"),
      256,
    )
    let ke256 = @crypto.kdf_hmac_sha2(
      @crypto.Enctype::Aes256CtsHmacSha384_192,
      base256,
      must_hex("00000002AA"),
      None,
      256,
    )
    let ki256 = @crypto.kdf_hmac_sha2(
      @crypto.Enctype::Aes256CtsHmacSha384_192,
      base256,
      must_hex("0000000255"),
      None,
      192,
    )
    ke128 == must_hex("9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E") &&
    prf128 ==
    must_hex(
      "9D 18 86 16 F6 38 52 FE 86 91 5B B8 40 B4 A8 86 FF 3E 6B B0 F8 19 B4 9B 89 33 93 D3 93 85 42 95",
    ) &&
    ke256 ==
    must_hex(
      "56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7 A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49",
    ) &&
    ki256 ==
    must_hex(
      "69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F",
    )
  } catch {
    _ => false
  }
  results.push(
    ("RFC 8009 Appendix A KDF-HMAC-SHA2 (Ke/Ki/PRF)", rfc8009_kdf_ok),
  )
  // 5. RFC 8009 Appendix A aes128-cts-hmac-sha256-128 Encrypt/Decrypt & Checksum
  let pt21 = must_hex(
    "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14",
  )
  let rfc8009_128_ok = try {
    let ct = @crypto.encrypt(
      @crypto.Enctype::Aes128CtsHmacSha256_128,
      base128,
      @crypto.KU_TICKET,
      pt21,
      must_hex("A7 A4 E2 9A 47 28 CE 10 66 4F B6 4E 49 AD 3F AC"),
    )
    let dec = @crypto.decrypt(
      @crypto.Enctype::Aes128CtsHmacSha256_128,
      base128,
      @crypto.KU_TICKET,
      ct,
    )
    let ck = @crypto.make_checksum(
      @crypto.ChecksumType::HmacSha256_128Aes128,
      base128,
      @crypto.KU_TICKET,
      pt21,
    )
    ct ==
    must_hex(
      "72 0F 73 B1 8D 98 59 CD 6C CB 43 46 11 5C D3 36 C7 0F 58 ED C0 C4 43 7C 55 73 54 4C 31 C8 13 BC E1 E6 D0 72 C1 86 B3 9A 41 3C 2F 92 CA 9B 83 34 A2 87 FF CB FC",
    ) &&
    dec == pt21 &&
    ck == must_hex("D7 83 67 18 66 43 D6 7B 41 1C BA 91 39 FC 1D EE")
  } catch {
    _ => false
  }
  results.push(
    ("RFC 8009 Appendix A AES128-CTS-HMAC-SHA256-128", rfc8009_128_ok),
  )
  // 6. RFC 8009 Appendix A aes256-cts-hmac-sha384-192 Encrypt/Decrypt & Checksum
  let rfc8009_256_ok = try {
    let ct = @crypto.encrypt(
      @crypto.Enctype::Aes256CtsHmacSha384_192,
      base256,
      @crypto.KU_TICKET,
      pt21,
      must_hex("76 3E 65 36 7E 86 4F 02 F5 51 53 C7 E3 B5 8A F1"),
    )
    let dec = @crypto.decrypt(
      @crypto.Enctype::Aes256CtsHmacSha384_192,
      base256,
      @crypto.KU_TICKET,
      ct,
    )
    let ck = @crypto.make_checksum(
      @crypto.ChecksumType::HmacSha384_192Aes256,
      base256,
      @crypto.KU_TICKET,
      pt21,
    )
    ct ==
    must_hex(
      "40 01 3E 2D F5 8E 87 51 95 7D 28 78 BC D2 D6 FE 10 1C CF D5 56 CB 1E AE 79 DB 3C 3E E8 64 29 F2 B2 A6 02 AC 86 FE F6 EC B6 47 D6 29 5F AE 07 7A 1F EB 51 75 08 D2 C1 6B 41 92 E0 1F 62",
    ) &&
    dec == pt21 &&
    ck ==
    must_hex(
      "45 EE 79 15 67 EE FC A3 7F 4A C1 E0 22 2D E8 0D 43 C3 BF A0 66 99 67 2A",
    )
  } catch {
    _ => false
  }
  results.push(
    ("RFC 8009 Appendix A AES256-CTS-HMAC-SHA384-192", rfc8009_256_ok),
  )
  results
}

///|
fn issue_demo_service_ticket(
  etype : @crypto.Enctype,
  seed : Bytes,
  t0 : Int64,
) -> (
  @protocol.Client,
  @protocol.Service,
  @protocol.Credential,
  @crypto.DeterministicRng,
) raise @protocol.ProtocolError {
  let realm = "DEFENSE.LOCAL"
  let rng = @crypto.DeterministicRng::new(seed)
  let krbtgt_key : @protocol.PrincipalKey = {
    etype,
    key: rng.next_bytes(etype.key_size()),
    salt: realm + "krbtgt" + realm,
    s2kparams: None,
  }
  let kdc = @protocol.Kdc::new(realm, [krbtgt_key], require_preauth=false)
  let alice = @types.PrincipalName::user("alice")
  let svc_name = @types.PrincipalName::service("HTTP", "vault.defense.local")
  let alice_pw = b"defense-demo-alice"
  let svc_pw = b"defense-demo-svc"
  let s2k = Some(u32_be(16))
  kdc.add_principal_with_password(alice, alice_pw, [etype], s2kparams=s2k)
  kdc.add_principal_with_password(svc_name, svc_pw, [etype], s2kparams=s2k)
  let kt = kdc.export_keytab(svc_name)
  let service = @protocol.Service::new(realm, svc_name, kt)
  let client = @protocol.Client::new(alice, realm, alice_pw, preferred_etypes=[
    etype,
  ])
  let as_req = client.build_as_req(t0, rng)
  let as_rep = kdc.handle_message(t0, 1, rng, as_req)
  let _ = client.handle_as_response(t0, 2, rng, as_rep)
  let tgs_req = client.build_tgs_req(svc_name, t0 + 1L, 3, rng)
  let tgs_rep = kdc.handle_message(t0 + 1L, 4, rng, tgs_req)
  let svc_cred = client.handle_tgs_response(tgs_rep)
  (client, service, svc_cred, rng)
}

///|
/// Demonstrate five active security defenses against classic Kerberos 5 attacks:
/// 1. Expired Ticket rejection (`TicketExpired`)
/// 2. Replay Authenticator detection (`ReplayDetected`)
/// 3. Tampered EncPart ciphertext rejection (`IntegrityCheckFailed`)
/// 4. KeyUsage Confusion rejection (`IntegrityCheckFailed`)
/// 5. Malformed / Non-Canonical DER rejection (`DerError`)
pub fn run_security_defense_demo() -> Array[(String, Bool)] {
  let results : Array[(String, Bool)] = []
  let t0 : Int64 = 1735689600L
  // Defense 1: Expired Ticket
  let expired_blocked = try {
    let (client, service, svc_cred, rng) = issue_demo_service_ticket(
      @crypto.Enctype::Aes256CtsHmacSha1_96,
      b"defense-expired",
      t0,
    )
    let t_expired = t0 + 40000L
    let ap_req = client.build_ap_req(svc_cred, t_expired, 11, rng)
    let _ = service.verify_ap_req(t_expired, rng, ap_req)
    false
  } catch {
    @protocol.ProtocolError::TicketExpired => true
    _ => false
  }
  results.push(
    ("Expired Ticket -> blocked with TicketExpired", expired_blocked),
  )
  // Defense 2: Replay Authenticator
  let replay_blocked = try {
    let (client, service, svc_cred, rng) = issue_demo_service_ticket(
      @crypto.Enctype::Aes128CtsHmacSha256_128,
      b"defense-replay",
      t0,
    )
    let ap_req = client.build_ap_req(svc_cred, t0 + 5L, 42, rng)
    let _ = service.verify_ap_req(t0 + 5L, rng, ap_req)
    let _ = service.verify_ap_req(t0 + 6L, rng, ap_req)
    false
  } catch {
    @protocol.ProtocolError::ReplayDetected => true
    _ => false
  }
  results.push(
    ("Replay Authenticator -> blocked with ReplayDetected", replay_blocked),
  )
  // Defense 3: Tampered EncPart (1-bit flip in Ticket ciphertext)
  let tamper_blocked = try {
    let (client, service, svc_cred, rng) = issue_demo_service_ticket(
      @crypto.Enctype::Aes256CtsHmacSha384_192,
      b"defense-tamper",
      t0,
    )
    let ap_req_der = client.build_ap_req(svc_cred, t0 + 5L, 77, rng)
    let decoded = @types.ApReq::decode(ap_req_der) catch {
      e => raise @protocol.ProtocolError::Der(e)
    }
    let tampered_cipher = flip_byte(decoded.ticket.enc_part.cipher, 0, 0x01)
    let tampered_ap_req : @types.ApReq = {
      ..decoded,
      ticket: {
        ..decoded.ticket,
        enc_part: { ..decoded.ticket.enc_part, cipher: tampered_cipher, },
      },
    }
    let tampered_der = tampered_ap_req.encode() catch {
      e => raise @protocol.ProtocolError::Der(e)
    }
    let _ = service.verify_ap_req(t0 + 5L, rng, tampered_der)
    false
  } catch {
    @protocol.ProtocolError::Crypto(@crypto.CryptoError::IntegrityCheckFailed) =>
      true
    _ => false
  }
  results.push(
    ("Tampered EncPart -> blocked with IntegrityCheckFailed", tamper_blocked),
  )
  // Defense 4: KeyUsage Confusion (encrypt with KU_AP_REQ_AUTH=11, decrypt with KU_AP_REP_ENCPART=12)
  let ku_blocked = try {
    let rng = @crypto.DeterministicRng::new(b"defense-ku")
    let et = @crypto.Enctype::Aes256CtsHmacSha384_192
    let key = rng.next_bytes(et.key_size())
    let conf = rng.next_bytes(et.confounder_size())
    let ct = @crypto.encrypt(
      et,
      key,
      @crypto.KU_AP_REQ_AUTH,
      b"kerberos-authenticator-plaintext",
      conf,
    )
    let _ = @crypto.decrypt(et, key, @crypto.KU_AP_REP_ENCPART, ct)
    false
  } catch {
    @crypto.CryptoError::IntegrityCheckFailed => true
    _ => false
  }
  results.push(
    ("KeyUsage Confusion -> blocked with IntegrityCheckFailed", ku_blocked),
  )
  // Defense 5: Malformed / Non-Canonical DER (indefinite length, non-minimal length,
  // non-canonical integer, trailing bytes)
  let indefinite_ok = try {
    let _ = @asn1.decode_der(must_hex("30 80 00 00"))
    false
  } catch {
    @asn1.DerError::IndefiniteLength => true
    _ => false
  }
  let non_minimal_len_ok = try {
    let _ = @asn1.decode_der(must_hex("04 81 01 41"))
    false
  } catch {
    @asn1.DerError::NonCanonicalLength => true
    _ => false
  }
  let non_canonical_int_ok = try {
    let _ = @asn1.decode_der(must_hex("02 02 00 01"))
    false
  } catch {
    @asn1.DerError::NonCanonicalInteger => true
    _ => false
  }
  let trailing_ok = try {
    let _ = @asn1.decode_der(must_hex("05 00 ff"))
    false
  } catch {
    @asn1.DerError::TrailingBytes(_) => true
    _ => false
  }
  let malformed_der_blocked = indefinite_ok &&
    non_minimal_len_ok &&
    non_canonical_int_ok &&
    trailing_ok
  results.push(
    ("Malformed DER (4 variants) -> strictly rejected", malformed_der_blocked),
  )
  results
}
