///|
test "bench_asn1_der_ticket_roundtrip" (b : @bench.T) {
  let ticket : @types.Ticket = {
    tkt_vno: @types.KRB5_PVNO,
    realm: "EXAMPLE.COM",
    sname: @types.PrincipalName::service("HTTP", "web.example.com"),
    enc_part: { etype: 20, kvno: Some(3U), cipher: Bytes::make(256, b'\xA5'), },
  }
  b.bench(fn() {
    let encoded = ticket.encode() catch { _ => abort("ticket encode failed") }
    let decoded = @types.Ticket::decode(encoded) catch {
      _ => abort("ticket decode failed")
    }
    b.keep(decoded)
  })
}

///|
test "bench_crypto_aes128_sha1_enc_dec" (b : @bench.T) {
  let etype = @crypto.Enctype::Aes128CtsHmacSha1_96
  let key = Bytes::make(16, b'\x11')
  let conf = Bytes::make(16, b'\x22')
  let payload = Bytes::make(256, b'\x33')
  b.bench(fn() {
    let ct = @crypto.encrypt(etype, key, @crypto.KU_TICKET, payload, conf) catch {
      _ => abort("encrypt failed")
    }
    let pt = @crypto.decrypt(etype, key, @crypto.KU_TICKET, ct) catch {
      _ => abort("decrypt failed")
    }
    b.keep(pt)
  })
}

///|
test "bench_crypto_aes256_sha1_enc_dec" (b : @bench.T) {
  let etype = @crypto.Enctype::Aes256CtsHmacSha1_96
  let key = Bytes::make(32, b'\x12')
  let conf = Bytes::make(16, b'\x23')
  let payload = Bytes::make(256, b'\x34')
  b.bench(fn() {
    let ct = @crypto.encrypt(etype, key, @crypto.KU_TICKET, payload, conf) catch {
      _ => abort("encrypt failed")
    }
    let pt = @crypto.decrypt(etype, key, @crypto.KU_TICKET, ct) catch {
      _ => abort("decrypt failed")
    }
    b.keep(pt)
  })
}

///|
test "bench_crypto_aes128_sha256_enc_dec" (b : @bench.T) {
  let etype = @crypto.Enctype::Aes128CtsHmacSha256_128
  let key = Bytes::make(16, b'\x13')
  let conf = Bytes::make(16, b'\x24')
  let payload = Bytes::make(256, b'\x35')
  b.bench(fn() {
    let ct = @crypto.encrypt(etype, key, @crypto.KU_TICKET, payload, conf) catch {
      _ => abort("encrypt failed")
    }
    let pt = @crypto.decrypt(etype, key, @crypto.KU_TICKET, ct) catch {
      _ => abort("decrypt failed")
    }
    b.keep(pt)
  })
}

///|
test "bench_crypto_aes256_sha384_enc_dec" (b : @bench.T) {
  let etype = @crypto.Enctype::Aes256CtsHmacSha384_192
  let key = Bytes::make(32, b'\x14')
  let conf = Bytes::make(16, b'\x25')
  let payload = Bytes::make(256, b'\x36')
  b.bench(fn() {
    let ct = @crypto.encrypt(etype, key, @crypto.KU_TICKET, payload, conf) catch {
      _ => abort("encrypt failed")
    }
    let pt = @crypto.decrypt(etype, key, @crypto.KU_TICKET, ct) catch {
      _ => abort("decrypt failed")
    }
    b.keep(pt)
  })
}

///|
test "bench_keytab_roundtrip" (b : @bench.T) {
  let kt = @keytab.Keytab::new()
  let etypes = [17, 18, 19, 20]
  let key_lens = [16, 32, 16, 32]
  for i = 0; i < etypes.length(); i = i + 1 {
    kt.add_entry({
      realm: "EXAMPLE.COM",
      components: ["HTTP", "web.example.com"],
      name_type: @types.NT_SRV_HST,
      timestamp: 1700000000U,
      kvno: 3U,
      etype: etypes[i],
      key: Bytes::make(key_lens[i], (0x40 + i).to_byte()),
    })
  }
  b.bench(fn() {
    let encoded = kt.encode() catch { _ => abort("keytab encode failed") }
    let decoded = @keytab.Keytab::decode(encoded) catch {
      _ => abort("keytab decode failed")
    }
    b.keep(decoded)
  })
}

///|
test "bench_full_krb5_handshake_aes256_sha384" (b : @bench.T) {
  let realm = "EXAMPLE.COM"
  let etype = @crypto.Enctype::Aes256CtsHmacSha384_192
  let s2k = Some(b"\x00\x00\x00\x01")
  let alice = @types.PrincipalName::user("alice")
  let http_svc = @types.PrincipalName::service("HTTP", "web.example.com")
  let alice_pw = b"bench-alice-password!"
  let setup_rng = @crypto.DeterministicRng::new(b"bench_handshake_setup")
  let krbtgt_pk : @protocol.PrincipalKey = {
    etype,
    key: setup_rng.next_bytes(32),
    salt: realm + "krbtgt" + realm,
    s2kparams: s2k,
  }
  let alice_salt_str = realm + "alice"
  let alice_salt = Bytes::makei(alice_salt_str.length(), fn(i) {
    alice_salt_str[i].to_byte()
  })
  let alice_key = @crypto.string_to_key(etype, alice_pw, alice_salt, s2k) catch {
    _ => abort("alice string_to_key failed")
  }
  let alice_pk : @protocol.PrincipalKey = {
    etype,
    key: alice_key,
    salt: alice_salt_str,
    s2kparams: s2k,
  }
  let svc_key = setup_rng.next_bytes(32)
  let svc_pk : @protocol.PrincipalKey = {
    etype,
    key: svc_key,
    salt: realm + "HTTPweb.example.com",
    s2kparams: s2k,
  }
  let kt = @keytab.Keytab::new()
  kt.add_entry({
    realm,
    components: ["HTTP", "web.example.com"],
    name_type: @types.NT_SRV_HST,
    timestamp: 1700000000U,
    kvno: 1U,
    etype: etype.to_int(),
    key: svc_key,
  })
  let t0 : Int64 = 1700000000L
  b.bench(fn() {
    let rng = @crypto.DeterministicRng::new(b"bench_iter_rng")
    let kdc = @protocol.Kdc::new(realm, [krbtgt_pk], require_preauth=true)
    kdc.add_principal_keys(alice, 1U, [alice_pk])
    kdc.add_principal_keys(http_svc, 1U, [svc_pk])
    let service = @protocol.Service::new(realm, http_svc, kt)
    let client = @protocol.Client::new(
      alice,
      realm,
      alice_pw,
      preferred_etypes=[etype],
      min_s2k_iterations=1U,
    )
    let ok = try {
      let as_req1 = client.build_as_req(t0, rng)
      let as_resp1 = kdc.handle_message(t0, 1, rng, as_req1)
      let as_req2 = match client.handle_as_response(t0 + 1L, 2, rng, as_resp1) {
        @protocol.AsStepResult::NeedPreauthRetry(der) => der
        @protocol.AsStepResult::GotTgt(_) => abort("expected preauth")
      }
      let as_resp2 = kdc.handle_message(t0 + 1L, 3, rng, as_req2)
      let _ = client.handle_as_response(t0 + 1L, 4, rng, as_resp2)
      let tgs_req = client.build_tgs_req(http_svc, t0 + 2L, 5, rng)
      let tgs_resp = kdc.handle_message(t0 + 2L, 6, rng, tgs_req)
      let svc_cred = client.handle_tgs_response(tgs_resp)
      let ap_req = client.build_ap_req(
        svc_cred,
        t0 + 3L,
        7,
        rng,
        mutual_required=true,
      )
      let verified = service.verify_ap_req(t0 + 3L, rng, ap_req)
      let ap_rep = match verified.ap_rep_der {
        Some(der) => der
        None => abort("missing AP-REP")
      }
      let _ = client.handle_ap_rep(ap_rep)
      client.state() == @protocol.ClientState::Authenticated
    } catch {
      _ => abort("handshake failed")
    }
    b.keep(ok)
  })
}
