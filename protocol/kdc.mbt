///|
/// Long-term principal key record held in the KDC database.
#derive(Eq, Debug)
pub(all) struct PrincipalKey {
  etype : @crypto.Enctype
  key : Bytes
  salt : String
  s2kparams : Bytes?
}

///|
pub impl Show for PrincipalKey with fn output(self, logger) {
  logger.write_string("PrincipalKey(etype=")
  Show::output(self.etype, logger)
  logger.write_string(", salt=")
  Show::output(self.salt, logger)
  logger.write_string(", key_len=")
  Show::output(self.key.length(), logger)
  logger.write_string(")")
}

///|
priv struct PrincipalEntry {
  name : @types.PrincipalName
  kvno : UInt32
  keys : Array[PrincipalKey]
}

///|
/// In-memory Sans-I/O Kerberos 5 Key Distribution Center (AS + TGS).
pub struct Kdc {
  priv realm : String
  priv require_preauth : Bool
  priv max_skew_secs : Int64
  priv default_lifetime_secs : Int64
  priv principals : Map[String, PrincipalEntry]
  priv as_replay_cache : ReplayCache
  priv tgs_replay_cache : ReplayCache
}

///|
/// Create a new KDC for `realm` with the given `krbtgt/<realm>` keys.
pub fn Kdc::new(
  realm : String,
  krbtgt_keys : Array[PrincipalKey],
  require_preauth~ : Bool = true,
  max_skew_secs~ : Int64 = 300L,
  default_lifetime_secs~ : Int64 = 36000L,
) -> Kdc {
  let kdc : Kdc = {
    realm,
    require_preauth,
    max_skew_secs,
    default_lifetime_secs,
    principals: {},
    as_replay_cache: ReplayCache::new(max_skew_secs~),
    tgs_replay_cache: ReplayCache::new(max_skew_secs~),
  }
  let krbtgt_name = @types.PrincipalName::service("krbtgt", realm)
  kdc.add_principal_keys(krbtgt_name, 1U, krbtgt_keys)
  kdc
}

///|
/// Register or update a principal with explicit long-term keys and kvno.
pub fn Kdc::add_principal_keys(
  self : Kdc,
  name : @types.PrincipalName,
  kvno : UInt32,
  keys : Array[PrincipalKey],
) -> Unit {
  let lookup = principal_lookup_key(name)
  self.principals.set(lookup, { name, kvno, keys: keys.copy(), })
}

///|
/// Register or update a principal by deriving keys from a password using
/// RFC 3962 / RFC 8009 `string_to_key` with default salt `realm + components.join("")`.
pub fn Kdc::add_principal_with_password(
  self : Kdc,
  name : @types.PrincipalName,
  password : Bytes,
  etypes : Array[@crypto.Enctype],
  kvno~ : UInt32 = 1U,
  s2kparams~ : Bytes? = None,
) -> Unit raise ProtocolError {
  let salt = default_salt(self.realm, name)
  let keys : Array[PrincipalKey] = []
  for etype in etypes {
    let key = derive_string_to_key(etype, password, salt, s2kparams)
    keys.push({ etype, key, salt, s2kparams, })
  }
  self.add_principal_keys(name, kvno, keys)
}

///|
/// Export a principal's keys as a standard Kerberos 5 Keytab object.
pub fn Kdc::export_keytab(
  self : Kdc,
  name : @types.PrincipalName,
  timestamp~ : UInt32 = 0U,
) -> @keytab.Keytab raise ProtocolError {
  let lookup = principal_lookup_key(name)
  let entry = match self.principals.get(lookup) {
    Some(e) => e
    None => raise ProtocolError::KeyNotFound(name.to_display())
  }
  let kt = @keytab.Keytab::new()
  for pk in entry.keys {
    kt.add_entry({
      realm: self.realm,
      components: entry.name.name_string.copy(),
      name_type: entry.name.name_type,
      timestamp,
      kvno: entry.kvno,
      etype: pk.etype.to_int(),
      key: pk.key,
    })
  }
  kt
}

///|
fn Kdc::find_principal(
  self : Kdc,
  name : @types.PrincipalName,
) -> PrincipalEntry? {
  self.principals.get(principal_lookup_key(name))
}

///|
fn find_principal_key_by_etype(
  entry : PrincipalEntry,
  etype_int : Int32,
) -> PrincipalKey? {
  for pk in entry.keys {
    if pk.etype.to_int() == etype_int {
      return Some(pk)
    }
  }
  None
}

///|
fn negotiate_key(
  requested_etypes : Array[Int32],
  entry : PrincipalEntry,
) -> PrincipalKey? {
  for et_int in requested_etypes {
    let supported = try {
      let _ = @crypto.Enctype::from_int(et_int)
      true
    } catch {
      _ => false
    }
    if supported {
      match find_principal_key_by_etype(entry, et_int) {
        Some(pk) => return Some(pk)
        None => ()
      }
    }
  }
  None
}

///|
fn build_etype_info2_for_client(
  requested_etypes : Array[Int32],
  client_entry : PrincipalEntry,
) -> Array[@types.EtypeInfo2Entry] {
  let out : Array[@types.EtypeInfo2Entry] = []
  let seen : Map[Int32, Bool] = Map([])
  for et_int in requested_etypes {
    if seen.contains(et_int) {
      continue
    }
    seen.set(et_int, true)
    match find_principal_key_by_etype(client_entry, et_int) {
      Some(pk) =>
        out.push({
          etype: pk.etype.to_int(),
          salt: Some(pk.salt),
          s2kparams: pk.s2kparams,
        })
      None => ()
    }
  }
  out
}

///|
fn has_unsupported_kdc_options(opts : UInt32) -> Bool {
  let supported = @types.KDC_OPT_FORWARDABLE |
    @types.KDC_OPT_PROXIABLE |
    @types.KDC_OPT_RENEWABLE
  (opts & (supported ^ 0xFFFFFFFFU)) != 0U
}

///|
fn count_padata(padata : Array[@types.PaData]?, pa_type : Int32) -> Int32 {
  match padata {
    None => 0
    Some(items) => {
      let mut n = 0
      for pa in items {
        if pa.padata_type == pa_type {
          n += 1
        }
      }
      n
    }
  }
}

///|
fn Kdc::make_krb_error(
  self : Kdc,
  now : Int64,
  now_usec : Int32,
  code : Int32,
  text : String,
  crealm~ : String? = None,
  cname~ : @types.PrincipalName? = None,
  sname~ : @types.PrincipalName? = None,
  e_data~ : Bytes? = None,
) -> Bytes {
  let stime = @types.unix_to_kerberos_time(now) catch { _ => "19700101000000Z" }
  let target_sname = match sname {
    Some(s) => s
    None => @types.PrincipalName::service("krbtgt", self.realm)
  }
  let err : @types.KrbError = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_KRB_ERROR,
    ctime: None,
    cusec: None,
    stime,
    susec: now_usec,
    error_code: code,
    crealm,
    cname,
    realm: self.realm,
    sname: target_sname,
    e_text: Some(text),
    e_data,
  }
  err.encode() catch {
    _ => b""
  }
}

///|
fn find_padata(
  padata : Array[@types.PaData]?,
  pa_type : Int32,
) -> @types.PaData? {
  match padata {
    None => None
    Some(items) => {
      for pa in items {
        if pa.padata_type == pa_type {
          return Some(pa)
        }
      }
      None
    }
  }
}

///|
/// Dispatch an incoming DER-encoded KDC request (`[APPLICATION 10]` AS-REQ or
/// `[APPLICATION 12]` TGS-REQ). All RFC 4120 errors return DER-encoded `KRB-ERROR`.
pub fn Kdc::handle_message(
  self : Kdc,
  now : Int64,
  now_usec : Int32,
  rng : @crypto.DeterministicRng,
  req_der : Bytes,
) -> Bytes {
  let app_tag = @asn1.peek_application_tag(req_der) catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_ERR_GENERIC,
        "Malformed DER KDC request",
      )
  }
  if app_tag == @asn1.APP_AS_REQ {
    self.handle_as_req(now, now_usec, rng, req_der)
  } else if app_tag == @asn1.APP_TGS_REQ {
    self.handle_tgs_req(now, now_usec, rng, req_der)
  } else {
    self.make_krb_error(
      now,
      now_usec,
      @types.KRB_AP_ERR_MSG_TYPE,
      "Unsupported KDC request application tag",
    )
  }
}

///|
/// Handle an RFC 4120 Authentication Service Request (`AS-REQ`, `[APPLICATION 10]`).
pub fn Kdc::handle_as_req(
  self : Kdc,
  now : Int64,
  now_usec : Int32,
  rng : @crypto.DeterministicRng,
  req_der : Bytes,
) -> Bytes {
  let req = @types.KdcReq::decode_as_req(req_der) catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_ERR_GENERIC,
        "Failed to decode AS-REQ",
      )
  }
  if req.pvno != @types.KRB5_PVNO {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KDC_ERR_BAD_PVNO,
      "Unsupported protocol version",
    )
  }
  if req.msg_type != @types.MSG_AS_REQ {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KRB_AP_ERR_MSG_TYPE,
      "Unexpected msg-type in AS-REQ",
    )
  }
  let body = req.req_body
  let cname = match body.cname {
    Some(c) => c
    None =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KDC_ERR_C_PRINCIPAL_UNKNOWN,
        "Missing cname in AS-REQ",
      )
  }
  let sname = match body.sname {
    Some(s) => s
    None =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KDC_ERR_S_PRINCIPAL_UNKNOWN,
        "Missing sname in AS-REQ",
        crealm=Some(body.realm),
        cname=Some(cname),
      )
  }
  if body.realm != self.realm {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KDC_ERR_C_PRINCIPAL_UNKNOWN,
      "Unknown realm",
      crealm=Some(body.realm),
      cname=Some(cname),
      sname=Some(sname),
    )
  }
  if has_unsupported_kdc_options(body.kdc_options) {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KDC_ERR_BADOPTION,
      "Unsupported kdc-options requested in AS-REQ",
      crealm=Some(self.realm),
      cname=Some(cname),
      sname=Some(sname),
    )
  }
  if count_padata(req.padata, @types.PA_ENC_TIMESTAMP) > 1 {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KDC_ERR_PREAUTH_FAILED,
      "Duplicate PA-ENC-TIMESTAMP in AS-REQ",
      crealm=Some(self.realm),
      cname=Some(cname),
      sname=Some(sname),
    )
  }
  let client_entry = match self.find_principal(cname) {
    Some(e) => e
    None =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KDC_ERR_C_PRINCIPAL_UNKNOWN,
        "Client principal not found",
        crealm=Some(self.realm),
        cname=Some(cname),
        sname=Some(sname),
      )
  }
  let server_entry = match self.find_principal(sname) {
    Some(e) => e
    None =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KDC_ERR_S_PRINCIPAL_UNKNOWN,
        "Server principal not found",
        crealm=Some(self.realm),
        cname=Some(cname),
        sname=Some(sname),
      )
  }
  let default_client_pk = match negotiate_key(body.etype, client_entry) {
    Some(pk) => pk
    None =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KDC_ERR_ETYPE_NOSUPP,
        "No matching client encryption type",
        crealm=Some(self.realm),
        cname=Some(cname),
        sname=Some(sname),
      )
  }
  let server_pk = match negotiate_key(body.etype, server_entry) {
    Some(pk) => pk
    None =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KDC_ERR_ETYPE_NOSUPP,
        "No matching server encryption type",
        crealm=Some(self.realm),
        cname=Some(cname),
        sname=Some(sname),
      )
  }
  let mut reply_pk = default_client_pk
  let mut preauth_ok = false
  match find_padata(req.padata, @types.PA_ENC_TIMESTAMP) {
    Some(pa_ts) => {
      let enc_ts = try {
        let der_val = @asn1.decode_der(pa_ts.padata_value)
        @types.EncryptedData::from_der(der_val)
      } catch {
        _ =>
          return self.make_krb_error(
            now,
            now_usec,
            @types.KDC_ERR_PREAUTH_FAILED,
            "Malformed PA-ENC-TIMESTAMP",
            crealm=Some(self.realm),
            cname=Some(cname),
            sname=Some(sname),
          )
      }
      match enc_ts.kvno {
        Some(k) =>
          if k != client_entry.kvno {
            return self.make_krb_error(
              now,
              now_usec,
              @types.KDC_ERR_PREAUTH_FAILED,
              "Pre-authentication key version mismatch",
              crealm=Some(self.realm),
              cname=Some(cname),
              sname=Some(sname),
            )
          }
        None => ()
      }
      let pa_pk = match
        find_principal_key_by_etype(client_entry, enc_ts.etype) {
        Some(pk) => pk
        None =>
          return self.make_krb_error(
            now,
            now_usec,
            @types.KDC_ERR_PREAUTH_FAILED,
            "Unsupported pre-authentication etype",
            crealm=Some(self.realm),
            cname=Some(cname),
            sname=Some(sname),
          )
      }
      let ts_plain = decrypt_data(
        enc_ts,
        pa_pk.key,
        @crypto.KU_AS_REQ_PA_ENC_TIMESTAMP,
      ) catch {
        _ =>
          return self.make_krb_error(
            now,
            now_usec,
            @types.KDC_ERR_PREAUTH_FAILED,
            "Pre-authentication decryption failed",
            crealm=Some(self.realm),
            cname=Some(cname),
            sname=Some(sname),
          )
      }
      let ts_enc = @types.PaEncTsEnc::decode(ts_plain) catch {
        _ =>
          return self.make_krb_error(
            now,
            now_usec,
            @types.KDC_ERR_PREAUTH_FAILED,
            "Malformed PA-ENC-TS-ENC",
            crealm=Some(self.realm),
            cname=Some(cname),
            sname=Some(sname),
          )
      }
      let ts_unix = @types.kerberos_time_to_unix(ts_enc.patimestamp) catch {
        _ =>
          return self.make_krb_error(
            now,
            now_usec,
            @types.KDC_ERR_PREAUTH_FAILED,
            "Invalid patimestamp",
            crealm=Some(self.realm),
            cname=Some(cname),
            sname=Some(sname),
          )
      }
      if abs_i64(now - ts_unix) > self.max_skew_secs {
        return self.make_krb_error(
          now,
          now_usec,
          @types.KRB_AP_ERR_SKEW,
          "Clock skew too great in pre-authentication",
          crealm=Some(self.realm),
          cname=Some(cname),
          sname=Some(sname),
        )
      }
      let pausec = ts_enc.pausec.unwrap_or(0)
      self.as_replay_cache.check_and_insert(
        now,
        self.realm,
        cname,
        ts_enc.patimestamp,
        pausec,
      ) catch {
        ProtocolError::ReplayDetected =>
          return self.make_krb_error(
            now,
            now_usec,
            @types.KRB_AP_ERR_REPEAT,
            "Replay detected in pre-authentication",
            crealm=Some(self.realm),
            cname=Some(cname),
            sname=Some(sname),
          )
        _ =>
          return self.make_krb_error(
            now,
            now_usec,
            @types.KDC_ERR_PREAUTH_FAILED,
            "Pre-authentication replay check failed",
            crealm=Some(self.realm),
            cname=Some(cname),
            sname=Some(sname),
          )
      }
      // If the client used a requested etype for pre-auth, reply with that key.
      for et_int in body.etype {
        if et_int == pa_pk.etype.to_int() {
          reply_pk = pa_pk
          break
        }
      }
      preauth_ok = true
    }
    None =>
      if self.require_preauth {
        let info2 = build_etype_info2_for_client(body.etype, client_entry)
        let info2_der = @types.encode_etype_info2(info2)
        let method_data = @types.encode_method_data([
          { padata_type: @types.PA_ETYPE_INFO2, padata_value: info2_der, },
        ])
        return self.make_krb_error(
          now,
          now_usec,
          @types.KDC_ERR_PREAUTH_REQUIRED,
          "Additional pre-authentication required",
          crealm=Some(self.realm),
          cname=Some(cname),
          sname=Some(sname),
          e_data=Some(method_data),
        )
      }
  }
  // Compute ticket lifetime
  let till_unix = @types.kerberos_time_to_unix(body.till) catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_ERR_GENERIC,
        "Invalid till timestamp",
        crealm=Some(self.realm),
        cname=Some(cname),
        sname=Some(sname),
      )
  }
  let max_end = now + self.default_lifetime_secs
  let end_unix = if till_unix == 0L || till_unix > max_end {
    max_end
  } else {
    till_unix
  }
  if end_unix <= now {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KDC_ERR_NEVER_VALID,
      "Requested ticket lifetime is invalid",
      crealm=Some(self.realm),
      cname=Some(cname),
      sname=Some(sname),
    )
  }
  let authtime = @types.unix_to_kerberos_time(now) catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_ERR_GENERIC,
        "Invalid current timestamp",
      )
  }
  let endtime = @types.unix_to_kerberos_time(end_unix) catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_ERR_GENERIC,
        "Invalid end timestamp",
      )
  }
  let mut flags = @types.TKT_FLAG_INITIAL
  if preauth_ok {
    flags = flags | @types.TKT_FLAG_PRE_AUTHENT
  }
  if (body.kdc_options & @types.KDC_OPT_FORWARDABLE) != 0U {
    flags = flags | @types.TKT_FLAG_FORWARDABLE
  }
  if (body.kdc_options & @types.KDC_OPT_PROXIABLE) != 0U {
    flags = flags | @types.TKT_FLAG_PROXIABLE
  }
  if (body.kdc_options & @types.KDC_OPT_RENEWABLE) != 0U {
    flags = flags | @types.TKT_FLAG_RENEWABLE
  }
  let renew_till : String? = if (flags & @types.TKT_FLAG_RENEWABLE) != 0U {
    let mut renew_unix = end_unix + self.default_lifetime_secs
    match body.rtime {
      Some(rtime_str) => {
        let rtime_unix = @types.kerberos_time_to_unix(rtime_str) catch {
          _ =>
            return self.make_krb_error(
              now,
              now_usec,
              @types.KRB_ERR_GENERIC,
              "Invalid rtime timestamp",
              crealm=Some(self.realm),
              cname=Some(cname),
              sname=Some(sname),
            )
        }
        if rtime_unix > end_unix && rtime_unix < renew_unix {
          renew_unix = rtime_unix
        }
      }
      None => ()
    }
    let rt_str = @types.unix_to_kerberos_time(renew_unix) catch {
      _ =>
        return self.make_krb_error(
          now,
          now_usec,
          @types.KRB_ERR_GENERIC,
          "Invalid renew_till timestamp",
        )
    }
    Some(rt_str)
  } else {
    None
  }
  let session_etype = server_pk.etype
  let session_key : @types.EncryptionKey = {
    keytype: session_etype.to_int(),
    keyvalue: rng.next_bytes(session_etype.key_size()),
  }
  let enc_ticket_part : @types.EncTicketPart = {
    flags,
    key: session_key,
    crealm: self.realm,
    cname,
    transited: { tr_type: 1, contents: b"", },
    authtime,
    starttime: Some(authtime),
    endtime,
    renew_till,
    caddr: None,
    authorization_data: None,
  }
  let ticket_enc = try {
    let pt = enc_ticket_part.encode()
    encrypt_data(
      server_pk.etype,
      server_pk.key,
      Some(server_entry.kvno),
      @crypto.KU_TICKET,
      pt,
      rng,
    )
  } catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_ERR_GENERIC,
        "Failed to encrypt ticket",
      )
  }
  let ticket : @types.Ticket = {
    tkt_vno: @types.KRB5_PVNO,
    realm: self.realm,
    sname,
    enc_part: ticket_enc,
  }
  let enc_as_rep_part : @types.EncKdcRepPart = {
    key: session_key,
    last_req: [{ lr_type: 0, lr_value: authtime, }],
    nonce: body.nonce,
    key_expiration: None,
    flags,
    authtime,
    starttime: Some(authtime),
    endtime,
    renew_till,
    srealm: self.realm,
    sname,
    caddr: None,
  }
  let rep_enc = try {
    let pt = enc_as_rep_part.encode_enc_as_rep_part()
    encrypt_data(
      reply_pk.etype,
      reply_pk.key,
      Some(client_entry.kvno),
      @crypto.KU_AS_REP_ENCPART,
      pt,
      rng,
    )
  } catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_ERR_GENERIC,
        "Failed to encrypt AS-REP part",
      )
  }
  let reply_info2 = @types.encode_etype_info2([
    {
      etype: reply_pk.etype.to_int(),
      salt: Some(reply_pk.salt),
      s2kparams: reply_pk.s2kparams,
    },
  ])
  let as_rep : @types.KdcRep = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_AS_REP,
    padata: Some([
      { padata_type: @types.PA_ETYPE_INFO2, padata_value: reply_info2, },
    ]),
    crealm: self.realm,
    cname,
    ticket,
    enc_part: rep_enc,
  }
  as_rep.encode_as_rep() catch {
    _ =>
      self.make_krb_error(
        now,
        now_usec,
        @types.KRB_ERR_GENERIC,
        "Failed to encode AS-REP",
      )
  }
}

///|
/// Handle an RFC 4120 Ticket-Granting Service Request (`TGS-REQ`, `[APPLICATION 12]`).
pub fn Kdc::handle_tgs_req(
  self : Kdc,
  now : Int64,
  now_usec : Int32,
  rng : @crypto.DeterministicRng,
  req_der : Bytes,
) -> Bytes {
  let (req, raw_req_body) = @types.KdcReq::decode_tgs_req_with_raw_body(req_der) catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_ERR_GENERIC,
        "Failed to decode TGS-REQ",
      )
  }
  if req.pvno != @types.KRB5_PVNO {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KDC_ERR_BAD_PVNO,
      "Unsupported protocol version",
    )
  }
  if req.msg_type != @types.MSG_TGS_REQ {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KRB_AP_ERR_MSG_TYPE,
      "Unexpected msg-type in TGS-REQ",
    )
  }
  if count_padata(req.padata, @types.PA_TGS_REQ) > 1 {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KRB_AP_ERR_MSG_TYPE,
      "Duplicate PA-TGS-REQ in TGS-REQ",
    )
  }
  let pa_tgs = match find_padata(req.padata, @types.PA_TGS_REQ) {
    Some(pa) => pa
    None =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KDC_ERR_PADATA_TYPE_NOSUPP,
        "Missing PA-TGS-REQ in TGS-REQ",
      )
  }
  let ap_req = @types.ApReq::decode(pa_tgs.padata_value) catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_AP_ERR_MSG_TYPE,
        "Failed to decode AP-REQ in PA-TGS-REQ",
      )
  }
  if ap_req.pvno != @types.KRB5_PVNO ||
    ap_req.ticket.tkt_vno != @types.KRB5_PVNO {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KRB_AP_ERR_BADVERSION,
      "Unsupported AP-REQ or Ticket version",
    )
  }
  if ap_req.msg_type != @types.MSG_AP_REQ {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KRB_AP_ERR_MSG_TYPE,
      "Invalid msg-type in PA-TGS-REQ",
    )
  }
  // Verify TGT is addressed to krbtgt/<realm>
  let krbtgt_name = @types.PrincipalName::service("krbtgt", self.realm)
  if ap_req.ticket.realm != self.realm ||
    ap_req.ticket.sname.name_string != krbtgt_name.name_string {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KRB_AP_ERR_NOT_US,
      "TGT is not for krbtgt/" + self.realm,
    )
  }
  let krbtgt_entry = match self.find_principal(krbtgt_name) {
    Some(e) => e
    None =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_AP_ERR_NOKEY,
        "krbtgt principal not configured",
      )
  }
  match ap_req.ticket.enc_part.kvno {
    Some(k) =>
      if k != krbtgt_entry.kvno {
        return self.make_krb_error(
          now,
          now_usec,
          @types.KRB_AP_ERR_BADKEYVER,
          "TGT key version mismatch",
        )
      }
    None => ()
  }
  let krbtgt_pk = match
    find_principal_key_by_etype(krbtgt_entry, ap_req.ticket.enc_part.etype) {
    Some(pk) => pk
    None =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_AP_ERR_NOKEY,
        "No matching krbtgt key for TGT etype",
      )
  }
  let tgt_plain = decrypt_data(
    ap_req.ticket.enc_part,
    krbtgt_pk.key,
    @crypto.KU_TICKET,
  ) catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_AP_ERR_BAD_INTEGRITY,
        "TGT decryption failed",
      )
  }
  let tgt_enc = @types.EncTicketPart::decode(tgt_plain) catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_AP_ERR_BAD_INTEGRITY,
        "Failed to decode TGT EncTicketPart",
      )
  }
  // Validate TGT flags and validity period
  if (tgt_enc.flags & @types.TKT_FLAG_INVALID) != 0U {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KRB_AP_ERR_TKT_NYV,
      "TGT has INVALID flag set",
      crealm=Some(tgt_enc.crealm),
      cname=Some(tgt_enc.cname),
    )
  }
  let tgt_start_str = tgt_enc.starttime.unwrap_or(tgt_enc.authtime)
  let tgt_start_unix = @types.kerberos_time_to_unix(tgt_start_str) catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_ERR_GENERIC,
        "Invalid TGT starttime",
      )
  }
  if tgt_start_unix > now + self.max_skew_secs {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KRB_AP_ERR_TKT_NYV,
      "TGT not yet valid",
      crealm=Some(tgt_enc.crealm),
      cname=Some(tgt_enc.cname),
    )
  }
  let tgt_end_unix = @types.kerberos_time_to_unix(tgt_enc.endtime) catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_ERR_GENERIC,
        "Invalid TGT endtime",
      )
  }
  if now > tgt_end_unix {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KRB_AP_ERR_TKT_EXPIRED,
      "TGT expired",
      crealm=Some(tgt_enc.crealm),
      cname=Some(tgt_enc.cname),
    )
  }
  // Decrypt Authenticator with TGT session key (KU_TGS_REQ_AUTH = 7)
  if ap_req.authenticator.etype != tgt_enc.key.keytype {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KRB_AP_ERR_BAD_INTEGRITY,
      "Authenticator enctype does not match TGT session key",
      crealm=Some(tgt_enc.crealm),
      cname=Some(tgt_enc.cname),
    )
  }
  let tgt_etype = @crypto.Enctype::from_int(tgt_enc.key.keytype) catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KDC_ERR_ETYPE_NOSUPP,
        "Unsupported TGT session key enctype",
      )
  }
  let auth_plain = decrypt_data(
    ap_req.authenticator,
    tgt_enc.key.keyvalue,
    @crypto.KU_TGS_REQ_AUTH,
  ) catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_AP_ERR_BAD_INTEGRITY,
        "TGS Authenticator decryption failed",
        crealm=Some(tgt_enc.crealm),
        cname=Some(tgt_enc.cname),
      )
  }
  let auth = @types.Authenticator::decode(auth_plain) catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_AP_ERR_BAD_INTEGRITY,
        "Failed to decode TGS Authenticator",
      )
  }
  if auth.authenticator_vno != @types.KRB5_PVNO {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KRB_AP_ERR_BADVERSION,
      "Unsupported Authenticator version",
    )
  }
  if auth.crealm != tgt_enc.crealm ||
    !principal_names_equal(auth.cname, tgt_enc.cname) {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KRB_AP_ERR_BADMATCH,
      "Authenticator principal does not match TGT",
      crealm=Some(tgt_enc.crealm),
      cname=Some(tgt_enc.cname),
    )
  }
  let auth_ctime_unix = @types.kerberos_time_to_unix(auth.ctime) catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_ERR_GENERIC,
        "Invalid Authenticator ctime",
      )
  }
  if abs_i64(now - auth_ctime_unix) > self.max_skew_secs {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KRB_AP_ERR_SKEW,
      "Clock skew too great",
      crealm=Some(tgt_enc.crealm),
      cname=Some(tgt_enc.cname),
    )
  }
  // Read-only replay check before req-body checksum to prevent MITM cache poisoning DoS.
  if self.tgs_replay_cache.contains(
      now,
      auth.crealm,
      auth.cname,
      auth.ctime,
      auth.cusec,
    ) {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KRB_AP_ERR_REPEAT,
      "Replay detected in TGS-REQ authenticator",
      crealm=Some(tgt_enc.crealm),
      cname=Some(tgt_enc.cname),
    )
  }
  // Mandatory verification of Authenticator.cksum over exact on-the-wire DER req_body bytes
  let cksum = match auth.cksum {
    Some(ck) => ck
    None =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_AP_ERR_MODIFIED,
        "Missing req-body checksum in TGS-REQ authenticator",
        crealm=Some(tgt_enc.crealm),
        cname=Some(tgt_enc.cname),
      )
  }
  let cksum_type = @crypto.ChecksumType::from_int(cksum.cksumtype) catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KDC_ERR_SUMTYPE_NOSUPP,
        "Unsupported checksum type",
        crealm=Some(tgt_enc.crealm),
        cname=Some(tgt_enc.cname),
      )
  }
  if cksum_type != tgt_etype.default_checksum_type() {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KRB_AP_ERR_MODIFIED,
      "Checksum type does not match TGT session key enctype",
      crealm=Some(tgt_enc.crealm),
      cname=Some(tgt_enc.cname),
    )
  }
  let cksum_valid = @crypto.verify_checksum(
    cksum_type,
    tgt_enc.key.keyvalue,
    @crypto.KU_TGS_REQ_AUTH_CKSUM,
    raw_req_body,
    cksum.checksum,
  ) catch {
    _ => false
  }
  if !cksum_valid {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KRB_AP_ERR_MODIFIED,
      "TGS-REQ req-body checksum verification failed",
      crealm=Some(tgt_enc.crealm),
      cname=Some(tgt_enc.cname),
    )
  }
  // Insert into TGS replay cache only AFTER Authenticator.cksum verification succeeds.
  self.tgs_replay_cache.insert(
    now,
    auth.crealm,
    auth.cname,
    auth.ctime,
    auth.cusec,
  ) catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_ERR_GENERIC,
        "Replay cache insert failed",
      )
  }
  // Look up target service principal
  let body = req.req_body
  let sname = match body.sname {
    Some(s) => s
    None =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KDC_ERR_S_PRINCIPAL_UNKNOWN,
        "Missing target service name in TGS-REQ",
        crealm=Some(tgt_enc.crealm),
        cname=Some(tgt_enc.cname),
      )
  }
  if has_unsupported_kdc_options(body.kdc_options) {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KDC_ERR_BADOPTION,
      "Unsupported kdc-options requested in TGS-REQ",
      crealm=Some(tgt_enc.crealm),
      cname=Some(tgt_enc.cname),
      sname=Some(sname),
    )
  }
  if body.realm != self.realm {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KDC_ERR_S_PRINCIPAL_UNKNOWN,
      "Target realm mismatch",
      crealm=Some(tgt_enc.crealm),
      cname=Some(tgt_enc.cname),
      sname=Some(sname),
    )
  }
  let service_entry = match self.find_principal(sname) {
    Some(e) => e
    None =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KDC_ERR_S_PRINCIPAL_UNKNOWN,
        "Target service principal not found",
        crealm=Some(tgt_enc.crealm),
        cname=Some(tgt_enc.cname),
        sname=Some(sname),
      )
  }
  let service_pk = match negotiate_key(body.etype, service_entry) {
    Some(pk) => pk
    None =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KDC_ERR_ETYPE_NOSUPP,
        "No matching service encryption type",
        crealm=Some(tgt_enc.crealm),
        cname=Some(tgt_enc.cname),
        sname=Some(sname),
      )
  }
  // Compute service ticket lifetime (clamped by TGT endtime and default lifetime)
  let till_unix = @types.kerberos_time_to_unix(body.till) catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_ERR_GENERIC,
        "Invalid till timestamp in TGS-REQ",
      )
  }
  let mut end_unix = now + self.default_lifetime_secs
  if tgt_end_unix < end_unix {
    end_unix = tgt_end_unix
  }
  if till_unix != 0L && till_unix < end_unix {
    end_unix = till_unix
  }
  if end_unix <= now {
    return self.make_krb_error(
      now,
      now_usec,
      @types.KDC_ERR_NEVER_VALID,
      "Requested service ticket lifetime is invalid",
      crealm=Some(tgt_enc.crealm),
      cname=Some(tgt_enc.cname),
      sname=Some(sname),
    )
  }
  let now_str = @types.unix_to_kerberos_time(now) catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_ERR_GENERIC,
        "Invalid current timestamp",
      )
  }
  let endtime = @types.unix_to_kerberos_time(end_unix) catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_ERR_GENERIC,
        "Invalid service ticket endtime",
      )
  }
  let mut svc_flags = 0U
  if (tgt_enc.flags & @types.TKT_FLAG_PRE_AUTHENT) != 0U {
    svc_flags = svc_flags | @types.TKT_FLAG_PRE_AUTHENT
  }
  if (body.kdc_options & @types.KDC_OPT_FORWARDABLE) != 0U &&
    (tgt_enc.flags & @types.TKT_FLAG_FORWARDABLE) != 0U {
    svc_flags = svc_flags | @types.TKT_FLAG_FORWARDABLE
  }
  if (body.kdc_options & @types.KDC_OPT_PROXIABLE) != 0U &&
    (tgt_enc.flags & @types.TKT_FLAG_PROXIABLE) != 0U {
    svc_flags = svc_flags | @types.TKT_FLAG_PROXIABLE
  }
  if (body.kdc_options & @types.KDC_OPT_RENEWABLE) != 0U &&
    (tgt_enc.flags & @types.TKT_FLAG_RENEWABLE) != 0U {
    svc_flags = svc_flags | @types.TKT_FLAG_RENEWABLE
  }
  let svc_renew_till : String? = if (svc_flags & @types.TKT_FLAG_RENEWABLE) !=
    0U {
    let mut renew_unix = end_unix + self.default_lifetime_secs
    match tgt_enc.renew_till {
      Some(tgt_rt_str) => {
        let tgt_rt_unix = @types.kerberos_time_to_unix(tgt_rt_str) catch {
          _ =>
            return self.make_krb_error(
              now,
              now_usec,
              @types.KRB_ERR_GENERIC,
              "Invalid TGT renew_till timestamp",
            )
        }
        if tgt_rt_unix < renew_unix {
          renew_unix = tgt_rt_unix
        }
      }
      None => ()
    }
    match body.rtime {
      Some(rtime_str) => {
        let rtime_unix = @types.kerberos_time_to_unix(rtime_str) catch {
          _ =>
            return self.make_krb_error(
              now,
              now_usec,
              @types.KRB_ERR_GENERIC,
              "Invalid rtime timestamp in TGS-REQ",
            )
        }
        if rtime_unix > end_unix && rtime_unix < renew_unix {
          renew_unix = rtime_unix
        }
      }
      None => ()
    }
    if renew_unix < end_unix {
      renew_unix = end_unix
    }
    let rt_str = @types.unix_to_kerberos_time(renew_unix) catch {
      _ =>
        return self.make_krb_error(
          now,
          now_usec,
          @types.KRB_ERR_GENERIC,
          "Invalid service ticket renew_till timestamp",
        )
    }
    Some(rt_str)
  } else {
    None
  }
  let svc_session_etype = service_pk.etype
  let svc_session_key : @types.EncryptionKey = {
    keytype: svc_session_etype.to_int(),
    keyvalue: rng.next_bytes(svc_session_etype.key_size()),
  }
  let svc_enc_ticket_part : @types.EncTicketPart = {
    flags: svc_flags,
    key: svc_session_key,
    crealm: tgt_enc.crealm,
    cname: tgt_enc.cname,
    transited: tgt_enc.transited,
    authtime: tgt_enc.authtime,
    starttime: Some(now_str),
    endtime,
    renew_till: svc_renew_till,
    caddr: None,
    authorization_data: None,
  }
  let svc_ticket_enc = try {
    let pt = svc_enc_ticket_part.encode()
    encrypt_data(
      service_pk.etype,
      service_pk.key,
      Some(service_entry.kvno),
      @crypto.KU_TICKET,
      pt,
      rng,
    )
  } catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_ERR_GENERIC,
        "Failed to encrypt service ticket",
      )
  }
  let svc_ticket : @types.Ticket = {
    tkt_vno: @types.KRB5_PVNO,
    realm: self.realm,
    sname,
    enc_part: svc_ticket_enc,
  }
  let enc_tgs_rep_part : @types.EncKdcRepPart = {
    key: svc_session_key,
    last_req: [{ lr_type: 0, lr_value: now_str, }],
    nonce: body.nonce,
    key_expiration: None,
    flags: svc_flags,
    authtime: tgt_enc.authtime,
    starttime: Some(now_str),
    endtime,
    renew_till: svc_renew_till,
    srealm: self.realm,
    sname,
    caddr: None,
  }
  let (reply_etype, reply_key_bytes, reply_usage) = match auth.subkey {
    Some(subkey) => {
      let sub_et = @crypto.Enctype::from_int(subkey.keytype) catch {
        _ =>
          return self.make_krb_error(
            now,
            now_usec,
            @types.KDC_ERR_ETYPE_NOSUPP,
            "Unsupported Authenticator subkey enctype",
          )
      }
      (sub_et, subkey.keyvalue, @crypto.KU_TGS_REP_ENCPART_AUTH_SUBKEY)
    }
    None =>
      (tgt_etype, tgt_enc.key.keyvalue, @crypto.KU_TGS_REP_ENCPART_SESSION_KEY)
  }
  let tgs_rep_enc = try {
    let pt = enc_tgs_rep_part.encode_enc_tgs_rep_part()
    encrypt_data(reply_etype, reply_key_bytes, None, reply_usage, pt, rng)
  } catch {
    _ =>
      return self.make_krb_error(
        now,
        now_usec,
        @types.KRB_ERR_GENERIC,
        "Failed to encrypt TGS-REP part",
      )
  }
  let tgs_rep : @types.KdcRep = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_TGS_REP,
    padata: None,
    crealm: tgt_enc.crealm,
    cname: tgt_enc.cname,
    ticket: svc_ticket,
    enc_part: tgs_rep_enc,
  }
  tgs_rep.encode_tgs_rep() catch {
    _ =>
      self.make_krb_error(
        now,
        now_usec,
        @types.KRB_ERR_GENERIC,
        "Failed to encode TGS-REP",
      )
  }
}
