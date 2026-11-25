///|
/// State of the Sans-I/O Kerberos 5 client authentication state machine.
#derive(Eq, Debug)
pub(all) enum ClientState {
  Init
  AwaitingAsRep
  HasTgt
  AwaitingTgsRep
  HasServiceTicket
  AwaitingApRep
  Authenticated
}

///|
pub impl Show for ClientState with fn output(self, logger) {
  let name = match self {
    Init => "Init"
    AwaitingAsRep => "AwaitingAsRep"
    HasTgt => "HasTgt"
    AwaitingTgsRep => "AwaitingTgsRep"
    HasServiceTicket => "HasServiceTicket"
    AwaitingApRep => "AwaitingApRep"
    Authenticated => "Authenticated"
  }
  logger.write_string(name)
}

///|
/// A Kerberos 5 credential (TGT or service ticket with its decrypted session key).
#derive(Eq, Debug)
pub(all) struct Credential {
  client : @types.PrincipalName
  crealm : String
  server : @types.PrincipalName
  srealm : String
  session_key : @types.EncryptionKey
  ticket : @types.Ticket
  authtime : String
  starttime : String?
  endtime : String
  flags : UInt32
}

///|
pub impl Show for Credential with fn output(self, logger) {
  logger.write_string("Credential(client=")
  Show::output(self.client, logger)
  logger.write_string("@")
  logger.write_string(self.crealm)
  logger.write_string(", server=")
  Show::output(self.server, logger)
  logger.write_string("@")
  logger.write_string(self.srealm)
  logger.write_string(", endtime=")
  logger.write_string(self.endtime)
  logger.write_string(")")
}

///|
/// Result of processing an AS-REQ response from the KDC.
#derive(Eq, Debug)
pub(all) enum AsStepResult {
  NeedPreauthRetry(Bytes)
  GotTgt(Credential)
}

///|
pub impl Show for AsStepResult with fn output(self, logger) {
  match self {
    NeedPreauthRetry(b) => {
      logger.write_string("NeedPreauthRetry(")
      Show::output(b.length(), logger)
      logger.write_string(" bytes)")
    }
    GotTgt(cred) => {
      logger.write_string("GotTgt(")
      Show::output(cred, logger)
      logger.write_string(")")
    }
  }
}

///|
/// Sans-I/O Kerberos 5 client state machine covering AS, TGS, and AP exchanges.
pub struct Client {
  priv cname : @types.PrincipalName
  priv realm : String
  priv password : Bytes
  priv preferred_etypes : Array[@crypto.Enctype]
  priv mut state : ClientState
  priv mut tgt : Credential?
  priv mut service_ticket : Credential?
  priv mut pending_as_nonce : UInt32?
  priv mut pending_as_key : (@crypto.Enctype, Bytes)?
  priv mut preauth_attempted : Bool
  priv mut pending_tgs_nonce : UInt32?
  priv mut pending_tgs_subkey : @types.EncryptionKey?
  priv mut pending_ap_cred : Credential?
  priv mut pending_ap_ctime : String?
  priv mut pending_ap_cusec : Int32?
}

///|
/// Create a new Sans-I/O Kerberos 5 client.
pub fn Client::new(
  cname : @types.PrincipalName,
  realm : String,
  password : Bytes,
  preferred_etypes~ : Array[@crypto.Enctype] = [
    @crypto.Enctype::Aes256CtsHmacSha384_192,
    @crypto.Enctype::Aes128CtsHmacSha256_128,
    @crypto.Enctype::Aes256CtsHmacSha1_96,
    @crypto.Enctype::Aes128CtsHmacSha1_96,
  ],
) -> Client {
  {
    cname,
    realm,
    password,
    preferred_etypes: preferred_etypes.copy(),
    state: Init,
    tgt: None,
    service_ticket: None,
    pending_as_nonce: None,
    pending_as_key: None,
    preauth_attempted: false,
    pending_tgs_nonce: None,
    pending_tgs_subkey: None,
    pending_ap_cred: None,
    pending_ap_ctime: None,
    pending_ap_cusec: None,
  }
}

///|
pub fn Client::state(self : Client) -> ClientState {
  self.state
}

///|
pub fn Client::tgt(self : Client) -> Credential? {
  self.tgt
}

///|
pub fn Client::service_ticket(self : Client) -> Credential? {
  self.service_ticket
}

///|
fn Client::preferred_etype_ints(self : Client) -> Array[Int32] {
  let out : Array[Int32] = []
  for et in self.preferred_etypes {
    out.push(et.to_int())
  }
  out
}

///|
fn Client::supports_etype(self : Client, et : @crypto.Enctype) -> Bool {
  for pref in self.preferred_etypes {
    if pref == et {
      return true
    }
  }
  false
}

///|
/// Build an initial `AS-REQ` (`[APPLICATION 10]`) to request a TGT for `krbtgt/<realm>`.
pub fn Client::build_as_req(
  self : Client,
  now : Int64,
  rng : @crypto.DeterministicRng,
) -> Bytes raise ProtocolError {
  match self.state {
    Init => ()
    _ =>
      raise ProtocolError::InvalidState(
        "build_as_req requires Init state, got " + Show::to_string(self.state),
      )
  }
  let nonce = next_nonce(rng)
  let till = unix_to_ktime(now + 36000L)
  let req_body : @types.KdcReqBody = {
    kdc_options: @types.KDC_OPT_FORWARDABLE | @types.KDC_OPT_RENEWABLE,
    cname: Some(self.cname),
    realm: self.realm,
    sname: Some(@types.PrincipalName::service("krbtgt", self.realm)),
    from: None,
    till,
    rtime: None,
    nonce,
    etype: self.preferred_etype_ints(),
    addresses: None,
    enc_authorization_data: None,
    additional_tickets: None,
  }
  let req : @types.KdcReq = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_AS_REQ,
    padata: None,
    req_body,
  }
  let der = req.encode_as_req() catch { e => raise ProtocolError::Der(e) }
  self.pending_as_nonce = Some(nonce)
  self.pending_as_key = None
  self.preauth_attempted = false
  self.state = AwaitingAsRep
  der
}

///|
/// Handle a KDC response to `AS-REQ`.
/// - On `KRB-ERROR(KDC_ERR_PREAUTH_REQUIRED = 25)`: parses `PA-ETYPE-INFO2`, derives the
///   client key with `string_to_key`, builds a retry `AS-REQ` with `PA-ENC-TIMESTAMP`,
///   and returns `NeedPreauthRetry(bytes)`.
/// - On `AS-REP`: decrypts `EncAsRepPart`, verifies `nonce`/`cname`/`crealm`, stores TGT,
///   transitions to `HasTgt`, and returns `GotTgt(cred)`.
pub fn Client::handle_as_response(
  self : Client,
  now : Int64,
  now_usec : Int32,
  rng : @crypto.DeterministicRng,
  resp_der : Bytes,
) -> AsStepResult raise ProtocolError {
  match self.state {
    AwaitingAsRep => ()
    _ =>
      raise ProtocolError::InvalidState(
        "handle_as_response requires AwaitingAsRep state, got " +
        Show::to_string(self.state),
      )
  }
  let app_tag = @asn1.peek_application_tag(resp_der) catch {
    e => raise ProtocolError::Der(e)
  }
  if app_tag == @asn1.APP_KRB_ERROR {
    let krb_err = @types.KrbError::decode(resp_der) catch {
      e => raise ProtocolError::Der(e)
    }
    if krb_err.error_code == @types.KDC_ERR_PREAUTH_REQUIRED {
      if self.preauth_attempted {
        raise ProtocolError::PreauthFailed(
          "KDC requested pre-authentication again after retry",
        )
      }
      let e_data = match krb_err.e_data {
        Some(d) => d
        None => raise ProtocolError::PreauthRequired
      }
      let method_data = @types.decode_method_data(e_data) catch {
        e => raise ProtocolError::Der(e)
      }
      let pa_info2 = match
        find_padata(Some(method_data), @types.PA_ETYPE_INFO2) {
        Some(pa) => pa
        None =>
          raise ProtocolError::PreauthFailed(
            "Missing PA-ETYPE-INFO2 in PREAUTH_REQUIRED error",
          )
      }
      let info2_entries = @types.decode_etype_info2(pa_info2.padata_value) catch {
        e => raise ProtocolError::Der(e)
      }
      let mut chosen : (@crypto.Enctype, @types.EtypeInfo2Entry)? = None
      for entry in info2_entries {
        let maybe_et : @crypto.Enctype? = Some(
          @crypto.Enctype::from_int(entry.etype),
        ) catch {
          _ => None
        }
        match maybe_et {
          Some(et) =>
            if self.supports_etype(et) {
              chosen = Some((et, entry))
              break
            }
          None => ()
        }
      }
      let (etype, info2_entry) = match chosen {
        Some(pair) => pair
        None =>
          raise ProtocolError::PreauthFailed(
            "No mutually supported enctype in PA-ETYPE-INFO2",
          )
      }
      let salt = info2_entry.salt.unwrap_or(
        default_salt(self.realm, self.cname),
      )
      let key = derive_string_to_key(
        etype,
        self.password,
        salt,
        info2_entry.s2kparams,
      )
      let patimestamp = unix_to_ktime(now)
      let pa_ts_enc : @types.PaEncTsEnc = {
        patimestamp,
        pausec: Some(now_usec),
      }
      let ts_plain = pa_ts_enc.encode() catch {
        e => raise ProtocolError::Der(e)
      }
      let enc_ts = encrypt_data(
        etype,
        key,
        None,
        @crypto.KU_AS_REQ_PA_ENC_TIMESTAMP,
        ts_plain,
        rng,
      )
      let enc_ts_der = @asn1.encode_der(enc_ts.to_der())
      let nonce = next_nonce(rng)
      let till = unix_to_ktime(now + 36000L)
      let req_body : @types.KdcReqBody = {
        kdc_options: @types.KDC_OPT_FORWARDABLE | @types.KDC_OPT_RENEWABLE,
        cname: Some(self.cname),
        realm: self.realm,
        sname: Some(@types.PrincipalName::service("krbtgt", self.realm)),
        from: None,
        till,
        rtime: None,
        nonce,
        etype: self.preferred_etype_ints(),
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
      }
      let retry_req : @types.KdcReq = {
        pvno: @types.KRB5_PVNO,
        msg_type: @types.MSG_AS_REQ,
        padata: Some([
          { padata_type: @types.PA_ENC_TIMESTAMP, padata_value: enc_ts_der, },
        ]),
        req_body,
      }
      let retry_der = retry_req.encode_as_req() catch {
        e => raise ProtocolError::Der(e)
      }
      self.pending_as_nonce = Some(nonce)
      self.pending_as_key = Some((etype, key))
      self.preauth_attempted = true
      return AsStepResult::NeedPreauthRetry(retry_der)
    } else if krb_err.error_code == @types.KDC_ERR_PREAUTH_FAILED {
      raise ProtocolError::PreauthFailed(
        krb_err.e_text.unwrap_or("KDC_ERR_PREAUTH_FAILED"),
      )
    } else {
      raise ProtocolError::KrbErrorReceived(
        code=krb_err.error_code,
        text=krb_err.e_text.unwrap_or(""),
      )
    }
  }
  if app_tag != @asn1.APP_AS_REP {
    raise ProtocolError::UnexpectedMessage(
      "Expected AS-REP or KRB-ERROR, got application tag " + app_tag.to_string(),
    )
  }
  let rep = @types.KdcRep::decode_as_rep(resp_der) catch {
    e => raise ProtocolError::Der(e)
  }
  if rep.pvno != @types.KRB5_PVNO || rep.msg_type != @types.MSG_AS_REP {
    raise ProtocolError::UnexpectedMessage("Invalid AS-REP pvno or msg-type")
  }
  if rep.crealm != self.realm || rep.cname != self.cname {
    raise ProtocolError::PrincipalMismatch(
      "AS-REP client principal does not match requested principal",
    )
  }
  let rep_etype = enctype_from_int(rep.enc_part.etype)
  let reply_key = match self.pending_as_key {
    Some((cached_et, cached_key)) if cached_et == rep_etype => cached_key
    _ => {
      // Check PA-ETYPE-INFO2 inside AS-REP padata for salt/s2kparams
      let mut salt = default_salt(self.realm, self.cname)
      let mut s2kparams : Bytes? = None
      match find_padata(rep.padata, @types.PA_ETYPE_INFO2) {
        Some(pa) => {
          let entries = @types.decode_etype_info2(pa.padata_value) catch {
            _ => []
          }
          for entry in entries {
            if entry.etype == rep.enc_part.etype {
              match entry.salt {
                Some(s) => salt = s
                None => ()
              }
              s2kparams = entry.s2kparams
              break
            }
          }
        }
        None => ()
      }
      derive_string_to_key(rep_etype, self.password, salt, s2kparams)
    }
  }
  let plain = decrypt_data(rep.enc_part, reply_key, @crypto.KU_AS_REP_ENCPART)
  let enc_part = @types.EncKdcRepPart::decode_enc_as_rep_part(plain) catch {
    e => raise ProtocolError::Der(e)
  }
  match self.pending_as_nonce {
    Some(expected_nonce) =>
      if enc_part.nonce != expected_nonce {
        raise ProtocolError::NonceMismatch
      }
    None => raise ProtocolError::InvalidState("Missing pending AS nonce")
  }
  let cred : Credential = {
    client: rep.cname,
    crealm: rep.crealm,
    server: enc_part.sname,
    srealm: enc_part.srealm,
    session_key: enc_part.key,
    ticket: rep.ticket,
    authtime: enc_part.authtime,
    starttime: enc_part.starttime,
    endtime: enc_part.endtime,
    flags: enc_part.flags,
  }
  self.tgt = Some(cred)
  self.pending_as_nonce = None
  self.state = HasTgt
  AsStepResult::GotTgt(cred)
}

///|
/// Build a `TGS-REQ` (`[APPLICATION 12]`) using the acquired TGT to request a service ticket.
pub fn Client::build_tgs_req(
  self : Client,
  service_name : @types.PrincipalName,
  now : Int64,
  now_usec : Int32,
  rng : @crypto.DeterministicRng,
  use_subkey~ : Bool = false,
) -> Bytes raise ProtocolError {
  match self.state {
    HasTgt | HasServiceTicket | Authenticated => ()
    _ =>
      raise ProtocolError::InvalidState(
        "build_tgs_req requires an acquired TGT, got " +
        Show::to_string(self.state),
      )
  }
  let tgt = match self.tgt {
    Some(t) => t
    None => raise ProtocolError::InvalidState("No TGT available")
  }
  let nonce = next_nonce(rng)
  let till = unix_to_ktime(now + 36000L)
  let req_body : @types.KdcReqBody = {
    kdc_options: 0U,
    cname: None,
    realm: self.realm,
    sname: Some(service_name),
    from: None,
    till,
    rtime: None,
    nonce,
    etype: self.preferred_etype_ints(),
    addresses: None,
    enc_authorization_data: None,
    additional_tickets: None,
  }
  let body_der = req_body.encode() catch { e => raise ProtocolError::Der(e) }
  let tgt_etype = enctype_from_int(tgt.session_key.keytype)
  let cksum_type = tgt_etype.default_checksum_type()
  let cksum_bytes = @crypto.make_checksum(
    cksum_type,
    tgt.session_key.keyvalue,
    @crypto.KU_TGS_REQ_AUTH_CKSUM,
    body_der,
  ) catch {
    e => raise map_crypto_error(e)
  }
  let opt_subkey : @types.EncryptionKey? = if use_subkey {
    Some({
      keytype: tgt_etype.to_int(),
      keyvalue: rng.next_bytes(tgt_etype.key_size()),
    })
  } else {
    None
  }
  let ctime = unix_to_ktime(now)
  let auth : @types.Authenticator = {
    authenticator_vno: @types.KRB5_PVNO,
    crealm: tgt.crealm,
    cname: tgt.client,
    cksum: Some({ cksumtype: cksum_type.to_int(), checksum: cksum_bytes, }),
    cusec: now_usec,
    ctime,
    subkey: opt_subkey,
    seq_number: None,
    authorization_data: None,
  }
  let auth_plain = auth.encode() catch { e => raise ProtocolError::Der(e) }
  let enc_auth = encrypt_data(
    tgt_etype,
    tgt.session_key.keyvalue,
    None,
    @crypto.KU_TGS_REQ_AUTH,
    auth_plain,
    rng,
  )
  let ap_req : @types.ApReq = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_AP_REQ,
    ap_options: 0U,
    ticket: tgt.ticket,
    authenticator: enc_auth,
  }
  let ap_req_der = ap_req.encode() catch { e => raise ProtocolError::Der(e) }
  let tgs_req : @types.KdcReq = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_TGS_REQ,
    padata: Some([{ padata_type: @types.PA_TGS_REQ, padata_value: ap_req_der, }]),
    req_body,
  }
  let der = tgs_req.encode_tgs_req() catch { e => raise ProtocolError::Der(e) }
  self.pending_tgs_nonce = Some(nonce)
  self.pending_tgs_subkey = opt_subkey
  self.state = AwaitingTgsRep
  der
}

///|
/// Handle a KDC response to `TGS-REQ`, decrypting `EncTgsRepPart` with either the
/// authenticator subkey (`KU_TGS_REP_ENCPART_AUTH_SUBKEY = 9`) or the TGT session
/// key (`KU_TGS_REP_ENCPART_SESSION_KEY = 8`) and verifying the `nonce`.
pub fn Client::handle_tgs_response(
  self : Client,
  resp_der : Bytes,
) -> Credential raise ProtocolError {
  match self.state {
    AwaitingTgsRep => ()
    _ =>
      raise ProtocolError::InvalidState(
        "handle_tgs_response requires AwaitingTgsRep state, got " +
        Show::to_string(self.state),
      )
  }
  let tgt = match self.tgt {
    Some(t) => t
    None => raise ProtocolError::InvalidState("No TGT available")
  }
  let app_tag = @asn1.peek_application_tag(resp_der) catch {
    e => raise ProtocolError::Der(e)
  }
  if app_tag == @asn1.APP_KRB_ERROR {
    let krb_err = @types.KrbError::decode(resp_der) catch {
      e => raise ProtocolError::Der(e)
    }
    raise ProtocolError::KrbErrorReceived(
      code=krb_err.error_code,
      text=krb_err.e_text.unwrap_or(""),
    )
  }
  if app_tag != @asn1.APP_TGS_REP {
    raise ProtocolError::UnexpectedMessage(
      "Expected TGS-REP or KRB-ERROR, got application tag " +
      app_tag.to_string(),
    )
  }
  let rep = @types.KdcRep::decode_tgs_rep(resp_der) catch {
    e => raise ProtocolError::Der(e)
  }
  if rep.pvno != @types.KRB5_PVNO || rep.msg_type != @types.MSG_TGS_REP {
    raise ProtocolError::UnexpectedMessage("Invalid TGS-REP pvno or msg-type")
  }
  if rep.crealm != tgt.crealm || rep.cname != tgt.client {
    raise ProtocolError::PrincipalMismatch(
      "TGS-REP client principal does not match TGT",
    )
  }
  let (dec_key, key_usage) = match self.pending_tgs_subkey {
    Some(subkey) => (subkey, @crypto.KU_TGS_REP_ENCPART_AUTH_SUBKEY)
    None => (tgt.session_key, @crypto.KU_TGS_REP_ENCPART_SESSION_KEY)
  }
  if rep.enc_part.etype != dec_key.keytype {
    raise ProtocolError::UnexpectedMessage(
      "TGS-REP enctype does not match expected decryption key",
    )
  }
  let plain = decrypt_data(rep.enc_part, dec_key.keyvalue, key_usage)
  let enc_part = @types.EncKdcRepPart::decode_enc_tgs_rep_part(plain) catch {
    e => raise ProtocolError::Der(e)
  }
  match self.pending_tgs_nonce {
    Some(expected_nonce) =>
      if enc_part.nonce != expected_nonce {
        raise ProtocolError::NonceMismatch
      }
    None => raise ProtocolError::InvalidState("Missing pending TGS nonce")
  }
  let cred : Credential = {
    client: rep.cname,
    crealm: rep.crealm,
    server: enc_part.sname,
    srealm: enc_part.srealm,
    session_key: enc_part.key,
    ticket: rep.ticket,
    authtime: enc_part.authtime,
    starttime: enc_part.starttime,
    endtime: enc_part.endtime,
    flags: enc_part.flags,
  }
  self.service_ticket = Some(cred)
  self.pending_tgs_nonce = None
  self.pending_tgs_subkey = None
  self.state = HasServiceTicket
  cred
}

///|
/// Build an `AP-REQ` (`[APPLICATION 14]`) to authenticate to an application server.
pub fn Client::build_ap_req(
  self : Client,
  cred : Credential,
  now : Int64,
  now_usec : Int32,
  rng : @crypto.DeterministicRng,
  mutual_required~ : Bool = true,
  use_subkey~ : Bool = false,
) -> Bytes raise ProtocolError {
  match self.state {
    HasServiceTicket | Authenticated | HasTgt => ()
    _ =>
      raise ProtocolError::InvalidState(
        "build_ap_req requires HasServiceTicket/Authenticated/HasTgt state, got " +
        Show::to_string(self.state),
      )
  }
  let svc_etype = enctype_from_int(cred.session_key.keytype)
  let opt_subkey : @types.EncryptionKey? = if use_subkey {
    Some({
      keytype: svc_etype.to_int(),
      keyvalue: rng.next_bytes(svc_etype.key_size()),
    })
  } else {
    None
  }
  let ctime = unix_to_ktime(now)
  let auth : @types.Authenticator = {
    authenticator_vno: @types.KRB5_PVNO,
    crealm: cred.crealm,
    cname: cred.client,
    cksum: None,
    cusec: now_usec,
    ctime,
    subkey: opt_subkey,
    seq_number: None,
    authorization_data: None,
  }
  let auth_plain = auth.encode() catch { e => raise ProtocolError::Der(e) }
  let enc_auth = encrypt_data(
    svc_etype,
    cred.session_key.keyvalue,
    None,
    @crypto.KU_AP_REQ_AUTH,
    auth_plain,
    rng,
  )
  let ap_options = if mutual_required {
    @types.AP_OPT_MUTUAL_REQUIRED
  } else {
    0U
  }
  let ap_req : @types.ApReq = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_AP_REQ,
    ap_options,
    ticket: cred.ticket,
    authenticator: enc_auth,
  }
  let der = ap_req.encode() catch { e => raise ProtocolError::Der(e) }
  self.pending_ap_cred = Some(cred)
  self.pending_ap_ctime = Some(ctime)
  self.pending_ap_cusec = Some(now_usec)
  self.state = if mutual_required { AwaitingApRep } else { Authenticated }
  der
}

///|
/// Verify an `AP-REP` (`[APPLICATION 15]`) for mutual authentication.
/// Strictly checks that the decrypted `ctime` and `cusec` match the sent `AP-REQ`.
pub fn Client::handle_ap_rep(
  self : Client,
  ap_rep_der : Bytes,
) -> @types.EncApRepPart raise ProtocolError {
  match self.state {
    AwaitingApRep => ()
    _ =>
      raise ProtocolError::InvalidState(
        "handle_ap_rep requires AwaitingApRep state, got " +
        Show::to_string(self.state),
      )
  }
  let app_tag = @asn1.peek_application_tag(ap_rep_der) catch {
    e => raise ProtocolError::Der(e)
  }
  if app_tag == @asn1.APP_KRB_ERROR {
    let krb_err = @types.KrbError::decode(ap_rep_der) catch {
      e => raise ProtocolError::Der(e)
    }
    raise ProtocolError::KrbErrorReceived(
      code=krb_err.error_code,
      text=krb_err.e_text.unwrap_or(""),
    )
  }
  if app_tag != @asn1.APP_AP_REP {
    raise ProtocolError::UnexpectedMessage(
      "Expected AP-REP or KRB-ERROR, got application tag " + app_tag.to_string(),
    )
  }
  let ap_rep = @types.ApRep::decode(ap_rep_der) catch {
    e => raise ProtocolError::Der(e)
  }
  if ap_rep.pvno != @types.KRB5_PVNO || ap_rep.msg_type != @types.MSG_AP_REP {
    raise ProtocolError::UnexpectedMessage("Invalid AP-REP pvno or msg-type")
  }
  let cred = match self.pending_ap_cred {
    Some(c) => c
    None => raise ProtocolError::InvalidState("Missing pending AP credential")
  }
  let expected_ctime = match self.pending_ap_ctime {
    Some(t) => t
    None => raise ProtocolError::InvalidState("Missing pending AP ctime")
  }
  let expected_cusec = match self.pending_ap_cusec {
    Some(u) => u
    None => raise ProtocolError::InvalidState("Missing pending AP cusec")
  }
  if ap_rep.enc_part.etype != cred.session_key.keytype {
    raise ProtocolError::MutualAuthFailed(
      "AP-REP enctype does not match service session key",
    )
  }
  let plain = decrypt_data(
    ap_rep.enc_part,
    cred.session_key.keyvalue,
    @crypto.KU_AP_REP_ENCPART,
  )
  let enc_ap_rep = @types.EncApRepPart::decode(plain) catch {
    e => raise ProtocolError::Der(e)
  }
  if enc_ap_rep.ctime != expected_ctime || enc_ap_rep.cusec != expected_cusec {
    raise ProtocolError::MutualAuthFailed(
      "AP-REP ctime/cusec mismatch: expected (" +
      expected_ctime +
      ", " +
      expected_cusec.to_string() +
      "), got (" +
      enc_ap_rep.ctime +
      ", " +
      enc_ap_rep.cusec.to_string() +
      ")",
    )
  }
  self.pending_ap_cred = None
  self.pending_ap_ctime = None
  self.pending_ap_cusec = None
  self.state = Authenticated
  enc_ap_rep
}
