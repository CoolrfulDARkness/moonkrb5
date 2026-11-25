///|
/// Result of verifying an incoming `AP-REQ` at an application server.
#derive(Eq, Debug)
pub(all) struct VerifiedAuth {
  client : @types.PrincipalName
  crealm : String
  session_key : @types.EncryptionKey
  subkey : @types.EncryptionKey?
  authtime : String
  endtime : String
  ctime : String
  cusec : Int32
  mutual_required : Bool
  ap_rep_der : Bytes?
}

///|
pub impl Show for VerifiedAuth with fn output(self, logger) {
  logger.write_string("VerifiedAuth(client=")
  Show::output(self.client, logger)
  logger.write_string("@")
  logger.write_string(self.crealm)
  logger.write_string(", mutual_required=")
  Show::output(self.mutual_required, logger)
  logger.write_string(")")
}

///|
/// Sans-I/O Kerberos 5 application server verifier backed by a Keytab and ReplayCache.
pub struct Service {
  priv realm : String
  priv sname : @types.PrincipalName
  priv keytab : @keytab.Keytab
  priv max_skew_secs : Int64
  priv replay_cache : ReplayCache
}

///|
/// Create a new Sans-I/O Kerberos 5 service verifier.
pub fn Service::new(
  realm : String,
  sname : @types.PrincipalName,
  keytab : @keytab.Keytab,
  max_skew_secs~ : Int64 = 300L,
) -> Service {
  {
    realm,
    sname,
    keytab,
    max_skew_secs,
    replay_cache: ReplayCache::new(max_skew_secs~),
  }
}

///|
/// Verify an incoming DER-encoded `AP-REQ` (`[APPLICATION 14]`).
/// If `AP_OPT_MUTUAL_REQUIRED` is set, builds and returns the DER-encoded `AP-REP`
/// in `VerifiedAuth.ap_rep_der`.
pub fn Service::verify_ap_req(
  self : Service,
  now : Int64,
  rng : @crypto.DeterministicRng,
  ap_req_der : Bytes,
) -> VerifiedAuth raise ProtocolError {
  let ap_req = @types.ApReq::decode(ap_req_der) catch {
    e => raise ProtocolError::Der(e)
  }
  if ap_req.pvno != @types.KRB5_PVNO || ap_req.msg_type != @types.MSG_AP_REQ {
    raise ProtocolError::UnexpectedMessage(
      "Expected AP-REQ (pvno=5, msg_type=14)",
    )
  }
  if ap_req.ticket.tkt_vno != @types.KRB5_PVNO {
    raise ProtocolError::UnexpectedMessage("Unsupported Ticket version")
  }
  // Verify ticket is addressed to this service
  if ap_req.ticket.realm != self.realm || ap_req.ticket.sname != self.sname {
    raise ProtocolError::WrongService(
      "Expected " +
      self.sname.to_display() +
      "@" +
      self.realm +
      ", got " +
      ap_req.ticket.sname.to_display() +
      "@" +
      ap_req.ticket.realm,
    )
  }
  // Look up service key in keytab (distinguish BadKeyVersion vs KeyNotFound)
  let tkt_etype = ap_req.ticket.enc_part.etype
  let kt_entry = match ap_req.ticket.enc_part.kvno {
    Some(req_kvno) =>
      match
        self.keytab.find_key(
          self.realm,
          self.sname.name_string,
          tkt_etype,
          kvno=req_kvno,
        ) {
        Some(entry) => entry
        None =>
          match
            self.keytab.find_key(self.realm, self.sname.name_string, tkt_etype) {
            Some(_) => raise ProtocolError::BadKeyVersion
            None =>
              raise ProtocolError::KeyNotFound(
                "No keytab entry for " +
                self.sname.to_display() +
                "@" +
                self.realm +
                " etype=" +
                tkt_etype.to_string(),
              )
          }
      }
    None =>
      match
        self.keytab.find_key(self.realm, self.sname.name_string, tkt_etype) {
        Some(entry) => entry
        None =>
          raise ProtocolError::KeyNotFound(
            "No keytab entry for " +
            self.sname.to_display() +
            "@" +
            self.realm +
            " etype=" +
            tkt_etype.to_string(),
          )
      }
  }
  // Decrypt EncTicketPart with service key (KU_TICKET = 2)
  let tkt_plain = decrypt_data(
    ap_req.ticket.enc_part,
    kt_entry.key,
    @crypto.KU_TICKET,
  )
  let enc_tkt = @types.EncTicketPart::decode(tkt_plain) catch {
    e => raise ProtocolError::Der(e)
  }
  // Check ticket flags and validity window
  if (enc_tkt.flags & @types.TKT_FLAG_INVALID) != 0U {
    raise ProtocolError::TicketInvalidFlag
  }
  let start_str = enc_tkt.starttime.unwrap_or(enc_tkt.authtime)
  let start_unix = ktime_to_unix(start_str)
  if start_unix > now + self.max_skew_secs {
    raise ProtocolError::TicketNotYetValid
  }
  let end_unix = ktime_to_unix(enc_tkt.endtime)
  if now > end_unix {
    raise ProtocolError::TicketExpired
  }
  // Decrypt Authenticator with ticket session key (KU_AP_REQ_AUTH = 11)
  if ap_req.authenticator.etype != enc_tkt.key.keytype {
    raise ProtocolError::UnexpectedMessage(
      "Authenticator enctype does not match ticket session key",
    )
  }
  let auth_plain = decrypt_data(
    ap_req.authenticator,
    enc_tkt.key.keyvalue,
    @crypto.KU_AP_REQ_AUTH,
  )
  let auth = @types.Authenticator::decode(auth_plain) catch {
    e => raise ProtocolError::Der(e)
  }
  if auth.authenticator_vno != @types.KRB5_PVNO {
    raise ProtocolError::UnexpectedMessage("Unsupported Authenticator version")
  }
  // Check client principal matches ticket
  if auth.crealm != enc_tkt.crealm || auth.cname != enc_tkt.cname {
    raise ProtocolError::PrincipalMismatch(
      "Authenticator client does not match ticket client",
    )
  }
  // Check clock skew
  let ctime_unix = ktime_to_unix(auth.ctime)
  let diff = now - ctime_unix
  if abs_i64(diff) > self.max_skew_secs {
    raise ProtocolError::ClockSkew(diff)
  }
  // Check and insert into replay cache
  self.replay_cache.check_and_insert(
    now,
    auth.crealm,
    auth.cname,
    auth.ctime,
    auth.cusec,
  )
  // Build AP-REP when mutual authentication is requested
  let mutual_required = (ap_req.ap_options & @types.AP_OPT_MUTUAL_REQUIRED) !=
    0U
  let ap_rep_der : Bytes? = if mutual_required {
    let sess_etype = enctype_from_int(enc_tkt.key.keytype)
    let enc_ap_rep_part : @types.EncApRepPart = {
      ctime: auth.ctime,
      cusec: auth.cusec,
      subkey: None,
      seq_number: None,
    }
    let pt = enc_ap_rep_part.encode() catch { e => raise ProtocolError::Der(e) }
    let enc_part = encrypt_data(
      sess_etype,
      enc_tkt.key.keyvalue,
      None,
      @crypto.KU_AP_REP_ENCPART,
      pt,
      rng,
    )
    let ap_rep : @types.ApRep = {
      pvno: @types.KRB5_PVNO,
      msg_type: @types.MSG_AP_REP,
      enc_part,
    }
    let der = ap_rep.encode() catch { e => raise ProtocolError::Der(e) }
    Some(der)
  } else {
    None
  }
  {
    client: enc_tkt.cname,
    crealm: enc_tkt.crealm,
    session_key: enc_tkt.key,
    subkey: auth.subkey,
    authtime: enc_tkt.authtime,
    endtime: enc_tkt.endtime,
    ctime: auth.ctime,
    cusec: auth.cusec,
    mutual_required,
    ap_rep_der,
  }
}

///|
/// Build a DER-encoded `KRB-ERROR` (`[APPLICATION 30]`) originating from this service.
pub fn Service::make_krb_error(
  self : Service,
  now : Int64,
  now_usec : Int32,
  code : Int32,
  text : String,
) -> Bytes raise ProtocolError {
  let stime = unix_to_ktime(now)
  let err : @types.KrbError = {
    pvno: @types.KRB5_PVNO,
    msg_type: @types.MSG_KRB_ERROR,
    ctime: None,
    cusec: None,
    stime,
    susec: now_usec,
    error_code: code,
    crealm: None,
    cname: None,
    realm: self.realm,
    sname: self.sname,
    e_text: Some(text),
    e_data: None,
  }
  err.encode() catch {
    e => raise ProtocolError::Der(e)
  }
}
