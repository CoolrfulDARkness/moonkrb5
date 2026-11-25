///|
fn validate_pvno(
  pvno : Int32,
  field_name : String,
) -> Unit raise @asn1.DerError {
  if pvno != KRB5_PVNO {
    raise @asn1.DerError::InvalidValue(
      "\{field_name} must be \{KRB5_PVNO}, got \{pvno}",
    )
  }
}

///|
fn validate_msg_type(
  msg_type : Int32,
  expected : Int32,
) -> Unit raise @asn1.DerError {
  if msg_type != expected {
    raise @asn1.DerError::InvalidValue(
      "msg-type must be \{expected}, got \{msg_type}",
    )
  }
}

///|
fn unwrap_app(
  val : @asn1.DerValue,
  expected_tag : Int32,
) -> @asn1.DerValue raise @asn1.DerError {
  match val {
    Application(tag, inner) =>
      if tag == expected_tag {
        inner
      } else {
        raise @asn1.DerError::TagMismatch(
          expected="APPLICATION[\{expected_tag}]",
          got="APPLICATION[\{tag}]",
        )
      }
    other =>
      raise @asn1.DerError::TagMismatch(
        expected="APPLICATION[\{expected_tag}]",
        got="\{other}",
      )
  }
}

///|
/// RFC 4120 §5.3 `Ticket ::= [APPLICATION 1] SEQUENCE`.
#derive(Eq, Debug)
pub(all) struct Ticket {
  tkt_vno : Int32
  realm : String
  sname : PrincipalName
  enc_part : EncryptedData
}

///|
pub impl Show for Ticket with fn output(self, logger) {
  logger.write_string(
    "Ticket(tkt_vno=\{self.tkt_vno}, realm=\{self.realm}, sname=\{self.sname}, enc_part=\{self.enc_part})",
  )
}

///|
pub fn Ticket::to_der(self : Ticket) -> @asn1.DerValue raise @asn1.DerError {
  validate_pvno(self.tkt_vno, "tkt-vno")
  @asn1.DerValue::Application(
    @asn1.APP_TICKET,
    @asn1.DerValue::Sequence([
      @asn1.context_field(0, @asn1.encode_int(self.tkt_vno)),
      @asn1.context_field(1, @asn1.encode_general_string(self.realm)),
      @asn1.context_field(2, self.sname.to_der()),
      @asn1.context_field(3, self.enc_part.to_der()),
    ]),
  )
}

///|
pub fn Ticket::from_der(val : @asn1.DerValue) -> Ticket raise @asn1.DerError {
  let inner = unwrap_app(val, @asn1.APP_TICKET)
  let r = @asn1.SeqReader::new(inner)
  let tkt_vno = @asn1.decode_int(r.read_required(0))
  validate_pvno(tkt_vno, "tkt-vno")
  let realm = @asn1.decode_general_string(r.read_required(1))
  let sname = PrincipalName::from_der(r.read_required(2))
  let enc_part = EncryptedData::from_der(r.read_required(3))
  r.finish()
  { tkt_vno, realm, sname, enc_part, }
}

///|
pub fn Ticket::encode(self : Ticket) -> Bytes raise @asn1.DerError {
  @asn1.encode_der(self.to_der())
}

///|
pub fn Ticket::decode(data : Bytes) -> Ticket raise @asn1.DerError {
  let inner = @asn1.decode_application(data, @asn1.APP_TICKET)
  let r = @asn1.SeqReader::new(inner)
  let tkt_vno = @asn1.decode_int(r.read_required(0))
  validate_pvno(tkt_vno, "tkt-vno")
  let realm = @asn1.decode_general_string(r.read_required(1))
  let sname = PrincipalName::from_der(r.read_required(2))
  let enc_part = EncryptedData::from_der(r.read_required(3))
  r.finish()
  { tkt_vno, realm, sname, enc_part, }
}

///|
/// RFC 4120 §5.5.1 `Authenticator ::= [APPLICATION 2] SEQUENCE`.
#derive(Eq, Debug)
pub(all) struct Authenticator {
  authenticator_vno : Int32
  crealm : String
  cname : PrincipalName
  cksum : Checksum?
  cusec : Int32
  ctime : String
  subkey : EncryptionKey?
  seq_number : UInt32?
  authorization_data : Array[AuthorizationDataEntry]?
}

///|
pub impl Show for Authenticator with fn output(self, logger) {
  logger.write_string(
    "Authenticator(vno=\{self.authenticator_vno}, crealm=\{self.crealm}, cname=\{self.cname}, cksum=",
  )
  write_show_opt(self.cksum, logger)
  logger.write_string(", cusec=\{self.cusec}, ctime=\{self.ctime}, subkey=")
  write_show_opt(self.subkey, logger)
  logger.write_string(", seq_number=")
  write_show_opt(self.seq_number, logger)
  logger.write_string(", authorization_data=")
  write_show_opt_array(self.authorization_data, logger)
  logger.write_string(")")
}

///|
pub fn Authenticator::to_der(
  self : Authenticator,
) -> @asn1.DerValue raise @asn1.DerError {
  validate_pvno(self.authenticator_vno, "authenticator-vno")
  validate_microseconds(self.cusec)
  let fields : Array[@asn1.DerValue] = [
    @asn1.context_field(0, @asn1.encode_int(self.authenticator_vno)),
    @asn1.context_field(1, @asn1.encode_general_string(self.crealm)),
    @asn1.context_field(2, self.cname.to_der()),
  ]
  match self.cksum {
    Some(c) => fields.push(@asn1.context_field(3, c.to_der()))
    None => ()
  }
  fields.push(@asn1.context_field(4, @asn1.encode_int(self.cusec)))
  fields.push(@asn1.context_field(5, @asn1.encode_generalized_time(self.ctime)))
  match self.subkey {
    Some(k) => fields.push(@asn1.context_field(6, k.to_der()))
    None => ()
  }
  match self.seq_number {
    Some(s) => fields.push(@asn1.context_field(7, @asn1.encode_uint32(s)))
    None => ()
  }
  match self.authorization_data {
    Some(ad) =>
      fields.push(@asn1.context_field(8, encode_authorization_data(ad)))
    None => ()
  }
  @asn1.DerValue::Application(
    @asn1.APP_AUTHENTICATOR,
    @asn1.DerValue::Sequence(fields),
  )
}

///|
pub fn Authenticator::from_der(
  val : @asn1.DerValue,
) -> Authenticator raise @asn1.DerError {
  let inner = unwrap_app(val, @asn1.APP_AUTHENTICATOR)
  let r = @asn1.SeqReader::new(inner)
  let authenticator_vno = @asn1.decode_int(r.read_required(0))
  validate_pvno(authenticator_vno, "authenticator-vno")
  let crealm = @asn1.decode_general_string(r.read_required(1))
  let cname = PrincipalName::from_der(r.read_required(2))
  let cksum = match r.read_optional(3) {
    Some(v) => Some(Checksum::from_der(v))
    None => None
  }
  let cusec = @asn1.decode_int(r.read_required(4))
  validate_microseconds(cusec)
  let ctime = @asn1.decode_generalized_time(r.read_required(5))
  let subkey = match r.read_optional(6) {
    Some(v) => Some(EncryptionKey::from_der(v))
    None => None
  }
  let seq_number = match r.read_optional(7) {
    Some(v) => Some(@asn1.decode_uint32(v))
    None => None
  }
  let authorization_data = match r.read_optional(8) {
    Some(v) => Some(decode_authorization_data(v))
    None => None
  }
  r.finish()
  {
    authenticator_vno,
    crealm,
    cname,
    cksum,
    cusec,
    ctime,
    subkey,
    seq_number,
    authorization_data,
  }
}

///|
pub fn Authenticator::encode(
  self : Authenticator,
) -> Bytes raise @asn1.DerError {
  @asn1.encode_der(self.to_der())
}

///|
pub fn Authenticator::decode(
  data : Bytes,
) -> Authenticator raise @asn1.DerError {
  let inner = @asn1.decode_application(data, @asn1.APP_AUTHENTICATOR)
  Authenticator::from_der(
    @asn1.DerValue::Application(@asn1.APP_AUTHENTICATOR, inner),
  )
}

///|
/// RFC 4120 §5.3 `EncTicketPart ::= [APPLICATION 3] SEQUENCE`.
#derive(Eq, Debug)
pub(all) struct EncTicketPart {
  flags : UInt32
  key : EncryptionKey
  crealm : String
  cname : PrincipalName
  transited : TransitedEncoding
  authtime : String
  starttime : String?
  endtime : String
  renew_till : String?
  caddr : Array[HostAddress]?
  authorization_data : Array[AuthorizationDataEntry]?
}

///|
pub impl Show for EncTicketPart with fn output(self, logger) {
  logger.write_string(
    "EncTicketPart(flags=\{self.flags}, key=\{self.key}, crealm=\{self.crealm}, cname=\{self.cname}, transited=\{self.transited}, authtime=\{self.authtime}, starttime=",
  )
  write_show_opt(self.starttime, logger)
  logger.write_string(", endtime=\{self.endtime}, renew_till=")
  write_show_opt(self.renew_till, logger)
  logger.write_string(", caddr=")
  write_show_opt_array(self.caddr, logger)
  logger.write_string(", authorization_data=")
  write_show_opt_array(self.authorization_data, logger)
  logger.write_string(")")
}

///|
pub fn EncTicketPart::to_der(
  self : EncTicketPart,
) -> @asn1.DerValue raise @asn1.DerError {
  let fields : Array[@asn1.DerValue] = [
    @asn1.context_field(0, @asn1.encode_kerberos_flags(self.flags)),
    @asn1.context_field(1, self.key.to_der()),
    @asn1.context_field(2, @asn1.encode_general_string(self.crealm)),
    @asn1.context_field(3, self.cname.to_der()),
    @asn1.context_field(4, self.transited.to_der()),
    @asn1.context_field(5, @asn1.encode_generalized_time(self.authtime)),
  ]
  match self.starttime {
    Some(t) =>
      fields.push(@asn1.context_field(6, @asn1.encode_generalized_time(t)))
    None => ()
  }
  fields.push(
    @asn1.context_field(7, @asn1.encode_generalized_time(self.endtime)),
  )
  match self.renew_till {
    Some(t) =>
      fields.push(@asn1.context_field(8, @asn1.encode_generalized_time(t)))
    None => ()
  }
  match self.caddr {
    Some(addrs) =>
      fields.push(@asn1.context_field(9, encode_host_addresses(addrs)))
    None => ()
  }
  match self.authorization_data {
    Some(ad) =>
      fields.push(@asn1.context_field(10, encode_authorization_data(ad)))
    None => ()
  }
  @asn1.DerValue::Application(
    @asn1.APP_ENC_TICKET_PART,
    @asn1.DerValue::Sequence(fields),
  )
}

///|
pub fn EncTicketPart::from_der(
  val : @asn1.DerValue,
) -> EncTicketPart raise @asn1.DerError {
  let inner = unwrap_app(val, @asn1.APP_ENC_TICKET_PART)
  let r = @asn1.SeqReader::new(inner)
  let flags = @asn1.decode_kerberos_flags(r.read_required(0))
  let key = EncryptionKey::from_der(r.read_required(1))
  let crealm = @asn1.decode_general_string(r.read_required(2))
  let cname = PrincipalName::from_der(r.read_required(3))
  let transited = TransitedEncoding::from_der(r.read_required(4))
  let authtime = @asn1.decode_generalized_time(r.read_required(5))
  let starttime = match r.read_optional(6) {
    Some(v) => Some(@asn1.decode_generalized_time(v))
    None => None
  }
  let endtime = @asn1.decode_generalized_time(r.read_required(7))
  let renew_till = match r.read_optional(8) {
    Some(v) => Some(@asn1.decode_generalized_time(v))
    None => None
  }
  let caddr = match r.read_optional(9) {
    Some(v) => Some(decode_host_addresses(v))
    None => None
  }
  let authorization_data = match r.read_optional(10) {
    Some(v) => Some(decode_authorization_data(v))
    None => None
  }
  r.finish()
  {
    flags,
    key,
    crealm,
    cname,
    transited,
    authtime,
    starttime,
    endtime,
    renew_till,
    caddr,
    authorization_data,
  }
}

///|
pub fn EncTicketPart::encode(
  self : EncTicketPart,
) -> Bytes raise @asn1.DerError {
  @asn1.encode_der(self.to_der())
}

///|
pub fn EncTicketPart::decode(
  data : Bytes,
) -> EncTicketPart raise @asn1.DerError {
  let inner = @asn1.decode_application(data, @asn1.APP_ENC_TICKET_PART)
  EncTicketPart::from_der(
    @asn1.DerValue::Application(@asn1.APP_ENC_TICKET_PART, inner),
  )
}

///|
/// RFC 4120 §5.4.1 `KDC-REQ-BODY ::= SEQUENCE`.
#derive(Eq, Debug)
pub(all) struct KdcReqBody {
  kdc_options : UInt32
  cname : PrincipalName?
  realm : String
  sname : PrincipalName?
  from : String?
  till : String
  rtime : String?
  nonce : UInt32
  etype : Array[Int32]
  addresses : Array[HostAddress]?
  enc_authorization_data : EncryptedData?
  additional_tickets : Array[Ticket]?
}

///|
pub impl Show for KdcReqBody with fn output(self, logger) {
  logger.write_string("KdcReqBody(kdc_options=\{self.kdc_options}, cname=")
  write_show_opt(self.cname, logger)
  logger.write_string(", realm=\{self.realm}, sname=")
  write_show_opt(self.sname, logger)
  logger.write_string(", from=")
  write_show_opt(self.from, logger)
  logger.write_string(", till=\{self.till}, rtime=")
  write_show_opt(self.rtime, logger)
  logger.write_string(", nonce=\{self.nonce}, etype=")
  write_show_array(self.etype, logger)
  logger.write_string(", addresses=")
  write_show_opt_array(self.addresses, logger)
  logger.write_string(", enc_authorization_data=")
  write_show_opt(self.enc_authorization_data, logger)
  logger.write_string(", additional_tickets=")
  write_show_opt_array(self.additional_tickets, logger)
  logger.write_string(")")
}

///|
pub fn KdcReqBody::to_der(
  self : KdcReqBody,
) -> @asn1.DerValue raise @asn1.DerError {
  let fields : Array[@asn1.DerValue] = [
    @asn1.context_field(0, @asn1.encode_kerberos_flags(self.kdc_options)),
  ]
  match self.cname {
    Some(c) => fields.push(@asn1.context_field(1, c.to_der()))
    None => ()
  }
  fields.push(@asn1.context_field(2, @asn1.encode_general_string(self.realm)))
  match self.sname {
    Some(s) => fields.push(@asn1.context_field(3, s.to_der()))
    None => ()
  }
  match self.from {
    Some(t) =>
      fields.push(@asn1.context_field(4, @asn1.encode_generalized_time(t)))
    None => ()
  }
  fields.push(@asn1.context_field(5, @asn1.encode_generalized_time(self.till)))
  match self.rtime {
    Some(t) =>
      fields.push(@asn1.context_field(6, @asn1.encode_generalized_time(t)))
    None => ()
  }
  fields.push(@asn1.context_field(7, @asn1.encode_uint32(self.nonce)))
  let etypes : Array[@asn1.DerValue] = []
  for et in self.etype {
    etypes.push(@asn1.encode_int(et))
  }
  fields.push(@asn1.context_field(8, @asn1.DerValue::Sequence(etypes)))
  match self.addresses {
    Some(addrs) =>
      fields.push(@asn1.context_field(9, encode_host_addresses(addrs)))
    None => ()
  }
  match self.enc_authorization_data {
    Some(ead) => fields.push(@asn1.context_field(10, ead.to_der()))
    None => ()
  }
  match self.additional_tickets {
    Some(tkts) => {
      let tkt_vals : Array[@asn1.DerValue] = []
      for t in tkts {
        tkt_vals.push(t.to_der())
      }
      fields.push(@asn1.context_field(11, @asn1.DerValue::Sequence(tkt_vals)))
    }
    None => ()
  }
  @asn1.DerValue::Sequence(fields)
}

///|
pub fn KdcReqBody::from_der(
  val : @asn1.DerValue,
) -> KdcReqBody raise @asn1.DerError {
  let r = @asn1.SeqReader::new(val)
  let kdc_options = @asn1.decode_kerberos_flags(r.read_required(0))
  let cname = match r.read_optional(1) {
    Some(v) => Some(PrincipalName::from_der(v))
    None => None
  }
  let realm = @asn1.decode_general_string(r.read_required(2))
  let sname = match r.read_optional(3) {
    Some(v) => Some(PrincipalName::from_der(v))
    None => None
  }
  let from = match r.read_optional(4) {
    Some(v) => Some(@asn1.decode_generalized_time(v))
    None => None
  }
  let till = @asn1.decode_generalized_time(r.read_required(5))
  let rtime = match r.read_optional(6) {
    Some(v) => Some(@asn1.decode_generalized_time(v))
    None => None
  }
  let nonce = @asn1.decode_uint32(r.read_required(7))
  let etype_items = expect_sequence(r.read_required(8))
  let etype : Array[Int32] = []
  for item in etype_items {
    etype.push(@asn1.decode_int(item))
  }
  let addresses = match r.read_optional(9) {
    Some(v) => Some(decode_host_addresses(v))
    None => None
  }
  let enc_authorization_data = match r.read_optional(10) {
    Some(v) => Some(EncryptedData::from_der(v))
    None => None
  }
  let additional_tickets = match r.read_optional(11) {
    Some(v) => {
      let items = expect_sequence(v)
      let out : Array[Ticket] = []
      for item in items {
        out.push(Ticket::from_der(item))
      }
      Some(out)
    }
    None => None
  }
  r.finish()
  {
    kdc_options,
    cname,
    realm,
    sname,
    from,
    till,
    rtime,
    nonce,
    etype,
    addresses,
    enc_authorization_data,
    additional_tickets,
  }
}

///|
pub fn KdcReqBody::encode(self : KdcReqBody) -> Bytes raise @asn1.DerError {
  @asn1.encode_der(self.to_der())
}

///|
pub fn KdcReqBody::decode(data : Bytes) -> KdcReqBody raise @asn1.DerError {
  KdcReqBody::from_der(@asn1.decode_der(data))
}

///|
/// RFC 4120 §5.4.1 `KDC-REQ` (used by `AS-REQ [APPLICATION 10]` and `TGS-REQ [APPLICATION 12]`).
/// Note: context tags start at `[1]`, not `[0]`.
#derive(Eq, Debug)
pub(all) struct KdcReq {
  pvno : Int32
  msg_type : Int32
  padata : Array[PaData]?
  req_body : KdcReqBody
}

///|
pub impl Show for KdcReq with fn output(self, logger) {
  logger.write_string(
    "KdcReq(pvno=\{self.pvno}, msg_type=\{self.msg_type}, padata=",
  )
  write_show_opt_array(self.padata, logger)
  logger.write_string(", req_body=\{self.req_body})")
}

///|
fn encode_kdc_req(
  req : KdcReq,
  expected_msg_type : Int32,
  app_tag : Int32,
) -> Bytes raise @asn1.DerError {
  validate_pvno(req.pvno, "pvno")
  validate_msg_type(req.msg_type, expected_msg_type)
  let fields : Array[@asn1.DerValue] = [
    @asn1.context_field(1, @asn1.encode_int(req.pvno)),
    @asn1.context_field(2, @asn1.encode_int(req.msg_type)),
  ]
  match req.padata {
    Some(pa) => fields.push(@asn1.context_field(3, encode_padata_seq(pa)))
    None => ()
  }
  fields.push(@asn1.context_field(4, req.req_body.to_der()))
  @asn1.encode_application(app_tag, @asn1.DerValue::Sequence(fields))
}

///|
fn decode_kdc_req(
  data : Bytes,
  expected_msg_type : Int32,
  app_tag : Int32,
) -> KdcReq raise @asn1.DerError {
  let inner = @asn1.decode_application(data, app_tag)
  let r = @asn1.SeqReader::new(inner)
  let pvno = @asn1.decode_int(r.read_required(1))
  validate_pvno(pvno, "pvno")
  let msg_type = @asn1.decode_int(r.read_required(2))
  validate_msg_type(msg_type, expected_msg_type)
  let padata = match r.read_optional(3) {
    Some(v) => Some(decode_padata_seq(v))
    None => None
  }
  let req_body = KdcReqBody::from_der(r.read_required(4))
  r.finish()
  { pvno, msg_type, padata, req_body, }
}

///|
pub fn KdcReq::encode_as_req(self : KdcReq) -> Bytes raise @asn1.DerError {
  encode_kdc_req(self, MSG_AS_REQ, @asn1.APP_AS_REQ)
}

///|
pub fn KdcReq::decode_as_req(data : Bytes) -> KdcReq raise @asn1.DerError {
  decode_kdc_req(data, MSG_AS_REQ, @asn1.APP_AS_REQ)
}

///|
pub fn KdcReq::encode_tgs_req(self : KdcReq) -> Bytes raise @asn1.DerError {
  encode_kdc_req(self, MSG_TGS_REQ, @asn1.APP_TGS_REQ)
}

///|
fn read_raw_tlv_header(
  data : Bytes,
  pos : Int32,
  end : Int32,
) -> (Int32, Bool, Int32, Int32, Int32) raise @asn1.DerError {
  if pos >= end {
    raise @asn1.DerError::UnexpectedEof
  }
  let b0 = data[pos].to_int()
  let class_bits = (b0 >> 6) & 0x03
  let constructed = (b0 & 0x20) != 0
  let low = b0 & 0x1F
  let mut cur = pos + 1
  let tag_num = if low < 31 {
    low
  } else {
    if cur >= end {
      raise @asn1.DerError::UnexpectedEof
    }
    let mut num = 0
    while true {
      if cur >= end {
        raise @asn1.DerError::UnexpectedEof
      }
      let b = data[cur].to_int()
      cur += 1
      if num > 0x00FF_FFFF {
        raise @asn1.DerError::InvalidTag("high tag number overflow")
      }
      num = (num << 7) | (b & 0x7F)
      if (b & 0x80) == 0 {
        break
      }
    }
    num
  }
  if cur >= end {
    raise @asn1.DerError::UnexpectedEof
  }
  let l0 = data[cur].to_int()
  cur += 1
  let len = if l0 < 0x80 {
    l0
  } else if l0 == 0x80 {
    raise @asn1.DerError::IndefiniteLength
  } else {
    let num_octets = l0 & 0x7F
    if num_octets == 0 || num_octets > 4 || num_octets > end - cur {
      raise @asn1.DerError::InvalidLength("invalid DER length encoding")
    }
    let mut v = 0
    for i = 0; i < num_octets; i = i + 1 {
      let b = data[cur + i].to_int()
      if i == 0 && num_octets == 4 && (b & 0x80) != 0 {
        raise @asn1.DerError::InvalidLength(
          "length overflows signed 32-bit Int",
        )
      }
      v = (v << 8) | b
    }
    cur += num_octets
    v
  }
  if len > end - cur {
    raise @asn1.DerError::UnexpectedEof
  }
  (class_bits, constructed, tag_num, cur, cur + len)
}

///|
fn extract_kdc_req_raw_body(
  data : Bytes,
  app_tag : Int32,
) -> Bytes raise @asn1.DerError {
  let total = data.length()
  let (c1, cons1, t1, app_start, app_end) = read_raw_tlv_header(data, 0, total)
  if c1 != 1 || !cons1 || t1 != app_tag || app_end != total {
    raise @asn1.DerError::TagMismatch(
      expected="APPLICATION[\{app_tag}]",
      got="class=\{c1} tag=\{t1}",
    )
  }
  let (c2, cons2, t2, seq_start, seq_end) = read_raw_tlv_header(
    data, app_start, app_end,
  )
  if c2 != 0 || !cons2 || t2 != 16 || seq_end != app_end {
    raise @asn1.DerError::TagMismatch(
      expected="SEQUENCE",
      got="class=\{c2} tag=\{t2}",
    )
  }
  let mut cur = seq_start
  while cur < seq_end {
    let (cf, consf, tf, vstart, vend) = read_raw_tlv_header(data, cur, seq_end)
    if cf == 2 && consf && tf == 4 {
      return Bytes::makei(vend - vstart, fn(i) { data[vstart + i] })
    }
    cur = vend
  }
  raise @asn1.DerError::MissingField("context[4]")
}

///|
pub fn KdcReq::decode_tgs_req(data : Bytes) -> KdcReq raise @asn1.DerError {
  decode_kdc_req(data, MSG_TGS_REQ, @asn1.APP_TGS_REQ)
}

///|
/// Decode a `TGS-REQ` (`[APPLICATION 12]`) while also returning the exact raw
/// on-the-wire DER bytes of `[4] KDC-REQ-BODY` (unwrapped from the `[4]` tag)
/// for RFC 4120 §5.4.1 `Authenticator.cksum` verification.
pub fn KdcReq::decode_tgs_req_with_raw_body(
  data : Bytes,
) -> (KdcReq, Bytes) raise @asn1.DerError {
  let req = decode_kdc_req(data, MSG_TGS_REQ, @asn1.APP_TGS_REQ)
  let raw_body = extract_kdc_req_raw_body(data, @asn1.APP_TGS_REQ)
  (req, raw_body)
}

///|
/// RFC 4120 §5.4.2 `KDC-REP` (used by `AS-REP [APPLICATION 11]` and `TGS-REP [APPLICATION 13]`).
#derive(Eq, Debug)
pub(all) struct KdcRep {
  pvno : Int32
  msg_type : Int32
  padata : Array[PaData]?
  crealm : String
  cname : PrincipalName
  ticket : Ticket
  enc_part : EncryptedData
}

///|
pub impl Show for KdcRep with fn output(self, logger) {
  logger.write_string(
    "KdcRep(pvno=\{self.pvno}, msg_type=\{self.msg_type}, padata=",
  )
  write_show_opt_array(self.padata, logger)
  logger.write_string(
    ", crealm=\{self.crealm}, cname=\{self.cname}, ticket=\{self.ticket}, enc_part=\{self.enc_part})",
  )
}

///|
fn encode_kdc_rep(
  rep : KdcRep,
  expected_msg_type : Int32,
  app_tag : Int32,
) -> Bytes raise @asn1.DerError {
  validate_pvno(rep.pvno, "pvno")
  validate_msg_type(rep.msg_type, expected_msg_type)
  let fields : Array[@asn1.DerValue] = [
    @asn1.context_field(0, @asn1.encode_int(rep.pvno)),
    @asn1.context_field(1, @asn1.encode_int(rep.msg_type)),
  ]
  match rep.padata {
    Some(pa) => fields.push(@asn1.context_field(2, encode_padata_seq(pa)))
    None => ()
  }
  fields.push(@asn1.context_field(3, @asn1.encode_general_string(rep.crealm)))
  fields.push(@asn1.context_field(4, rep.cname.to_der()))
  fields.push(@asn1.context_field(5, rep.ticket.to_der()))
  fields.push(@asn1.context_field(6, rep.enc_part.to_der()))
  @asn1.encode_application(app_tag, @asn1.DerValue::Sequence(fields))
}

///|
fn decode_kdc_rep(
  data : Bytes,
  expected_msg_type : Int32,
  app_tag : Int32,
) -> KdcRep raise @asn1.DerError {
  let inner = @asn1.decode_application(data, app_tag)
  let r = @asn1.SeqReader::new(inner)
  let pvno = @asn1.decode_int(r.read_required(0))
  validate_pvno(pvno, "pvno")
  let msg_type = @asn1.decode_int(r.read_required(1))
  validate_msg_type(msg_type, expected_msg_type)
  let padata = match r.read_optional(2) {
    Some(v) => Some(decode_padata_seq(v))
    None => None
  }
  let crealm = @asn1.decode_general_string(r.read_required(3))
  let cname = PrincipalName::from_der(r.read_required(4))
  let ticket = Ticket::from_der(r.read_required(5))
  let enc_part = EncryptedData::from_der(r.read_required(6))
  r.finish()
  { pvno, msg_type, padata, crealm, cname, ticket, enc_part, }
}

///|
pub fn KdcRep::encode_as_rep(self : KdcRep) -> Bytes raise @asn1.DerError {
  encode_kdc_rep(self, MSG_AS_REP, @asn1.APP_AS_REP)
}

///|
pub fn KdcRep::decode_as_rep(data : Bytes) -> KdcRep raise @asn1.DerError {
  decode_kdc_rep(data, MSG_AS_REP, @asn1.APP_AS_REP)
}

///|
pub fn KdcRep::encode_tgs_rep(self : KdcRep) -> Bytes raise @asn1.DerError {
  encode_kdc_rep(self, MSG_TGS_REP, @asn1.APP_TGS_REP)
}

///|
pub fn KdcRep::decode_tgs_rep(data : Bytes) -> KdcRep raise @asn1.DerError {
  decode_kdc_rep(data, MSG_TGS_REP, @asn1.APP_TGS_REP)
}

///|
/// RFC 4120 §5.4.2 `EncKDCRepPart` (used by `EncASRepPart [APPLICATION 25]` and `EncTGSRepPart [APPLICATION 26]`).
#derive(Eq, Debug)
pub(all) struct EncKdcRepPart {
  key : EncryptionKey
  last_req : Array[LastReqEntry]
  nonce : UInt32
  key_expiration : String?
  flags : UInt32
  authtime : String
  starttime : String?
  endtime : String
  renew_till : String?
  srealm : String
  sname : PrincipalName
  caddr : Array[HostAddress]?
}

///|
pub impl Show for EncKdcRepPart with fn output(self, logger) {
  logger.write_string("EncKdcRepPart(key=\{self.key}, last_req=")
  write_show_array(self.last_req, logger)
  logger.write_string(", nonce=\{self.nonce}, key_expiration=")
  write_show_opt(self.key_expiration, logger)
  logger.write_string(
    ", flags=\{self.flags}, authtime=\{self.authtime}, starttime=",
  )
  write_show_opt(self.starttime, logger)
  logger.write_string(", endtime=\{self.endtime}, renew_till=")
  write_show_opt(self.renew_till, logger)
  logger.write_string(", srealm=\{self.srealm}, sname=\{self.sname}, caddr=")
  write_show_opt_array(self.caddr, logger)
  logger.write_string(")")
}

///|
fn encode_enc_kdc_rep_part(
  part : EncKdcRepPart,
  app_tag : Int32,
) -> Bytes raise @asn1.DerError {
  let lr_items : Array[@asn1.DerValue] = []
  for lr in part.last_req {
    lr_items.push(lr.to_der())
  }
  let fields : Array[@asn1.DerValue] = [
    @asn1.context_field(0, part.key.to_der()),
    @asn1.context_field(1, @asn1.DerValue::Sequence(lr_items)),
    @asn1.context_field(2, @asn1.encode_uint32(part.nonce)),
  ]
  match part.key_expiration {
    Some(t) =>
      fields.push(@asn1.context_field(3, @asn1.encode_generalized_time(t)))
    None => ()
  }
  fields.push(@asn1.context_field(4, @asn1.encode_kerberos_flags(part.flags)))
  fields.push(
    @asn1.context_field(5, @asn1.encode_generalized_time(part.authtime)),
  )
  match part.starttime {
    Some(t) =>
      fields.push(@asn1.context_field(6, @asn1.encode_generalized_time(t)))
    None => ()
  }
  fields.push(
    @asn1.context_field(7, @asn1.encode_generalized_time(part.endtime)),
  )
  match part.renew_till {
    Some(t) =>
      fields.push(@asn1.context_field(8, @asn1.encode_generalized_time(t)))
    None => ()
  }
  fields.push(@asn1.context_field(9, @asn1.encode_general_string(part.srealm)))
  fields.push(@asn1.context_field(10, part.sname.to_der()))
  match part.caddr {
    Some(addrs) =>
      fields.push(@asn1.context_field(11, encode_host_addresses(addrs)))
    None => ()
  }
  @asn1.encode_application(app_tag, @asn1.DerValue::Sequence(fields))
}

///|
fn decode_enc_kdc_rep_part(
  data : Bytes,
  app_tag : Int32,
) -> EncKdcRepPart raise @asn1.DerError {
  let inner = @asn1.decode_application(data, app_tag)
  let r = @asn1.SeqReader::new(inner)
  let key = EncryptionKey::from_der(r.read_required(0))
  let lr_items = expect_sequence(r.read_required(1))
  let last_req : Array[LastReqEntry] = []
  for item in lr_items {
    last_req.push(LastReqEntry::from_der(item))
  }
  let nonce = @asn1.decode_uint32(r.read_required(2))
  let key_expiration = match r.read_optional(3) {
    Some(v) => Some(@asn1.decode_generalized_time(v))
    None => None
  }
  let flags = @asn1.decode_kerberos_flags(r.read_required(4))
  let authtime = @asn1.decode_generalized_time(r.read_required(5))
  let starttime = match r.read_optional(6) {
    Some(v) => Some(@asn1.decode_generalized_time(v))
    None => None
  }
  let endtime = @asn1.decode_generalized_time(r.read_required(7))
  let renew_till = match r.read_optional(8) {
    Some(v) => Some(@asn1.decode_generalized_time(v))
    None => None
  }
  let srealm = @asn1.decode_general_string(r.read_required(9))
  let sname = PrincipalName::from_der(r.read_required(10))
  let caddr = match r.read_optional(11) {
    Some(v) => Some(decode_host_addresses(v))
    None => None
  }
  r.finish()
  {
    key,
    last_req,
    nonce,
    key_expiration,
    flags,
    authtime,
    starttime,
    endtime,
    renew_till,
    srealm,
    sname,
    caddr,
  }
}

///|
pub fn EncKdcRepPart::encode_enc_as_rep_part(
  self : EncKdcRepPart,
) -> Bytes raise @asn1.DerError {
  encode_enc_kdc_rep_part(self, @asn1.APP_ENC_AS_REP_PART)
}

///|
pub fn EncKdcRepPart::decode_enc_as_rep_part(
  data : Bytes,
) -> EncKdcRepPart raise @asn1.DerError {
  decode_enc_kdc_rep_part(data, @asn1.APP_ENC_AS_REP_PART)
}

///|
pub fn EncKdcRepPart::encode_enc_tgs_rep_part(
  self : EncKdcRepPart,
) -> Bytes raise @asn1.DerError {
  encode_enc_kdc_rep_part(self, @asn1.APP_ENC_TGS_REP_PART)
}

///|
pub fn EncKdcRepPart::decode_enc_tgs_rep_part(
  data : Bytes,
) -> EncKdcRepPart raise @asn1.DerError {
  decode_enc_kdc_rep_part(data, @asn1.APP_ENC_TGS_REP_PART)
}

///|
/// RFC 4120 §5.5.1 `AP-REQ ::= [APPLICATION 14] SEQUENCE`.
#derive(Eq, Debug)
pub(all) struct ApReq {
  pvno : Int32
  msg_type : Int32
  ap_options : UInt32
  ticket : Ticket
  authenticator : EncryptedData
}

///|
pub impl Show for ApReq with fn output(self, logger) {
  logger.write_string(
    "ApReq(pvno=\{self.pvno}, msg_type=\{self.msg_type}, ap_options=\{self.ap_options}, ticket=\{self.ticket}, authenticator=\{self.authenticator})",
  )
}

///|
pub fn ApReq::to_der(self : ApReq) -> @asn1.DerValue raise @asn1.DerError {
  validate_pvno(self.pvno, "pvno")
  validate_msg_type(self.msg_type, MSG_AP_REQ)
  @asn1.DerValue::Application(
    @asn1.APP_AP_REQ,
    @asn1.DerValue::Sequence([
      @asn1.context_field(0, @asn1.encode_int(self.pvno)),
      @asn1.context_field(1, @asn1.encode_int(self.msg_type)),
      @asn1.context_field(2, @asn1.encode_kerberos_flags(self.ap_options)),
      @asn1.context_field(3, self.ticket.to_der()),
      @asn1.context_field(4, self.authenticator.to_der()),
    ]),
  )
}

///|
pub fn ApReq::from_der(val : @asn1.DerValue) -> ApReq raise @asn1.DerError {
  let inner = unwrap_app(val, @asn1.APP_AP_REQ)
  let r = @asn1.SeqReader::new(inner)
  let pvno = @asn1.decode_int(r.read_required(0))
  validate_pvno(pvno, "pvno")
  let msg_type = @asn1.decode_int(r.read_required(1))
  validate_msg_type(msg_type, MSG_AP_REQ)
  let ap_options = @asn1.decode_kerberos_flags(r.read_required(2))
  let ticket = Ticket::from_der(r.read_required(3))
  let authenticator = EncryptedData::from_der(r.read_required(4))
  r.finish()
  { pvno, msg_type, ap_options, ticket, authenticator, }
}

///|
pub fn ApReq::encode(self : ApReq) -> Bytes raise @asn1.DerError {
  @asn1.encode_der(self.to_der())
}

///|
pub fn ApReq::decode(data : Bytes) -> ApReq raise @asn1.DerError {
  let inner = @asn1.decode_application(data, @asn1.APP_AP_REQ)
  ApReq::from_der(@asn1.DerValue::Application(@asn1.APP_AP_REQ, inner))
}

///|
/// RFC 4120 §5.5.2 `AP-REP ::= [APPLICATION 15] SEQUENCE`.
#derive(Eq, Debug)
pub(all) struct ApRep {
  pvno : Int32
  msg_type : Int32
  enc_part : EncryptedData
}

///|
pub impl Show for ApRep with fn output(self, logger) {
  logger.write_string(
    "ApRep(pvno=\{self.pvno}, msg_type=\{self.msg_type}, enc_part=\{self.enc_part})",
  )
}

///|
pub fn ApRep::to_der(self : ApRep) -> @asn1.DerValue raise @asn1.DerError {
  validate_pvno(self.pvno, "pvno")
  validate_msg_type(self.msg_type, MSG_AP_REP)
  @asn1.DerValue::Application(
    @asn1.APP_AP_REP,
    @asn1.DerValue::Sequence([
      @asn1.context_field(0, @asn1.encode_int(self.pvno)),
      @asn1.context_field(1, @asn1.encode_int(self.msg_type)),
      @asn1.context_field(2, self.enc_part.to_der()),
    ]),
  )
}

///|
pub fn ApRep::from_der(val : @asn1.DerValue) -> ApRep raise @asn1.DerError {
  let inner = unwrap_app(val, @asn1.APP_AP_REP)
  let r = @asn1.SeqReader::new(inner)
  let pvno = @asn1.decode_int(r.read_required(0))
  validate_pvno(pvno, "pvno")
  let msg_type = @asn1.decode_int(r.read_required(1))
  validate_msg_type(msg_type, MSG_AP_REP)
  let enc_part = EncryptedData::from_der(r.read_required(2))
  r.finish()
  { pvno, msg_type, enc_part, }
}

///|
pub fn ApRep::encode(self : ApRep) -> Bytes raise @asn1.DerError {
  @asn1.encode_der(self.to_der())
}

///|
pub fn ApRep::decode(data : Bytes) -> ApRep raise @asn1.DerError {
  let inner = @asn1.decode_application(data, @asn1.APP_AP_REP)
  ApRep::from_der(@asn1.DerValue::Application(@asn1.APP_AP_REP, inner))
}

///|
/// RFC 4120 §5.5.2 `EncAPRepPart ::= [APPLICATION 27] SEQUENCE`.
#derive(Eq, Debug)
pub(all) struct EncApRepPart {
  ctime : String
  cusec : Int32
  subkey : EncryptionKey?
  seq_number : UInt32?
}

///|
pub impl Show for EncApRepPart with fn output(self, logger) {
  logger.write_string(
    "EncApRepPart(ctime=\{self.ctime}, cusec=\{self.cusec}, subkey=",
  )
  write_show_opt(self.subkey, logger)
  logger.write_string(", seq_number=")
  write_show_opt(self.seq_number, logger)
  logger.write_string(")")
}

///|
pub fn EncApRepPart::to_der(
  self : EncApRepPart,
) -> @asn1.DerValue raise @asn1.DerError {
  validate_microseconds(self.cusec)
  let fields : Array[@asn1.DerValue] = [
    @asn1.context_field(0, @asn1.encode_generalized_time(self.ctime)),
    @asn1.context_field(1, @asn1.encode_int(self.cusec)),
  ]
  match self.subkey {
    Some(k) => fields.push(@asn1.context_field(2, k.to_der()))
    None => ()
  }
  match self.seq_number {
    Some(s) => fields.push(@asn1.context_field(3, @asn1.encode_uint32(s)))
    None => ()
  }
  @asn1.DerValue::Application(
    @asn1.APP_ENC_AP_REP_PART,
    @asn1.DerValue::Sequence(fields),
  )
}

///|
pub fn EncApRepPart::from_der(
  val : @asn1.DerValue,
) -> EncApRepPart raise @asn1.DerError {
  let inner = unwrap_app(val, @asn1.APP_ENC_AP_REP_PART)
  let r = @asn1.SeqReader::new(inner)
  let ctime = @asn1.decode_generalized_time(r.read_required(0))
  let cusec = @asn1.decode_int(r.read_required(1))
  validate_microseconds(cusec)
  let subkey = match r.read_optional(2) {
    Some(v) => Some(EncryptionKey::from_der(v))
    None => None
  }
  let seq_number = match r.read_optional(3) {
    Some(v) => Some(@asn1.decode_uint32(v))
    None => None
  }
  r.finish()
  { ctime, cusec, subkey, seq_number, }
}

///|
pub fn EncApRepPart::encode(self : EncApRepPart) -> Bytes raise @asn1.DerError {
  @asn1.encode_der(self.to_der())
}

///|
pub fn EncApRepPart::decode(data : Bytes) -> EncApRepPart raise @asn1.DerError {
  let inner = @asn1.decode_application(data, @asn1.APP_ENC_AP_REP_PART)
  EncApRepPart::from_der(
    @asn1.DerValue::Application(@asn1.APP_ENC_AP_REP_PART, inner),
  )
}

///|
/// RFC 4120 §5.9.1 `KRB-ERROR ::= [APPLICATION 30] SEQUENCE`.
#derive(Eq, Debug)
pub(all) struct KrbError {
  pvno : Int32
  msg_type : Int32
  ctime : String?
  cusec : Int32?
  stime : String
  susec : Int32
  error_code : Int32
  crealm : String?
  cname : PrincipalName?
  realm : String
  sname : PrincipalName
  e_text : String?
  e_data : Bytes?
}

///|
pub impl Show for KrbError with fn output(self, logger) {
  logger.write_string(
    "KrbError(pvno=\{self.pvno}, msg_type=\{self.msg_type}, ctime=",
  )
  write_show_opt(self.ctime, logger)
  logger.write_string(", cusec=")
  write_show_opt(self.cusec, logger)
  logger.write_string(
    ", stime=\{self.stime}, susec=\{self.susec}, error_code=\{self.error_code}, crealm=",
  )
  write_show_opt(self.crealm, logger)
  logger.write_string(", cname=")
  write_show_opt(self.cname, logger)
  logger.write_string(", realm=\{self.realm}, sname=\{self.sname}, e_text=")
  write_show_opt(self.e_text, logger)
  logger.write_string(", e_data=")
  match self.e_data {
    None => logger.write_string("None")
    Some(b) => logger.write_string("Some(\{@asn1.hex_encode(b)})")
  }
  logger.write_string(")")
}

///|
pub fn KrbError::to_der(self : KrbError) -> @asn1.DerValue raise @asn1.DerError {
  validate_pvno(self.pvno, "pvno")
  validate_msg_type(self.msg_type, MSG_KRB_ERROR)
  validate_microseconds(self.susec)
  let fields : Array[@asn1.DerValue] = [
    @asn1.context_field(0, @asn1.encode_int(self.pvno)),
    @asn1.context_field(1, @asn1.encode_int(self.msg_type)),
  ]
  match self.ctime {
    Some(t) =>
      fields.push(@asn1.context_field(2, @asn1.encode_generalized_time(t)))
    None => ()
  }
  match self.cusec {
    Some(us) => {
      validate_microseconds(us)
      fields.push(@asn1.context_field(3, @asn1.encode_int(us)))
    }
    None => ()
  }
  fields.push(@asn1.context_field(4, @asn1.encode_generalized_time(self.stime)))
  fields.push(@asn1.context_field(5, @asn1.encode_int(self.susec)))
  fields.push(@asn1.context_field(6, @asn1.encode_int(self.error_code)))
  match self.crealm {
    Some(cr) =>
      fields.push(@asn1.context_field(7, @asn1.encode_general_string(cr)))
    None => ()
  }
  match self.cname {
    Some(cn) => fields.push(@asn1.context_field(8, cn.to_der()))
    None => ()
  }
  fields.push(@asn1.context_field(9, @asn1.encode_general_string(self.realm)))
  fields.push(@asn1.context_field(10, self.sname.to_der()))
  match self.e_text {
    Some(et) =>
      fields.push(@asn1.context_field(11, @asn1.encode_general_string(et)))
    None => ()
  }
  match self.e_data {
    Some(ed) =>
      fields.push(@asn1.context_field(12, @asn1.encode_octet_string(ed)))
    None => ()
  }
  @asn1.DerValue::Application(
    @asn1.APP_KRB_ERROR,
    @asn1.DerValue::Sequence(fields),
  )
}

///|
pub fn KrbError::from_der(
  val : @asn1.DerValue,
) -> KrbError raise @asn1.DerError {
  let inner = unwrap_app(val, @asn1.APP_KRB_ERROR)
  let r = @asn1.SeqReader::new(inner)
  let pvno = @asn1.decode_int(r.read_required(0))
  validate_pvno(pvno, "pvno")
  let msg_type = @asn1.decode_int(r.read_required(1))
  validate_msg_type(msg_type, MSG_KRB_ERROR)
  let ctime = match r.read_optional(2) {
    Some(v) => Some(@asn1.decode_generalized_time(v))
    None => None
  }
  let cusec = match r.read_optional(3) {
    Some(v) => {
      let us = @asn1.decode_int(v)
      validate_microseconds(us)
      Some(us)
    }
    None => None
  }
  let stime = @asn1.decode_generalized_time(r.read_required(4))
  let susec = @asn1.decode_int(r.read_required(5))
  validate_microseconds(susec)
  let error_code = @asn1.decode_int(r.read_required(6))
  let crealm = match r.read_optional(7) {
    Some(v) => Some(@asn1.decode_general_string(v))
    None => None
  }
  let cname = match r.read_optional(8) {
    Some(v) => Some(PrincipalName::from_der(v))
    None => None
  }
  let realm = @asn1.decode_general_string(r.read_required(9))
  let sname = PrincipalName::from_der(r.read_required(10))
  let e_text = match r.read_optional(11) {
    Some(v) => Some(@asn1.decode_general_string(v))
    None => None
  }
  let e_data = match r.read_optional(12) {
    Some(v) => Some(@asn1.decode_octet_string(v))
    None => None
  }
  r.finish()
  {
    pvno,
    msg_type,
    ctime,
    cusec,
    stime,
    susec,
    error_code,
    crealm,
    cname,
    realm,
    sname,
    e_text,
    e_data,
  }
}

///|
pub fn KrbError::encode(self : KrbError) -> Bytes raise @asn1.DerError {
  @asn1.encode_der(self.to_der())
}

///|
pub fn KrbError::decode(data : Bytes) -> KrbError raise @asn1.DerError {
  let inner = @asn1.decode_application(data, @asn1.APP_KRB_ERROR)
  KrbError::from_der(@asn1.DerValue::Application(@asn1.APP_KRB_ERROR, inner))
}
