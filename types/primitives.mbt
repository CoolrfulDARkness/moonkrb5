///|
fn validate_microseconds(v : Int32) -> Unit raise @asn1.DerError {
  if v < 0 || v > 999999 {
    raise @asn1.DerError::InvalidValue(
      "Microseconds out of range 0..999999: \{v}",
    )
  }
}

///|
fn expect_sequence(
  val : @asn1.DerValue,
) -> Array[@asn1.DerValue] raise @asn1.DerError {
  match val {
    Sequence(items) => items
    other =>
      raise @asn1.DerError::TagMismatch(expected="SEQUENCE", got="\{other}")
  }
}

///|
fn[T : Show] write_show_array(items : Array[T], logger : &Logger) -> Unit {
  logger.write_string("[")
  for i = 0; i < items.length(); i = i + 1 {
    if i > 0 {
      logger.write_string(", ")
    }
    Show::output(items[i], logger)
  }
  logger.write_string("]")
}

///|
fn[T : Show] write_show_opt(opt : T?, logger : &Logger) -> Unit {
  match opt {
    None => logger.write_string("None")
    Some(v) => {
      logger.write_string("Some(")
      Show::output(v, logger)
      logger.write_string(")")
    }
  }
}

///|
fn[T : Show] write_show_opt_array(opt : Array[T]?, logger : &Logger) -> Unit {
  match opt {
    None => logger.write_string("None")
    Some(arr) => {
      logger.write_string("Some(")
      write_show_array(arr, logger)
      logger.write_string(")")
    }
  }
}

///|
/// RFC 4120 §5.2.2 `PrincipalName`.
#derive(Eq, Debug)
pub(all) struct PrincipalName {
  name_type : Int32
  name_string : Array[String]
}

///|
pub fn PrincipalName::new(
  name_type : Int32,
  name_string : Array[String],
) -> PrincipalName {
  { name_type, name_string, }
}

///|
pub fn PrincipalName::user(name : String) -> PrincipalName {
  { name_type: NT_PRINCIPAL, name_string: [name], }
}

///|
pub fn PrincipalName::service(svc : String, host : String) -> PrincipalName {
  { name_type: NT_SRV_INST, name_string: [svc, host], }
}

///|
pub fn PrincipalName::to_display(self : PrincipalName) -> String {
  let sb = StringBuilder()
  for i = 0; i < self.name_string.length(); i = i + 1 {
    if i > 0 {
      sb.write_char('/')
    }
    sb.write_string(self.name_string[i])
  }
  sb.to_string()
}

///|
pub impl Show for PrincipalName with fn output(self, logger) {
  logger.write_string(
    "PrincipalName(type=\{self.name_type}, name=\{self.to_display()})",
  )
}

///|
pub fn PrincipalName::to_der(self : PrincipalName) -> @asn1.DerValue {
  let names : Array[@asn1.DerValue] = []
  for s in self.name_string {
    names.push(@asn1.encode_general_string(s))
  }
  @asn1.DerValue::Sequence([
    @asn1.context_field(0, @asn1.encode_int(self.name_type)),
    @asn1.context_field(1, @asn1.DerValue::Sequence(names)),
  ])
}

///|
pub fn PrincipalName::from_der(
  val : @asn1.DerValue,
) -> PrincipalName raise @asn1.DerError {
  let r = @asn1.SeqReader::new(val)
  let name_type = @asn1.decode_int(r.read_required(0))
  let name_items = expect_sequence(r.read_required(1))
  let name_string : Array[String] = []
  for item in name_items {
    name_string.push(@asn1.decode_general_string(item))
  }
  r.finish()
  { name_type, name_string, }
}

///|
/// RFC 4120 §5.2.5 `HostAddress`.
#derive(Eq, Debug)
pub(all) struct HostAddress {
  addr_type : Int32
  address : Bytes
}

///|
pub impl Show for HostAddress with fn output(self, logger) {
  logger.write_string(
    "HostAddress(type=\{self.addr_type}, addr=\{@asn1.hex_encode(self.address)})",
  )
}

///|
pub fn HostAddress::to_der(self : HostAddress) -> @asn1.DerValue {
  @asn1.DerValue::Sequence([
    @asn1.context_field(0, @asn1.encode_int(self.addr_type)),
    @asn1.context_field(1, @asn1.encode_octet_string(self.address)),
  ])
}

///|
pub fn HostAddress::from_der(
  val : @asn1.DerValue,
) -> HostAddress raise @asn1.DerError {
  let r = @asn1.SeqReader::new(val)
  let addr_type = @asn1.decode_int(r.read_required(0))
  let address = @asn1.decode_octet_string(r.read_required(1))
  r.finish()
  { addr_type, address, }
}

///|
fn encode_host_addresses(addrs : Array[HostAddress]) -> @asn1.DerValue {
  let items : Array[@asn1.DerValue] = []
  for a in addrs {
    items.push(a.to_der())
  }
  @asn1.DerValue::Sequence(items)
}

///|
fn decode_host_addresses(
  val : @asn1.DerValue,
) -> Array[HostAddress] raise @asn1.DerError {
  let items = expect_sequence(val)
  let out : Array[HostAddress] = []
  for item in items {
    out.push(HostAddress::from_der(item))
  }
  out
}

///|
/// RFC 4120 §5.2.9 `EncryptedData`.
#derive(Eq, Debug)
pub(all) struct EncryptedData {
  etype : Int32
  kvno : UInt32?
  cipher : Bytes
}

///|
pub impl Show for EncryptedData with fn output(self, logger) {
  logger.write_string("EncryptedData(etype=\{self.etype}, kvno=")
  write_show_opt(self.kvno, logger)
  logger.write_string(", cipher=\{@asn1.hex_encode(self.cipher)})")
}

///|
pub fn EncryptedData::to_der(self : EncryptedData) -> @asn1.DerValue {
  let fields : Array[@asn1.DerValue] = [
    @asn1.context_field(0, @asn1.encode_int(self.etype)),
  ]
  match self.kvno {
    Some(k) => fields.push(@asn1.context_field(1, @asn1.encode_uint32(k)))
    None => ()
  }
  fields.push(@asn1.context_field(2, @asn1.encode_octet_string(self.cipher)))
  @asn1.DerValue::Sequence(fields)
}

///|
pub fn EncryptedData::from_der(
  val : @asn1.DerValue,
) -> EncryptedData raise @asn1.DerError {
  let r = @asn1.SeqReader::new(val)
  let etype = @asn1.decode_int(r.read_required(0))
  let kvno = match r.read_optional(1) {
    Some(v) => Some(@asn1.decode_uint32(v))
    None => None
  }
  let cipher = @asn1.decode_octet_string(r.read_required(2))
  r.finish()
  { etype, kvno, cipher, }
}

///|
/// RFC 4120 §5.2.9 `EncryptionKey`.
#derive(Eq, Debug)
pub(all) struct EncryptionKey {
  keytype : Int32
  keyvalue : Bytes
}

///|
pub impl Show for EncryptionKey with fn output(self, logger) {
  logger.write_string(
    "EncryptionKey(keytype=\{self.keytype}, keyvalue=\{@asn1.hex_encode(self.keyvalue)})",
  )
}

///|
pub fn EncryptionKey::to_der(self : EncryptionKey) -> @asn1.DerValue {
  @asn1.DerValue::Sequence([
    @asn1.context_field(0, @asn1.encode_int(self.keytype)),
    @asn1.context_field(1, @asn1.encode_octet_string(self.keyvalue)),
  ])
}

///|
pub fn EncryptionKey::from_der(
  val : @asn1.DerValue,
) -> EncryptionKey raise @asn1.DerError {
  let r = @asn1.SeqReader::new(val)
  let keytype = @asn1.decode_int(r.read_required(0))
  let keyvalue = @asn1.decode_octet_string(r.read_required(1))
  r.finish()
  { keytype, keyvalue, }
}

///|
/// RFC 4120 §5.2.9 `Checksum`.
#derive(Eq, Debug)
pub(all) struct Checksum {
  cksumtype : Int32
  checksum : Bytes
}

///|
pub impl Show for Checksum with fn output(self, logger) {
  logger.write_string(
    "Checksum(cksumtype=\{self.cksumtype}, checksum=\{@asn1.hex_encode(self.checksum)})",
  )
}

///|
pub fn Checksum::to_der(self : Checksum) -> @asn1.DerValue {
  @asn1.DerValue::Sequence([
    @asn1.context_field(0, @asn1.encode_int(self.cksumtype)),
    @asn1.context_field(1, @asn1.encode_octet_string(self.checksum)),
  ])
}

///|
pub fn Checksum::from_der(
  val : @asn1.DerValue,
) -> Checksum raise @asn1.DerError {
  let r = @asn1.SeqReader::new(val)
  let cksumtype = @asn1.decode_int(r.read_required(0))
  let checksum = @asn1.decode_octet_string(r.read_required(1))
  r.finish()
  { cksumtype, checksum, }
}

///|
/// RFC 4120 §5.3 `TransitedEncoding`.
#derive(Eq, Debug)
pub(all) struct TransitedEncoding {
  tr_type : Int32
  contents : Bytes
}

///|
pub impl Show for TransitedEncoding with fn output(self, logger) {
  logger.write_string(
    "TransitedEncoding(tr_type=\{self.tr_type}, contents=\{@asn1.hex_encode(self.contents)})",
  )
}

///|
pub fn TransitedEncoding::to_der(self : TransitedEncoding) -> @asn1.DerValue {
  @asn1.DerValue::Sequence([
    @asn1.context_field(0, @asn1.encode_int(self.tr_type)),
    @asn1.context_field(1, @asn1.encode_octet_string(self.contents)),
  ])
}

///|
pub fn TransitedEncoding::from_der(
  val : @asn1.DerValue,
) -> TransitedEncoding raise @asn1.DerError {
  let r = @asn1.SeqReader::new(val)
  let tr_type = @asn1.decode_int(r.read_required(0))
  let contents = @asn1.decode_octet_string(r.read_required(1))
  r.finish()
  { tr_type, contents, }
}

///|
/// RFC 4120 §5.2.6 `AuthorizationData` element.
#derive(Eq, Debug)
pub(all) struct AuthorizationDataEntry {
  ad_type : Int32
  ad_data : Bytes
}

///|
pub impl Show for AuthorizationDataEntry with fn output(self, logger) {
  logger.write_string(
    "AuthorizationDataEntry(ad_type=\{self.ad_type}, ad_data=\{@asn1.hex_encode(self.ad_data)})",
  )
}

///|
pub fn AuthorizationDataEntry::to_der(
  self : AuthorizationDataEntry,
) -> @asn1.DerValue {
  @asn1.DerValue::Sequence([
    @asn1.context_field(0, @asn1.encode_int(self.ad_type)),
    @asn1.context_field(1, @asn1.encode_octet_string(self.ad_data)),
  ])
}

///|
pub fn AuthorizationDataEntry::from_der(
  val : @asn1.DerValue,
) -> AuthorizationDataEntry raise @asn1.DerError {
  let r = @asn1.SeqReader::new(val)
  let ad_type = @asn1.decode_int(r.read_required(0))
  let ad_data = @asn1.decode_octet_string(r.read_required(1))
  r.finish()
  { ad_type, ad_data, }
}

///|
fn encode_authorization_data(
  entries : Array[AuthorizationDataEntry],
) -> @asn1.DerValue {
  let items : Array[@asn1.DerValue] = []
  for e in entries {
    items.push(e.to_der())
  }
  @asn1.DerValue::Sequence(items)
}

///|
fn decode_authorization_data(
  val : @asn1.DerValue,
) -> Array[AuthorizationDataEntry] raise @asn1.DerError {
  let items = expect_sequence(val)
  let out : Array[AuthorizationDataEntry] = []
  for item in items {
    out.push(AuthorizationDataEntry::from_der(item))
  }
  out
}

///|
/// RFC 4120 §5.4.2 `LastReq` element.
#derive(Eq, Debug)
pub(all) struct LastReqEntry {
  lr_type : Int32
  lr_value : String
}

///|
pub impl Show for LastReqEntry with fn output(self, logger) {
  logger.write_string(
    "LastReqEntry(lr_type=\{self.lr_type}, lr_value=\{self.lr_value})",
  )
}

///|
pub fn LastReqEntry::to_der(
  self : LastReqEntry,
) -> @asn1.DerValue raise @asn1.DerError {
  @asn1.DerValue::Sequence([
    @asn1.context_field(0, @asn1.encode_int(self.lr_type)),
    @asn1.context_field(1, @asn1.encode_generalized_time(self.lr_value)),
  ])
}

///|
pub fn LastReqEntry::from_der(
  val : @asn1.DerValue,
) -> LastReqEntry raise @asn1.DerError {
  let r = @asn1.SeqReader::new(val)
  let lr_type = @asn1.decode_int(r.read_required(0))
  let lr_value = @asn1.decode_generalized_time(r.read_required(1))
  r.finish()
  { lr_type, lr_value, }
}

///|
/// RFC 4120 §5.2.7 `PA-DATA` (note: tags start at `[1]`, not `[0]`).
#derive(Eq, Debug)
pub(all) struct PaData {
  padata_type : Int32
  padata_value : Bytes
}

///|
pub impl Show for PaData with fn output(self, logger) {
  logger.write_string(
    "PaData(padata_type=\{self.padata_type}, padata_value=\{@asn1.hex_encode(self.padata_value)})",
  )
}

///|
pub fn PaData::to_der(self : PaData) -> @asn1.DerValue {
  @asn1.DerValue::Sequence([
    @asn1.context_field(1, @asn1.encode_int(self.padata_type)),
    @asn1.context_field(2, @asn1.encode_octet_string(self.padata_value)),
  ])
}

///|
pub fn PaData::from_der(val : @asn1.DerValue) -> PaData raise @asn1.DerError {
  let r = @asn1.SeqReader::new(val)
  let padata_type = @asn1.decode_int(r.read_required(1))
  let padata_value = @asn1.decode_octet_string(r.read_required(2))
  r.finish()
  { padata_type, padata_value, }
}

///|
fn encode_padata_seq(items : Array[PaData]) -> @asn1.DerValue {
  let out : Array[@asn1.DerValue] = []
  for item in items {
    out.push(item.to_der())
  }
  @asn1.DerValue::Sequence(out)
}

///|
fn decode_padata_seq(
  val : @asn1.DerValue,
) -> Array[PaData] raise @asn1.DerError {
  let items = expect_sequence(val)
  let out : Array[PaData] = []
  for item in items {
    out.push(PaData::from_der(item))
  }
  out
}

///|
/// RFC 4120 §5.2.7.2 `PA-ENC-TS-ENC`.
#derive(Eq, Debug)
pub(all) struct PaEncTsEnc {
  patimestamp : String
  pausec : Int32?
}

///|
pub impl Show for PaEncTsEnc with fn output(self, logger) {
  logger.write_string("PaEncTsEnc(patimestamp=\{self.patimestamp}, pausec=")
  write_show_opt(self.pausec, logger)
  logger.write_string(")")
}

///|
pub fn PaEncTsEnc::to_der(
  self : PaEncTsEnc,
) -> @asn1.DerValue raise @asn1.DerError {
  let fields : Array[@asn1.DerValue] = [
    @asn1.context_field(0, @asn1.encode_generalized_time(self.patimestamp)),
  ]
  match self.pausec {
    Some(us) => {
      validate_microseconds(us)
      fields.push(@asn1.context_field(1, @asn1.encode_int(us)))
    }
    None => ()
  }
  @asn1.DerValue::Sequence(fields)
}

///|
pub fn PaEncTsEnc::from_der(
  val : @asn1.DerValue,
) -> PaEncTsEnc raise @asn1.DerError {
  let r = @asn1.SeqReader::new(val)
  let patimestamp = @asn1.decode_generalized_time(r.read_required(0))
  let pausec = match r.read_optional(1) {
    Some(v) => {
      let us = @asn1.decode_int(v)
      validate_microseconds(us)
      Some(us)
    }
    None => None
  }
  r.finish()
  { patimestamp, pausec, }
}

///|
pub fn PaEncTsEnc::encode(self : PaEncTsEnc) -> Bytes raise @asn1.DerError {
  @asn1.encode_der(self.to_der())
}

///|
pub fn PaEncTsEnc::decode(data : Bytes) -> PaEncTsEnc raise @asn1.DerError {
  PaEncTsEnc::from_der(@asn1.decode_der(data))
}

///|
/// RFC 4120 §5.2.7.5 `ETYPE-INFO2-ENTRY`.
#derive(Eq, Debug)
pub(all) struct EtypeInfo2Entry {
  etype : Int32
  salt : String?
  s2kparams : Bytes?
}

///|
pub impl Show for EtypeInfo2Entry with fn output(self, logger) {
  logger.write_string("EtypeInfo2Entry(etype=\{self.etype}, salt=")
  write_show_opt(self.salt, logger)
  logger.write_string(", s2kparams=")
  match self.s2kparams {
    None => logger.write_string("None")
    Some(b) => logger.write_string("Some(\{@asn1.hex_encode(b)})")
  }
  logger.write_string(")")
}

///|
pub fn EtypeInfo2Entry::to_der(self : EtypeInfo2Entry) -> @asn1.DerValue {
  let fields : Array[@asn1.DerValue] = [
    @asn1.context_field(0, @asn1.encode_int(self.etype)),
  ]
  match self.salt {
    Some(s) =>
      fields.push(@asn1.context_field(1, @asn1.encode_general_string(s)))
    None => ()
  }
  match self.s2kparams {
    Some(p) => fields.push(@asn1.context_field(2, @asn1.encode_octet_string(p)))
    None => ()
  }
  @asn1.DerValue::Sequence(fields)
}

///|
pub fn EtypeInfo2Entry::from_der(
  val : @asn1.DerValue,
) -> EtypeInfo2Entry raise @asn1.DerError {
  let r = @asn1.SeqReader::new(val)
  let etype = @asn1.decode_int(r.read_required(0))
  let salt = match r.read_optional(1) {
    Some(v) => Some(@asn1.decode_general_string(v))
    None => None
  }
  let s2kparams = match r.read_optional(2) {
    Some(v) => Some(@asn1.decode_octet_string(v))
    None => None
  }
  r.finish()
  { etype, salt, s2kparams, }
}

///|
/// Encode RFC 4120 §5.2.7.5 `ETYPE-INFO2 ::= SEQUENCE SIZE (1..MAX) OF ETYPE-INFO2-ENTRY`.
pub fn encode_etype_info2(entries : Array[EtypeInfo2Entry]) -> Bytes {
  let items : Array[@asn1.DerValue] = []
  for e in entries {
    items.push(e.to_der())
  }
  @asn1.encode_der(@asn1.DerValue::Sequence(items))
}

///|
/// Decode RFC 4120 §5.2.7.5 `ETYPE-INFO2 ::= SEQUENCE SIZE (1..MAX) OF ETYPE-INFO2-ENTRY`.
pub fn decode_etype_info2(
  data : Bytes,
) -> Array[EtypeInfo2Entry] raise @asn1.DerError {
  let items = expect_sequence(@asn1.decode_der(data))
  if items.is_empty() {
    raise @asn1.DerError::InvalidValue(
      "ETYPE-INFO2 must contain at least 1 entry",
    )
  }
  let out : Array[EtypeInfo2Entry] = []
  for item in items {
    out.push(EtypeInfo2Entry::from_der(item))
  }
  out
}

///|
/// Encode RFC 4120 §5.9.1 `METHOD-DATA ::= SEQUENCE OF PA-DATA`.
pub fn encode_method_data(items : Array[PaData]) -> Bytes {
  @asn1.encode_der(encode_padata_seq(items))
}

///|
/// Decode RFC 4120 §5.9.1 `METHOD-DATA ::= SEQUENCE OF PA-DATA`.
pub fn decode_method_data(data : Bytes) -> Array[PaData] raise @asn1.DerError {
  decode_padata_seq(@asn1.decode_der(data))
}
