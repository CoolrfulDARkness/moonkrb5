///|
/// Errors raised during strict ASN.1 DER decoding, validation, or helper conversion.
#derive(Eq, Debug)
pub suberror DerError {
  UnexpectedEof
  InvalidTag(String)
  InvalidLength(String)
  NonCanonicalLength
  IndefiniteLength
  NonCanonicalInteger
  NonCanonicalBoolean
  InvalidBitString(String)
  InvalidGeneralizedTime(String)
  TrailingBytes(Int32)
  MaxDepthExceeded
  TagMismatch(expected~ : String, got~ : String)
  MissingField(String)
  InvalidValue(String)
}

///|
pub impl Show for DerError with fn output(self, logger) {
  match self {
    UnexpectedEof => logger.write_string("UnexpectedEof")
    InvalidTag(msg) => logger.write_string("InvalidTag(\{msg})")
    InvalidLength(msg) => logger.write_string("InvalidLength(\{msg})")
    NonCanonicalLength => logger.write_string("NonCanonicalLength")
    IndefiniteLength => logger.write_string("IndefiniteLength")
    NonCanonicalInteger => logger.write_string("NonCanonicalInteger")
    NonCanonicalBoolean => logger.write_string("NonCanonicalBoolean")
    InvalidBitString(msg) => logger.write_string("InvalidBitString(\{msg})")
    InvalidGeneralizedTime(msg) =>
      logger.write_string("InvalidGeneralizedTime(\{msg})")
    TrailingBytes(n) => logger.write_string("TrailingBytes(\{n})")
    MaxDepthExceeded => logger.write_string("MaxDepthExceeded")
    TagMismatch(expected~, got~) =>
      logger.write_string("TagMismatch(expected=\{expected}, got=\{got})")
    MissingField(msg) => logger.write_string("MissingField(\{msg})")
    InvalidValue(msg) => logger.write_string("InvalidValue(\{msg})")
  }
}

///|
/// ASN.1 tag class (bits 7..6 of the identifier octet).
#derive(Eq, Debug)
pub(all) enum TagClass {
  Universal
  Application
  ContextSpecific
  Private
}

///|
pub impl Show for TagClass with fn output(self, logger) {
  match self {
    Universal => logger.write_string("Universal")
    Application => logger.write_string("Application")
    ContextSpecific => logger.write_string("ContextSpecific")
    Private => logger.write_string("Private")
  }
}

///|
/// Parsed ASN.1 tag identifier.
#derive(Eq, Debug)
pub(all) struct Tag {
  class : TagClass
  constructed : Bool
  number : Int32
}

///|
pub impl Show for Tag with fn output(self, logger) {
  logger.write_string(
    "Tag(class=\{self.class}, constructed=\{self.constructed}, number=\{self.number})",
  )
}

///|
/// ASN.1 DER value tree.
///
/// In RFC 4120, `Application(n, inner)` and `Context(n, inner)` are constructed
/// explicit wrappers (`0x60 | n` / `0xA0 | n`, plus high-tag-number encoding
/// when `n >= 31`). Non-explicit or unrecognized TLVs are preserved in `Raw`.
#derive(Eq, Debug)
pub(all) enum DerValue {
  Boolean(Bool)
  Integer(Bytes)
  BitString(Int32, Bytes)
  OctetString(Bytes)
  Null
  Oid(Array[Int32])
  GeneralString(String)
  GeneralizedTime(String)
  Sequence(Array[DerValue])
  Set(Array[DerValue])
  Application(Int32, DerValue)
  Context(Int32, DerValue)
  Raw(Tag, Bytes)
}

///|
pub impl Show for DerValue with fn output(self, logger) {
  match self {
    Boolean(b) => logger.write_string("Boolean(\{b})")
    Integer(raw) => logger.write_string("Integer(\{hex_encode(raw)})")
    BitString(unused, data) =>
      logger.write_string("BitString(\{unused}, \{hex_encode(data)})")
    OctetString(data) => logger.write_string("OctetString(\{hex_encode(data)})")
    Null => logger.write_string("Null")
    Oid(arcs) => {
      logger.write_string("Oid(")
      for i = 0; i < arcs.length(); i = i + 1 {
        if i > 0 {
          logger.write_string(".")
        }
        logger.write_string("\{arcs[i]}")
      }
      logger.write_string(")")
    }
    GeneralString(s) => logger.write_string("GeneralString(\{s})")
    GeneralizedTime(s) => logger.write_string("GeneralizedTime(\{s})")
    Sequence(items) => {
      logger.write_string("Sequence([")
      for i = 0; i < items.length(); i = i + 1 {
        if i > 0 {
          logger.write_string(", ")
        }
        Show::output(items[i], logger)
      }
      logger.write_string("])")
    }
    Set(items) => {
      logger.write_string("Set([")
      for i = 0; i < items.length(); i = i + 1 {
        if i > 0 {
          logger.write_string(", ")
        }
        Show::output(items[i], logger)
      }
      logger.write_string("])")
    }
    Application(n, inner) => {
      logger.write_string("Application(\{n}, ")
      Show::output(inner, logger)
      logger.write_string(")")
    }
    Context(n, inner) => {
      logger.write_string("Context(\{n}, ")
      Show::output(inner, logger)
      logger.write_string(")")
    }
    Raw(tag, data) => logger.write_string("Raw(\{tag}, \{hex_encode(data)})")
  }
}

///|
/// RFC 4120 `[APPLICATION n]` tag numbers.
pub const APP_TICKET : Int32 = 1

///|
pub const APP_AUTHENTICATOR : Int32 = 2

///|
pub const APP_ENC_TICKET_PART : Int32 = 3

///|
pub const APP_AS_REQ : Int32 = 10

///|
pub const APP_AS_REP : Int32 = 11

///|
pub const APP_TGS_REQ : Int32 = 12

///|
pub const APP_TGS_REP : Int32 = 13

///|
pub const APP_AP_REQ : Int32 = 14

///|
pub const APP_AP_REP : Int32 = 15

///|
pub const APP_KRB_SAFE : Int32 = 20

///|
pub const APP_KRB_PRIV : Int32 = 21

///|
pub const APP_KRB_CRED : Int32 = 22

///|
pub const APP_ENC_AS_REP_PART : Int32 = 25

///|
pub const APP_ENC_TGS_REP_PART : Int32 = 26

///|
pub const APP_ENC_AP_REP_PART : Int32 = 27

///|
pub const APP_ENC_KRB_PRIV_PART : Int32 = 28

///|
pub const APP_ENC_KRB_CRED_PART : Int32 = 29

///|
pub const APP_KRB_ERROR : Int32 = 30

///|
const MAX_DEPTH : Int32 = 64

///|
const TAG_BOOLEAN : Int32 = 1

///|
const TAG_INTEGER : Int32 = 2

///|
const TAG_BIT_STRING : Int32 = 3

///|
const TAG_OCTET_STRING : Int32 = 4

///|
const TAG_NULL : Int32 = 5

///|
const TAG_OID : Int32 = 6

///|
const TAG_SEQUENCE : Int32 = 16

///|
const TAG_SET : Int32 = 17

///|
const TAG_GENERALIZED_TIME : Int32 = 24

///|
const TAG_GENERAL_STRING : Int32 = 27

///|
fn describe_tag(tag : Tag) -> String {
  let cls = match tag.class {
    Universal => "UNIVERSAL"
    Application => "APPLICATION"
    ContextSpecific => "CONTEXT"
    Private => "PRIVATE"
  }
  let form = if tag.constructed { "constructed" } else { "primitive" }
  "\{cls}[\{tag.number}](\{form})"
}

///|
fn describe_der_tag(val : DerValue) -> String {
  match val {
    Boolean(_) => "BOOLEAN"
    Integer(_) => "INTEGER"
    BitString(_, _) => "BIT STRING"
    OctetString(_) => "OCTET STRING"
    Null => "NULL"
    Oid(_) => "OBJECT IDENTIFIER"
    GeneralString(_) => "GeneralString"
    GeneralizedTime(_) => "GeneralizedTime"
    Sequence(_) => "SEQUENCE"
    Set(_) => "SET"
    Application(n, _) => "APPLICATION[\{n}]"
    Context(n, _) => "CONTEXT[\{n}]"
    Raw(tag, _) => describe_tag(tag)
  }
}
