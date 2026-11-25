///|
/// Errors raised by the Sans-I/O Kerberos 5 protocol state machines.
#derive(Eq, Debug)
pub(all) suberror ProtocolError {
  Der(@asn1.DerError)
  Crypto(@crypto.CryptoError)
  Keytab(@keytab.KeytabError)
  KrbErrorReceived(code~ : Int32, text~ : String)
  InvalidState(String)
  UnexpectedMessage(String)
  TicketExpired
  TicketNotYetValid
  TicketInvalidFlag
  ClockSkew(Int64)
  ReplayDetected
  PrincipalMismatch(String)
  WrongService(String)
  KeyNotFound(String)
  BadKeyVersion
  ChecksumMismatch
  NonceMismatch
  MutualAuthFailed(String)
  PreauthRequired
  PreauthFailed(String)
  UnsupportedEnctype(Int32)
}

///|
pub impl Show for ProtocolError with fn output(self, logger) {
  match self {
    Der(e) => {
      logger.write_string("Der(")
      Show::output(e, logger)
      logger.write_string(")")
    }
    Crypto(e) => {
      logger.write_string("Crypto(")
      Show::output(e, logger)
      logger.write_string(")")
    }
    Keytab(e) => {
      logger.write_string("Keytab(")
      Show::output(e, logger)
      logger.write_string(")")
    }
    KrbErrorReceived(code~, text~) => {
      logger.write_string("KrbErrorReceived(code=")
      Show::output(code, logger)
      logger.write_string(", text=")
      Show::output(text, logger)
      logger.write_string(")")
    }
    InvalidState(msg) => {
      logger.write_string("InvalidState(")
      Show::output(msg, logger)
      logger.write_string(")")
    }
    UnexpectedMessage(msg) => {
      logger.write_string("UnexpectedMessage(")
      Show::output(msg, logger)
      logger.write_string(")")
    }
    TicketExpired => logger.write_string("TicketExpired")
    TicketNotYetValid => logger.write_string("TicketNotYetValid")
    TicketInvalidFlag => logger.write_string("TicketInvalidFlag")
    ClockSkew(skew) => {
      logger.write_string("ClockSkew(")
      Show::output(skew, logger)
      logger.write_string(")")
    }
    ReplayDetected => logger.write_string("ReplayDetected")
    PrincipalMismatch(msg) => {
      logger.write_string("PrincipalMismatch(")
      Show::output(msg, logger)
      logger.write_string(")")
    }
    WrongService(msg) => {
      logger.write_string("WrongService(")
      Show::output(msg, logger)
      logger.write_string(")")
    }
    KeyNotFound(msg) => {
      logger.write_string("KeyNotFound(")
      Show::output(msg, logger)
      logger.write_string(")")
    }
    BadKeyVersion => logger.write_string("BadKeyVersion")
    ChecksumMismatch => logger.write_string("ChecksumMismatch")
    NonceMismatch => logger.write_string("NonceMismatch")
    MutualAuthFailed(msg) => {
      logger.write_string("MutualAuthFailed(")
      Show::output(msg, logger)
      logger.write_string(")")
    }
    PreauthRequired => logger.write_string("PreauthRequired")
    PreauthFailed(msg) => {
      logger.write_string("PreauthFailed(")
      Show::output(msg, logger)
      logger.write_string(")")
    }
    UnsupportedEnctype(et) => {
      logger.write_string("UnsupportedEnctype(")
      Show::output(et, logger)
      logger.write_string(")")
    }
  }
}
