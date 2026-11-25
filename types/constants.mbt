///|
/// Kerberos V5 protocol version number (RFC 4120 §5.4.1).
pub const KRB5_PVNO : Int32 = 5

///|
/// RFC 4120 message types.
pub const MSG_AS_REQ : Int32 = 10

///|
pub const MSG_AS_REP : Int32 = 11

///|
pub const MSG_TGS_REQ : Int32 = 12

///|
pub const MSG_TGS_REP : Int32 = 13

///|
pub const MSG_AP_REQ : Int32 = 14

///|
pub const MSG_AP_REP : Int32 = 15

///|
pub const MSG_KRB_SAFE : Int32 = 20

///|
pub const MSG_KRB_PRIV : Int32 = 21

///|
pub const MSG_KRB_CRED : Int32 = 22

///|
pub const MSG_KRB_ERROR : Int32 = 30

///|
/// RFC 4120 §6.2 principal name types.
pub const NT_UNKNOWN : Int32 = 0

///|
pub const NT_PRINCIPAL : Int32 = 1

///|
pub const NT_SRV_INST : Int32 = 2

///|
pub const NT_SRV_HST : Int32 = 3

///|
pub const NT_SRV_XHST : Int32 = 4

///|
pub const NT_UID : Int32 = 5

///|
pub const NT_ENTERPRISE : Int32 = 10

///|
/// RFC 4120 §5.2.7 pre-authentication data types.
pub const PA_TGS_REQ : Int32 = 1

///|
pub const PA_ENC_TIMESTAMP : Int32 = 2

///|
pub const PA_PW_SALT : Int32 = 3

///|
pub const PA_ETYPE_INFO : Int32 = 11

///|
pub const PA_ETYPE_INFO2 : Int32 = 19

///|
/// RFC 4120 §5.3 TicketFlags (MSB-first 32-bit KerberosFlags).
pub const TKT_FLAG_FORWARDABLE : UInt32 = 0x40000000U

///|
pub const TKT_FLAG_FORWARDED : UInt32 = 0x20000000U

///|
pub const TKT_FLAG_PROXIABLE : UInt32 = 0x10000000U

///|
pub const TKT_FLAG_PROXY : UInt32 = 0x08000000U

///|
pub const TKT_FLAG_MAY_POSTDATE : UInt32 = 0x04000000U

///|
pub const TKT_FLAG_POSTDATED : UInt32 = 0x02000000U

///|
pub const TKT_FLAG_INVALID : UInt32 = 0x01000000U

///|
pub const TKT_FLAG_RENEWABLE : UInt32 = 0x00800000U

///|
pub const TKT_FLAG_INITIAL : UInt32 = 0x00400000U

///|
pub const TKT_FLAG_PRE_AUTHENT : UInt32 = 0x00200000U

///|
pub const TKT_FLAG_HW_AUTHENT : UInt32 = 0x00100000U

///|
/// RFC 4120 §5.4.1 KDCOptions (MSB-first 32-bit KerberosFlags).
pub const KDC_OPT_FORWARDABLE : UInt32 = 0x40000000U

///|
pub const KDC_OPT_PROXIABLE : UInt32 = 0x10000000U

///|
pub const KDC_OPT_ALLOW_POSTDATE : UInt32 = 0x04000000U

///|
pub const KDC_OPT_RENEWABLE : UInt32 = 0x00800000U

///|
pub const KDC_OPT_CANONICALIZE : UInt32 = 0x00010000U

///|
pub const KDC_OPT_RENEWABLE_OK : UInt32 = 0x00000010U

///|
pub const KDC_OPT_ENC_TKT_IN_SKEY : UInt32 = 0x00000008U

///|
pub const KDC_OPT_RENEW : UInt32 = 0x00000002U

///|
pub const KDC_OPT_VALIDATE : UInt32 = 0x00000001U

///|
/// RFC 4120 §5.5.1 APOptions (MSB-first 32-bit KerberosFlags).
pub const AP_OPT_USE_SESSION_KEY : UInt32 = 0x40000000U

///|
pub const AP_OPT_MUTUAL_REQUIRED : UInt32 = 0x20000000U

///|
/// RFC 4120 §7.5.9 Kerberos error codes.
pub const KDC_ERR_NONE : Int32 = 0

///|
pub const KDC_ERR_NAME_EXP : Int32 = 1

///|
pub const KDC_ERR_SERVICE_EXP : Int32 = 2

///|
pub const KDC_ERR_BAD_PVNO : Int32 = 3

///|
pub const KDC_ERR_C_OLD_MAST_KVNO : Int32 = 4

///|
pub const KDC_ERR_S_OLD_MAST_KVNO : Int32 = 5

///|
pub const KDC_ERR_C_PRINCIPAL_UNKNOWN : Int32 = 6

///|
pub const KDC_ERR_S_PRINCIPAL_UNKNOWN : Int32 = 7

///|
pub const KDC_ERR_PRINCIPAL_NOT_UNIQUE : Int32 = 8

///|
pub const KDC_ERR_NULL_KEY : Int32 = 9

///|
pub const KDC_ERR_CANNOT_POSTDATE : Int32 = 10

///|
pub const KDC_ERR_NEVER_VALID : Int32 = 11

///|
pub const KDC_ERR_POLICY : Int32 = 12

///|
pub const KDC_ERR_BADOPTION : Int32 = 13

///|
pub const KDC_ERR_ETYPE_NOSUPP : Int32 = 14

///|
pub const KDC_ERR_SUMTYPE_NOSUPP : Int32 = 15

///|
pub const KDC_ERR_PADATA_TYPE_NOSUPP : Int32 = 16

///|
pub const KDC_ERR_TRTYPE_NOSUPP : Int32 = 17

///|
pub const KDC_ERR_CLIENT_REVOKED : Int32 = 18

///|
pub const KDC_ERR_SERVICE_REVOKED : Int32 = 19

///|
pub const KDC_ERR_TGT_REVOKED : Int32 = 20

///|
pub const KDC_ERR_CLIENT_NOTYET : Int32 = 21

///|
pub const KDC_ERR_SERVICE_NOTYET : Int32 = 22

///|
pub const KDC_ERR_KEY_EXPIRED : Int32 = 23

///|
pub const KDC_ERR_PREAUTH_FAILED : Int32 = 24

///|
pub const KDC_ERR_PREAUTH_REQUIRED : Int32 = 25

///|
pub const KRB_AP_ERR_BAD_INTEGRITY : Int32 = 31

///|
pub const KRB_AP_ERR_TKT_EXPIRED : Int32 = 32

///|
pub const KRB_AP_ERR_TKT_NYV : Int32 = 33

///|
pub const KRB_AP_ERR_REPEAT : Int32 = 34

///|
pub const KRB_AP_ERR_NOT_US : Int32 = 35

///|
pub const KRB_AP_ERR_BADMATCH : Int32 = 36

///|
pub const KRB_AP_ERR_SKEW : Int32 = 37

///|
pub const KRB_AP_ERR_BADADDR : Int32 = 38

///|
pub const KRB_AP_ERR_BADVERSION : Int32 = 39

///|
pub const KRB_AP_ERR_MSG_TYPE : Int32 = 40

///|
pub const KRB_AP_ERR_MODIFIED : Int32 = 41

///|
pub const KRB_AP_ERR_BADORDER : Int32 = 42

///|
pub const KRB_AP_ERR_BADKEYVER : Int32 = 44

///|
pub const KRB_AP_ERR_NOKEY : Int32 = 45

///|
pub const KRB_AP_ERR_MUT_FAIL : Int32 = 46

///|
pub const KRB_ERR_GENERIC : Int32 = 60
