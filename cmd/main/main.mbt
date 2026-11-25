///|
fn status_tag(ok : Bool) -> String {
  if ok {
    "[PASS]"
  } else {
    "[FAIL]"
  }
}

///|
fn main {
  println(
    "====================================================================",
  )
  println("  CoolrfulDARkness/moonkrb5 v\{@moonkrb5.version()}")
  println("  Pure MoonBit | Zero-FFI | Sans-I/O Kerberos 5 Protocol Stack")
  println("  Standards: RFC 4120 | RFC 3961 | RFC 3962 | RFC 8009 | MIT Keytab")
  println(
    "====================================================================",
  )
  let mut passed = 0
  let mut total = 0
  let mut any_failed = false
  // [1/3] Official RFC 3961 / 3962 / 8009 Cryptographic Test Vectors
  println("")
  println("[1/3] RFC 3961 / 3962 / 8009 Cryptographic Self-Check")
  println(
    "--------------------------------------------------------------------",
  )
  let vectors = @moonkrb5.run_rfc_vector_self_check()
  for item in vectors {
    let (label, ok) = item
    total = total + 1
    if ok {
      passed = passed + 1
    } else {
      any_failed = true
    }
    println("  \{status_tag(ok)} \{label}")
  }
  // [2/3] End-to-End 3-Party Kerberos 5 Handshake across all 4 Enctypes
  println("")
  println(
    "[2/3] Full 3-Party Kerberos 5 Handshake + Keytab + Mutual Auth (4 Suites)",
  )
  println(
    "--------------------------------------------------------------------",
  )
  for etype in @moonkrb5.all_enctypes() {
    total = total + 1
    try {
      let r = @moonkrb5.run_full_handshake_demo(etype)
      let ok = r.mutual_authenticated
      if ok {
        passed = passed + 1
      } else {
        any_failed = true
      }
      println(
        "  \{status_tag(ok)} etype \{r.etype_id}: \{r.etype_name} (\{r.client_principal} -> \{r.service_principal})",
      )
      println(
        "         DER sizes: AS-REQ=\{r.as_req_bytes}B | KRB-ERR=\{r.preauth_err_bytes}B | AS-REQ+PA=\{r.as_req_preauth_bytes}B | AS-REP=\{r.as_rep_bytes}B",
      )
      println(
        "         DER sizes: TGS-REQ=\{r.tgs_req_bytes}B | TGS-REP=\{r.tgs_rep_bytes}B | KEYTAB=\{r.keytab_bytes}B | AP-REQ=\{r.ap_req_bytes}B | AP-REP=\{r.ap_rep_bytes}B",
      )
    } catch {
      err => {
        any_failed = true
        println("  [FAIL] etype handshake raised error: \{err}")
      }
    }
  }
  // [3/3] Active Security Defense-in-Depth Demonstration
  println("")
  println("[3/3] Security Defense-in-Depth Attack Mitigation Demo")
  println(
    "--------------------------------------------------------------------",
  )
  let defenses = @moonkrb5.run_security_defense_demo()
  for item in defenses {
    let (label, ok) = item
    total = total + 1
    if ok {
      passed = passed + 1
    } else {
      any_failed = true
    }
    println("  \{status_tag(ok)} \{label}")
  }
  // Summary
  println("")
  println(
    "====================================================================",
  )
  if any_failed {
    println("  SUMMARY: \{passed}/\{total} checks passed — SELF-CHECK FAILED")
    println(
      "====================================================================",
    )
    abort("moonkrb5 CLI self-check failed")
  } else {
    println("  SUMMARY: \{passed}/\{total} checks passed — ALL CHECKS PASSED")
    println(
      "====================================================================",
    )
  }
}
