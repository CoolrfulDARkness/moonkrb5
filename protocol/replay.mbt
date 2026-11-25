///|
/// RFC 4120 §10 authenticator replay cache keyed on `(crealm, cname, ctime, cusec)`.
pub struct ReplayCache {
  priv max_skew_secs : Int64
  priv entries : Map[String, Int64]
}

///|
/// Create a new replay cache with the given maximum clock skew window (default 300s).
pub fn ReplayCache::new(max_skew_secs~ : Int64 = 300L) -> ReplayCache {
  { max_skew_secs, entries: {}, }
}

///|
fn replay_entry_key(
  crealm : String,
  cname : @types.PrincipalName,
  ctime : String,
  cusec : Int32,
) -> String {
  let buf = StringBuilder()
  buf.write_string(crealm.length().to_string())
  buf.write_string(":")
  buf.write_string(crealm)
  buf.write_string("|")
  buf.write_string(principal_lookup_key(cname))
  buf.write_string("|")
  buf.write_string(ctime)
  buf.write_string("|")
  buf.write_string(cusec.to_string())
  buf.to_string()
}

///|
/// Remove all cached entries whose timestamps are older than `now - max_skew_secs`.
pub fn ReplayCache::prune(self : ReplayCache, now : Int64) -> Unit {
  let expired : Array[String] = []
  self.entries.each(fn(k, ts) {
    if now - ts > self.max_skew_secs {
      expired.push(k)
    }
  })
  for k in expired {
    self.entries.remove(k)
  }
}

///|
/// Return the current number of entries stored in the replay cache.
pub fn ReplayCache::len(self : ReplayCache) -> Int32 {
  self.entries.length()
}

///|
/// Prune expired entries, then check whether `(crealm, cname, ctime, cusec)` was
/// already seen. Raises `ReplayDetected` on duplicate, otherwise inserts it.
pub fn ReplayCache::check_and_insert(
  self : ReplayCache,
  now : Int64,
  crealm : String,
  cname : @types.PrincipalName,
  ctime : String,
  cusec : Int32,
) -> Unit raise ProtocolError {
  self.prune(now)
  let ctime_unix = ktime_to_unix(ctime)
  let key = replay_entry_key(crealm, cname, ctime, cusec)
  if self.entries.contains(key) {
    raise ProtocolError::ReplayDetected
  }
  self.entries.set(key, ctime_unix)
}
