///|
/// Deterministic Sans-I/O pseudorandom byte generator based on SHA-256 in counter mode.
pub struct DeterministicRng {
  priv state_key : Bytes
  priv mut counter : UInt64
  priv buf : FixedArray[Byte]
  priv mut pos : Int32
}

///|
/// Create a new `DeterministicRng` seeded from `seed`.
pub fn DeterministicRng::new(seed : Bytes) -> DeterministicRng {
  let state_key = sha256(seed)
  { state_key, counter: 0UL, buf: FixedArray::make(32, b'\x00'), pos: 32, }
}

///|
fn DeterministicRng::refill(self : DeterministicRng) -> Unit {
  let inp = FixedArray::make(40, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    inp[i] = self.state_key[i]
  }
  write_be_u64(inp, 32, self.counter)
  self.counter = self.counter + 1UL
  let block = sha256(fixed_to_bytes(inp, 40))
  for i = 0; i < 32; i = i + 1 {
    self.buf[i] = block[i]
  }
  self.pos = 0
}

///|
/// Generate `n` deterministic pseudorandom bytes.
pub fn DeterministicRng::next_bytes(
  self : DeterministicRng,
  n : Int32,
) -> Bytes {
  if n <= 0 {
    return Bytes::make(0, b'\x00')
  }
  let out = FixedArray::make(n, b'\x00')
  let mut written = 0
  while written < n {
    if self.pos >= 32 {
      self.refill()
    }
    let avail = 32 - self.pos
    let need = n - written
    let take = if avail < need { avail } else { need }
    for i = 0; i < take; i = i + 1 {
      out[written + i] = self.buf[self.pos + i]
    }
    self.pos = self.pos + take
    written = written + take
  }
  fixed_to_bytes(out, n)
}

///|
/// Generate a deterministic pseudorandom 32-bit unsigned integer.
pub fn DeterministicRng::next_u32(self : DeterministicRng) -> UInt32 {
  let b = self.next_bytes(4)
  read_be_u32(b, 0)
}
