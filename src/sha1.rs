//! SHA-1 (FIPS 180-4), and the pieces of its compression function that collision detection reuses.

use std::convert::Infallible;
use std::ops::Range;

use crate::Hasher;
use crate::block::{BLOCK, Blocks};

/// The digest's length in bytes.
pub(crate) const LEN: usize = 20;

pub(crate) const INITIAL: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];

/// The working state between steps: the variables a, b, c, d and e.
pub(crate) type State = [u32; 5];

/// A message block expanded to one word per step.
pub(crate) type Expanded = [u32; 80];

/// SHA-1, with no collision detection: [`crate::Sha1Checked`] is what git uses to name objects. Use this where the
/// data can't be an attacker's, or isn't being trusted on its hash.
#[derive(Clone)]
pub struct Sha1 {
	state: State,
	blocks: Blocks,
}

impl Sha1 {
	pub const fn new() -> Self {
		Self { state: INITIAL, blocks: Blocks::new() }
	}

	/// Feed it more data.
	pub fn update(&mut self, data: &[u8]) {
		let state = &mut self.state;
		self.blocks.update(data, |block| compress(state, &expand(block)));
	}

	/// The digest of everything fed in.
	pub fn finish(mut self) -> [u8; LEN] {
		let state = &mut self.state;
		self.blocks.finish(|block| compress(state, &expand(block)));
		to_bytes(&self.state)
	}

	/// The digest of `data`, in one call.
	pub fn digest(data: &[u8]) -> [u8; LEN] {
		let mut h = Self::new();
		h.update(data);
		h.finish()
	}
}

impl Default for Sha1 {
	fn default() -> Self {
		Self::new()
	}
}

impl Hasher for Sha1 {
	type Digest = [u8; LEN];
	type Error = Infallible;
	const NAME: &'static str = "sha1";
	const LEN: usize = LEN;

	fn update(&mut self, data: &[u8]) {
		Sha1::update(self, data);
	}

	fn finish(self) -> Result<[u8; LEN], Infallible> {
		Ok(Sha1::finish(self))
	}
}

impl std::io::Write for Sha1 {
	fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
		self.update(buf);
		Ok(buf.len())
	}

	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}

pub(crate) fn to_bytes(state: &State) -> [u8; LEN] {
	let mut out = [0; LEN];
	for (bytes, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(state) {
		*bytes = word.to_be_bytes();
	}
	out
}

/// Expand a block to the 80 words the steps use.
pub(crate) fn expand(block: &[u8; BLOCK]) -> Expanded {
	let mut w = [0; 80];
	for (word, bytes) in w.iter_mut().zip(block.as_chunks::<4>().0) {
		*word = u32::from_be_bytes(*bytes);
	}
	for t in 16..80 {
		w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
	}
	w
}

const K: [u32; 4] = [0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xCA62_C1D6];

fn choose(b: u32, c: u32, d: u32) -> u32 {
	d ^ (b & (c ^ d))
}

fn parity(b: u32, c: u32, d: u32) -> u32 {
	b ^ c ^ d
}

fn majority(b: u32, c: u32, d: u32) -> u32 {
	(b & c) | (d & (b ^ c))
}

/// Steps `range`, all in one round, which uses the function `f` and constant `k`. Inlined, so each round's loop is
/// compiled with its own function.
#[inline(always)]
fn round(s: &mut State, w: &Expanded, range: Range<usize>, f: impl Fn(u32, u32, u32) -> u32, k: u32) {
	let [mut a, mut b, mut c, mut d, mut e] = *s;
	for t in range {
		let next = a.rotate_left(5).wrapping_add(f(b, c, d)).wrapping_add(e).wrapping_add(k).wrapping_add(w[t]);
		e = d;
		d = c;
		c = b.rotate_left(30);
		b = a;
		a = next;
	}
	*s = [a, b, c, d, e];
}

/// Steps `range` (within 0..80) of the compression function, in any rounds.
#[inline(always)]
pub(crate) fn steps(s: &mut State, w: &Expanded, range: Range<usize>) {
	let part = |lo: usize, hi: usize| range.start.max(lo)..range.end.min(hi);
	round(s, w, part(0, 20), choose, K[0]);
	round(s, w, part(20, 40), parity, K[1]);
	round(s, w, part(40, 60), majority, K[2]);
	round(s, w, part(60, 80), parity, K[3]);
}

/// Undo step `t`: from the state after it, the state before it.
pub(crate) fn step_back(s: &mut State, w: &Expanded, t: usize) {
	let [next, a, c_rotated, c, d] = *s;
	let b = c_rotated.rotate_right(30);
	let f = match t {
		0..20 => choose(b, c, d),
		20..40 | 60..80 => parity(b, c, d),
		_ => majority(b, c, d),
	};
	let e = next.wrapping_sub(a.rotate_left(5).wrapping_add(f).wrapping_add(K[t / 20]).wrapping_add(w[t]));
	*s = [a, b, c, d, e];
}

/// Add a block's final working state into the chaining value.
pub(crate) fn add(ihv: &mut State, s: &State) {
	for (h, v) in ihv.iter_mut().zip(s) {
		*h = h.wrapping_add(*v);
	}
}

/// The whole compression function, on an expanded block.
pub(crate) fn compress(ihv: &mut State, w: &Expanded) {
	let mut s = *ihv;
	steps(&mut s, w, 0..80);
	add(ihv, &s);
}

#[cfg(test)]
mod tests {
	use super::*;

	fn hex(d: &[u8]) -> String {
		d.iter().map(|b| format!("{b:02x}")).collect()
	}

	#[test]
	fn fips_180_examples() {
		assert_eq!(hex(&Sha1::digest(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
		assert_eq!(hex(&Sha1::digest(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
		assert_eq!(hex(&Sha1::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
		assert_eq!(hex(&Sha1::digest(&[b'a'; 1_000_000])), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
	}

	#[test]
	fn steps_undo() {
		let w = expand(&[0x5A; 64]);
		let mut s = INITIAL;
		let mut before = Vec::new();
		for t in 0..80 {
			before.push(s);
			steps(&mut s, &w, t..t + 1);
		}
		for t in (0..80).rev() {
			step_back(&mut s, &w, t);
			assert_eq!(s, before[t], "step {t}");
		}
	}

	#[test]
	fn steps_in_pieces_match_all_at_once() {
		let w = expand(&[0xC3; 64]);
		let mut whole = INITIAL;
		steps(&mut whole, &w, 0..80);
		let mut pieces = INITIAL;
		for range in [0..17, 17..58, 58..65, 65..80] {
			steps(&mut pieces, &w, range);
		}
		assert_eq!(pieces, whole);
	}
}
