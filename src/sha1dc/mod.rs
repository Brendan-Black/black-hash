//! SHA-1 with collision detection: a port of sha1collisiondetection by Marc Stevens and Dan Shumow
//! (<https://github.com/cr-marcstevens/sha1collisiondetection>), the SHA-1 git uses. MIT licensed; the notice is in
//! [`ubc`], the part converted from their generated code.
//!
//! Every known practical collision attack on SHA-1 builds near-collision blocks along one of a few disturbance vectors.
//! For each block, [`ubc::ubc_check`] cheaply rules out the vectors whose necessary bit conditions the block misses.
//! For each one left, the block is XORed with the vector's message difference, giving the block an attacker would pair
//! with it, and that block is run back to its input chaining value and forward to its output from a state stored
//! mid-compression. If the output matches this block's, the two blocks collide: the data is one half of an attack.
//!
//! Ordinary data passes after the cheap check, so this costs little over plain SHA-1 and gives the same digest.

mod ubc;

use std::fmt;

use crate::Hasher;
use crate::block::{BLOCK, Blocks};
use crate::sha1::{self, Expanded, INITIAL, LEN, State};

/// The steps whose starting states the disturbance vectors recompress from.
const STORED_STEPS: [usize; 2] = [58, 65];

/// SHA-1 that detects the known collision attacks, as git hashes objects with it. Its digest is SHA-1's for all data
/// except one half of a collision attack, which it refuses with a [`Collision`].
#[derive(Clone)]
pub struct Sha1Checked {
	ihv: State,
	blocks: Blocks,
	/// Blocks compressed so far, to say where a collision is.
	block_count: u64,
	/// The first collision found; hashing goes on, hardened, so its digest is still the attack-proof one.
	collision: Option<u64>,
	/// Check only the vectors `ubc_check` leaves; off only to test that check against checking them all.
	use_ubc: bool,
}

impl Sha1Checked {
	pub const fn new() -> Self {
		Self { ihv: INITIAL, blocks: Blocks::new(), block_count: 0, collision: None, use_ubc: true }
	}

	/// Feed it more data.
	pub fn update(&mut self, data: &[u8]) {
		let Self { ihv, blocks, block_count, collision, use_ubc } = self;
		blocks.update(data, |block| process(ihv, block, block_count, collision, *use_ubc));
	}

	/// The SHA-1 digest of everything fed in, or a [`Collision`] if any block was half of a collision attack.
	pub fn finish(self) -> Result<[u8; LEN], Collision> {
		let Self { mut ihv, blocks, mut block_count, mut collision, use_ubc } = self;
		blocks.finish(|block| process(&mut ihv, block, &mut block_count, &mut collision, use_ubc));
		let digest = sha1::to_bytes(&ihv);
		match collision {
			None => Ok(digest),
			Some(block) => Err(Collision { block_offset: block * BLOCK as u64, hardened_digest: digest }),
		}
	}

	/// The digest of `data`, in one call.
	pub fn digest(data: &[u8]) -> Result<[u8; LEN], Collision> {
		let mut h = Self::new();
		h.update(data);
		h.finish()
	}
}

impl Default for Sha1Checked {
	fn default() -> Self {
		Self::new()
	}
}

impl Hasher for Sha1Checked {
	type Digest = [u8; LEN];
	type Error = Collision;
	const NAME: &'static str = "sha1";
	const LEN: usize = LEN;

	fn update(&mut self, data: &[u8]) {
		Sha1Checked::update(self, data);
	}

	fn finish(self) -> Result<[u8; LEN], Collision> {
		Sha1Checked::finish(self)
	}
}

impl std::io::Write for Sha1Checked {
	fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
		self.update(buf);
		Ok(buf.len())
	}

	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}

/// The data is one half of a SHA-1 collision attack: it contains a block that, with another block an attacker made
/// to go with it, gives the same SHA-1. Its SHA-1 can't be trusted to identify it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Collision {
	block_offset: u64,
	hardened_digest: [u8; LEN],
}

impl Collision {
	/// Where the first colliding block starts, in bytes from the start of the data.
	pub fn block_offset(&self) -> u64 {
		self.block_offset
	}

	/// The digest with each colliding block hashed three times instead of once, so its twin no longer matches. Not the
	/// data's SHA-1: git reports this one, as in "SHA-1 appears to be part of a collision attack: <digest>".
	pub fn hardened_digest(&self) -> [u8; LEN] {
		self.hardened_digest
	}
}

impl fmt::Display for Collision {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "SHA-1 collision attack: the 64-byte block at byte {} is half of a near-collision pair (hardened digest ", self.block_offset)?;
		for b in self.hardened_digest {
			write!(f, "{b:02x}")?;
		}
		write!(f, ")")
	}
}

impl std::error::Error for Collision {}

/// Compress one block into `ihv`, checking it against every disturbance vector.
fn process(ihv: &mut State, block: &[u8; BLOCK], block_count: &mut u64, collision: &mut Option<u64>, use_ubc: bool) {
	let w = sha1::expand(block);
	let mut s = *ihv;
	let mut stored = [[0; 5]; 2];
	sha1::steps(&mut s, &w, 0..STORED_STEPS[0]);
	stored[0] = s;
	sha1::steps(&mut s, &w, STORED_STEPS[0]..STORED_STEPS[1]);
	stored[1] = s;
	sha1::steps(&mut s, &w, STORED_STEPS[1]..80);
	sha1::add(ihv, &s);

	let mask = if use_ubc { ubc::ubc_check(&w) } else { !0 };
	if mask != 0 && collides(ihv, &w, &stored, mask) {
		collision.get_or_insert(*block_count);
		// Hardening: two more passes, so neither half of the pair keeps the colliding digest.
		sha1::compress(ihv, &w);
		sha1::compress(ihv, &w);
	}
	*block_count += 1;
}

/// Whether the block with expanded message `w`, whose output chaining value is `ihv_out`, collides with the block
/// any vector in `mask` pairs it with.
fn collides(ihv_out: &State, w: &Expanded, stored: &[State; 2], mask: u32) -> bool {
	ubc::DVS.iter().enumerate().filter(|(i, _)| mask >> i & 1 == 1).any(|(_, dv)| {
		let mut twin = [0; 80];
		for ((t, m), d) in twin.iter_mut().zip(w).zip(&dv.dm) {
			*t = m ^ d;
		}
		let state = if dv.test_step == STORED_STEPS[0] { stored[0] } else { stored[1] };
		recompress(&twin, dv.test_step, state) == *ihv_out
	})
}

/// The output chaining value of message `w` run from `state`, the state before step `t`: back to step 0 for the input
/// chaining value, then forward from `t` to the end, added to it.
fn recompress(w: &Expanded, t: usize, state: State) -> State {
	let mut ihv_in = state;
	for step in (0..t).rev() {
		sha1::step_back(&mut ihv_in, w, step);
	}
	let mut s = state;
	sha1::steps(&mut s, w, t..80);
	let mut out = ihv_in;
	sha1::add(&mut out, &s);
	out
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::Sha1;

	const SHATTERED_1: &[u8] = include_bytes!("../../tests/data/shattered-1-prefix.bin");
	const SHATTERED_2: &[u8] = include_bytes!("../../tests/data/shattered-2-prefix.bin");
	const SHA_MBLES_1: &[u8] = include_bytes!("../../tests/data/sha-mbles-1.bin");
	const SHA_MBLES_2: &[u8] = include_bytes!("../../tests/data/sha-mbles-2.bin");
	const ATTACKS: [(&str, &[u8]); 4] = [("shattered-1", SHATTERED_1), ("shattered-2", SHATTERED_2), ("sha-mbles-1", SHA_MBLES_1), ("sha-mbles-2", SHA_MBLES_2)];

	fn checked(data: &[u8], use_ubc: bool) -> Result<[u8; LEN], Collision> {
		let mut h = Sha1Checked::new();
		h.use_ubc = use_ubc;
		h.update(data);
		h.finish()
	}

	/// Deterministic pseudo-random bytes.
	fn noise(len: usize, seed: u64) -> Vec<u8> {
		let mut x = seed | 1;
		(0..len)
			.map(|_| {
				x ^= x << 13;
				x ^= x >> 7;
				x ^= x << 17;
				x as u8
			})
			.collect()
	}

	#[test]
	fn the_fixtures_are_real_collisions() {
		assert_ne!(SHATTERED_1, SHATTERED_2);
		assert_eq!(Sha1::digest(SHATTERED_1), Sha1::digest(SHATTERED_2));
		assert_ne!(SHA_MBLES_1, SHA_MBLES_2);
		assert_eq!(Sha1::digest(SHA_MBLES_1), Sha1::digest(SHA_MBLES_2));
	}

	#[test]
	fn detects_shattered_and_sha_mbles() {
		for (name, data) in ATTACKS {
			let c = Sha1Checked::digest(data).expect_err(name);
			assert_eq!(c.block_offset() % 64, 0, "{name}");
			assert!(c.block_offset() < data.len() as u64, "{name}");
			assert_ne!(c.hardened_digest(), Sha1::digest(data), "{name}: the hardened digest must differ from SHA-1's");
			// The finding doesn't depend on where the data was split.
			let mut h = Sha1Checked::new();
			for piece in data.chunks(7) {
				h.update(piece);
			}
			assert_eq!(h.finish(), Err(c), "{name}, fed in pieces");
		}
		// The two halves of each pair no longer share a digest.
		let hardened = |d| Sha1Checked::digest(d).expect_err("an attack").hardened_digest();
		assert_ne!(hardened(SHATTERED_1), hardened(SHATTERED_2));
		assert_ne!(hardened(SHA_MBLES_1), hardened(SHA_MBLES_2));
	}

	#[test]
	fn finds_the_attack_after_other_data() {
		// A collision only holds from the chaining value it was built on, so prefixed data hides it: it isn't one.
		let prefixed = [&b"blob 320\0"[..], SHATTERED_1].concat();
		assert_eq!(Sha1Checked::digest(&prefixed), Ok(Sha1::digest(&prefixed)));
		// Data after the attack doesn't.
		let suffixed = [SHATTERED_1, &noise(1000, 3)].concat();
		let c = Sha1Checked::digest(&suffixed).expect_err("the attack is still there");
		assert_eq!(c.block_offset(), Sha1Checked::digest(SHATTERED_1).expect_err("an attack").block_offset());
	}

	#[test]
	fn a_changed_byte_in_the_colliding_blocks_ends_the_collision() {
		for (name, data) in ATTACKS {
			let offset = Sha1Checked::digest(data).expect_err(name).block_offset() as usize;
			for i in [offset, offset + 1, offset + 31, offset + 63] {
				let mut changed = data.to_vec();
				changed[i] ^= 0x01;
				assert_eq!(Sha1Checked::digest(&changed), Ok(Sha1::digest(&changed)), "{name} with byte {i} changed");
			}
		}
	}

	#[test]
	fn ordinary_data_gets_plain_sha1() {
		for len in [0, 1, 55, 56, 63, 64, 65, 1000, 100_000] {
			let data = noise(len, len as u64 + 11);
			assert_eq!(Sha1Checked::digest(&data), Ok(Sha1::digest(&data)), "{len} bytes");
		}
		assert_eq!(Sha1Checked::digest(&[0; 1 << 16]), Ok(Sha1::digest(&[0; 1 << 16])));
	}

	/// The bit conditions only skip work: checking every vector on every block must find the same collisions.
	#[test]
	fn the_bit_conditions_change_no_result() {
		for (name, data) in ATTACKS {
			assert_eq!(checked(data, true), checked(data, false), "{name}");
		}
		for seed in 0..200 {
			let data = noise(64 * 4, seed);
			assert_eq!(checked(&data, true), checked(&data, false), "noise seed {seed}");
		}
	}

	/// Each attack's colliding block must meet its vector's bit conditions: if the conversion from C broke one, that
	/// vector's bit would be clear here and the attack would be missed with the check on.
	#[test]
	fn the_bit_conditions_pass_each_attack_block() {
		for (name, data) in ATTACKS {
			let offset = Sha1Checked::digest(data).expect_err(name).block_offset() as usize;
			// The chaining value going into the colliding block, and the block's own output.
			let mut ihv = INITIAL;
			for block in data[..offset].as_chunks::<64>().0 {
				sha1::compress(&mut ihv, &sha1::expand(block));
			}
			let block = data[offset..offset + 64].try_into().expect("a whole block");
			let w = sha1::expand(block);
			let mut stored = [[0; 5]; 2];
			let mut s = ihv;
			sha1::steps(&mut s, &w, 0..58);
			stored[0] = s;
			sha1::steps(&mut s, &w, 58..65);
			stored[1] = s;
			sha1::steps(&mut s, &w, 65..80);
			sha1::add(&mut ihv, &s);
			// Every vector the attack's block collides along, found by trying each alone.
			let found: Vec<usize> = (0..32).filter(|&i| collides(&ihv, &w, &stored, 1 << i)).collect();
			assert!(!found.is_empty(), "{name}: no vector collides");
			let mask = ubc::ubc_check(&w);
			for i in found {
				assert_eq!(mask >> i & 1, 1, "{name}: the bit conditions rule out vector {i}, which collides");
			}
		}
	}

	#[test]
	fn the_vector_table_is_whole() {
		assert!(ubc::DVS.iter().all(|dv| STORED_STEPS.contains(&dv.test_step)));
		// Each vector's difference follows the message expansion, as an XOR difference of two expanded blocks must.
		for (i, dv) in ubc::DVS.iter().enumerate() {
			for t in 16..80 {
				let expanded = (dv.dm[t - 3] ^ dv.dm[t - 8] ^ dv.dm[t - 14] ^ dv.dm[t - 16]).rotate_left(1);
				assert_eq!(dv.dm[t], expanded, "vector {i}, word {t}");
			}
		}
	}

	#[test]
	fn the_error_says_where() {
		let c = Sha1Checked::digest(SHATTERED_1).expect_err("an attack");
		let msg = c.to_string();
		assert!(msg.starts_with(&format!("SHA-1 collision attack: the 64-byte block at byte {} ", c.block_offset())), "{msg}");
	}
}
