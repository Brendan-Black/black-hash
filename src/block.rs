//! The Merkle-Damgård framing SHA-1 and SHA-256 share: 64-byte blocks, and padding that ends with the message's
//! length in bits as a big-endian 64-bit number.

pub(crate) const BLOCK: usize = 64;

/// Collects data into whole blocks for a compression function.
#[derive(Clone)]
pub(crate) struct Blocks {
	/// A partial block waiting for more data.
	pending: [u8; BLOCK],
	pending_len: usize,
	/// Bytes taken in so far.
	total: u64,
}

impl Blocks {
	pub(crate) const fn new() -> Self {
		Self { pending: [0; BLOCK], pending_len: 0, total: 0 }
	}

	/// Take in `data`, calling `compress` on each block it completes.
	pub(crate) fn update(&mut self, mut data: &[u8], mut compress: impl FnMut(&[u8; BLOCK])) {
		self.total = self.total.wrapping_add(data.len() as u64);
		if self.pending_len > 0 {
			let take = data.len().min(BLOCK - self.pending_len);
			self.pending[self.pending_len..self.pending_len + take].copy_from_slice(&data[..take]);
			self.pending_len += take;
			data = &data[take..];
			if self.pending_len < BLOCK {
				return;
			}
			compress(&self.pending);
			self.pending_len = 0;
		}
		let (blocks, rest) = data.as_chunks::<BLOCK>();
		for block in blocks {
			compress(block);
		}
		self.pending[..rest.len()].copy_from_slice(rest);
		self.pending_len = rest.len();
	}

	/// Pad the message and compress its last block or two.
	pub(crate) fn finish(mut self, mut compress: impl FnMut(&[u8; BLOCK])) {
		let bits = self.total.wrapping_mul(8);
		let mut tail = [0u8; 2 * BLOCK];
		tail[..self.pending_len].copy_from_slice(&self.pending[..self.pending_len]);
		tail[self.pending_len] = 0x80;
		// The length goes in the last 8 bytes of the first block it fits in.
		let end = if self.pending_len < BLOCK - 8 { BLOCK } else { 2 * BLOCK };
		tail[end - 8..end].copy_from_slice(&bits.to_be_bytes());
		let (blocks, _) = tail[..end].as_chunks::<BLOCK>();
		for block in blocks {
			compress(block);
		}
		self.pending_len = 0;
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Every block `Blocks` hands on for `parts`, fed in that order.
	fn blocks_of(parts: &[&[u8]]) -> Vec<[u8; BLOCK]> {
		let mut b = Blocks::new();
		let mut out = Vec::new();
		for part in parts {
			b.update(part, |blk| out.push(*blk));
		}
		b.finish(|blk| out.push(*blk));
		out
	}

	#[test]
	fn pads_to_whole_blocks_with_the_bit_length() {
		let one = blocks_of(&[b"abc"]);
		assert_eq!(one.len(), 1);
		assert_eq!(&one[0][..4], b"abc\x80");
		assert_eq!(one[0][63], 24);
		// 55 bytes still fit the length in the same block; 56 need another.
		assert_eq!(blocks_of(&[&[7; 55]]).len(), 1);
		assert_eq!(blocks_of(&[&[7; 56]]).len(), 2);
		assert_eq!(blocks_of(&[&[7; 64]]).len(), 2);
		assert_eq!(
			blocks_of(&[b""]),
			[{
				let mut b = [0; 64];
				b[0] = 0x80;
				b
			}]
		);
	}

	#[test]
	fn splitting_the_input_changes_nothing() {
		let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 + i / 13) as u8).collect();
		let whole = blocks_of(&[&data]);
		for cut in [0, 1, 55, 63, 64, 65, 128, 999, 1000] {
			assert_eq!(blocks_of(&[&data[..cut], &data[cut..]]), whole, "cut at {cut}");
		}
		let bytes: Vec<&[u8]> = data.chunks(1).collect();
		assert_eq!(blocks_of(&bytes), whole);
	}
}
