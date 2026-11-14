//! Hash functions with no dependencies: the two git names its objects with, and room for more.
//!
//! - [`Sha1`]: SHA-1 (FIPS 180-4).
//! - [`Sha1Checked`]: SHA-1 that detects the known collision attacks (SHAttered, SHA-mbles) and refuses data built
//!   with them, as git hashes objects. A port of Marc Stevens and Dan Shumow's sha1collisiondetection.
//! - [`Sha256`]: SHA-256 (FIPS 180-4).
//!
//! Each has inherent methods with the natural signatures, and implements [`Hasher`] for code that works with any
//! algorithm, such as a git object ID that may be SHA-1 or SHA-256.
//!
//! ```
//! use black_hash::{Sha1, Sha1Checked, Sha256};
//!
//! assert_eq!(Sha1::digest(b"abc")[..4], [0xa9, 0x99, 0x3e, 0x36]);
//! assert_eq!(Sha256::digest(b"abc")[..4], [0xba, 0x78, 0x16, 0xbf]);
//!
//! let mut h = Sha1Checked::new();
//! h.update(b"a");
//! h.update(b"bc");
//! assert_eq!(h.finish()?, Sha1::digest(b"abc"));
//! # Ok::<(), black_hash::Collision>(())
//! ```
//!
//! There is no `unsafe` code. Hardware-accelerated SHA-1 and SHA-256 (x86 SHA extensions, ARMv8 crypto) will need
//! it; when they come, they will be the only `unsafe` in the crate, each block saying why it is sound.

#![forbid(unsafe_code)]

mod block;
mod sha1;
mod sha1dc;
mod sha256;

pub use sha1::Sha1;
pub use sha1dc::{Collision, Sha1Checked};
pub use sha256::Sha256;

/// A hash algorithm, for code that works with whichever one it is given.
///
/// `io::Write` feeds it data, so `std::io::copy(&mut file, &mut hasher)` hashes a file of any size.
pub trait Hasher: Clone + Default + std::io::Write {
	/// The digest: a byte array of [`Hasher::LEN`] bytes.
	type Digest: AsRef<[u8]> + Copy + Eq + std::hash::Hash + std::fmt::Debug;
	/// What [`Hasher::finish`] can find wrong with the data: [`std::convert::Infallible`] for an algorithm that accepts
	/// everything.
	type Error: std::error::Error;

	/// The algorithm's name, as git spells it in `extensions.objectFormat`: `sha1` or `sha256`.
	const NAME: &'static str;
	/// The digest's length in bytes.
	const LEN: usize;

	/// Feed it more data.
	fn update(&mut self, data: &[u8]);

	/// The digest of everything fed in.
	fn finish(self) -> Result<Self::Digest, Self::Error>;

	/// The digest of `data`, in one call.
	fn digest(data: &[u8]) -> Result<Self::Digest, Self::Error> {
		let mut h = Self::default();
		h.update(data);
		h.finish()
	}
}
