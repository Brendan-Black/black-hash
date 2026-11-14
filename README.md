# black-hash

Hash functions with **no dependencies**: the two git names its objects with, with room for more. Works on any
platform; a sibling of [black-zlib](https://github.com/Brendan-Black/black-zlib) and
[black-serde](https://github.com/Brendan-Black/black-serde).

| Type | What it is |
| --- | --- |
| `Sha1` | SHA-1 (FIPS 180-4) |
| `Sha1Checked` | SHA-1 that detects the known collision attacks and refuses data built with them, as git hashes objects |
| `Sha256` | SHA-256 (FIPS 180-4) |

Each has `new`, `update`, `finish` and a one-call `digest`, and implements `io::Write`, so `io::copy` hashes a file of
any size. The `Hasher` trait covers all of them for code that takes any algorithm (a git object ID may be SHA-1 or
SHA-256). Its `finish` returns a `Result`: `Infallible` for the plain hashes, `Collision` for `Sha1Checked`.

```rust
use black_hash::{Sha1, Sha1Checked, Sha256};

let id = Sha1Checked::digest(b"blob 5\0hello")?; // git's object ID for "hello"
assert_eq!(Sha1::digest(b"blob 5\0hello"), id);
let id256 = Sha256::digest(b"blob 5\0hello");
```

## Collision detection

`Sha1Checked` is a port of [sha1collisiondetection](https://github.com/cr-marcstevens/sha1collisiondetection) by Marc
Stevens and Dan Shumow, the SHA-1 git uses. Every practical collision attack on SHA-1 (SHAttered in 2017, SHA-mbles in
2020) builds near-collision blocks along one of 32 known disturbance vectors. Each block is checked against them: cheap
bit conditions rule most vectors out, and for each one left, the block an attacker would pair with this one is
recomputed from a state saved mid-compression. If it gives the same output, the data is one half of an attack, and
`finish` returns `Err(Collision)`. The error says which block, and carries git's "hardened" digest, which hashes that
block three times so the pair no longer match. Git prints that digest in its "SHA-1 appears to be part of a collision
attack" error.

Ordinary data gives exactly SHA-1's digest. The detection costs about a quarter of plain SHA-1's speed.

The disturbance vector table and bit conditions in `src/sha1dc/ubc.rs` were converted mechanically from the C
original's generated `ubc_check.c`, and carry its MIT license notice.

## Speed

Software only for now, measured on 256 MB:

| | black-hash | For comparison |
| --- | --- | --- |
| `Sha1` | 615 MB/s | `sha1sum` (SHA-NI): 1970 MB/s |
| `Sha1Checked` | 447 MB/s | `git hash-object`, the C original: 743 MB/s |
| `Sha256` | 405 MB/s | `sha256sum` (SHA-NI): 2081 MB/s |

The crate is `#![forbid(unsafe_code)]`. Hardware SHA (x86 SHA extensions, ARMv8 crypto) for `Sha1` and `Sha256` is
planned. It needs `std::arch` intrinsics, so it will be the crate's only `unsafe`: one module, chosen at run time
when the CPU has the instructions, with each block saying why it is sound. Collision detection can't use those
instructions, since it needs the states between steps.

## Adding an algorithm

A new algorithm is a module with its type, `new`/`update`/`finish`/`digest`, and impls of `Hasher`, `Default` and
`io::Write`. A Merkle-Damgård hash with 64-byte blocks (as SHA-1 and SHA-256 are) reuses `block::Blocks` for the
buffering and padding. One with 128-byte blocks (SHA-512) needs that generalized over the block size and length
field. Other designs (BLAKE3) bring their own.

## Tests

`cargo test` runs everywhere:
- the FIPS 180 examples
- the SHAttered and SHA-mbles collision pairs in `tests/data`: both detected, and not with any byte of the colliding
  block changed
- collision detection against checking every vector without the bit conditions
- the vector table against SHA-1's message expansion

`tests/tools_crosscheck.rs` also checks against the system's `sha1sum` and `sha256sum`, and against git's object IDs
in SHA-1 and SHA-256 repositories. Each part skips itself where its tool isn't installed.

## License

MIT. See [LICENSE](LICENSE).
