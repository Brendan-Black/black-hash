//! Checks the hashes against other implementations: the system's `sha1sum` and `sha256sum`, and git, which names
//! objects with collision-detecting SHA-1 or with SHA-256. Each part skips itself (passing) where its tool isn't
//! installed, as on Windows.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use black_hash::{Hasher, Sha1, Sha1Checked, Sha256};

/// Run `program` with `args`, feeding it `input`; `None` if it isn't installed.
fn run(program: &str, args: &[&str], input: &[u8]) -> Option<String> {
	let mut child = Command::new(program).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().ok()?;
	let mut stdin = child.stdin.take().expect("stdin was piped");
	let input = input.to_vec();
	// Write on another thread so a full output pipe can't deadlock us.
	let writer = std::thread::spawn(move || stdin.write_all(&input));
	let out = child.wait_with_output().expect("waiting for the tool");
	writer.join().expect("the writer thread").expect("writing the tool's input");
	assert!(out.status.success(), "{program} {args:?} failed");
	Some(String::from_utf8(out.stdout).expect("the tool's output is text"))
}

fn hex(d: &[u8]) -> String {
	d.iter().map(|b| format!("{b:02x}")).collect()
}

fn samples() -> Vec<Vec<u8>> {
	let mut seed = 0x0123_4567_89AB_CDEF_u64;
	let noise: Vec<u8> = (0..300_000)
		.map(|_| {
			seed ^= seed << 13;
			seed ^= seed >> 7;
			seed ^= seed << 17;
			seed as u8
		})
		.collect();
	let mut v = vec![vec![], b"a".to_vec(), "hello hello hello, said the echo; ".repeat(2000).into_bytes(), vec![0; 3 << 20], noise];
	// Every length across the padding boundaries.
	v.extend((50..=130).map(|n| (0..n).map(|i| i as u8).collect()));
	v
}

/// The first word of each line of the tool's output, one per sample, for tools that take several files at once.
fn sum_tool(tool: &str) -> Option<Vec<String>> {
	static N: AtomicUsize = AtomicUsize::new(0);
	let dir = std::env::temp_dir().join(format!("black-hash-{tool}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
	std::fs::create_dir_all(&dir).expect("creating a temporary directory");
	let paths: Vec<PathBuf> = samples()
		.iter()
		.enumerate()
		.map(|(i, data)| {
			let p = dir.join(format!("{i}"));
			std::fs::write(&p, data).expect("writing a sample");
			p
		})
		.collect();
	let args: Vec<&str> = paths.iter().map(|p| p.to_str().expect("a UTF-8 temporary path")).collect();
	let out = run(tool, &args, b"");
	std::fs::remove_dir_all(&dir).expect("removing the temporary directory");
	if out.is_none() {
		eprintln!("{tool} isn't installed; skipping");
	}
	Some(out?.lines().map(|l| l.split_whitespace().next().expect("a digest on each line").to_owned()).collect())
}

#[test]
fn sha1sum_agrees() {
	let Some(theirs) = sum_tool("sha1sum") else { return };
	for (data, want) in samples().iter().zip(&theirs) {
		assert_eq!(&hex(&Sha1::digest(data)), want, "{} bytes", data.len());
		assert_eq!(&hex(&Sha1Checked::digest(data).expect("not an attack")), want, "{} bytes, checked", data.len());
	}
}

#[test]
fn sha256sum_agrees() {
	let Some(theirs) = sum_tool("sha256sum") else { return };
	for (data, want) in samples().iter().zip(&theirs) {
		assert_eq!(&hex(&Sha256::digest(data)), want, "{} bytes", data.len());
	}
}

/// A git object's ID, as `H` computes it: the hash of `blob <size>\0` and the data.
fn blob_id<H: Hasher>(data: &[u8]) -> String
where
	H::Error: std::fmt::Debug,
{
	let mut h = H::default();
	h.update(format!("blob {}\0", data.len()).as_bytes());
	h.update(data);
	hex(h.finish().expect("not an attack").as_ref())
}

/// The ID git gives `data` as a blob in a new repository of `format`, or `None` without git.
fn git_blob_id(repo: &Path, data: &[u8]) -> Option<String> {
	Some(run("git", &["-C", repo.to_str().expect("a UTF-8 temporary path"), "hash-object", "--stdin"], data)?.trim().to_owned())
}

fn git_repo(format: &str) -> Option<PathBuf> {
	let dir = std::env::temp_dir().join(format!("black-hash-git-{format}-{}", std::process::id()));
	// Left over from an earlier run that failed, at most.
	match std::fs::remove_dir_all(&dir) {
		Err(e) if e.kind() != std::io::ErrorKind::NotFound => panic!("removing {}: {e}", dir.display()),
		_ => {}
	}
	run("git", &["init", "--quiet", "--bare", &format!("--object-format={format}"), dir.to_str().expect("a UTF-8 temporary path")], b"").or_else(|| {
		eprintln!("git isn't installed; skipping");
		None
	})?;
	Some(dir)
}

fn git_agrees<H: Hasher>(format: &str)
where
	H::Error: std::fmt::Debug,
{
	assert_eq!(H::NAME, format);
	let Some(repo) = git_repo(format) else { return };
	for data in samples().iter().take(5) {
		assert_eq!(Some(blob_id::<H>(data)), git_blob_id(&repo, data), "{} bytes in a {format} repository", data.len());
	}
	std::fs::remove_dir_all(&repo).expect("removing the temporary repository");
}

#[test]
fn git_agrees_on_sha1_object_ids() {
	git_agrees::<Sha1Checked>("sha1");
}

#[test]
fn git_agrees_on_sha256_object_ids() {
	git_agrees::<Sha256>("sha256");
}
