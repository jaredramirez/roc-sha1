//! Usage: sha1-compare SIZE ITERATIONS
//!
//! Times the same work as bench/main.roc with two Rust crates and prints one
//! line per implementation, `name: NS`, the fastest nanoseconds per hash.

use sha1::Digest;
use std::hint::black_box;
use std::time::Instant;

fn best(iterations: u64, reps: u64, f: impl Fn() -> usize) -> u64 {
    f();
    f();
    let mut min = u64::MAX;
    for _ in 0..iterations {
        let start = Instant::now();
        let mut len = 0;
        for _ in 0..reps {
            len += black_box(f());
        }
        let ns = start.elapsed().as_nanos() as u64 / reps;
        assert!(len > 0);
        min = min.min(ns);
    }
    min
}

fn main() {
    let args: Vec<u64> = std::env::args()
        .skip(1)
        .map(|a| a.parse().expect("SIZE and ITERATIONS are numbers"))
        .collect();
    let [size, iterations] = args[..] else {
        panic!("Usage: sha1-compare SIZE ITERATIONS")
    };
    let bytes: Vec<u8> = (0..size).map(|i| (i * 31 + 7) as u8).collect();
    let reps = if size == 0 { 1 } else { (262144 + size - 1) / size };
    assert_eq!(
        sha1::Sha1::digest(&bytes)[..],
        sha1_smol::Sha1::from(&bytes).digest().bytes()[..]
    );
    let crypto = best(iterations, reps, || {
        sha1::Sha1::digest(black_box(&bytes)).len()
    });
    let smol = best(iterations, reps, || {
        sha1_smol::Sha1::from(black_box(&bytes)).digest().bytes().len()
    });
    println!("rust sha1: {crypto}");
    println!("rust sha1_smol: {smol}");
}
