app [main!] {
	pf: platform "https://github.com/roc-lang/basic-cli/releases/download/0.28.1/7brgwR8YUqfeGrkdfF1V4GPPN7DnP7ftqub9KcrTEZtr.tar.zst",
	sha1: "../package/main.roc",
}

import pf.Monotonic
import pf.OsStr
import pf.Stderr
import pf.Stdout
import sha1.Sha1

## Usage: bench/main.roc SIZE ITERATIONS
##
## Hashes SIZE bytes ITERATIONS times, one shot and in 4 KiB writes, after two
## warm-up runs, and prints the fastest time for each in nanoseconds with the
## throughput.
main! : List(OsStr) => Try({}, _)
main! = |os_args|
	match os_args.map(OsStr.display).map(U64.from_str) {
		[Ok(size), Ok(iterations)] => {
			bytes = List.from_iter((0.U64).until(size)).map(|i| (i * 31 + 7).to_u8_wrap())
			chunks = split_every(bytes, 4096)
			if Sha1.hash_chunks(chunks.iter()) != Sha1.hash(bytes) {
				Stderr.line!("chunked hashing disagrees with one-shot hashing")?
				return Err(Exit(1))
			}
			# Each sample times enough calls to cover 256 KiB, for timer resolution
			reps = if (size == 0) 1 else (262144 + size - 1) / size
			one_shot = best!(iterations, reps, |{}| Sha1.hash(bytes).to_bytes().len())
			chunked = best!(iterations, reps, |{}| Sha1.hash_chunks(chunks.iter()).to_bytes().len())
			Stdout.line!("hash ${size.to_str()} bytes: ${show(one_shot, size)}")?
			Stdout.line!("hash_chunks of 4 KiB: ${show(chunked, size)}")?
			Ok({})
		}
		_ => {
			Stderr.line!("Usage: bench/main.roc SIZE ITERATIONS")?
			Err(Exit(1))
		}
	}

## Nanoseconds and MB/s (10^6 bytes per second)
show : U64, U64 -> Str
show = |ns, size| {
	mb_per_s = if (ns == 0) 0 else size * 1000 / ns
	"${ns.to_str()} ns, ${mb_per_s.to_str()} MB/s"
}

split_every : List(U8), U64 -> List(List(U8))
split_every = |bytes, width| {
	var $chunks = []
	var $start = 0
	while $start < bytes.len() {
		$chunks = $chunks.append(bytes.sublist({ start: $start, len: width }))
		$start = $start + width
	}
	$chunks
}

## The fastest of `iterations` samples of `reps` runs of `f`, in nanoseconds
## per run. Each run's output length is checked, so the work cannot be skipped.
best! : U64, U64, ({} -> U64) => U64
best! = |iterations, reps, f| {
	_warm1 = f({})
	_warm2 = f({})
	var $min = 0xFFFF_FFFF_FFFF_FFFF.U64
	for _ in List.from_iter((0.U64).until(iterations)) {
		start = Monotonic.now!()
		var $len = 0
		for _ in List.from_iter((0.U64).until(reps)) {
			$len = $len + f({})
		}
		ns = start.elapsed!().to_nanos() / reps
		if $len == 0 {
			crash "a run produced no output"
		}
		if ns < $min {
			$min = ns
		}
	}
	$min
}
