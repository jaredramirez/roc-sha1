app [main!] {
	pf: platform "https://github.com/roc-lang/basic-cli/releases/download/0.28.1/7brgwR8YUqfeGrkdfF1V4GPPN7DnP7ftqub9KcrTEZtr.tar.zst",
	sha1: "../package/main.roc",
}

import pf.Monotonic
import pf.Stderr
import pf.Stdout
import sha1.Sha1

## A performance regression check. Hashing 1 MiB must stay at least
## `min_speedup` times faster than the plain textbook implementation below,
## measured in the same process, so the check works on any machine. It's
## about 4-5x on macOS and 4x on Linux, so this catches a slowdown of roughly
## 25-35%, such as falling back to loop-style rounds (about 1x) or an
## allocation per word load (2.3x). Smaller regressions, such as an extra copy
## of every block (3.8x), pass, so watch `just bench` too. Run with
## `just perf-check`, which builds with --opt=speed.
min_speedup_tenths : U64
min_speedup_tenths = 30

size : U64
size = 1024 * 1024

iterations : U64
iterations = 40

main! = |_args| {
	bytes = List.from_iter((0.U64).until(size)).map(|i| (i * 31 + 7).to_u8_wrap())
	chunks = List.from_iter((0.U64).until(size / 4096)).map(|i| bytes.sublist({ start: i * 4096, len: 4096 }))

	# The reference must agree with the library before its time means anything
	agree =
		reference(bytes) == Sha1.hash(bytes).to_bytes()
			and reference([]) == Sha1.hash([]).to_bytes()
			and reference("abc".to_utf8()) == Sha1.hash("abc".to_utf8()).to_bytes()
			and Sha1.hash_chunks(chunks.iter()) == Sha1.hash(bytes)
	if !agree {
		Stderr.line!("the reference implementation disagrees with the library")?
		return Err(Exit(1))
	}

	baseline = best!(|{}| reference(bytes).len())
	results = [
		("hash", best!(|{}| Sha1.hash(bytes).to_bytes().len())),
		("hash_chunks of 4 KiB", best!(|{}| Sha1.hash_chunks(chunks.iter()).to_bytes().len())),
	]
	var $failed = False
	for (name, ns) in results {
		tenths = baseline * 10 / ns
		verdict = if (tenths >= min_speedup_tenths) "ok" else "TOO SLOW"
		Stdout.line!("${name} of 1 MiB: ${(ns / 1000).to_str()} µs (${(size * 1000 / ns).to_str()} MB/s), reference ${(baseline / 1000).to_str()} µs, ${tenth_str(tenths)}x faster (need ${tenth_str(min_speedup_tenths)}x) ${verdict}")?
		if tenths < min_speedup_tenths {
			$failed = True
		}
	}
	if $failed {
		Err(Exit(1))
	} else {
		Ok({})
	}
}

tenth_str : U64 -> Str
tenth_str = |tenths| "${(tenths / 10).to_str()}.${(tenths % 10).to_str()}"

## The fastest of [iterations] runs of `f`, in nanoseconds, after warming up
best! : ({} -> U64) => U64
best! = |f| {
	_warm1 = f({})
	_warm2 = f({})
	_warm3 = f({})
	var $min = 0xFFFF_FFFF_FFFF_FFFF.U64
	for _ in List.from_iter((0.U64).until(iterations)) {
		start = Monotonic.now!()
		len = f({})
		ns = start.elapsed!().to_nanos()
		if len == 0 {
			crash "a run produced no output"
		}
		if ns < $min {
			$min = ns
		}
	}
	$min
}

## SHA-1 as FIPS 180-4 section 6.1.2 describes it, written plainly: pad a copy
## of the message, then for each block build the 80-word schedule in a list
## and run the rounds in a loop
reference : List(U8) -> List(U8)
reference = |message| {
	bits = message.len() * 8
	var $padded = message.append(0x80)
	while $padded.len() % 64 != 56 {
		$padded = $padded.append(0)
	}
	for i in [7, 6, 5, 4, 3, 2, 1, 0] {
		$padded = $padded.append(bits.shr_zf_wrap(i * 8).to_u8_wrap())
	}

	var $h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
	var $block = 0
	while $block < $padded.len() {
		var $w = []
		for t in List.from_iter((0.U64).until(80)) {
			word = if t < 16 {
				at = $block + t * 4
				byte_at($padded, at).shl_wrap(24)
					.bitwise_or(byte_at($padded, at + 1).shl_wrap(16))
					.bitwise_or(byte_at($padded, at + 2).shl_wrap(8))
					.bitwise_or(byte_at($padded, at + 3))
			} else {
				rotate_left(word_at($w, t - 3).bitwise_xor(word_at($w, t - 8)).bitwise_xor(word_at($w, t - 14)).bitwise_xor(word_at($w, t - 16)), 1)
			}
			$w = $w.append(word)
		}
		var $a = word_at($h, 0)
		var $b = word_at($h, 1)
		var $c = word_at($h, 2)
		var $d = word_at($h, 3)
		var $e = word_at($h, 4)
		for t in List.from_iter((0.U64).until(80)) {
			(f, k) =
				if t < 20 {
					($b.bitwise_and($c).bitwise_or($b.bitwise_not().bitwise_and($d)), 0x5A827999)
				} else if t < 40 {
					($b.bitwise_xor($c).bitwise_xor($d), 0x6ED9EBA1)
				} else if t < 60 {
					($b.bitwise_and($c).bitwise_or($b.bitwise_and($d)).bitwise_or($c.bitwise_and($d)), 0x8F1BBCDC)
				} else {
					($b.bitwise_xor($c).bitwise_xor($d), 0xCA62C1D6)
				}
			temp = rotate_left($a, 5).plus_wrap(f).plus_wrap($e).plus_wrap(k).plus_wrap(word_at($w, t))
			$e = $d
			$d = $c
			$c = rotate_left($b, 30)
			$b = $a
			$a = temp
		}
		$h = [
			word_at($h, 0).plus_wrap($a),
			word_at($h, 1).plus_wrap($b),
			word_at($h, 2).plus_wrap($c),
			word_at($h, 3).plus_wrap($d),
			word_at($h, 4).plus_wrap($e),
		]
		$block = $block + 64
	}

	var $digest = []
	for word in $h {
		for shift in [24, 16, 8, 0] {
			$digest = $digest.append(word.shr_zf_wrap(shift).to_u8_wrap())
		}
	}
	$digest
}

rotate_left : U32, U8 -> U32
rotate_left = |x, n| x.shl_wrap(n).bitwise_or(x.shr_zf_wrap(32 - n))

byte_at : List(U8), U64 -> U32
byte_at = |bytes, index|
	match bytes.get(index) {
		Ok(byte) => byte.to_u32()
		Err(OutOfBounds) => crash "the padded message is a whole number of blocks"
	}

word_at : List(U32), U64 -> U32
word_at = |words, index|
	match words.get(index) {
		Ok(word) => word
		Err(OutOfBounds) => crash "the schedule and state are indexed within their lengths"
	}
