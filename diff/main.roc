app [main!] {
	pf: platform "https://github.com/roc-lang/basic-cli/releases/download/0.28.1/7brgwR8YUqfeGrkdfF1V4GPPN7DnP7ftqub9KcrTEZtr.tar.zst",
	sha1: "../package/main.roc",
}

import pf.Cmd
import pf.OsStr
import pf.Random
import pf.Stderr
import pf.Stdout
import sha1.Sha1

usage =
	\\Compare this package against GNU coreutils (sha1sum) and OpenSSL
	\\(openssl dgst -sha1) on random inputs. Each input is also hashed in random
	\\chunks, through both hash_chunks and State, which must agree with the
	\\one-shot digest.
	\\
	\\Usage: diff/main.roc [--count INTEGER] [--seed INTEGER]
	\\
	\\  --count INTEGER  How many random inputs to check (default 300)
	\\  --seed INTEGER   Reproduce a run (default: fresh randomness)
	\\  --help           Show this message

Args : { count : U64, seed : [Fixed(U64), Fresh], help : Bool }

parse_args : List(Str), Args -> Try(Args, [BadArgs(Str)])
parse_args = |args, parsed|
	match args {
		[] => Ok(parsed)
		["--help", .. as rest] => parse_args(rest, { ..parsed, help: True })
		["--count", value, .. as rest] =>
			match U64.from_str(value) {
				Ok(count) => parse_args(rest, { ..parsed, count })
				Err(_) => Err(BadArgs("--count must be a non-negative integer, but got ${value}"))
			}
		["--seed", value, .. as rest] =>
			match U64.from_str(value) {
				Ok(seed) => parse_args(rest, { ..parsed, seed: Fixed(seed) })
				Err(_) => Err(BadArgs("--seed must be a non-negative integer, but got ${value}"))
			}
		[other, ..] => Err(BadArgs("Unknown or incomplete argument: ${other}"))
	}

## SplitMix64: the next state and a random number
next : U64 -> (U64, U64)
next = |state| {
	s = state.plus_wrap(0x9E3779B97F4A7C15)
	z1 = s.bitwise_xor(s.shr_zf_wrap(30)).times_wrap(0xBF58476D1CE4E5B9)
	z2 = z1.bitwise_xor(z1.shr_zf_wrap(27)).times_wrap(0x94D049BB133111EB)
	(s, z2.bitwise_xor(z2.shr_zf_wrap(31)))
}

## `count` random bytes
random_bytes : U64, U64 -> (U64, List(U8))
random_bytes = |state, count| {
	var $state = state
	var $bytes = List.with_capacity(count)
	for _ in List.from_iter((0.U64).until(count)) {
		(s, n) = next($state)
		$state = s
		$bytes = $bytes.append(n.to_u8_wrap())
	}
	($state, $bytes)
}

## `bytes` cut into random pieces of 0 to 150 bytes, empty pieces included
random_chunks : U64, List(U8) -> (U64, List(List(U8)))
random_chunks = |state, bytes| {
	var $state = state
	var $chunks = []
	var $start = 0
	while $start < bytes.len() {
		(s, n) = next($state)
		$state = s
		width = n % 151
		$chunks = $chunks.append(bytes.sublist({ start: $start, len: width }))
		$start = $start + width
	}
	($state, $chunks)
}

## Run `program` with `input` on standard input, and return the first 40
## characters of its output, where both tools print the hex digest
digest_tool! : Str, List(Str), List(U8) => Try(Str, [ToolFailed(Str)])
digest_tool! = |program, args, input| {
	command = Str.join_with([program].concat(args), " ")
	output = Cmd.new(OsStr.from_str(program))
		.args(args.map(OsStr.from_str))
		.stdin(Bytes(input))
		.run!() ? |err| ToolFailed("${command}: ${Str.inspect(err)}")
	match output.status {
		Exited(0) if output.stdout_bytes.len() >= 40 => Ok(Str.from_utf8_lossy(output.stdout_bytes.take_first(40)))
		_ => Err(ToolFailed("${command} failed: ${Str.from_utf8_lossy(output.stderr_bytes)}"))
	}
}

## Ours and theirs, for one comparison that differed
Mismatch : { check : Str, len : U64, ours : Str, theirs : Str }

## Every comparison for one input
check_input! : List(U8), List(List(U8)) => Try(List(Mismatch), [ToolFailed(Str)])
check_input! = |input, chunks| {
	ours = Sha1.hash(input).to_hex()
	var $mismatches = []
	for (check, theirs) in [
		("hash vs sha1sum", digest_tool!("sha1sum", [], input)?),
		("hash vs openssl dgst -sha1", digest_tool!("openssl", ["dgst", "-sha1", "-r"], input)?),
		("hash_chunks vs hash", Sha1.hash_chunks(chunks.iter()).to_hex()),
		("State.write vs hash", chunks.fold(Sha1.State.empty(), |state, chunk| state.write(chunk)).finish().to_hex()),
	] {
		if theirs != ours {
			$mismatches = $mismatches.append({ check, len: input.len(), ours, theirs })
		}
	}
	Ok($mismatches)
}

## Fail unless `sha1sum` is GNU coreutils, which devenv provides
require_gnu! : Str => Try({}, [ToolFailed(Str)])
require_gnu! = |program| {
	output = Cmd.new(OsStr.from_str(program))
		.args([OsStr.from_str("--version")])
		.run!() ? |err| ToolFailed("${program}: ${Str.inspect(err)}")
	if Str.from_utf8_lossy(output.stdout_bytes).contains("GNU coreutils") {
		Ok({})
	} else {
		Err(ToolFailed("${program} is not GNU coreutils, so run inside `devenv shell`"))
	}
}

## Comparisons per input
checks_per_input : U64
checks_per_input = 4

run! = |os_args| {
	args = parse_args(os_args.map(OsStr.display), { count: 300, seed: Fresh, help: False })?
	if args.help {
		Stdout.line!(usage)?
		return Ok({})
	}
	require_gnu!("sha1sum")?

	seed = match args.seed {
		Fixed(value) => value
		Fresh => Random.seed_u64!()?
	}

	var $state = seed
	var $mismatches = []
	var $bytes = 0.U64
	for case in List.from_iter((0.U64).until(args.count)) {
		# Mostly short inputs, which cover every padding case, some that span
		# many blocks, and a few large ones
		(s1, a) = next($state)
		len = match case % 50 {
			49 => a % 200_000
			n if n % 10 == 9 => a % 5000
			_ => a % 300
		}
		(s2, input) = random_bytes(s1, len)
		(s3, chunks) = random_chunks(s2, input)
		$state = s3
		$bytes = $bytes + len
		$mismatches = $mismatches.concat(check_input!(input, chunks)?)
	}

	for m in $mismatches.take_first(10) {
		Stderr.line!("${m.check}, ${m.len.to_str()} bytes\n  ours:   ${m.ours}\n  theirs: ${m.theirs}")?
	}
	summary = "${args.count.to_str()} inputs (${$bytes.to_str()} bytes), ${(args.count * checks_per_input).to_str()} comparisons, ${$mismatches.len().to_str()} mismatches (--seed ${seed.to_str()})"
	if $mismatches.is_empty() {
		Stdout.line!(summary)?
		Ok({})
	} else {
		Err(Mismatches(summary))
	}
}

main! : List(OsStr) => Try({}, _)
main! = |args|
	match run!(args) {
		Ok({}) => Ok({})
		Err(err) => {
			message = match err {
				BadArgs(msg) => "${msg}\n\n${usage}"
				ToolFailed(msg) => msg
				Mismatches(summary) => summary
				other => "Unexpected error: ${Str.inspect(other)}"
			}
			Stderr.line!(message)?
			Err(Exit(1))
		}
	}
