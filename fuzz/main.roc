app [target] {
	fuzz: platform "https://github.com/lukewilliamboswell/roc-fuzz/releases/download/0.7.0/HBigHQhVZWEF2EkLxpYK35u8P6UNsAmPYxpNFTxXK1Br.tar.zst",
	sha1: "../package/main.roc",
}

import fuzz.Fuzz
import sha1.Sha1

## Raw fuzz input. `cuts` gives the widths of the chunks `data` is written in,
## and `text` is parsed as a hex digest.
Input : { data : List(U8), cuts : List(U8), text : Str }

## `data` cut into chunks of the widths in `cuts`, then the rest as one chunk
chunks_of : List(U8), List(U8) -> List(List(U8))
chunks_of = |data, cuts| {
	var $chunks = []
	var $start = 0
	for cut in cuts {
		width = cut.to_u64()
		$chunks = $chunks.append(data.sublist({ start: $start, len: width }))
		$start = $start + width
	}
	$chunks.append(data.drop_first($start))
}

is_hex_digit : U8 -> Bool
is_hex_digit = |c| (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F')

lowercase : U8 -> U8
lowercase = |c| if (c >= 'A' and c <= 'Z') c + 32 else c

uppercase : U8 -> U8
uppercase = |c| if (c >= 'a' and c <= 'z') c - 32 else c

## `from_hex` accepts exactly the 40-byte strings of hex digits, and otherwise
## reports the first bad byte or the wrong length
check_from_hex : Str -> {}
check_from_hex = |text| {
	chars = text.to_utf8()
	match Sha1.Digest.from_hex(text) {
		Ok(digest) if chars.len() == 40 and chars.all(is_hex_digit) and digest.to_hex().to_utf8() == chars.map(lowercase) => {}
		Ok(_) => crash "from_hex accepted something that is not 40 hex digits, or decoded it wrongly"
		Err(WrongLength({ expected: 40, actual })) if actual == chars.len() and actual != 40 => {}
		Err(WrongLength(_)) => crash "from_hex reported the wrong length"
		Err(InvalidHex({ index, byte })) if chars.len() == 40 and chars.get(index) == Ok(byte) and !is_hex_digit(byte) and chars.take_first(index).all(is_hex_digit) => {}
		Err(InvalidHex(_)) => crash "from_hex did not report the first bad byte"
	}
}

## Chunked and incremental hashing agree with one-shot hashing however the
## input is cut, a snapshot of the state is unaffected by later writes, digests
## round trip through bytes and hex in either case, and `from_bytes` and
## `from_hex` accept exactly the valid inputs
test! : Input => Fuzz.Outcome
test! = |{ data, cuts, text }| {
	# A known answer, so the comparisons below can't all agree on a wrong
	# digest. Digests are compared by their bytes, not `==`, so a broken
	# `is_eq` can't hide a disagreement.
	# (`take_first(0)` keeps the compiler from evaluating it at compile time)
	if Sha1.hash("abc".to_utf8().concat(data.take_first(0))).to_hex() != "a9993e364706816aba3e25717850c26c9cd0d89d" {
		crash "the known answer for abc is wrong"
	}
	digest = Sha1.hash(data)
	bytes = digest.to_bytes()
	chunks = chunks_of(data, cuts)
	if Sha1.hash_chunks(chunks.iter()).to_bytes() != bytes {
		crash "hash_chunks disagrees with hash"
	}
	first = chunks.first() ?? []
	after_first = Sha1.State.empty().write(first)
	snapshot = after_first.finish()
	all = chunks.drop_first(1).fold(after_first, |state, chunk| state.write(chunk))
	if all.finish().to_bytes() != bytes {
		crash "State.write disagrees with hash"
	}
	if snapshot.to_bytes() != Sha1.hash(first).to_bytes() or after_first.finish().to_bytes() != snapshot.to_bytes() {
		crash "writing after a snapshot changed it"
	}

	hex = digest.to_hex()
	if Sha1.Digest.from_hex(hex).map_ok(|d| d.to_bytes()) != Ok(bytes) or Sha1.Digest.from_bytes(bytes).map_ok(|d| d.to_bytes()) != Ok(bytes) {
		crash "a digest did not round trip"
	}
	if Sha1.Digest.from_hex(Str.from_utf8_lossy(hex.to_utf8().map(uppercase))).map_ok(|d| d.to_bytes()) != Ok(bytes) {
		crash "uppercase hex did not decode"
	}

	match Sha1.Digest.from_bytes(data) {
		Ok(d) if data.len() == 20 and d.to_bytes() == data => {}
		Ok(_) => crash "from_bytes accepted the wrong length or changed the bytes"
		Err(WrongLength({ expected: 20, actual })) if actual == data.len() and actual != 20 => {}
		Err(WrongLength(_)) => crash "from_bytes reported the wrong length"
	}

	check_from_hex(text)
	# Arbitrary strings are rarely 40 bytes long, so also corrupt a valid hex
	# digest with a byte of the input
	position = (cuts.first() ?? 0).to_u64() % 40
	corrupted = hex.to_utf8().take_first(position).concat(data.take_first(1)).concat(hex.to_utf8().drop_first(position + 1))
	match Str.from_utf8(corrupted) {
		Ok(corrupted_text) => check_from_hex(corrupted_text)
		Err(_) => {}
	}
	Fuzz.keep
}

target = Fuzz.target_with!({
	examples: [
		Fuzz.example({ name: "empty", revision: "1", make: || { data: [], cuts: [], text: "" } }),
		Fuzz.example({ name: "abc", revision: "1", make: || { data: "abc".to_utf8(), cuts: [1, 0, 1], text: "A9993E364706816ABA3E25717850C26C9CD0D89D" } }),
		Fuzz.example({ name: "padding-edge", revision: "1", make: || { data: List.repeat('a', 120), cuts: [55, 9, 0, 56], text: "a9993e364706816aba3e25717850c26c9cd0d8zz" } }),
	],
	name: "sha1",
	generator: Fuzz.map2(
		Fuzz.map2(Fuzz.bytes, Fuzz.bytes, |data, cuts| { data, cuts }),
		Fuzz.str,
		|{ data, cuts }, text| { data, cuts, text },
	),
	test!,
	show: |input| Str.inspect(input),
})
