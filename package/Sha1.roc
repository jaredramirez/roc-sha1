## SHA-1 as specified in [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final),
## with the same API as the builtin `Crypto.SHA256`.
##
## SHA-1 is broken for collision resistance. Use it where a protocol or format
## requires it, such as UUIDv5, git object IDs, and WebSocket handshakes. Never
## use it for signatures, certificates, or passwords.
##
## ```roc
## digest = Sha1.hash("abc".to_utf8())
## digest.to_hex() == "a9993e364706816aba3e25717850c26c9cd0d89d"
## ```
Sha1 := [].{

	## Why [Digest.from_bytes] rejected its input. A digest is exactly 20 bytes.
	DigestBytesErr := [WrongLength({ expected : U64, actual : U64 })].{
		is_eq : _
		to_hash : _
	}

	## Why [Digest.from_hex] rejected its input. A digest is exactly 40 hex
	## characters. `index` counts bytes of the string's UTF-8, and `byte` is the
	## byte found there.
	DigestHexErr := [
		WrongLength({ expected : U64, actual : U64 }),
		InvalidHex({ index : U64, byte : U8 }),
	].{
		is_eq : _
		to_hash : _
	}

	## A SHA-1 digest.
	Digest :: { bytes : List(U8) }.{

		## Return this digest as its 20 raw bytes.
		to_bytes : Digest -> List(U8)
		to_bytes = |digest| digest.bytes

		## Return this digest as 40 lowercase hexadecimal characters.
		to_hex : Digest -> Str
		to_hex = |digest| {
			var $out = List.with_capacity(hex_len)
			for byte in digest.bytes {
				$out = $out.append(hex_digit(byte.shr_zf_wrap(4))).append(hex_digit(byte.bitwise_and(15)))
			}
			# The output is ASCII by construction, so no bytes are ever replaced
			Str.from_utf8_lossy($out)
		}

		## Build a digest from exactly 20 raw bytes.
		from_bytes : List(U8) -> Try(Digest, DigestBytesErr)
		from_bytes = |bytes|
			if bytes.len() == digest_len {
				Ok(Digest.{ bytes })
			} else {
				Err(DigestBytesErr.WrongLength({ expected: digest_len, actual: bytes.len() }))
			}

		## Build a digest from exactly 40 ASCII hex characters. Uppercase and
		## lowercase are accepted, and a `0x` prefix is not.
		from_hex : Str -> Try(Digest, DigestHexErr)
		from_hex = |hex| {
			chars = hex.to_utf8()
			if chars.len() != hex_len {
				return Err(DigestHexErr.WrongLength({ expected: hex_len, actual: chars.len() }))
			}
			var $out = List.with_capacity(digest_len)
			var $failure = NoFailure
			var $index = 0
			while $index < hex_len {
				high = char_at(chars, $index)
				low = char_at(chars, $index + 1)
				match (hex_value(high), hex_value(low)) {
					(Ok(h), Ok(l)) => {
						$out = $out.append(h.shl_wrap(4).bitwise_or(l))
					}
					(Err(NotHex), _) => {
						$failure = Failed({ index: $index, byte: high })
						break
					}
					(_, Err(NotHex)) => {
						$failure = Failed({ index: $index + 1, byte: low })
						break
					}
				}
				$index = $index + 2
			}
			match $failure {
				NoFailure => Ok(Digest.{ bytes: $out })
				Failed(problem) => Err(DigestHexErr.InvalidHex(problem))
			}
		}

		## Returns `True` if both digests contain the same bytes.
		is_eq : Digest, Digest -> Bool
		is_eq = |left, right| left.bytes == right.bytes

		## Feed the digest bytes into a regular non-cryptographic `Hasher`, so
		## digests can be `Dict` keys and `Set` elements.
		to_hash : Digest, Hasher -> Hasher
		to_hash = |digest, hasher| hasher.write_bytes(digest.bytes)

		## Return a typed, human-readable digest.
		to_inspect : Digest -> Str
		to_inspect = |digest| "Sha1.Digest(\"${digest.to_hex()}\")"
	}

	## Incremental SHA-1 hashing, the equivalent of the builtin
	## `Crypto.SHA256.Hasher`. It is not called `Hasher` because a nested type
	## with that name shadows the builtin `Hasher`, and the compiler then warns
	## in every app that uses this package.
	State :: { vars : Vars, buffer : List(U8), len : U64 }.{

		## Start a fresh SHA-1 state.
		empty : () -> State
		empty = || State.{ vars: initial_vars, buffer: [], len: 0 }

		## Add bytes to this state and return the updated state.
		write : State, List(U8) -> State
		write = |state, bytes| {
			len = state.len.plus_wrap(bytes.len())
			buffered = state.buffer.len()
			if buffered + bytes.len() < block_len {
				# Not enough for a block yet
				State.{ vars: state.vars, buffer: state.buffer.concat(bytes), len }
			} else if buffered == 0 {
				(vars, next) = compress_blocks(state.vars, bytes, 0)
				State.{ vars, buffer: leftover(bytes, next), len }
			} else {
				# Complete the buffered block, then go on from the input itself
				need = block_len - buffered
				block = state.buffer.concat(bytes.take_first(need))
				(vars, next) = compress_blocks(compress(state.vars, block, 0), bytes, need)
				State.{ vars, buffer: leftover(bytes, next), len }
			}
		}

		## Finish a state snapshot and return its digest.
		## The state value is immutable, so callers can also continue writing to the prior state.
		finish : State -> Digest
		finish = |state| Digest.{ bytes: pad_and_finish(state.vars, state.buffer, 0, state.len) }
	}

	## Hash all bytes in one SHA-1 operation.
	##
	## ```roc
	## digest = Sha1.hash("abc".to_utf8())
	## hex = digest.to_hex()
	## ```
	hash : List(U8) -> Digest
	hash = |bytes| {
		(vars, next) = compress_blocks(initial_vars, bytes, 0)
		Digest.{ bytes: pad_and_finish(vars, bytes, next, bytes.len()) }
	}

	## Hash byte chunks in order with SHA-1.
	##
	## ```roc
	## digest = Sha1.hash_chunks(["a".to_utf8(), "bc".to_utf8()].iter())
	## ```
	hash_chunks : Iter(List(U8)) -> Digest
	hash_chunks = |chunks| State.finish(Iter.fold(chunks, State.empty(), State.write))
}

# Everything below is private to this module

## The five 32-bit hash values, H0 to H4
Vars : (U32, U32, U32, U32, U32)

initial_vars : Vars
initial_vars = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)

block_len : U64
block_len = 64

digest_len : U64
digest_len = 20

hex_len : U64
hex_len = 40

## Compress every whole block of `bytes` from `start`. Returns the new hash values
## and where the unprocessed tail begins.
compress_blocks : Vars, List(U8), U64 -> (Vars, U64)
compress_blocks = |vars, bytes, start| {
	var $vars = vars
	var $at = start
	while $at + block_len <= bytes.len() {
		$vars = compress($vars, bytes, $at)
		$at = $at + block_len
	}
	($vars, $at)
}

## Pad the last bytes of the message, from `start` in `bytes`, compress the
## one or two final blocks, and return the digest bytes. `total` is the
## message length in bytes.
pad_and_finish : Vars, List(U8), U64, U64 -> List(U8)
pad_and_finish = |vars, bytes, start, total| {
	tail = bytes.drop_first(start)
	# The tail, a 1 bit, zeros, and the 64-bit big-endian bit length fill one
	# block, or two when fewer than 9 bytes are left in the first
	padded_len = if (tail.len() < 56) block_len else block_len * 2
	bits = total.shl_wrap(3)
	var $block = List.with_capacity(padded_len).concat(tail).append(0x80)
	while $block.len() < padded_len - 8 {
		$block = $block.append(0)
	}
	$block = $block
		.append(bits.shr_zf_wrap(56).to_u8_wrap())
		.append(bits.shr_zf_wrap(48).to_u8_wrap())
		.append(bits.shr_zf_wrap(40).to_u8_wrap())
		.append(bits.shr_zf_wrap(32).to_u8_wrap())
		.append(bits.shr_zf_wrap(24).to_u8_wrap())
		.append(bits.shr_zf_wrap(16).to_u8_wrap())
		.append(bits.shr_zf_wrap(8).to_u8_wrap())
		.append(bits.to_u8_wrap())
	(final_vars, _) = compress_blocks(vars, $block, 0)
	(h0, h1, h2, h3, h4) = final_vars
	List.with_capacity(digest_len)
		|> append_be(h0)
		|> append_be(h1)
		|> append_be(h2)
		|> append_be(h3)
		|> append_be(h4)
}

## The bytes of `bytes` from `start`, which are fewer than a block, copied so
## that a state does not keep a large input alive
leftover : List(U8), U64 -> List(U8)
leftover = |bytes, start| List.with_capacity(block_len).concat(bytes.drop_first(start))

append_be : List(U8), U32 -> List(U8)
append_be = |out, word|
	out
		.append(word.shr_zf_wrap(24).to_u8_wrap())
		.append(word.shr_zf_wrap(16).to_u8_wrap())
		.append(word.shr_zf_wrap(8).to_u8_wrap())
		.append(word.to_u8_wrap())

## Compress the 64-byte block at `at`, which the caller has checked is there.
## The 80 rounds and the message schedule are written out in full, so every
## word stays in a register.
compress : Vars, List(U8), U64 -> Vars
compress = |vars, bytes, at| {
	(w0, w1, w2, w3) = words(bytes, at)
	(w4, w5, w6, w7) = words(bytes, at + 16)
	(w8, w9, w10, w11) = words(bytes, at + 32)
	(w12, w13, w14, w15) = words(bytes, at + 48)
	var $s = vars
	$s = round1($s, w0)
	$s = round1($s, w1)
	$s = round1($s, w2)
	$s = round1($s, w3)
	$s = round1($s, w4)
	$s = round1($s, w5)
	$s = round1($s, w6)
	$s = round1($s, w7)
	$s = round1($s, w8)
	$s = round1($s, w9)
	$s = round1($s, w10)
	$s = round1($s, w11)
	$s = round1($s, w12)
	$s = round1($s, w13)
	$s = round1($s, w14)
	$s = round1($s, w15)
	w16 = expand(w13, w8, w2, w0)
	$s = round1($s, w16)
	w17 = expand(w14, w9, w3, w1)
	$s = round1($s, w17)
	w18 = expand(w15, w10, w4, w2)
	$s = round1($s, w18)
	w19 = expand(w16, w11, w5, w3)
	$s = round1($s, w19)
	w20 = expand(w17, w12, w6, w4)
	$s = round2($s, w20)
	w21 = expand(w18, w13, w7, w5)
	$s = round2($s, w21)
	w22 = expand(w19, w14, w8, w6)
	$s = round2($s, w22)
	w23 = expand(w20, w15, w9, w7)
	$s = round2($s, w23)
	w24 = expand(w21, w16, w10, w8)
	$s = round2($s, w24)
	w25 = expand(w22, w17, w11, w9)
	$s = round2($s, w25)
	w26 = expand(w23, w18, w12, w10)
	$s = round2($s, w26)
	w27 = expand(w24, w19, w13, w11)
	$s = round2($s, w27)
	w28 = expand(w25, w20, w14, w12)
	$s = round2($s, w28)
	w29 = expand(w26, w21, w15, w13)
	$s = round2($s, w29)
	w30 = expand(w27, w22, w16, w14)
	$s = round2($s, w30)
	w31 = expand(w28, w23, w17, w15)
	$s = round2($s, w31)
	w32 = expand(w29, w24, w18, w16)
	$s = round2($s, w32)
	w33 = expand(w30, w25, w19, w17)
	$s = round2($s, w33)
	w34 = expand(w31, w26, w20, w18)
	$s = round2($s, w34)
	w35 = expand(w32, w27, w21, w19)
	$s = round2($s, w35)
	w36 = expand(w33, w28, w22, w20)
	$s = round2($s, w36)
	w37 = expand(w34, w29, w23, w21)
	$s = round2($s, w37)
	w38 = expand(w35, w30, w24, w22)
	$s = round2($s, w38)
	w39 = expand(w36, w31, w25, w23)
	$s = round2($s, w39)
	w40 = expand(w37, w32, w26, w24)
	$s = round3($s, w40)
	w41 = expand(w38, w33, w27, w25)
	$s = round3($s, w41)
	w42 = expand(w39, w34, w28, w26)
	$s = round3($s, w42)
	w43 = expand(w40, w35, w29, w27)
	$s = round3($s, w43)
	w44 = expand(w41, w36, w30, w28)
	$s = round3($s, w44)
	w45 = expand(w42, w37, w31, w29)
	$s = round3($s, w45)
	w46 = expand(w43, w38, w32, w30)
	$s = round3($s, w46)
	w47 = expand(w44, w39, w33, w31)
	$s = round3($s, w47)
	w48 = expand(w45, w40, w34, w32)
	$s = round3($s, w48)
	w49 = expand(w46, w41, w35, w33)
	$s = round3($s, w49)
	w50 = expand(w47, w42, w36, w34)
	$s = round3($s, w50)
	w51 = expand(w48, w43, w37, w35)
	$s = round3($s, w51)
	w52 = expand(w49, w44, w38, w36)
	$s = round3($s, w52)
	w53 = expand(w50, w45, w39, w37)
	$s = round3($s, w53)
	w54 = expand(w51, w46, w40, w38)
	$s = round3($s, w54)
	w55 = expand(w52, w47, w41, w39)
	$s = round3($s, w55)
	w56 = expand(w53, w48, w42, w40)
	$s = round3($s, w56)
	w57 = expand(w54, w49, w43, w41)
	$s = round3($s, w57)
	w58 = expand(w55, w50, w44, w42)
	$s = round3($s, w58)
	w59 = expand(w56, w51, w45, w43)
	$s = round3($s, w59)
	w60 = expand(w57, w52, w46, w44)
	$s = round4($s, w60)
	w61 = expand(w58, w53, w47, w45)
	$s = round4($s, w61)
	w62 = expand(w59, w54, w48, w46)
	$s = round4($s, w62)
	w63 = expand(w60, w55, w49, w47)
	$s = round4($s, w63)
	w64 = expand(w61, w56, w50, w48)
	$s = round4($s, w64)
	w65 = expand(w62, w57, w51, w49)
	$s = round4($s, w65)
	w66 = expand(w63, w58, w52, w50)
	$s = round4($s, w66)
	w67 = expand(w64, w59, w53, w51)
	$s = round4($s, w67)
	w68 = expand(w65, w60, w54, w52)
	$s = round4($s, w68)
	w69 = expand(w66, w61, w55, w53)
	$s = round4($s, w69)
	w70 = expand(w67, w62, w56, w54)
	$s = round4($s, w70)
	w71 = expand(w68, w63, w57, w55)
	$s = round4($s, w71)
	w72 = expand(w69, w64, w58, w56)
	$s = round4($s, w72)
	w73 = expand(w70, w65, w59, w57)
	$s = round4($s, w73)
	w74 = expand(w71, w66, w60, w58)
	$s = round4($s, w74)
	w75 = expand(w72, w67, w61, w59)
	$s = round4($s, w75)
	w76 = expand(w73, w68, w62, w60)
	$s = round4($s, w76)
	w77 = expand(w74, w69, w63, w61)
	$s = round4($s, w77)
	w78 = expand(w75, w70, w64, w62)
	$s = round4($s, w78)
	w79 = expand(w76, w71, w65, w63)
	$s = round4($s, w79)
	(a, b, c, d, e) = $s
	(h0, h1, h2, h3, h4) = vars
	(h0.plus_wrap(a), h1.plus_wrap(b), h2.plus_wrap(c), h3.plus_wrap(d), h4.plus_wrap(e))
}

## Rounds 0 to 19, with the choice function
round1 : Vars, U32 -> Vars
round1 = |(a, b, c, d, e), w| step(a, b, c, d, e, d.bitwise_xor(b.bitwise_and(c.bitwise_xor(d))).plus_wrap(0x5A827999).plus_wrap(w))

## Rounds 20 to 39, with the parity function
round2 : Vars, U32 -> Vars
round2 = |(a, b, c, d, e), w| step(a, b, c, d, e, b.bitwise_xor(c).bitwise_xor(d).plus_wrap(0x6ED9EBA1).plus_wrap(w))

## Rounds 40 to 59, with the majority function
round3 : Vars, U32 -> Vars
round3 = |(a, b, c, d, e), w| step(a, b, c, d, e, b.bitwise_and(c).bitwise_or(d.bitwise_and(b.bitwise_or(c))).plus_wrap(0x8F1BBCDC).plus_wrap(w))

## Rounds 60 to 79, with the parity function
round4 : Vars, U32 -> Vars
round4 = |(a, b, c, d, e), w| step(a, b, c, d, e, b.bitwise_xor(c).bitwise_xor(d).plus_wrap(0xCA62C1D6).plus_wrap(w))

## One round, given f(b, c, d) + K + W for it
step : U32, U32, U32, U32, U32, U32 -> Vars
step = |a, b, c, d, e, fkw| (rotl(a, 5).plus_wrap(e).plus_wrap(fkw), a, rotl(b, 30), c, d)

## The next word of the message schedule
expand : U32, U32, U32, U32 -> U32
expand = |w3, w8, w14, w16| rotl(w3.bitwise_xor(w8).bitwise_xor(w14).bitwise_xor(w16), 1)

rotl : U32, U8 -> U32
rotl = |x, n| x.shl_wrap(n).bitwise_or(x.shr_zf_wrap(32 - n))

## The four big-endian words in the 16 bytes at `at`
words : List(U8), U64 -> (U32, U32, U32, U32)
words = |bytes, at| {
	v = match U8x16.load(bytes, at) {
		Ok(loaded) => loaded.table_lookup(byte_swap).to_u32x4_bits()
		Err(OutOfBounds) => crash "words needs at + 16 <= len"
	}
	(v.get_lane(0), v.get_lane(1), v.get_lane(2), v.get_lane(3))
}

## Reverses the bytes of each 32-bit lane
byte_swap : U8x16
byte_swap = match U8x16.from_list([3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12]) {
	Ok(v) => v
	Err(WrongLength) => crash "byte_swap has 16 lanes"
}

hex_digit : U8 -> U8
hex_digit = |n| if (n < 10) '0' + n else 'a' + n - 10

## The value of an ASCII hex digit in either case
hex_value : U8 -> Try(U8, [NotHex])
hex_value = |c|
	if c >= '0' and c <= '9' {
		Ok(c - '0')
	} else if c >= 'a' and c <= 'f' {
		Ok(c - 'a' + 10)
	} else if c >= 'A' and c <= 'F' {
		Ok(c - 'A' + 10)
	} else {
		Err(NotHex)
	}

char_at : List(U8), U64 -> U8
char_at = |chars, index|
	match chars.get(index) {
		Ok(c) => c
		Err(OutOfBounds) => crash "char_at is only called below the checked length"
	}

# Tests

## Hex digest of `bytes`
hex_of : List(U8) -> Str
hex_of = |bytes| Sha1.hash(bytes).to_hex()

## FIPS 180-4 examples (NIST "SHA1.pdf" and FIPS 180-2 appendix A)
expect hex_of("abc".to_utf8()) == "a9993e364706816aba3e25717850c26c9cd0d89d"
expect hex_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_utf8()) == "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
expect hex_of("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".to_utf8()) == "a49b2446a02c645bf419f995b67091253a04a259"
expect hex_of(List.repeat('a', 1_000_000)) == "34aa973cd4c4daa4f61eeb2bdbad27316534016f"

## The million 'a' message written in 1000 chunks of 1000, through both
## incremental APIs
expect {
	chunk = List.repeat('a', 1000)
	expected = "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
	var $state = Sha1.State.empty()
	for _ in List.from_iter((0.U64).until(1000)) {
		$state = $state.write(chunk)
	}
	$state.finish().to_hex() == expected
		and Sha1.hash_chunks(List.repeat(chunk, 1000).iter()).to_hex() == expected
}

## NIST CAVP SHA1ShortMsg.rsp, byte-oriented messages of 0 to 8 bytes
expect hex_of([]) == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
expect hex_of([0x36]) == "c1dfd96eea8cc2b62785275bca38ac261256e278"
expect hex_of([0x19, 0x5a]) == "0a1c2d555bbe431ad6288af5a54f93e0449c9232"
expect hex_of([0xdf, 0x4b, 0xd2]) == "bf36ed5d74727dfd5d7854ec6b1d49468d8ee8aa"
expect hex_of([0x54, 0x9e, 0x95, 0x9e]) == "b78bae6d14338ffccfd5d5b5674a275f6ef9c717"
expect hex_of([0xf7, 0xfb, 0x1b, 0xe2, 0x05]) == "60b7d5bb560a1acf6fa45721bd0abb419a841a89"
expect hex_of([0xc0, 0xe5, 0xab, 0xea, 0xea, 0x63]) == "a6d338459780c08363090fd8fc7d28dc80e8e01f"
expect hex_of([0x63, 0xbf, 0xc1, 0xed, 0x7f, 0x78, 0xab]) == "860328d80509500c1783169ebf0ba0c4b94da5e5"
expect hex_of([0x7e, 0x3d, 0x7b, 0x3e, 0xad, 0xa9, 0x88, 0x66]) == "24a2c34b976305277ce58c2f42d5092031572520"

expect hex_of("The quick brown fox jumps over the lazy dog".to_utf8()) == "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"

## Runs of 'a' around the padding edges. Up to 55 bytes the padding fits in
## the last block, from 56 to 63 it needs another block, and the same again
## at 119 and 120. Checked against sha1sum.
expect {
	cases = [
		(55, "c1c8bbdc22796e28c0e15163d20899b65621d65a"),
		(56, "c2db330f6083854c99d4b5bfb6e8f29f201be699"),
		(57, "f08f24908d682555111be7ff6f004e78283d989a"),
		(63, "03f09f5b158a7a8cdad920bddc29b81c18a551f5"),
		(64, "0098ba824b5c16427bd7a1122a5a442a25ec644d"),
		(65, "11655326c708d70319be2610e8a57d9a5b959d3b"),
		(119, "ee971065aaa017e0632a8ca6c77bb3bf8b1dfc56"),
		(120, "f34c1488385346a55709ba056ddd08280dd4c6d6"),
		(121, "fa6b5a6f8ac27182f838fe7841ec6d2aef3ade29"),
		(127, "89d95fa32ed44a7c610b7ee38517ddf57e0bb975"),
		(128, "ad5b3fdbcb526778c2839d2f151ea753995e26a0"),
		(129, "d96debf1bdcbc896e6c134ea76e8141f40d78536"),
	]
	wrong = cases.keep_if(|(len, hex)| hex_of(List.repeat('a', len)) != hex).map(|(len, _)| len)
	wrong == []
}

## The first `len` bytes of a fixed pattern
pattern : U64 -> List(U8)
pattern = |len| List.from_iter((0.U64).until(len)).map(|i| (i * 31 + 7).to_u8_wrap())

## Every length from 0 to 200 of the pattern, against digests from Python's
## hashlib, checked with sha1sum and openssl. Covers every padding case, and
## the block edges at 55, 56, 64, 119, 120, and 128.
expect {
	expected = [
		"da39a3ee5e6b4b0d3255bfef95601890afd80709",
		"5d1be7e9dda1ee8896be5b7e34a85ee16452a7b4",
		"7878ac025cfe0384191ff21ebb1627fd25f8a60c",
		"d2df16b976a43628c63ea246436fccf6d7635d09",
		"d4f9ceaade7da644940e6e48e5f6f3df890012e5",
		"30b0747dfbd07a32d9c8d1dd980fa3715c61705d",
		"0e86f0b0df735206bc8c63c98ece2615752a583a",
		"7b5fdb60a909101741efaccfcf4623768ed8c772",
		"090a21896cc276ea75ecae78af863a34cb135e1e",
		"9750943838c5a41ce8324080d24c1c83b5d1ddae",
		"975fa4a481ddb865543aa46b4215abce0867415e",
		"ee99d55549e856af7d230f17aeab852297174f6f",
		"527c9aac039e4100422ef17c4c31439fcd2ed067",
		"07befd60125f9d2be5d1cc5c78eb1307af0a7f98",
		"139710c70c7560646711ee1f9fee2b75ef959c3e",
		"4508ec78db0dec110697f0a89f3fea668c45c1e6",
		"5884f1f093c6dc6a7df8dab75d43d5748c6dd583",
		"0de0ccd6c9688fc89864747b6e86b924294c6838",
		"96e3d5678470c65732139e7258e0fbe9bded4954",
		"2def2581a20f472ae671840e4510efc76a45bd75",
		"6adb00acc942e8f09009d3edefb763df7046d6e4",
		"8ed8c70c44cd332747e115c148e202be6a5ac11f",
		"52fab989df29c762c730822e5b4f3e581fa83538",
		"0a479e663a8aa605af3c940d34473fc6a9f608af",
		"9781f9c5e30ee04d7e34f3b67270438fbb0e8cab",
		"19ff4253e8faa698d1bd4e7860da45f38df1aee5",
		"ddf4e79df3a624427b473b43d0f762a9128ee0b1",
		"282d5c7ba20281c5862c5dfec06ac09b02bc9028",
		"0545246c1176ec07a5c76da77dc0b47d658bd58c",
		"2d77de3600a1a02c27f113247055a1288f85f21e",
		"a8e474f565ca3ed1c6c5dc8b8ddecb52e25f2ee3",
		"8a3cfab36a8e4e5510d5800dd0063725f29c614f",
		"4a9f58da1bac35a4d50e87dc0f9e49f3a740192f",
		"b28afc2dfa3c4884e18f7c7d943dfad7647a389b",
		"77260e68115b3238848446189d3e8058f82a08ea",
		"64e36d9226e117d413fbbc9b0d2506c6e6588a1e",
		"cc4b77f45d09f88399625712a877e8c7ddefcede",
		"4aba15b96465339c44cd4c633b0f88f889298d38",
		"6dae0fbb08600217dc4d3a572506da98b5259237",
		"dbd96a88971e828294e76676c6cc7b7c8d5dd705",
		"50ece239fb3daf7330821cc85d2bae03fcb27fa3",
		"e59d729c6e8445387de15ce274af9a65f9751557",
		"4deacbbf65843c9bb338c266c3e291f70ead30c3",
		"815ef303fdb28e94299b6fcf3efa8d7f469b2c8f",
		"b66b61cf262d2a8926c28bdcd33fe66892bd134e",
		"177d0ee82815c1d1e83b6d0d923e47cc4ef9ca03",
		"131814fd29a1b2d86ef58667156f102ab8d3af4b",
		"fabb661be319d4ed390cf5e23edb7b680a4ee663",
		"0796640c41bebef2c7920f1015483e8e45a600c3",
		"b428ec560cf367cb4386371aa88c2c55ae291a12",
		"7f4aa52203322f756b073b2802277d0add9bdd87",
		"e9f34b4f49c516a758f2283cb5b6528b10d07770",
		"4962b732ea68858be5ccd40469422cf32dd5d7b7",
		"9b13b43b467c30af032111a01964cbfa91c22f12",
		"d55036939dd1f1b82217b436fd60b32b5d015ab1",
		"749bbefb28edc4638b28b2b9a9e03ab9a4032b90",
		"a5b6e9c29d201c774753ff8e7fb64931656f5e63",
		"eb0737bed5451790722b2df351829ce117e3d9dd",
		"6f139fad1ae8ba7233bf48be73eed09d469ca735",
		"150327206b90a9129013cebce50ccfcbae9cd53d",
		"86ea3d4e8c9a086ee3d01af2c614cd463e3aa969",
		"e38613ee100936fadbff7cedd2ef467868d79032",
		"0c7a70093fd6a9d8c0ee69571185f7a3334d5f9a",
		"d1a454409359fc372b4d22b3cea6488d6ba1be00",
		"39a0d8b645ad85f1f976731ed112ac9455e28b78",
		"d0c96e18890114a14716e9686528d2e3fdba8d9e",
		"92dd5fd255e87de53cf6a7771cbb1130f52ea24b",
		"906f093cacd2ce78b8496c3bed7d6bacdd92ea0c",
		"d8cf76c08d523b04919a72ed459c111a370b02ce",
		"5c4b40e6fa54508cc31fe6de86f4cb2a66bd5e53",
		"e5b80b9ab19552e389496fca5dff8f27aca7f240",
		"64aa38cd51d7f21e8e1a80de8112dd0658dd63d8",
		"0fc775c234d6c8448a3678e209c1b13aef9287e9",
		"27a2a1fea010cf2c1108e5dd4bdba043d587e073",
		"3a9e0307c3de796b815542b3d0c90b61a5203ee9",
		"7b0c0b3a6e961b371a5080cef54220a30a9afa39",
		"35e5aa233c9f7d5d5f4095f10a7eb2386463714a",
		"5ec5f3cd53f4d8d2812e925971169aae05ca00f5",
		"9844dbb7e5438dad535b3cc267fda22915094ddc",
		"8857e00278b786a9a1bd1a5c00ca81ceea1183c6",
		"d46f1abac4e4c1437ba50751cd0f07dda03d8cbd",
		"f23f0e200cd3addc10856d5516cffcef136cbc8f",
		"9d3c1709d9f47eaf1648b1e9bff9f8fa9392c70e",
		"2adcc5a0476b9515cd32f6f385f6947c9b8c57df",
		"8b97fc8197d94c55f3c41ff380638944a0663870",
		"3e864c1c7ad899444cacd46e395788e3dab4ba2a",
		"2cb97ff3028dac2fe801cc3f0f1d7febbc488538",
		"e3636b2b64f8558b204f41db4fa426e9c91d5e64",
		"62ad6e1f0a7e3b265368770c8190874c1cdad0ae",
		"af07c561d91d82e46109b0aab65e1d4ff4855adb",
		"38590da98c032dacf8f5c243b822a11d35d82781",
		"2f710782948aa2118d8c8aad53ef0eb358dab3ab",
		"cde050590efe5bf54f7587dfdc121ae9c50738fb",
		"f2d4b1262ca216f4aee403a20d7c437e8acf483a",
		"f620a42282907d04ce5c903f854f344353bcb777",
		"0bb5f88272722ddc29c25568d42914813f6de17c",
		"76e26ff288e11ef8edf9312a5e7ee9bf0c50cf43",
		"d84d70748d2ee2ea756f963c5cf49b587059c4a9",
		"55daa3807db216e0a35afbf8c4f9fd6de165319d",
		"e9a44fabc5fff0912a4b281aec98410137e8da8b",
		"24cc0e3734497f698400621736077d9eb76da6a9",
		"906e0268163374e07bf4ecb4dae03b734f44ae40",
		"2877fa097b9c2580071933e6106b7b608c70cd60",
		"d66cf6cad0d6d1c10061f29ec20a79cf507effac",
		"55e2d15c1d7e04fe1c3fc1bca464f6737958b7af",
		"5fd9eacd785e626e3e8b72e1d4f7da20db61fad4",
		"a5a7f6e4493a4cb51c34a4a7519e6f83f864fddb",
		"6bdbbbe5295fee5739a7e4747716ce88b06cbe84",
		"e099acd9514668911e336732eee09848b1fc319f",
		"41080f14c6cbdebbc5fe633b26f27a95cdde775c",
		"4c602d8d85a4f13ac1a30f9cae0c425f9d9fde00",
		"b7b42d19ae6be209c36efe0c5dfe5bde4d306c43",
		"11e920cd4ed45c60c05a916e48a942f9e39c770b",
		"2a7237734453edb508687d4fcec7e027f10be533",
		"b5d4dfbd4ced11e3134ebeedb5233e57bfb82ccc",
		"6444cd62a8468402ffdd46685ce21e337a238ce6",
		"4f8620d09aa7a1f131dca718d89e74d9476611fe",
		"e180f5f16991aa42bd46d35773a9c8fb4172bedb",
		"9d8202fb77261222d9171118fc9ee72a1c567454",
		"562ecf8a430f8e1056e3619bae33628e9a1d0a4e",
		"353f6d2bf0e91aa91b74a2e0b3f297510f7d825f",
		"851880ff7adea68af146cd4fb9214f491b4ff8d7",
		"843c30316b74e98e9c38c11ff275bbdc7b69e46d",
		"9bfb90e2acd16502945af378546bcc419c4bcfb4",
		"ebbc830bd617b41a71e8cdc8884197075e7ce856",
		"dccf4bd5fdfcaecbd3bc4c140988452284da9978",
		"60fc5d6a45f329c5d4c4ea95e9a4082054d201b4",
		"bebc42d2d3d1e5fb8ad8895c2dcef2d68a6c279a",
		"0060f2a7e34b6e4d459f560197ef93243732a400",
		"3a16082d1bf09b604907ec6908b9893ca3e937c0",
		"6a259313b592f17840cde208eed964698df0148a",
		"185bb246c5c44fe2a707741827bec16506633d60",
		"900965de24d9b299a416a5e6f0c9d78c932dc7bd",
		"05796370fed7d906081bfff1f645f062e56b2784",
		"6b09963c9150d496bfc93866e788b556b509b1b1",
		"03718638a4a13734c43b3ddab053492029eaebcb",
		"2040e82cd626142536aadf74b3cd2c5d1c782ab2",
		"72902777c4b44ae586d122a7cc41efabf7348bc4",
		"5fc142e90e91960d3a4fcc1645d6cd9ebf96dfe6",
		"8ade39148f0dddce032c0334a426498dd87de7c9",
		"ced1a8f2878ec4d3c2d944dd8de8951523651def",
		"3f0abb644b8485f30a7e6e41ce3e6deb1a7b1626",
		"3cf78f772a2f3a39c65cecdfc2d2cc325ceb06b1",
		"818c0e19dc63992c2f38d519fdb43740e339ead3",
		"b04347aaa1ad87ffad57833744dcd92ee8be4992",
		"19ef87b71f4a284cb77d0d05500eee3d619d9292",
		"ef5916a0fc0d7ce1fb9cdc387938fdfbaa246a11",
		"19ae7ffd6792b03b2991a8c3e6f9a5be916b2ede",
		"f761052d22dda1a8fc46ba5068e93abf45407f06",
		"665504085edd036fbd952b04b5bf1248d68ae98c",
		"480cd2572d399647c3780fea38c09618b43d8461",
		"c6a6ebb238ea18878eaf4afc3654591f256495f1",
		"dd8596470a72eb2b45381c59d1b2c523c0c7d3c0",
		"dc044a346d37926603db52577d8a0fe8eb5bc99a",
		"296d4ddfd67e3823e97855c60395e605e655476b",
		"f9e1258ec4f4608be1736b8c7a7da04b64d06182",
		"2d09de23f719099bd142536f090ff9b45eaf0f6d",
		"de291520468ecded3b2964d7e4beb9d7eef3a805",
		"b915f0247ec3beec3ff24a35c6e0a0e45cb2725e",
		"006ef40ccd7ee02ccb588226ffde2214a3a22124",
		"b5463a28c25a3728b4005b3955e703adcd3a7dbb",
		"2b66b39f1b3fba3e3d42a62c0214696c6ba4550a",
		"487d923d5a6b831bb5826770d70e4c8402444615",
		"2ad2857a28387b8d3a236115b31e031f176ad868",
		"8efc8a892c29bfc41cf80bb508dbc0f9500a3643",
		"37ef081346677938a399bc8dc91edb99d368e66b",
		"2723e22f537887b23b5377fabb1f28ae2ea5ffda",
		"da4c92feb380aa32abb264b97593d72b33034d55",
		"407ad7a7142a71817bad5672d3d0f40627d0cb78",
		"9fbe2dae5712950fa9168bc7f07e8e5ff8c0f85c",
		"7416e462f0af7e3fc753144c2e0f43e3587cbce7",
		"acbfc1f70c1e9b9d8a4142a3d26897dc83eeceba",
		"5379243ba20b851e2dc9f8769f46739e8e716289",
		"54e9d91f05965167a116479aacba721c6c2dddc0",
		"41eaa4b0c587cb38ca3a709ff2bf75d543392b29",
		"76eb44a9456cae3985acbf6b4e61882ea8bf1a01",
		"b003f0bd5dde9717bc13e4d874a5e4afa131e4d2",
		"dfad13619a9c3064f4fdfd0478269d704d871063",
		"b700f829a8eaf4d64724b54389c8abcc50de81ac",
		"7aae0d1b701a5777f33f54d95424706587e5fb06",
		"6ff72c93a3bfe1f723b2c4670062124072016657",
		"fedf4e093b0e0413786b9a114813ffb6239d86f2",
		"0bcc478275e210d150d2be97a504960376ef2314",
		"870cbbfb74a4bb71369de543b8e0f3473f29a602",
		"3ab35d8a160f267b435f0a325ff461a64d3c7b7b",
		"b9790528c15f989b03f341e23feec45a6d5ce81c",
		"3207cc92551cab8ea72221124bcc09338e941610",
		"2024f7a28d3ffb7edfa95672c7d6ae3a24dd7310",
		"f7ca0920d7595bfe4287636f821f67491a1471fa",
		"aa63b1b356240e8494cce1cd06c3e75d99a49e83",
		"8e4bb0244bc7fce3b1ce94cc5d8db2996c6ed262",
		"90d881e31a36af55e527ceb7f011b051a6dd4ac2",
		"9d9112152625f518fae155f757471e6564167ac8",
		"d665859ce51ed06764f8be49466cd7bbfd9bdf06",
		"8386eca1acc749138710ecdbe5279f5c87d3ebc2",
		"dc2ab28cb02a317b8a5d09c34a2a49a21f522733",
		"417f863ee634afbc6e0fc3e4a91fc80c3540a3e8",
		"481856077580a67edc7f96227ea3403ea683aea8",
		"ecabad2c248cf1b50346ac26afe67837b329d077",
		"6ddadf9e2c69ed1bdf0b71bd01dd603ba6556107",
		"9194d8145e556594766df1e7699e2dfda424d1ee",
	]
	wrong = expected.map_with_index(|hex, len| (len, hex)).keep_if(|(len, hex)| hex_of(pattern(len)) != hex).map(|(len, _)| len)
	expected.len() == 201 and wrong == []
}

## Writing `bytes` split at `cut`, through both incremental APIs, gives the
## one-shot digest
split_agrees : List(U8), U64 -> Bool
split_agrees = |bytes, cut| {
	expected = Sha1.hash(bytes)
	first = bytes.take_first(cut)
	rest = bytes.drop_first(cut)
	Sha1.State.empty().write(first).write(rest).finish() == expected
		and Sha1.hash_chunks([first, rest].iter()) == expected
}

## Every two-way split of 300 bytes
expect {
	bytes = pattern(300)
	wrong = List.from_iter((0.U64).to(300)).drop_if(|cut| split_agrees(bytes, cut))
	wrong == []
}

## Three-way splits, including empty pieces
expect {
	bytes = pattern(260)
	expected = Sha1.hash(bytes)
	cuts = List.from_iter((0.U64).to(260)).keep_if(|n| n % 5 == 0 or n % 64 < 2 or n % 64 > 61)
	var $wrong = []
	for i in cuts {
		for j in cuts {
			if i <= j {
				pieces = [bytes.take_first(i), bytes.sublist({ start: i, len: j - i }), bytes.drop_first(j)]
				via_state = pieces.fold(Sha1.State.empty(), |state, piece| state.write(piece)).finish()
				if via_state != expected or Sha1.hash_chunks(pieces.iter()) != expected {
					$wrong = $wrong.append((i, j))
				}
			}
		}
	}
	$wrong == []
}

## The same input in equal chunks of every width from 1 to 140, with an empty
## write between chunks
expect {
	bytes = pattern(333)
	expected = Sha1.hash(bytes)
	wrong = List.from_iter((1.U64).to(140)).drop_if(
		|width| {
			var $state = Sha1.State.empty()
			var $chunks = []
			var $start = 0
			while $start < bytes.len() {
				chunk = bytes.sublist({ start: $start, len: width })
				$state = $state.write(chunk).write([])
				$chunks = $chunks.append(chunk).append([])
				$start = $start + width
			}
			$state.finish() == expected and Sha1.hash_chunks($chunks.iter()) == expected
		},
	)
	wrong == []
}

## A state is a value. Finishing does not consume it, and two writes to the
## same state do not affect each other.
expect {
	start = Sha1.State.empty().write("ab".to_utf8())
	snapshot = start.finish()
	left = start.write("c".to_utf8())
	right = start.write(pattern(100))
	snapshot == Sha1.hash("ab".to_utf8())
		and left.finish() == Sha1.hash("abc".to_utf8())
		and right.finish() == Sha1.hash("ab".to_utf8().concat(pattern(100)))
		and start.finish() == snapshot
}

expect Sha1.State.empty().finish() == Sha1.hash([])
expect Sha1.hash_chunks([].iter()) == Sha1.hash([])

## Digests

expect Sha1.hash([]).to_bytes().len() == 20
expect Sha1.hash("abc".to_utf8()).to_bytes() == [0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d]
expect Str.inspect(Sha1.hash("abc".to_utf8())) == "Sha1.Digest(\"a9993e364706816aba3e25717850c26c9cd0d89d\")"
expect Sha1.hash("abc".to_utf8()) != Sha1.hash("abd".to_utf8())
expect Set.from_list([Sha1.hash([]), Sha1.hash([1]), Sha1.hash([])]).len() == 2

## to_hex and from_hex round trip, and so do to_bytes and from_bytes
expect {
	wrong = List.from_iter((0.U64).to(200)).drop_if(
		|len| {
			digest = Sha1.hash(pattern(len))
			hex = digest.to_hex()
			Sha1.Digest.from_hex(hex) == Ok(digest)
				and Sha1.Digest.from_bytes(digest.to_bytes()) == Ok(digest)
				and hex.to_utf8().len() == 40
				and hex.to_utf8().all(|c| (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))
		},
	)
	wrong == []
}

expect Sha1.Digest.from_hex("A9993E364706816ABA3E25717850C26C9CD0D89D") == Ok(Sha1.hash("abc".to_utf8()))
expect Sha1.Digest.from_hex("a9993E364706816aBA3E25717850c26c9cD0D89d") == Ok(Sha1.hash("abc".to_utf8()))
expect Sha1.Digest.from_hex("00112233445566778899aabbccddeeffAABBCCDD").map_ok(|d| d.to_bytes()) == Ok([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xaa, 0xbb, 0xcc, 0xdd])

## Bad hex
expect Sha1.Digest.from_hex("") == Err(WrongLength({ expected: 40, actual: 0 }))
expect Sha1.Digest.from_hex("a9993e364706816aba3e25717850c26c9cd0d89") == Err(WrongLength({ expected: 40, actual: 39 }))
expect Sha1.Digest.from_hex("a9993e364706816aba3e25717850c26c9cd0d89d0") == Err(WrongLength({ expected: 40, actual: 41 }))
expect Sha1.Digest.from_hex("0xa9993e364706816aba3e25717850c26c9cd0d89d") == Err(WrongLength({ expected: 40, actual: 42 }))
expect Sha1.Digest.from_hex("0x993e364706816aba3e25717850c26c9cd0d89d") == Err(InvalidHex({ index: 1, byte: 'x' }))
expect Sha1.Digest.from_hex("g9993e364706816aba3e25717850c26c9cd0d89d") == Err(InvalidHex({ index: 0, byte: 'g' }))
expect Sha1.Digest.from_hex("a9993e364706816aba3e25717850c26c9cd0d89G") == Err(InvalidHex({ index: 39, byte: 'G' }))
expect Sha1.Digest.from_hex("a9993e364706816aba3e 5717850c26c9cd0d89d") == Err(InvalidHex({ index: 20, byte: ' ' }))
expect Sha1.Digest.from_hex("a9993e364706816aba3e25717850c26c9cd0d89-") == Err(InvalidHex({ index: 39, byte: '-' }))

## The index counts UTF-8 bytes, and the first bad byte is reported
expect Sha1.Digest.from_hex("a9993e364706816aba3e25717850c26c9cd0d8\u(e9)") == Err(InvalidHex({ index: 38, byte: 0xc3 }))
expect Sha1.Digest.from_hex("a9993e364706816aba3e25717850c26c9cd0d8zz") == Err(InvalidHex({ index: 38, byte: 'z' }))

## Every ASCII byte that is not a hex digit is rejected wherever it is
expect {
	valid = "a9993e364706816aba3e25717850c26c9cd0d89d".to_utf8()
	hex_digits = "0123456789abcdefABCDEF".to_utf8()
	var $wrong = []
	for byte in List.from_iter((0.U64).until(128)).map(|n| n.to_u8_wrap()) {
		if !hex_digits.contains(byte) {
			for index in [0, 1, 17, 38, 39] {
				bad = valid.take_first(index).append(byte).concat(valid.drop_first(index + 1))
				result = Sha1.Digest.from_hex(Str.from_utf8_lossy(bad))
				if result != Err(InvalidHex({ index, byte })) {
					$wrong = $wrong.append((index, byte))
				}
			}
		}
	}
	$wrong == []
}

expect Sha1.Digest.from_bytes([]) == Err(WrongLength({ expected: 20, actual: 0 }))
expect Sha1.Digest.from_bytes(List.repeat(0, 19)) == Err(WrongLength({ expected: 20, actual: 19 }))
expect Sha1.Digest.from_bytes(List.repeat(0, 21)) == Err(WrongLength({ expected: 20, actual: 21 }))
expect Sha1.Digest.from_bytes(List.repeat(0, 20)).map_ok(|d| d.to_hex()) == Ok("0000000000000000000000000000000000000000")
