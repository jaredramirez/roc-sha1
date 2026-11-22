# roc-sha1

SHA-1 for [Roc](https://www.roc-lang.org), written in pure Roc and following
[FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).

Roc's builtins have SHA-256 and BLAKE3 in `Crypto`, but not SHA-1. This
package fills that gap with the same API as `Crypto.SHA256`, so it feels
native. Written for the Roc 0.1.0_RC1 compiler.

## Security

SHA-1 is broken for collision resistance. Attackers can make two different
inputs with the same digest. Use it only where a format or protocol requires
SHA-1, such as

- name-based UUIDs (UUIDv5)
- git object IDs
- WebSocket handshakes and other protocol checks

Never use it for signatures, certificates, passwords, or anything else that
must resist an attacker. Use `Crypto.SHA256` or `Crypto.BLAKE3` for those, and
a password hashing function for passwords.

## Usage

Add the package to your app header:

```roc
app [main!] {
	pf: platform "https://github.com/roc-lang/basic-cli/releases/download/0.28.1/7brgwR8YUqfeGrkdfF1V4GPPN7DnP7ftqub9KcrTEZtr.tar.zst",
	sha1: "https://github.com/jaredramirez/roc-sha1/releases/download/0.1.0/Ut9T4r8fpujaXBVV3aaDrFQZHHErAnmyAcMe2pDqGn8.tar.zst",
}

import pf.Stdout
import sha1.Sha1

main! = |_args| {
	Stdout.line!(Sha1.hash("abc".to_utf8()).to_hex())?
	Ok({})
}
```

Hash bytes that are already in memory with `hash`.

```roc
digest = Sha1.hash("abc".to_utf8())
digest.to_hex() # "a9993e364706816aba3e25717850c26c9cd0d89d"
digest.to_bytes() # the 20 raw bytes
```

Hash input that arrives in pieces with `hash_chunks`, or with a `Sha1.State`
that you write to as the pieces come in.

```roc
Sha1.hash_chunks(["a".to_utf8(), "bc".to_utf8()].iter())

var $h = Sha1.State.empty()
$h = $h.write("a".to_utf8())
$h = $h.write("bc".to_utf8())
$h.finish() # the same digest as Sha1.hash("abc".to_utf8())
```

A state is an ordinary value. Finishing it does not use it up, so you can take
a digest of a prefix and keep writing.

```roc
var $h = Sha1.State.empty()
$h = $h.write(header)
header_digest = $h.finish()
$h = $h.write(body)
whole_digest = $h.finish()
```

Read digests back from bytes or hex.

```roc
Sha1.Digest.from_hex("A9993E364706816ABA3E25717850C26C9CD0D89D") # Ok(digest), either case works
Sha1.Digest.from_hex("0xa9993e") # Err(WrongLength({ expected: 40, actual: 8 }))
Sha1.Digest.from_hex("a9993e364706816aba3e25717850c26c9cd0d8zz") # Err(InvalidHex({ index: 38, byte: 'z' }))
Sha1.Digest.from_bytes(bytes) # Ok(digest) for exactly 20 bytes
```

## API

| Name | Type |
| --- | --- |
| `Sha1.hash` | `List(U8) -> Digest` |
| `Sha1.hash_chunks` | `Iter(List(U8)) -> Digest` |
| `Sha1.State.empty` | `() -> State` |
| `Sha1.State.write` | `State, List(U8) -> State` |
| `Sha1.State.finish` | `State -> Digest` |
| `Sha1.Digest.to_bytes` | `Digest -> List(U8)` |
| `Sha1.Digest.to_hex` | `Digest -> Str` |
| `Sha1.Digest.from_bytes` | `List(U8) -> Try(Digest, DigestBytesErr)` |
| `Sha1.Digest.from_hex` | `Str -> Try(Digest, DigestHexErr)` |

`to_hex` gives 40 lowercase hex characters. `from_hex` takes exactly 40 hex
characters in either case and rejects a `0x` prefix. Digests support `==`, can
be `Dict` keys and `Set` elements, and show as `Sha1.Digest("a999…")` in
`Str.inspect` and `dbg`.

The errors have the same tags and payloads as the builtin ones.

- `DigestBytesErr` is `WrongLength({ expected : U64, actual : U64 })`.
- `DigestHexErr` is `WrongLength({ expected : U64, actual : U64 })` or
  `InvalidHex({ index : U64, byte : U8 })`. The `index` counts bytes of the
  string's UTF-8, and `byte` is the first bad byte.

### Differences from `Crypto.SHA256`

- The incremental type is `Sha1.State`, not `Sha1.Hasher`. A type named
  `Hasher` inside the package shadows the builtin `Hasher`. The compiler warns
  about that in every app that uses the package, and `roc check` then exits
  with status 2, which fails CI. `State` has the same `empty`, `write`, and
  `finish`.
- The error types are this package's own `Sha1.DigestBytesErr` and
  `Sha1.DigestHexErr`, because only the builtins can return
  `Crypto.DigestBytesErr` and `Crypto.DigestHexErr` values. They also support
  `==`, which the builtin ones do not.
- `Str.inspect` shows `Sha1.Digest(…)` where the builtin shows
  `SHA256.Digest(…)`.

## Performance

The compression function is written out in full, all 80 rounds and the message
schedule, so the five state words and the 16 schedule words stay in registers.
Each block's words are loaded 16 bytes at a time with a `U8x16` byte shuffle.
Whole blocks are hashed straight from the input without copying, and `write`
buffers at most 63 bytes between calls.

On an Apple M5 Pro with `--opt=speed`, `hash` runs at about 1200 MB/s on
1 MiB, and 64 bytes take about 150 ns. That matches OpenSSL 3 with its
hand-written assembly limited to plain instructions (`OPENSSL_armcap=0`), which
runs at 1170 MB/s. OpenSSL is about three times faster when it can use the
CPU's SHA-1 instructions, which Roc does not expose. `hash_chunks` and `State`
cost about 2% more on 1 MiB written 4 KiB at a time.

`just bench` prints these figures. `just perf-check` fails if `hash` or
`hash_chunks` falls below 3x the speed of a plain textbook implementation
measured in the same process.

## Testing

`just test` runs the tests in `package/Sha1.roc`.

- The FIPS 180-4 examples, including the million `a` message in one piece and
  in 1000 writes
- The NIST CAVP short message vectors from 0 to 8 bytes
- Every length from 0 to 200 bytes, against digests from Python's `hashlib`
  that `sha1sum` and `openssl` agree with
- Runs of `a` around the padding edges at 55, 56, 64, 119, 120, and 128 bytes
- `hash_chunks` and `State` against `hash` for every two-way split of 300
  bytes, 2278 three-way splits, and chunks of every width up to 140
  with empty writes between them
- Writing after `finish`, and writing two different things to one state
- Hex and byte round trips, and rejection of wrong lengths, `0x` prefixes, and
  every non-hex ASCII byte at several positions

`devenv test` runs the tests with all four backends, `interpreter`, `dev`,
`speed`, and `size`, because apps that use the package may build with any of
them.

`just diff` compares the package with `sha1sum` from GNU coreutils and
`openssl dgst -sha1` on random inputs from 0 bytes to 200 KB. It also cuts
each input into random chunks and checks that `hash_chunks` and `State` agree.
Pass `--count` for more inputs and `--seed` to reproduce a run. CI runs 2000
inputs.

`just fuzz` runs a [roc-fuzz](https://github.com/lukewilliamboswell/roc-fuzz)
target. It cuts arbitrary bytes into arbitrary chunks and checks that every
way of hashing agrees, that a snapshot does not change after more writes, and
that digests round trip. It also checks that `from_bytes` and `from_hex`
accept exactly the valid inputs and report the first bad byte.

CI runs the tests, the performance check, the differential test, and a minute
of fuzzing on Linux and macOS for every push to main and every pull request.

## Development

Development requires [Nix](https://nixos.org/download/) and
[devenv 2.x](https://devenv.sh/getting-started/). The environment pins
Roc 0.1.0_RC1 and devenv modules v2.1.2. `devenv.lock` pins the Nix inputs.

```sh
devenv shell
just check
just test        # the tests with the dev backend
just test-all    # the tests with every backend
just fuzz 30     # check the fuzz examples, then explore for 30 seconds
just diff        # compare against sha1sum and openssl on random inputs
just bench       # time hashing 1 MiB
just perf-check  # fail if hashing falls below 3x the reference speed
just docs        # generate API docs in generated-docs/
```

With direnv installed, `direnv allow` activates the same environment
automatically.

## Releasing

Push a version tag such as `0.1.0`. The release workflow runs the tests, the
performance check, and the differential test. Then it bundles `package/` with
`just bundle` and attaches the archive to a GitHub release whose notes give the
package URL.

## Layout

- `package/` holds the package, `main.roc` and `Sha1.roc` with its tests
- `fuzz/main.roc` is the fuzz target
- `diff/main.roc` is the differential test against coreutils and OpenSSL
- `bench/main.roc` is the benchmark
- `bench/check.roc` is the performance regression check and its reference
  implementation
