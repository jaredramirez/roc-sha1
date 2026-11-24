set positional-arguments

# List available commands.
default:
    @just --list

check:
    roc check package/main.roc
    roc check fuzz/main.roc
    roc check bench/main.roc
    roc check diff/main.roc
    roc check bench/check.roc

# Run the tests with the default dev backend.
test:
    roc test package/Sha1.roc

# Run the tests with every backend, as apps that use the package may.
test-all:
    roc test --opt=interpreter package/Sha1.roc
    roc test --opt=dev package/Sha1.roc
    roc test --opt=speed package/Sha1.roc
    roc test --opt=size package/Sha1.roc

fmt:
    roc fmt package fuzz bench diff

# Fail if any file needs formatting.
fmt-check:
    roc fmt --check package fuzz bench diff

docs:
    roc docs package/main.roc --output=generated-docs

# Check the fuzz examples, then explore for the given number of seconds.
fuzz seconds="30":
    mkdir -p fuzz-out/corpus
    roc build --fuzz fuzz/main.roc --output=fuzz-out/sha1
    cd fuzz-out && ./sha1 check && ./sha1 explore corpus --time={{seconds}}

# Compare against GNU coreutils and OpenSSL on random inputs. See --help.
diff *args:
    roc diff/main.roc "$@"

# Time hashing SIZE bytes with the optimizing backend.
bench size="1048576" iterations="200":
    mkdir -p bench-out
    roc build --opt=speed bench/main.roc --output=bench-out/roc
    ./bench-out/roc {{size}} {{iterations}}

# Compare with Rust, Go and Python. Needs `devenv --profile bench shell`.
bench-compare:
    python3 bench/compare/run.py

# Fail if hashing falls below 3x the speed of a plain reference implementation.
perf-check:
    mkdir -p bench-out
    roc build --opt=speed bench/check.roc --output=bench-out/check
    ./bench-out/check

# Bundle the package into dist/ for a release; prints the archive name.
bundle:
    rm -rf dist && mkdir -p dist
    cp LICENSE package/LICENSE
    cd package && roc bundle main.roc Sha1.roc LICENSE --output-dir ../dist; status=$?; rm -f LICENSE; exit $status
