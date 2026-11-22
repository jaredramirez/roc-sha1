set positional-arguments

# List available commands.
default:
    @just --list

check:
    roc check package/main.roc
    roc check fuzz/main.roc
    roc check diff/main.roc

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
    roc fmt package fuzz diff

# Fail if any file needs formatting.
fmt-check:
    roc fmt --check package fuzz diff

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

# Bundle the package into dist/ for a release; prints the archive name.
bundle:
    rm -rf dist && mkdir -p dist
    cp LICENSE package/LICENSE
    cd package && roc bundle main.roc Sha1.roc LICENSE --output-dir ../dist; status=$?; rm -f LICENSE; exit $status
