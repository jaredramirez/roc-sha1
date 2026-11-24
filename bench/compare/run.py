"""Builds every benchmark, runs each at a few input sizes and prints a
Markdown table of throughput. Run with `just bench-compare` from the bench
profile, `devenv --profile bench shell`.
"""

import pathlib
import platform
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "bench-out"
SIZES = [64, 1024, 1024 * 1024]
ITERATIONS = 50


def sh(*args, cwd=ROOT, **kwargs):
    return subprocess.run(args, check=True, text=True, cwd=cwd, **kwargs)


def build():
    OUT.mkdir(exist_ok=True)
    sh("roc", "build", "--opt=speed", "bench/main.roc", f"--output={OUT}/roc")
    sh("cargo", "build", "--quiet", "--release", "--manifest-path", "bench/compare/rust/Cargo.toml",
       "--target-dir", f"{OUT}/rust")
    sh("go", "build", "-o", f"{OUT}/go", ".", cwd=ROOT / "bench/compare/go")


def run(size):
    """Nanoseconds per hash for each implementation at this size."""
    args = [str(size), str(ITERATIONS)]
    roc = sh(f"{OUT}/roc", *args, capture_output=True).stdout
    results = {"roc-sha1": int(re.search(r"^hash \d+ bytes: (\d+) ns", roc, re.M).group(1))}
    for command in ([f"{OUT}/rust/release/sha1-compare"], [f"{OUT}/go"],
                    [sys.executable, "bench/compare/python/bench.py"]):
        for line in sh(*command, *args, capture_output=True).stdout.splitlines():
            name, ns = line.rsplit(": ", 1)
            results[name] = int(ns)
    return results


def size_label(size):
    return f"{size // (1024 * 1024)} MiB" if size >= 1024 * 1024 else f"{size // 1024} KiB" if size >= 1024 else f"{size} B"


def main():
    build()
    rows = [(size, run(size)) for size in SIZES]
    names = list(rows[0][1])
    print(f"SHA-1 throughput in MB/s, higher is better ({platform.machine()}, {platform.system()})\n")
    print("| Input | " + " | ".join(names) + " |")
    print("| --- |" + " ---: |" * len(names))
    for size, results in rows:
        cells = [f"{size * 1000 // results[n]:,}" if results[n] else "-" for n in names]
        print(f"| {size_label(size)} | " + " | ".join(cells) + " |")


main()
