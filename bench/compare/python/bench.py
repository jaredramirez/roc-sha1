"""Usage: bench.py SIZE ITERATIONS

Times the same work as bench/main.roc with Python's hashlib, which calls
OpenSSL, and prints `python hashlib: NS`, the fastest nanoseconds per hash.
"""

import hashlib
import sys
import time

size, iterations = int(sys.argv[1]), int(sys.argv[2])
data = bytes((i * 31 + 7) % 256 for i in range(size))
reps = 1 if size == 0 else (262144 + size - 1) // size
sha1 = hashlib.sha1
sha1(data).digest()
sha1(data).digest()
best = None
for _ in range(iterations):
    start = time.perf_counter_ns()
    for _ in range(reps):
        sha1(data).digest()
    ns = (time.perf_counter_ns() - start) // reps
    best = ns if best is None else min(best, ns)
print(f"python hashlib: {best}")
