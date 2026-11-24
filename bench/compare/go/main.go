// Usage: sha1compare SIZE ITERATIONS
//
// Times the same work as bench/main.roc with Go's crypto/sha1 and prints
// `go crypto/sha1: NS`, the fastest nanoseconds per hash.
package main

import (
	"crypto/sha1"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Written after every hash, so the work can't be skipped
var sink byte

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "Usage: sha1compare SIZE ITERATIONS")
		os.Exit(1)
	}
	size, _ := strconv.ParseUint(os.Args[1], 10, 64)
	iterations, _ := strconv.ParseUint(os.Args[2], 10, 64)
	bytes := make([]byte, size)
	for i := range bytes {
		bytes[i] = byte(uint64(i)*31 + 7)
	}
	reps := uint64(1)
	if size > 0 {
		reps = (262144 + size - 1) / size
	}
	sum := func() { d := sha1.Sum(bytes); sink ^= d[0] }
	sum()
	sum()
	min := uint64(1<<64 - 1)
	for i := uint64(0); i < iterations; i++ {
		start := time.Now()
		for r := uint64(0); r < reps; r++ {
			sum()
		}
		ns := uint64(time.Since(start).Nanoseconds()) / reps
		if ns < min {
			min = ns
		}
	}
	fmt.Printf("go crypto/sha1: %d\n", min)
}
