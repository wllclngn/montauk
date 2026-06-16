// bench_go.go -- Benchmark: Go slices.Sort (pdqsort-based)
// Protocol: argv[1]=size argv[2]=pattern argv[3]=runs
// Output: JSON line with ns_per_element
package main

import (
	"fmt"
	"math"
	"os"
	"slices"
	"strconv"
	"time"
)

func fillRandom(arr []int64, seed uint64) {
	s := seed
	for i := range arr {
		s = s*6364136223846793005 + 1442695040888963407
		arr[i] = int64(s >> 16)
	}
}

func fillPattern(arr []int64, pattern string, seed uint64) {
	n := len(arr)
	switch pattern {
	case "random":
		fillRandom(arr, seed)
	case "sorted":
		for i := 0; i < n; i++ {
			arr[i] = int64(i)
		}
	case "reversed":
		for i := 0; i < n; i++ {
			arr[i] = int64(n - i)
		}
	case "nearly":
		for i := 0; i < n; i++ {
			arr[i] = int64(i)
		}
		swaps := n / 100
		if swaps < 2 {
			swaps = 2
		}
		s := seed
		for k := 0; k < swaps; k++ {
			s = s*6364136223846793005 + 1442695040888963407
			i := int(s>>33) % n
			s = s*6364136223846793005 + 1442695040888963407
			j := int(s>>33) % n
			arr[i], arr[j] = arr[j], arr[i]
		}
	case "few_unique":
		s := seed
		for i := range arr {
			s = s*6364136223846793005 + 1442695040888963407
			arr[i] = int64((s >> 33) % 5)
		}
	case "pipe_organ":
		half := n / 2
		for i := 0; i < half; i++ {
			arr[i] = int64(i)
		}
		for i := half; i < n; i++ {
			arr[i] = int64(n - i)
		}
	case "phased":
		boundary := n * 3 / 4
		for i := 0; i < boundary; i++ {
			arr[i] = int64(i)
		}
		fillRandom(arr[boundary:], seed)
	case "equal":
		for i := range arr {
			arr[i] = 42
		}
	default:
		fillRandom(arr, seed)
	}
}

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <size> <pattern> <runs>\n", os.Args[0])
		os.Exit(1)
	}
	n, _ := strconv.Atoi(os.Args[1])
	pattern := os.Args[2]
	runs, _ := strconv.Atoi(os.Args[3])

	arr := make([]int64, n)
	bestNs := math.MaxFloat64

	// warm up
	fillPattern(arr, pattern, 42)
	slices.Sort(arr)

	for r := 0; r < runs; r++ {
		fillPattern(arr, pattern, 42+uint64(r))
		t0 := time.Now()
		slices.Sort(arr)
		elapsed := float64(time.Since(t0).Nanoseconds())
		nsPer := elapsed / float64(n)
		if nsPer < bestNs {
			bestNs = nsPer
		}
	}

	fmt.Printf("{\"algo\":\"go_slices_sort\",\"size\":%d,\"pattern\":\"%s\",\"ns_per_elem\":%.2f}\n",
		n, pattern, bestNs)
}
