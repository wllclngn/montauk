// Cross-language search bench, Go standard library point.
// literal: bytes.Index (two-way / Rabin-Karp). regex: regexp (RE2 lineage).
// Protocol: <corpusfile> <pattern> <runs> <literal|regex>
package main

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"time"
)

func countLiteral(hay, pat []byte) int {
	c, i := 0, 0
	for i+len(pat) <= len(hay) {
		j := bytes.Index(hay[i:], pat)
		if j < 0 {
			break
		}
		c++
		i += j + 1 // overlapping occurrences
	}
	return c
}

func countRegex(hay []byte, re *regexp.Regexp) int {
	return len(re.FindAllIndex(hay, -1)) // non-overlapping leftmost
}

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintln(os.Stderr, "usage: bench_go file pat runs literal|regex")
		os.Exit(2)
	}
	hay, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	pat := os.Args[2]
	_, _ = strconv.Atoi(os.Args[3])
	isRegex := os.Args[4] == "regex"

	var re *regexp.Regexp
	if isRegex {
		re = regexp.MustCompile(pat)
	}

	run := func() int {
		if isRegex {
			return countRegex(hay, re)
		}
		return countLiteral(hay, []byte(pat))
	}
	count := run()

	dt := make([]float64, 9)
	for r := 0; r < 9; r++ {
		t0 := time.Now()
		_ = run()
		dt[r] = time.Since(t0).Seconds()
	}
	sort.Float64s(dt)
	mb := float64(len(hay)) / 1e6 / dt[4]
	algo := "go_bytes_index"
	if isRegex {
		algo = "go_regexp"
	}
	fmt.Printf("{\"algo\":\"%s\",\"count\":%d,\"mb_s\":%.0f}\n", algo, count, mb)
}
