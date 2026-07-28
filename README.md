```
███╗   ███╗  ██████╗  ███╗   ██╗ ████████╗  █████╗  ██╗   ██╗ ██╗  ██╗
████╗ ████║ ██╔═══██╗ ████╗  ██║ ╚══██╔══╝ ██╔══██╗ ██║   ██║ ██║ ██╔╝
██╔████╔██║ ██║   ██║ ██╔██╗ ██║    ██║    ███████║ ██║   ██║ █████╔╝ 
██║╚██╔╝██║ ██║   ██║ ██║╚██╗██║    ██║    ██╔══██║ ██║   ██║ ██╔═██╗ 
██║ ╚═╝ ██║ ╚██████╔╝ ██║ ╚████║    ██║    ██║  ██║ ╚██████╔╝ ██║  ██╗
╚═╝     ╚═╝  ╚═════╝  ╚═╝  ╚═══╝    ╚═╝    ╚═╝  ╚═╝  ╚═════╝  ╚═╝  ╚═╝
```

## Overview

montauk is a Linux observability platform in one statically-linked C++23 binary: An event-driven system monitor, an eBPF flight recorder, an offline analyzer, built on sublimation, its in-tree sort, search, learn core and an MCP stdio JSON-RPC 2.0 server, vector.

The system monitor attributes CPU, multi-vendor GPU, thermal, PMU cost to individual processes in real time and renders area charts over the Kitty graphics protocol. The tracer (`--trace`) is an eBPF flight recorder over a whole process tree, event-driven discovery with no ptrace: Per-thread syscalls and scheduler decisions with wake-to-run latency, sync-object contention, heap traffic, signals, file I/O and hardware counters through `perf_event_open`, at near-zero overhead into a binary log. The analyzer (`montauk_analyze` / `montauk_trace_decode`) folds a 450 MB capture once into 27 single-pass diagnostic reports and cross-run population statistics, no live target and no privileges.

Every surface, the TUI, the Prometheus endpoint and structured JSON, renders from one typed result, provably consistent and enforced by byte-identical golden gates: A script or an agent reads exactly the data the human report shows. That result is enriched, not just measured: The classical-ML core scores each process for anomaly on the live snapshot, and vector, montauk's agent-facing MCP server, serves it over stdio JSON-RPC through seven read-only tools, three that return conclusions rather than metrics.

The kernel module (`montauk-kernel`), the external-metrics provider sockets and `vector` are the only seams to the outside; everything else is one statically-linked C++23 binary.

**sublimation** is montauk's in-tree, adaptive sort, search and learn core: A disorder-classified sort that measures what structure an input already carries (runs, rotation, sampled inversions, a distinct-value estimate, the phase boundary, the Young-tableau shape via patience sorting) and routes every input to the algorithm its structure earns, from a no-op through an O(n) reverse, counting sort, the spectral-merge run tree, a rotation fix and binary insertion, and a distribution radix for random data. Beside the sort is a text-matching engine with three faces (literal, regex, fuzzy k-mismatch), dispatched by pattern shape. Alongside search and sort is the the classical-ML core: Three lanes of pure-algorithm learning (anomaly detectors, a graph-spectral engine, an FFT/signal-residual lane) with zero downloaded weights that turn telemetry into conclusions. The process table's ordering, the analyzer's rankers, the latency-structure classification its reports read and all of montauk's text matching run through it; the `sublimation` CLI exposes the same engine as a shell command with grep-exact exit codes.

**vector** is montauk's stdio JSON-RPC 2.0 server exposing montauk and sublimation to any MCP-speaking agent: A single static Rust binary, zero third-party crates, the same no-dependency stance as the rest of the tree.

## Screenshots

### Main Interface
![Main](assets/screenshot-default.png)

Default view. PROCESS MONITOR on the left; pixel-rendered area charts (PROCESSOR, GPU, VRAM, GPU MEM, ENC, DEC, MEMORY, NETWORK) stacked on the right. Charts emit through Kitty's `t=t` /dev/shm transport (Sixel fallback) and update at 1 Hz over a 60-second rolling window.

### SYSTEM Focus (`s`)
![SYSTEM](assets/screenshot-system.png)

`s` swaps the right-column chart stack for a text panel: Identity (hostname, kernel, uptime), runtime (collector, scheduler, process states), CPU (model, threads, freq/governor, load avg, ctxt-sw rate), GPU (model, util, NVML, power, p-state), memory, disk I/O, network, thermal margins and process-security findings, severity-colored in place.

### CPU Topology (`Shift+C`)
![Topology](assets/screenshot-topology.png)

`Shift+C` swaps PROCESS MONITOR for a dynamic grid of bordered boxes, one per logical CPU, each rendering a pixel-rasterized area chart of that core's recent utilization (60s default, `[chart] history_seconds`) with live util% centered on the top border. Grid columns auto-fit the rect; high-core-count systems fall into scroll mode at minimum cell height. Same monotone-cubic AA rasterizer and Kitty/Sixel emit path as the right-column charts; the right column is unaffected by the toggle.

## Components

| Tool | Invocation | Role |
|---|---|---|
| **monitor** | `montauk` | Event-driven TUI. Per-process CPU and multi-vendor GPU attribution (NVIDIA NVML + `nvidia-smi` fallbacks, AMD sysfs, Intel fdinfo), thermal margins, security findings, live search (literal, regex, fuzzy) and disorder classification. Cell-clipped UI, pixel-rendered area charts (Kitty `t=t` /dev/shm transport, Sixel fallback), three column-swappable views. Optional Prometheus `/metrics` over io_uring, hourly `.prom` logging and a one-shot `--json` snapshot. |
| **tracer** | `montauk --trace PATTERN` | eBPF flight recorder over a whole process tree: Event-driven discovery, no ptrace, no `/proc`. Per-thread state and syscalls, ntsync / futex / keyed-event sync, heap traffic, signals and aborts, file I/O, file-backed mmap, scheduler decisions with wake-to-run latency, CCX-bucketed migrations and hardware PMU counters via `perf_event_open`. Composes with `--metrics`, `--log` and a near-zero-overhead binary log (`--trace-out`). |
| **analyzer** | `montauk_analyze`, `montauk_trace_decode` | Folds a capture once into single-pass diagnostic reports (27 of them, from `waits` and `doublefree` to `dispatch-stall` and `fractal`) over logs reaching 450 MB+, plus recording-directory digests and cross-run population statistics. No live target, no privileges. |
| **sublimation** | `sublimation` CLI + in-tree core  | montauk's sort, search and match core, used everywhere: The process table, every ordering the analyzer emits, the structure classification its reports read and all of montauk's text matching. The CLI exposes the same engine as a complete stream-processing surface: Statistics, structure, text and relational operations, with grep-exact exit codes. |
| **vector** | `components/vector/target/release/vector` | Agent-facing MCP server: Stdio JSON-RPC 2.0, a separate static Rust binary, zero third-party crates. Seven read-only tools, three of them returning conclusions rather than metrics: `montauk_anomalies` (ranked, explained anomalies over the live process population), `montauk_similar` (behavioral nearest by effective resistance) and `montauk_regime` (did the load regime shift, and when), beside `montauk_snapshot`, `montauk_analyze_report`, `montauk_digest` and `sublimation` (direct FFI, no subprocess per call). |

## sublimation: An adaptive sort, search and learn core

**sort core** The sort is a disorder classifier standing in front of six algorithms. One O(n) pass reads how much order an input already carries — run count, monotone runs, descent gaps — and the verdict picks the algorithm that order earns. Sorted input costs a scan. Reversed input costs a reverse. Few-unique goes to a counting sort, rotated data to an O(n) rotation fix, low-displacement data to binary insertion. Past those sit the two poles. Structured data takes a natural-run merge that closes with a spectral merge: Run joins ordered by effective resistance on the run-boundary path Laplacian, so the cheapest joins happen while the data is still hot. Random data takes a distribution radix — a tuned LSD with a combined-histogram scan, a write-combining scatter and a constant-byte skip — because once no order survives, comparison has no edge left to exploit. Equal keys never move, held by a packed-index tiebreak. Type-generic across i32/i64/u32/u64/f32/f64, and at scale both poles fork onto one Chase-Lev work-stealing deque, each at a threshold that was measured rather than assumed.

**search core** The matcher is one engine wearing three faces, and the pattern picks which. The regex face is a Glushkov position-NFA compiled into a bitset field. Thompson's construction — the one this replaced in v8.0.0 — burns its time on epsilon-transitions and a closure computation over a live state set; Glushkov's is epsilon-free, so every state is a position in the pattern, the whole transition function precomputes into one bitmask per input byte, and a match step is a shift and an AND. The pattern fits in a machine word. Nothing backtracks, so a pathological pattern cannot blow up — runtime is linear in the input, always. The price of fitting in a word is a 64-position cap, so an over-long pattern is rejected outright instead of quietly degrading, and a long alternation splits into its branches. Above the field runs a prefilter ladder — a required literal, then a class field, then the alternation branches — each rung anchored on the rarest byte as measured in the data at hand, never a fixed English frequency table. The literal face is that anchor alone. The fuzzy face matches within N substitutions behind a pigeonhole prefilter, something no standard library ships.

**classical-ML core** The learn core is three lanes of classical machine learning with nothing to download: No weights, no training step, no model file. The learn lane ranks every process in the live table — the full population, not a top-N sample — on three detectors chosen to be blind in different directions. MAD modified z-score catches one axis gone extreme. Mahalanobis, through a Cholesky, catches an odd combination of individually ordinary axes. Half-Space Trees catch density with no assumption about shape. They combine by rank rather than raw score, which is the only reason detectors on unrelated scales can be added at all. The spectral lane answers what behaves like this one: Effective resistance through the Laplacian pseudoinverse, a commute-time distance that counts every path between two processes instead of the shortest, so many weak similarities outweigh a single fluke edge. The signal lane is an FFT carrying Spectral Residual — subtract the log-amplitude spectrum's own smoothed average and what remains is the part of the signal that fails to explain itself, which is where a regime shifts. Each lane comes out as a conclusion rather than a number: Anomalies, neighbors, regime shifts.

| Component | Function |
|---|---|
| **disorder classifier** | One O(n) pass → the verdict: `sorted` / `reversed` / `nearly-sorted` / `few-unique` / `phased` / `random`. The analyzer's `sched` report reads it to label a latency timeline's structure. |
| **run-merge tree** | Merges structured runs smallest-boundary-gap-first through a union-find, so the cheapest joins happen while the data is hottest |
| **index sorts** | order a `uint32_t` index array by a numeric key without moving rows (32-bit key packed with its index into one `uint64_t` and sorted adaptively; 64-bit key carried as a satellite, classified and routed to the radix or the spectral merge like the value sort) |
| **string sort** | prefix-pack + MSD-radix, for the process-name column |
| **structural locator** | slides the classifier across a stream to find *where* a disorder pattern sits (`locate`) |
| **randomness battery** | eight entropy lenses (hook-length entropy, LIS vs `2√n`, inversion ratio, distinct ratio, horizontal-visibility degree, ordinal permutation entropy, RQA determinism, spectral flatness on the comparison Laplacian) fused as confidence = (1 − 2⁻ᵏ) × meet, with a typed verdict: Max-entropy / consistent / mixed / structured (`rand`). RQA catches deterministic chaos (the logistic map) that every counting and ordinal lens reads as random. |
| **matcher** | text search, one engine, three faces: Literal/anchor (data-relative rare-byte prefilter), regex (Glushkov bit-parallel field + reach-closure memo + literal prefilter), fuzzy k-mismatch (pigeonhole prefilter). Pattern shape picks the face. Backs `search` and all of montauk's text matching. |
| **value search** | `select` (quickselect) and `searchsorted` (binary, lower/upper bound) |
| **field** | N-th delimited column projection, awk's `{print $N}` |
| **learn lane** | pure-algorithm, zero-weight anomaly detectors over a feature matrix: Robust MAD modified-z (with a mean-absolute-deviation fallback so a constant column does not go blind), EWMA residual, squared Mahalanobis through a  Cholesky and streaming Half-Space Trees. The three spatial detectors (MAD, Mahalanobis, Half-Space Trees) rank-average into the per-process anomaly score montauk enriches its snapshot with -- each a lens the others cannot see through, MAD per-axis, Mahalanobis for an odd combination, Half-Space Trees for density with no shape assumption; EWMA is the temporal lens, held for the changepoint axis. |
| **spectral lane** | a cyclic-Jacobi symmetric eigensolver, effective resistance (the commute-time graph distance) through the Laplacian pseudoinverse, the Fiedler value with a spectral-gap partition count and Ng-Jordan-Weiss spectral clustering over a  Lloyd k-means. Backs `montauk_similar`. |
| **signal lane** | a  radix-2 FFT and the Spectral Residual saliency detector built on it, a weight-free shape-anomaly detector over a time series. Backs `montauk_regime`. |

**sublimation CLI** enables the full engine to be utilized via the shell for endusers directly. Numeric commands read a value stream (`--field N` pulls a delimited column, folding in awk's extraction): Order and quantiles, k-th selection and value lookup, the reductions (`sum`/`mean`/`min`/`max`/`count`, `stdev`/`variance`), disorder classification, a randomness verdict and `characterize`, the structural verdict that names a stream's disorder class, its randomness and its exploitable structure. `search`, `field` and `where` are the line tools; `group` is datamash / SQL `GROUP BY`, `describe` the one-shot pandas summary, `histogram` the shape, `outliers` the robust Tukey-fence flag; `replace` is `sed s/pat/repl/g` on the same matcher; `intersect`/`subtract`/`union`/`join` are the two-stream relational lane; `locate --values` is select-by-structure (keep the part of the stream that *is* sorted, random or phased); `uniq`/`cut`/`column`/`tac`/`paste`/`head`/`tail` fill out coreutils and `distinct`/`tally` are `sort | uniq [-c]`.


Nothing requires the pipe to name `sublimation` outright: A few `~/.bashrc` wrapper functions can route the stream forms of `grep`, `sort`, `wc`, `awk`, `cut`, `tac`, `paste`, `sed`, `head`, `tail` and `datamash` to it, so `awk '{print $1,$3}'`, `cut -f2 -d,` or `sed 's/foo/X/g'` resolve to `field`, `cut` or `replace`. The awk language proper (`BEGIN`/`END`, `NF`/`NR`, variables, `printf`, control flow) stays awk's; the wrappers route only the byte-for-byte idioms and rely on sublimation's grep-exact exit codes to keep shell conditionals correct.

| Command | Operation |
|---|---|
| `sublimation sort [--desc] [--keyed]` | order ascending / descending; `--keyed` keeps the whole line, ordering by the key (`--field N` or the whole line), coreutils' `sort -k` with stable ties |
| `sublimation quantile Q [--nearest]` | the Q-quantile (Q in 0..1); `--nearest` for the nearest-rank order statistic |
| `sublimation select K` | the K-th smallest (0-based) |
| `sublimation searchsorted V` | insertion index of V in the sorted input |
| `sublimation sum \| mean \| min \| max` | reductions over the value stream, awk's `{s+=$N}` family |
| `sublimation stdev \| variance` | sample (n−1) standard deviation / variance |
| `sublimation count [--words\|--bytes]` | line / word / byte count, `wc -l/-w/-c` |
| `sublimation head N` / `tail N` | first / last N lines |
| `sublimation describe \| histogram \| outliers` | pandas-style summary, 10-bin text histogram, Tukey-fence outliers |
| `sublimation classify` | disorder class + profile of the stream |
| `sublimation locate CLASS [--values]` | the windows where a disorder pattern sits; `--values` emits the data in them |
| `sublimation rand` | randomness confidence from the eight-lens battery |
| `sublimation characterize` | the structural verdict: Disorder class, randomness confidence, sort efficiency |
| `sublimation search PATTERN [FILE..]` | matching lines from stdin or files; regex by default, `-F` fixed string, `-k N` fuzzy k-mismatch |
| `sublimation replace PAT REPL` | global per-line regex substitution, `sed s/pat/repl/g` |
| `sublimation field N,M [--delim D]` | the N-th column, or a comma-list, awk's `{print $N}` and `{print $1,$3}` |
| `sublimation where 'N OP V'` | lines whose field N satisfies the numeric predicate, awk's `$N OP V` |
| `sublimation group KEY OP [VAL]` | group by field KEY, aggregate field VAL (`sum`/`mean`/`count`/`min`/`max`), datamash `-g` |
| `sublimation uniq \| cut \| column \| tac \| paste -s` | the coreutils line idioms |
| `sublimation distinct \| tally` | distinct-token count / per-token frequency, `sort \| uniq [-c]` |
| `sublimation intersect \| subtract \| union \| join` | the two-stream relational lane |

`search` carries the full grep working set: `-F`/`-E`/`-k N` pick the face, `-i` and `-S` (smart case) handle casing, `-v`/`-c`/`-n`/`-o`/`-q`/`-m N` shape output, `-A`/`-B`/`-C` add context, `-w`/`-x` anchor to words or whole lines, `-e PAT`/`-f FILE` build multi-pattern sets, `-l`/`-L` name files with or without a match, `-H`/`-h`/`--label` control the filename prefix, `-s` silences unreadable-file messages, `-a`/`-I` set binary-file handling, `--color=auto|always|never` highlights, `--line-buffered` flushes per line and `--files-from LIST` reads input paths from a list (`find ... -print0 | sublimation search PAT --files-from -`). That last flag is the traversal affordance: Native directory walking deliberately stays with grep and rg, by the division-by-target rule below. Exit codes are grep's contract exactly: 0 matched, 1 nothing, 2 unreadable input. The whole surface is byte-verified against GNU grep and coreutils in a 74-case parity gate plus an exit-code oracle.

For example: `cat dump | sublimation quantile 0.99 --field 2` for a column's 99th percentile, `ps aux | sublimation where '6 > 100000'` to keep the heavy processes, `seq 1 1000 | shuf | sublimation characterize` to name a stream's shape. The division is by **target**: sublimation owns the stream (the column, filter, reduce, order and structure idioms) while `grep`, `find` and `awk` keep filesystem traversal and the awk language itself.

**Performance**

AMD Ryzen 5 3600, Zen 2, `-O2 -march=native`, ns/element, best of 5; the harness is in-tree at `sublimation/tests/bench/`, each language sorting the same seeded data with its own standard library: C `qsort`, an inline introsort, Rust `slice::sort_unstable` (ipnsort), Go `slices.Sort` and Python `sorted`. Keys are full-width — a narrower fill leaves the top bytes of a 64-bit key constant, which gives a radix a free pass skip that a comparison sort never gets.

**Structured Sort Performance** (n = 100K)

Where the adaptive routing pays: The sort reads the order an input already carries instead of rebuilding it, so a comparison sort's O(n log n) is work it never does.

| Pattern | sublimation | Rust | Go | introsort | qsort | Python |
|---|--:|--:|--:|--:|--:|--:|
| sorted | **0.1** | 0.2 | 0.5 | 4.6 | 21.8 | 3.3 |
| equal | **0.1** | 0.3 | 0.5 | 8.5 | 22.8 | 2.6 |
| reversed | 0.5 | **0.4** | 0.8 | 5.2 | 31.0 | 5.2 |
| pipe-organ | **2.9** | 17.5 | 23.1 | 51.0 | 26.6 | 7.9 |
| nearly-sorted | 10.3 | 15.9 | 13.8 | **8.0** | 39.9 | 17.1 |
| few-unique | 13.7 | **2.2** | 8.3 | 17.6 | 53.7 | 57.2 |
| phased | 35.3 | **13.2** | 30.0 | 51.2 | 102.0 | 37.3 |
| random | 33.0 | **16.0** | 66.0 | 48.9 | 96.3 | 127.6 |

Sorted and equal input costs a scan, and pipe-organ — one ascending run and one descending — is read as two runs and merged rather than partitioned, which is where the run-merge tree earns its keep. The honest losses are also here: Rust's pdqsort has a dedicated equal-elements partition that beats the counting sort on few-unique, and introsort wins nearly-sorted at this size.

**Random Sort Performance**

Where there is no structure to exploit, so the radix competes head-on with tuned in-place comparison sorts.

| n | sublimation | Rust pdqsort | Go | introsort | qsort | Python |
|---|--:|--:|--:|--:|--:|--:|
| 100K | 33.0 | **16.0** | 66.0 | 48.9 | 96.3 | 127.6 |
| 1M | **15.6** | 18.1 | 77.8 | 61.6 | 122.8 | 215.5 |
| 10M | **15.6** | 20.6 | 89.5 | 68.9 | 139.7 | 348.8 |
| 100M | **16.0** | 23.2 | 101.6 | 78.9 | 162.0 | 510.1 |

Below the parallel threshold the radix is a serial LSD and Rust's pdqsort wins outright at 100K. From 1M up both poles fork onto the work-stealing deque and sublimation takes the lead, holding flat at 15.6-16.0 ns/element from 1M through 100M while every comparison sort degrades as the working set leaves cache — the crossover the thresholds exist to find. The margin widens with n: 1.2x over Rust at 1M, 1.5x at 100M; against C's `qsort` 8-10x, against Go 5-6x, against Python 14-32x.

**Search Performance**

AMD Ryzen 5 3600, Zen 2, MB/s on 4 MB corpora, higher is better. The harness is in-tree at `sublimation/tests/search/bench/`: Seeded deterministic corpora, median-of-9, with C, C++, Go, Rust-std and Rust-regex comparators, byte-parity-gated against Python `re`, a brute k-mismatch oracle and a position checksum. The regex face against the Rust `regex` crate (ripgrep's engine, SIMD Teddy + lazy DFA) and Go `regexp` (RE2 lineage):

| Pattern | corpus | sublimation | Rust regex crate | Go regexp |
|---|---|--:|--:|--:|
| `A[CG]TT` | DNA | **273** | 234 | 39 |
| `str[a-z]ct` | source | 1.6k | 4.7k | 484 |
| `MARK[A-Z]R` | repetitive | 26.7k | 56.9k | 52.7k |

A scalar bit-parallel field, measured against a SIMD one. It wins where the pattern is dense and literal-poor and the reach-closure memo does the work (`A[CG]TT`, ahead of every engine measured and 7x Go). It loses where a literal prefilter is the whole game and Rust's is vectorized: `str[a-z]ct` by 2.9x and `MARK[A-Z]R` by 2.1x. That is the one standing gap and it is a stated non-goal — Teddy/FDR-class multi-literal SIMD is deliberately not built, because chasing grep's throughput is not what sublimation is for. Against Python `re`, C++ `std::regex` and POSIX the margin is 3-500x on every pattern. **Fuzzy k-mismatch is a face no standard library ships at all**: `SIGKILL` k=1 at 8.8k MB/s, with no competitor to put in the column.

**Build.** Compiled as a static library with montauk. Requires a Haswell-or-newer CPU (BMI2 + AVX2) and gcc 13+ (C23).

**Where montauk uses it:** The process-table sort and the analyzer's orderings (latency quantiles, report rows, struct-by-key sorts via `sublimation_order_*`, value lookups via `searchsorted`); the `sched` report's structure classification and locator; and all of montauk's text matching (kernel-thread classification, the live `/`-search, `--trace` token matching). montauk's C++ carries zero `std::sort`, `std::stable_sort` or `std::nth_element` call sites; every ordering routes through sublimation.

## vector: An agent-facing tool surface

montauk's Rust MCP server — where an agent interrogates the platform directly. Registration is one line, and nothing in it can go stale: No venv, no interpreter to resolve, no PATH entry pointing at a script that moved.

```
claude mcp add --scope project montauk -- components/vector/target/release/vector
```

Seven tools, read-only and observational only (no killing processes, no scheduler-policy changes, nothing mutating, stated explicitly in every tool description). Three return conclusions rather than metrics: What is anomalous, what behaves like a given process and what shifted.

| Tool | Wraps | Function |
|---|---|---|
| `montauk_anomalies` | `montauk --json` features + learn lane (FFI) | fuses MAD + Mahalanobis + Half-Space Trees in-process over the full live process population and returns the top processes by anomaly score with the dominant feature axis and a plain-language note |
| `montauk_similar` | `montauk --json` + spectral lane | the processes behaving like a given one: A standardized feature vector per process, a self-tuning (local-scaling) affinity graph so an outlier query keeps a defined neighborhood, ranked by effective resistance (commute-time distance) FFI'd out of the spectral lane |
| `montauk_regime` | `/proc/stat` + signal lane | did the machine's load regime shift recently, and when: Samples aggregate CPU over a short window and runs Spectral Residual to locate shifts, each with how many seconds ago |
| `montauk_snapshot` | `montauk --json` | one-shot structured snapshot of live system state |
| `montauk_analyze_report` | `montauk_analyze FILE --report ... --json` | diagnostic reports over a trace file as the structured JSON envelope |
| `montauk_digest` | `montauk_analyze DIR --digest --json` | compact specs + stability + thermal + offenders digest over a recording directory |
| `sublimation` | direct FFI into `libsublimation.a` | sort / classify / search, no subprocess spawn per call |

The three conclusion tools compute their math **in-process** through `extern "C"` bindings into the learn, spectral and signal lanes of the same static library `montauk_core` and `montauk_analyze` already link -- the anomaly fusion (`sublimation_anomaly_fuse`, the *same* primitive montauk's own snapshot enrichment calls, so the numbers agree by construction), effective resistance and the Spectral Residual all run over FFI, never a spawned process for the computation. `montauk_anomalies` and `montauk_similar` read the live snapshot from `montauk --json` first (features in, conclusion computed here); `montauk_regime` reads `/proc/stat` directly, needing no snapshot; `montauk_snapshot`, `montauk_analyze_report` and `montauk_digest` wrap the standalone `montauk` and `montauk_analyze` processes.

Four substantive source files plus glue: `rpc.rs` (a hand-rolled JSON-RPC 2.0 loop over stdio; stdout carries protocol messages only, all logging goes to stderr), `json.rs` (a  JSON parser and serializer; `include/util/json.h` is write-only by design, so this is the first thing in montauk that reads JSON), `ffi.rs` (the bindings, linked via `build.rs` against `libsublimation.a`) and `tools.rs` (the tool registry, dispatch and JSON Schemas). `main.rs`/`lib.rs` are the wrapper and module glue.

**Build.** `cd components/vector && cargo build --release`. No CMake target; a separate build tree beside the C++ binary, the same pattern the kernel module (`components/kernel`) uses.

## montauk's CLI Operating Modes

montauk composes its modes from CLI flags:

| Command | Operation |
|---|---|
| `montauk` | TUI only |
| `montauk --log /var/log/montauk` | TUI + Prometheus-format log files |
| `montauk --log /var/log/montauk --log-interval-ms 5000` | Custom write interval (default: 1000ms) |
| `montauk --metrics 9101` | TUI + Prometheus endpoint on :9101 |
| `montauk --headless --metrics 9101` | Daemon mode: Prometheus only, no TUI |
| `montauk --headless --metrics 9101 --log /var/log/montauk` | Daemon mode: both |
| `montauk --headless --log /var/log/montauk` | Daemon mode: logging only |
| `montauk --headless` | Error: requires --metrics or --log |
| `montauk --trace firefox` | Trace mode: per-thread diagnostics for process group |
| `montauk --trace myapp --metrics 9101` | Trace mode + Prometheus endpoint |
| `montauk --trace myapp --log /tmp/trace` | Trace mode + flight recorder |
| `montauk --trace myapp --trace-out FILE.bin` | Trace mode + raw binary event log |
| `montauk --trace myapp --stream-out /dev/ttyS1` | Second binary stream to a character device |
| `montauk --json` | One-shot structured system snapshot (JSON), then exit. |
| `montauk_trace_decode FILE.bin` | Decode a binary log to text (--csv for CSV) |
| `montauk_analyze FILE.bin --json`  | Emit the diagnostic reports as one JSON envelope. |
| `montauk_analyze FILE.bin --report waits` | Run an analysis report over a binary log |
| `montauk --init-theme` | Detect terminal palette, write config.toml |

**Prometheus Metrics Endpoint:**

With `--metrics PORT`, montauk serves Prometheus exposition format (text/plain; version=0.0.4) at `http://localhost:PORT/metrics`. The endpoint reads the same lock-free SnapshotBuffers the TUI uses: No mutexes, no additional overhead. io_uring drives all socket I/O (requires liburing at build time).

Exported metric families (~55 gauges, all prefixed `montauk_`): CPU aggregate and per-core with user/system/iowait/irq/steal breakdown, context switches and interrupts; memory (bytes and percent); per-interface and aggregate network throughput; per-device disk throughput and utilization; per-mount filesystem usage; process state counts; per-process top-N CPU, resident memory, GPU utilization and GPU memory (labeled by PID and command); per-device GPU VRAM, temperature, fan, power and encoder/decoder load.

**Log Writer:**

With `--log DIR`, montauk writes timestamped Prometheus exposition snapshots to disk, rotating hourly as `montauk_YYYY-MM-DD_HH.prom`, each block prefixed with a `# montauk_scrape_timestamp_ms` comment for replay. The LogWriter reads the same SnapshotBuffers; it works independently of or alongside `--metrics`.

**Structured JSON (`--json`):**

Both the monitor and the analyzer emit their state as JSON, so an agent or a script consumes montauk without scraping the TUI or parsing prose.

- `montauk --json` prints one structured snapshot of live system state and exits. It warms two producer cycles so the rate deltas (context switches, network and disk throughput) are real, then serializes system specs, CPU (with per-core), PMU, memory, GPU, thermal, network, disk, filesystems and the ranked top processes as one JSON object. No TUI, no server, no daemon. Paired with `--trace PATTERN`, a second JSON-lines record follows with the live trace snapshot (threads, migrations, ntsync, fds, sched-op counts), one shared walk with the Prometheus renderer so the two surfaces cannot drift apart on a field.
- `montauk_analyze FILE --json` emits the diagnostic reports as one JSON envelope: A `schema_version`, the trace context (path, pattern, event count, format version, start time) and a `reports` array, each report carrying its verdict, typed findings, gauges (with the same help text the Prometheus export uses) and offenders.

The JSON is a renderer, not a second computation. Every report computes a typed result once; the text, Prometheus and JSON surfaces all render from that one result, so they cannot disagree on a number. A byte-identical corpus gate freezes the `json` surface and a per-report parity pass verifies identical gauges in text and JSON (see [Testing](#testing)). The writer is one in-tree serializer (`include/util/json.h`, ~140 lines, no third-party dependency); montauk only ever writes JSON, never parses it.

**Trace Mode (eBPF):**

With `--trace PATTERN`, montauk runs headless and attaches BPF programs to kernel tracepoints (`sched_process_fork/exec/exit`, `raw_syscalls sys_enter/exit`, `sched_switch`, `sched_wakeup`, `signal_deliver`, scheduler-decision tracepoints and per-syscall tracepoints for fd and mmap tracking) and to libc uprobes (heap allocation, the abort path). No `/proc` scanning, no text parsing, no TOCTOU races.

Discovery is event-driven with zero userspace roundtrip on the critical path. The pattern lives in a BPF array map and matches in-kernel, case-insensitively, at four points: The `sched_process_exec` handler (against the exec'd filename and `task->comm`), a process's first syscall (catches `clone()` without `exec()`), `prctl(PR_SET_NAME)` (catches processes that rename themselves) and `sched_process_fork` (children of a tracked parent auto-track; the parent is tracked before it can fork, so children are never missed). Userspace rescan remains as a fallback for edge cases. If no matching process is running, montauk waits for one; it excludes its own process chain. This works for any process model on Linux: Thread pools, container runtimes, daemons that rename themselves.

Per-thread capture: Thread state (R/S/D/T/Z) from `sched_switch`; the current syscall with decoded arguments; on-CPU time; open fds via the openat/close/socket/eventfd2 tracepoints; file I/O (`read`/`write`/`lseek`/`pread64`/`fstat` with fd, byte count, offset and return value); futex ops with op/val/uaddr for wait/wake correlation; heap traffic (`malloc`/`free`/`realloc`/`calloc` via uprobes, size paired with address, realloc moves tracked); signals with a user-mode stack snapshot, abnormal-exit postmortem stacks and the libc abort path (`__assert_fail`/`__libc_message`/`abort`); file-backed mmap (anonymous mappings filtered); scheduler decisions (enqueue / pick / preempt / wakeup / wake-to-run latency, bound by generic role to whatever decision tracepoints the active scheduler exposes; montauk names no scheduler in source); per-thread core and migration counts bucketed intra / cross / unknown-CCX against a sysfs-derived L3-domain map; and ntsync (Wine/Proton NT synchronization ioctls with the waited-on object fds). Scheduler decisions aggregate per-CPU by default (one counter increment, near-zero overhead); `--sched-detail` opts into the heavy per-switch stream (per-CPU idle boundaries, the EEVDF pick fallback) that the placement, slice and stall reports need, at ~6× cost on CPU-cycling workloads.

Trace mode composes with `--metrics` and `--log`: The Prometheus endpoint appends the trace families alongside the system metrics, and the hourly `.prom` files become a flight recorder. The families: `montauk_trace_process_info`, `_thread_state`, `_thread_cpu_percent`, `_thread_syscall`, `_thread_io`, `_fd_target`, `_thread_cpu`, `_thread_migrations`, `_migrations_intra_ccx`/`_cross_ccx`/`_unknown_ccx`, `_ntsync`, `montauk_sched_op_total{op}`, the `montauk_pmu_*` gauges (below) and the group-metadata gauges (`montauk_trace_group_size`, `_thread_total`, `_waiting`).

The trace subsystem runs as a parallel pipeline with its own lock-free seqlock double buffer, independent of the main monitoring pipeline. BPF programs maintain per-thread state maps in the kernel; userspace reads them every 500ms to publish snapshots. Zero `/proc` reads after attach. No impact on the TUI or system metrics when `--trace` is not used.

Runtime requires root (`CAP_SYS_ADMIN` on most configurations). Build requires `libbpf`, `bpftool` and `clang` (BPF target), auto-detected by CMake; if unavailable, `--trace` prints an error.

**Binary Event Log (`--trace-out`):**

The periodic Prometheus snapshot carries aggregate per-thread state. For high-rate event streams (scheduler decisions, heap traffic), formatting each event to text at trace time is a syscall-per-event firehose that perturbs the workload being measured. `--trace-out FILE` writes the raw ring records verbatim, batched into ~256 KB writes (one syscall per batch); trace-time cost per event drops to a memcpy. The header captures `CLOCK_MONOTONIC` and `CLOCK_REALTIME` anchors at trace start, so readers reconstruct absolute wall-clock per event and correlate against external logs. `--stream-out DEVICE` opens a second, independent stream in the same format, meant for a character device (a qemu-backed serial port), so capture survives a hang that takes `--trace-out`'s filesystem down with it. Both are independent of `MONTAUK_TRACE_VERBOSE` (the per-event stderr aid) and `--log` (the Prometheus flight recorder). The offline tools that read the log are covered under [Trace Analysis Tools](#trace-analysis-tools).

**Hardware Performance Counters (PMU):**

Trace mode additionally samples hardware counters via `perf_event_open`: Per-CPU L2 cache misses/references (AMD Zen raw events), instructions, cycles, context switches, CPU migrations, branch misses and, where the `amd_uncore` module exposes the `amd_l3` PMU, per-CCX L3 accesses/misses. Derived rates (IPC, L2 miss percent, cycles-per-L2-miss, per-second rates) export as the `montauk_pmu_*` gauges. The `amd_l3` event encoding comes entirely from sysfs; nothing is hardcoded but the documented Zen2 fallback. This is the cache-placement signal that pairs with the CCX-migration counters: Misses explain why cross-CCX moves hurt.

On the same recording stream montauk derives the efficiency picture from sysfs: Package power from the powercap RAPL counters (`montauk_power_watts`), a wrap-safe cumulative package energy (`montauk_package_energy_joules_total`, whose delta is the digest's window-integral energy), average CPU frequency (`montauk_cpu_frequency_mhz_avg`), per-state idle residency (`montauk_cstate_residency_percent{state}`) and energy-per-instruction (`montauk_energy_per_instruction_pj`). One capture carries temperature, power, clock, idle depth, scheduler churn and the efficiency they imply.

PMU sampling requires `kernel.perf_event_paranoid <= 0` or `CAP_PERFMON` and is exclusive to trace mode by design; the plain monitor never calls `perf_event_open`. If the permission check fails, PMU is disabled with a one-line notice and tracing continues.

**External Metrics Providers:**

montauk ingests external programs' own metrics. `ProviderCollector` scrapes unix sockets named `<name>.sock` in `$XDG_RUNTIME_DIR/montauk/providers/` (fallback `/run/montauk/providers/`): Connect, read one full Prometheus-text snapshot to EOF. Providers self-identify by socket filename; montauk names none in source, and a missing directory or unreachable provider is a silent per-scrape no-op. Provider text passes through montauk's Prometheus exposition verbatim and embeds into the binary trace stream as provider-snapshot records, so a capture carries the external program's self-reported state inline with the kernel events. Export-only: Not shown in the TUI.

## Trace Analysis Tools

Two standalone tools consume a binary trace log (`--trace-out`) offline: No privileges, no live target, no external dependencies. Both share one length-authoritative record walk (validate magic+version; an older decoder skips newer event types cleanly) and build without a `montauk_core` or BPF link, so they decode a capture anywhere. They install alongside `montauk` and must track its version (`montauk_analyze --version` prints it), since a newer `montauk` emits event types an older decoder would silently drop.

**`montauk_trace_decode`** renders a log to a human-readable event stream:

```bash
montauk_trace_decode trace.bin          # one line per event, elapsed + wall timestamps
montauk_trace_decode trace.bin --csv    # CSV for tooling
```

**`montauk_analyze`** runs single-pass diagnostic reports over a log:

```bash
montauk_analyze trace.bin                       # all reports
montauk_analyze trace.bin --report doublefree   # one report
montauk_analyze trace.bin --report waits,spins  # several
montauk_analyze trace.bin --json                # all reports as one JSON envelope
montauk_analyze RECORDING_DIR --digest          # one-call shareable digest
montauk_analyze --version                       # print version, exit
```

Each report folds the file once, so analysis scales to captures of 450 MB+. Generic row qualifiers (`--sig`, `--comm`, `--pid`, `--tid`, `--window`) narrow a report to one signal, task or time window. The suite, by domain:

- **`summary`**: Header, duration, throughput, per type+subtype event counts and the trace-derived dispatch/preempt rates.
- **Sync**: `waits` (per `(tid,fd)` ntsync wait-completion stats), `spins` (livelock detector: Streaks of sub-tick wait completions sustained past a threshold, with a verdict), `pairing` (per object fd, waits vs signal-side ops, to find a signal that never reaches a waiter), `endstate` (who was parked in what wait when the trace ended, and for how long), `futex` (per-uaddr wait/wake stats and who is still blocked), `keyedevt` (keyed-event waits vs releases by critical-section address).
- **Heap**: `heapstk` (unique allocation sites of a size-filtered `malloc`/`calloc`, ranked by count), `doublefree` (an address freed while not live, with both freeing tids/comms; realloc moves tracked so a moved chunk isn't mis-flagged), `abortpm` (per-abort arena post-mortem: Replays the heap stream up to each abort and names the glibc top-chunk overrun victim allocation).
- **Signals**: `signals` (every delivered signal decomposed, with the row qualifiers).
- **I/O**: `iolat` (per-syscall I/O completion latency), `iowait` (who sat parked in a blocking I/O-wait syscall).
- **Scheduler**: `sched` (wake-to-run latency distribution with percentiles, plus a structure classification of the latency sequence through sublimation), `slice` (per-CPU dispatched-slice length between consecutive picks, p50/p90/p99/worst/mean, idle strands excluded), `service` (per-PID CPU service from dispatched slices), `wakers` (localizes request-level latency to the waker's critical path), `work-conservation` (per-CPU idle strands and how each ended), `placement-race` and `dispatch-stall` (decompose tick-floored wakeups into their mechanism), `kick-latency` (kick-issue to response), `storm` (sched_ext cpu_release kick storms), `kstrand` (per-CPU kernel-thread dispatch strands), `locality` (CCX locality of each placement migration), `classmix` (per-class distribution of enqueued tasks), `field-persist` (an adaptive scheduler's structural-reclassification gate over time), `fractal` (self-similarity of the dispatch and migration timeline). The placement, slice and stall reports need a capture taken with `--sched-detail`.

`--json` emits the same reports as one structured envelope, rendered from the same typed results (see Structured JSON above).

**Over a recording directory**, `montauk_analyze` reads a whole `--trace` recording, the `montauk_*.prom` scrapes beside the sibling `.events`:

- `RECORDING_DIR --digest [--redact]` is the one-call shareable report: A SCHEDULER STABILITY block (ejection and clean-room state, what invalidates every number under it) leads above SYSTEM specs, then the ranked POORLY-BEHAVING ITEMS (a consolidated `montauk_offender{}` view over the spin / pairing / idle-strand detectors and the L2 hot-CPU), CROSS-CCX PLACEMENT, THERMAL/POWER (temperature, fan, package power, window-integral energy, clock, idle residency, scheduler churn) and KEY METRICS (the wake-to-run verdict and the dispatch-stall mechanism). Stability-first and KB-scale; `--redact` swaps process comms for stable FNV-1a hash handles for public sharing. With no `.events` present it still reports stability, specs, thermal/power and the offenders derivable from the scrapes.
- `RECORDING_DIR --l2-by-cpu` localizes L2 misses per CPU over the busy window: Which cores eat the misses, and how concentrated.
- `DIR | *.prom [--by LABEL] [--metric SUBSTR] [--full]` computes population statistics across many runs: Cross-version / cross-scheduler inference (Cliff's delta, permutation tests, Monte-Carlo run-count power) over the `.prom` archives, the inferential unit being one run. The `capture` axis splits by filename timestamp, so an uncommitted A/B on the same version still separates instead of folding into one cell.

## Installation

### Simple Install

```bash
./install.py
```

### Advanced Install (CMake)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
sudo cmake --install build   # optional
```

liburing is auto-detected at configure time and enables the Prometheus metrics endpoint; without it montauk builds normally with the endpoint disabled.

### Other Commands

```bash
./install.py build      # Build only, don't install
./install.py clean      # Clean build directory
./install.py uninstall  # Remove installed binary
./install.py test       # Run tests
./install.py --kernel   # Build with kernel module support
./install.py --debug    # Debug build
```

### Arch Linux Package

```bash
makepkg -si   # From the PKGBUILD at the repo root
```

## Uninstall (CMake)

```bash
sudo xargs rm -v < build/install_manifest.txt
```

## Packaging (Arch Linux)

- PKGBUILD at the repo root; `makepkg -si` installs to `/usr/bin/montauk`
- Build deps: `cmake`, `gcc`, `make`
- Optional build: `liburing` (Prometheus endpoint); optional runtime: `nvidia-utils`
- NVML auto-detected at build time; tests off by default

### TUI Process Collection

montauk auto-detects the best available backend, in this priority:

| backend | mechanism | requires | CPU overhead | event detection | syscalls per snapshot |
|---|---|---|---|---|---|
| **kernel module** | genetlink read of the in-kernel table; kprobes update it directly, workqueue refreshes CPU times at 1 Hz; zero `/proc` reads, zero netlink event traffic | `montauk.ko` loaded | ~0.1-0.2% | sub-millisecond | 1 |
| **netlink proc_connector** | fork/exec/exit events from the kernel, `/proc/[pid]/*` reads for details | `CAP_NET_ADMIN` | ~0.5-1% | sub-millisecond | ~1 + N events |
| **/proc polling** | scans `/proc` each cycle; identical functionality and UI | nothing | ~2-5% | ~1s | ~3 per process |

To enable netlink proc_connector when the kernel module isn't loaded:
```bash
sudo setcap cap_net_admin=ep /usr/local/bin/montauk
```

Force a backend for testing:
```bash
MONTAUK_COLLECTOR=kernel ./montauk       # requires montauk.ko
MONTAUK_COLLECTOR=netlink ./montauk      # requires the capability
MONTAUK_COLLECTOR=traditional ./montauk  # /proc polling
```

## TUI Controls

**Navigation:** `q` quits; `↑/↓` scrolls the process list; `PgUp/PgDn` pages.

**Search/Filter:** `/` or `Ctrl+F` enters live case-insensitive substring filtering; `Enter` confirms, `Esc` exits (or clears an active filter from normal mode); `Backspace` deletes (empty backspace exits).

**Sorting:** `c` CPU%, `m` Memory, `g` GPU%, `v` GPU Memory, `p` PID, `n` Name.

**Modes and toggles:**
- `s` toggles SYSTEM focus (right column: Chart stack ↔ text panel)
- `C` (Shift+C) toggles the CPU TOPOLOGY grid (left column; arrows and PageUp/PageDown scroll on high-core systems; `Esc` or `C` returns). The two column toggles are independent.
- `i` toggles CPU scale: Machine-share (100% = the whole machine, processes sum toward system usage) ↔ per-core IRIX-style (100% = one core, multi-threaded apps exceed 100%)
- `u` toggles GPU scale (capacity ↔ utilization)
- `G` toggles the GPU charts (util / VRAM / GPU MEM / ENC / DEC)
- `t` toggles the Thermal section inside SYSTEM focus
- `R` resets the UI; `+/-` adjusts the refresh rate

**Help overlay:** `?` or `h` opens it. The overlay loads `man montauk` at runtime and renders it inside the PROCESS MONITOR column, reflowing to the available width via `MANWIDTH`; edit `montauk.1` and the overlay updates on next open. While open: `j`/`k` scroll, `d`/`Space` page down, `u` page up, `g`/`G` jump, `q`/`?`/`Esc` close.

## Configuration

montauk reads a unified TOML file at `~/.config/montauk/config.toml`, resolving each value TOML → `MONTAUK_*` environment variable → compiled default; no file means compiled defaults at zero overhead. `montauk --init-theme` writes a starter with your terminal's 16-color palette detected. The full schema (`[palette]`, `[roles]`, `[thresholds]`, `[ui]`, `[process]`, `[nvidia]`, `[keybinds]`), the process-collector settings and the complete `MONTAUK_*` reference live in [`CONFIG.md`](CONFIG.md). The process columns, two-column layout and severity color coding are documented in [`CONFIG.md`](CONFIG.md#display-details).

## GPU Support

### NVIDIA

Full NVML integration (recommended): Per-process GPU utilization (SM, encoder, decoder), per-process VRAM, device-level metrics (util, power, temps, clocks), MIG detection and PRIME render offload. Runtime needs `nvidia-utils` (`libnvidia-ml.so.1`); montauk loads NVML dynamically, no dev headers required. Static NVML linkage is an optional CMake opt-in via the `cuda` headers.

When NVML is unavailable or insufficient, montauk walks a fallback chain: Device-level `nvidia-smi --query-gpu=…`, `nvidia-smi pmon` per-process sampling, `nvidia-smi --query-compute-apps` for compute memory, `/proc/driver/nvidia/gpus/*/fb_memory_usage` for device VRAM, then heuristic distribution from device-level metrics.

### AMD/Intel

`/sys/class/drm` for VRAM, temperatures and power; `/proc/*/fdinfo` (DRM) for per-process utilization; `gpu_busy_percent` for device utilization.

### Browser GPU Process Detection

montauk identifies browser GPU processes (Chrome, Chromium, Helium, etc.) by scanning for `--type=gpu-process` in command lines, enriching up to 256 processes with full cmdline data, applying fallback attribution when processes use minimal CPU and inspecting `/proc/*/fd` device files for decode-only workloads.

### GPU Configuration

All GPU settings live under `[nvidia]` in TOML. Env var fallbacks:

```bash
MONTAUK_NVIDIA_PMON=0     # [nvidia] pmon = false
MONTAUK_NVIDIA_MEM=0      # [nvidia] mem = false
MONTAUK_LOG_NVML=1        # [nvidia] log_nvml = true
MONTAUK_NVIDIA_SMI_DEV=0  # [nvidia] smi_dev = false
MONTAUK_NVIDIA_SMI_PATH=… # [nvidia] smi_path = "…"
MONTAUK_SMI_MIN_INTERVAL_MS=1000  # [nvidia] smi_min_interval_ms = 1000
MONTAUK_GPU_DEBUG=1       # [nvidia] gpu_debug = true
MONTAUK_DISABLE_NVML=1    # [nvidia] disable_nvml = true
MONTAUK_NVML_PATH=…       # [nvidia] nvml_path = "…"
```

## Churn Handling

During heavy system activity (builds, installs, rapid process creation), `/proc` and `/sys` entries vanish between directory scans and file reads. This affects the userspace collectors; the kernel module is immune, since it reads `task_struct` directly. montauk absorbs churn without breaking: Churned processes may show partial metrics for one sample, then clear, and the system stays responsive throughout.

When churn is active, the SYSTEM box swaps PROC SECURITY for a PROC CHURN readout: A summary line (`PROC CHURN  N events [LAST 2s]`, colored as caution), a `PROC:X  SYSFS:Y` source breakdown and the affected PIDs (the event count can exceed the visible PIDs, since processes exit before the display updates). When churn subsides, PROC SECURITY returns automatically. Reproduce it with the stress script under [Testing](#testing).

## Testing

**Build with tests:**
```bash
cmake -S . -B build -DMONTAUK_BUILD_TESTS=ON
cmake --build build -j
./build/montauk_tests
```

With liburing, this includes the Prometheus serializer tests. A standalone `montauk_json_test` checks the in-tree JSON writer byte-for-byte and validates its output through `python -m json.tool`.

**One runner (`tests/run.py`)** drives four layers: The C++/C23 unit tests, the Python gate layer, the live BPF trace harness (root; skipped, not failed, without it) and vector's own `cargo test`. The gate layer stacks four proofs:

- `corpus_check.py` freezes the analyzer's reports, the decoder's output, the `sublimation` CLI and the analyzer's `--json` envelope against goldens over a deterministic synthetic capture; any surface changing a byte fails the gate, and a per-report parity pass asserts every report emits identical gauges in its text (`.prom`) and JSON renderings.
- `parity_check.py` runs 74 cases of sublimation verbs against the real coreutils and GNU grep on identical input (one skips where datamash is absent) and fails on any byte divergence: The regression guard that keeps shell-wrapper routing safe.
- `pop_gate.py` pins the population mode: An injected +50% shift must be found (full-magnitude Cliff's delta at the boundary pair) and a stable family must yield no change point.
- `semantic_check.py` rejects any emitted gauge family whose help text is a placeholder or an echo of its own name.

sublimation carries its own standalone suite under `sublimation/tests/` (843k checks green, ASan and TSan clean, with libc sorts surviving only as differential oracles) plus the search byte-parity oracle (Python `re`, brute k-mismatch, position checksum) and the in-tree sort and search benches.

**Self-test mode:** `./build/montauk --self-test-seconds 5`

**Churn stress:** `tests/proc_churn.sh 30 100` spawns and destroys 100 processes/second for 30 seconds to exercise `/proc` resilience on the userspace collectors. Watch it with montauk running (`s` for SYSTEM focus).

Tests are disabled by default in packaging builds (`MONTAUK_BUILD_TESTS=OFF`).

## Policy

Vendoring is enforced, not aspirational: CMake poisons `FetchContent_Declare` and `ExternalProject_Add` with `FATAL_ERROR` at configure time, so a third-party fetch cannot enter the build. NVML and liburing are auto-detected and gracefully disabled when unavailable.

## References

The work the algorithms descend from. Source-comment attributions and the [Lineage](#sublimation-an-adaptive-sort-search-and-learn-core) paragraph resolve here; sibling-project lineage (the OUROBOROS-derived UI, PANDEMONIUM's oscillator envelope) is in-house.

**Lineage.** Influenced by flow-model research (Kyng-Dinic maximum flow, spectral graph theory); the lineage survives in the spectral merge (effective resistance on the run-boundary path Laplacian), the graph-spectral learn lane (effective resistance as commute-time distance, Ng-Jordan-Weiss clustering) and the adaptive-control primitives. The rest of the family tree: Robinson-Schensted correspondence (sorting ↔ Young tableaux), TimSort (the run-adaptive lineage; the prior C++ TimSort/Powersort implementation is archived out of tree), Thompson's NFA construction (the prior regex engine, retired in v8.0.0 for the Glushkov field), Fiedler spectral seriation (Atkins-Boman-Hendrickson), the classical-ML detectors (Iglewicz-Hoaglin robust z, Tan-Ting-Liu Half-Space Trees, Ren et al. Spectral Residual), CoDel and damped-oscillator adaptive control, AlphaDev-shaped AVX2 sorting networks, and the radix arm (Wassenberg-Sanders write-combining, Skarupke's ska_sort and American Flag MSD, the eloj/radix-sorting notes).

**Sorting and structure**
- G. de B. Robinson, "On the Representations of the Symmetric Group", American Journal of Mathematics 60, 1938. C. Schensted, "Longest increasing and decreasing subsequences", Canadian Journal of Mathematics 13, 1961.
- J. S. Frame, G. de B. Robinson and R. M. Thrall, "The hook graphs of the symmetric group", Canadian Journal of Mathematics 6, 1954.
- D. Aldous and P. Diaconis, "Longest increasing subsequences: from patience sorting to the Baik-Deift-Johansson theorem", Bulletin of the AMS 36, 1999.
- J. Baik, P. Deift and K. Johansson, "On the distribution of the length of the longest increasing subsequence of random permutations", Journal of the AMS 12, 1999.
- T. Peters, "Timsort", CPython `Objects/listsort.txt`, 2002. J. Ian Munro and S. Wild, "Nearly-Optimal Mergesorts" (Powersort), ESA 2018 — the run-adaptive merge lineage.
- O. R. L. Peters, "Pattern-defeating Quicksort", arXiv:2106.05123, 2021.
- D. J. Mankowitz et al., "Faster sorting algorithms discovered using deep reinforcement learning", Nature 618, 2023 — the AVX2 small-sort networks.
- J. Wassenberg and P. Sanders, "Engineering a Multi-Core Radix Sort", Euro-Par 2011 (write-combining buffered scatter); M. Skarupke, "I Wrote a Faster Sorting Algorithm" (ska_sort) and American Flag sort, 2016-2017; the eloj/radix-sorting notes — the radix arm.
- N. M. Lê, A. Pop, A. Cohen and F. Zappa Nardelli, "Correct and Efficient Work-Stealing for Weak Memory Models", PPoPP 2013 — the Chase-Lev deque the parallel engine is built on.
- L. Bergdoll and O. Peters, ipnsort, the Rust standard library's `sort_unstable` implementation as of Rust 1.81, 2024 — a perf comparator.

**Text matching**
- K. Thompson, "Programming Techniques: Regular expression search algorithm", Communications of the ACM 11(6), 1968.
- V. M. Glushkov, "The abstract theory of automata", Russian Mathematical Surveys 16, 1961.
- R. S. Boyer and J S. Moore, "A fast string searching algorithm", Communications of the ACM 20(10), 1977. R. N. Horspool, "Practical fast searching in strings", Software: Practice and Experience 10(6), 1980.

**Spectral and flow heritage**
- M. Fiedler, "Algebraic connectivity of graphs", Czechoslovak Mathematical Journal 23, 1973.
- A. Y. Ng, M. I. Jordan and Y. Weiss, "On Spectral Clustering: Analysis and an algorithm", NIPS 14, 2001.
- D. J. Klein and M. Randić, "Resistance distance", Journal of Mathematical Chemistry 12, 1993.
- J. E. Atkins, E. G. Boman and B. Hendrickson, "A spectral algorithm for seriation and the consecutive ones problem", SIAM Journal on Computing 28(1), 1998.
- E. A. Dinic, "Algorithm for solution of a problem of maximum flow in a network with power estimation", Soviet Mathematics Doklady 11, 1970.
- L. Chen, R. Kyng, Y. P. Liu, R. Peng, M. Probst Gutenberg and S. Sachdeva, "Maximum Flow and Minimum-Cost Flow in Almost-Linear Time", FOCS 2022.

**Randomness battery**
- C. Bandt and B. Pompe, "Permutation entropy: a natural complexity measure for time series", Physical Review Letters 88, 174102, 2002.
- B. Luque, L. Lacasa, F. Ballesteros and J. Luque, "Horizontal visibility graphs: Exact results for random time series", Physical Review E 80, 046103, 2009.
- J. P. Zbilut and C. L. Webber Jr., "Embeddings and delays as derived from quantification of recurrence plots", Physics Letters A 171, 1992.
- N. Marwan, M. C. Romano, M. Thiel and J. Kurths, "Recurrence plots for the analysis of complex systems", Physics Reports 438, 2007.

**Learn lane, anomaly detection and signal**
- B. Iglewicz and D. C. Hoaglin, "How to Detect and Handle Outliers", ASQC Quality Press, 1993 (the MAD modified z-score).
- B. P. Welford, "Note on a method for calculating corrected sums of squares and products", Technometrics 4(3), 1962.
- S. C. Tan, K. M. Ting and T. F. Liu, "Fast Anomaly Detection for Streaming Data", IJCAI 2011 (Half-Space Trees).
- H. Ren et al., "Time-Series Anomaly Detection Service at Microsoft", KDD 2019 (Spectral Residual).

**Adaptive control**
- K. Nichols and V. Jacobson, "Controlling Queue Delay", ACM Queue 10(5), 2012. RFC 8289, "Controlled Delay Active Queue Management", 2018.

## License

GPL-2.0, see the [`LICENSE`](LICENSE) file. sublimation is covered by the same license. One license, one tree.
