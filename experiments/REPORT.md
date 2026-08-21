# Real ripgrep + FRE AOT experiment

## Result

This implementation proves a narrow result, not a general new-query speedup.

An ordinary, fresh `rg --engine=fre ...` process can be materially faster than
stock ripgrep when its exact query was compiled into the binary and the corpus
matches a favorable specialization. With AArch64 ASIMD enabled, the strongest
64 MiB cells were 1.81x-1.86x faster end to end. The overlapping-literal
mixed-log cell was 1.18x faster.

It does **nothing faster for an arbitrary new query**. A registry miss builds
and uses ripgrep's stock Rust matcher. In this run that control was 3% slower,
not faster. The registered trace and source-like cells were also 4%-10% slower.
The large wins came from deliberately discriminating, single-line `a...a`
corpora, so they establish that the FRE specialization can survive real
ripgrep process/searcher/printer overhead; they do not establish broad value
for normal ad-hoc source searches.

There is no query cache, cross-query fusion, daemon, multi-query batching, or
amortization across invocations here. Every sample launches one new process
and runs one normal ripgrep query.

## What was implemented

- `--engine=fre` is a real ripgrep engine choice.
- Ripgrep's walker, searcher, sinks, printer, and output modes are unchanged.
- A fixed build-time registry selects FRE `Optimizing + Span` only for an
  exact pattern/profile key.
- Registry misses and unsupported profiles transparently use the stock
  `grep::regex::RegexMatcher`.
- `SearchWorker::clone` creates a separately prepared FRE handle for each
  worker. Handles are never shared concurrently.
- Captures and matcher metadata are delegated to the stock matcher. This
  preserves replacement/color behavior, but it also means a registry hit
  still pays the stock regex compilation cost at process startup.
- FRE's internal Span iterator may refill several spans per native call. That
  is an implementation detail inside one query/haystack, not batching queries.

The current FRE eligibility profile is deliberately conservative: exactly one
case-sensitive pattern, no word/line boundary rewriting, no fixed-string
rewriting, no multiline or CRLF mode, no NUL line terminator, and Unicode
syntax enabled. Any other profile falls back.

The fixed registry contains:

```text
(?:ab|a)
(?:aaaaaaaaab|aaaaaaaab|aaaaaaab|aaaaaab|aaaaab|aaaab|aaab|aab|ab)
a{0,100}b
(?:a|aa)*b
ERR_SYS|PME_TURN_OFF|LINK_REQ_RST|CFG_BME_EVT
```

The ASIMD build logs identify every entry as
`route=direct-native`, `engine=ordered-dfa`,
`accelerator=aarch64-asimd`, and `features=0x100000000`.

## Correctness

The unmodified upstream test suite passed:

```text
118 unit tests passed
323 integration tests passed
```

The experiment-specific verifier compared the preserved stock binary against
`--engine=fre` for registered hits, registry/profile fallbacks, `-o`, color,
replacement, stdin, a parallel `-j4` search, no-match exit status, and all 12
shape/size combinations. All 31 cases had identical exit status and
byte-identical stdout and stderr. The ASIMD record is
`artifacts/raw/correctness-asimd.json`.

## Headline ASIMD timings

The unit is one query in one newly launched process. Each cell has three
unrecorded warm-up pairs and 31 recorded pairs in alternating AB/BA order.
Both processes capture stdout/stderr identically, and every timed pair is
rejected unless status and output bytes are equal. The OS filesystem cache is
warm; there is no application cache. `stock/FRE > 1` favors FRE.

The ratio column is the ratio of separate medians. The final column is the
median of the 31 paired ratios with a deterministic percentile-bootstrap 95%
interval; it is descriptive, not a claim about other machines or corpora.

| Cell | Stock ms | FRE ms | Ratio of medians | Paired median [95%] |
|---|---:|---:|---:|---:|
| ordered, generated logs, count lines | 29.441 | 30.943 | 0.951x | 0.945x [0.934, 0.968] |
| overlapping literals, generated logs, count matches | 50.597 | 42.834 | 1.181x | 1.169x [1.157, 1.183] |
| trace alternation, generated logs | 25.961 | 28.686 | 0.905x | 0.902x [0.889, 0.918] |
| ordered alternation, real ripgrep source concat | 4.836 | 5.048 | 0.958x | 0.983x [0.976, 0.994] |
| trace alternation, real ripgrep source concat | 3.743 | 4.048 | 0.925x | 0.934x [0.925, 0.940] |
| unregistered query fallback, generated logs | 20.387 | 21.050 | 0.969x | 0.967x [0.944, 0.979] |
| unsupported `-i` fallback, generated logs | 35.527 | 35.465 | 1.002x | 0.992x [0.973, 1.012] |
| registered query, tiny file/startup control | 2.854 | 2.859 | 0.998x | 1.008x [0.976, 1.043] |
| `(?:a|aa)*b`, negative 64 KiB | 2.847 | 2.857 | 0.996x | 0.983x [0.965, 0.991] |
| `(?:a|aa)*b`, sparse final `b` 64 KiB | 2.855 | 2.822 | 1.012x | 0.998x [0.967, 1.032] |
| `(?:a|aa)*b`, negative 1 MiB | 3.258 | 2.967 | 1.098x | 1.096x [1.067, 1.114] |
| `(?:a|aa)*b`, sparse final `b` 1 MiB | 3.243 | 3.520 | 0.921x | 0.906x [0.896, 0.929] |
| `(?:a|aa)*b`, negative 64 MiB | 35.310 | 18.939 | **1.864x** | **1.867x [1.851, 1.882]** |
| `(?:a|aa)*b`, sparse final `b` 64 MiB | 36.759 | 52.556 | **0.699x** | **0.694x [0.686, 0.712]** |
| `a{0,100}b`, negative 64 KiB | 3.541 | 3.544 | 0.999x | 1.005x [0.985, 1.041] |
| `a{0,100}b`, sparse final `b` 64 KiB | 3.464 | 3.578 | 0.968x | 0.983x [0.961, 0.995] |
| `a{0,100}b`, negative 1 MiB | 4.131 | 3.881 | 1.064x | 1.064x [1.025, 1.094] |
| `a{0,100}b`, sparse final `b` 1 MiB | 4.124 | 4.084 | 1.010x | 1.032x [0.981, 1.062] |
| `a{0,100}b`, negative 64 MiB | 37.038 | 20.130 | **1.840x** | **1.872x [1.825, 1.888]** |
| `a{0,100}b`, sparse final `b` 64 MiB | 36.851 | 20.411 | **1.805x** | **1.820x [1.794, 1.836]** |

The `(?:a|aa)*b` sign reversal is especially important. ASIMD rejects a
64 MiB haystack with no required final `b` very quickly, but finding a `b` at
the end and reconstructing the leftmost span is 30% slower than stock. This is
not a generally dominant matcher; routing must account for pattern *and input
distribution*.

## Scalar diagnostic run

The first run accidentally emitted `features=0x0` scalar FRE objects, which
was unfair to FRE on an Apple M5 Max where Advanced SIMD is available. It is
preserved and labeled diagnostic rather than silently discarded:

- overlapping mixed-log cell: 0.739x
- trace mixed-log cell: 0.626x
- ambiguous negative 64 MiB: 1.009x
- bounded negative 64 MiB: 1.010x
- bounded sparse-final-`b` 64 MiB: 1.011x

The complete scalar samples are in
`artifacts/raw/fresh-process-benchmark-scalar.json`. The SIMD correction is
the source of the large favorable cells; it is not caching or fusion.

## Interpretation for a new query

For a truly new, ad-hoc query, realism is currently zero: the binary has no
matching AOT artifact, so it runs stock ripgrep. To make this useful for new
queries would require a real compile/publish path (or a sufficiently broad
ahead-of-time catalog plus a trustworthy router) whose compilation, loading,
code size, and break-even point are included in the measurement.

For a known query compiled before deployment, the experiment is realistic at
the CLI integration level: it is a fresh process and uses stock ripgrep I/O
and output machinery. It is not yet representative at the workload level.
The only >1.25x cells are selected 64 MiB, mostly single-line synthetic shapes;
the real-source and trace-shaped cells miss that threshold and regress.

## Revisions and environment

- ripgrep base: `f9c05a949d1a0dc8e16dee28ca9605d38611faeb`
- FRE dependency: clean detached worktree at
  `b1dfe2b159433b0430e33a7703e2a5c7f3ad8c2d`
- host: Apple M5 Max, macOS arm64, 18 logical CPUs
- compiler: `rustc 1.93.0`, LLVM 21.1.8
- build: ripgrep `release` profile, using `--ignore-rust-version` because this
  upstream revision declares Rust 1.96
- stock binary: 5.7 MiB,
  SHA-256 `85245572a1f1e35f0293ee8f73fef6e213b44e05a6b7e0ff0fded109add39019`
- ASIMD FRE binary: 7.1 MiB,
  SHA-256 `5ea3bc80ac1cecd3ad7ae32c2add0b3df26db07b30506039e149da025a9a6637`

After timing, a clean-source rebuild produced a different whole-file hash
because the timed build had seen a rustfmt-only line-layout change in the
detached FRE worktree. The formatting change was reversed and the dependency
worktree is clean. The clean rebuild and preserved timed binary have identical
Mach-O sizes and a byte-identical `__TEXT,__text` section (SHA-256
`76b5d057a13dd54659b31964efdc4bff4e36b93efddd5615736bd03331b067eb`).
Their 1,048 differing bytes are confined to the Mach-O UUID, source-location
constants, and link/debug metadata; the timed machine code is exactly
reproduced by the clean revision.

The clean `/Users/danluu/dev/ripgrep` worktree and dirty
`/Users/danluu/dev/fre-3` worktree were not modified. All implementation and
experiment files live in the isolated ripgrep worktree; the FRE dependency
worktree is clean at the revision above.

## Artifacts

- Full SIMD samples: `artifacts/raw/fresh-process-benchmark-asimd.json`
- Full scalar samples: `artifacts/raw/fresh-process-benchmark-scalar.json`
- Compact statistics and bootstrap intervals:
  `artifacts/raw/benchmark-summary.json`
- Correctness matrix: `artifacts/raw/correctness-asimd.json`
- Route evidence: `artifacts/raw/route-asimd-*.log`
- Exact registry: `experiments/fre-patterns.tsv`
- Corpus generator: `experiments/generate_benchmark_corpus.py`
- Equivalence verifier: `experiments/verify_equivalence.py`
- Benchmark harness: `experiments/benchmark_fresh_process.py`
- Reproduction commands: `experiments/COMMANDS.md`

## Limitations

- Patterns and shape corpora were selected using prior FRE evidence; this is
  not a blind held-out aggregate result.
- The 64 MiB shape files are adversarial single lines, not ordinary source or
  log files.
- The real-source corpus is a deterministic 3.16 MiB concatenation of 228
  tracked non-NUL files, so startup is a large share of its elapsed time.
- Filesystem pages are warm after explicit warmups; cold-storage behavior was
  not tested.
- The registry is built for Apple arm64 ASIMD and is not a portable release
  artifact.
- The candidate still compiles a stock Rust matcher on a registry hit for
  fallback/capture metadata, making startup conservative but preserving
  semantics.
- This does not include the cost of adding a new pattern to the registry and
  rebuilding the binary.
