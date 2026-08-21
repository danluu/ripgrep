# Background FRE AOT mid-scan experiment

This is the receipt-v2 replacement for `experiments/background-aot`. The old
experiment measured file-boundary selection and an external-linker pipeline;
those results do not describe the direct in-process publisher or line-aligned
mid-file promotion.

The experiment asks two separate questions:

1. **Does promotion work correctly inside a file?** `correctness` uses the
   private publication gate
   `RG_FRE_AOT_BACKGROUND_TEST_MIN_STOCK_BYTES=8388608`. This deterministically
   holds publication until at least 8 MiB has been scanned by the stock engine.
   Exact status/stdout/stderr equality (including line and byte offsets),
   `stock_committed_bytes`, and receipt-v2 `mixed_engine_files` telemetry must
   then prove stock-to-AOT promotion in one file. A second case exercises the
   same transition with ripgrep's default worker count.
2. **Does it make a fresh ordinary query faster?** `benchmark` launches a new
   process for every arm and runs the deliberately unregistered expression
   `a{0,99}b`. It compares the same candidate binary with the flag off and on,
   in alternating AB/BA pairs. No application AOT cache is involved.

The correctness gate is never a timing tool. The benchmark refuses to start if
that environment variable is inherited and also removes it from every child
environment. Natural all-stock, mixed, and all-AOT routing are measurements,
not benchmark preconditions.

## Protocol

Build the candidate release binary and preserve an upstream/stock release
binary separately. Formal runs require a clean source commit; the harness
records the candidate and upstream hashes, Rust toolchain, Cargo/config hashes,
and the commit-pinned FRE dependency, then verifies them again after the run.
Generate the newline-dense negative corpus:

```sh
python3 experiments/background-aot-midscan/generate_corpus.py
```

The default corpus contains 64 MiB, 256 MiB, and 1 GiB single-file cells plus
sixteen independently named 64 MiB tree shards. Files consist of 4096-byte
newline-terminated records, so a safe scan quantum can end at a line boundary.
The separate correctness file has one match before and one after the 8 MiB
publication gate. Use `--single-mib` repeatedly to make a smaller pilot corpus.

Run correctness before timing:

```sh
python3 experiments/background-aot-midscan/harness.py correctness \
  --binary target/release/rg \
  --stock-binary /absolute/path/to/upstream/rg \
  --output experiments/background-aot-midscan/results/correctness.json
```

Run the fresh-process benchmark only after correctness passes:

```sh
env -u RG_FRE_AOT_BACKGROUND_TEST_MIN_STOCK_BYTES \
python3 experiments/background-aot-midscan/harness.py benchmark \
  --binary target/release/rg \
  --stock-binary /absolute/path/to/upstream/rg \
  --pairs 31 --warmup-pairs 3 \
  --output experiments/background-aot-midscan/results/benchmark.json
```

The primary timing comparison is candidate flag-off (the normal ripgrep query
engine) versus the same binary with `--fre-aot-background`, which avoids
conflating unrelated fork changes with AOT speedup. The preserved upstream
binary is also timed as a secondary standard-ripgrep control. The primary
statistic is the median paired `normal/background` ratio with a descriptive
bootstrap interval and variance/order-effect checks. A ratio above 1 means the
background-AOT arm is faster.

Interpret each timing cell together with its receipt summary:

- `mixed_samples` reports natural same-file promotion.
- `all_aot_samples` means publication beat the first matcher window.
- `stock_only_samples` means the query ended before usable publication.
- `publish_ns` measures direct in-process publication; every receipt must state
  `external_linker_invocations: 0` and `direct_native_only: true`.
- `stock_committed_bytes` counts the line-aligned candidate-search prefix that
  cannot be replayed after promotion. Window-byte counters include matcher
  inputs and may overlap, so they should not be used as throughput denominators.

The primary cells use ordinary ripgrep I/O (no forced mmap). Single-file cells
fix `--threads=1`, with one 256 MiB forced-mmap control. The
`tree-8x64m-default-threads` and `tree-16x64m-default-threads` cells omit
`--threads`; `--quiet` on a no-match corpus keeps output deterministic while
requiring a full scan. One newline-free giant line, and patterns with absolute
haystack anchors, remain indivisible while publication is pending because no
semantically safe intermediate line boundary exists.
