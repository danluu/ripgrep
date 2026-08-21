# Representative background-AOT experiment

The completed local and EC2 results are in [RESULTS.md](RESULTS.md).

This harness tests the normal ripgrep path against the same binary with
`--fre-aot-background` on frozen, actual ripgrep query shapes. It does not use
the earlier synthetic `a{0,99}b` workload.

The primary cohort is the frozen 84-query out-of-time set reconstructed from
Codex history. Selection predates this integration and its performance
results. Every query runs in all three panels:

1. A clean archive of ripgrep `f9c05a9`, with normal line output and default
   threads. This transplant is known to contain 25 matching and 59 nonmatching
   queries.
2. A clean archive of FRE `6f96146`, with normalized
   `--count --include-zero` output and default threads.
3. The same FRE archive and output contract with `--threads=1`.

An optional deterministic sample from the larger frozen expression inventory
is included in panels 2 and 3. A spelling's first chronological retained
semantics and target class define its sampled profile; the report separates
cases whose retained semantics required normalization. Public JSON contains aggregates only. The
private JSON contains the exact patterns and per-process observations and is
ignored by Git.

## Probe first

Build the stock and candidate binaries, then run the correctness and
classification probe. This is not a formal timing run:

```sh
python3 experiments/background-aot-representative/harness.py probe \
  --binary target/release/rg \
  --candidate-source . \
  --stock-binary /Users/danluu/dev/ripgrep/target/release/rg \
  --stock-source /Users/danluu/dev/ripgrep \
  --inventory-root /Users/danluu/dev/rg-aot \
  --database /Users/danluu/.codex/thread_history_1.sqlite \
  --ripgrep-corpus-repo /Users/danluu/dev/ripgrep \
  --ripgrep-corpus-commit f9c05a949d1a0dc8e16dee28ca9605d38611faeb \
  --fre-corpus-repo /Users/danluu/dev/fre-rg-midscan-deps-20260820 \
  --fre-corpus-commit 6f961465d00ff50f2096cfb05520c0653a87d2cd \
  --private-output experiments/background-aot-representative/results/probe.private.json \
  --public-output experiments/background-aot-representative/results/probe.public.json
```

The probe uses one fresh process per stock/normal/background observation. It
compares default-thread output as an unordered multiset of complete LF records
because worker scheduling can reorder records. Thread-1 output is compared
byte-for-byte. Profile declines, compile failures, publication refusals,
timeouts, runtime-helper requirements, and queries that never cut over all
remain in the aggregate denominator.

For a remote AArch64 profile matrix, repeat `--cpu-profile` in the requested
order, for example `--cpu-profile auto --cpu-profile sve --cpu-profile sve2`.
`asimd` is also accepted as an optional control. An unsupported requested
profile is recorded as a decline, never silently replaced with `auto`.
Receipts report the requested, host, and effective feature masks plus the
compiler engine and actual start accelerator. On a remote SVE host, add (for
example) `--expected-sve-vl-bytes 16` to fail closed if the process vector
length is not the audited value. Profiles run profile-major, so their adjacent
normal/background speedups are valid but cross-profile uplift is not paired.
Fast queries may finish before the compiler thread detects the host; those
receipts retain an explicit unfinished lifecycle state. Before formal timing,
the complete probe matrix must nevertheless contain at least one fully
target-validated receipt for every requested CPU profile, all with one common
host feature mask.

## Small remote selection manifest

Remote hosts do not need the 3.4 GB history database or 125 MB private
inventory. Export the exact already-frozen selection locally:

```sh
python3 experiments/background-aot-representative/harness.py export-selection \
  --inventory-root /Users/danluu/dev/rg-aot \
  --database /Users/danluu/.codex/thread_history_1.sqlite \
  --wider-sample-size 128 --wider-sample-seed 168239142 \
  --output experiments/background-aot-representative/private/selection.json
```

Copy only that mode-0600 JSON to the remote host. For both its probe and
benchmark commands, replace `--inventory-root ... --database ...` with:

```sh
--selection-manifest-input /private/path/selection.json
```

The standalone file preserves every case ID, cohort, exact expression,
retained semantics, suffix, weight, and source class. Its declared counts,
selection knobs, frozen-source provenance, and canonical manifest digest are
validated before and after each workload. Only this standalone selection-v1
envelope is accepted for transport; a probe-private result lacks the frozen
selection-knob envelope and is deliberately rejected.

## Formal paired timing

Only start this after reviewing a complete, clean probe:

```sh
python3 experiments/background-aot-representative/harness.py benchmark \
  [the same input options as probe] \
  --probe-public experiments/background-aot-representative/results/probe.public.json \
  --probe-private experiments/background-aot-representative/results/probe.private.json \
  --pairs 12 --warmup-pairs 2 \
  --private-output experiments/background-aot-representative/results/benchmark.private.json \
  --public-output experiments/background-aot-representative/results/benchmark.public.json
```

Each sample contains three fresh processes: preserved upstream stock, the
candidate's normal path, and the candidate's background-AOT path. A four-order
rotation balances whether stock comes before or after while keeping normal and
background adjacent and balancing NB/BN. Timed processes do not write receipts,
because receipt publication would charge only the background arm; all receipt
classification comes from the mandatory matching untimed probe. The primary
statistic is the median paired `normal/background` elapsed-time ratio for each
pattern, but only when every configured sample for that pattern has valid
statuses and exact stock/normal/background output. The report also shows NB
versus BN medians and their order effect. It then computes an
equal-unique-pattern distribution and geometric mean. Preserved
`stock/background`, occurrence weighting within each cohort, and stable-only
results are secondary diagnostics. Occurrence weights are never mixed across
the OOT and wider cohorts because their windows and inclusion probabilities
differ, and selected versus successfully measured occurrence-weight totals are
reported so censoring cannot silently renormalize that diagnostic. Each corpus
is materialized once before the workload and then scanned repeatedly without
cache eviction. Results therefore represent fresh query processes and fresh
AOT compilation over an uncontrolled, deliberately cache-hot filesystem—not a
cold-cache first traversal. A
formal run refuses a probe with missing cases, output mismatches, receipt
validation failures, changed binaries, changed source, changed corpus trees,
changed host/toolchain/SVE vector length, a changed raw cohort manifest, or
changed frozen inventory. Both public result files bind their complete private
counterpart by SHA-256. The formal gate reconstructs the exact
profile/panel/case row matrix,
recomputes semantic output equality and receipt validation from private
evidence, and requires its regenerated aggregates to equal the public report.
Provenance parses the candidate's Cargo manifest and
lockfile to require its actual FRE git dependency revision to equal the corpus
commit. It separately requires the local FRE corpus source mirror to be clean,
and records rustc/cargo, corpus file counts/bytes, and start/end host load
averages.

These are historical query transplants, not replays of historical commands:
the original targets, target sizes, match densities, and complete argv are not
available. The normalized count panels isolate matcher/payback behavior, while
the default-output panel exposes early-match and output costs.
