# Representative background-AOT experiment

The completed local and EC2 results are in [RESULTS.md](RESULTS.md). Those
checked-in results are historical Span-entry runs with v3 receipts. The
current harness emits `ripgrep.fre-aot-background.v5` SelectedEnd receipts and
continues to validate existing v4 evidence without reinterpreting v3 results.
V5 adds an authenticated primary-native-route record and keeps a Teddy leaf's
retained semantic-DFA incumbent explicitly separate from that primary route.
It also attests whether receipt-only compiler settlement was requested and
whether the compiler thread reached a definitive outcome.

This harness tests the normal ripgrep path against the same binary with
`--fre-aot-background` on frozen, actual ripgrep query shapes. It does not use
the earlier synthetic `a{0,99}b` workload for performance results; that
pattern appears only in the deterministic correctness-only cutover gate
described below.

The primary cohort is the frozen 84-query out-of-time set reconstructed from
Codex history. Selection predates this integration and its performance
results. Every query runs in all three panels:

1. A clean archive of ripgrep `f9c05a9`, with normal line output and default
   threads. This transplant is known to contain 25 matching and 59 nonmatching
   queries.
2. A clean archive of the frozen FRE corpus commit `6f96146`, with normalized
   `--count --include-zero` output and default threads.
3. The same FRE archive and output contract with `--threads=1`.

An optional deterministic sample from the larger frozen expression inventory
is included in panels 2 and 3. A spelling's first chronological retained
semantics and target class define its sampled profile; the report separates
cases whose retained semantics required normalization. Public JSON contains aggregates only. The
private JSON contains the exact patterns and per-process observations and is
ignored by Git.

## Fast exact-Teddy census

Before designing a timed gate, `exact-teddy-census` runs each of the frozen
212 queries exactly once per requested CPU profile on the canonical
single-thread count panel. It invokes only the background candidate, records
no timing samples, and selects IDs solely from the authenticated compiler
primary-route receipt after a hidden receipt-only teardown join has settled
the compiler. Both `wait_requested` and `compiler_settled` must be true and
the outcome must be non-`unfinished`. Ordinary probes never request this wait
and do not embed or claim a compiler-selected census. The private result contains fully qualified
`profile/cohort/private-id` sets; the public result contains counts and
tier/ISA/scanner contracts only. This diagnostic does not claim benchmark
eligibility:

```sh
python3 experiments/background-aot-representative/harness.py exact-teddy-census \
  --binary target/release/rg \
  --candidate-source . \
  --stock-binary /Users/danluu/dev/ripgrep/target/release/rg \
  --stock-source /Users/danluu/dev/ripgrep \
  --inventory-root /Users/danluu/dev/rg-aot \
  --database /Users/danluu/.codex/thread_history_1.sqlite \
  --ripgrep-corpus-repo /Users/danluu/dev/ripgrep \
  --ripgrep-corpus-commit f9c05a949d1a0dc8e16dee28ca9605d38611faeb \
  --fre-corpus-repo /Users/danluu/dev/fre-teddy-census-0ed0d09a-20260821 \
  --fre-corpus-commit 6f961465d00ff50f2096cfb05520c0653a87d2cd \
  --private-output experiments/background-aot-representative/results/teddy-census.private.json \
  --public-output experiments/background-aot-representative/results/teddy-census.public.json
```

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
  --fre-corpus-repo /Users/danluu/dev/fre-teddy-census-0ed0d09a-20260821 \
  --fre-corpus-commit 6f961465d00ff50f2096cfb05520c0653a87d2cd \
  --private-output experiments/background-aot-representative/results/probe.private.json \
  --public-output experiments/background-aot-representative/results/probe.public.json
```

The clean `--fre-corpus-repo` checkout must be at the exact FRE revision pinned
by the candidate (`0ed0d09a2816716f47b244d44711a1070e52f3c1` for this
iteration), while `--fre-corpus-commit` deliberately remains the older frozen
`6f96146` corpus. The harness verifies both independently. This keeps the
searched bytes constant as compiler dependencies evolve.

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
compiler engine and actual start accelerator. A successfully compiled v4/v5
receipt also identifies the `selected_end` output contract, the
`selected_end_search_v1` entry ABI, the source of any reported machine
geometry, forward/reverse analysis state counts, and whether the compiler
selected its reverse start-recovery pass. Counts and their source are null when
no complete-machine receipt exists; an `ordered_nfa` semantic engine may still
report them when the native optimizer selected a DFA/K0 sidecar. Contextual
analysis may retain reverse geometry even though the SelectedEnd native entry
does not use it, so the separately authenticated
`compiled_reverse_start_recovery: false` field is the code-generation claim.
All six compiled fields are null when compilation has not succeeded yet. On a
remote SVE host, add (for example) `--expected-sve-vl-bytes 16` to fail closed if the process
vector length is not the audited value. Profiles run profile-major, so their
adjacent normal/background speedups are valid but cross-profile uplift is not
paired. Fast queries may finish before the compiler thread detects the host;
those receipts retain an explicit unfinished lifecycle state. Before formal
timing, the complete probe matrix must nevertheless contain at least one fully
target-validated receipt for every requested CPU profile, all with one common
host feature mask.

The v4/v5 route counters describe candidate discovery only. A mixed-engine file
can merely reflect different matcher operations. A genuine mid-scan cutover is
counted separately and requires a nonempty, line-aligned stock prefix to be
committed before AOT scans a later suffix. Candidate file/byte totals and the
first strict mid-scan witness are aggregated alongside both classifications.
Stock span and capture calls are reported and
aggregated separately because SelectedEnd can locate a candidate endpoint and
still use the stock matcher to recover output spans or captures; that work is
not a candidate-discovery engine cutover.

Specifically, candidate discovery reports `candidate_stock_files`,
`candidate_fre_aot_files`, `candidate_mixed_engine_files`, stock/AOT window
counts and bytes, `candidate_stock_committed_bytes`, and
`candidate_midscan_cutover_files`. The three
`first_candidate_midscan_cutover_*` values are either all null or all
nonnegative, and a reported witness must have positive committed stock bytes.
Only positive-length input scans count as candidate windows or file routes;
an empty-haystack nullable probe cannot manufacture a mid-scan transition.
Stock follow-up work uses the separate `stock_span_calls`, `stock_span_bytes`,
`stock_capture_calls`, and `stock_capture_bytes` counters.

Before the historical-query matrix, the probe also runs one synthetic,
correctness-only SelectedEnd gate for each CPU profile. A single 16 MiB
newline-dense file contains exactly two bounded-repeat matches, one before and
one on the final line after a deterministic 4 MiB publication barrier. Candidate-normal,
candidate-background, and upstream ripgrep must produce identical literal
`--only-matching --byte-offset --line-number` output. The background receipt
must prove one real same-file mid-scan transition, positive stock and AOT
candidate work, in-memory publication with no native-call failure, the
`selected_end_search_v1` ABI, and no selected reverse-start-recovery pass.
The barrier environment variable is scrubbed from every historical-query
probe and every timed invocation; this synthetic gate is never included in a
speedup aggregate.

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
validation failures (including a non-SelectedEnd compiled contract/ABI or
invalid candidate/stock-work accounting), changed binaries, changed source,
changed corpus trees, changed host/toolchain/SVE vector length, a changed raw
cohort manifest, or changed frozen inventory. Both public result files bind
their complete private counterpart by SHA-256. The formal gate reconstructs
the exact profile/panel/case row matrix,
recomputes semantic output equality and receipt validation from private
evidence, and requires its regenerated aggregates to equal the public report.
Provenance parses the candidate's Cargo manifest and
lockfile to require its actual FRE git dependency revision to equal the clean
local FRE mirror's HEAD. It separately authenticates the older frozen corpus
commit and tree from that mirror, and records rustc/cargo, corpus file
counts/bytes, and start/end host load averages.

These are historical query transplants, not replays of historical commands:
the original targets, target sizes, match densities, and complete argv are not
available. The normalized count panels isolate matcher/payback behavior, while
the default-output panel exposes early-match and output costs.
