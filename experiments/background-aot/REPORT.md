# Normal ripgrep with background FRE AOT cutover

> Status: protocol and harness implemented; no benchmark numbers have been
> collected yet.

## Question

This experiment asks whether one ordinary, fresh ripgrep invocation can start
searching immediately with ripgrep's normal Rust regex matcher, compile a
direct-native FRE Span matcher concurrently, publish it safely, and use it for
later files in that same invocation. The opt-in is the separate
`--fre-aot-background` flag. It is not `--engine=fre`, a daemon, a precompiled
registry, a query batch, or a cross-process cache.

The primary comparison is the same binary and query with the flag off and on.
A preserved unmodified upstream binary versus the new binary with the flag off
is a secondary code-layout/integration control.

## Why the corpus is multi-file

Promotion is a file/reader-boundary decision. A file that starts with the stock
matcher finishes with that matcher; an AOT artifact is never swapped into an
active sink or matcher call. Consequently, a single 64 MiB file can show
compile overhead or publication-too-late behavior, but it cannot demonstrate a
stock-to-FRE cutover after that file begins.

The primary generated unit is therefore one 64 MiB file. The break-even curve
uses prefixes of 1, 2, 4, 8, and 16 files: 64 MiB through 1 GiB of logical
input. The first large file gives compilation useful overlap; later files give
the published matcher work over which to amortize compilation and publication.
Every scaling row records whether publication happened soon enough. A
too-late compile is retained as a result instead of failing the harness; only
rows where every sample actually used both routes can qualify as a measured
cutover break-even.

## Predeclared workload cells

| Cell family | Files × size | Purpose |
|---|---:|---|
| `tiny-fresh-process-control` | 1 tiny file | Startup/cancellation tail control; preparation will often be unfinished and no cutover is required. |
| `bounded-negative-{1,2,4,8,16}x64m` | 1--16 × 64 MiB | Primary discrete break-even curve for `a{0,100}b` over long `a...c` files. The fixed-AOT experiment found this favorable at 64 MiB. |
| `ambiguous-negative-8x64m` | 8 × 64 MiB | Favorable selected-shape control for `(?:a\|aa)*b` with no final `b`. |
| `ambiguous-positive-8x64m` | 8 × 64 MiB | Sign-reversal control. Fixed AOT was slower when a final `b` forced span reconstruction. |
| `overlap-mixed-log-8x64m` | 8 × 64 MiB | Newline-dense overlapping-literal case; fixed AOT had a modest end-to-end win. |
| `trace-mixed-log-8x64m` | 8 × 64 MiB | Trace-shaped registered case that regressed with fixed AOT. |
| `bounded-negative-default-output-8x64m` | 8 × 64 MiB | Ordinary default-output no-match search, ensuring the timing evidence is not confined to `--count`. |
| `ignore-case-declined-8x64m` | 8 × 64 MiB | Guaranteed synchronous eligibility decline; measures flag/routing overhead while all files remain stock. |
| `ordered-source-shaped-8x64m` | 8 × 64 MiB | Optional source-shaped control when the generator is given a clean source repository. Fixed AOT regressed on the corresponding real-source pattern. |

The shape cells are deliberately selected from prior evidence. They expose the
mechanism and its break-even point; they are not a blind estimator for normal
source searches. The positive and trace/source controls prevent a favorable
shape from being reported as a generally dominant matcher.

The generator uses independent regular-file copies by default. Its `hardlink`
mode is a labeled, space-saving pilot only and the timing harness refuses it
unless explicitly overridden.

## Correctness gate

`verify_correctness.py` compares three fresh processes for every case:

1. candidate binary, flag off;
2. the same binary with `--fre-aot-background`;
3. preserved unmodified upstream ripgrep.

It requires identical exit status and literal byte equality for stdout and
stderr. The matrix covers line output, only-matching output, replacement and
captures, forced color, no-match status, files-with-matches, anchors/empty
matches, stdin, an invalid expression, ignored-case and multi-pattern decline,
one-file completion, sequential negative and positive real cutovers, a
receipt-proven named-capture replacement after cutover, a nullable native
iterator after a mid-search cutover across 4,096 tiny files, a four-worker
no-match cutover, and early-match cancellation. The tiny one-file checks still
validate stock/unfinished behavior; they are not presented as active-FRE
coverage.

Compiler and routing diagnostics never share stdout or stderr. They use a
unique create-new path named by `RG_FRE_AOT_BACKGROUND_RECEIPT`. Thus a
background compiler failure cannot be hidden by excluding diagnostic lines
from the equality check.

## Receipt gate

Every flagged timing invocation publishes schema
`ripgrep.fre-aot-background.v1`. The harness validates:

- outcome is exactly `ready`, `declined`, or `unfinished`;
- `stock_files + fre_aot_files == total_file_attempts`;
- cutover ordinal and timestamp exist if and only if an FRE file exists;
- publication readiness precedes the first cutover;
- `compile_ns` measures only FRE's in-process `compile(request)` call;
- `prepare_ns` measures the complete background transaction through object
  write, link, load, symbol resolution, and publication readiness;
- each phase duration is zero if that phase did not complete before the exit
  snapshot; a completed `prepare_ns >= compile_ns`, and a `ready` receipt has
  a nonzero preparation duration plus a readiness timestamp at least as large
  as `prepare_ns`;
- declined and unfinished runs never report an FRE file;
- a cutover cell has `ready`, `stock_files > 0`, and `fre_aot_files > 0` on
  every warmup and measured invocation;
- the ignore-case control reports `declined` and remains entirely stock.

`ready` with zero FRE files is reported separately as “compiled too late to
cut over.” Such a sample is never silently reclassified as an AOT run.

## Exact timing boundary and cache semantics

The parent process starts `time.perf_counter_ns` immediately before launching
one child and stops only after the child exits and its stdout/stderr pipes are
drained. Inside that wall interval are:

- ripgrep process startup and normal matcher construction;
- fresh FRE compilation and preparation work performed before process exit;
- object writing, linking, loading, and immutable-factory publication when
  preparation finishes;
- normal and FRE searches selected at file boundaries;
- traversal, reads, sinks, count formatting, output, receipt serialization,
  cleanup, and process exit.

Compilation overlaps search, so compile or preparation time is not added to
search time as a separate phase. The receipt records core compilation,
full-preparation, readiness, and cutover offsets to show where that overlap
occurred. On a short `unfinished` run, the child can exit before preparation
completes; its wall time includes the background work actually performed up to
exit, not a hypothetical completed artifact. Any sample with a `ready`
receipt necessarily completed its entire compile/write/link/load/publication
transaction inside the measured process lifetime. The only performance
endpoint is complete child wall time.

There is no persistent compiled-query cache. Every flagged sample starts a new
process and recompiles. Each invocation gets a unique `TMPDIR`; any file or
directory left there besides the finalized receipt is fatal. Unrecorded pairs
warm executable, compiler, and corpus pages in the operating-system cache, but
they cannot warm an application AOT artifact. This is therefore a fresh
compile with warm OS pages—not a persistent-cache hit and not a cold-storage
measurement.

The harness also records child user and system CPU. Background compilation can
spend an additional core to reduce wall latency, so wall speedup must not be
presented as CPU-efficiency improvement.

## Pairing and inference

Each cell receives three unrecorded warmup pairs and 31 recorded adjacent
pairs. Order alternates normal/background then background/normal, with phase
rotated by cell. Every pair is equality-checked. The primary statistic is the
median of paired `normal elapsed / background elapsed` ratios; values above one
favor background AOT. A deterministic 20,000-resample percentile bootstrap
gives a descriptive 95% interval. Raw samples, per-order medians, relative MAD,
and relative order effect are retained. A cell is stable only when both arms'
relative MAD and the relative difference between AB and BA paired-ratio medians
are at most 15%.

The discrete break-even is predeclared as the smallest tested primary scaling
stable cell where every measured pair has a real stock-to-FRE cutover and the
paired 95% lower bound exceeds 1.0. If no cell qualifies, the result is “no
observed break-even through 1 GiB.” A valid receipt is required for every
flagged sample; `unfinished`, ready-without-cutover, and mixed-route outcomes
are retained and summarized rather than discarded.

Selected cells also run 11 paired upstream/flag-off comparisons. These are
secondary diagnostics only; the primary denominator is the exact same binary
without the new flag.

## Reproduction

Run from `/Users/danluu/dev/ripgrep-fre-aot-background-20260820`.
Generate physically independent 64 MiB files. The optional source control is
bound to the recorded source commit and tracked non-NUL contents:

```sh
python3 experiments/background-aot/generate_corpus.py \
  --output experiments/background-aot/data \
  --source-repo /Users/danluu/dev/ripgrep
```

Build the candidate in release mode (the repository's Cargo configuration
supplies the FRE dependency/build settings):

```sh
cargo +1.96.0 build --release --bin rg -j1
```

Then run the full correctness gate before timing. The stock binary below is
the preserved build of the common upstream base:

```sh
python3 experiments/background-aot/verify_correctness.py \
  --binary target/release/rg \
  --stock-binary /Users/danluu/dev/ripgrep-fre-aot-20260820/artifacts/bin/rg-stock-f9c05a9 \
  --manifest experiments/background-aot/data/manifest.json \
  --output experiments/background-aot/results/correctness.json
```

Then run the paired benchmark on an otherwise idle host:

```sh
python3 experiments/background-aot/benchmark.py \
  --binary target/release/rg \
  --stock-binary /Users/danluu/dev/ripgrep-fre-aot-20260820/artifacts/bin/rg-stock-f9c05a9 \
  --manifest experiments/background-aot/data/manifest.json \
  --pairs 31 \
  --warmup-pairs 3 \
  --stock-pairs 11 \
  --require-clean \
  --output experiments/background-aot/results/benchmark.json
```

The final artifact records source status, binary and manifest hashes, versions,
host metadata, raw results, exact commands, output digests and bytes, receipts,
statistics, a post-run corpus verification, and the predeclared break-even
result. A partial artifact is rewritten after every completed cell, outside
every child timing boundary.

## Results

No timings have been run.

| Cell | Normal median | Background median | Normal/background paired median [95%] | Stock/FRE files | Result |
|---|---:|---:|---:|---:|---|
| Primary scaling rows | TBD | TBD | TBD | TBD | TBD |
| Favorable controls | TBD | TBD | TBD | TBD | TBD |
| Regression controls | TBD | TBD | TBD | TBD | TBD |
| Decline control | TBD | TBD | TBD | 8/0 expected | TBD |

## Threats and interpretation limits

- The 64 MiB one-line shape files are adversarial, selected inputs. The mixed
  logs and repeated source concatenation are synthetic too.
- File-boundary cutover makes file size and ordering part of the mechanism.
  A repository of tiny files, one huge file, stdin, or an early `-q` exit can
  expose a different fraction of FRE work.
- Warm filesystem pages model repeated searches, not cold storage.
- Background compilation changes CPU allocation and may contend with search.
- A structurally compilable query is not necessarily faster under FRE; the
  positive ambiguous and trace/source controls are specifically expected to
  show this.
- Bootstrap intervals describe repeated executions on this host and corpus,
  not machines or query populations.
- A win here would establish that fresh compilation can be hidden and
  amortized for selected long multi-file queries. It would not justify making
  the flag default or claim a general ripgrep speedup.
