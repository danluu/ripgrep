# Normal ripgrep with background FRE AOT cutover

> Status: experiment complete. The committed-HEAD binary passed all 17
> correctness cases and the final 18-cell, 31-pair run completed without an
> output/status mismatch. The hybrid wins for selected long sequential scans,
> but loses through 1 GiB when ripgrep uses its default parallel workers.

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

This prototype's native publication path is macOS/AArch64-only and invokes
`/usr/bin/clang` to turn FRE's object into a loadable Mach-O bundle. Other
platforms asynchronously decline and continue entirely with stock ripgrep.
The conservative synchronous eligibility gate also declines multiple patterns,
case-insensitive modes, `-F`, `-w`, `-x`, multiline, CRLF, null-data, and
no-Unicode searches. Decline is fallback behavior, not a search error.

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
| `bounded-negative-default-threads-{8,16}x64m` | 8--16 × 64 MiB | Same favorable negative shape with ripgrep's default worker count and default no-match output; tests whether concurrent AOT still pays back against normal parallel search. |
| `unregistered-bounded-negative-{8,16}x64m` | 8--16 × 64 MiB | Single-thread fresh-query control for `a{0,99}b`, which is deliberately absent from the build-time fixed AOT registry. |
| `unregistered-bounded-default-threads-16x64m` | 16 × 64 MiB | The same unregistered query with ripgrep's default worker count. |
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

The primary break-even curve fixes one search thread. The two
`default-threads` controls omit both `--threads` and `--sort`; on this host
ripgrep may use up to 12 search workers while the compiler consumes another
core. Because the corpus has no match, default output is deterministically
empty with status 1 even though scheduling order is nondeterministic. These
controls are reported separately and cannot satisfy the sequential break-even
definition.

The original shape patterns also exist in the candidate's older fixed AOT
registry. The background route nevertheless recompiles them and publishes a
new process-local artifact, but that overlap weakens a “previously unseen
query” demonstration. The `unregistered-bounded` cells close that evidentiary
gap: `a{0,99}b` is not in `experiments/fre-patterns.tsv` and is compiled only by
the background path during each measured process.

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

The correctness and timing harnesses run without `--debug` or `--trace`, so
compiler and routing diagnostics do not share stdout or stderr. They use a
unique create-new path named by `RG_FRE_AOT_BACKGROUND_RECEIPT`. Thus a
background compiler failure cannot be hidden by excluding diagnostic lines
from the equality check. Explicit ripgrep debug/trace logging can still report
the route on stderr, as normal for those modes.

## Receipt gate

Every flagged timing invocation publishes schema
`ripgrep.fre-aot-background.v1`. The harness validates:

- outcome is exactly `ready`, `declined`, or `unfinished`;
- `stock_files + fre_aot_files == total_file_attempts`;
- cutover ordinal and timestamp exist if and only if an FRE file exists;
- publication readiness precedes the first cutover;
- `compile_ns` measures only FRE's in-process `compile(request)` call;
- `prepare_ns` measures the preparation-attempt duration through success or
  early failure; only a `ready` outcome proves object write, link, load, and
  symbol resolution all completed;
- each phase duration is zero if that phase did not return before the exit
  snapshot; a nonzero `prepare_ns >= compile_ns`, and a `ready` receipt has a
  nonzero preparation duration plus an artifact-ready timestamp at least as
  large as `prepare_ns`;
- declined and unfinished runs never report an FRE file;
- the timing matrix retains every valid outcome; actual mixed stock/FRE samples
  are counted instead of requiring cutover as a harness precondition;
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
receipt necessarily completed its entire compile/write/link/load transaction
and made the artifact available inside the measured process lifetime. The only
performance endpoint is complete child wall time.

An “FRE file” means FRE performs group-zero span and matching-line discovery
for that file. Ripgrep's stock matcher still owns capture extraction and matcher
metadata, so replacement and capture output remain governed by stock semantics.
After promotion, an invalid native status or span becomes a search error rather
than accepted data; the implementation never swaps routes in the middle of a
file.

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
  --output experiments/background-aot/results/correctness-r4.json
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
  --fre-repo /Users/danluu/dev/fre-rg-aot-deps-20260820 \
  --require-clean \
  --output experiments/background-aot/results/benchmark-r2.json
```

The final artifact records ripgrep and FRE source commits/status, Rust/Cargo,
Clang/Xcode, binary and manifest hashes, host metadata, raw results, exact
commands, output digests and bytes, receipts, statistics, per-cell start/end
timestamps and load averages, a post-run corpus verification, and the
predeclared break-even result. A partial artifact is rewritten after every
completed cell, outside every child timing boundary.

## Results

Run 2 is the final artifact. It binds clean ripgrep commit `8a4b97b3be`, clean
FRE commit `b1dfe2b159`, candidate SHA-256 `7e2a4fa6...1537d3c`, stock SHA-256
`85245572...add39019`, and corpus-manifest SHA-256
`9f7a3682...631f6b5`. The matching `correctness-r4.json` uses the same candidate
and stock hashes and passes 17/17 cases. The raw benchmark SHA-256 is
`7f2d5dfd...b1a3c5c3`; the correctness artifact is
`92cc0837...a11d691`. The final full
`cargo +1.96.0 test --workspace --no-fail-fast -j1` run exited successfully,
including all 323 CLI integration tests and workspace doctests.

Ratios below are paired `normal/background`; values above 1 favor background
AOT. “Mixed” counts samples that searched at least one file with stock and a
later file with FRE. A dagger marks a cell that failed the predeclared 15%
order/rMAD stability gate.

| Cell | Normal / background median | Paired ratio [descriptive 95%] | Mixed samples; median stock/FRE files |
|---|---:|---:|---:|
| tiny fresh process | 2.884 / 6.953 ms | 0.410 [0.394, 0.421] | 0/31; 1/0 |
| bounded 1×64 MiB | 31.681 / 38.336 ms | 0.824 [0.818, 0.827] | 0/31; 1/0 |
| bounded 2×64 MiB | 56.009 / 135.290 ms | 0.422 [0.377, 0.450]† | 0/31; 2/0 |
| bounded 4×64 MiB | 93.296 / 127.362 ms | 0.732 [0.659, 0.752]† | 0/31; 4/0 |
| bounded 8×64 MiB | 175.710 / 152.160 ms | **1.159 [1.143, 1.173]** | 31/31; 6/2 |
| bounded 16×64 MiB | 345.313 / 193.120 ms | **1.769 [1.759, 1.807]** | 30/31; 6/10 |
| bounded default threads, 8×64 MiB | 69.986 / 164.380 ms | 0.447 [0.405, 0.457]† | 0/31; 8/0 |
| bounded default threads, 16×64 MiB | 119.623 / 180.476 ms | 0.666 [0.653, 0.675] | 0/31; 16/0 |
| **unregistered** bounded 8×64 MiB | 194.508 / 167.690 ms | **1.156 [1.148, 1.171]** | 31/31; 6/2 |
| **unregistered** bounded 16×64 MiB | 365.387 / 204.083 ms | **1.789 [1.769, 1.818]** | 30/31; 6/10 |
| **unregistered** bounded default threads, 16×64 MiB | 117.947 / 176.016 ms | 0.669 [0.654, 0.685] | 0/31; 16/0 |
| ambiguous negative, 8×64 MiB | 173.837 / 153.166 ms | 1.138 [1.131, 1.170] | 31/31; 6/2 |
| ambiguous positive, 8×64 MiB | 176.036 / 211.176 ms | 0.834 [0.831, 0.838] | 31/31; 6/2 |
| overlap mixed logs, 8×64 MiB | 318.812 / 289.161 ms | 1.105 [1.101, 1.118] | 31/31; 4/4 |
| trace mixed logs, 8×64 MiB | 159.793 / 167.769 ms | 0.953 [0.944, 0.960] | 29/31; 7/1 |
| bounded ordinary output, 8×64 MiB | 173.388 / 149.146 ms | 1.165 [1.159, 1.167] | 31/31; 6/2 |
| ignore-case synchronous decline | 208.716 / 218.259 ms | 0.966 [0.944, 0.973] | 0/31; 8/0 |
| ordered source-shaped, 8×64 MiB | 263.136 / 261.540 ms | 1.004 [1.001, 1.007] | 30/31; 4/4 |

### What the result means

The predeclared discrete sequential break-even is 8×64 MiB, or 512 MiB, for
the selected negative `a{0,100}b` shape. All 31 samples used both engines and
the cell was stable. This is a first observed tested point, not a precise
threshold or a familywise 95% claim. The unregistered `a{0,99}b` query closely
reproduces it: 1.156× at 512 MiB and 1.789× at 1 GiB. That establishes a real
fresh-query runtime compile/link/load/cutover result rather than a fixed-registry
lookup. Since 512 MiB was the smallest unregistered size tested, it is not an
estimated fresh-query break-even.

FRE core compilation itself was about 2.0--2.2 ms for these bounded queries,
but full successful preparation was about 123--131 ms. Object emission,
external linking, loading, and symbol resolution therefore dominate readiness.
At 512 MiB the median route was six stock files followed by two FRE files; at
1 GiB it was six stock then ten FRE. Publication is useful only because later
file boundaries remain after that roughly 125 ms delay. One registered and one
unregistered 1 GiB sample had an unusually long preparation attempt and never
published, so larger input does not monotonically guarantee cutover.

Default parallelism reverses the result. Every worker claimed all 8 or 16 files
before the artifact became ready, so all 31 samples stayed entirely stock while
also paying concurrent compilation and shutdown/cleanup cost. The registered
and unregistered 1 GiB controls were respectively 0.666× and 0.669× normal
ripgrep. Larger file sets might eventually leave a later scheduling wave, but
there is no observed default-thread break-even through 1 GiB.

Wall latency is not free CPU parallelism. For the unregistered sequential query,
the reported median user+system sums were about 191/222 ms (normal/background)
at 512 MiB, but 362/259 ms at 1 GiB once the faster native scan dominated. The
unregistered default-thread 1 GiB control used about 823/887 ms while also
losing wall time. Background compilation must therefore be judged on both
latency and CPU cost at the intended scale.

The matcher is also shape-sensitive. With nearly identical stock/FRE routing,
the ambiguous negative case won 1.138× while its positive counterpart lost at
0.834×. The source-shaped gain was only 0.4%, below the level that should drive
an engineering decision. An eligible compiler route is not evidence that FRE
will be faster for that query and corpus.

The first full run was superseded because an unrelated test began halfway
through and drove its ending load average to 37.7. Run 2 recorded per-cell load;
the one-minute value ranged from 6.4 to 12.4 on this 18-core host and all cells
except the marked 2-file, 4-file, and default-thread-8 controls passed the
stability rule. It was a moderate-load paired run, not an idle-host result.
Nevertheless, the key run-1/run-2 paired ratios reproduced closely: bounded
512 MiB 1.153/1.159, bounded 1 GiB 1.767/1.769, and default-thread 1 GiB
0.677/0.666.

## Threats and interpretation limits

- The 64 MiB one-line shape files are adversarial, selected inputs. The mixed
  logs and repeated source concatenation are synthetic too.
- File-boundary cutover makes file size and ordering part of the mechanism.
  A repository of tiny files, one huge file, stdin, or an early `-q` exit can
  expose a different fraction of FRE work.
- Warm filesystem pages model repeated searches, not cold storage.
- Background compilation changes CPU allocation and may contend with search.
- Core FRE compilation can be abandoned before filesystem work starts. Once
  object writing/link/loading begins, normal shutdown waits to reap Clang and
  remove the private temporary directory; an early exit can therefore pay that
  tail. Abnormal process termination can still strand temporary files.
- A structurally compilable query is not necessarily faster under FRE; the
  positive ambiguous and trace/source controls are specifically expected to
  show this.
- Bootstrap intervals describe repeated executions on this host and corpus,
  not machines or query populations.
- A win here would establish that fresh compilation can be hidden and
  amortized for selected long multi-file queries. It would not justify making
  the flag default or claim a general ripgrep speedup.
