# Background FRE AOT with mid-file cutover

## Result

The revised prototype fixes both defects in the first background-AOT version:

- `--fre-aot-background` now promotes from the normal ripgrep matcher to FRE
  inside a file, at safe complete-line boundaries. It no longer waits for the
  next file.
- FRE native code is published directly in process through
  `fre-aot-regex-loader`. There is no object-file round trip, Clang process,
  dynamic linker, or temporary native-code directory.

On the selected synthetic no-match workload, the controlled comparison against
the same candidate binary with the flag off improved fresh-process wall time by
2.23x to 6.70x. Default-thread tree searches improved by 2.65x to 3.28x. Every
timed background process compiled the query anew and naturally cut over inside
at least one file.

| Workload | Flag off | Background AOT | Paired speedup (descriptive 95% interval) | Upstream / AOT |
|---|---:|---:|---:|---:|
| 64 MiB, 1 thread | 31.275 ms | 14.061 ms | **2.231x** [2.166, 2.315] | 3.082x |
| 256 MiB, 1 thread | 111.492 ms | 24.978 ms | **4.559x** [4.337, 4.753] | 6.543x |
| 256 MiB mmap control | 116.013 ms | 24.203 ms | **4.771x** [4.635, 5.029] | 6.546x |
| 1 GiB, 1 thread | 449.529 ms | 66.803 ms | **6.699x** [6.447, 6.900] | 9.132x |
| 8 x 64 MiB, default threads | 48.270 ms | 18.290 ms | **2.654x** [2.526, 2.769] | 3.146x |
| 16 x 64 MiB, default threads | 84.142 ms | 25.440 ms | **3.281x** [3.193, 3.399] | 4.047x |

The `Upstream / AOT` column is an end-to-end control, not a clean attribution
to AOT. The candidate's flag-off path was itself 1.19x to 1.42x faster than the
fresh unmodified upstream build. The paired flag-off/background column is the
controlled estimate of this feature's incremental effect.

All six cells passed the predeclared stability checks. Their intervals are
descriptive and are not adjusted for the six comparisons.

## What changed

The normal ripgrep matcher is constructed first and starts searching
immediately. An independent thread compiles the configured HIR with FRE's
optimizing Span compiler. Once `publish_span` installs the immutable native
mapping, matcher workers observe it through shared publication state.

While native code is pending, ripgrep's fast line search advances in roughly
1 MiB windows extended through the next complete newline-terminated line. A
negative stock window is then irrevocably complete, so the worker can poll and
give the unconsumed suffix to FRE without replaying output or changing match
semantics at an artificial byte boundary. Captures and matcher metadata remain
owned by the stock matcher.

Across all 192 background timing samples:

- median FRE compilation was 2.079 ms;
- median direct publication was 19.0 microseconds;
- median readiness was 2.202 ms and median first cutover was 2.220 ms;
- every result was `ready`, every sample used both engines in one file, and
  every sample used AOT;
- there were zero external-linker invocations, declines, unfinished compiles,
  or native-call failures.

For single-file searches, the median stock prefix was 4.59 to 4.97 MiB. FRE
searched the rest of the same file. Under default parallelism, 7--8 of 8 files
and 11--12 of 16 files were mixed per sample, while every file used AOT.

## Correctness evidence

The correctness gate deliberately delayed publication until at least 8 MiB of
stock work had committed. In the one-file positive fixture, exact matches were
placed on opposite sides of that boundary:

- line 1025, byte offset 4,198,299;
- line 4097, byte offset 16,781,211;
- observed promotion after 8,450,048 committed bytes.

Flag-off, background-AOT, and unmodified upstream ripgrep produced identical
status, stdout, stderr, line numbers, byte offsets, and match bytes. A second
gated case used ripgrep's default worker count; all eight files were mixed and
the route-byte accounting covered the exact 512 MiB corpus.

The full timing run contained 576 fresh process executions. All had identical
status/stdout/stderr within their 192 three-arm samples. The timed query was
`a{0,99}b`, which is absent from the fixed AOT registry and absent from the
candidate binary's registered-pattern strings. No application-level compiled
matcher cache was used.

## Scope and limitations

This is strong evidence for the mechanism and this workload, not a general
ripgrep speedup claim:

- The corpus is synthetic, ASCII, newline-dense, warm in the OS page cache,
  and contains no match for a deliberately favorable FRE expression.
- The smallest timed input was 64 MiB, so this run does not locate the
  fresh-query break-even below 64 MiB.
- Output-heavy and capture-heavy paths are not part of the performance matrix;
  stock capture handling has unit and integration coverage.
- The tree cells pass explicit file paths. Directory discovery/traversal is not
  timed.
- Complete-line boundaries are the safe promotion points. A single giant line
  or a haystack-anchored expression remains on one engine for that matcher
  call while publication is pending.
- Eligibility is deliberately conservative. Unsupported flags, semantics,
  platforms, compiler failures, and publication failures retain the stock
  matcher.
- These results are from one macOS ARM64 host. The one-minute load average was
  5.75--7.53 on 18 CPUs during the run; paired variance and order checks still
  passed, but this was not a literally idle machine.

## Reproduction and provenance

The measured candidate source is commit `752d2703433ea2ff0f940978e9d78864e66885b5`
and binary SHA-256
`36345e49610a7b44eb33d2168ac2004dd3fa7d6668f2c23da04d750333f75c41`.
The unmodified upstream control is commit
`f9c05a949d1a0dc8e16dee28ca9605d38611faeb` and binary SHA-256
`c23ebfd27192ae14b7c59acf33adf2b62e1af380422fdf6657b0a6d0294f43c6`.

FRE is pinned to `6f961465d00ff50f2096cfb05520c0653a87d2cd`, which includes the
in-process Span loader and is published on FRE `main`.

Artifacts:

- `results/benchmark-final.json` — all raw samples, receipts, commands,
  outputs, timing summaries, load, and provenance; SHA-256
  `61753a89aa6da16b8008d1763480aeb30ff411270389a22dea091e91cea9e022`.
- `results/correctness-r9.json` — exact forced-cutover checks; SHA-256
  `84033fd3c0f03ccec80786f461ae5872799e89ba67a4a74e37a9d3c0180a3575`.

The commands and corpus-generation procedure are in `README.md`. Every timed
arm is a new ripgrep process, so startup, parsing, stock matcher construction,
FRE compilation, in-process publication, searching, output handling, and exit
are inside the wall-clock boundary.
