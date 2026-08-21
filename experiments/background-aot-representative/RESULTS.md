# Background FRE AOT on actual queries: results

## Conclusion

The favorable result from the earlier bounded-repeat synthetic query was not
representative. On a broader set of 212 actual Codex-generated ripgrep
expressions, unconditional background FRE AOT regressed overall on the 71 MB
FRE corpus. On the EC2 AArch64 host, the automatic CPU profile made the
default-thread count workload **12.2% slower** and the one-thread workload
**42.9% slower** by equal-pattern geometric mean. Pure SVE and the SVE2 tier
also regressed. The 3.25 MB default-output workload was essentially neutral,
but it normally finished before any scan cut over to AOT, so it is not evidence
of an AOT speedup.

There are real individual wins: the best automatic-profile, one-thread query
was 1.346x faster, and 50 of 212 queries were faster than the normal engine.
That makes selective admission or better query-specific code generation worth
investigating. The current implementation should not enable FRE AOT for every
eligible query. In particular, the present FRE route performs poorly on many
of the longer, alternation-heavy expressions in this sample.

## EC2 timing results

The primary ratio is:

```text
candidate normal elapsed / candidate --fre-aot-background elapsed
```

A ratio greater than 1 favors background AOT. A ratio below 1 is a regression;
for example, 0.700x means the background-AOT elapsed time was 42.9% higher,
not merely 30% higher. Each pattern's value is the median of eight paired
ratios. The table's geometric mean gives every unique pattern equal weight.
`Stable` counts patterns whose per-arm relative MAD was at most 15% and whose
normal-first/background-first order effect was within 0.90--1.10.

| CPU target | Workload | Patterns | Stable | Geometric mean | Median | p10--p90 | Background elapsed |
|---|---|---:|---:|---:|---:|---:|---:|
| auto | ripgrep tree, default output/threads | 84 | 30 | 0.9949x | 0.9958x | 0.9040--1.0969x | +0.5% |
| auto | FRE tree, count, default threads | 212 | 150 | 0.8909x | 0.9901x | 0.5518--1.1075x | +12.2% |
| auto | FRE tree, count, one thread | 212 | 212 | 0.7000x | 0.8834x | 0.3360--1.0984x | +42.9% |
| pure SVE | ripgrep tree, default output/threads | 84 | 40 | 0.9877x | 0.9952x | 0.8768--1.0717x | +1.2% |
| pure SVE | FRE tree, count, default threads | 212 | 141 | 0.8372x | 0.9673x | 0.5133--1.0981x | +19.4% |
| pure SVE | FRE tree, count, one thread | 212 | 212 | 0.6420x | 0.7242x | 0.3701--1.0011x | +55.8% |
| SVE2 tier | ripgrep tree, default output/threads | 84 | 33 | 0.9888x | 0.9941x | 0.8740--1.1362x | +1.1% |
| SVE2 tier | FRE tree, count, default threads | 212 | 137 | 0.8756x | 0.9830x | 0.5661--1.0957x | +14.2% |
| SVE2 tier | FRE tree, count, one thread | 212 | 212 | 0.7361x | 0.8462x | 0.4374--1.0478x | +35.8% |

The result is not caused only by adding the wider cohort. Under `auto`, the
84-query out-of-time cohort and the 128-query wider cohort both regressed:

| Workload | Out-of-time 84 | Wider 128 |
|---|---:|---:|
| FRE count, default threads | 0.9443x | 0.8575x |
| FRE count, one thread | 0.7478x | 0.6703x |

The preserved upstream-stock/background geometric means closely match the
same-candidate normal/background results. The candidate's flag-off path is
therefore not hiding the conclusion.

## Query cohorts and corpora

The exact 212-query selection was frozen before the formal timing run:

- The primary cohort contains 84 unique, out-of-time expressions from 85
  eligible occurrences. All are case-sensitive regular expressions. Their
  lengths range from 10 to 266 characters (median 56), and they have one to 20
  unescaped alternation arms outside character classes (median three).
- The wider cohort is a deterministic 128-unique-expression sample selected
  with seed `168239142` from the larger frozen history inventory. Its lengths
  range from 9 to 365 characters (median 63.5), and it has one to 22
  unescaped alternation arms outside character classes (median four). It
  contains 126 regex and two fixed-string
  cases; two regex cases request ignore-case matching.

Across both cohorts there are 45 short expressions (under 32 characters), 141
medium expressions, and 26 expressions of at least 128 characters. There are
37 one-arm, 38 two-arm, 85 three-to-five-arm, 49 six-to-sixteen-arm, and three
greater-than-sixteen-arm expressions. These are actual expressions from the
user's Codex history, but they skew longer and more alternation-heavy than an
unknown population of all ripgrep users.

Every out-of-time query ran with normal line output and default threads over a
clean archive of upstream ripgrep commit
`f9c05a949d1a0dc8e16dee28ca9605d38611faeb`: 236 files and 3,254,144 bytes.
All 212 queries also ran with normalized `--count --include-zero` output over a
clean archive of FRE commit
`6f961465d00ff50f2096cfb05520c0653a87d2cd`: 1,370 files and 71,187,631
bytes, once with default threads and once with `--threads=1`.

These are query transplants, not replays of the original historical commands.
The original target bytes, paths, sizes, ignore state, and match densities were
not available. The measured match rate on the FRE archive was 173 of 212. The
two fixed-string and two ignore-case expressions were retained in the
denominator and declined by the current AOT eligibility gate in each FRE
panel.

## Method

Each sample used three fresh processes: preserved upstream stock ripgrep, the
candidate with the flag off, and the same candidate with
`--fre-aot-background`. Thus every measured background process compiled its
new query from scratch; no compiled matcher was cached between queries. One
warmup triad preceded eight measured triads per profile/panel/query. Four
orders balanced stock placement and normal/background order while keeping the
two candidate arms adjacent. Timed processes disabled receipts symmetrically;
the matching untimed probe supplied compilation and routing classifications.

The corpus archives were materialized once and were then scanned repeatedly
without cache eviction. This is a cache-hot/uncontrolled filesystem workload,
not a cold-cache first traversal. It nevertheless measures the intended
end-to-end cost for a new query: normal ripgrep starts immediately while FRE
compilation happens in parallel, and any benefit must repay that work within
the same process.

The EC2 timing host was 64-bit AArch64 with 32 logical CPUs and 16-byte SVE
vector length. Its one-minute load average was 0.181 at benchmark start and
1.099 at the end, small relative to 32 CPUs. Rust and Cargo were 1.96.0. CPU
profiles ran profile-major, so comparisons across `auto`, SVE, and SVE2 are
not directly paired.

## Cutover and actual accelerator findings

The implementation is no longer limited to assigning an entire file to one
engine. The probe records newline-safe scan windows, and it observed many files
that used stock search first and FRE later in the same file. Joining each
probe classification to its formal timing ratio gives the following `auto`
results on the FRE corpus:

| Workload | Probe route | Queries | Geometric mean |
|---|---|---:|---:|
| default threads | stock only | 74 | 1.0015x |
| default threads | different files split between engines | 11 | 1.0211x |
| default threads | at least one file cut over mid-scan | 127 | 0.8224x |
| one thread | stock only | 13 | 0.9845x |
| one thread | different files split between engines | 134 | 0.7103x |
| one thread | at least one file cut over mid-scan | 65 | 0.6344x |

On the 3.25 MB default-output workload, all 84 automatic-profile probe scans
were stock-only. The near-1.0 result there mostly measures the flag and
background-thread overhead before the short search exits.

Timed runs disabled receipts to avoid charging telemetry only to the
background arm. Route and accelerator labels therefore come from the matching
untimed probe. The tables above establish that same-file cutover works and
show a strong route-associated slowdown, but they do not record the route of
every individual timed invocation.

The actual native entry matters as well. With the automatic profile on the
one-thread FRE workload, the 172 queries whose probe published an
`aarch64_sve2` start accelerator had a 0.7493x geometric mean; the 25 that
published `aarch64_sve` had 0.3679x; and the 13 stock-only/no-start-accelerator
queries had 0.9845x. On default threads, the corresponding SVE2 and SVE groups
were 0.8969x (136 queries) and 0.5791x (18 queries). Three additional cases
published a non-vector `none` entry across the two panels and also regressed.

Query shape strongly correlates with the one-thread automatic-profile result:

| Alternation arms (including nested groups) | Queries | Geometric mean |
|---|---:|---:|
| 1 | 37 | 0.9585x |
| 2 | 38 | 0.9550x |
| 3--5 | 85 | 0.6908x |
| 6--16 | 49 | 0.4722x |
| more than 16 | 3 | 0.2554x |

Short, medium, and long expressions had one-thread geometric means of 0.8812x,
0.6981x, and 0.4768x respectively. Matching queries were also worse (0.6697x
for 173) than misses (0.8517x for 39). This points toward a problem in the
current generated Span search route for complex matching expressions, in
addition to the unavoidable per-query compilation work.

The distribution is not uniformly bad. Examples of automatic-profile,
one-thread wins are:

- `struct K0AbsoluteEndProof|enum K0AbsoluteEndProof|type K0AbsoluteEndProof`
  at 1.346x;
- `(?:return )?Ok\(PortableRegex \{` at 1.326x;
- `struct PortableParsedBuildContext|impl PortableParsedBuildContext` at
  1.304x; and
- `pub enum ObjectError|enum ObjectError` at 1.261x.

These wins support a query-specialized admission policy, but alternation count
alone is not enough: even the one- and two-arm strata remain slightly below
1.0 overall.

## SVE and SVE2

The host reported feature mask `0x700000000`. The requested/effective masks
were `0x700000000` for `auto`, `0x200000000` for the pure-SVE profile, and
`0x600000000` for the SVE2 tier. For every profile, 500 of 508 probe receipts
were fully target-validated against the common host mask; the other eight were
the expected fixed-string/case-mode eligibility declines. The probe had no
target-validation failures.

The pure-SVE profile's vector entries were exclusively `aarch64_sve`. The SVE2
tier selected 368 `aarch64_sve2` and 42 `aarch64_sve` start accelerators across
all 508 probe cases; the rest either finished before a start accelerator was
available, declined, or used the non-vector entry. At 16-byte vector length,
the SVE2-tier timing was less bad than pure SVE on both count workloads, but it
still lost substantially to normal ripgrep. This profile comparison is
directional because profiles were not interleaved or paired against each
other.

Within the SVE2-tier one-thread panel, cases that actually started with SVE2
had a 0.7992x geometric mean (173 queries), while SVE fallback had 0.3501x (24
queries). Pure SVE's 197 actually-SVE cases had a 0.6237x geometric mean.
These results give no basis for enabling the current SVE/SVE2 AOT path
unconditionally.

## Publication path: no Clang

This implementation does not invoke Clang or another external linker at query
time. The normal matcher begins scanning immediately. A background thread
uses FRE to compile an in-memory native Span artifact and
`fre-aot-regex-loader::publish_span` to map and publish a direct native entry.
Search workers acquire that immutable entry and may switch at a newline-safe
window inside a file.

Across all 1,524 EC2 probe rows, receipts reported zero external-linker
invocations, zero runtime-helper requirements, and zero native-call failures.
For `auto`, median compilation time was 0.856 ms on the small default-output
panel, 1.331 ms on the default-thread FRE panel, and 1.732 ms on the one-thread
panel. Median in-process publication time was only 15--17 microseconds. The
observed regression therefore is not Clang startup or external linking
overhead.

The Window 3 in-process Span-publication work at `1359dc688` and the external
pattern-manifest integration at `6f961465d` supplied the required FRE API.
Both changes were committed and pushed to FRE `origin/main` before this run.
The candidate's manifest and lockfile pin exact revision
`6f961465d00ff50f2096cfb05520c0653a87d2cd`; the clean integration worktree and
`origin/main` both resolve to it. No additional or uncommitted FRE change was
needed for this benchmark phase.

## Correctness and provenance

The untimed EC2 probe contains 1,524 rows: 508 query/panel cases for each of
the three CPU profiles. All 1,524 candidate normal/background comparisons and
all 1,524 upstream-stock/candidate-normal comparisons were exact. There were
no timeouts, receipt-validation failures, or unexpected temporary files. The
background outcomes, including queries that finished before compilation,
were:

| Profile | Ready | Unfinished | Expected decline |
|---|---:|---:|---:|
| auto | 406 | 94 | 8 |
| pure SVE | 409 | 91 | 8 |
| SVE2 tier | 413 | 87 | 8 |

The formal EC2 benchmark contains 1,524 rows, 12,192 measured triads, and
36,576 fresh process invocations. Every triad had exact normal/background and
stock/normal output: 12,192 exact comparisons of each kind, with no timeout or
temporary-artifact observation. Independent recomputation from every raw
elapsed time reproduced all rows, counts, and medians and every public panel
aggregate to the reported precision; cross-platform `exp`/`log` evaluation
caused only final-bit geometric-mean differences.

The measured candidate source was clean commit
`4f6507b5f42b3c61f48b4c25d1718ae8c86af239`, tree
`59c5700b5ef85501aeef79f8be8e6272f190956f`. Its EC2 binary SHA-256 was
`d3104ccbd6dd94acb32ba56cfdcaafd93218ebc71018bcb4d1335cbaeaaf0b73`.
The preserved stock source was clean commit
`f9c05a949d1a0dc8e16dee28ca9605d38611faeb`; its EC2 binary SHA-256 was
`213b98c42d4e63e34363db74cdbbc7f3b136f61dcf7a4cb149e3755ed7c86236`.
The selection's canonical manifest digest was
`cf5960da72a770c96eb2a7e5532472f5feeca9df8214489d73baed9e35b1bb2e`.
The formal gate revalidated the probe, binary/source/corpus provenance, and
this selection before timing.

The benchmark-v1 public envelope binds the probe and selection but does not
contain a hash of its own private result. This report therefore binds each
exact public/private file explicitly below rather than relying on filenames.
The probe public envelopes do contain and match their private-result hashes.
The harness has been corrected to include the private-result SHA-256 in both
public envelope types for future runs; that artifact-only fix did not justify
rerunning these timings.

## Local diagnostic run

The matching local Apple-arm64 run was correct but not suitable as a primary
timing result. Its 508 probe rows were exact with no receipt failures, but the
18-CPU host's one-minute load average rose from 9.70 to 126.53 during formal
timing. Independently recomputed geometric means were 1.0041x for the small
default-output panel, 0.9806x for the FRE default-thread panel, and 0.8051x for
the FRE one-thread panel. The last two point in the same direction as EC2, but
the magnitude should be treated only as diagnostic under that load.

## Exact result artifacts

All paths below are relative to
`experiments/background-aot-representative/results/`. Private files contain
the raw query strings and per-process evidence and are intentionally ignored
by Git. SHA-256 values were recomputed from the files used for this report.

| File | SHA-256 |
|---|---|
| `selection-212.private.json` | `8b18839dc473f4b3f8b7a0590e5e29964f9e748e09ca251de5440df748d7c888` |
| `ec2-c9g-probe-4f6507b-auto-sve-sve2-r1.private.json` | `2dd68fde829e60c0eeb68896dcf777dfc7a76950c2a16ba54faf8cd6d239a0ea` |
| `ec2-c9g-probe-4f6507b-auto-sve-sve2-r1.public.json` | `863c801d54e3e913616c17b4c174de9bb6bdd269b51890e924a7ac47c88bd636` |
| `ec2-c9g-benchmark-4f6507b-auto-sve-sve2-p8-w1-r1.private.json` | `912d598c020510db695b957a21bb4edbbe7d5ae1074a1f9b5c8caf3f49f468fb` |
| `ec2-c9g-benchmark-4f6507b-auto-sve-sve2-p8-w1-r1.public.json` | `da706d0aad951928fa400884107eec419c8c955af67bfb5ea35ef5a59f1311df` |
| `probe-local-auto-4f6507b.private.json` | `2e933fd0cc623ced01f5fd218605a29672b17346d1ca539ebf8dddfa0c767bf8` |
| `probe-local-auto-4f6507b.public.json` | `6bb7f82ee909d31dee084fa3d0391e377f4840e417a20bccce7d180fc60ddfb4` |
| `benchmark-local-auto-4f6507b.private.json` | `24a9a18ea26774a54f46618ef89576ee508817471dbb36926d5bd0b2128030ff` |
| `benchmark-local-auto-4f6507b.public.json` | `5723e7f0c7d9b708f3ff00bfbab1c7fb2eb2b6cbfdfc34c2397d83c5b6226c41` |

## Limitations and next step

- Actual expressions do not make these exact expression/corpus pairs
  historical replays. Results may differ with the original targets, cold
  filesystem cache, larger trees, different match density, or a different
  output mode.
- The cohort represents the user's Codex-generated searches, not a random
  sample of all ripgrep usage. Equal-pattern aggregation also deliberately
  does not claim a real-world query-frequency distribution.
- Only two source-tree corpora and one SVE/SVE2 host/vector length were used.
  Default-output timings are noisy and almost never exercised cutover.
- The result is end-to-end by design: it charges background compilation,
  publication, contention, and native scanning to a new query. It does not
  isolate steady-state matcher throughput after a free precompile.

The most useful next experiment is a conservative admission model trained and
validated on held-out queries, with normal ripgrep retained for patterns the
model cannot confidently accelerate. Before that, FRE's many-alternation Span
generation should be profiled against the normal engine: the current shape
strata make unconditional admission predictably harmful.
