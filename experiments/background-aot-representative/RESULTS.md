# Background FRE AOT on actual queries: results

## Conclusion

The SelectedEnd iteration compiled roughly **18--22% faster** on the count
probes, but it did not improve end-to-end search. Against the prior Span
baseline, every comparable representative count ratio became **1.2--3.7%
worse**: automatic-profile default-thread count moved from 0.8909x to 0.8690x
and one-thread count from 0.7000x to 0.6788x. Default-output search remained
neutral, at 0.9910x--1.0055x across the four targets. The unchanged one-thread
stock-only stratum, 0.9849x versus 0.9845x before, isolates the regression to
work that actually used AOT rather than the flag-off ripgrep path.

The most likely explanation is that cheaper SelectedEnd compilation publishes
earlier and exposes more of each scan to FRE's still-slower forward search. The
automatic/default-thread probe had 142 non-stock routes instead of 138, while
the one-thread probe shifted seven cases from cross-file cutover into same-file
work. Ratios also fell within every recorded query-shape stratum and every AOT
route. This is an evidence-backed inference, not a paired causal measurement:
route membership came from matching untimed probes, and the two formal runs
were separate campaigns.

SelectedEnd is therefore not an admission-ready optimization. It reduces
compiler work and removes reverse-start recovery from candidate discovery, but
the forward matcher still needs query specialization or selective admission.
The prior Span result is retained below as an explicitly labeled baseline.

## Newest result: SelectedEnd at `c568c42917`

### EC2 timing results

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

This campaign reused the exact frozen selection, ripgrep archive, FRE archive,
fresh-process pairing, one warmup, and eight measured pairs described in the
baseline sections. It added ASIMD as a fourth CPU profile; it did not change a
query, corpus byte, or aggregation rule.

| CPU target | Workload | Patterns | Stable | Geometric mean | Median | p10--p90 | Background elapsed |
|---|---|---:|---:|---:|---:|---:|---:|
| auto | ripgrep tree, default output/threads | 84 | 34 | 1.0002x | 0.9956x | 0.8894--1.1265x | 0.0% |
| auto | FRE tree, count, default threads | 212 | 133 | 0.8690x | 0.9889x | 0.5069--1.1124x | +15.1% |
| auto | FRE tree, count, one thread | 212 | 212 | 0.6788x | 0.8546x | 0.2960--1.0991x | +47.3% |
| pure SVE | ripgrep tree, default output/threads | 84 | 27 | 0.9928x | 0.9975x | 0.9125--1.0614x | +0.7% |
| pure SVE | FRE tree, count, default threads | 212 | 138 | 0.8215x | 0.9647x | 0.5108--1.0848x | +21.7% |
| pure SVE | FRE tree, count, one thread | 212 | 212 | 0.6179x | 0.6985x | 0.3184--0.9983x | +61.8% |
| SVE2 tier | ripgrep tree, default output/threads | 84 | 32 | 1.0055x | 0.9962x | 0.9599--1.1180x | -0.5% |
| SVE2 tier | FRE tree, count, default threads | 212 | 139 | 0.8655x | 0.9801x | 0.5578--1.0807x | +15.5% |
| SVE2 tier | FRE tree, count, one thread | 212 | 212 | 0.7165x | 0.8266x | 0.4049--1.0540x | +39.6% |
| ASIMD | ripgrep tree, default output/threads | 84 | 38 | 0.9910x | 0.9977x | 0.8988--1.0920x | +0.9% |
| ASIMD | FRE tree, count, default threads | 212 | 137 | 0.8747x | 0.9961x | 0.5224--1.1179x | +14.3% |
| ASIMD | FRE tree, count, one thread | 212 | 212 | 0.6792x | 0.8549x | 0.2970--1.1168x | +47.2% |

The upstream-stock/background geometric means were 0.9934x, 0.8696x, and
0.6813x for the three automatic-profile panels, closely tracking the
same-candidate ratios. The candidate's flag-off path is not hiding the result.

### Change from the Span baseline

The following cells compare like-for-like formal EC2 geometric means. The last
column is the relative change in the reported ratio, not elapsed-time percent.
ASIMD has no prior formal baseline.

| CPU target | Count workload | Span baseline | SelectedEnd | Relative ratio change |
|---|---|---:|---:|---:|
| auto | default threads | 0.8909x | 0.8690x | -2.5% |
| auto | one thread | 0.7000x | 0.6788x | -3.0% |
| pure SVE | default threads | 0.8372x | 0.8215x | -1.9% |
| pure SVE | one thread | 0.6420x | 0.6179x | -3.7% |
| SVE2 tier | default threads | 0.8756x | 0.8655x | -1.2% |
| SVE2 tier | one thread | 0.7361x | 0.7165x | -2.7% |

Compilation itself improved. In the matching local probe, median compile time
fell from 1.642 ms to 1.326 ms for default-thread count (-19.2%) and from
1.484 ms to 1.152 ms for one-thread count (-22.4%). Across the comparable EC2
count cells it fell 17.1--22.0%; the automatic/default-thread cell was the low
endpoint. Publication remained in-process and on the order of tens of
microseconds.

The one-thread query-shape comparison below uses independently recomputed
equal-pattern geometric means. Each cell is `SelectedEnd / Span (delta)`.
Every arm-count cell regressed, including the simple patterns.

| Alternation arms | auto | pure SVE | SVE2 tier |
|---|---:|---:|---:|
| 1 | 0.9366 / 0.9585 (-0.0219) | 0.7281 / 0.7617 (-0.0336) | 0.7266 / 0.7613 (-0.0347) |
| 2 | 0.9495 / 0.9550 (-0.0055) | 0.7776 / 0.7903 (-0.0127) | 0.8103 / 0.8211 (-0.0108) |
| 3--5 | 0.6719 / 0.6908 (-0.0189) | 0.6363 / 0.6572 (-0.0209) | 0.8063 / 0.8165 (-0.0102) |
| 6--16 | 0.4551 / 0.4722 (-0.0171) | 0.4698 / 0.4875 (-0.0177) | 0.5734 / 0.5874 (-0.0140) |
| more than 16 | 0.1678 / 0.2554 (-0.0876) | 0.1706 / 0.2593 (-0.0887) | 0.1691 / 0.2581 (-0.0890) |

The automatic-profile length and outcome strata moved in the same direction:

| One-thread stratum | SelectedEnd | Span baseline | Delta |
|---|---:|---:|---:|
| expression under 32 characters | 0.8610x | 0.8812x | -0.0202x |
| expression 32--127 characters | 0.6812x | 0.6981x | -0.0169x |
| expression at least 128 characters | 0.4416x | 0.4768x | -0.0352x |
| matching query | 0.6476x | 0.6697x | -0.0221x |
| miss | 0.8369x | 0.8517x | -0.0148x |

The automatic-profile one-thread route audit likewise leaves stock-only
unchanged and associates the decline with AOT work. Route membership differs
between probes, so the deltas are diagnostic strata rather than matched-query
effects.

| Probe route | SelectedEnd queries | SelectedEnd | Span baseline | Delta |
|---|---:|---:|---:|---:|
| stock only | 13 | 0.9849x | 0.9845x | +0.0004x |
| cross-file split | 127 | 0.7123x | 0.7375x | -0.0252x |
| true same-file midscan cutover | 67 | 0.6009x | 0.6179x | -0.0170x |
| same-file operation mix | 5 | 0.3898x | 0.4076x | -0.0178x |

### Forced mid-file cutover and publication path

The forced large-file gate passed for all four CPU profiles. Each run committed
5,263,360 bytes to stock search before publication and then gave 10,985,472
bytes to AOT in the same file. The receipt reported ABI
`selected_end_search_v1`, one forward state, zero reverse states, no reverse
start recovery, and four stock span-recovery calls covering 8,190 bytes in
each profile. The post-cutover matches and recovered output were exact.

Target evidence matched the host in every gate: `auto` requested mask
`0x700000000` and selected SVE2; pure SVE used `0x200000000` and SVE; the SVE2
tier used `0x600000000` and SVE2; and ASIMD used `0x100000000` and ASIMD. The
host's SVE vector length was 16 bytes.

There is still no Clang or external linker on the query path. FRE compiles and
publishes an immutable SelectedEnd module in process, and ripgrep uses it only
for candidate-end discovery. Normal ripgrep remains responsible for exact span
or capture recovery when output requires it. Across all 2,032 untimed probe
rows there were zero external-linker invocations, runtime-helper requirements,
or native-call failures.

### Correctness, provenance, and exact artifacts

The probe contains 2,032 rows: 508 query/panel cases for each of four profiles.
Every normal/background and stock/normal output comparison was exact, with no
receipt-validation failure or timeout. Each profile had 500 fully
target-qualified cases and the expected eight fixed-string/case-mode declines.

The formal benchmark contains 2,032 rows, 16,256 measured triads, and 48,768
measured fresh-process invocations, plus 2,032 warmup triads. Every measured
normal/background and stock/normal comparison was exact; there were no
timeouts or unexpected temporary artifacts, and receipt instrumentation was
disabled symmetrically. The host had 32 logical CPUs. Its
one-minute/five-minute/fifteen-minute load averages were 1.141/1.152/0.539 at
the start and 1.185/1.681/1.404 at the end.

The candidate was clean commit
`c568c42917faba9fde790af07b1074dd54b3d4e4`, tree
`997bd14026de541c88ba959bc0b51e61b601b920`, with EC2 binary SHA-256
`8773c1e3795aa508f5d31ee1c18cabc7f16c40e07f8cb53a71720e0191dab1cd`.
Its manifest and lockfile pin FRE commit
`abad8a8e9007409ae483c9627397886d09a9fdf6`, whose clean source-mirror tree
was `f81e1f1bc9489f4cfb67f788e198b118d7b49256`. The stock source remained
clean commit `f9c05a949d1a0dc8e16dee28ca9605d38611faeb`, tree
`ce81df4f8cad2dbfd1afb6b3ba53fd19846a5794`, with binary SHA-256
`76f31a2a7b52508a21a4d45b999a43eeb9817faf9488456c67632a7d6a84b324`.
The frozen selection file SHA-256 remained
`8b18839dc473f4b3f8b7a0590e5e29964f9e748e09ca251de5440df748d7c888`;
the canonical selection-manifest digest was
`cf5960da72a770c96eb2a7e5532472f5feeca9df8214489d73baed9e35b1bb2e`.

Paths are relative to `experiments/background-aot-representative/results/`.
The public benchmark binds the private benchmark hash, and the benchmark binds
the exact probe public hash used as its pre-timing gate.

| File | SHA-256 |
|---|---|
| `probe-selectedend-c568c429-auto-sve-sve2-asimd-r1.private.json` | `17aa1588e05a21db4cd116fc6fc16e4edf4835850879605ad55fcfee02e409a5` |
| `probe-selectedend-c568c429-auto-sve-sve2-asimd-r1.public.json` | `b5285c710e37d46118a137dd19eb0115b31628b6748eeeabb27a3ebb151a77f4` |
| `benchmark-selectedend-c568c429-auto-sve-sve2-asimd-p8-w1-r1.private.json` | `84b930291604408e43c681e62e5326fe6288600f1c991bee12ad29a95da50613` |
| `benchmark-selectedend-c568c429-auto-sve-sve2-asimd-p8-w1-r1.public.json` | `58f4e66ef4379047705e656a462365b1f8b6f91edca5eceba3e50725b127c27f` |

## Prior baseline: Span at `4f6507b5f`

Everything below this point describes the earlier Span-publication campaign.
It is retained so that the SelectedEnd iteration can be compared with the
original measurements and audit trail.

### Baseline EC2 timing results

The ratio definition, pairing, and stability criteria are the same as for the
newest result.

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

### Baseline query cohorts and corpora

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

### Baseline method

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

### Baseline cutover and actual accelerator findings

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

### Baseline SVE and SVE2

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

### Baseline publication path: no Clang

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

### Baseline correctness and provenance

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

### Baseline local diagnostic run

The matching local Apple-arm64 run was correct but not suitable as a primary
timing result. Its 508 probe rows were exact with no receipt failures, but the
18-CPU host's one-minute load average rose from 9.70 to 126.53 during formal
timing. Independently recomputed geometric means were 1.0041x for the small
default-output panel, 0.9806x for the FRE default-thread panel, and 0.8051x for
the FRE one-thread panel. The last two point in the same direction as EC2, but
the magnitude should be treated only as diagnostic under that load.

### Baseline exact result artifacts

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

### Baseline limitations and next step

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
