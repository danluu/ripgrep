# Background FRE AOT on actual queries: results

## Current result: exact-Teddy V2 at `542b139` -- NO-GO

The default-off exact-Teddy V2 experiment is correctness-qualified, but it is
**not admission-ready**. Automatic selected no Teddy route in the frozen
44-pattern intention-to-treat (ITT) cohort. Force selected and published the
authenticated exact-Teddy route for the pre-timing 34-pattern compiler-fact
stratum, but its pooled end-to-end ratio against the same candidate's normal
path was only `0.979076567x`. The preregistered direct-viability threshold was
`1.03x`. The answer is therefore **NO-GO**: leave V2 default-off and do not
promote either the forced route or a derived automatic policy from these data.

Force did materially improve the selected route relative to Automatic, which
used the ordinary DFA, but that is not the deployment comparison. On the
primary automatic-profile/default-thread count panel, the pooled selected-34
Force/Automatic effect was `DN=1.452377920`, while Force versus normal remained
below parity. The stock-normalized alignment statistic was `K=1.002264845`, so
the observed Force effect is internally aligned; it simply does not make
background AOT faster than normal ripgrep.

This section records the complete authenticated chain: the initial census at
`d0711c3`, the corrected qualification at `542b139`, formal Automatic-then-Force
round 1, preregistered reverse-order Force-then-Automatic round 2, and the
separate frozen FRE holdout at `9b19adf`. The older SelectedEnd and Span results
remain below as historical baselines.

### Census and qualification

The result-blind `frozen-structural-44-v1` cohort contains 14 OOT and 30 wider
patterns. Its ordered manifest SHA-256 is
`35b0037122bf2ab9a2c1641a562f23f12b88856ceb66c713ceb9403adb541823`;
the transported 212-case source manifest is
`cf5960da72a770c96eb2a7e5532472f5feeca9df8214489d73baed9e35b1bb2e`.
The selection transport itself is
`8b18839dc473f4b3f8b7a0590e5e29964f9e748e09ca251de5440df748d7c888`.

The first clean c9g census used ripgrep commit
`d0711c31771f96b7ff68e831f00ec7e2c04eb822`, tree
`9b9595d699a5d42adea9751532f9c6e8bc73b50c`, and binary
`07a5c68de7f9a3bb3f8a98e3bc0b374855dbfa4382523fea320456470a78c7b7`.
It discovered the stable per-profile compiler outcome: Force published Teddy
for 34 cases, nine remained ready on `ordered_dfa`, and `wider-0121` declined
at `compile_object`; Automatic published zero Teddy routes and retained all 44
on `ordered_dfa`. The then-current harness classified the ten Force
nonselections as invalid, so timing stopped. That discovery run was evidence,
not qualification.

Commit `542b139178eab59ea29781f4f413b0a5f0622e2d`, tree
`e9e904f655c741135cea9f51a4441b000ba1045c`, corrected the fail-closed
nonselection validation without changing the frozen cohort. A new isolated
build produced candidate binary
`7c11e0c5009d01bd2f19b754e100e0aa8e0ffaead75fd861272a6fa24d8c2d73`.
The stock source remained clean `f9c05a949d1a0dc8e16dee28ca9605d38611faeb`,
tree `ce81df4f8cad2dbfd1afb6b3ba53fd19846a5794`, binary
`e6719a285a9a82442291f93032ed5a72c2be95fd0f53da65a9077dde2dffd933`.
All direct FRE dependencies and lock entries pinned clean commit
`d2b352b7a051628bbcf8afc7f23d1362a850cb25`, tree
`fc129a6436035103c3f5d3c589127a08f93ab3a0`. The searched FRE corpus stayed
at frozen commit `6f961465d00ff50f2096cfb05520c0653a87d2cd`.

The corrected settled censuses were identical on `auto`, `asimd`, `sve`, and
`sve2`:

| Policy | Teddy | ready ordinary DFA | `compile_object` | invalid |
|---|---:|---:|---:|---:|
| Automatic | 0 | 44 | 0 | 0 |
| Force | 34 | 9 | 1 | 0 |

Force authenticated the exact hard-pinned selected-34 set (11 OOT/23 wider),
and authenticated the exact nine-ready/one-decline complement. Its synthetic
exact-Teddy gate strictly selected on every profile. Automatic and Force then
each passed the complete 408-row qualification matrix: 14 default-output plus
44 default-thread count plus 44 one-thread count cases per profile. All
normal/background and stock/normal outputs and statuses matched; receipts,
policy, target, source, binary, corpus, and manifest bindings passed; no fault,
timeout, or unexpected temporary artifact occurred.

Those policy probes were classification/correctness evidence, not performance
runs. Their 408 historical-query rows and fixed exact-Teddy gates were run with
timing collection disabled. The historical `542b139` probe implementation
still sampled unused clock fields in the separate synthetic forced-midscan
gate; no aggregate or formal timing consumed them. The current hygiene change
passes `collect_timing=False` to all three forced-midscan arms as well, so
future probe records contain no `elapsed_ns`, `user_ns`, or `system_ns` fields.
Output, receipt, and midscan-cutover validation are unchanged.

### Formal design and independent reconstruction

Round 1 ran Automatic and then Force. The preregistered confirmation reversed
the order: Force and then Automatic. Within every policy, profiles ran
`auto`, `asimd`, `sve`, `sve2`; every row had two discarded warmup pairs and
12 measured pairs in the same four-order stock/normal/background rotation.
Each policy therefore contains 408 rows, 4,896 measured triplets and 14,688
timed child invocations. The pinned harness control flow supplies another
2,448 untabulated warmup invocations per policy. Across both orders, 58,752
measured child invocations completed; the pinned control flow accounts for
9,792 additional discarded warmup child invocations.

For pattern `i` and policy `p`, the direct estimators are:

```text
R_i^p = median_k(normal_i,k^p / background_i,k^p)
Q_i^p = median_k(stock_i,k^p / background_i,k^p)
DN = GM_i(R_i^Force / R_i^Automatic)
DS = GM_i(Q_i^Force / Q_i^Automatic)
K  = DN / DS
```

`RA` and `RF` below are the equal-pattern geometric means of `R` under
Automatic and Force. `K` is the stock-normalized alignment check; `DS` is not
a control-drift estimate. Equal-order pooling first takes each pattern's
geometric mean across rounds and only then takes the equal-pattern geometric
mean. No pooled confidence interval was invented.

Both standalone auditors recomputed every row median and complete public
aggregate tree from private samples without importing the workload harness.
They verified exact pair indices/order, all outputs and statuses, invocation
counts, absence of timed receipts, probe/campaign/source/binary/corpus
bindings, cross-policy workload identity, cross-generation identity, and the
Automatic-Force/Force-Automatic chronology. Round 1 ended with
`INDEPENDENT_FORMAL_AUDIT_OK`; the reverse audit ended with
`INDEPENDENT_REVERSE_AUDIT_OK`. Recomputed/public floating differences were
only cross-libm rounding, at most three ULP.

### Pooled 12-cell ITT result

This table contains all 12 profile/panel ITT cells. The output panel has the
14 applicable OOT patterns; both count panels have all 44. Values are the
equal-order pooled point estimates.

| Profile | Panel | n | RA | RF | DN | DS | K |
|---|---|---:|---:|---:|---:|---:|---:|
| auto | default output | 14 | 0.944285350 | 0.988877985 | 1.047223686 | 1.027362328 | 1.019332379 |
| auto | count, default threads | 44 | 0.632714891 | 0.853549785 | 1.349027496 | 1.344052176 | 1.003701731 |
| auto | count, one thread | 44 | 0.427799327 | 0.676184058 | 1.580610384 | 1.581183024 | 0.999637841 |
| asimd | default output | 14 | 0.994776396 | 0.980954916 | 0.986105943 | 1.009103861 | 0.977209562 |
| asimd | count, default threads | 44 | 0.638944000 | 0.846291393 | 1.324515753 | 1.325599545 | 0.999182413 |
| asimd | count, one thread | 44 | 0.427514050 | 0.664151095 | 1.553518755 | 1.553968065 | 0.999710863 |
| sve | default output | 14 | 0.992905089 | 0.994395188 | 1.001500747 | 0.977008521 | 1.025068590 |
| sve | count, default threads | 44 | 0.619825687 | 0.846179708 | 1.365189803 | 1.375149192 | 0.992757594 |
| sve | count, one thread | 44 | 0.429952115 | 0.689240527 | 1.603063466 | 1.602948185 | 1.000071918 |
| sve2 | default output | 14 | 0.976171181 | 1.022433684 | 1.047391793 | 0.974481847 | 1.074819194 |
| sve2 | count, default threads | 44 | 0.755025681 | 0.889018169 | 1.177467458 | 1.169791474 | 1.006561840 |
| sve2 | count, one thread | 44 | 0.585529742 | 0.741851861 | 1.266975539 | 1.266883279 | 1.000072825 |

Force never clears the `RF >= 1.03` direct-viability threshold in an ITT
cell. Its strongest pooled ITT point is the small SVE2 default-output cell at
`1.022433684x`; every count cell remains below normal, often substantially.

### Primary cell, compiler-fact strata, and uncertainty

The preregistered primary cell is `auto/fre-count-default-threads`. Values are
shown as `round 1 / reverse round 2 / equal-order pooled`:

| Stratum | n | RF | DN | DS | K |
|---|---:|---:|---:|---:|---:|
| ITT | 44 | 0.855057087 / 0.852045140 / 0.853549785 | 1.351565724 / 1.346494034 / 1.349027496 | 1.329001325 / 1.359273478 / 1.344052176 | 1.016978463 / 0.990598328 / 1.003701731 |
| Force-selected | 34 | 0.984197024 / 0.973982750 / 0.979076567 | 1.461916595 / 1.442901483 / 1.452377920 | 1.430860080 / 1.467564215 / 1.449095942 | 1.021704788 / 0.983194785 / 1.002264845 |
| Force complement | 10 | 0.530028871 / 0.540705957 / 0.535340796 | 1.035015181 / 1.064375320 / 1.049592594 | 1.033906942 / 1.047417736 / 1.040640413 | 1.001071894 / 1.016189896 / 1.008602570 |

Primary order changes were all under 5%: ITT `DN` and `RF` round-2/round-1
ratios were `0.996247544` and `0.996477490`; selected-34 ratios were
`0.986993026` and `0.989621718`; complement-10 ratios were `1.028366868` and
`1.020144349`. No primary `DN` or `RF` estimate straddled 1 or the `1.03`
viability cutoff. Primary ITT and selected-34 `K` did straddle 1 across the
two orders, while staying in their `[0.97,1.03]` alignment band in both
orders and pooled.

Round 1 additionally received a transparent 10,000-draw conditional
hierarchical percentile bootstrap. It resampled pattern IDs, then resampled
the 12 complete normal/background/stock triplets jointly within each policy
but independently across the two policy campaigns. The documentation
reproduction uses the first eight bytes, interpreted as an unsigned
big-endian integer, of
`SHA256(ASCII("rg-aot-v2-r1-conditional-bootstrap-v1") || 0x00 ||
decode_hex(automatic-private-sha256) ||
decode_hex(force-private-sha256))`, where each decoded digest is exactly 32
bytes. The resulting seed digest is
`42f3d527eb892501e9a80a4a0746105ca2b1540b471d28de7c56ea47ce1adef3`,
seed `4824433993276007681`. Targets are drawn in table order; within each draw,
pattern indices precede Automatic triplet indices and then Force triplet
indices. Percentiles use `round((10,000 - 1) * p)`, giving 0-based indices
250 and 9749 after sorting 10,000 draws. This explicit seed is a documentation
reproduction, not a change to the preregistered analysis. These intervals are
**round-1 conditional intervals only**:

| Estimate | Round-1 point | Conditional 95% interval |
|---|---:|---:|
| primary ITT RF | 0.855057 | [0.763303, 0.936292] |
| primary ITT DN | 1.351566 | [1.219262, 1.494083] |
| primary ITT DS | 1.329001 | [1.196312, 1.464352] |
| primary ITT K | 1.016978 | [0.982807, 1.057480] |
| selected-34 DN | 1.461917 | [1.303173, 1.641762] |
| complement-10 DN | 1.035015 | [0.952295, 1.114475] |
| auto/count-one-thread ITT DN | 1.581296 | [1.393533, 1.801341] |
| auto/default-output ITT RF | 1.004006 | [0.965608, 1.056194] |

The primary ITT interval excludes direct viability by a wide margin. The
complement point-estimate neutrality rule, `DN` in `[0.97,1.03]`, fails in
round 1, round 2, and pooled (`1.035015181`, `1.064375320`, and
`1.049592594`), although the round-1 conditional interval contains neutrality.

Round-1 descriptive primary subgroups were:

| Subgroup | n | RF | DN | DS | K |
|---|---:|---:|---:|---:|---:|
| OOT | 14 | 0.864688 | 1.252719 | 1.230812 | 1.017799 |
| wider | 30 | 0.850599 | 1.400327 | 1.377467 | 1.016596 |
| matched | 42 | 0.857432 | 1.370727 | 1.345930 | 1.018424 |
| miss | 2 | 0.806680 | 1.005651 | 1.018801 | 0.987092 |
| 4 arms | 20 | 1.003115 | 1.301003 | 1.259743 | 1.032753 |
| 5--7 arms | 15 | 0.874024 | 1.509049 | 1.501468 | 1.005049 |
| at least 8 arms | 9 | 0.578084 | 1.224216 | 1.221406 | 1.002300 |
| minimum width 3--4 | 14 | 0.706376 | 1.315728 | 1.276163 | 1.031003 |
| minimum width 5--8 | 11 | 0.847166 | 1.514122 | 1.558630 | 0.971444 |
| minimum width at least 9 | 19 | 0.989588 | 1.290866 | 1.248632 | 1.033824 |

These shape cells are descriptive, especially the two-pattern miss cell. They
do not define a post-hoc admission rule. Across the complete 36-cell reverse
audit, four complement `DN` cells and one complement `RF` cell changed by more
than 5%; 14 cells had `K` outside the alignment band in at least one
order/pooled estimate. The primary cell was stable, but the global follow-up
trigger fired and is another reason not to promote from this experiment.

### Separate V2 holdout correctness gate

The clock-free holdout used clean FRE commit
`9b19adfab3b013cb47c76588878ca0cf311ee779`, tree
`4a9ba5ff172bdfeb1daa4d4cfcce02ea671e69d6`, release binary
`2104419187f332e5c99c7c83ed4bb29a71521b69b0bbf7d32e787fd3184f87c6`,
and the same c9g AArch64/SVE-VL16 target. All 19 frozen cases were
structurally ineligible for V2: `0/19` eligible, `19/19` ineligible, zero
declines, zero faults, and zero eligible windows. Both Automatic and Force
settled ready on the incumbent. All `676/676` comparisons passed: 169 expanded
inputs times full and nonzero-bounded windows times two policies.

This is useful non-target regression evidence, not selected-route coverage.
The next holdout must add a separately frozen eligible cohort before it can
make a generalization claim about the V2 Teddy route itself.

### Exact artifact roots and hashes

Private artifacts remain mode `0600` and outside Git. The authenticated local
roots are:

```text
/Users/danluu/dev/fre-teddy-v2-c9g-probe-results-d0711c-r1
/Users/danluu/dev/fre-teddy-v2-c9g-qual-results-542b139-r1
/Users/danluu/dev/fre-teddy-v2-c9g-formal-results-542b139-r1
/Users/danluu/dev/fre-teddy-v2-c9g-formal-reverse-results-542b139-r2
/Users/danluu/dev/fre-holdout-v2-results-9b19adf-c9g-r1
```

The formal remote root is preserved at
`/private/tmp/rg-fre-v2-542b139-c9g-qual-r1`; the holdout root is preserved at
`/private/tmp/fre-holdout-v2-9b19adf-c9g-r1`.

| Root | File | SHA-256 |
|---|---|---|
| discovery | `results/census-automatic.private.json` | `b7d6e9e723d8939a4862ae2192aa6b407d0dcf0d36b21b248066631860c09c7f` |
| discovery | `results/census-automatic.public.json` | `256fb9216b56bbeda660dfa8a53ba80eda79a0e28b5b64413dec04a37055a45c` |
| discovery | `results/census-force.private.json` | `976427ba5abe65ca8d895b8b910208914d87aca2aed3a20831bf1186d0c842d5` |
| discovery | `results/census-force.public.json` | `92a32ddbcbbf8747ae9dadde4c61ec012b857c8444a617383d77fe5b55dafbd5` |
| qualification | `results/census-automatic.private.json` | `f2d123a59ad5bcbb0f5a1483f6d0b881847b4941fb59b69f621af775aec74246` |
| qualification | `results/census-automatic.public.json` | `841769124f9ef84808aa8ab0ca6605d8991ebc1790480595f2ccb5b5bb9f5e50` |
| qualification | `results/census-force.private.json` | `561957b9cd8727160ad4bf1c405bf58e508e80f33ab2b4998162c1b86701cc34` |
| qualification | `results/census-force.public.json` | `fe111f87b1fa7234d4d1b11a0169f13087127fed9e6ecf7f70d5ff1a6488924b` |
| qualification/formal | `results/probe-automatic.private.json` | `04895bf1a86df16a6e0e8c3f7fc4b0575493e49a0a954947d3d3145d3b51f1d5` |
| qualification/formal | `results/probe-automatic.public.json` | `9e6235445f499296c808f675f5e010dffbd45aad0bab90a31622ffd1f015df25` |
| qualification/formal | `results/probe-force.private.json` | `28355e1f68a2907c1d3c034c0d9ac95dd47d99604d04a8b75c6f8043d38bb001` |
| qualification/formal | `results/probe-force.public.json` | `82f6256c0dc022fbfe55bdad30521d73d0d6d44a62b78243ce146444f3dbf796` |
| formal r1 | `results/benchmark-automatic.formal-r1.private.json` | `0cba838549635e57cb14d3eaddfffe26351f886cb22ce79520ce32656d54899a` |
| formal r1 | `results/benchmark-automatic.formal-r1.public.json` | `4151ed85517c30cc55756eb9a35331fe07013bfe45a4b8e6e8fbac9101abde5e` |
| formal r1 | `results/benchmark-force.formal-r1.private.json` | `156211b58a104e5a14997446630cee6181bb682c735e72bffab0aa37a89e0946` |
| formal r1 | `results/benchmark-force.formal-r1.public.json` | `606400a1a9a3b9f5d2faa8ee973dda425697b06fab8137e56d883d0bd142d74e` |
| formal r1 | `audit/audit_formal.py` | `19ea56f6e13b1f49403d620277652e9dff6adc88af429a23db9a1c2697ad6c29` |
| reverse r2 | `results/benchmark-force.formal-r2.private.json` | `ec207493311f314af45484397a9ae77e200a9af36c6e7863fe38a0a5b00b66f0` |
| reverse r2 | `results/benchmark-force.formal-r2.public.json` | `67496c220dcb52d5582ab55f6c8f24298bb2b5ed4cea111fe80dea98fe4b223d` |
| reverse r2 | `results/benchmark-automatic.formal-r2.private.json` | `befcb62602cc42124c52190bee1b88268292d690ac4a6aa6b99ce81482430173` |
| reverse r2 | `results/benchmark-automatic.formal-r2.public.json` | `73b49f2ee73d823b3789c800e573714790243be1847eecc8e6264075e36d46e2` |
| reverse r2 | `audit/audit_reverse.py` | `a6463117af9896c06df1da479ebe367e645cff74167c06915dc001fc4e690adc` |
| holdout | `results/correctness.json` | `6171ffc64e289c016fe6a1fe95fcbceb6c72e01ce1015a798d8327e8ad2fb808` |
| holdout | `logs/correctness.log` | `32df15f6e9c527659c95f2d6b71df28172c27aa25bef51a64cc85ad4383d9e61` |

The exact executed formal command files are preserved beside the logs. Round
1 Automatic/Force command SHA-256 values are
`4faca8134ec558781bfac1f55123605c20a21a53efebad5fa4d4acd4a2c1a67d`
and `705ae6b5fc25d8d9ea5e3e4f24e0936a16f213a83522f50072b90a731a256cfc`;
round 2 Force/Automatic values are
`4bc7f6eab2cffd5b144c05b5770d0079463415640dec8bff0187626e1ac688c6`
and `b4e2e63bca06d47fa2058ad6e0ca11157d1d9ead5ef94c16c3f6a55ab6b134d6`.
The formal evidence pins the historical harness SHA-256
`082c5b6ababcb859cafc567bdc5c51e5a9c70811d1f6727e010604fdfabb0e87`;
the later clock-free forced-midscan hygiene edit does not rewrite or
reinterpret those artifacts.

### Decision and next work

1. Keep exact-Teddy V2 default-off. Do not infer an Automatic admission rule
   from the forced selected-34 or from descriptive shape strata.
2. Improve the generated route or its admission economics until a new frozen
   selected cohort clears direct `RF >= 1.03`, not merely Force/Automatic
   `DN > 1`.
3. Explain and eliminate the complement point-effect before reusing the
   policy comparison; preserve ITT44 as primary.
4. Freeze an eligible non-Rebar holdout cohort. The current 0/19 holdout proves
   incumbent parity only.
5. If a materially new candidate earns timing, repeat settled clock-free
   qualification first, preregister both policy orders, and keep order-specific
   intervals separate unless a pooled interval method is frozen in advance.

## Prior SelectedEnd conclusion

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

## Prior result: SelectedEnd at `c568c42917`

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
