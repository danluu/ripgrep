# Retained-mask scanner-delta control

`scanner_delta.py` is the sealed four-arm control for attributing a performance
change to FRE's retained-candidate-mask scanner. It does not build ripgrep or
FRE. It accepts only already-qualified old and new binaries and fails closed
unless their source, binary, FRE dependency, qualification, probe, corpus,
selection, runner, and auditor identities match a canonical preregistration
written before timing.

Both pinned probes must also attest the same stable Linux/AArch64 capability
signature: platform/kernel, architecture, CPU count, SVE vector length, one
host feature mask, and the requested/effective masks for `auto`, `asimd`,
`sve`, and `sve2`. The canonical ASCII JSON bytes and SHA-256 of that signature
are preregistered. The timing runner independently reads Linux auxiliary-vector
capabilities before and after the workload, requires ASIMD, SVE, SVE2 and
16-byte SVE vectors, and requires exact equality with both probe attestations.

The schema family is `background-aot-scanner-delta-v1`. Private, public,
preregistration, and audit documents use the `.private`, `.public`,
`.preregistration`, and `.audit` suffixes. Destinations must be new; the runner
never appends to or overwrites a campaign.
Each campaign also reserves a distinct append-only
`.private-checkpoint-jsonl` file at mode 0600. It fsyncs safe stage records and
each fully closed row. A terminal failure appends its stage, exception class,
and completed-row count while withholding a public success artifact.

## Frozen identities and arms

The old identity is ripgrep
`1aae40aefaab5cdf6142de0079dc51b622b4b589`, tree
`44e2c9777143f2ddc9e4da5791b741e41c6a3b48`, binary
`793d8971ea374448252e3cdbd2b22cadef99a9a9ad06acd7904aa0b3aba1e228`,
and FRE `d2b352b7a051628bbcf8afc7f23d1362a850cb25`, tree
`fc129a6436035103c3f5d3c589127a08f93ab3a0`, optimizer 25. Its bound
selected-or-stock private/public probes are
`872893a89d613a1c6c84dfbaa4037eb7925aa33dbb06c212675aa9956bca11bd`
and `0344f0befe93289643af6ea92d2cbb82fe5793031b95058d16e18164c431d27c`.

The new identity is ripgrep
`77ed5a475666d56dedd90200a8ffefeee543b949`, tree
`60b89c07fc89a5115310ca8bb6996d47d9ce9c9d`, binary
`72009b3cc591f4da60abbaaf391de7d823f503b42c2b7ea6a87bc8b3e3d2ce87`,
and FRE `eca0972ff205daa860ca8cd20e125910b05baa34`, tree
`07e72f0a7f6ade8acb15533fb041b6d60c81bc10`, optimizer 26. Its bound
selected-or-stock private/public probes are
`494229fb67d4d25df4b9a161587ab9576990ac9525dda83d8909fa329ed8023c`
and `296c5e01692a5f5f5e7a1e2631fe223103aa07aad3ce3eb8c29788273f30ec22`.
The independent qualification manifest/archive hashes are
`92b7004df4d003ba9e1ee1ec60cf3ad202b799209e7d35f744db37cd3d730194`
and `eb75c7fa645cfd2529bf4b1b1b6ff02a45cdfa9bd5b14f61fc724b55a89fa40b`.

The probes used different untimed stock references. The preregistration binds
each probe's stock binary and source commit/tree separately, and the validator
requires both reference-correctness gates to be closed. Neither stock binary
is timed. The general representative receipt validator remains strict at
optimizer 26 for v7 receipts. The sole optimizer-25 compatibility path acts
on an in-memory copy after the exact old source, binary, and probe hashes are
authenticated.
The runner independently recomputes both private exact-Teddy and forced
mid-scan gates, requires the complete target matrix to be qualified, and
reproduces the exact per-profile 34 selected / 9 stock-fallback / 1 decline
disposition. It does not trust the public `all_passed` flags alone.

| Symbol | Name | Binary | Background | V2 policy |
| --- | --- | --- | --- | --- |
| A | B0 | old | enabled | `force-selected-or-stock` |
| B | B1 | new | enabled | `force-selected-or-stock` |
| D | N1 | new | disabled and scrubbed | none |
| C | N0 | old | disabled and scrubbed | none |

No stock or Automatic-policy arm is timed. Every invocation uses a fresh
process and isolated temporary directory. A quartet closes only when all four
statuses, semantic stdout, and stderr agree; all statuses are 0 or 1; and
there is no timeout, receipt, parse error, or leftover temporary artifact.

## Schedule and estimands

Each of the 408 canonical profile/panel/query rows runs two discarded warmup
quartets followed by eight measured quartets. The fixed orders are:

1. `A B D C`
2. `B D C A`
3. `D C A B`
4. `C A B D`
5. `A C D B`
6. `C D B A`
7. `D B A C`
8. `B A C D`

For stable canonical row ordinal `r`, warmups use `(r-2) mod 8` and `(r-1)
mod 8`; measured quartet `i` uses `(r+i) mod 8`. A reverse confirmation
reverses the global 408-row traversal but retains the original canonical
ordinal for every offset. Warmup order and correctness evidence are recorded,
but warmup timings are omitted and never enter an estimator.

Raw quartet metrics are `S=A/B`, `C=C/D`, `R0=C/A`, `R1=D/B`, and
`D=R1/R0=S/C`; values above one favor the new scanner or the applicable
background arm. Each ID contributes its eight-quartet median, followed by an
equal-ID geometric mean. The preregistered diagnostics are the S ratio of the
four A-before-B orders to the four B-before-A orders and the D ratio of order
indices 0--3 to 4--7.

The result-blind ITT manifest is
`35b0037122bf2ab9a2c1641a562f23f12b88856ceb66c713ceb9403adb541823`
(44 count-panel IDs). Secondary selected-34 and complement-10 manifests are
`b2e2ab1fcdc39d78e60eadb1bb34aeb3075ebf0133ef67532843d8da952cb951`
and `398657722d7192f0b641770e69fc390f808faf249efc02990667c0587a38a795`.
Profiles remain `auto`, `asimd`, `sve`, and `sve2`; panels remain default
output, count/default threads, and count/thread 1. The primary cell is
`auto/fre-count-default-threads/ITT44`.

The deterministic 10,000-draw seed is SHA-256 of ASCII
`rg-aot-retained-mask-scanner-delta-v1-bootstrap`, one NUL, then decoded old
binary, new binary, old private probe, new private probe, and fixed44 hashes.
The digest is
`1caba9b4acf7e92d40917bfafce52b33867be78078b4c4a748e3216b67629892`;
the unsigned big-endian first-eight-byte seed is `2065931447540640045`.
Iteration is profile, panel, stratum (ITT/selected/complement), replicate. Each
draw resamples IDs and then eight complete four-arm quartets independently for
each drawn ID occurrence. All metrics use the same draws; arms and metrics are
never resampled separately. Sorted interval indices are 250 and 9749.

For a reverse confirmation, the offline auditor first validates both runs
separately. Within each ID and metric it pools the two ordinary eight-quartet
medians as `sqrt(primary * reverse)`, then forms the equal-ID geometric-mean
cell. Its deterministic 10,000-draw paired bootstrap uses the same resampled
IDs for both runs, independently resamples eight complete quartets within each
run, pools the two resampled per-ID medians geometrically, and derives all five
metrics jointly. RNG consumption is again profile, panel, stratum, replicate;
within an ID occurrence it draws the primary quartet indices before the
reverse indices.

## Preregistration and commands

The preregistration is canonical JSON: sorted keys, compact separators, ASCII
escaping, no NaN, and one trailing newline. Its keys are `schema`,
`sealed_before_timing`, `protocol`, `identities`, `qualification_probes`,
`qualification_artifacts`, `inputs`, `runner`, and
`host_capability_attestation`. Obtain the frozen protocol from
`scanner_delta.protocol_record()`; its canonical SHA-256 is
`e244d3b79d0430994c99abc2edc3d191c7a33ab8dcd5392bd9410a8b9c1670c5`.
Dynamic fields bind the probes' separate stock references, transported
selection, corpus commits/trees, clean control-runner commit/tree, and exact
runner/auditor hashes. The runner hashes the complete extracted corpus entry
tree (relative paths, types, modes, symlink targets, and regular-file bytes)
both before and after timing. These fields have no defaults.

Primary campaign (all paths are examples):

```sh
python3 experiments/background-aot-representative/scanner_delta.py \
  benchmark-scanner-delta \
  --preregistration /path/prereg.json \
  --selection-manifest-input /path/selection.private.json \
  --old-binary /path/old/rg --old-source /path/old/source \
  --old-fre-source /path/old/fre \
  --new-binary /path/new/rg --new-source /path/new/source \
  --new-fre-source /path/new/fre \
  --old-probe-private /path/old-probe.private.json \
  --old-probe-public /path/old-probe.public.json \
  --new-probe-private /path/new-probe.private.json \
  --new-probe-public /path/new-probe.public.json \
  --new-qualification-manifest /path/new-qualification-manifest.json \
  --new-qualification-archive /path/new-qualification-archive \
  --ripgrep-corpus-repo /path/ripgrep-mirror \
  --ripgrep-corpus-commit COMMIT \
  --fre-corpus-repo /path/fre-mirror --fre-corpus-commit COMMIT \
  --campaign-role primary --row-traversal canonical \
  --private-checkpoint-output /new/path/primary.checkpoint.private.jsonl \
  --private-output /new/path/primary.private.json \
  --public-output /new/path/primary.public.json
```

Independent offline audit:

```sh
python3 experiments/background-aot-representative/scanner_delta.py \
  audit-scanner-delta \
  --preregistration /path/prereg.json \
  --selection-manifest-input /path/selection.private.json \
  --old-probe-private /path/old-probe.private.json \
  --old-probe-public /path/old-probe.public.json \
  --new-probe-private /path/new-probe.private.json \
  --new-probe-public /path/new-probe.public.json \
  --new-qualification-manifest /path/new-qualification-manifest.json \
  --new-qualification-archive /path/new-qualification-archive \
  --primary-private-result /path/primary.private.json \
  --primary-public-result /path/primary.public.json \
  --output /new/path/primary.audit.json
```

The auditor imports neither the runner nor `harness.py`. It reconstructs the
exact panel argv grammar (including flags, thread count, separator, pattern,
and consistent corpus root), every quartet metric and summary, all cohort
aggregates, the bootstrap stream, and every decision. Nested provenance and
result objects use closed schemas. Public artifacts are rejected if they
contain a private ID, a manifest pattern, an argv-like list, a path-like
string, or a private row/query key. The executing auditor must hash to the
exact preregistered auditor digest before it can emit `verified: true`.

R1 is clear GO only when its 95% interval is wholly above 1.03 and clear
NO-GO only when wholly below. Attribution also requires ITT S and D intervals
wholly above 1, selected-34 D wholly above 1, ITT C in `[0.97,1.03]`,
complement S and D in `[0.97,1.03]`, and split ratios in `[0.95,1.05]`.
Delta is material only at D point estimate at least 1.03. Any failed or
inconclusive gate records exact triggers and requires a separate reverse run.

That invocation uses `--campaign-role reverse-row-confirmation`,
`--row-traversal reverse-canonical`, and the primary private, public, and audit
paths, with distinct outputs. A final audit supplies both result pairs and the
primary authorization audit. It verifies chronology/non-overlap, recomputes
both analyses, reports reverse/primary diagnostics, performs the joint paired
bootstrap above, and emits the sealed combined verdict.

Combined enablement requires both run R1 points at least 1.03, a pooled R1
interval wholly above 1.03, and reverse/primary R1 in `[0.95,1.05]`. Combined
scanner win requires both run S and D points above 1, pooled S and D intervals
above 1, pooled selected-34 D above 1, pooled C and complement controls in
their original bands, reverse/primary S/D/C/R1 in `[0.95,1.05]`, and every
run's direction, orientation, and control gates to pass. Pooled D must still
be at least 1.03. Clear NO-GO holds if the pooled R1 interval is wholly below
1.03 or either run R1 point is below 1.03; otherwise a non-GO result is
inconclusive. Pooling can never rescue a failed direction, order, or control
gate.
