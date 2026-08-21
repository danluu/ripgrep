# Commands used

All commands below were run from
`/Users/danluu/dev/ripgrep-fre-aot-20260820` unless noted.

## Isolated worktrees

```sh
git -C /Users/danluu/dev/ripgrep worktree add \
  -b fre-aot-20260820 \
  /Users/danluu/dev/ripgrep-fre-aot-20260820 \
  f9c05a949d1a0dc8e16dee28ca9605d38611faeb

git -C /Users/danluu/dev/fre-3 worktree add --detach \
  /Users/danluu/dev/fre-rg-aot-deps-20260820 \
  b1dfe2b159433b0430e33a7703e2a5c7f3ad8c2d
```

## Preserved stock build

This was done before modifying ripgrep source:

```sh
cargo build --release --ignore-rust-version
mkdir -p artifacts/bin artifacts/raw
cp target/release/rg artifacts/bin/rg-stock-f9c05a9
shasum -a 256 artifacts/bin/rg-stock-f9c05a9
```

## Candidate build and tests

`.cargo/config.toml` supplies the exact manifest and `asimd` AOT build feature.

```sh
cargo build --release --ignore-rust-version
cargo test --ignore-rust-version
python3 experiments/generate_benchmark_corpus.py
python3 experiments/verify_equivalence.py
```

Route checks use the normal CLI debug log, for example:

```sh
target/release/rg --debug --engine=fre --count \
  '(?:a|aa)*b' experiments/correctness-input.txt

target/release/rg --debug --engine=fre --count \
  'an-unregistered-query' experiments/correctness-input.txt
```

## Fresh-process benchmark

```sh
python3 experiments/benchmark_fresh_process.py
cp artifacts/raw/fresh-process-benchmark.json \
  artifacts/raw/fresh-process-benchmark-asimd.json
cp artifacts/raw/fresh-process-benchmark.partial.json \
  artifacts/raw/fresh-process-benchmark-asimd.partial.json
python3 experiments/summarize_benchmark.py
```

The harness itself defines all arguments and records the exact command inputs,
31 raw pairs per cell, order, elapsed nanoseconds, status, and output bytes.
It alternates stock/FRE order and aborts on any output or exit mismatch.

## Scalar diagnostic

The scalar run used the same source, corpus, cells, and protocol before
`FRE_RIPGREP_AOT_FEATURES=asimd` was added. Its binary and raw output were
preserved as:

```text
artifacts/bin/rg-fre-scalar-cf59dc
artifacts/raw/fresh-process-benchmark-scalar.json
```

For a new scalar rebuild without editing the checked-in config, an explicitly
empty process environment value takes precedence over Cargo's config value:

```sh
FRE_RIPGREP_AOT_FEATURES= \
  CARGO_TARGET_DIR=target-scalar \
  cargo build --release --ignore-rust-version
```

## Integrity and worktree checks

```sh
shasum -a 256 \
  artifacts/bin/rg-stock-f9c05a9 \
  artifacts/bin/rg-fre-asimd-5ea3bc \
  artifacts/raw/fresh-process-benchmark-asimd.json \
  artifacts/raw/fresh-process-benchmark-scalar.json

git -C /Users/danluu/dev/fre-rg-aot-deps-20260820 status --short
git -C /Users/danluu/dev/ripgrep status --short
git -C /Users/danluu/dev/fre-3 status --short
```

The timed ASIMD binary was also compared with a clean-source rebuild. The
`__TEXT,__text` offset and size below come from `otool -l`; both hashes were
identical:

```sh
dd if=artifacts/bin/rg-fre-asimd-5ea3bc \
  bs=1 skip=2240 count=3467444 2>/dev/null | shasum -a 256
dd if=target/release/rg \
  bs=1 skip=2240 count=3467444 2>/dev/null | shasum -a 256
```
