#!/usr/bin/env python3
"""Create a compact, deterministic summary from both fresh-process runs."""

from __future__ import annotations

import json
import random
import statistics
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_SEED = 20_260_820
BOOTSTRAP_RESAMPLES = 20_000


def summarize(label: str) -> dict:
    source = ROOT / f"artifacts/raw/fresh-process-benchmark-{label}.json"
    record = json.loads(source.read_text())
    rng = random.Random(BOOTSTRAP_SEED)
    cells = []
    for cell in record["cells"]:
        ratios = [
            sample["stock"]["elapsed_ns"] / sample["fre"]["elapsed_ns"]
            for sample in cell["samples"]
        ]
        bootstrap_medians = sorted(
            statistics.median(rng.choices(ratios, k=len(ratios)))
            for _ in range(BOOTSTRAP_RESAMPLES)
        )
        summary = cell["summary"]
        cells.append(
            {
                "id": cell["id"],
                "class": cell["class"],
                "stock_median_ms": summary["stock_median_ns"] / 1_000_000,
                "fre_median_ms": summary["fre_median_ns"] / 1_000_000,
                "ratio_of_medians_stock_over_fre": summary[
                    "ratio_of_medians_stock_over_fre"
                ],
                "paired_ratio_median_stock_over_fre": statistics.median(ratios),
                "paired_ratio_bootstrap_95_low": bootstrap_medians[499],
                "paired_ratio_bootstrap_95_high": bootstrap_medians[19_499],
                "fre_faster_pairs": sum(ratio > 1.0 for ratio in ratios),
                "pairs": len(ratios),
            }
        )
    return {
        "label": label,
        "source": str(source.relative_to(ROOT)),
        "binaries": record["binaries"],
        "method": record["method"],
        "cells": cells,
    }


def main() -> None:
    output = {
        "schema": "rg-fre-aot-benchmark-summary-v1",
        "ratio_definition": "stock elapsed / FRE elapsed; greater than 1 favors FRE",
        "bootstrap": {
            "unit": "paired stock/FRE elapsed ratio",
            "statistic": "median",
            "resamples": BOOTSTRAP_RESAMPLES,
            "seed": BOOTSTRAP_SEED,
            "interval": "percentile 95%",
        },
        "runs": [summarize("asimd"), summarize("scalar")],
    }
    destination = ROOT / "artifacts/raw/benchmark-summary.json"
    destination.write_text(json.dumps(output, indent=2) + "\n")
    print(destination)


if __name__ == "__main__":
    main()
