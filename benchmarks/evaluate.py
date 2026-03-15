"""Detection Benchmark Harness — measures recall/precision/F1 per category."""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from cloakllm import Shield, ShieldConfig


NER_CATEGORIES = {"PERSON", "ORG", "GPE"}

CORPUS_PATH = Path(__file__).parent / "corpus.json"


@dataclass
class Metrics:
    """Accumulates TP/FP/FN and computes precision/recall/F1."""

    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int,
              threshold: float = 0.5) -> bool:
    """Check if two spans overlap by at least `threshold` of the smaller span."""
    overlap = max(0, min(a_end, b_end) - max(a_start, b_start))
    smaller = min(a_end - a_start, b_end - b_start)
    return overlap / smaller >= threshold if smaller > 0 else False


def load_corpus(path: Path | str | None = None, skip_ner: bool = False) -> list[dict]:
    """Load corpus from JSON file. Optionally filter out NER entities."""
    if path is None:
        path = CORPUS_PATH
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    samples = data["samples"]
    if skip_ner:
        for s in samples:
            s["entities"] = [
                e for e in s["entities"]
                if e["category"] not in NER_CATEGORIES
            ]
    return samples


def evaluate(shield: Shield, corpus: list[dict]) -> dict:
    """Run detection on every corpus sample and compute metrics.

    Returns dict with 'overall', 'per_category', and 'samples' keys.
    """
    per_cat: dict[str, Metrics] = defaultdict(Metrics)
    overall = Metrics()
    sample_results = []

    for sample in corpus:
        detections, _ = shield.detector.detect(sample["text"])
        ground_truth = sample["entities"]

        matched_gt: set[int] = set()
        matched_det: set[int] = set()

        # Greedy 1:1 matching — first match wins
        for di, det in enumerate(detections):
            for gi, gt in enumerate(ground_truth):
                if gi in matched_gt:
                    continue
                if det.category == gt["category"] and _overlaps(
                    det.start, det.end, gt["start"], gt["end"]
                ):
                    matched_gt.add(gi)
                    matched_det.add(di)
                    per_cat[gt["category"]].tp += 1
                    overall.tp += 1
                    break

        # False positives: detections not matched to any ground truth
        sample_fp = 0
        for di in range(len(detections)):
            if di not in matched_det:
                per_cat[detections[di].category].fp += 1
                overall.fp += 1
                sample_fp += 1

        # False negatives: ground truth not matched to any detection
        sample_fn = 0
        for gi, gt in enumerate(ground_truth):
            if gi not in matched_gt:
                per_cat[gt["category"]].fn += 1
                overall.fn += 1
                sample_fn += 1

        sample_results.append({
            "id": sample["id"],
            "tags": sample.get("tags", []),
            "expected": len(ground_truth),
            "detected": len(detections),
            "tp": len(matched_gt),
            "fp": sample_fp,
            "fn": sample_fn,
        })

    return {
        "overall": {
            "precision": round(overall.precision, 4),
            "recall": round(overall.recall, 4),
            "f1": round(overall.f1, 4),
            "tp": overall.tp,
            "fp": overall.fp,
            "fn": overall.fn,
        },
        "per_category": {
            cat: {
                "precision": round(m.precision, 4),
                "recall": round(m.recall, 4),
                "f1": round(m.f1, 4),
                "tp": m.tp,
                "fp": m.fp,
                "fn": m.fn,
            }
            for cat, m in sorted(per_cat.items())
        },
        "samples": sample_results,
    }


def main() -> None:
    """CLI entry point: python -m benchmarks.evaluate [--json] [--no-ner]"""
    use_json = "--json" in sys.argv
    skip_ner = "--no-ner" in sys.argv

    shield = Shield(ShieldConfig(audit_enabled=False))
    corpus = load_corpus(skip_ner=skip_ner)
    results = evaluate(shield, corpus)

    if use_json:
        print(json.dumps(results, indent=2))
    else:
        o = results["overall"]
        print(f"\nOverall: P={o['precision']:.1%}  R={o['recall']:.1%}  "
              f"F1={o['f1']:.1%}  (TP={o['tp']} FP={o['fp']} FN={o['fn']})")
        print()
        for cat, m in results["per_category"].items():
            print(f"  {cat:15s}  P={m['precision']:.1%}  R={m['recall']:.1%}  "
                  f"F1={m['f1']:.1%}  (TP={m['tp']} FP={m['fp']} FN={m['fn']})")

        # Threshold checks
        failed = False
        if o["recall"] < 0.95:
            print(f"\n  FAIL: Overall recall {o['recall']:.1%} < 95% target")
            failed = True
        if o["precision"] < 0.80:
            print(f"\n  FAIL: Overall precision {o['precision']:.1%} < 80% target")
            failed = True
        for cat, m in results["per_category"].items():
            if m["recall"] < 0.80 and (m["tp"] + m["fn"]) > 0:
                print(f"\n  FAIL: {cat} recall {m['recall']:.1%} < 80% target")
                failed = True

        if failed:
            sys.exit(1)
        else:
            print("\n  All thresholds passed.")


if __name__ == "__main__":
    main()
