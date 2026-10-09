"""Score CloakLLM on the synthetic clinical corpus.

For every labelled span (see _gen_clinical_corpus.py):
  expect=remove  ->  SCRUBBED (>=99% of its characters removed), PARTIAL, or RAW leak.
                     Character coverage by ANY detection, as in report_hard.py:
                     the no-PII promise is about characters, not category labels.
  expect=keep    ->  OVER-REMOVED if any detection touches it. Removing a drug,
                     a lab or a value breaks the clinical question.
Plus OTHER removals: detections that touch no labelled span at all.

Identifiers are grouped by scope:
  default      caught by CloakLLM today
  pack         the job of the v0.13.0 clinical identifier pack
  safe_harbor  HIPAA Safe Harbor only (other dates, ages 90+, addresses, ZIP)

Output contains categories and counts only. Values are printed only for the
fictitious corpus, and only with --show.

Run: python -m benchmarks.clinical.report_clinical [--show] [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import os
import tempfile
import warnings
from collections import defaultdict
from pathlib import Path

warnings.filterwarnings("ignore")

from cloakllm import Shield, ShieldConfig  # noqa: E402

CORPUS = Path(__file__).parent / "corpus_clinical.json"
SCOPES = ("default", "pack", "safe_harbor")


def configs(log_dir: str):
    """The configurations compared. 'tuned-0.12.7' is the two-line setup
    shown on cloakllm.dev/health -- measured here so its limits are known."""
    return {
        "default": ShieldConfig(log_dir=log_dir, audit_enabled=False),
        # v0.13.0: default settings plus the clinical date and age engine.
        "default+dates": ShieldConfig(
            log_dir=log_dir, audit_enabled=False,
            detect_dates=True, detect_ages_over_89=True,
        ),
        # v0.13.0: dates + ages + the US health identifier pack.
        "default+health": ShieldConfig(
            log_dir=log_dir, audit_enabled=False,
            detect_dates=True, detect_ages_over_89=True, detect_us_health_ids=True,
        ),
        "tuned-0.12.7": ShieldConfig(
            log_dir=log_dir, audit_enabled=False,
            ner_entity_types={"PERSON", "GPE"},
            custom_patterns=[("MRN", r"(?<=MRN )\d{6,10}"),
                             ("DOB", r"(?<=DOB )\d{2}/\d{2}/\d{4}")],
        ),
    }


def coverage(start, end, dets):
    n = end - start
    covered = [False] * n
    for d in dets:
        lo, hi = max(start, d.start), min(end, d.end)
        for i in range(lo - start, hi - start):
            covered[i] = True
    return sum(covered) / n if n else 0.0


def measure(shield, samples, show=False):
    rm = defaultdict(lambda: {"total": 0, "scrub": 0, "partial": 0, "raw": 0})
    keep = defaultdict(lambda: {"total": 0, "over": 0})
    other = defaultdict(int)
    examples = defaultdict(list)
    for s in samples:
        dets, _ = shield.detector.detect(s["text"])
        for e in s["entities"]:
            if e["expect"] == "remove":
                key = (e["scope"], e["category"])
                b = rm[key]; b["total"] += 1
                cov = coverage(e["start"], e["end"], dets)
                if cov >= 0.99:
                    b["scrub"] += 1
                elif cov > 0:
                    b["partial"] += 1
                    examples["partial"].append((e["category"], e["value"], s["kind"]))
                else:
                    b["raw"] += 1
                    examples["raw"].append((e["category"], e["value"], s["kind"]))
            else:
                b = keep[e["category"]]; b["total"] += 1
                hit = [d for d in dets if d.start < e["end"] and d.end > e["start"]]
                if hit:
                    b["over"] += 1
                    examples["over"].append((e["category"], e["value"], [d.category for d in hit]))
        for d in dets:
            if not any(d.start < e["end"] and d.end > e["start"] for e in s["entities"]):
                other[d.category] += 1
                examples["other"].append((d.category, d.text, s["kind"]))
    return rm, keep, other, examples


def pct(a, b):
    return f"{100 * a / b:5.1f}%" if b else "   - "


def print_report(name, rm, keep, other, examples, show):
    print(f"\n=== {name} ===")
    print("Identifiers (expect=remove), scrubbed / partial / raw leak:")
    for scope in SCOPES:
        rows = sorted((k, v) for k, v in rm.items() if k[0] == scope)
        if not rows:
            continue
        tot = {f: sum(v[f] for _, v in rows) for f in ("total", "scrub", "partial", "raw")}
        print(f"  [{scope}] scrub {pct(tot['scrub'], tot['total'])}  "
              f"({tot['scrub']}/{tot['total']}, partial {tot['partial']}, raw {tot['raw']})")
        for (_, cat), v in rows:
            print(f"      {cat:16} {pct(v['scrub'], v['total'])}  "
                  f"({v['scrub']}/{v['total']}, partial {v['partial']}, raw {v['raw']})")
    print("Clinical content (expect=keep), wrongly removed:")
    for cat, v in sorted(keep.items()):
        print(f"      {cat:16} {pct(v['over'], v['total'])}  ({v['over']}/{v['total']})")
    print("Other removals (touching no labelled span): "
          + (", ".join(f"{c} {n}" for c, n in sorted(other.items())) or "none"))
    if show:
        for kind in ("raw", "partial", "over", "other"):
            seen = []
            for x in examples[kind]:
                if x not in seen:
                    seen.append(x)
            if seen:
                print(f"  e.g. {kind}: " + "; ".join(repr(x) for x in seen[:8]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--show", action="store_true", help="print example values (fictitious corpus only)")
    ap.add_argument("--json", help="write a machine-readable summary here")
    args = ap.parse_args()
    data = json.loads(CORPUS.read_text(encoding="utf-8"))
    samples = data["samples"]
    print(f"Synthetic clinical corpus: {len(samples)} notes (seed {data['seed']}), fictitious data only.")
    summary = {}
    with tempfile.TemporaryDirectory(dir=os.getcwd()) as d:
        for name, cfg in configs(d).items():
            rm, keep, other, ex = measure(Shield(cfg), samples, args.show)
            print_report(name, rm, keep, other, ex, args.show)
            summary[name] = {
                "remove": {f"{s}/{c}": v for (s, c), v in rm.items()},
                "keep": dict(keep),
                "other": dict(other),
            }
    if args.json:
        Path(args.json).write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
