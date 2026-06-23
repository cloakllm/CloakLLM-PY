"""Honest detection-quality report over the HARD corpus.

The no-PII guarantee depends on the sensitive CHARACTERS being removed, not on
the category label being perfect. So this measures three distinct things per
ground-truth PII entity, using character-level coverage by the union of all
detections (regardless of category):

  * SCRUBBED      - >=99% of the PII characters are covered by some detection,
                    so the value is tokenized/removed. The no-PII invariant
                    HOLDS even if the category label is wrong.
  * PARTIAL LEAK  - 1..98% covered: part of the PII survives into the output.
  * RAW LEAK      - 0% covered: the value flows verbatim into the "clean" log.

and separately CATEGORY-CORRECT recall (covered AND right category).

Reported on the FAIR slice (realistic / formatted / multilingual / embedded)
vs the ADVERSARIAL (obfuscated) slice, plus hard-negative false positives.
Scope = the DEFAULT Shield (regex + spaCy NER), what users get out of the box.

Run: python -m benchmarks.report_hard
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from cloakllm import Shield, ShieldConfig
from benchmarks.evaluate import load_corpus

HARD = Path(__file__).parent / "corpus_hard.json"


def _coverage(span_start, span_end, dets):
    """Fraction of [span_start,span_end) covered by the union of detection spans,
    and whether any covering detection had the right category placeholder."""
    n = span_end - span_start
    if n <= 0:
        return 0.0, []
    covered = [False] * n
    hitting = []
    for d in dets:
        lo, hi = max(span_start, d.start), min(span_end, d.end)
        if hi > lo:
            hitting.append(d)
            for i in range(lo - span_start, hi - span_start):
                covered[i] = True
    return sum(covered) / n, hitting


def measure(shield, corpus):
    """Return (buckets, raw_leaks, partial_leaks, miscat, hard_neg_fp).

    buckets[slice] = {scrub, partial, raw, catok, total} where 'scrub' counts
    entities whose characters are >=99% removed (no-PII invariant holds, even if
    the category label is wrong). Reused by main() and the CI threshold test.
    """
    B = defaultdict(lambda: {"scrub": 0, "partial": 0, "raw": 0, "catok": 0, "total": 0})
    raw_leaks, partial_leaks, miscat, hard_neg_fp = [], [], [], []
    for s in corpus:
        dets, _ = shield.detector.detect(s["text"])
        tags = set(s.get("tags", []))
        slc = "obfuscated" if "obfuscated" in tags else "fair"
        for g in s["entities"]:
            cov, hitting = _coverage(g["start"], g["end"], dets)
            cat_ok = any(d.category == g["category"] for d in hitting)
            b = B[slc]; b["total"] += 1
            if cov >= 0.99:
                b["scrub"] += 1
                if cat_ok:
                    b["catok"] += 1
                else:
                    miscat.append((g["category"], [d.category for d in hitting], g["value"]))
            elif cov > 0:
                b["partial"] += 1
                partial_leaks.append((g["category"], round(cov, 2), g["value"]))
            else:
                b["raw"] += 1
                raw_leaks.append((g["category"], g["value"], sorted(tags)))
        if "hard-negative" in tags:
            for d in dets:
                hard_neg_fp.append((d.category, s["text"][d.start:d.end]))
    return B, raw_leaks, partial_leaks, miscat, hard_neg_fp


def main():
    shield = Shield(ShieldConfig(audit_enabled=False))
    corpus = load_corpus(HARD)
    B, raw_leaks, partial_leaks, miscat, hard_neg_fp = measure(shield, corpus)

    def line(name, b):
        t = b["total"] or 1
        print(f"{name:12} n={b['total']:3}  scrub(no-PII)={b['scrub']/t:5.1%}  "
              f"cat-correct={b['catok']/t:5.1%}  partial={b['partial']}  RAW-LEAK={b['raw']}")

    print("\n=== Detection quality on the HARD corpus (default regex+NER) ===")
    line("FAIR", B["fair"])
    line("ADVERSARIAL", B["obfuscated"])
    print(f"HARD-NEGATIVES: {len(hard_neg_fp)} false positive(s)")

    print("\n--- RAW LEAKS (value flows verbatim into the log; breaks no-PII) ---")
    for cat, val, tags in raw_leaks or []:
        print(f"   [{cat:11}] {val!r:50} ({','.join(tags)})")
    if not raw_leaks:
        print("   (none)")

    print("\n--- PARTIAL LEAKS (only part of the PII removed) ---")
    for cat, cov, val in partial_leaks or []:
        print(f"   [{cat:11}] {cov:.0%} covered: {val!r}")
    if not partial_leaks:
        print("   (none)")

    print("\n--- MISCLASSIFIED (scrubbed, so no-PII holds, but wrong category) ---")
    for want, got, val in miscat or []:
        print(f"   want {want:11} got {got} : {val!r}")
    if not miscat:
        print("   (none)")

    print("\n--- FALSE POSITIVES on hard-negatives ---")
    for cat, val in hard_neg_fp or []:
        print(f"   [{cat:11}] {val!r}")
    if not hard_neg_fp:
        print("   (none)")


if __name__ == "__main__":
    main()
