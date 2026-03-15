"""Detection benchmark threshold tests.

These tests run the full PII corpus through the detection engine
and assert minimum recall/precision thresholds are met.
"""

import pytest
from pathlib import Path

from cloakllm import Shield, ShieldConfig
from benchmarks.evaluate import evaluate, load_corpus


CORPUS_PATH = Path(__file__).parent.parent / "benchmarks" / "corpus.json"


@pytest.fixture(scope="module")
def results():
    """Run evaluation once for all tests in this module."""
    shield = Shield(ShieldConfig(audit_enabled=False))
    corpus = load_corpus(CORPUS_PATH)
    return evaluate(shield, corpus)


def test_overall_recall(results):
    """Overall recall must be >= 95%."""
    assert results["overall"]["recall"] >= 0.95, (
        f"Overall recall {results['overall']['recall']:.1%} < 95%"
    )


def test_overall_precision(results):
    """Overall precision must be >= 80%.

    NER (spaCy) produces structural false positives — it detects entities
    (ORG, GPE, LOC, NORP) that aren't in the ground truth. This is expected
    and keeps the threshold at 80% rather than 90%.
    """
    assert results["overall"]["precision"] >= 0.80, (
        f"Overall precision {results['overall']['precision']:.1%} < 80%"
    )


def test_no_category_below_80_recall(results):
    """No individual category should have recall below 80%."""
    for cat, m in results["per_category"].items():
        if (m["tp"] + m["fn"]) > 0:  # skip categories with no samples
            assert m["recall"] >= 0.80, (
                f"{cat} recall {m['recall']:.1%} < 80%"
            )


def test_no_false_positives_on_negatives(results):
    """Negative samples (no PII) should produce zero false positives."""
    for sample in results["samples"]:
        if "negative" in sample.get("tags", []):
            assert sample["fp"] == 0, (
                f"False positive on negative sample {sample['id']}"
            )
