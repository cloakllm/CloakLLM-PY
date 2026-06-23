"""AUDIT-14(b): cross-SDK detection differential.

Runs one shared adversarial corpus through BOTH SDKs' REGEX detectors and diffs
the verdicts. The hand-mirrored Python/JS regexes MUST agree -- a divergence
means one SDK leaks (or over-redacts) where the other doesn't, which is exactly
the shape the v0.11.2 IBAN-ordering bug would have had if fixed in only one SDK.

NER (spaCy vs compromise) divergence is expected and excluded; only the shared
regex categories are compared.

Requires the cloakllm-js sibling repo + node on PATH. Run from the cloakllm-py
root during Step 0 (AUDIT-14):  python -m benchmarks.xsdk_detection_diff
Exit 0 = parity, 1 = divergence (ASCII-only output).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from cloakllm import Shield, ShieldConfig

SHARED_CATS = {"EMAIL", "SSN", "CREDIT_CARD", "PHONE", "IP_ADDRESS",
               "API_KEY", "AWS_KEY", "JWT", "IBAN"}
_HERE = Path(__file__).resolve().parent
_JS_DUMP = _HERE.parents[1] / "cloakllm-js" / "tools" / "_xsdk_dump.js"

# adversarial structures on top of the two committed corpora
EXTRA = [
    "login at https://admin:s3cr3tP@ss@host.example.com/path",
    "GET /api?email=jane@x.com&ssn=123-45-6789&card=4111111111111111",
    '{"email":"a.b@c.io","ip":"10.0.0.5","phone":"+1-415-555-0199"}',
    "card4111 1111 1111 1111here",
    "5105105105105100 and 5105 1051 0510 5100",
    "IPv6 ::ffff:192.168.0.1 mapped", "fe80::1%eth0 scoped",
    "IBANs: NL91ABNA0417164300 and NL91 ABNA 0417 1643 00",
    "amex372 8 not a card; 378282246310005 is",
    "SSN123456789 contiguous and 123-45-6789 dashed",
    "Bearer eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.abcDEF_123-xyz",
    "AKIAIOSFODNN7EXAMPLE and akia not a key",
    "email UPPER.CASE@EXAMPLE.COM and Mixed@Case.Org",
    "phone (415) 555-0199 x42 and 415.555.0199",
    "weird 4111-1111 1111-1111 mixed seps",
    "tel +44 (0)20 7946 0958 uk", "ip 256.1.1.1 invalid and 192.168.1.1 valid",
    "card 6011000990139424 discover", "ssn 000-12-3456 invalid prefix",
    "kr number 010-1234-5678 style",
]


def _load_corpus_texts():
    texts = []
    for name in ("corpus.json", "corpus_hard.json"):
        p = _HERE / name
        if p.exists():
            d = json.loads(p.read_text(encoding="utf-8"))
            texts += [s["text"] for s in (d if isinstance(d, list) else d["samples"])]
    return texts


def main():
    if not _JS_DUMP.exists():
        print("SKIP: cloakllm-js sibling not found at", _JS_DUMP)
        return 0
    inputs = _load_corpus_texts() + EXTRA
    fd, ipath = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    Path(ipath).write_text(json.dumps(inputs, ensure_ascii=False), encoding="utf-8")

    shield = Shield(ShieldConfig(audit_enabled=False))
    py = []
    for t in inputs:
        dets, _ = shield.detector.detect(t)
        py.append(sorted([[d.category, d.start, d.end] for d in dets
                          if d.source == "regex" and d.category in SHARED_CATS]))

    res = subprocess.run(["node", str(_JS_DUMP), ipath],
                         capture_output=True, text=True)
    if res.returncode != 0:
        print("JS dump failed:", res.stderr[:500])
        return 1
    js = json.loads(res.stdout)

    div = 0
    for t, pa, jrec in zip(inputs, py, js):
        jb = sorted([x for x in jrec["reg"] if x[0] in SHARED_CATS])
        if pa != jb:
            div += 1
            print(f"\nDIVERGE: {t!r}\n   PY: {pa}\n   JS: {jb}")
    print(f"\ncross-SDK regex differential: {len(inputs)} inputs, {div} divergence(s)")
    return 1 if div else 0


if __name__ == "__main__":
    sys.exit(main())
