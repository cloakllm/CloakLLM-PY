"""Generate a HARD, realistic PII detection corpus (benchmarks/corpus_hard.json).

Goal: an honest measure of detection quality on the messy, varied, sometimes
adversarial text real users actually send — not the curated easy corpus.

Offsets are computed programmatically (left-to-right cursor per sample) so a
label can never drift. Each sample is tagged by difficulty axis so the report
can slice a FAIR real-world number (realistic / format-variant / multilingual /
context-embedded) from an ADVERSARIAL one (obfuscated) and from hard-negatives.

Scope = the DEFAULT Shield config (regex + spaCy NER), which is what the ~1.9k
downloads/week of users get out of the box. Categories the OPTIONAL Ollama LLM
pass would catch (ADDRESS, DOB, MEDICAL) are intentionally NOT labeled here;
they are out of default scope and would be a separate benchmark.
"""
from __future__ import annotations

import json
from pathlib import Path

# (text, [(value, category), ...], [tags])
SAMPLES: list[tuple[str, list[tuple[str, str]], list[str]]] = []


def add(text, ents, tags):
    SAMPLES.append((text, ents, tags))


# ---------------------------------------------------------------- EMAIL
add("Shoot me a note at first.last+newsletter@sub.example.co.uk when ready.",
    [("first.last+newsletter@sub.example.co.uk", "EMAIL")], ["realistic", "format-variant"])
add("From: \"Díaz, María\" <maria.diaz@empresa.es>\nSubject: factura",
    [("maria.diaz@empresa.es", "EMAIL")], ["realistic", "context-embedded"])
add("user_email='a_b-c.d@mail-server.io'; // config",
    [("a_b-c.d@mail-server.io", "EMAIL")], ["context-embedded", "format-variant"])
add("reach me — john dot doe at gmail dot com — thanks",
    [("john dot doe at gmail dot com", "EMAIL")], ["obfuscated"])
add("Contact: jane[at]example[dot]org",
    [("jane[at]example[dot]org", "EMAIL")], ["obfuscated"])
add("Two addresses: sales@acme.com and billing@acme.com please cc both.",
    [("sales@acme.com", "EMAIL"), ("billing@acme.com", "EMAIL")], ["realistic", "multi"])

# ---------------------------------------------------------------- PHONE
add("Call me on +44 20 7946 0958 after lunch.",
    [("+44 20 7946 0958", "PHONE")], ["realistic", "multilingual", "format-variant"])
add("Mobile: (555) 123-4567 ext. 89",
    [("(555) 123-4567", "PHONE")], ["realistic", "format-variant"])
add("tel:+1.415.555.0132",
    [("+1.415.555.0132", "PHONE")], ["format-variant", "context-embedded"])
add("Mein Handy ist 0151 23456789, ruf einfach an.",
    [("0151 23456789", "PHONE")], ["multilingual"])
add("ring me five five five, two three four, nine eight seven six",
    [("five five five, two three four, nine eight seven six", "PHONE")], ["obfuscated"])
add("Numéro: 06 12 34 56 78 (portable)",
    [("06 12 34 56 78", "PHONE")], ["multilingual", "format-variant"])

# ---------------------------------------------------------------- SSN
add("SSN on file: 123 45 6789 (no dashes in the form).",
    [("123 45 6789", "SSN")], ["format-variant"])
add("the last four of my social are 6789, full is 123-45-6789",
    [("123-45-6789", "SSN")], ["realistic", "context-embedded"])
add("ssn=123456789 in the legacy export",
    [("123456789", "SSN")], ["format-variant", "context-embedded"])

# ---------------------------------------------------------------- CREDIT_CARD
add("Card: 4111 1111 1111 1111 exp 12/27 cvv 123",
    [("4111 1111 1111 1111", "CREDIT_CARD")], ["realistic", "format-variant"])
add("Amex 3782 822463 10005 declined again",
    [("3782 822463 10005", "CREDIT_CARD")], ["format-variant"])
add("charged to 5500-0000-0000-0004 yesterday",
    [("5500-0000-0000-0004", "CREDIT_CARD")], ["format-variant"])

# ---------------------------------------------------------------- IP / API / AWS / JWT
add("server logged from 192.168.0.14 and also 2001:0db8:85a3::8a2e:0370:7334",
    [("192.168.0.14", "IP_ADDRESS"), ("2001:0db8:85a3::8a2e:0370:7334", "IP_ADDRESS")],
    ["context-embedded", "multi", "format-variant"])
add("export OPENAI_API_KEY=sk-proj-abc123DEF456ghi789JKL012mno345PQ",
    [("sk-proj-abc123DEF456ghi789JKL012mno345PQ", "API_KEY")], ["context-embedded"])
add("AWS creds leaked: AKIAIOSFODNN7EXAMPLE / secret hidden",
    [("AKIAIOSFODNN7EXAMPLE", "AWS_KEY")], ["context-embedded"])
add("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
    [("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", "JWT")],
    ["context-embedded"])

# ---------------------------------------------------------------- IBAN
add("Please wire to DE89 3704 0044 0532 0130 00 by Friday.",
    [("DE89 3704 0044 0532 0130 00", "IBAN")], ["realistic", "multilingual"])
add("IBAN GB29 NWBK 6016 1331 9268 19 for the refund",
    [("GB29 NWBK 6016 1331 9268 19", "IBAN")], ["multilingual", "format-variant"])
add("Compte: FR1420041010050500013M02606",
    [("FR1420041010050500013M02606", "IBAN")], ["multilingual", "format-variant"])

# ---------------------------------------------------------------- PERSON (NER — the weak axis)
add("Hi, it's sarah from accounting, can you resend the invoice?",
    [("sarah", "PERSON")], ["realistic", "obfuscated"])  # lowercase, weak NER signal
add("Dr. Emily Carter signed off on the procedure.",
    [("Emily Carter", "PERSON")], ["realistic"])
add("escalate to Raj Patel and Wei Zhang on the oncall rota",
    [("Raj Patel", "PERSON"), ("Wei Zhang", "PERSON")], ["realistic", "multi", "multilingual"])
add("Approved by François Lefèvre per the contract.",
    [("François Lefèvre", "PERSON")], ["multilingual"])
add("ping @msmith but cc Margaret Smith on the legal thread",
    [("Margaret Smith", "PERSON")], ["realistic"])
add("Patient: Nguyen Van An, room 4B",
    [("Nguyen Van An", "PERSON")], ["multilingual", "context-embedded"])

# ---------------------------------------------------------------- ORG / GPE
add("She moved from Acme Corp to Globex before relocating to Lyon.",
    [("Acme Corp", "ORG"), ("Globex", "ORG"), ("Lyon", "GPE")], ["realistic", "multi"])
add("Our Berlin office handles all EU requests.",
    [("Berlin", "GPE")], ["realistic"])

# ---------------------------------------------------------------- HARD NEGATIVES (detect NOTHING)
add("Order #123-45-6789 shipped; tracking 1Z999AA10123456784.", [], ["hard-negative"])
add("Build 4.11.1.1192 deployed to 10 nodes; commit a1b2c3d4e5f6.", [], ["hard-negative"])
add("The UUID is 550e8400-e29b-41d4-a716-446655440000 (not secret).", [], ["hard-negative"])
add("ISBN 978-3-16-148410-0 and SKU 4111111111111111-RED in stock.", [], ["hard-negative"])
add("Meeting at 192 Main St, room 168, from 9:00 to 17:30.", [], ["hard-negative"])
add("Pi is 3.14159265 and the ratio was 16:9 on screen 2560x1440.", [], ["hard-negative"])
add("Invoice total $4,111.11; PO 1111-1111-1111-1111 internal ref only.", [], ["hard-negative"])


def _label(text, ents):
    out, cursor = [], 0
    for value, category in ents:
        idx = text.find(value, cursor)
        if idx < 0:  # fall back to a global search; never silently drop
            idx = text.find(value)
        if idx < 0:
            raise ValueError(f"value not found in text: {value!r} / {text!r}")
        out.append({"start": idx, "end": idx + len(value),
                    "category": category, "value": value})
        cursor = idx + len(value)
    return out


def main():
    samples = []
    for i, (text, ents, tags) in enumerate(SAMPLES):
        samples.append({
            "id": f"hard_{i:03d}",
            "text": text,
            "entities": _label(text, ents),
            "tags": tags,
        })
    out = {"samples": samples}
    path = Path(__file__).parent / "corpus_hard.json"
    path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    ents = sum(len(s["entities"]) for s in samples)
    print(f"wrote {path}  ({len(samples)} samples, {ents} labeled entities)")


if __name__ == "__main__":
    main()
