"""Generate the synthetic CLINICAL corpus (benchmarks/clinical/corpus_clinical.json).

Purpose: tune and measure the v0.13.0 health edition (PLAN_health_edition.md)
on clinical text, before any real clinic data is involved. US-first, English.

EVERYTHING HERE IS FICTITIOUS. No real patient, record or note was used.
  * Names are drawn from short invented-combination lists.
  * Phone numbers use 555-01xx, the range reserved for fiction.
  * Emails use example.com / example.org / example.net (reserved, RFC 2606).
  * SSNs are only 078-05-1120 and 219-09-9999, both publicly voided numbers.
  * MRNs, member IDs and Medicare numbers (MBI) are random strings in the
    published formats; any match to a real identifier would be coincidence.
  * Dates, ages and addresses are random.

Offsets cannot drift: every note is built from (text, label) pieces and the
span offsets are computed while joining them. The generator is seeded, so the
corpus is reproducible; regenerate rather than hand-editing the JSON.

Each labelled span has:
  category  -- what it is (PERSON, MRN, DATE_OF_BIRTH, CLINICAL_TERM, ...)
  expect    -- "remove": an identifier that must not reach the AI
               "keep":   clinical content that must survive (a drug, a lab,
                         a value, a disease named after a person)
  scope     -- for "remove" spans, who is responsible for catching it:
               "default"     detected by CloakLLM today (regex + NER)
               "pack"        the v0.13.0 clinical identifier pack's job
               "safe_harbor" required only by HIPAA Safe Harbor (other dates,
                             ages over 89, street addresses, cities, ZIP codes);
                             NOT in v0.13.0 -- measured so the gap is visible
  role      -- optional: "patient", "clinician", "relative"

Run: python -m benchmarks.clinical._gen_clinical_corpus
"""
from __future__ import annotations

import json
import random
from pathlib import Path

OUT = Path(__file__).parent / "corpus_clinical.json"
SEED = 20261009
N_PER_TEMPLATE = 12

FIRST = ["Maria", "James", "Linda", "Robert", "Aisha", "Daniel", "Grace", "Hector",
         "Priya", "Thomas", "Nora", "Samuel", "Ellen", "Marcus", "Rosa", "Victor",
         "Janet", "Kevin", "Lucia", "Owen"]
LAST = ["Lopez", "Whitaker", "Brennan", "Okafor", "Delgado", "Hartley", "Novak",
        "Castillo", "Pruitt", "Lindqvist", "Morrow", "Vance", "Kowalski", "Ferreira",
        "Abernathy", "Quinlan", "Sato", "Mbeki", "Halvorsen", "Draper"]
CLIN_LAST = ["Whitfield", "Osei", "Ramirez", "Cho", "Bergmann", "Patel", "Langley", "Ibarra"]
STREETS = ["Maple Ave", "Oak Street", "Birch Lane", "Cedar Court", "Willow Drive", "Elm Road"]
CITIES = [("Springfield", "IL"), ("Riverside", "CA"), ("Franklin", "TN"), ("Greenville", "SC"),
          ("Madison", "WI"), ("Salem", "OR")]
SSNS = ["078-05-1120", "219-09-9999"]

# Clinical content that must SURVIVE sanitization. Several are eponyms or
# place names on purpose: that is where name detection over-removes.
DRUG_CLASSES = ["SGLT2 inhibitor", "GLP-1 agonist", "ACE inhibitor", "ARB", "beta blocker",
                "statin", "DOAC", "PPI", "SSRI", "loop diuretic"]
DRUGS = ["metformin", "lisinopril", "atorvastatin", "apixaban", "warfarin", "empagliflozin",
         "semaglutide", "furosemide", "sertraline", "omeprazole", "levothyroxine", "insulin glargine"]
LABS = ["HbA1c", "eGFR", "BNP", "troponin", "CRP", "INR", "TSH", "LDL", "creatinine", "ferritin"]
CONDITIONS = ["T2DM", "COPD", "CHF", "CKD stage 3b", "NSTEMI", "atrial fibrillation",
              "hypertension", "hypothyroidism", "GERD", "major depressive disorder"]
EPONYMS = ["Parkinson's disease", "Crohn's disease", "Hodgkin lymphoma", "Cushing syndrome",
           "Alzheimer's disease", "Bell's palsy", "Graves' disease", "Lyme disease",
           "Down syndrome", "Addison's disease"]

MRN_LABELS = ["MRN: ", "MRN ", "MRN #", "Med Rec No. ", "Medical record number ", "Patient ID: ",
              "Chart #", "PID "]
DOB_LABELS = ["DOB: ", "DOB ", "D.O.B. ", "Date of birth: ", "born "]
MEMBER_LABELS = ["Member ID: ", "Member ID ", "Policy #", "Insurance ID: ", "Subscriber ID "]


class Note:
    """Accumulates (text, label) pieces; computes exact offsets on build()."""

    def __init__(self, kind: str, tags: list[str]):
        self.kind, self.tags, self.parts = kind, tags, []

    def t(self, s: str):
        self.parts.append((s, None))
        return self

    def rm(self, s: str, category: str, scope: str, role: str | None = None):
        self.parts.append((s, {"category": category, "expect": "remove", "scope": scope, "role": role}))
        return self

    def keep(self, s: str, category: str = "CLINICAL_TERM"):
        self.parts.append((s, {"category": category, "expect": "keep"}))
        return self

    def build(self, idx: int) -> dict:
        text, ents, pos = "", [], 0
        for s, lab in self.parts:
            if lab is not None:
                e = {"start": pos, "end": pos + len(s), "value": s, **{k: v for k, v in lab.items() if v is not None}}
                ents.append(e)
            text += s
            pos += len(s)
        return {"id": f"clin_{idx:03d}", "kind": self.kind, "text": text, "entities": ents, "tags": self.tags}


class Gen:
    def __init__(self, seed: int):
        self.r = random.Random(seed)

    # --- fictitious values ---------------------------------------------
    def pick(self, xs):
        return self.r.choice(xs)

    def name(self):
        return f"{self.pick(FIRST)} {self.pick(LAST)}"

    def clinician(self):
        return f"{self.pick(['Alan', 'Beth', 'Chen', 'Dana', 'Emil', 'Farah'])} {self.pick(CLIN_LAST)}"

    def phone(self):
        area = self.pick(["312", "415", "617", "713", "206", "404"])
        n = f"{self.r.randint(100, 199):03d}"[-2:]
        style = self.r.randint(0, 2)
        return [f"({area}) 555-01{n}", f"{area}-555-01{n}", f"{area}.555.01{n}"][style]

    def email(self, name):
        first, last = name.lower().split()
        return f"{first}.{last}@{self.pick(['example.com', 'example.org', 'example.net'])}"

    def mrn(self):
        if self.r.random() < 0.25:
            return f"{self.pick('ABCDEFGH')}{self.r.randint(10**6, 10**7 - 1)}"
        return str(self.r.randint(10**5, 10**9)).zfill(self.r.choice([7, 8, 9]))

    def dob(self):
        y, m, d = self.r.randint(1931, 2004), self.r.randint(1, 12), self.r.randint(1, 28)
        months = ["January", "February", "March", "April", "May", "June", "July", "August",
                  "September", "October", "November", "December"]
        return self.pick([f"{m:02d}/{d:02d}/{y}", f"{m}/{d}/{y}", f"{y}-{m:02d}-{d:02d}",
                          f"{months[m - 1]} {d}, {y}"])

    def visit_date(self):
        m, d = self.r.randint(1, 12), self.r.randint(1, 28)
        return self.pick([f"{m:02d}/{d:02d}/2026", f"2026-{m:02d}-{d:02d}", f"{m}/{d}"])

    def member_id(self):
        return self.pick(["XJH", "W", "MBR", "U"]) + str(self.r.randint(10**7, 10**10))

    def mbi(self):
        # CMS Medicare Beneficiary Identifier layout: C A AN N A AN N A A N N,
        # letters exclude S L O I B Z.
        L = "ACDEFGHJKMNPQRTUVWXY"
        A = L + "0123456789"
        c = [str(self.r.randint(1, 9)), self.pick(L), self.pick(A), str(self.r.randint(0, 9)),
             self.pick(L), self.pick(A), str(self.r.randint(0, 9)), self.pick(L), self.pick(L),
             str(self.r.randint(0, 9)), str(self.r.randint(0, 9))]
        s = "".join(c)
        return f"{s[:4]}-{s[4:7]}-{s[7:]}" if self.r.random() < 0.5 else s

    def address(self):
        city, st = self.pick(CITIES)
        return f"{self.r.randint(12, 989)} {self.pick(STREETS)}", city, st, f"{self.r.randint(10000, 99999)}"

    def a1c(self):
        return f"{self.r.randint(55, 129) / 10}%"

    def egfr(self):
        return f"{self.r.randint(180, 950) / 10}"

    # --- templates (each returns a Note) --------------------------------
    def ask_ai_medication(self):
        p = self.name(); age = self.r.randint(35, 84)
        n = Note("prompt_medication", ["prompt"])
        n.t("Patient ").rm(p, "PERSON", "default", "patient").t(", ")
        lab = self.pick(MRN_LABELS); n.t(lab).rm(self.mrn(), "MRN", "pack").t(", ")
        n.t(self.pick(DOB_LABELS)).rm(self.dob(), "DATE_OF_BIRTH", "pack").t(". ")
        n.t(f"{age}-year-old with ").keep(self.pick(CONDITIONS)).t(", ")
        n.keep("HbA1c").t(" ").keep(self.a1c(), "LAB_VALUE").t(", ").keep("eGFR").t(" ").keep(self.egfr(), "LAB_VALUE")
        n.t(", on ").keep(self.pick(DRUGS)).t(" ").keep(f"{self.pick([500, 850, 1000])} mg", "LAB_VALUE").t(" twice daily. ")
        n.t("Should we add an ").keep(self.pick(["SGLT2", "GLP-1"])).t(" agent?")
        return n

    def referral_letter(self):
        p = self.name(); doc = self.clinician()
        n = Note("referral_letter", ["letter"])
        n.t("Draft a referral letter to Dr. ").rm(doc, "PERSON", "default", "clinician")
        n.t(" for ").rm(p, "PERSON", "default", "patient").t(" (")
        n.t(self.pick(DOB_LABELS)).rm(self.dob(), "DATE_OF_BIRTH", "pack").t(", ")
        n.t(self.pick(MRN_LABELS)).rm(self.mrn(), "MRN", "pack").t("). ")
        n.t("History of ").keep(self.pick(EPONYMS), "EPONYM_DISEASE").t(" and ").keep(self.pick(CONDITIONS))
        n.t(". Seen on ").rm(self.visit_date(), "DATE", "safe_harbor").t(" with worsening symptoms. ")
        n.t("Please include current ").keep(self.pick(DRUGS)).t(" dose.")
        return n

    def discharge_summary(self):
        p = self.name(); street, city, st, z = self.address()
        n = Note("discharge_summary", ["summary"])
        n.t("Summarise this discharge note in plain language for the patient. ")
        n.t("Name: ").rm(p, "PERSON", "default", "patient").t(". ")
        n.t(self.pick(MRN_LABELS)).rm(self.mrn(), "MRN", "pack").t(". ")
        n.t("Admitted ").rm(self.visit_date(), "DATE", "safe_harbor").t(", discharged ").rm(self.visit_date(), "DATE", "safe_harbor").t(". ")
        n.t("Address: ").rm(street, "ADDRESS", "safe_harbor").t(", ").rm(city, "CITY", "safe_harbor").t(f", {st} ").rm(z, "ZIP", "safe_harbor").t(". ")
        n.t("Dx: ").keep(self.pick(["NSTEMI", "CHF exacerbation", "COPD exacerbation", "community-acquired pneumonia"]))
        n.t(". Peak ").keep("troponin").t(" ").keep(f"{self.r.randint(20, 900) / 100}", "LAB_VALUE").t(" ng/mL, ")
        n.t("started on ").keep(self.pick(DRUG_CLASSES)).t(" and ").keep(self.pick(DRUGS)).t(".")
        return n

    def portal_message(self):
        p = self.name(); ph = self.phone()
        n = Note("portal_message", ["patient-message"])
        n.t("Reply kindly to this patient message: 'Hi, this is ").rm(p, "PERSON", "default", "patient")
        n.t(". My ").keep("INR").t(" was ").keep(f"{self.r.randint(15, 45) / 10}", "LAB_VALUE").t(" yesterday and I take ")
        n.t("").keep("warfarin").t(". Should I change my dose? Call me at ").rm(ph, "PHONE", "default")
        n.t(" or email ").rm(self.email(p), "EMAIL", "default").t(".'")
        return n

    def insurance_appeal(self):
        p = self.name()
        n = Note("insurance_appeal", ["letter", "insurance"])
        n.t("Write a prior-authorization appeal for ").rm(p, "PERSON", "default", "patient").t(", ")
        n.t(self.pick(MEMBER_LABELS)).rm(self.member_id(), "HEALTH_PLAN_ID", "pack").t(", ")
        if self.r.random() < 0.75:
            n.t("Medicare MBI ").rm(self.mbi(), "MEDICARE_MBI", "pack").t(", ")
        n.t(self.pick(DOB_LABELS)).rm(self.dob(), "DATE_OF_BIRTH", "pack").t(". ")
        n.t("Requesting ").keep(self.pick(["semaglutide", "empagliflozin", "apixaban"])).t(" for ")
        n.keep(self.pick(CONDITIONS)).t("; ").keep("HbA1c").t(" ").keep(self.a1c(), "LAB_VALUE").t(" despite ")
        n.keep("metformin").t(".")
        return n

    def ed_triage(self):
        p = self.name(); age = self.r.randint(90, 101) if self.r.random() < 0.5 else self.r.randint(18, 89)
        n = Note("ed_triage", ["triage"])
        n.t("Triage: ").rm(p, "PERSON", "default", "patient").t(", ")
        if age > 89:
            n.rm(str(age), "AGE_90PLUS", "safe_harbor").t("-year-old")
        else:
            n.t(f"{age}-year-old")
        n.t(", presents with chest pain. BP ").keep(f"{self.r.randint(95, 190)}/{self.r.randint(55, 110)}", "LAB_VALUE")
        n.t(", HR ").keep(str(self.r.randint(48, 140)), "LAB_VALUE").t(", SpO2 ").keep(f"{self.r.randint(86, 100)}%", "LAB_VALUE")
        n.t(". Hx ").keep(self.pick(CONDITIONS)).t(", on ").keep(self.pick(DRUGS)).t(". ")
        n.t("SSN on file ").rm(self.pick(SSNS), "SSN", "default").t(". What is the most likely differential?")
        return n

    def lab_followup(self):
        p = self.name(); doc = self.clinician()
        n = Note("lab_followup", ["summary"])
        n.t("Explain these results to ").rm(p, "PERSON", "default", "patient")
        n.t(" (").t(self.pick(MRN_LABELS)).rm(self.mrn(), "MRN", "pack").t("): ")
        for lab in self.r.sample(LABS, 3):
            n.keep(lab).t(" ").keep(f"{self.r.randint(5, 999) / 10}", "LAB_VALUE").t(", ")
        n.t("ordered by Dr. ").rm(doc, "PERSON", "default", "clinician").t(".")
        return n

    def eponym_trap(self):
        # A patient whose SURNAME is also a disease eponym, plus that disease.
        # Protecting the bare surname would leak the patient; the disease form
        # must still survive.
        sur, disease = self.pick([("Parkinson", "Parkinson's disease"), ("Crohn", "Crohn's disease"),
                                  ("Addison", "Addison's disease"), ("Graves", "Graves' disease")])
        p = f"{self.pick(FIRST)} {sur}"
        n = Note("eponym_trap", ["trap", "eponym"])
        n.t("Patient ").rm(p, "PERSON", "default", "patient").t(" asks whether their ")
        n.keep(disease, "EPONYM_DISEASE").t(" affects ").keep(self.pick(DRUGS)).t(" dosing. ")
        n.t(self.pick(DOB_LABELS)).rm(self.dob(), "DATE_OF_BIRTH", "pack").t(".")
        return n

    def unlabeled_ids(self):
        # Identifiers written WITHOUT a label. The keyword-gated pack is NOT
        # expected to catch these: they measure the stated limit honestly.
        p = self.name()
        n = Note("unlabeled_ids", ["unlabeled", "limit"])
        n.rm(p, "PERSON", "default", "patient").t(" ").rm(self.mrn(), "MRN", "pack").t(" ")
        n.rm(self.dob(), "DATE_OF_BIRTH", "pack").t(" - ").keep(self.pick(CONDITIONS))
        n.t(", ").keep("eGFR").t(" ").keep(self.egfr(), "LAB_VALUE").t(". Summarise.")
        return n

    def family_history(self):
        p = self.name(); rel = self.name()
        n = Note("family_history", ["history"])
        n.t("Patient ").rm(p, "PERSON", "default", "patient").t(". Mother ").rm(rel, "PERSON", "default", "relative")
        n.t(" had ").keep(self.pick(EPONYMS), "EPONYM_DISEASE").t("; father had ").keep(self.pick(CONDITIONS))
        n.t(". Lives at ")
        street, city, st, z = self.address()
        n.rm(street, "ADDRESS", "safe_harbor").t(", ").rm(city, "CITY", "safe_harbor").t(f", {st} ").rm(z, "ZIP", "safe_harbor")
        n.t(". Is genetic testing indicated?")
        return n

    def numeric_only(self):
        # No identifiers at all: decimals, doses, vitals. Anything removed here
        # is over-removal of clinical data (the 0.12.7 class of bug).
        n = Note("numeric_only", ["numeric", "hard-negative"])
        n.t("Interpret: ").keep("creatinine").t(" ").keep(f"{self.r.randint(5, 40) / 10}", "LAB_VALUE")
        n.t(" mg/dL, ").keep("BNP").t(" ").keep(str(self.r.randint(40, 4000)), "LAB_VALUE")
        n.t(" pg/mL, weight ").keep(f"{self.r.randint(450, 1400) / 10} kg", "LAB_VALUE")
        n.t(", ").keep("LDL").t(" ").keep(f"{self.r.randint(400, 2200) / 10}", "LAB_VALUE")
        n.t(" mg/dL, order 2026091712. Dose ").keep(self.pick(DRUGS)).t(" ").keep(f"{self.pick([2.5, 5, 10, 20, 40])} mg", "LAB_VALUE").t(".")
        return n

    def clinic_chat(self):
        p = self.name(); doc = self.clinician(); ph = self.phone()
        n = Note("clinic_chat", ["prompt", "context-embedded"])
        n.t("Hi, quick one from clinic: ").rm(p, "PERSON", "default", "patient")
        n.t(" (").t(self.pick(DOB_LABELS)).rm(self.dob(), "DATE_OF_BIRTH", "pack").t(", cell ")
        n.rm(ph, "PHONE", "default").t(") on ").keep(self.pick(DRUG_CLASSES)).t(" developed ")
        n.keep(self.pick(["hyperkalemia", "angioedema", "a rash", "dizziness"])).t(". Dr. ")
        n.rm(doc, "PERSON", "default", "clinician").t(" wants alternatives. ")
        n.t(self.pick(MEMBER_LABELS)).rm(self.member_id(), "HEALTH_PLAN_ID", "pack").t(".")
        return n


TEMPLATES = ["ask_ai_medication", "referral_letter", "discharge_summary", "portal_message",
             "insurance_appeal", "ed_triage", "lab_followup", "eponym_trap", "unlabeled_ids",
             "family_history", "numeric_only", "clinic_chat"]


def main():
    g = Gen(SEED)
    notes = []
    for _ in range(N_PER_TEMPLATE):
        for name in TEMPLATES:
            notes.append(getattr(g, name)())
    samples = [n.build(i) for i, n in enumerate(notes)]
    for s in samples:  # offsets must reproduce the values exactly
        for e in s["entities"]:
            assert s["text"][e["start"]:e["end"]] == e["value"], (s["id"], e)
        assert all(ord(c) < 128 for c in s["text"]), s["id"]
    OUT.write_text(json.dumps({
        "about": "Synthetic clinical notes. Entirely fictitious. See _gen_clinical_corpus.py.",
        "seed": SEED,
        "samples": samples,
    }, indent=1, ensure_ascii=True) + "\n", encoding="utf-8")
    ents = [e for s in samples for e in s["entities"]]
    print(f"wrote {OUT.name}: {len(samples)} notes, "
          f"{sum(e['expect'] == 'remove' for e in ents)} identifiers to remove, "
          f"{sum(e['expect'] == 'keep' for e in ents)} clinical spans to keep")


if __name__ == "__main__":
    main()
