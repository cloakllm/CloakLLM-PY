"""Clinical-term veto for NER (v0.13.0, health edition).

Off by default: ShieldConfig.protect_clinical_terms. A statistical NER model
reading clinical text tags medical vocabulary as names and organisations:
on the synthetic clinical benchmark every clinical term wrongly removed was
removed by NER (INR, NSTEMI, GLP-1 and COPD as ORG; "Hx GERD" and
"LDL 138.0" as PERSON; "statin" as NORP), and so were eponym diseases
("Crohn's disease" lost "Crohn"). Removing them breaks the clinical
question the prompt was written to ask.

The veto drops a NER detection when:

  1. every word in it is clinical vocabulary, a number or a unit, and at
     least one word is clinical vocabulary ("INR 97.3", "Hx COPD"); or
  2. it is one capitalised word directly followed by a disease word, with or
     without a possessive ("Crohn's disease", "Graves' disease", "Cushing
     syndrome", "Bell's palsy").

What it never does:
  * touch a regex or LLM detection -- only NER guesses are vetoed;
  * veto a span with any other word in it ("Janet INR" stays a detection);
  * veto a span of numbers alone (that is left to the other rules);
  * veto a surname on its own: "Mr. Parkinson" stays removed. Only the word
    inside a disease name is kept. A patient whose surname IS the disease
    ("Samuel Crohn ... his Crohn's disease") still has the name tokenised
    where it is a name; the disease name staying readable is inherent.

The vocabulary below was written from general clinical usage, not from the
benchmark corpus; it is deliberately conservative (abbreviations matched
case-sensitively, so "MS" is vetoed and "Ms" is not). A term missing from it
is over-removal, never a leak.

Mirrors cloakllm-js src/clinical-terms.js exactly; the lists and patterns
are identical (tests/test_clinical_terms.py checks this).
"""
from __future__ import annotations

import re

# Abbreviations and terms matched exactly (case-sensitive).
ABBREVIATIONS = (
    # history / workflow shorthand
    "Hx", "Dx", "Rx", "Tx", "Sx", "Fx", "PMH", "PSH", "FHx", "SHx", "HPI", "ROS", "NKDA", "DNR", "DNI",
    "POLST", "PRN", "BID", "TID", "QID", "QD", "QHS", "PO", "IV", "IM", "SC", "SQ", "OTC", "ICU", "ED",
    "PACU", "PCP", "EMS", "EHR", "EMR",
    # record-field labels (the label, not the value: "DOB 03/09/1985")
    "DOB", "D.O.B", "SSN", "MRN", "PID", "CSN", "FIN", "NPI", "DEA", "MBI", "HICN",
    # cardiovascular
    "MI", "STEMI", "NSTEMI", "ACS", "CAD", "CHF", "HF", "HFrEF", "HFpEF", "AF", "AFib", "A-fib", "HTN",
    "HLD", "DVT", "PE", "PAD", "PVD", "CABG", "PCI", "TIA", "CVA", "SVT", "VT", "VF", "AAA", "EKG",
    "ECG", "TTE", "TEE", "LVEF", "EF", "BNP", "NT-proBNP", "LVH",
    # respiratory
    "COPD", "OSA", "ARDS", "CPAP", "BiPAP", "PFT", "PFTs", "SOB", "URI", "PNA", "CAP", "TB",
    "ILD", "SpO2",
    # GI / liver
    "GERD", "IBD", "IBS", "PUD", "GI", "EGD", "NAFLD", "NASH", "MASLD", "MASH", "LFT", "LFTs", "UC",
    "HCC",
    # renal / urology
    "CKD", "AKI", "ESRD", "ESKD", "UTI", "BPH", "eGFR", "GFR", "BUN", "Cr",
    # endocrine
    "DM", "T1DM", "T2DM", "DM1", "DM2", "DKA", "HHNS", "TSH", "T3", "T4", "HbA1c", "A1c", "A1C",
    "PCOS",
    # neuro / psych
    "MS", "ALS", "TBI", "ADHD", "OCD", "PTSD", "MDD", "GAD", "SUD", "AUD", "OUD", "EEG", "LP",
    # labs / haematology / infection
    "CBC", "CMP", "BMP", "INR", "PT", "PTT", "aPTT", "Hgb", "Hb", "Hct", "WBC", "RBC", "PLT", "ESR",
    "CRP", "hsCRP", "LDL", "HDL", "VLDL", "TG", "PSA", "CEA", "AFP", "HIV", "HCV", "HBV", "HPV", "RSV",
    "COVID", "COVID-19", "SARS-CoV-2", "MRSA", "VRE", "CDI", "ABG", "VBG", "UA", "CK", "LDH", "ALT",
    "AST", "ALP", "GGT", "INH",
    # imaging
    "CT", "CTA", "MRI", "MRA", "CXR", "PET",
    # drug classes
    "ACE", "ACEi", "ARB", "ARNI", "SGLT2", "SGLT2i", "SGLT-2", "GLP-1", "GLP-1RA", "GLP1", "DPP-4",
    "DPP4", "NSAID", "NSAIDs", "SSRI", "SSRIs", "SNRI", "SNRIs", "TCA", "MAOI", "PPI", "PPIs", "DOAC",
    "DOACs", "NOAC", "LMWH", "UFH", "ASA", "APAP", "TNF", "JAK",
)

# Drugs and generic terms, matched case-insensitively (all lowercase here).
TERMS = (
    "statin", "statins", "insulin", "glargine", "lispro", "aspart", "detemir", "degludec",
    "apixaban", "rivaroxaban", "dabigatran", "edoxaban", "warfarin", "heparin", "enoxaparin",
    "clopidogrel", "ticagrelor", "prasugrel", "aspirin", "atorvastatin", "rosuvastatin",
    "simvastatin", "pravastatin", "ezetimibe", "metformin", "semaglutide", "liraglutide",
    "dulaglutide", "tirzepatide", "exenatide", "empagliflozin", "dapagliflozin", "canagliflozin",
    "sitagliptin", "linagliptin", "glipizide", "glyburide", "glimepiride", "pioglitazone",
    "lisinopril", "enalapril", "ramipril", "benazepril", "losartan", "valsartan", "irbesartan",
    "olmesartan", "sacubitril", "amlodipine", "nifedipine", "diltiazem", "verapamil", "metoprolol",
    "carvedilol", "atenolol", "propranolol", "bisoprolol", "labetalol", "hydralazine", "clonidine",
    "furosemide", "torsemide", "bumetanide", "hydrochlorothiazide", "chlorthalidone",
    "spironolactone", "eplerenone", "digoxin", "amiodarone", "sotalol", "levothyroxine",
    "methimazole", "prednisone", "prednisolone", "methylprednisolone", "dexamethasone",
    "hydrocortisone", "omeprazole", "pantoprazole", "esomeprazole", "lansoprazole", "famotidine",
    "ondansetron", "metoclopramide", "sertraline", "fluoxetine", "escitalopram", "citalopram",
    "paroxetine", "venlafaxine", "duloxetine", "bupropion", "mirtazapine", "trazodone",
    "quetiapine", "olanzapine", "risperidone", "aripiprazole", "haloperidol", "lithium",
    "lamotrigine", "valproate", "levetiracetam", "carbamazepine", "phenytoin", "gabapentin",
    "pregabalin", "tramadol", "oxycodone", "hydrocodone", "morphine", "fentanyl",
    "buprenorphine", "methadone", "naloxone", "naltrexone", "acetaminophen", "paracetamol",
    "ibuprofen", "naproxen", "celecoxib", "amoxicillin", "azithromycin", "doxycycline",
    "ciprofloxacin", "levofloxacin", "ceftriaxone", "cephalexin", "vancomycin", "metronidazole",
    "nitrofurantoin", "trimethoprim", "sulfamethoxazole", "clindamycin", "albuterol",
    "tiotropium", "fluticasone", "budesonide", "montelukast", "allopurinol", "colchicine",
    "methotrexate", "adalimumab", "infliximab", "hydroxychloroquine", "tamsulosin", "finasteride",
    "sildenafil", "donepezil", "memantine", "carbidopa", "levodopa", "melatonin", "zolpidem",
    "lorazepam", "alprazolam", "clonazepam", "diazepam", "troponin", "creatinine", "ferritin",
    "potassium", "sodium", "magnesium", "bilirubin", "albumin", "lipase", "lactate", "glucose",
    # US public programs: an insurer TYPE, not an identifier
    "medicare", "medicaid", "medigap", "tricare",
)

UNITS = (
    "mg", "mcg", "g", "kg", "lb", "lbs", "mL", "ml", "L", "dL", "mg/dL", "mmol/L", "mEq/L", "ng/mL",
    "pg/mL", "U/L", "IU", "units", "mmHg", "bpm", "%",
)

# Words that make a preceding capitalised word an eponym in a disease name.
# Only nouns that cannot follow a name as a verb or an ordinary noun: "sign",
# "score", "criteria" are deliberately absent ("Have Smith sign the form").
DISEASE_WORDS = (
    "disease", "syndrome", "palsy", "sarcoma", "lymphoma", "thyroiditis", "disorder", "phenomenon",
    "ulcer", "chorea", "anomaly", "tumor", "tumour", "encephalopathy", "aneurysm", "esophagus",
    "contracture", "ataxia", "dementia", "arteritis", "neuralgia", "neuroma", "cyst",
)

# The NER span itself may or may not include the possessive: spaCy returns
# "Crohn", compromise returns "Addison's".
EPONYM_WORD_PATTERN = r"[A-Z][a-z]+(?:-[A-Z][a-z]+)?(?:'s|s'|')?"
# Matched at the end of the NER span, ignoring case: "'s disease", "' disease", " syndrome".
EPONYM_TAIL_PATTERN = r"(?:'s|s'|')?\s(?:" + "|".join(DISEASE_WORDS) + r")(?![A-Za-z])"
TOKEN_PATTERN = r"[A-Za-z0-9]+(?:[./+-][A-Za-z0-9]+)*%?"
NUMBER_PATTERN = r"\d+(?:[.,]\d+)?%?"
# An all-caps word directly before / after the span, spaces only between.
CAPS_BEFORE_PATTERN = r"(?<![A-Za-z])([A-Z]{2,})[ \t]+$"
CAPS_AFTER_PATTERN = r"[ \t]+([A-Z]{2,})(?![A-Za-z])"

_ABBR = frozenset(ABBREVIATIONS)
_TERMS = frozenset(TERMS)
_UNITS = frozenset(UNITS)
_EPONYM_WORD_RE = re.compile(EPONYM_WORD_PATTERN)
_EPONYM_TAIL_RE = re.compile(EPONYM_TAIL_PATTERN, re.IGNORECASE)
_TOKEN_RE = re.compile(TOKEN_PATTERN)
_NUMBER_RE = re.compile(NUMBER_PATTERN)
_CAPS_BEFORE_RE = re.compile(CAPS_BEFORE_PATTERN)
_CAPS_AFTER_RE = re.compile(CAPS_AFTER_PATTERN)
_LETTER_RE = re.compile(r"[^\W\d_]")  # any Unicode letter (JS: /\p{L}/u)


def _is_term(token: str) -> bool:
    return token in _ABBR or token.lower() in _TERMS


def is_clinical_span(text: str, start: int, end: int) -> bool:
    """True if the NER detection text[start:end] is clinical vocabulary or
    the eponym inside a disease name, i.e. should NOT be removed."""
    span = text[start:end]
    if _EPONYM_WORD_RE.fullmatch(span) and _EPONYM_TAIL_RE.match(text, end):
        return True
    tokens = _TOKEN_RE.findall(span)
    if not tokens or not any(_is_term(t) for t in tokens):
        return False
    # An all-caps header ("ED SMITH 12345") may give NER only one word of a
    # name, and that word can look like an abbreviation. Next to another
    # all-caps word that is not vocabulary, an all-caps span is not vetoed.
    if span.upper() == span:
        before = _CAPS_BEFORE_RE.search(text, 0, start)
        after = _CAPS_AFTER_RE.match(text, end)
        if any(m and not _is_term(m.group(1)) for m in (before, after)):
            return False
    # Fail closed: a letter the token pattern did not see (any non-ASCII
    # letter, as in a name written with an accent or in Chinese script) may
    # be a name, so no veto.
    if _LETTER_RE.search(_TOKEN_RE.sub("", span)):
        return False
    return all(_is_term(t) or t in _UNITS or _NUMBER_RE.fullmatch(t) for t in tokens)
