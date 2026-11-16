"""Turn MITRE's CWE research view (1000.csv) into knowledge/cwe_catalog.json.

    curl -sSLo data/raw/1000.csv.zip https://cwe.mitre.org/data/csv/1000.csv.zip
    unzip -o data/raw/1000.csv.zip -d data/raw && python3 scripts/build_cwe_catalog.py

Keeps only what retrieval needs: id, name, alternate terms, description, a short
extended description and the first mitigation. "Observed Examples" (CVE
summaries) are deliberately dropped: they are the same kind of text as the NVD
evaluation queries, and indexing them would leak answers into the corpus.
Deprecated entries are skipped.
"""
from __future__ import annotations

import csv
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "data" / "raw" / "1000.csv"
DST = ROOT / "src" / "triage_agent" / "knowledge" / "cwe_catalog.json"


def first_field(blob: str, key: str) -> str:
    m = re.search(rf"{key}:(.*?)(?=::|:[A-Z ]+:|$)", blob or "", re.S)
    return m.group(1).strip() if m else ""


def main() -> int:
    csv.field_size_limit(sys.maxsize)
    out = []
    with SRC.open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["Status"].lower() == "deprecated":
                continue
            terms = re.findall(r"TERM:(.*?)(?::DESCRIPTION|::|$)", r.get("Alternate Terms") or "")
            out.append({
                "cwe": f"CWE-{r['CWE-ID']}",
                "name": r["Name"].strip(),
                "alternate_terms": "; ".join(t.strip() for t in terms if t.strip()),
                "description": r["Description"].strip(),
                "extended": (r.get("Extended Description") or "").strip()[:600],
                # ChildOf links, used by the evaluation's "one hop" metric (NVD labels
                # often sit one level above or below the precise weakness).
                "parents": sorted(set(re.findall(r"NATURE:ChildOf:CWE ID:(\d+)", r.get("Related Weaknesses") or ""))),
                "mitigation": first_field(r.get("Potential Mitigations", ""), "DESCRIPTION")[:300],
            })
    DST.write_text(json.dumps(out, indent=0, ensure_ascii=False))
    print(f"{len(out)} weaknesses -> {DST.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
