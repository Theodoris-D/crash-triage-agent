"""Offline evaluation of the cwe_lookup retrievers (no LLM, no API cost).

Question: given a natural-language description of a memory-safety bug, does the
retriever put the right CWE first (top-1) or among the three entries the agent
sees (top-3)?

Two query sets, both with every literal "CWE-123" stripped:
  * nvd   -- real CVE descriptions from the NVD API, one per CVE, kept only when
             NVD gives a single CWE label (data/nvd_queries.json, 15 CWEs).
  * agent -- the root-cause explanations the agent itself wrote in the two real
             Haiku 5.5 runs on the 12-case benchmark (eval/results.db), labelled
             with the benchmark's ground-truth CWE.

Two corpora: the 18 hand-written entries the tool used so far, and the full
MITRE catalogue (956 weaknesses). Retrievers: keyword (the old tool), BM25,
and dense Hugging Face embedding models stored in ChromaDB.

    PYTHONPATH=src .venv/bin/python eval/retrieval_eval.py   # writes eval/retrieval_report.md
"""
from __future__ import annotations

import json
import pathlib
import sqlite3
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from triage_agent import retrieval as R  # noqa: E402

KB = ROOT / "src" / "triage_agent" / "knowledge"
AGENT_RUNS = ["20261110-141440-bc9f4b", "20261115-214207-6c443d"]
DENSE_MODELS = ["sentence-transformers/all-MiniLM-L6-v2", "BAAI/bge-small-en-v1.5",
                "BAAI/bge-base-en-v1.5"]


def load_queries() -> dict[str, list[tuple[str, str]]]:
    nvd = [(R.strip_cwe_ids(q["text"]), q["cwe"])
           for q in json.loads((ROOT / "data" / "nvd_queries.json").read_text())]
    # results.db is not committed, so the agent's explanations are exported once to
    # data/agent_queries.json (with their ground truth) and read from there.
    aq = ROOT / "data" / "agent_queries.json"
    if not aq.exists():
        truth = {c["id"]: c["cwe"] for c in json.loads((ROOT / "benchmark" / "manifest.json").read_text())}
        con = sqlite3.connect(ROOT / "eval" / "results.db")
        rows = con.execute(
            f"SELECT run_id, case_id, report_json FROM results WHERE kind='capability' AND error IS NULL "
            f"AND run_id IN ({','.join('?' * len(AGENT_RUNS))}) ORDER BY run_id, case_id", AGENT_RUNS).fetchall()
        export = [{"run_id": r, "case_id": c, "cwe": truth[c],
                   "text": R.strip_cwe_ids((json.loads(rj or "{}").get("explanation") or "").strip())}
                  for r, c, rj in rows]
        aq.write_text(json.dumps([e for e in export if e["text"]], indent=1))
    agent = [(e["text"], e["cwe"]) for e in json.loads(aq.read_text())]
    return {"nvd": nvd, "agent": agent}


def related(catalog: list[dict]) -> dict[str, set[str]]:
    """CWE -> itself plus its ChildOf parents and children (one hop)."""
    rel: dict[str, set[str]] = {e["cwe"]: {e["cwe"]} for e in catalog}
    for e in catalog:
        for p in e["parents"]:
            pid = f"CWE-{p}"
            rel[e["cwe"]].add(pid)
            rel.setdefault(pid, {pid}).add(e["cwe"])
    return rel


def score(retriever, queries, rel) -> dict:
    top1 = top3 = hop1 = 0
    vec = []
    t0 = time.perf_counter()
    for text, gold in queries:
        hits = [c for c, _ in retriever.search(text, k=3)]
        ok = bool(hits) and hits[0] == gold
        vec.append(ok)
        top1 += ok
        top3 += gold in hits
        hop1 += bool(hits) and hits[0] in rel.get(gold, {gold})
    ms = (time.perf_counter() - t0) * 1000 / max(1, len(queries))
    return {"n": len(queries), "top1": top1, "top3": top3, "hop1": hop1, "ms": ms, "vec": vec}


def fmt(k: int, n: int) -> str:
    lo, hi = R.wilson(k, n)
    return f"{100 * k / n:.0f}% [{100 * lo:.0f}-{100 * hi:.0f}]"


def main() -> int:
    queries = load_queries()
    catalog_raw = json.loads((KB / "cwe_catalog.json").read_text())
    rel = related(catalog_raw)
    corpora = {"curated-18": R.load_curated(KB / "cwe.json"),
               "mitre-956": R.load_catalog(KB / "cwe_catalog.json")}
    index_dir = ROOT / "data" / "chroma"

    rows = []
    for cname, docs in corpora.items():
        builders = [("keyword", lambda d=docs: R.KeywordRetriever(d)),
                    ("BM25", lambda d=docs: R.BM25Retriever(d))]
        builders += [(m.split("/")[-1], lambda d=docs, m=m: R.DenseRetriever(d, m, index_dir))
                     for m in DENSE_MODELS]
        builders += [
            ("hybrid BM25+bge-small (RRF)", lambda d=docs: R.HybridRetriever(
                R.BM25Retriever(d), R.DenseRetriever(d, "BAAI/bge-small-en-v1.5", index_dir))),
            ("bge-small top-30 + bge-reranker-base", lambda d=docs: R.RerankRetriever(
                R.DenseRetriever(d, "BAAI/bge-small-en-v1.5", index_dir), d)),
        ]
        for rname, build in builders:
            t0 = time.perf_counter()
            ret = build()
            build_s = time.perf_counter() - t0
            for qname, qs in queries.items():
                rows.append((cname, rname, qname, score(ret, qs, rel), build_s))
                print(cname, rname, qname, {k: v for k, v in rows[-1][3].items() if k != "vec"}, file=sys.stderr)

    out = ["# CWE retrieval evaluation", "",
           "Offline, no LLM. Top-1 / top-3: the gold CWE is the first / among the three "
           "entries `cwe_lookup` returns. One-hop: the first entry is the gold CWE or its "
           "direct ChildOf parent or child in MITRE's research view (NVD labels often sit "
           "one level off, e.g. CWE-787 for a heap overflow). 95% Wilson intervals in brackets. "
           "Literal CWE ids are stripped from every query. The old tool is keyword retrieval "
           "over the 18 curated entries; the paired column counts queries a retriever gets "
           "right that the old tool misses (+) and the reverse (-), with an exact McNemar test.", "",
           f"Query sets: nvd = {len(queries['nvd'])} single-label NVD CVE descriptions over "
           f"15 CWEs; agent = {len(queries['agent'])} root-cause explanations the agent wrote "
           "in two real Haiku 5.5 runs on the 12-case benchmark.", ""]
    for qname in queries:
        out += [f"## Query set: {qname}", "",
                "| corpus | retriever | top-1 | top-3 | one-hop top-1 | top-1 vs old tool (+wins / -losses, McNemar p) | ms/query |",
                "|---|---|---|---|---|---|---|"]
        ref = next(s["vec"] for c, r, q, s, _ in rows if (c, r, q) == ("curated-18", "keyword", qname))
        for cname, rname, qn, s, _ in rows:
            if qn == qname:
                w = sum(a and not b for a, b in zip(s["vec"], ref))
                l = sum(b and not a for a, b in zip(s["vec"], ref))
                cmp = "reference" if (cname, rname) == ("curated-18", "keyword") else \
                    f"+{w} / -{l}, p={R.mcnemar_p(w, l):.3f}"
                out.append(f"| {cname} | {rname} | {fmt(s['top1'], s['n'])} | "
                           f"{fmt(s['top3'], s['n'])} | {fmt(s['hop1'], s['n'])} | {cmp} | {s['ms']:.1f} |")
        out.append("")
    (ROOT / "eval" / "retrieval_report.md").write_text("\n".join(out))
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
