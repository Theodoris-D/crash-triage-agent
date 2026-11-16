"""CWE retrieval backends for the `cwe_lookup` tool.

Three retrievers share one interface, `search(query, k) -> list[(cwe_id, score)]`:

  * KeywordRetriever -- token overlap plus id/name boosts. The original tool; no
    dependencies, used by CI and as the fallback.
  * BM25Retriever    -- Okapi BM25 over the same documents. The strong lexical
    baseline a dense retriever has to beat to be worth its dependencies.
  * DenseRetriever   -- a Hugging Face sentence-embedding model (sentence-
    transformers) with the vectors stored in a persistent ChromaDB collection.

Documents come from two trusted sources: the 18-entry hand-written knowledge base
(knowledge/cwe.json, with curated summaries and fix hints) and the full MITRE CWE
catalogue (research view 1000, ~950 weaknesses; knowledge/cwe_catalog.json, built
by scripts/build_cwe_catalog.py). Neither is case-controlled text, so the tool
output stays trusted.
"""
from __future__ import annotations

import json
import math
import pathlib
import re
from collections import Counter
from dataclasses import dataclass

_TOKEN = re.compile(r"[a-z0-9]+")
_CWE_ID = re.compile(r"\bcwe[-_ ]?(\d+)\b", re.I)


def tokenize(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


@dataclass
class CweDoc:
    cwe: str            # "CWE-121"
    name: str
    text: str           # what gets indexed
    summary: str        # what the tool shows
    fix_hint: str


def load_curated(path: pathlib.Path) -> list[CweDoc]:
    docs = []
    for e in json.loads(path.read_text()):
        text = " ".join([e["name"], " ".join(e["aliases"]), " ".join(e["keywords"]), e["summary"]])
        docs.append(CweDoc(e["cwe"], e["name"], text, e["summary"], e["fix_hint"]))
    return docs


def load_catalog(path: pathlib.Path) -> list[CweDoc]:
    docs = []
    for e in json.loads(path.read_text()):
        text = " ".join(x for x in [e["name"], e.get("alternate_terms", ""),
                                     e["description"], e.get("extended", "")] if x)
        docs.append(CweDoc(e["cwe"], e["name"], text, e["description"], e.get("mitigation", "")))
    return docs


class KeywordRetriever:
    """Token overlap; a literal CWE id or name in the query is a strong signal."""

    def __init__(self, docs: list[CweDoc]):
        self.docs = docs
        self._toks = [set(tokenize(d.text)) for d in docs]

    def search(self, query: str, k: int = 3) -> list[tuple[str, float]]:
        q = set(tokenize(query))
        ql = query.lower()
        scored = []
        for d, toks in zip(self.docs, self._toks):
            s = len(q & toks)
            if d.cwe.lower() in ql:
                s += 10
            if d.name.lower() in ql:
                s += 5
            if s:
                scored.append((d.cwe, float(s)))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:k]


class BM25Retriever:
    def __init__(self, docs: list[CweDoc]):
        from rank_bm25 import BM25Okapi
        self.docs = docs
        self._bm25 = BM25Okapi([tokenize(d.text) for d in docs])

    def search(self, query: str, k: int = 3) -> list[tuple[str, float]]:
        scores = self._bm25.get_scores(tokenize(query))
        order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:k]
        return [(self.docs[i].cwe, float(scores[i])) for i in order]


class DenseRetriever:
    """Sentence embeddings (Hugging Face) + ChromaDB cosine search.

    The collection is keyed by model and corpus size, and rebuilt when either
    changes, so a stale index cannot silently answer with old vectors.
    """

    def __init__(self, docs: list[CweDoc], model_name: str = "BAAI/bge-small-en-v1.5",
                 persist_dir: pathlib.Path | None = None, query_prefix: str | None = None):
        from sentence_transformers import SentenceTransformer
        import chromadb

        self.docs = docs
        self.model_name = model_name
        self._model = SentenceTransformer(model_name, device="cpu")
        # BGE v1.5 models expect this instruction on short retrieval queries.
        if query_prefix is None:
            query_prefix = ("Represent this sentence for searching relevant passages: "
                            if "bge" in model_name.lower() else "")
        self._qp = query_prefix
        client = (chromadb.PersistentClient(path=str(persist_dir)) if persist_dir
                  else chromadb.EphemeralClient())
        name = re.sub(r"[^a-zA-Z0-9_-]", "_", f"cwe_{model_name}_{len(docs)}")[:60]
        self._col = client.get_or_create_collection(name, metadata={"hnsw:space": "cosine"})
        if self._col.count() != len(docs):
            if self._col.count():
                client.delete_collection(name)
                self._col = client.create_collection(name, metadata={"hnsw:space": "cosine"})
            vecs = self._model.encode([d.text for d in docs], batch_size=32,
                                      normalize_embeddings=True, show_progress_bar=False)
            self._col.add(ids=[f"{i}" for i in range(len(docs))],
                          embeddings=vecs.tolist(),
                          metadatas=[{"cwe": d.cwe} for d in docs])

    def search(self, query: str, k: int = 3) -> list[tuple[str, float]]:
        v = self._model.encode([self._qp + query], normalize_embeddings=True)
        res = self._col.query(query_embeddings=v.tolist(), n_results=k)
        return [(m["cwe"], 1.0 - dist) for m, dist in zip(res["metadatas"][0], res["distances"][0])]


class HybridRetriever:
    """Reciprocal-rank fusion of a lexical and a dense ranking (k=60, standard RRF)."""

    def __init__(self, lexical, dense, depth: int = 20, k_rrf: int = 60):
        self.lexical, self.dense, self.depth, self.k_rrf = lexical, dense, depth, k_rrf

    def search(self, query: str, k: int = 3) -> list[tuple[str, float]]:
        fused: dict[str, float] = {}
        for ranking in (self.lexical.search(query, self.depth), self.dense.search(query, self.depth)):
            for rank, (cwe, _) in enumerate(ranking):
                fused[cwe] = fused.get(cwe, 0.0) + 1.0 / (self.k_rrf + rank + 1)
        return sorted(fused.items(), key=lambda x: x[1], reverse=True)[:k]


class RerankRetriever:
    """Retrieve `depth` candidates, then rescore (query, document) pairs with a
    Hugging Face cross-encoder, which reads both texts together instead of
    comparing two independent embeddings."""

    def __init__(self, first_stage, docs: list[CweDoc], model_name: str = "BAAI/bge-reranker-base",
                 depth: int = 30):
        from sentence_transformers import CrossEncoder
        self.first, self.depth = first_stage, depth
        self._text = {d.cwe: d.text[:1500] for d in docs}
        self._ce = CrossEncoder(model_name, device="cpu")

    def search(self, query: str, k: int = 3) -> list[tuple[str, float]]:
        cands = [c for c, _ in self.first.search(query, self.depth)]
        if not cands:
            return []
        scores = self._ce.predict([(query, self._text[c]) for c in cands], show_progress_bar=False)
        ranked = sorted(zip(cands, scores), key=lambda x: x[1], reverse=True)
        return [(c, float(s)) for c, s in ranked[:k]]


def mcnemar_p(a_only: int, b_only: int) -> float:
    """Exact two-sided McNemar test on discordant pairs (paired comparison)."""
    n = a_only + b_only
    if n == 0:
        return 1.0
    m = min(a_only, b_only)
    tail = sum(math.comb(n, i) for i in range(m + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def strip_cwe_ids(text: str) -> str:
    """Remove literal CWE ids so an evaluation query cannot carry its label."""
    return _CWE_ID.sub("", text)


def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (max(0.0, centre - half), min(1.0, centre + half))
