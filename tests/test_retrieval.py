"""Retrieval layer: the keyword backend must keep the old tool's behaviour, and the
evaluation helpers must be correct. Dense tests run only when the optional `rag`
dependencies and the model are available (they are skipped in offline CI)."""
import os

import pytest

from triage_agent import retrieval as R, tools_impl
from triage_agent.config import KNOWLEDGE_DIR


def test_keyword_ranks_stack_overflow_first():
    docs = R.load_curated(KNOWLEDGE_DIR / "cwe.json")
    hits = R.KeywordRetriever(docs).search("strcpy overflows a local char buf on the stack", 3)
    assert hits[0][0] == "CWE-121"


def test_cwe_lookup_default_backend_is_keyword_and_trusted(monkeypatch):
    monkeypatch.delenv("TRIAGE_CWE_RETRIEVER", raising=False)
    tools_impl._RETRIEVER = None
    out = tools_impl.cwe_lookup("use after free of a heap pointer")
    assert isinstance(tools_impl._RETRIEVER, R.KeywordRetriever)
    assert out.text.splitlines()[0].startswith("CWE-416")
    assert out.untrusted is False


def test_strip_cwe_ids_removes_labels():
    assert "121" not in R.strip_cwe_ids("classic CWE-121 and cwe 787 bug")


def test_wilson_matches_reported_interval():
    lo, hi = R.wilson(9, 12)
    assert round(100 * lo, 1) == 46.8 and round(100 * hi, 1) == 91.1


def test_mcnemar_exact():
    assert R.mcnemar_p(0, 0) == 1.0
    assert R.mcnemar_p(6, 0) == pytest.approx(2 / 64)


@pytest.mark.skipif(not os.environ.get("TRIAGE_TEST_DENSE"), reason="set TRIAGE_TEST_DENSE=1 (needs rag extras + model)")
def test_dense_retriever_finds_double_free():
    docs = R.load_curated(KNOWLEDGE_DIR / "cwe.json")
    dense = R.DenseRetriever(docs, "BAAI/bge-small-en-v1.5")
    assert dense.search("the same pointer is released twice on an error path", 3)[0][0] == "CWE-415"
