# CWE retrieval evaluation

Offline, no LLM. Top-1 / top-3: the gold CWE is the first / among the three entries `cwe_lookup` returns. One-hop: the first entry is the gold CWE or its direct ChildOf parent or child in MITRE's research view (NVD labels often sit one level off, e.g. CWE-787 for a heap overflow). 95% Wilson intervals in brackets. Literal CWE ids are stripped from every query. The old tool is keyword retrieval over the 18 curated entries; the paired column counts queries a retriever gets right that the old tool misses (+) and the reverse (-), with an exact McNemar test.

Query sets: nvd = 288 single-label NVD CVE descriptions over 15 CWEs; agent = 24 root-cause explanations the agent wrote in two real Haiku 5.5 runs on the 12-case benchmark.

## Query set: nvd

| corpus | retriever | top-1 | top-3 | one-hop top-1 | top-1 vs old tool (+wins / -losses, McNemar p) | ms/query |
|---|---|---|---|---|---|---|
| curated-18 | keyword | 52% [47-58] | 73% [68-78] | 60% [55-66] | reference | 0.0 |
| curated-18 | BM25 | 50% [45-56] | 74% [69-79] | 56% [50-61] | +39 / -45, p=0.586 | 0.2 |
| curated-18 | all-MiniLM-L6-v2 | 52% [47-58] | 72% [67-77] | 60% [54-65] | +48 / -48, p=1.000 | 10.3 |
| curated-18 | bge-small-en-v1.5 | 58% [52-63] | 76% [71-81] | 66% [61-72] | +53 / -38, p=0.142 | 18.6 |
| curated-18 | bge-base-en-v1.5 | 58% [52-64] | 81% [76-85] | 64% [58-69] | +54 / -38, p=0.117 | 50.8 |
| curated-18 | hybrid BM25+bge-small (RRF) | 61% [55-66] | 82% [77-86] | 67% [61-72] | +48 / -24, p=0.006 | 18.4 |
| curated-18 | bge-small top-30 + bge-reranker-base | 75% [69-79] | 93% [89-95] | 82% [77-86] | +79 / -15, p=0.000 | 875.0 |
| mitre-956 | keyword | 14% [11-19] | 22% [17-27] | 18% [14-23] | +0 / -110, p=0.000 | 1.4 |
| mitre-956 | BM25 | 33% [27-38] | 50% [44-56] | 38% [33-44] | +28 / -85, p=0.000 | 4.1 |
| mitre-956 | all-MiniLM-L6-v2 | 11% [8-15] | 20% [16-25] | 15% [11-20] | +10 / -129, p=0.000 | 10.6 |
| mitre-956 | bge-small-en-v1.5 | 18% [14-23] | 26% [21-31] | 27% [23-33] | +17 / -115, p=0.000 | 22.5 |
| mitre-956 | bge-base-en-v1.5 | 18% [14-23] | 26% [22-32] | 23% [18-28] | +13 / -111, p=0.000 | 55.4 |
| mitre-956 | hybrid BM25+bge-small (RRF) | 28% [24-34] | 44% [39-50] | 38% [32-43] | +20 / -89, p=0.000 | 22.7 |
| mitre-956 | bge-small top-30 + bge-reranker-base | 22% [18-27] | 33% [28-39] | 31% [26-37] | +14 / -101, p=0.000 | 2953.8 |

## Query set: agent

| corpus | retriever | top-1 | top-3 | one-hop top-1 | top-1 vs old tool (+wins / -losses, McNemar p) | ms/query |
|---|---|---|---|---|---|---|
| curated-18 | keyword | 71% [51-85] | 88% [69-96] | 71% [51-85] | reference | 0.0 |
| curated-18 | BM25 | 92% [74-98] | 96% [80-99] | 92% [74-98] | +6 / -1, p=0.125 | 0.6 |
| curated-18 | all-MiniLM-L6-v2 | 67% [47-82] | 83% [64-93] | 67% [47-82] | +3 / -4, p=1.000 | 16.4 |
| curated-18 | bge-small-en-v1.5 | 92% [74-98] | 100% [86-100] | 92% [74-98] | +6 / -1, p=0.125 | 30.4 |
| curated-18 | bge-base-en-v1.5 | 92% [74-98] | 96% [80-99] | 92% [74-98] | +6 / -1, p=0.125 | 80.3 |
| curated-18 | hybrid BM25+bge-small (RRF) | 96% [80-99] | 100% [86-100] | 96% [80-99] | +6 / -0, p=0.031 | 31.6 |
| curated-18 | bge-small top-30 + bge-reranker-base | 25% [12-45] | 50% [31-69] | 25% [12-45] | +0 / -11, p=0.001 | 1659.2 |
| mitre-956 | keyword | 4% [1-20] | 4% [1-20] | 4% [1-20] | +0 / -16, p=0.000 | 1.9 |
| mitre-956 | BM25 | 4% [1-20] | 50% [31-69] | 4% [1-20] | +1 / -17, p=0.000 | 10.1 |
| mitre-956 | all-MiniLM-L6-v2 | 17% [7-36] | 25% [12-45] | 25% [12-45] | +1 / -14, p=0.001 | 17.2 |
| mitre-956 | bge-small-en-v1.5 | 21% [9-40] | 38% [21-57] | 33% [18-53] | +0 / -12, p=0.000 | 34.5 |
| mitre-956 | bge-base-en-v1.5 | 29% [15-49] | 42% [24-61] | 42% [24-61] | +1 / -11, p=0.006 | 85.7 |
| mitre-956 | hybrid BM25+bge-small (RRF) | 29% [15-49] | 67% [47-82] | 29% [15-49] | +2 / -12, p=0.013 | 41.5 |
| mitre-956 | bge-small top-30 + bge-reranker-base | 21% [9-40] | 38% [21-57] | 25% [12-45] | +0 / -12, p=0.000 | 4490.9 |
