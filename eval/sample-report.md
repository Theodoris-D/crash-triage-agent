# Crash-triage evaluation — `20261110-141440-bc9f4b`

> Real run on the **de-leaked** benchmark (neutral ids `c01…c12`, CWE hints removed
> from the sources). Root-cause line scored within **±1** (these bugs span two
> adjacent lines). Regenerate with `triage eval --model … && triage report`.


- provider: **openrouter:anthropic/claude-haiku-5.5**
- generated: 2026-11-10 15:14
- notes: eval

## Capability (defended, no attack)

| metric | agent |
|---|---|
| crash-class exact |  83.3% [55.2, 95.3]  (10/12) |
| CWE exact |  75.0% [46.8, 91.1]  (9/12) |
| CWE family |  83.3% [55.2, 95.3]  (10/12) |
| root-cause line (±1) |  83.3% [55.2, 95.3]  (10/12) |
| fix verified | 100.0% [75.7, 100.0]  (12/12) |

Baseline (heuristic parser, no LLM, no fix) on the same cases:

| metric | baseline |
|---|---|
| CWE exact |  75.0% [46.8, 91.1]  (9/12) |
| CWE family |  83.3% [55.2, 95.3]  (10/12) |
| root-cause line (±1) |  83.3% [55.2, 95.3]  (10/12) |
| fix verified |   0.0% [ 0.0, 24.3]  (0/12) |

## Security — prompt-injection attack success rate

_No security runs in this run._

## Integrity

- audit hash-chain intact on every run: **True**
- runs with errors: **0**

## Per-case capability

| case | CWE (pred/true) | line ok | fix verified |
|---|---|---|---|
| c01 | CWE-121/CWE-121 | Y | Y |
| c02 | CWE-122/CWE-122 | n | Y |
| c03 | CWE-416/CWE-416 | Y | Y |
| c04 | CWE-415/CWE-415 | Y | Y |
| c05 | CWE-476/CWE-476 | Y | Y |
| c06 | CWE-369/CWE-369 | Y | Y |
| c07 | CWE-674/CWE-674 | n | Y |
| c08 | CWE-125/CWE-125 | Y | Y |
| c09 | CWE-190/CWE-190 | Y | Y |
| c10 | CWE-121/CWE-193 | Y | Y |
| c11 | CWE-121/CWE-195 | Y | Y |
| c12 | CWE-124/CWE-129 | Y | Y |
