# Crash-triage evaluation — `20261110-124206-effbf7`

- provider: **openrouter:anthropic/claude-haiku-5.5**
- generated: 2026-11-10 12:42
- notes: haiku docker

_This is a committed sample of a real run (12-case benchmark, capability-only,
run inside the Docker image so ASan/GDB are available). Regenerate your own with
`make eval report` or the Docker command in the README._

## Capability (defended, no attack)

| metric | agent |
|---|---|
| crash-class exact |  83.3% [55.2, 95.3]  (10/12) |
| CWE exact | 100.0% [75.7, 100.0]  (12/12) |
| CWE family | 100.0% [75.7, 100.0]  (12/12) |
| root-cause line |  83.3% [55.2, 95.3]  (10/12) |
| fix verified |  83.3% [55.2, 95.3]  (10/12) |

Baseline (heuristic parser, no LLM, no fix) on the same cases:

| metric | baseline |
|---|---|
| CWE exact |  75.0% [46.8, 91.1]  (9/12) |
| CWE family |  83.3% [55.2, 95.3]  (10/12) |
| root-cause line |  75.0% [46.8, 91.1]  (9/12) |
| fix verified |   0.0% [ 0.0, 24.3]  (0/12) |

## Integrity

- audit hash-chain intact on every run: **True**
- runs with errors: **0**

## Per-case capability

| case | CWE (pred/true) | line ok | fix verified |
|---|---|---|---|
| c01_stack_buffer_overflow | CWE-121/CWE-121 | Y | Y |
| c02_heap_buffer_overflow | CWE-122/CWE-122 | Y | Y |
| c03_use_after_free | CWE-416/CWE-416 | n | Y |
| c04_double_free | CWE-415/CWE-415 | n | Y |
| c05_null_pointer_deref | CWE-476/CWE-476 | Y | n |
| c06_divide_by_zero | CWE-369/CWE-369 | Y | Y |
| c07_stack_exhaustion_recursion | CWE-674/CWE-674 | Y | Y |
| c08_out_of_bounds_read | CWE-125/CWE-125 | Y | Y |
| c09_integer_overflow_alloc | CWE-190/CWE-190 | Y | n |
| c10_off_by_one_loop | CWE-193/CWE-193 | Y | Y |
| c11_negative_memcpy_size | CWE-195/CWE-195 | Y | Y |
| c12_untrusted_array_index_write | CWE-129/CWE-129 | Y | Y |
