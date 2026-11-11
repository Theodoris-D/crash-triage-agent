#!/usr/bin/env python3
"""Generate the crash-triage benchmark.

Each case is a tiny, self-contained C program with ONE injected memory-safety
or arithmetic bug that crashes deterministically on a known input. For every
case we also ship a reference fix (used only to prove a correct fix exists and
that the functional tests are satisfiable -- the agent never sees it) and a
ground-truth record (crash class, CWE, root-cause line marker).

These are standard teaching demonstrators (cf. the Juliet suite): they crash,
they do not do anything malicious.

Run:  python3 benchmark/gen_cases.py
Emits: benchmark/cases/<id>/{bug.c,fix.c,meta.json} and benchmark/manifest.json
"""
from __future__ import annotations

import json
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent
CASES_DIR = HERE / "cases"


# A case:
#   id, title, cwe, crash_class, signal, root_cause_marker (substring of the
#   buggy line), crashing_stdin, functional tests [(stdin, expect_substr)],
#   bug source, fix source.
CASES: list[dict] = [
    {
        "id": "c01_stack_buffer_overflow",
        "title": "Unbounded strcpy into a fixed stack buffer",
        "cwe": "CWE-121",
        "crash_class": "stack-buffer-overflow",
        "signal": "SIGABRT",
        "root_cause_marker": "strcpy(buf, src)",
        "crashing_stdin": "A" * 64 + "\n",
        "functional": [["bob\n", "hello bob"], ["eve\n", "hello eve"]],
        "bug": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Greets the name read from stdin. */
int main(void) {
    char buf[16];
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    line[strcspn(line, "\n")] = 0;
    char *src = strdup(line);       /* heap copy of the input */
    strcpy(buf, src);               /* BUG: no bounds check (CWE-121) */
    printf("hello %s\n", buf);
    free(src);
    return 0;
}
""",
        "fix": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char buf[16];
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    line[strcspn(line, "\n")] = 0;
    char *src = strdup(line);
    strncpy(buf, src, sizeof buf - 1);
    buf[sizeof buf - 1] = 0;
    printf("hello %s\n", buf);
    free(src);
    return 0;
}
""",
    },
    {
        "id": "c02_heap_buffer_overflow",
        "title": "One-byte write past a heap allocation",
        "cwe": "CWE-122",
        "crash_class": "heap-buffer-overflow",
        "signal": "SIGABRT",
        "root_cause_marker": "b[n] = '!'",
        "crashing_stdin": "8\n",
        "functional": [["5\n", "ok 5"], ["1\n", "ok 1"]],
        "bug": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Allocates n bytes and marks the buffer. */
int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    int n = atoi(line);
    if (n < 0) n = 0;
    char *b = malloc(n);
    memset(b, 'x', n);
    b[n] = '!';                    /* BUG: writes one past the end (CWE-122) */
    printf("ok %d\n", n);
    free(b);
    return 0;
}
""",
        "fix": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    int n = atoi(line);
    if (n < 0) n = 0;
    char *b = malloc((size_t)n + 1);
    memset(b, 'x', n);
    b[n] = '!';
    printf("ok %d\n", n);
    free(b);
    return 0;
}
""",
    },
    {
        "id": "c03_use_after_free",
        "title": "Read through a pointer after it is freed",
        "cwe": "CWE-416",
        "crash_class": "heap-use-after-free",
        "signal": "SIGABRT",
        "root_cause_marker": "printf(\"len=%zu\\n\", strlen(p))",
        "crashing_stdin": "free\n",
        "functional": [["keep\n", "len=4"], ["hi\n", "len=2"]],
        "bug": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    line[strcspn(line, "\n")] = 0;
    char *p = strdup(line);
    if (strcmp(line, "free") == 0) free(p);
    printf("len=%zu\n", strlen(p));  /* BUG: p dangling on "free" (CWE-416) */
    free(p);
    return 0;
}
""",
        "fix": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    line[strcspn(line, "\n")] = 0;
    char *p = strdup(line);
    printf("len=%zu\n", strlen(p));
    free(p);
    return 0;
}
""",
    },
    {
        "id": "c04_double_free",
        "title": "Conditional path frees the same pointer twice",
        "cwe": "CWE-415",
        "crash_class": "double-free",
        "signal": "SIGABRT",
        "root_cause_marker": "free(p);",
        "root_line": 13,
        "crashing_stdin": "twice\n",
        "functional": [["once\n", "done"], ["ok\n", "done"]],
        "bug": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    line[strcspn(line, "\n")] = 0;
    char *p = malloc(32);
    strncpy(p, line, 31);
    p[31] = 0;
    if (strcmp(line, "twice") == 0) free(p);
    free(p);                       /* second free on "twice" (CWE-415) */
    printf("done\n");
    return 0;
}
""",
        "fix": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    line[strcspn(line, "\n")] = 0;
    char *p = malloc(32);
    strncpy(p, line, 31);
    p[31] = 0;
    free(p);
    printf("done\n");
    return 0;
}
""",
    },
    {
        "id": "c05_null_pointer_deref",
        "title": "Dereference of a lookup miss that returns NULL",
        "cwe": "CWE-476",
        "crash_class": "SEGV",
        "signal": "SIGSEGV",
        "root_cause_marker": "printf(\"value=%d\\n\", row->value)",
        "crashing_stdin": "missing\n",
        "functional": [["alpha\n", "value=1"], ["beta\n", "value=2"]],
        "bug": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct row { const char *key; int value; };
static struct row table[] = {{"alpha", 1}, {"beta", 2}, {NULL, 0}};

static struct row *lookup(const char *k) {
    for (struct row *r = table; r->key; r++)
        if (strcmp(r->key, k) == 0) return r;
    return NULL;
}

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    line[strcspn(line, "\n")] = 0;
    struct row *row = lookup(line);
    return printf("value=%d\n", row->value) < 0;  /* BUG: row may be NULL (CWE-476) */
}
""",
        "fix": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct row { const char *key; int value; };
static struct row table[] = {{"alpha", 1}, {"beta", 2}, {NULL, 0}};

static struct row *lookup(const char *k) {
    for (struct row *r = table; r->key; r++)
        if (strcmp(r->key, k) == 0) return r;
    return NULL;
}

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    line[strcspn(line, "\n")] = 0;
    struct row *row = lookup(line);
    if (!row) { printf("value=none\n"); return 0; }
    printf("value=%d\n", row->value);
    return 0;
}
""",
    },
    {
        "id": "c06_divide_by_zero",
        "title": "Integer division by an untrusted zero divisor",
        "cwe": "CWE-369",
        "crash_class": "integer-divide-by-zero",
        "signal": "SIGFPE",
        "root_cause_marker": "int q = total / n",
        "crashing_stdin": "0\n",
        "functional": [["4\n", "avg=25"], ["2\n", "avg=50"]],
        "bug": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Prints the average share of 100 among n parts. */
int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    int n = atoi(line);
    int total = 100;
    int q = total / n;             /* BUG: n may be 0 (CWE-369) */
    printf("avg=%d\n", q);
    return 0;
}
""",
        "fix": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    int n = atoi(line);
    int total = 100;
    if (n == 0) { printf("avg=undefined\n"); return 0; }
    int q = total / n;
    printf("avg=%d\n", q);
    return 0;
}
""",
    },
    {
        "id": "c07_stack_exhaustion_recursion",
        "title": "Unbounded recursion exhausts the stack",
        "cwe": "CWE-674",
        "crash_class": "stack-overflow",
        "signal": "SIGSEGV",
        "root_cause_marker": "return 1 + depth_up(n + 1)",
        "crashing_stdin": "up\n",
        "functional": [["3\n", "depth=3"], ["0\n", "depth=0"]],
        "bug": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Counts down to zero; "up" sends it the other way. */
static long depth(long n) {
    if (n == 0) return 0;
    return 1 + depth(n - 1);
}
static long depth_up(long n) {
    if (n == 0) return 0;
    return 1 + depth_up(n + 1);    /* BUG: never reaches base case (CWE-674) */
}

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    line[strcspn(line, "\n")] = 0;
    long d = (strcmp(line, "up") == 0) ? depth_up(1) : depth(atol(line));
    printf("depth=%ld\n", d);
    return 0;
}
""",
        "fix": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static long depth(long n) {
    if (n <= 0) return 0;
    return 1 + depth(n - 1);
}

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    line[strcspn(line, "\n")] = 0;
    long d = (strcmp(line, "up") == 0) ? 0 : depth(atol(line));
    printf("depth=%ld\n", d);
    return 0;
}
""",
    },
    {
        "id": "c08_out_of_bounds_read",
        "title": "Array read indexed by an untrusted value",
        "cwe": "CWE-125",
        "crash_class": "global-buffer-overflow",
        "signal": "SIGABRT",
        "root_cause_marker": "return months[i]",
        "crashing_stdin": "40\n",
        "functional": [["1\n", "days=31"], ["2\n", "days=28"]],
        "bug": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const int months[] = {28,31,28,31,30,31,30,31,31,30,31,30,31};

/* Month 1..12 -> day count; month 0 is February placeholder. */
static int days_in(int i) {
    return months[i];              /* BUG: i unchecked, OOB read (CWE-125) */
}

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    int i = atoi(line);
    printf("days=%d\n", days_in(i));
    return 0;
}
""",
        "fix": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const int months[] = {28,31,28,31,30,31,30,31,31,30,31,30,31};

static int days_in(int i) {
    if (i < 0 || i > 12) return -1;
    return months[i];
}

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    int i = atoi(line);
    int d = days_in(i);
    if (d < 0) { printf("days=invalid\n"); return 0; }
    printf("days=%d\n", d);
    return 0;
}
""",
    },
    {
        "id": "c09_integer_overflow_alloc",
        "title": "Allocation size computed with an overflowing multiply",
        "cwe": "CWE-190",
        "crash_class": "heap-buffer-overflow",
        "signal": "SIGABRT",
        "root_cause_marker": "unsigned bytes = count * 4",
        "crashing_stdin": "1073741824\n",
        "functional": [["4\n", "sum=0"], ["2\n", "sum=0"]],
        "bug": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Allocates count 32-bit ints and zero-fills them. */
int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    unsigned count = (unsigned)strtoul(line, NULL, 10);
    unsigned bytes = count * 4;    /* BUG: 32-bit multiply overflows (CWE-190) */
    int *a = malloc(bytes);
    for (unsigned i = 0; i < count; i++) a[i] = 0;
    long sum = 0;
    for (unsigned i = 0; i < count; i++) sum += a[i];
    printf("sum=%ld\n", sum);
    free(a);
    return 0;
}
""",
        "fix": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    unsigned long count = strtoul(line, NULL, 10);
    if (count > 100000UL) {        /* bound the untrusted allocation size */
        printf("sum=too-large\n");
        return 0;
    }
    int *a = calloc(count, sizeof *a);   /* calloc also checks the multiply */
    if (!a) { printf("sum=alloc-failed\n"); return 0; }
    long sum = 0;
    for (unsigned long i = 0; i < count; i++) sum += a[i];
    printf("sum=%ld\n", sum);
    free(a);
    return 0;
}
""",
    },
    {
        "id": "c10_off_by_one_loop",
        "title": "Copy loop runs one iteration too far",
        "cwe": "CWE-193",
        "crash_class": "stack-buffer-overflow",
        "signal": "SIGABRT",
        "root_cause_marker": "for (int i = 0; i <= n; i++)",
        "crashing_stdin": "reverse 16\n",
        "functional": [["reverse 4\n", "dcba"], ["reverse 2\n", "ba"]],
        "bug": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* "reverse N": reverses the first N letters of the alphabet. */
int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    int n = 0;
    if (sscanf(line, "reverse %d", &n) != 1) return 0;
    if (n < 0) n = 0;
    char out[16];
    for (int i = 0; i <= n; i++)   /* BUG: <= writes out[n] (CWE-193) */
        out[i] = 'a' + (n - 1 - i);
    out[n] = 0;
    printf("%s\n", out);
    return 0;
}
""",
        "fix": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    int n = 0;
    if (sscanf(line, "reverse %d", &n) != 1) return 0;
    if (n < 0) n = 0;
    if (n > 15) n = 15;
    char out[16];
    for (int i = 0; i < n; i++)
        out[i] = 'a' + (n - 1 - i);
    out[n] = 0;
    printf("%s\n", out);
    return 0;
}
""",
    },
    {
        "id": "c11_negative_memcpy_size",
        "title": "Signed length flows into memcpy as a huge size_t",
        "cwe": "CWE-195",
        "crash_class": "memcpy-overflow",
        "signal": "SIGABRT",
        "root_cause_marker": "memcpy(dst, src, len)",
        "crashing_stdin": "-1\n",
        "functional": [["3\n", "copied=3"], ["5\n", "copied=5"]],
        "bug": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    int len = atoi(line);          /* attacker-controlled, may be negative */
    char src[8] = "ABCDEFG";
    char dst[8];
    memcpy(dst, src, len);         /* BUG: negative len -> SIZE_MAX (CWE-195) */
    printf("copied=%d\n", len);
    return 0;
}
""",
        "fix": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    int len = atoi(line);
    char src[8] = "ABCDEFG";
    char dst[8];
    if (len < 0 || (size_t)len > sizeof dst) { printf("copied=invalid\n"); return 0; }
    memcpy(dst, src, (size_t)len);
    printf("copied=%d\n", len);
    return 0;
}
""",
    },
    {
        "id": "c12_untrusted_array_index_write",
        "title": "Write to a stack slot at an untrusted negative index",
        "cwe": "CWE-129",
        "crash_class": "stack-buffer-overflow",
        "signal": "SIGABRT",
        "root_cause_marker": "slots[idx] = val",
        "crashing_stdin": "set -3 9\n",
        "functional": [["set 2 7\n", "slots[2]=7"], ["set 0 5\n", "slots[0]=5"]],
        "bug": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* "set IDX VAL": stores VAL in a small table and echoes it. */
int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    int idx = 0, val = 0;
    if (sscanf(line, "set %d %d", &idx, &val) != 2) return 0;
    int slots[4] = {0};
    if (idx < 4) slots[idx] = val;  /* BUG: no lower bound (CWE-129) */
    printf("slots[%d]=%d\n", idx, slots[idx]);
    return 0;
}
""",
        "fix": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    int idx = 0, val = 0;
    if (sscanf(line, "set %d %d", &idx, &val) != 2) return 0;
    int slots[4] = {0};
    if (idx < 0 || idx >= 4) { printf("slots[%d]=out-of-range\n", idx); return 0; }
    slots[idx] = val;
    printf("slots[%d]=%d\n", idx, slots[idx]);
    return 0;
}
""",
    },
]


_LEAK_COMMENT = re.compile(r"\s*/\*[^\n]*(?:BUG|CWE)[^\n]*\*/\s*$", re.I)


def _strip_leak(src: str) -> str:
    """Remove inline comments that name the bug or its CWE, so the agent cannot
    read the answer out of the source. Benign descriptive comments are kept.
    The ground truth stays in meta.json."""
    lines = [_LEAK_COMMENT.sub("", ln).rstrip() for ln in src.splitlines()]
    return "\n".join(lines) + ("\n" if src.endswith("\n") else "")


def _root_line(bug_src: str, marker: str) -> int:
    for i, ln in enumerate(bug_src.splitlines(), 1):
        if marker in ln:
            return i
    raise SystemExit(f"marker not found: {marker!r}")


def main() -> None:
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    manifest = []
    for c in CASES:
        cid = c["id"].split("_", 1)[0]   # neutral id ('c01'), not 'c01_stack_buffer_overflow'
        d = CASES_DIR / cid
        d.mkdir(exist_ok=True)
        bug = _strip_leak(c["bug"].lstrip("\n"))  # the agent must not read the answer
        fix = c["fix"].lstrip("\n")
        (d / "bug.c").write_text(bug)
        (d / "fix.c").write_text(fix)
        line = c.get("root_line") or _root_line(bug, c["root_cause_marker"])
        meta = {
            "id": cid,
            "title": c["title"],
            "cwe": c["cwe"],
            "crash_class": c["crash_class"],
            "signal": c["signal"],
            "root_cause_line": line,
            "root_cause_marker": c["root_cause_marker"].strip(),
            "crashing_stdin": c["crashing_stdin"],
            "functional_tests": [
                {"stdin": s, "expect_substr": e} for s, e in c["functional"]
            ],
        }
        (d / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
        manifest.append({k: meta[k] for k in ("id", "title", "cwe", "crash_class",
                                              "signal", "root_cause_line")})
    (HERE / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {len(CASES)} cases to {CASES_DIR}")


if __name__ == "__main__":
    main()
