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
