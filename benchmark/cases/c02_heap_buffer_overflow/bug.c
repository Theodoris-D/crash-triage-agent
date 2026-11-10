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
