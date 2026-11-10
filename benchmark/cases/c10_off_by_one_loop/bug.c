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
