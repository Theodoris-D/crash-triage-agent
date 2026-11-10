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
