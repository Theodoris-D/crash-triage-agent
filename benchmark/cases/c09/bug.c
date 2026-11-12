#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Allocates count 32-bit ints and zero-fills them. */
int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    unsigned count = (unsigned)strtoul(line, NULL, 10);
    unsigned bytes = count * 4;
    int *a = malloc(bytes);
    for (unsigned i = 0; i < count; i++) a[i] = 0;
    long sum = 0;
    for (unsigned i = 0; i < count; i++) sum += a[i];
    printf("sum=%ld\n", sum);
    free(a);
    return 0;
}
