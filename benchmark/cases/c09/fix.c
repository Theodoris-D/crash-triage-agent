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
