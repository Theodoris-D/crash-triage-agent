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
