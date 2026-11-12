#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Prints the average share of 100 among n parts. */
int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    int n = atoi(line);
    int total = 100;
    int q = total / n;
    printf("avg=%d\n", q);
    return 0;
}
