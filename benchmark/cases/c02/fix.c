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
