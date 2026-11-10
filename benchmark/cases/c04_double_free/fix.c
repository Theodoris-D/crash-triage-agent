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
