#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    line[strcspn(line, "\n")] = 0;
    char *p = strdup(line);
    printf("len=%zu\n", strlen(p));
    free(p);
    return 0;
}
