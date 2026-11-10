#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    line[strcspn(line, "\n")] = 0;
    char *p = strdup(line);
    if (strcmp(line, "free") == 0) free(p);
    printf("len=%zu\n", strlen(p));  /* BUG: p dangling on "free" (CWE-416) */
    free(p);
    return 0;
}
