#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Greets the name read from stdin. */
int main(void) {
    char buf[16];
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    line[strcspn(line, "\n")] = 0;
    char *src = strdup(line);       /* heap copy of the input */
    strcpy(buf, src);               /* BUG: no bounds check (CWE-121) */
    printf("hello %s\n", buf);
    free(src);
    return 0;
}
