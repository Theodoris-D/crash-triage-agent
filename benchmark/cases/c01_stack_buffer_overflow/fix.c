#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char buf[16];
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    line[strcspn(line, "\n")] = 0;
    char *src = strdup(line);
    strncpy(buf, src, sizeof buf - 1);
    buf[sizeof buf - 1] = 0;
    printf("hello %s\n", buf);
    free(src);
    return 0;
}
