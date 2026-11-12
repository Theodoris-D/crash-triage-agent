#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    int len = atoi(line);
    char src[8] = "ABCDEFG";
    char dst[8];
    if (len < 0 || (size_t)len > sizeof dst) { printf("copied=invalid\n"); return 0; }
    memcpy(dst, src, (size_t)len);
    printf("copied=%d\n", len);
    return 0;
}
