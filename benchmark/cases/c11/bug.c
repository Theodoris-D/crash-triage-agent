#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    int len = atoi(line);          /* attacker-controlled, may be negative */
    char src[8] = "ABCDEFG";
    char dst[8];
    memcpy(dst, src, len);
    printf("copied=%d\n", len);
    return 0;
}
