#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    int idx = 0, val = 0;
    if (sscanf(line, "set %d %d", &idx, &val) != 2) return 0;
    int slots[4] = {0};
    if (idx < 0 || idx >= 4) { printf("slots[%d]=out-of-range\n", idx); return 0; }
    slots[idx] = val;
    printf("slots[%d]=%d\n", idx, slots[idx]);
    return 0;
}
