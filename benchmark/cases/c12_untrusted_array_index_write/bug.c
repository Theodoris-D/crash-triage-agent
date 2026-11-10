#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* "set IDX VAL": stores VAL in a small table and echoes it. */
int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    int idx = 0, val = 0;
    if (sscanf(line, "set %d %d", &idx, &val) != 2) return 0;
    int slots[4] = {0};
    if (idx < 4) slots[idx] = val;  /* BUG: no lower bound (CWE-129) */
    printf("slots[%d]=%d\n", idx, slots[idx]);
    return 0;
}
