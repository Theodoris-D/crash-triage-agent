#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const int months[] = {28,31,28,31,30,31,30,31,31,30,31,30,31};

/* Month 1..12 -> day count; month 0 is February placeholder. */
static int days_in(int i) {
    return months[i];              /* BUG: i unchecked, OOB read (CWE-125) */
}

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    int i = atoi(line);
    printf("days=%d\n", days_in(i));
    return 0;
}
