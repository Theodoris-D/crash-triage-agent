#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const int months[] = {28,31,28,31,30,31,30,31,31,30,31,30,31};

static int days_in(int i) {
    if (i < 0 || i > 12) return -1;
    return months[i];
}

int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 0;
    int i = atoi(line);
    int d = days_in(i);
    if (d < 0) { printf("days=invalid\n"); return 0; }
    printf("days=%d\n", d);
    return 0;
}
