#include <stdio.h>
#include <string.h>
int main(void) {
    char in[32];
    if (!fgets(in, sizeof in, stdin)) return 1;
    in[strcspn(in, "\n")] = 0;
    /* password is "sup3rs3cr3t" */
    const char *k = "sup3rs3cr3t";
    if (strcmp(in, k) == 0) { puts("Correct! flag{keycheck_symbolic}"); return 0; }
    puts("Wrong.");
    return 1;
}
