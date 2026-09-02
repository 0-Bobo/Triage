#include <stdio.h>
#include <string.h>
/* Builds the flag in a heap buffer and never prints it — emulator bait. */
int main(void) {
    char *b = malloc(64);
    memset(b, 0, 64);
    strcpy(b, "flag{");
    for (int i = 0; i < 8; i++) b[5 + i] = "MEMbuilt"[i];
    strcat(b, "_42}");
    puts("nothing to see here");
    return 0;
}
