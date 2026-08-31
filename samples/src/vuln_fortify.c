#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char out[128];
    snprintf(out, sizeof out, "arg=%s", argc > 1 ? argv[1] : "");
    memcpy(out + 100, "tail", 5);       /* -> __memcpy_chk under FORTIFY */
    puts(out);
    return 0;
}
