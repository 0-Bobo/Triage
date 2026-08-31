#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void win(void) { system("/bin/sh"); }
void vuln(const char *s) {
    char buf[64];
    strcpy(buf, s);       /* VULN_BOF sink */
    printf(buf);          /* format-string sink, keeps real printf at -O0 */
}
int main(int argc, char **argv) { if (argc > 1) vuln(argv[1]); return 0; }
