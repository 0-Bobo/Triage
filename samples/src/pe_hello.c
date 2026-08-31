/* Minimal PE test fixture for the loader's pefile branch.
 * Build (from Windows, WinLibs on PATH):
 *   x86_64-w64-mingw32-gcc -O1 -s samples/src/pe_hello.c -o samples/pe64_hello.exe
 */
#include <stdio.h>
#include <string.h>

static char secret[16];

void win(void) {
    puts("you win");
}

int main(void) {
    strcpy(secret, "not-the-flag");
    printf("%s\n", secret);
    return 0;
}
