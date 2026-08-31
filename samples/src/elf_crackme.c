/* Minimal ELF test fixture: a `win` function and a flag built at runtime
 * from immediate stores (so static_string_reconstruct has something to find).
 * Build (from WSL):
 *   gcc -O0 -D_FORTIFY_SOURCE=0 -fno-stack-protector -no-pie \
 *       samples/src/elf_crackme.c -o samples/elf64_crackme
 */
#include <stdio.h>
#include <string.h>

__attribute__((used)) void win(void) {
    puts("shell would spawn here");
}

int check(const char *guess) {
    volatile char flag[16] = {0};
    /* built byte-by-byte so it isn't a plain .rodata string */
    flag[0] = 'F'; flag[1] = 'L'; flag[2] = 'A'; flag[3] = 'G';
    flag[4] = '{'; flag[5] = 'o'; flag[6] = 'k'; flag[7] = '}';
    return strncmp(guess, (const char *)flag, 8) == 0;
}

int main(int argc, char **argv) {
    char buf[32];
    if (argc > 1) {
        strcpy(buf, argv[1]);          /* deliberate overflow sink */
        if (check(buf)) win();
    }
    printf("%s\n", buf);
    return 0;
}
