#include <stdio.h>
void win(void) { puts("flag{arith_z3_solved}"); }
int main(void) {
    unsigned int x;
    printf("key: ");
    if (scanf("%x", &x) != 1) return 1;
    x ^= 0x1337u;
    x += 42u;
    x *= 3u;
    if (x == 0x7eu) win();
    else puts("nope");
    return 0;
}
