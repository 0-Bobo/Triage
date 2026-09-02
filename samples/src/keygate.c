#include <stdio.h>
void win(void) { puts("flag{keygate_static}"); }
int main(void) {
    unsigned int k = 0;
    printf("key: ");
    if (scanf("%x", &k) == 1 && k == 0xdeadbeef) win();
    else puts("nope, wrong key");
    return 0;
}
