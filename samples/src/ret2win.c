#include <stdio.h>
#include <unistd.h>
void win(void) { puts("flag{ret2win_reached}"); fflush(stdout); }
void vuln(void) { char buf[32]; read(0, buf, 256); }
int main(void) { setvbuf(stdout, 0, 2, 0); puts("overflow me:"); vuln(); return 0; }
