#include <stdio.h>
#include <string.h>
void win(void) { puts("you win"); }
int main(int argc, char **argv) {
    char buf[64];
    if (argc > 1) strcpy(buf, argv[1]);   /* real strcpy: no FORTIFY here */
    puts(buf);
    return 0;
}
