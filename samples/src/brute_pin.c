#include <stdio.h>
/* Short pure-digit PIN: autopwn's brute strategy can exhaust a 1-4 digit
 * keyspace outright (strat_brute.py mode 2). No win() function on purpose
 * (keygen/z3 both require has_win == False to defer to brute here), and no
 * "%s" anywhere in the binary (strat_brute.py's digits_only heuristic
 * requires "%d" present and "%s" absent). */
int main(void) {
    int pin;
    if (scanf("%d", &pin) != 1) return 1;
    if (pin == 42) {
        puts("flag{brute_42}");
        return 0;
    }
    puts("nope");
    return 1;
}
