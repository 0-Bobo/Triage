#include <fcntl.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    char buf[64];
    if (argc > 1) strcpy(buf, argv[1]);
    int fd = open("/etc/hostname", O_RDONLY);   /* VULN_PATTERNS: open */
    if (fd >= 0) { read(fd, buf, 8); write(1, buf, 8); close(fd); }
    return 0;
}
