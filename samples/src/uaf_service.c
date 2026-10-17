#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define RSIZE 40
#define MAXW 64
#define MAXC 64

typedef struct {
    long id;
    void (*cb)(int, long);
    char pad[RSIZE - 16];
} rec_t;

static rec_t *watchers[MAXW];
static int wcount = 0;

static int client_fd[MAXC];
static long client_id[MAXC];
static int client_used[MAXC];
static long next_id = 1;

void sender(int fd, const char *flag) {
    write(fd, flag, 64);
}

void flagfunc(int fd, long unused) {
    (void)unused;
    const char *flag = getenv("FLAG");
    sender(fd, flag);
}

void *handle(void *arg) {
    int fd = (int)(long)arg;
    char buf[256];
    long myid = next_id++;
    int slot = -1;
    for (int i = 0; i < MAXC; i++) {
        if (!client_used[i]) { slot = i; break; }
    }
    if (slot >= 0) {
        client_fd[slot] = fd;
        client_id[slot] = myid;
        client_used[slot] = 1;
    }
    rec_t *mine = NULL;

    for (;;) {
        int n = read(fd, buf, sizeof(buf) - 1);
        if (n <= 0) break;
        buf[n] = 0;
        if (!strncmp(buf, "LOGIN|", 6)) {
            write(fd, "ok\n", 3);
        } else if (!strncmp(buf, "WATCH", 5)) {
            mine = malloc(RSIZE);
            mine->id = myid;
            mine->cb = flagfunc;
            if (wcount < MAXW) watchers[wcount++] = mine;
            char out[64];
            int ln = snprintf(out, sizeof(out), "watching as #%ld\n", myid);
            write(fd, out, ln);
        } else if (!strncmp(buf, "CREATE|", 7)) {
            char *p = buf + 7;
            long price = atol(p);
            char *bar = strchr(p, '|');
            char *namep = bar ? bar + 1 : p;
            int namelen = n - (int)(namep - buf);
            rec_t *r = malloc(RSIZE);
            r->id = price;
            if (namelen > 0) {
                int cp = namelen < RSIZE - 8 ? namelen : RSIZE - 8;
                memcpy(((char *)r) + 8, namep, cp);
            }
            write(fd, "created\n", 8);
        } else if (!strncmp(buf, "BID", 3)) {
            for (int i = 0; i < wcount; i++) {
                rec_t *r = watchers[i];
                if (r) r->cb((int)r->id, 0);
            }
            write(fd, "bid done\n", 9);
        }
    }
    if (mine) free(mine);
    if (slot >= 0) client_used[slot] = 0;
    close(fd);
    return NULL;
}

int main(int argc, char **argv) {
    int port = argc > 1 ? atoi(argv[1]) : 8765;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    bind(s, (struct sockaddr *)&addr, sizeof(addr));
    listen(s, 16);
    printf("uaf_service listening on port %d\n", port);
    fflush(stdout);
    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) continue;
        pthread_t t;
        pthread_create(&t, NULL, handle, (void *)(long)c);
        pthread_detach(t);
    }
    return 0;
}
