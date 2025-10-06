// gcc -O0 -no-pie -fno-pic -g -o antidebug_demo samples/antidebug_demo.c
#include <stdio.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <errno.h>

int anti_debug_check(void) {
    errno = 0;
    long r = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    if (r == -1 && errno == EPERM) {
        return 1; // debugger detected
    }
    ptrace(PTRACE_DETACH, getpid(), NULL, NULL);
    return 0;
}

int main(int argc, char **argv) {
    if (anti_debug_check()) {
        puts("[anti-debug] debugger detected. exit.");
        return 2;
    }
    puts("[ok] no debugger detected; continuing.");
    if (argc > 1) printf("user arg: %s\n", argv[1]);
    puts("[demo] finished.");
    return 0;
}
