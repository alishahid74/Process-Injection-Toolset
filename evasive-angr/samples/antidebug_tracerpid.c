// gcc -O0 -no-pie -fno-pic -g -o antidebug_tracerpid samples/antidebug_tracerpid.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int is_debugger_attached(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;  // be permissive
    char line[256];
    int tracer = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tracer = atoi(line + 10);
            break;
        }
    }
    fclose(f);
    return tracer != 0;
}

int main(int argc, char **argv) {
    if (is_debugger_attached()) {
        puts("[anti-debug] TracerPid != 0 — debugger detected. exit.");
        return 2;
    }
    puts("[ok] TracerPid == 0 — no debugger; continuing.");
    if (argc > 1) printf("user arg: %s\n", argv[1]);
    puts("[demo] finished.");
    return 0;
}
