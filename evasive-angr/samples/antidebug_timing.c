// gcc -O0 -no-pie -fno-pic -g -o samples/antidebug_timing samples/antidebug_timing.c
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <stdint.h>

static int timing_check(void) {
    struct timespec t1, t2;
    // measure a small tight loop
    clock_gettime(CLOCK_MONOTONIC, &t1);
    volatile int x = 0;
    for (int i=0;i<1000000;i++) x += i & 1;
    clock_gettime(CLOCK_MONOTONIC, &t2);
    long delta_ns = (t2.tv_sec - t1.tv_sec) * 1000000000L + (t2.tv_nsec - t1.tv_nsec);
    // if delta too large, assume single-stepping or slowdown -> debugger
    if (delta_ns > 200000000L) { // 200ms threshold (example)
        return 1; // debugger suspected
    }
    return 0; // OK
}

int main(int argc, char **argv) {
    if (timing_check()) {
        puts("[anti-debug] timing check failed - slow execution/detector");
        return 2;
    }
    puts("[ok] timing check passed; continuing.");
    if (argc > 1) printf("user arg: %s\n", argv[1]);
    puts("[demo] finished.");
    return 0;
}
