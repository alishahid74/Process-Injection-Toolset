#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static inline long long nsec_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int main(void) {
    long long t1 = nsec_now();
    usleep(1500);  // ~1.5ms
    long long t2 = nsec_now();
    printf("[antidebug_timing] delta_ns=%lld\n", (t2 - t1));
    return 0;
}
