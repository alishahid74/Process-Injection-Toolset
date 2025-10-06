#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

int main(void) {
    puts("[loader_dlopen] attempting dlopen on libc");
    void *h = dlopen("libc.so.6", RTLD_LAZY);
    if (!h) {
        puts("[loader_dlopen] dlopen failed");
        return 1;
    }
    void (*puts_fn)(const char*) = dlsym(h, "puts");
    if (puts_fn) puts_fn("[loader_dlopen] resolved puts via dlsym");
    dlclose(h);
    return 0;
}
