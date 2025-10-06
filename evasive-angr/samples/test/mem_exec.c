#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    size_t pagesz = (size_t) sysconf(_SC_PAGESIZE);
    void *buf = mmap(NULL, pagesz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) { perror("mmap"); return 1; }

    /* tiny machine code: writes a string via puts-like ABI then returns
       for demo we just return immediately (ret) to avoid crashes on systems that forbid exec */
    unsigned char code[] = { 0xC3 }; /* ret */

    memcpy(buf, code, sizeof(code));
    if (mprotect(buf, pagesz, PROT_READ|PROT_EXEC) != 0) { perror("mprotect"); return 1; }

    printf("[mem_exec] allocated RX page at %p (won't actually jump to shellcode)\n", buf);
    /* You *could* cast and call ((void(*)())buf)(); but many kernels block W^X transitions. */
    return 0;
}
