#include <stdio.h>
#include <sys/ptrace.h>
#include <errno.h>

int main(void) {
    long r = ptrace(PTRACE_TRACEME, 0, 0, 0);
    if (r == -1) {
        printf("[antidebug_ptrace] ptrace -> -1 (errno=%d): debugger present or denied\n", errno);
    } else {
        puts("[antidebug_ptrace] ptrace succeeded");
    }
    return 0;
}
