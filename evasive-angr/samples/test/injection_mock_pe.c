#include <windows.h>
#include <stdio.h>

int main(void) {
    // call some Windows APIs to create import references
    HMODULE k = GetModuleHandleA("kernel32.dll");
    FARPROC va = GetProcAddress(k, "VirtualAlloc");
    FARPROC wpm = GetProcAddress(k, "WriteProcessMemory");
    printf("GetProcAddress results: %p %p\n", va, wpm);
    return 0;
}
