#include <inttypes.h>
#include <stdio.h>

int main() {
    fprintf(stderr, "%x\n", *((uint32_t*)0x100003f88));

    __asm__("mov xzr, xzr");

    return 0;
}
