#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "cbuffer.h"

void main(int argc, char**argv)
{
    void *addr = (void*)((unsigned long)shellcode_bin & ((0UL - 1UL) ^ 0xfff));/*get memory page*/
    int ans = mprotect(addr, 1, PROT_READ|PROT_WRITE|PROT_EXEC);/*set page attributes*/
    printf("Checking if it worked\n");
    if (ans)
    {
        exit(0);
    }
    printf("Executing shellcode\n");
    ((void(*)(void))shellcode_bin)();/*execute array*/
}
