// user/test_invalid.c
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int main() {
    printf("\n========== TEST 2: INVALID ACCESS ==========\n");
    
    printf("[TEST 2.1] Accessing invalid address 0xdeadbeef\n");
    int *bad = (int*)0xdeadbeef;
    *bad = 42;
    
    printf("ERROR: Should NOT reach here!\n");
    exit(0);
}