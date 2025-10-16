// user/test_swapfile.c
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int main() {
    printf("\n========== TEST 6: SWAP FILE ==========\n");
    
    printf("[TEST 6.1] Process should have swap file\n");
    printf("Check for /pgswpXXXXX file (where XXXXX is my PID)\n");
    
    // Allocate enough to force swapping
    printf("[TEST 6.2] Allocating many pages\n");
    for(int i = 0; i < 100; i++) {
        char *p = sbrk(4096);
        if(p != (char*)-1) {
            *p = i;
        }
    }
    
    printf("\n[TEST 6.3] Exiting - swap file should be cleaned up\n");
    exit(0);
}