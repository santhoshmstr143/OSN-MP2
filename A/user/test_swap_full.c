// user/test_swap_full.c
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int main() {
    printf("\n========== TEST 7: SWAP EXHAUSTION ==========\n");
    
    printf("[TEST 7.1] Allocating MANY pages to exhaust swap\n");
    printf("Max swap: 1024 pages (4MB)\n");
    
    for(int i = 0; i < 1200; i++) {
        char *p = sbrk(4096);
        if(p == (char*)-1) {
            printf("sbrk failed at page %d\n", i);
            break;
        }
        
        // Write to make dirty
        for(int j = 0; j < 4096; j += 512) {
            p[j] = i;
        }
        
        if(i % 100 == 0) {
            printf("Allocated %d pages\n", i);
        }
    }
    
    printf("Should have been killed by swap exhaustion!\n");
    exit(0);
}