// user/test_swapping.c
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int main() {
    printf("\n========== TEST 5: SWAPPING ==========\n");
    
    printf("[TEST 5.1] Allocating and writing to many pages\n");
    char *pages[150];
    int count = 0;
    
    for(int i = 0; i < 150; i++) {
        char *p = sbrk(4096);
        if(p == (char*)-1) break;
        
        pages[i] = p;
        // Write unique pattern to mark as dirty
        for(int j = 0; j < 10; j++) {
            p[j] = i + j;
        }
        count++;
        
        if(count % 30 == 0) {
            printf("Allocated and dirtied %d pages\n", count);
        }
    }
    
    printf("\n[TEST 5.2] Allocated %d pages total\n", count);
    
    // Access old pages to trigger swap-in
    printf("\n[TEST 5.3] Re-accessing swapped pages\n");
    for(int i = 0; i < 20 && i < count; i++) {
        int val = pages[i][0];
        if(val != i) {
            printf("ERROR: Page %d has wrong value! Expected %d, got %d\n", 
                   i, i, val);
        } else if(i % 5 == 0) {
            printf("Page %d verified: %d\n", i, val);
        }
    }
    
    printf("\n========== TEST 5 COMPLETE ==========\n");
    exit(0);
}