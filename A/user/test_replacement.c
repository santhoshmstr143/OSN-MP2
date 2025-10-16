// user/test_replacement.c
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int main() {
    printf("\n========== TEST 4: PAGE REPLACEMENT ==========\n");
    
    printf("[TEST 4.1] Allocating pages until memory full\n");
    int pages = 0;
    char *ptrs[200];
    
    for(int i = 0; i < 200; i++) {
        char *p = sbrk(4096);
        if(p == (char*)-1) {
            printf("sbrk failed at %d pages\n", i);
            break;
        }
        ptrs[i] = p;
        *p = i;  // Touch the page to force allocation
        pages++;
        
        if(pages % 20 == 0) {
            printf("Allocated %d pages so far...\n", pages);
        }
    }
    
    printf("\n[TEST 4.2] Total pages allocated: %d\n", pages);
    
    // Now access old pages to trigger replacement
    printf("\n[TEST 4.3] Accessing earlier pages (should trigger replacement)\n");
    for(int i = 0; i < 10 && i < pages; i++) {
        printf("Accessing page %d: value=%d\n", i, ptrs[i][0]);
    }
    
    printf("\n========== TEST 4 COMPLETE ==========\n");
    exit(0);
}