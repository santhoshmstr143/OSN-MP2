// user/test_fifo.c
#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/memstat.h"
#include "user/user.h"

int main() {
    printf("\n========== TEST 9: FIFO POLICY ==========\n");
    
    printf("[TEST 9.1] Allocating pages in order\n");
    char *pages[50];
    for(int i = 0; i < 50; i++) {
        pages[i] = sbrk(4096);
        if(pages[i] != (char*)-1) {
            pages[i][0] = i;
            printf("Page %d allocated\n", i);
        }
    }
    
    printf("\n[TEST 9.2] Forcing more allocations to trigger eviction\n");
    for(int i = 0; i < 20; i++) {
        char *p = sbrk(4096);
        if(p != (char*)-1) {
            *p = 100 + i;
        }
    }
    
    printf("\n[TEST 9.3] Check VICTIM logs - should evict oldest (lowest seq)\n");
    
    printf("\n========== TEST 9 COMPLETE ==========\n");
    exit(0);
}