// user/test_invalid_bounds.c
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int main() {
    printf("\n========== TEST 3: BOUNDARY INVALID ACCESS ==========\n");
    
    // Allocate some heap
    char *heap = sbrk(8192);
    printf("Allocated 2 pages at %p\n", heap);
    heap[0] = 'X';
    
    printf("[TEST 3.1] Accessing just above proc->sz\n");
    char *beyond = heap + 8192 + 4096;  // One page beyond
    *beyond = 'Y';
    
    printf("ERROR: Should NOT reach here!\n");
    exit(0);
}