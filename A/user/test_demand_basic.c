// user/test_demand_basic.c
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int global_var = 999;

void deep_recursive(int depth) {
    // char buffer[900];
    // buffer[0] = depth;
    // buffer[899] = depth;
    if (depth > 0) {
        deep_recursive(depth - 1);
    }
}

int main() {
    printf("\n========== TEST 1: BASIC DEMAND PAGING ==========\n");
    
    // Test 1: Text/Data segment
    printf("\n[TEST 1.1] Text/Data segment access:\n");
    printf("global_var = %d\n", global_var);
    
    // Test 2: Heap allocation
    printf("\n[TEST 1.2] Heap allocation via sbrk:\n");
    char *heap1 = sbrk(4096);
    printf("sbrk(4096) returned: %p\n", heap1);
    heap1[0] = 'A';
    printf("First write to heap done: %c\n", heap1[0]);
    
    char *heap2 = sbrk(4096);
    heap2[100] = 'B';
    printf("Second heap page accessed: %c\n", heap2[100]);
    
    // Test 3: Stack growth
    printf("\n[TEST 1.3] Stack growth test:\n");
    deep_recursive(6);
    printf("Stack growth test completed\n");
    
    printf("\n========== TEST 1 COMPLETE ==========\n");
    exit(0);
}