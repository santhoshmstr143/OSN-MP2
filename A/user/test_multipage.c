// user/test_multipage.c
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

// Large array to span multiple pages
int large_array[2048];  // 8KB = 2 pages

int main() {
    printf("\n========== TEST 10: MULTI-PAGE SEGMENTS ==========\n");
    
    printf("[TEST 10.1] Accessing large data array\n");
    large_array[0] = 111;       // Page 0x1000 (offset 0)
    large_array[1024] = 222;    // Page 0x2000 (offset 4096 = 0x1000)
    large_array[2047] = 333;    // Page 0x3000 (offset 8188 = 0x1FF8)
    
    printf("Values: %d, %d, %d\n", 
           large_array[0], large_array[1024], large_array[2047]);
    
    printf("\n========== TEST 10 COMPLETE ==========\n");
    exit(0);
}