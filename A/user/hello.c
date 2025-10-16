#include <stdio.h>
#include <unistd.h>

int main() {
    printf("Hello World Test for Demand Paging\n");
    
    // Test sbrk (heap allocation)
    char *p = (char*)sbrk(4096);
    printf("sbrk returned: %p\n", p);
    *p = 'A';  // This should trigger a heap page fault
    printf("Wrote to heap: %c\n", *p);
    
    // Test stack growth
    char stack_var = 'B';
    printf("Stack variable: %c\n", stack_var);
    
    return 0;
}