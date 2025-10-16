// user/test_memstat.c
#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/memstat.h"
#include "user/user.h"

int main() {
    printf("\n========== TEST 8: MEMSTAT SYSCALL ==========\n");
    
    struct proc_mem_stat stat;
    
    // Initial state
    printf("\n[TEST 8.1] Initial memory state:\n");
    if(memstat(&stat) == 0) {
        printf("PID: %d\n", stat.pid);
        printf("Total pages: %d\n", stat.num_pages_total);
        printf("Resident pages: %d\n", stat.num_resident_pages);
        printf("Swapped pages: %d\n", stat.num_swapped_pages);
        printf("Next FIFO seq: %d\n", stat.next_fifo_seq);
    }
    
    // Allocate some pages
    printf("\n[TEST 8.2] After allocating 5 pages:\n");
    for(int i = 0; i < 5; i++) {
        char *p = sbrk(4096);
        *p = i;
    }
    
    if(memstat(&stat) == 0) {
        printf("Total pages: %d\n", stat.num_pages_total);
        printf("Resident pages: %d\n", stat.num_resident_pages);
        printf("Swapped pages: %d\n", stat.num_swapped_pages);
        
        printf("\n[TEST 8.3] Page details (first 10):\n");
        for(int i = 0; i < stat.num_pages_total && i < 10; i++) {
            printf("Page %d: va=0x%x state=%d dirty=%d seq=%d slot=%d\n",
                   i, stat.pages[i].va, stat.pages[i].state,
                   stat.pages[i].is_dirty, stat.pages[i].seq,
                   stat.pages[i].swap_slot);
        }
    }
    
    printf("\n========== TEST 8 COMPLETE ==========\n");
    exit(0);
}