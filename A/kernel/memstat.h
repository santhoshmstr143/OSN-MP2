#ifndef MEMSTAT_H
#define MEMSTAT_H

#define MAX_PAGES_INFO 128 // Max pages to report per syscall

// Page states
#define UNMAPPED 0 
#define RESIDENT 1 
#define SWAPPED  2

struct page_stat {
  uint va;        // Virtual address (page-aligned)
  int state;      // UNMAPPED, RESIDENT, or SWAPPED
  int is_dirty;   // 1 if page has been written to
  int seq;        // FIFO sequence number
  int swap_slot;  // Swap slot number (if swapped)
};

struct proc_mem_stat {
  int pid;
  int num_pages_total;     // All virtual pages between program start and proc->sz
  int num_resident_pages;  // Pages currently in physical memory
  int num_swapped_pages;   // Pages currently in swap
  int next_fifo_seq;       // Next FIFO sequence number to assign
  struct page_stat pages[MAX_PAGES_INFO];
};

#endif