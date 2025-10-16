// Physical memory allocator, for user processes,
// kernel stacks, page-table pages,
// and pipe buffers. Allocates whole 4096-byte pages.

#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "riscv.h"
#include "defs.h"

void freerange(void *pa_start, void *pa_end);

extern char end[]; // first address after kernel.
                   // defined by kernel.ld.

struct run {
  struct run *next;
};

struct {
  struct spinlock lock;
  struct run *freelist;
  int user_page_count;  // Track user allocations only
} kmem;

void
kinit()
{
  initlock(&kmem.lock, "kmem");
  kmem.user_page_count = 0;  // Initialize counter
  freerange(end, (void*)PHYSTOP);
}

void
freerange(void *pa_start, void *pa_end)
{
  char *p;
  p = (char*)PGROUNDUP((uint64)pa_start);
  for(; p + PGSIZE <= (char*)pa_end; p += PGSIZE)
    kfree(p);
}

// Free the page of physical memory pointed at by pa,
// which normally should have been returned by a
// call to kalloc().  (The exception is when
// initializing the allocator; see kinit above.)
void
kfree(void *pa)
{
  struct run *r;

  if(((uint64)pa % PGSIZE) != 0 || (char*)pa < end || (uint64)pa >= PHYSTOP)
    panic("kfree");

  // Fill with junk to catch dangling refs.
  memset(pa, 1, PGSIZE);

  r = (struct run*)pa;

  acquire(&kmem.lock);
  r->next = kmem.freelist;
  kmem.freelist = r;
  
  // Decrement user page count (if it was a user allocation)
  if(kmem.user_page_count > 0) {
    kmem.user_page_count--;
  }
  
  release(&kmem.lock);
}

// Allocate one 4096-byte page of physical memory.
// Returns a pointer that the kernel can use.
// Returns 0 if the memory cannot be allocated.
void *
kalloc(void)
{
  struct run *r;
  struct proc *p = myproc();  // Get current process

  acquire(&kmem.lock);
  r = kmem.freelist;
  
  if(r) {
    // Only limit user process allocations, not kernel allocations
    if(p != 0) {  // This is a user process allocation
      // Artificial limit for testing page replacement
      #define MAX_USER_PAGES 40  // Limit for user processes only
      
      if(kmem.user_page_count >= MAX_USER_PAGES) {
        release(&kmem.lock);
        return 0;  // Pretend we're out of memory
      }
      kmem.user_page_count++;
    }
    
    kmem.freelist = r->next;
  }
  
  release(&kmem.lock);

  if(r)
    memset((char*)r, 5, PGSIZE);
  return (void*)r;
}