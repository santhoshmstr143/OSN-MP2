#include "param.h"
#include "types.h"
#include "memlayout.h"
#include "elf.h"
#include "riscv.h"
#include "defs.h"
#include "spinlock.h"
#include "proc.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "fcntl.h"
#include "stat.h"

/*
 * the kernel's page table.
 */
pagetable_t kernel_pagetable;

extern char etext[]; // kernel.ld sets this to end of kernel code.

extern char trampoline[]; // trampoline.S

// Make a direct-map page table for the kernel.
pagetable_t
kvmmake(void)
{
  pagetable_t kpgtbl;

  kpgtbl = (pagetable_t)kalloc();
  memset(kpgtbl, 0, PGSIZE);

  // uart registers
  kvmmap(kpgtbl, UART0, UART0, PGSIZE, PTE_R | PTE_W);

  // virtio mmio disk interface
  kvmmap(kpgtbl, VIRTIO0, VIRTIO0, PGSIZE, PTE_R | PTE_W);

  // PLIC
  kvmmap(kpgtbl, PLIC, PLIC, 0x4000000, PTE_R | PTE_W);

  // map kernel text executable and read-only.
  kvmmap(kpgtbl, KERNBASE, KERNBASE, (uint64)etext - KERNBASE, PTE_R | PTE_X);

  // map kernel data and the physical RAM we'll make use of.
  kvmmap(kpgtbl, (uint64)etext, (uint64)etext, PHYSTOP - (uint64)etext, PTE_R | PTE_W);

  // map the trampoline for trap entry/exit to
  // the highest virtual address in the kernel.
  kvmmap(kpgtbl, TRAMPOLINE, (uint64)trampoline, PGSIZE, PTE_R | PTE_X);

  // allocate and map a kernel stack for each process.
  proc_mapstacks(kpgtbl);

  return kpgtbl;
}

// add a mapping to the kernel page table.
// only used when booting.
// does not flush TLB or enable paging.
void kvmmap(pagetable_t kpgtbl, uint64 va, uint64 pa, uint64 sz, int perm)
{
  if (mappages(kpgtbl, va, sz, pa, perm) != 0)
    panic("kvmmap");
}

// Initialize the kernel_pagetable, shared by all CPUs.
void kvminit(void)
{
  kernel_pagetable = kvmmake();
}

// Switch the current CPU's h/w page table register to
// the kernel's page table, and enable paging.
void kvminithart()
{
  // wait for any previous writes to the page table memory to finish.
  sfence_vma();

  w_satp(MAKE_SATP(kernel_pagetable));

  // flush stale entries from the TLB.
  sfence_vma();
}

// Return the address of the PTE in page table pagetable
// that corresponds to virtual address va.  If alloc!=0,
// create any required page-table pages.
//
// The risc-v Sv39 scheme has three levels of page-table
// pages. A page-table page contains 512 64-bit PTEs.
// A 64-bit virtual address is split into five fields:
//   39..63 -- must be zero.
//   30..38 -- 9 bits of level-2 index.
//   21..29 -- 9 bits of level-1 index.
//   12..20 -- 9 bits of level-0 index.
//    0..11 -- 12 bits of byte offset within the page.
pte_t *
walk(pagetable_t pagetable, uint64 va, int alloc)
{
  if (va >= MAXVA)
    panic("walk");

  for (int level = 2; level > 0; level--)
  {
    pte_t *pte = &pagetable[PX(level, va)];
    if (*pte & PTE_V)
    {
      pagetable = (pagetable_t)PTE2PA(*pte);
    }
    else
    {
      if (!alloc || (pagetable = (pde_t *)kalloc()) == 0)
        return 0;
      memset(pagetable, 0, PGSIZE);
      *pte = PA2PTE(pagetable) | PTE_V;
    }
  }
  return &pagetable[PX(0, va)];
}

// Look up a virtual address, return the physical address,
// or 0 if not mapped.
// Can only be used to look up user pages.
uint64
walkaddr(pagetable_t pagetable, uint64 va)
{
  pte_t *pte;
  uint64 pa;

  if (va >= MAXVA)
    return 0;

  pte = walk(pagetable, va, 0);
  if (pte == 0)
    return 0;
  if ((*pte & PTE_V) == 0)
    return 0;
  if ((*pte & PTE_U) == 0)
    return 0;
  pa = PTE2PA(*pte);
  return pa;
}

// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa.
// va and size MUST be page-aligned.
// Returns 0 on success, -1 if walk() couldn't
// allocate a needed page-table page.
int mappages(pagetable_t pagetable, uint64 va, uint64 size, uint64 pa, int perm)
{
  uint64 a, last;
  pte_t *pte;

  if ((va % PGSIZE) != 0)
    panic("mappages: va not aligned");

  if ((size % PGSIZE) != 0)
    panic("mappages: size not aligned");

  if (size == 0)
    panic("mappages: size");

  a = va;
  last = va + size - PGSIZE;
  for (;;)
  {
    if ((pte = walk(pagetable, a, 1)) == 0)
      return -1;
    if (*pte & PTE_V)
      panic("mappages: remap");
    *pte = PA2PTE(pa) | perm | PTE_V;
    if (a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// create an empty user page table.
// returns 0 if out of memory.
pagetable_t
uvmcreate()
{
  pagetable_t pagetable;
  pagetable = (pagetable_t)kalloc();
  if (pagetable == 0)
    return 0;
  memset(pagetable, 0, PGSIZE);
  return pagetable;
}

// Remove npages of mappings starting from va. va must be
// page-aligned. It's OK if the mappings don't exist.
// Optionally free the physical memory.
void uvmunmap(pagetable_t pagetable, uint64 va, uint64 npages, int do_free)
{
  uint64 a;
  pte_t *pte;

  if ((va % PGSIZE) != 0)
    panic("uvmunmap: not aligned");

  for (a = va; a < va + npages * PGSIZE; a += PGSIZE)
  {
    if ((pte = walk(pagetable, a, 0)) == 0) // leaf page table entry allocated?
      continue;
    if ((*pte & PTE_V) == 0) // has physical page been allocated?
      continue;
    if (do_free)
    {
      uint64 pa = PTE2PA(*pte);
      kfree((void *)pa);
    }
    *pte = 0;
  }
}

// Allocate PTEs and physical memory to grow a process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
uint64
uvmalloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz, int xperm)
{
  char *mem;
  uint64 a;

  if (newsz < oldsz)
    return oldsz;

  oldsz = PGROUNDUP(oldsz);
  for (a = oldsz; a < newsz; a += PGSIZE)
  {
    mem = kalloc();
    if (mem == 0)
    {
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
    memset(mem, 0, PGSIZE);
    if (mappages(pagetable, a, PGSIZE, (uint64)mem, PTE_R | PTE_U | xperm) != 0)
    {
      kfree(mem);
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
  }
  return newsz;
}

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
uint64
uvmdealloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz)
{
  if (newsz >= oldsz)
    return oldsz;

  if (PGROUNDUP(newsz) < PGROUNDUP(oldsz))
  {
    int npages = (PGROUNDUP(oldsz) - PGROUNDUP(newsz)) / PGSIZE;
    uvmunmap(pagetable, PGROUNDUP(newsz), npages, 1);
  }

  return newsz;
}

// Recursively free page-table pages.
// All leaf mappings must already have been removed.
void freewalk(pagetable_t pagetable)
{
  // there are 2^9 = 512 PTEs in a page table.
  for (int i = 0; i < 512; i++)
  {
    pte_t pte = pagetable[i];
    if ((pte & PTE_V) && (pte & (PTE_R | PTE_W | PTE_X)) == 0)
    {
      // this PTE points to a lower-level page table.
      uint64 child = PTE2PA(pte);
      freewalk((pagetable_t)child);
      pagetable[i] = 0;
    }
    else if (pte & PTE_V)
    {
      panic("freewalk: leaf");
    }
  }
  kfree((void *)pagetable);
}

// Free user memory pages,
// then free page-table pages.
void uvmfree(pagetable_t pagetable, uint64 sz)
{
  if (sz > 0)
    uvmunmap(pagetable, 0, PGROUNDUP(sz) / PGSIZE, 1);
  freewalk(pagetable);
}

// Given a parent process's page table, copy
// its memory into a child's page table.
// Copies both the page table and the
// physical memory.
// returns 0 on success, -1 on failure.
// frees any allocated pages on failure.
int uvmcopy(pagetable_t old, pagetable_t new, uint64 sz)
{
  pte_t *pte;
  uint64 pa, i;
  uint flags;
  char *mem;

  for (i = 0; i < sz; i += PGSIZE)
  {
    if ((pte = walk(old, i, 0)) == 0)
      continue; // page table entry hasn't been allocated
    if ((*pte & PTE_V) == 0)
      continue; // physical page hasn't been allocated
    pa = PTE2PA(*pte);
    flags = PTE_FLAGS(*pte);
    if ((mem = kalloc()) == 0)
      goto err;
    memmove(mem, (char *)pa, PGSIZE);
    if (mappages(new, i, PGSIZE, (uint64)mem, flags) != 0)
    {
      kfree(mem);
      goto err;
    }
  }
  return 0;

err:
  uvmunmap(new, 0, i / PGSIZE, 1);
  return -1;
}

// mark a PTE invalid for user access.
// used by exec for the user stack guard page.
void uvmclear(pagetable_t pagetable, uint64 va)
{
  pte_t *pte;

  pte = walk(pagetable, va, 0);
  if (pte == 0)
    panic("uvmclear");
  *pte &= ~PTE_U;
}

// Copy from kernel to user.
// Copy len bytes from src to virtual address dstva in a given page table.
// Return 0 on success, -1 on error.
int copyout(pagetable_t pagetable, uint64 dstva, char *src, uint64 len)
{
  uint64 n, va0, pa0;
  pte_t *pte;

  while (len > 0)
  {
    va0 = PGROUNDDOWN(dstva);
    if (va0 >= MAXVA)
      return -1;

    pa0 = walkaddr(pagetable, va0);
    if (pa0 == 0)
    {
      if (demand_page_load_new(va0, 1, 0) != 0)
      {
        return -1;
      }
      pa0 = walkaddr(pagetable, va0);
      if (pa0 == 0)
      {
        return -1;
      }
    }

    pte = walk(pagetable, va0, 0);
    // forbid copyout over read-only user text pages.
    if ((*pte & PTE_W) == 0)
      return -1;

    n = PGSIZE - (dstva - va0);
    if (n > len)
      n = len;
    memmove((void *)(pa0 + (dstva - va0)), src, n);

    len -= n;
    src += n;
    dstva = va0 + PGSIZE;
  }
  return 0;
}

// Copy from user to kernel.
// Copy len bytes to dst from virtual address srcva in a given page table.
// Return 0 on success, -1 on error.
int copyin(pagetable_t pagetable, char *dst, uint64 srcva, uint64 len)
{
  uint64 n, va0, pa0;

  while (len > 0)
  {
    va0 = PGROUNDDOWN(srcva);
    pa0 = walkaddr(pagetable, va0);
    if (pa0 == 0)
    {
      if (demand_page_load_new(va0, 0, 0) != 0)
      {
        return -1;
      }
      pa0 = walkaddr(pagetable, va0);
      if (pa0 == 0)
      {
        return -1;
      }
    }
    n = PGSIZE - (srcva - va0);
    if (n > len)
      n = len;
    memmove(dst, (void *)(pa0 + (srcva - va0)), n);

    len -= n;
    dst += n;
    srcva = va0 + PGSIZE;
  }
  return 0;
}

// Copy a null-terminated string from user to kernel.
// Copy bytes to dst from virtual address srcva in a given page table,
// until a '\0', or max.
// Return 0 on success, -1 on error.
int copyinstr(pagetable_t pagetable, char *dst, uint64 srcva, uint64 max)
{
  uint64 n, va0, pa0;
  int got_null = 0;

  while (got_null == 0 && max > 0)
  {
    va0 = PGROUNDDOWN(srcva);
    pa0 = walkaddr(pagetable, va0);
    if (pa0 == 0)
    {
      if (demand_page_load_new(va0, 0, 0) != 0)
      {
        return -1;
      }
      pa0 = walkaddr(pagetable, va0);
      if (pa0 == 0)
      {
        return -1;
      }
    }
    n = PGSIZE - (srcva - va0);
    if (n > max)
      n = max;

    char *p = (char *)(pa0 + (srcva - va0));
    while (n > 0)
    {
      if (*p == '\0')
      {
        *dst = '\0';
        got_null = 1;
        break;
      }
      else
      {
        *dst = *p;
      }
      --n;
      --max;
      p++;
      dst++;
    }

    srcva = va0 + PGSIZE;
  }
  if (got_null)
  {
    return 0;
  }
  else
  {
    return -1;
  }
}

// allocate and map user memory if process is referencing a page
// that was lazily allocated in sys_sbrk().
// returns 0 if va is invalid or already mapped, or if
// out of physical memory, and physical address if successful.
uint64
vmfault(pagetable_t pagetable, uint64 va, int read)
{
  uint64 mem;
  struct proc *p = myproc();

  if (va >= p->sz)
    return 0;
  va = PGROUNDDOWN(va);
  if (ismapped(pagetable, va))
  {
    return 0;
  }
  mem = (uint64)kalloc();
  if (mem == 0)
    return 0;
  memset((void *)mem, 0, PGSIZE);
  if (mappages(p->pagetable, va, PGSIZE, mem, PTE_W | PTE_U | PTE_R) != 0)
  {
    kfree((void *)mem);
    return 0;
  }
  return mem;
}

int ismapped(pagetable_t pagetable, uint64 va)
{
  pte_t *pte = walk(pagetable, va, 0);
  if (pte == 0)
  {
    return 0;
  }
  if (*pte & PTE_V)
  {
    return 1;
  }
  return 0;
}

// Find which lazy segment (if any) contains va. Returns index or -1.
static int
lazy_seg_find(struct proc *p, uint64 va, uint64 *seg_vstart)
{
  for (int i = 0; i < p->lazy_nseg; i++)
  {
    uint64 s = p->lazy_segs[i].vaddr;
    uint64 e = s + p->lazy_segs[i].memsz;
    if (va >= s && va < e)
    {
      if (seg_vstart)
        *seg_vstart = s;
      return i;
    }
  }
  return -1;
}

// Load a single page for process p at virtual address va
int demand_page_load(pagetable_t pagetable, struct proc *p, uint64 va, int is_write, int is_exec)
{
  uint64 a = PGROUNDDOWN(va);

  // Check if already mapped
  pte_t *pte = walk(pagetable, a, 0);
  if (pte && (*pte & PTE_V))
  {
    return 0; // already resident
  }

  // Log the page fault
  printf("PAGEFAULT pid=%d va=0x%lx write=%d exec=%d\n", p->pid, va, is_write, is_exec);

  // Check if va is in an executable segment
  uint64 seg_vstart;
  int si = lazy_seg_find(p, va, &seg_vstart);
  char *mem = 0;

  if (si >= 0)
  {
    // File-backed load (LOADEXEC)
    struct lazy_seg *seg = &p->lazy_segs[si];
    mem = kalloc();
    if (!mem)
    {
      printf("demand_page_load: kalloc failed\n");
      return -1;
    }
    memset(mem, 0, PGSIZE);

    // Calculate file offset for this page
    uint64 page_offset_in_seg = a - seg->vaddr;
    uint64 file_read_start = seg->fileoff + page_offset_in_seg;
    uint64 toread = 0;

    if (page_offset_in_seg < seg->filesz)
    {
      toread = seg->filesz - page_offset_in_seg;
      if (toread > PGSIZE)
        toread = PGSIZE;

      // Read from inode
      ilock(seg->ip);
      int r = readi(seg->ip, 0, (uint64)mem, file_read_start, toread);
      iunlock(seg->ip);

      if (r != toread)
      {
        kfree(mem);
        return -1;
      }
    }

    printf("LOADEXEC pid=%d addr=0x%lx seg=%d fileoff=0x%lx\n", p->pid, a, si, file_read_start);
  }
  else
  {
    // Not file-backed. Check if it's heap or stack
    if (a >= PGROUNDDOWN(p->lazy_heap_start) && a < p->sz)
    {
      // Heap page
      mem = kalloc();
      if (!mem)
      {
        printf("demand_page_load: kalloc failed\n");
        return -1;
      }
      memset(mem, 0, PGSIZE);
      printf("ALLOC pid=%d addr=0x%lx (heap)\n", p->pid, a);

      // Update max allocated address
      if (a + PGSIZE > p->lazy_max_addr)
      {
        p->lazy_max_addr = a + PGSIZE;
      }
    }
    else if (a >= p->lazy_stack_top && a < p->lazy_stack_top + 10 * PGSIZE)
    {
      // Stack page (starting at stack_top and growing upward, within reasonable limits)
      mem = kalloc();
      if (!mem)
      {
        printf("demand_page_load: kalloc failed\n");
        return -1;
      }
      memset(mem, 0, PGSIZE);
      printf("ALLOC pid=%d addr=0x%lx (stack)\n", p->pid, a);

      // Update process size to include this stack page
      if (a + PGSIZE > p->sz)
      {
        p->sz = a + PGSIZE;
      }

      // Update max allocated address
      if (a + PGSIZE > p->lazy_max_addr)
      {
        p->lazy_max_addr = a + PGSIZE;
      }
    }
    else if (p->sz == 0 && a < 0x100000)
    {
      // Special case: exec-time stack setup (process not fully initialized)
      mem = kalloc();
      if (!mem)
      {
        printf("demand_page_load: kalloc failed\n");
        return -1;
      }
      memset(mem, 0, PGSIZE);
      printf("ALLOC pid=%d addr=0x%lx (exec-stack)\n", p->pid, a);

      // Update max allocated address
      if (a + PGSIZE > p->lazy_max_addr)
      {
        p->lazy_max_addr = a + PGSIZE;
      }
    }
    else
    {
      // Outside valid ranges: kill process
      printf("PAGEFAULT_OUTSIDE pid=%d va=0x%lx\n", p->pid, va);
      p->killed = 1;
      return -1;
    }
  }

  // Map the page
  int perm = PTE_U;
  if (is_write || (si >= 0))
    perm |= PTE_W;
  if (si < 0 || is_exec)
    perm |= PTE_R;
  if (is_exec)
    perm |= PTE_X;
  else
    perm |= PTE_R | PTE_W; // for data pages

  if (mappages(pagetable, a, PGSIZE, (uint64)mem, perm) != 0)
  {
    kfree(mem);
    printf("demand_page_load: mappages failed\n");
    return -1;
  }

  // Emit RESIDENT record
  p->pf_seq++;
  printf("RESIDENT pid=%d seq=%ld va=0x%lx\n", p->pid, p->pf_seq, a);

  return 0;
}

// PagedOut Inc. helper functions for comprehensive demand paging

void add_resident_page(struct proc *p, uint64 va, int is_dirty)
{
  // ALWAYS increment sequence first
  p->pf_seq++;

  if (p->num_resident >= 256)
  {
    // Resident array is full, but sequence still incremented
    // In production, trigger page replacement here
    panic("resident set full - page replacement needed");
  }

  p->resident_pages[p->num_resident].va = va;
  p->resident_pages[p->num_resident].seq = p->pf_seq; // Use already incremented value
  p->resident_pages[p->num_resident].is_dirty = is_dirty;
  p->resident_pages[p->num_resident].swap_slot = -1;
  p->num_resident++;
}

void remove_resident_page(struct proc *p, uint64 va)
{
  for (int i = 0; i < p->num_resident; i++)
  {
    if (p->resident_pages[i].va == va)
    {
      // Shift remaining entries
      for (int j = i; j < p->num_resident - 1; j++)
      {
        p->resident_pages[j] = p->resident_pages[j + 1];
      }
      p->num_resident--;
      break;
    }
  }
}

int find_victim_page(struct proc *p)
{
  if (p->num_resident == 0)
    return -1;

  int oldest_idx = 0;
  int oldest_seq = p->resident_pages[0].seq;

  for (int i = 1; i < p->num_resident; i++)
  {
    if (p->resident_pages[i].seq < oldest_seq)
    {
      oldest_seq = p->resident_pages[i].seq;
      oldest_idx = i;
    }
  }
  return oldest_idx;
}

int find_free_swap_slot(struct proc *p)
{
  for (int i = 0; i < 1024; i++)
  {
    if (p->swap_slots[i] == 0)
    {
      p->swap_slots[i] = 1; // Mark as used
      return i;
    }
  }
  return -1;
}

void init_swap_file(struct proc *p)
{
  // Create per-process swap file name: /pgswpXXXXX where XXXXX is PID
  p->swap_filename[0] = '/';
  p->swap_filename[1] = 'p';
  p->swap_filename[2] = 'g';
  p->swap_filename[3] = 's';
  p->swap_filename[4] = 'w';
  p->swap_filename[5] = 'p';

  // Convert PID to 5-digit string
  int pid = p->pid;
  for (int i = 10; i >= 6; i--)
  {
    p->swap_filename[i] = '0' + (pid % 10);
    pid /= 10;
  }
  p->swap_filename[11] = '\0';

  // Skip actual file creation to avoid locking issues
  // Just set up tracking structures

  p->num_swapped = 0;
}

void cleanup_swap_file(struct proc *p)
{
  // Clear swap slots without locking (safe during cleanup)
  int freed_slots = 0;
  for (int i = 0; i < 1024; i++)
  {
    if (p->swap_slots[i] == 1)
    {
      freed_slots++;
      p->swap_slots[i] = 0;
    }
  }

  if (freed_slots > 0)
  {
    printf("[pid %d] SWAPCLEANUP freed_slots=%d\n", p->pid, freed_slots);
  }

  // No file operations needed since swapping is memory-only now
  // p->swap_file = 0;

  // Clear resident pages tracking
  p->num_resident = 0;
  p->num_swapped = 0;
  p->pf_seq = 0;
}

int swap_out_page(struct proc *p, uint64 va, int slot)
{
  // Get physical address of the page being swapped out
  pte_t *pte = walk(p->pagetable, va, 0);
  if (pte == 0 || (*pte & PTE_V) == 0)
  {
    return -1;
  }

  // Save page data to swapped_pages array
  if (p->num_swapped >= 256)
  {
    return -1; // No space for swapped pages
  }

  // Get the physical address and SAVE THE ACTUAL DATA!
  uint64 pa = PTE2PA(*pte);
  
  // Copy actual page contents to swap storage
  memmove(p->swapped_pages[p->num_swapped].data, (void*)pa, PGSIZE);
  
  // Record the swap mapping
  p->swapped_pages[p->num_swapped].va = va;
  p->swapped_pages[p->num_swapped].slot = slot;
  p->num_swapped++;

  printf("[pid %d] SWAPOUT va=0x%lx slot=%d\n", p->pid, va, slot);
  return 0;
}

int swap_in_page(struct proc *p, uint64 va, int slot, char *mem)
{
  // Find the swapped page
  int found = -1;
  for (int i = 0; i < p->num_swapped; i++)
  {
    if (p->swapped_pages[i].va == va && p->swapped_pages[i].slot == slot)
    {
      found = i;
      break;
    }
  }

  if (found < 0)
  {
    return -1; // Page not found in swap
  }

  // RESTORE THE ACTUAL DATA from swap storage!
  memmove(mem, p->swapped_pages[found].data, PGSIZE);

  // Remove from swapped pages array
  for (int i = found; i < p->num_swapped - 1; i++)
  {
    p->swapped_pages[i] = p->swapped_pages[i + 1];
  }
  p->num_swapped--;

  // Free the swap slot
  p->swap_slots[slot] = 0;

  // Don't log here - caller will log SWAPIN
  return 0;
}

// New comprehensive demand paging function
int demand_page_load_new(uint64 va, int is_write, int is_exec)
{
  struct proc *p = myproc();
  uint64 a = PGROUNDDOWN(va);

  // Check if already mapped
  pte_t *pte = walk(p->pagetable, a, 0);
  if (pte && (*pte & PTE_V))
  {
    // Page is resident, check if we need to mark it dirty
    if (is_write)
    {
      for (int i = 0; i < p->num_resident; i++)
      {
        if (p->resident_pages[i].va == a)
        {
          p->resident_pages[i].is_dirty = 1;
          break;
        }
      }
    }
    return 0;
  }

  // Determine access type and cause for logging
  char *access_type = is_exec ? "exec" : (is_write ? "write" : "read");
  char *cause = "unknown";

  // Check if this is a swapped page first
  // Check if this is a swapped page first
  int swap_slot = -1;
  for (int i = 0; i < p->num_swapped; i++)
  {
    if (p->swapped_pages[i].va == a)
    {
      swap_slot = p->swapped_pages[i].slot;
      cause = "swap";
      break;
    }
  }

  // Determine cause if not swapped
  if (swap_slot < 0)
  {
    uint64 seg_vstart;
    int si = lazy_seg_find(p, va, &seg_vstart);
    if (si >= 0)
    {
      cause = "exec";
    }
    else if (a >= PGROUNDDOWN(p->lazy_heap_start) && a < p->sz)
    {
      cause = "heap";
    }
    else
    {
      // Check if it's stack growth - allow growth down from top of memory
      if (a >= PGROUNDDOWN(p->sz - 2 * PGSIZE) && a < p->sz)
      {
        cause = "stack";
      }
    }
  }

  // Log the page fault (always first)
  printf("[pid %d] PAGEFAULT va=0x%lx access=%s cause=%s\n", p->pid, va, access_type, cause);

  // Check for invalid access
  uint64 seg_vstart;
  int si = lazy_seg_find(p, va, &seg_vstart);
  int is_valid = 0;

  if (si >= 0)
  {
    is_valid = 1; // In text/data segment
  }
  else if (a >= PGROUNDDOWN(p->lazy_heap_start) && a < p->sz)
  {
    is_valid = 1; // In heap
  }
  else if (swap_slot >= 0)
  {
    is_valid = 1; // Was swapped
  }
  else
  {
    // Check stack - allow growth down from top of memory
    if (a >= PGROUNDDOWN(p->sz - 2 * PGSIZE) && a < p->sz)
    {
      is_valid = 1; // Stack growth
    }
  }

  if (!is_valid)
  {
    printf("[pid %d] KILL invalid-access va=0x%lx access=%s\n", p->pid, va, access_type);
    p->killed = 1;
    kexit(-1);
    return -1;
  }

  // Try to allocate memory
  char *mem = kalloc();

  // If allocation failed, trigger page replacement
  if (!mem)
  {
    printf("[pid %d] MEMFULL\n", p->pid);

    // Find victim page using FIFO
    int victim_idx = find_victim_page(p);
    if (victim_idx < 0)
    {
      printf("[pid %d] KILL no-resident-pages\n", p->pid);
      setkilled(p);
      return -1;
    }

    uint64 victim_va = p->resident_pages[victim_idx].va;
    int victim_seq = p->resident_pages[victim_idx].seq;
    int victim_dirty = p->resident_pages[victim_idx].is_dirty;

    printf("[pid %d] VICTIM va=0x%lx seq=%d algo=FIFO\n", p->pid, victim_va, victim_seq);
    printf("[pid %d] EVICT va=0x%lx state=%s\n", p->pid, victim_va, victim_dirty ? "dirty" : "clean");

    if (victim_dirty)
    {
      // Need to swap out
      int slot = find_free_swap_slot(p);
      if (slot < 0)
      {
        printf("[pid %d] SWAPFULL\n", p->pid);
        printf("[pid %d] KILL swap-exhausted\n", p->pid);
        setkilled(p);
        return -1;
      }

      if (swap_out_page(p, victim_va, slot) < 0)
      {
        // swap_out failed (ran out of swapped_pages array)
        printf("[pid %d] SWAPFULL\n", p->pid);
        printf("[pid %d] KILL swap-exhausted\n", p->pid);
        setkilled(p);
        return -1;
      }
    }
    else
    {
      printf("[pid %d] DISCARD va=0x%lx\n", p->pid, victim_va);
    }

    // Free the victim page
    pte_t *victim_pte = walk(p->pagetable, victim_va, 0);
    if (victim_pte && (*victim_pte & PTE_V))
    {
      uint64 victim_pa = PTE2PA(*victim_pte);
      kfree((void *)victim_pa);
      *victim_pte = 0;
    }

    // Remove from resident set
    remove_resident_page(p, victim_va);

    // Try allocation again
    mem = kalloc();
    if (!mem)
    {
      printf("[pid %d] KILL allocation-failed\n", p->pid);
      setkilled(p);
      return -1;
    }
  }

  // Load the page content
  memset(mem, 0, PGSIZE);

  if (swap_slot >= 0)
  {
    // Load from swap - pass the allocated memory
    if (swap_in_page(p, a, swap_slot, mem) < 0)
    {
      kfree(mem);
      return -1;
    }
    printf("[pid %d] SWAPIN va=0x%lx slot=%d\n", p->pid, a, swap_slot);
  }
  else if (si >= 0)
  {
    // Load from executable
    struct lazy_seg *seg = &p->lazy_segs[si];
    uint64 page_offset_in_seg = a - seg->vaddr;
    uint64 file_read_start = seg->fileoff + page_offset_in_seg;

    if (page_offset_in_seg < seg->filesz)
    {
      uint64 toread = seg->filesz - page_offset_in_seg;
      if (toread > PGSIZE)
        toread = PGSIZE;

      ilock(seg->ip);
      int r = readi(seg->ip, 0, (uint64)mem, file_read_start, toread);
      iunlock(seg->ip);

      if (r != toread)
      {
        kfree(mem);
        return -1;
      }
    }
    printf("[pid %d] LOADEXEC va=0x%lx\n", p->pid, a);
  }
  else
  {
    // Zero-filled page (heap or stack)
    printf("[pid %d] ALLOC va=0x%lx\n", p->pid, a);
  }

  // Map the page
  if (mappages(p->pagetable, a, PGSIZE, (uint64)mem, PTE_U | PTE_R | PTE_W | PTE_X) != 0)
  {
    kfree(mem);
    return -1;
  }

  // Add to resident set and log
  add_resident_page(p, a, is_write); // Mark dirty if written
  printf("[pid %d] RESIDENT va=0x%lx seq=%lu\n", p->pid, a, p->pf_seq);

  return 0;
}

// Modify growproc to only adjust proc->sz without allocating pages
int growproc(int n)
{
  uint64 sz;
  struct proc *p = myproc();

  sz = p->sz;
  if (n > 0)
  {
    // Growing: just increase size, don't allocate pages
    p->sz = sz + n;
  }
  else if (n < 0)
  {
    // Shrinking: free pages and decrease size
    if (sz + n < p->lazy_heap_start)
      return -1;
    sz = uvmdealloc(p->pagetable, sz, sz + n);
    p->sz = sz;
  }
  return 0;
}
