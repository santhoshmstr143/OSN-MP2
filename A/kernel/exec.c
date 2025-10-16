#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "elf.h"



// map ELF permissions to PTE permission bits.
int flags2perm(int flags)
{
    int perm = 0;
    if(flags & 0x1)
      perm = PTE_X;
    if(flags & 0x2)
      perm |= PTE_W;
    return perm;
}

//
// the implementation of the exec() system call
//
int
exec(char *path, char **argv)
{
  char *s, *last;
  int i, off;
  uint64 argc, sz = 0, sp, ustack[MAXARG], stackbase;
  struct elfhdr elf;
  struct inode *ip;
  struct proghdr ph;
  pagetable_t pagetable = 0, oldpagetable;
  struct proc *p = myproc();

  begin_op();

  if((ip = namei(path)) == 0){
    end_op();
    return -1;
  }
  ilock(ip);

  // Check ELF header
  if(readi(ip, 0, (uint64)&elf, 0, sizeof(elf)) != sizeof(elf))
    goto bad;
  if(elf.magic != ELF_MAGIC)
    goto bad;

  if((pagetable = proc_pagetable(p)) == 0)
    goto bad;

  // Clear lazy segments
  p->lazy_nseg = 0;
  p->pf_seq = 0;

  // Load program into memory and record segments for lazy loading
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(readi(ip, 0, (uint64)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;
    if(ph.type != ELF_PROG_LOAD)
      continue;
    if(ph.memsz < ph.filesz)
      goto bad;
    if(ph.vaddr + ph.memsz < ph.vaddr)
      goto bad;
    if(ph.vaddr % PGSIZE != 0)
      goto bad;

    // Record this segment for lazy loading instead of allocating pages
    if(p->lazy_nseg >= 16) // too many segments
      goto bad;
    
    p->lazy_segs[p->lazy_nseg].vaddr = ph.vaddr;
    p->lazy_segs[p->lazy_nseg].filesz = ph.filesz;
    p->lazy_segs[p->lazy_nseg].memsz = ph.memsz;
    p->lazy_segs[p->lazy_nseg].fileoff = ph.off;
    p->lazy_segs[p->lazy_nseg].ip = ip;
    p->lazy_nseg++;
    
    if(ph.vaddr + ph.memsz > sz)
      sz = ph.vaddr + ph.memsz;
  }

  // Set up user stack - must allocate at least one stack page for exec
  sz = PGROUNDUP(sz);
  sz += 2*PGSIZE; // Reserve space for stack 
  sp = sz;
  stackbase = sp - PGSIZE;
  
  // Allocate the initial stack page immediately for exec to work
  uint64 stack_page = PGROUNDDOWN(stackbase);
  char *mem = kalloc();
  if(mem == 0)
    goto bad;
  memset(mem, 0, PGSIZE);
  if(mappages(pagetable, stack_page, PGSIZE, (uint64)mem, PTE_W|PTE_R|PTE_U) != 0){
    kfree(mem);
    goto bad;
  }

  // Push argument strings, prepare rest of stack in ustack.
  for(argc = 0; argv[argc]; argc++) {
    if(argc >= MAXARG)
      goto bad;
    sp -= strlen(argv[argc]) + 1;
    sp -= sp % 16; // riscv sp must be 16-byte aligned
    if(sp < stackbase)
      goto bad;
    if(copyout(pagetable, sp, argv[argc], strlen(argv[argc]) + 1) < 0)
      goto bad;
    ustack[argc] = sp;
  }
  ustack[argc] = 0;

  // push the array of argv[] pointers.
  sp -= (argc+1) * sizeof(uint64);
  sp -= sp % 16;
  if(sp < stackbase)
    goto bad;
  if(copyout(pagetable, sp, (char *)ustack, (argc+1)*sizeof(uint64)) < 0)
    goto bad;

  // arguments to user main(argc, argv)
  // argc is returned via the system call return
  // value, which goes in a0.
  p->trapframe->a1 = sp;

  // Save program name for debugging.
  for(last=s=path; *s; s++)
    if(*s == '/')
      last = s+1;
  safestrcpy(p->name, last, sizeof(p->name));

  // Clean up old swap state if exists
  if(p->num_swapped > 0) {
    cleanup_swap_file(p);
  }

  // Commit to the user image.
  oldpagetable = p->pagetable;
  uint64 oldsz = p->sz;
  p->pagetable = pagetable;
  p->sz = sz;
  
  // Initialize PagedOut Inc. demand paging metadata
  p->lazy_heap_start = sz; // heap starts after data/bss
  p->lazy_stack_top = sz;  // stack top
  p->lazy_max_addr = sz;   // initialize max allocated address
  
  // Set text and data segment bounds for validation
  if(p->lazy_nseg > 0) {
    p->text_start = p->lazy_segs[0].vaddr;
    p->text_end = p->lazy_segs[0].vaddr + p->lazy_segs[0].memsz;
  }
  if(p->lazy_nseg > 1) {
    p->data_start = p->lazy_segs[1].vaddr;  
    p->data_end = p->lazy_segs[1].vaddr + p->lazy_segs[1].memsz;
  }
  
  // Initialize resident page tracking and swap management
  p->num_resident = 0;
  p->num_swapped = 0;
  p->pf_seq = 0;  // Reset FIFO sequence counter for new program
  for(int i = 0; i < 256; i++) {
    p->resident_pages[i].va = 0;
    p->resident_pages[i].seq = 0;
    p->resident_pages[i].is_dirty = 0;
    p->resident_pages[i].swap_slot = -1;
  }
  for(int i = 0; i < 1024; i++) {
    p->swap_slots[i] = 0; // 0 = free
  }
  
  // Track the initial stack page as resident
  p->resident_pages[0].va = stack_page;
  p->resident_pages[0].seq = ++p->pf_seq;  // seq = 1
  p->resident_pages[0].is_dirty = 1; // Stack is writable
  p->resident_pages[0].swap_slot = -1;
  p->num_resident = 1;
  
  // Initialize per-process swap file
  init_swap_file(p);
  
  p->trapframe->epc = elf.entry;  // initial program counter = main
  p->trapframe->sp = sp; // initial stack pointer
  
  // Free old pagetable with its original size
  if(oldpagetable && oldpagetable != pagetable) {
    proc_freepagetable(oldpagetable, oldsz);  // Free old pagetable
  }

  // Keep reference to inode for lazy loading
  idup(ip);
  
  // Log PagedOut Inc. initialization
  printf("[pid %d] INIT-LAZYMAP text=[0x%lx,0x%lx) data=[0x%lx,0x%lx) heap_start=0x%lx stack_top=0x%lx\n",
         p->pid, p->text_start, p->text_end, p->data_start, p->data_end, 
         p->lazy_heap_start, p->lazy_stack_top);
  
  iunlock(ip);
  end_op();
  return argc; // this ends up in a0, the first argument to main(argc, argv)

 bad:
  if(pagetable)
    proc_freepagetable(pagetable, 1);
  if(ip){
    iunlock(ip);
    end_op();
  }
  return -1;
}


