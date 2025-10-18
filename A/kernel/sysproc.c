#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"
#include "vm.h"
#include "memstat.h"

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  kexit(n);
  return 0;  // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return kfork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return kwait(p);
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int n;

  argint(0, &n);
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

uint64
sys_pause(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  if(n < 0)
    n = 0;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(killed(myproc())){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kkill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}
uint64
sys_memstat(void)
{
  uint64 addr;
  argaddr(0, &addr);
  
  struct proc *p = myproc();
  struct proc_mem_stat stat;
  
  stat.pid = p->pid;
  stat.num_resident_pages = p->num_resident;
  stat.num_swapped_pages = p->num_swapped;
  stat.next_fifo_seq = p->pf_seq + 1;
  
  // Calculate total pages - round up
  stat.num_pages_total = PGROUNDUP(p->sz) / PGSIZE;
  
  // Fill page info
  int page_count = 0;
  for(uint64 va = 0; va < p->sz && page_count < MAX_PAGES_INFO; va += PGSIZE) {
    stat.pages[page_count].va = va;
    stat.pages[page_count].state = UNMAPPED;
    stat.pages[page_count].is_dirty = 0;
    stat.pages[page_count].seq = 0;
    stat.pages[page_count].swap_slot = -1;
    
    // Check if page is resident
    int found_resident = 0;
    for(int i = 0; i < p->num_resident; i++) {
      if(p->resident_pages[i].va == va) {
        stat.pages[page_count].state = RESIDENT;
        stat.pages[page_count].is_dirty = p->resident_pages[i].is_dirty;
        stat.pages[page_count].seq = p->resident_pages[i].seq;
        stat.pages[page_count].swap_slot = p->resident_pages[i].swap_slot;
        found_resident = 1;
        break;
      }
    }
    
    // Check if swapped (only if not resident)
    if(!found_resident) {
      for(int i = 0; i < p->num_swapped; i++) {
        if(p->swapped_pages[i].va == va) {
          stat.pages[page_count].state = SWAPPED;
          stat.pages[page_count].swap_slot = p->swapped_pages[i].slot;
          break;
        }
      }
    }
    
    page_count++;
  }
  
  if(copyout(p->pagetable, addr, (char*)&stat, sizeof(stat)) < 0)
    return -1;
  
  return 0;
}