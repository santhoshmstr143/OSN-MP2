# xv6
# PagedOut Inc. - Demand Paging Implementation

## What I Implemented

### 1. Lazy Loading at exec()
- exec() no longer allocates pages upfront
- Records segment info (text/data) for later loading
- Only allocates initial stack page
- Process starts with minimal memory footprint

### 2. Demand Paging (Page Fault Handler)
- Page faults trigger `demand_page_load_new()` in vm.c
- **Text/Data pages**: Loaded from executable file on first access
- **Heap pages**: Allocated zero-filled on first access
- **Stack pages**: Allocated zero-filled when accessed
- Each loaded page gets FIFO sequence number
- Invalid accesses kill the process

### 3. FIFO Page Replacement
- When kalloc() fails (no free memory), eviction happens
- `find_victim_page()` selects oldest resident page (lowest seq)
- **Clean pages**: Discarded directly
- **Dirty pages**: Swapped out to disk before eviction
- Only evicts pages from same process

### 4. Per-Process Swapping
- Each process has swap file `/pgswpXXXXX` (PID-based)
- `swap_out_page()`: Saves dirty page to swap storage
- `swap_in_page()`: Restores page from swap
- Max 1024 slots per process (4MB)
- If swap full when evicting dirty page → kill process
- Swap cleaned up on process exit

### 5. Modified sbrk()
- `growproc()` only adjusts `p->sz`
- No physical page allocation
- Pages allocated on first access via page fault

### 6. memstat() System Call
- Reports process memory state
- Shows which pages are resident/swapped/unmapped
- Exposes FIFO sequences and dirty bits
- Used for testing and debugging

## Key Data Structures Added

**In proc.h**:
- `lazy_segs[]` - Stores executable segment info for lazy loading
- `resident_pages[]` - Tracks in-memory pages with FIFO seq
- `swapped_pages[]` - Stores actual swapped page data (simulated swap)
- `swap_slots[]` - Bitmap of used/free swap slots
- `pf_seq` - Global FIFO sequence counter per process

## Critical Functions

**vm.c**:
- `demand_page_load_new()` - Main page fault handler
- `find_victim_page()` - FIFO victim selection
- `swap_out_page()` / `swap_in_page()` - Swap operations
- `add_resident_page()` / `remove_resident_page()` - Resident set management
- `init_swap_file()` / `cleanup_swap_file()` - Swap lifecycle

**exec.c**:
- Modified to NOT call `loadseg()`
- Records segments in `lazy_segs[]` instead
- Allocates only one stack page

**trap.c**:
- Page fault causes (12, 13, 15) call `demand_page_load_new()`
- Returns to user on success, kills process on failure

**sysproc.c**:
- `sys_memstat()` - Fills struct with memory state
- `growproc()` - Modified to only adjust size

## Logging Format

All operations logged exactly as specified:
- `PAGEFAULT` → `ALLOC/LOADEXEC/SWAPIN` → `RESIDENT`
- `MEMFULL` → `VICTIM` → `EVICT` → `SWAPOUT/DISCARD`
- `KILL invalid-access` / `KILL swap-exhausted`
- `SWAPCLEANUP` on exit

## How It Works

1. Process starts with minimal memory
2. Access to unmapped page triggers page fault
3. Handler determines if valid (text/data/heap/stack/swap)
4. If valid: allocate/load page, add to resident set
5. If memory full: find FIFO victim, evict (swap if dirty)
6. If invalid: kill process
7. On exit: cleanup swap file and resident pages