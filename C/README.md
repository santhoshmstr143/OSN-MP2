# Office Bakery: Multi-threaded Simulation

Concurrent programming simulation of an office bakery using POSIX threads to manage shared resources.

## Problem Statement

Office bakery with limited resources:
- 4 ovens, 4 chefs, 1 cash register
- 4 sofa seats, standing room available
- Maximum 25 customers capacity

## Building and Running

```bash
gcc -pthread -o bakery bakery.c
./bakery < input.txt
```

Input format:
```
5 Customer 1
7 Customer 2
<EOF>
```

## How It Works

### Customer Flow
1. Enter (1 sec) → 2. Sit (1 sec) → 3. Request cake → 4. Wait for baking → 5. Pay → 6. Wait for payment → 7. Leave

### Chef Behavior
- Priority 1: Accept payment (2 sec, uses cash register)
- Priority 2: Bake cake (2 sec, uses oven)
- Chefs prioritize payments over baking

### Resource Constraints
- **Sofa (4 seats)**: Must sit to order, standing customers wait FIFO
- **Ovens (4)**: Max 4 concurrent bakes
- **Cash register (1)**: Only 1 payment at a time
- **Capacity (25)**: Reject entry if full

## Implementation

### Thread Types
- **Customer threads**: One per customer, follows lifecycle
- **Chef threads**: 4 workers, event-driven
- **Timer thread**: Advances time every 1 second

### Synchronization
**Mutex**: Single global lock for all shared state

**Condition Variables**:
- `time_tick` - Time advancement signal
- `sofa_available` - Sofa seat opened
- `work_available` - Work ready for chefs

### Key Data Structures
**Queues**: `standing[]`, `on_sofa[]`, `waiting_payment[]`

**Counters**: `sofa_count`, `ovens_used`, `chefs_idle`, `cashier_free`

**State Arrays**: Track each customer's progress through system

### Timing Rules
- Customer actions: 1 second (enter, sit)
- Chef actions: 2 seconds (bake, payment)
- Actions are atomic (cannot be interrupted)
- Thread waits on condition variable during action duration

### FIFO Ordering
- Longest standing customer gets next sofa seat
- Longest waiting seated customer gets served first
- First to pay gets payment processed first

## Output Format
```
<time> <actor> <id> <action> [target]
```

Example:
```
5 Customer 1 enters
6 Customer 1 sits
6 Customer 1 requests cake
6 Chef 2 bakes for Customer 1
8 Customer 1 pays
8 Chef 3 accepts payment for Customer 1
10 Customer 1 leaves
```

## What I Implemented

**Thread coordination**: Multiple customer threads, 4 chef worker threads, timer thread

**Resource management**: Limited sofa seats, ovens, and cash register with proper allocation

**Synchronization**: Mutex and condition variables for thread-safe access and waiting

**Priority handling**: Chefs prioritize payment over baking

**FIFO queues**: Standing, seated, and payment queues with proper ordering

**Atomic actions**: All actions complete fully without interruption

**Timing simulation**: Timer thread advances global clock, threads wait for their action duration

**State tracking**: Arrays track customer progress through each stage

**Graceful termination**: All threads cleanup properly when simulation ends