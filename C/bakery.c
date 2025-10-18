// ############## LLM Generated Code Begins ##############
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#define MAX_CUSTOMERS 25
#define MAX_CHEFS 4
#define MAX_SOFA 4
#define MAX_OVENS 4

typedef struct {
    int id;
    int arrival_time;
    int idx;
} CustomerInput;

// Global state
CustomerInput customers[MAX_CUSTOMERS];
int num_customers = 0;
int start_time = 0;
int current_time = 0;

// Synchronization
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t time_tick = PTHREAD_COND_INITIALIZER;
pthread_cond_t sofa_available = PTHREAD_COND_INITIALIZER;
pthread_cond_t work_available = PTHREAD_COND_INITIALIZER;

// State tracking
int customers_inside = 0;
int customers_finished = 0;
int sofa_count = 0;
int ovens_used = 0;
int cashier_free = 1;
int chefs_idle = MAX_CHEFS;

// Queues - using arrays with head/tail pointers
int standing[MAX_CUSTOMERS], standing_head = 0, standing_tail = 0;
int on_sofa[MAX_CUSTOMERS], sofa_head = 0, sofa_tail = 0;
int waiting_payment[MAX_CUSTOMERS], payment_head = 0, payment_tail = 0;

// Customer states
int entered[MAX_CUSTOMERS] = {0};
int seated[MAX_CUSTOMERS] = {0};
int requested[MAX_CUSTOMERS] = {0};
int request_time[MAX_CUSTOMERS] = {0};
int baking[MAX_CUSTOMERS] = {0};
int ready_to_pay[MAX_CUSTOMERS] = {0};
int paid[MAX_CUSTOMERS] = {0};
int payment_time[MAX_CUSTOMERS] = {0};
int done[MAX_CUSTOMERS] = {0};

int simulation_done = 0;

void safe_print(int time, const char* actor, int id, const char* action, int target) {
    if (target >= 0)
        printf("%d %s %d %s Customer %d\n", time, actor, id, action, target);
    else
        printf("%d %s %d %s\n", time, actor, id, action);
    fflush(stdout);
}

void* customer_thread(void* arg) {
    int idx = *(int*)arg;
    free(arg);
    
    int cust_id = customers[idx].id;
    int arrival = customers[idx].arrival_time;
    
    // Wait until my arrival time
    pthread_mutex_lock(&mutex);
    while (current_time < arrival) {
        pthread_cond_wait(&time_tick, &mutex);
    }
    
    // Check capacity
    if (customers_inside >= MAX_CUSTOMERS) {
        pthread_mutex_unlock(&mutex);
        return NULL;
    }
    
    // Enter (takes 1 second - complete at next tick)
    customers_inside++;
    entered[idx] = 1;
    safe_print(current_time, "Customer", cust_id, "enters", -1);
    int enter_done = current_time + 1;
    
    // Wait 1 second for enter to complete
    while (current_time < enter_done) {
        pthread_cond_wait(&time_tick, &mutex);
    }
    
    // Try to sit
    if (sofa_count < MAX_SOFA) {
        sofa_count++;
        on_sofa[sofa_tail++] = idx;
        seated[idx] = 1;
        safe_print(current_time, "Customer", cust_id, "sits", -1);
        int sit_done = current_time + 1;
        
        // Wait 1 second for sit to complete
        while (current_time < sit_done) {
            pthread_cond_wait(&time_tick, &mutex);
        }
        
        // Request cake (instant action)
        requested[idx] = 1;
        request_time[idx] = current_time;
        safe_print(current_time, "Customer", cust_id, "requests cake", -1);
        
    } else {
        // Must stand and wait
        standing[standing_tail++] = idx;
        
        // Wait for sofa seat
        while (!seated[idx]) {
            pthread_cond_wait(&sofa_available, &mutex);
        }
        
        safe_print(current_time, "Customer", cust_id, "sits", -1);
        int sit_done = current_time + 1;
        
        // Wait 1 second for sit to complete
        while (current_time < sit_done) {
            pthread_cond_wait(&time_tick, &mutex);
        }
        
        requested[idx] = 1;
        request_time[idx] = current_time;
        safe_print(current_time, "Customer", cust_id, "requests cake", -1);
    }
    
    // Wait for baking to finish
    while (!ready_to_pay[idx]) {
        pthread_cond_wait(&time_tick, &mutex);
    }
    
    // Pay (instant action - print and enqueue)
    safe_print(current_time, "Customer", cust_id, "pays", -1);
    waiting_payment[payment_tail++] = idx;
    paid[idx] = 1;
    payment_time[idx] = current_time;
    
    // Wait for payment acceptance to complete
    while (!done[idx]) {
        pthread_cond_wait(&time_tick, &mutex);
    }
    
    // Leave (instant action)
    safe_print(current_time, "Customer", cust_id, "leaves", -1);
    customers_inside--;
    customers_finished++;
    
    // Free sofa seat now that customer is leaving
    sofa_count--;
    
    // Let standing customer sit if any
    if (standing_head < standing_tail) {
        int sit_idx = standing[standing_head++];
        sofa_count++;
        on_sofa[sofa_tail++] = sit_idx;
        seated[sit_idx] = 1;
        pthread_cond_broadcast(&sofa_available);
    }
    
    if (customers_finished >= num_customers) {
        simulation_done = 1;
        pthread_cond_broadcast(&work_available);
    }
    
    pthread_mutex_unlock(&mutex);
    return NULL;
}

void* chef_thread(void* arg) {
    int chef_id = *(int*)arg;
    free(arg);
    
    pthread_mutex_lock(&mutex);
    int my_last_action_time = current_time - 1;  // Initialize so chef waits for first real tick
    pthread_mutex_unlock(&mutex);
    
    while (1) {
        pthread_mutex_lock(&mutex);
        
        // Wait until time advances past our last check (not action completion)
        while (current_time <= my_last_action_time && !simulation_done) {
            pthread_cond_wait(&time_tick, &mutex);
        }
        
        if (simulation_done && customers_finished >= num_customers) {
            pthread_mutex_unlock(&mutex);
            break;
        }
        
        int work_done = 0;
        
        // PRIORITY 1: Accept payment (only if payment was made before current time)
        if (payment_head < payment_tail && cashier_free && chefs_idle > 0) {
            int idx = waiting_payment[payment_head];
            
            // Only accept payment if it was made before this time tick
            if (payment_time[idx] < current_time) {
                payment_head++;
                cashier_free = 0;
                chefs_idle--;
                
                int cust_id = customers[idx].id;
                safe_print(current_time, "Chef", chef_id, "accepts payment for", cust_id);
                int done_time = current_time + 2;
                
                // Wait 2 seconds (keep lock to ensure atomic 2-second operation)
                while (current_time < done_time) {
                    pthread_cond_wait(&time_tick, &mutex);
                }
                
                done[idx] = 1;
                cashier_free = 1;
                chefs_idle++;
                pthread_cond_broadcast(&time_tick);
                work_done = 1;
            }
        }
        
        // PRIORITY 2: Bake cake (only if no payment work was done)
        if (!work_done) {
            int found = -1;
            for (int i = sofa_head; i < sofa_tail; i++) {
                int idx = on_sofa[i];
                // Only pick up requests from previous time ticks
                if (requested[idx] && !baking[idx] && !ready_to_pay[idx] && request_time[idx] < current_time) {
                    found = idx;
                    // Remove from sofa queue (they're being served now)
                    for (int j = i; j < sofa_tail - 1; j++) {
                        on_sofa[j] = on_sofa[j + 1];
                    }
                    sofa_tail--;
                    break;
                }
            }
            
            if (found >= 0 && ovens_used < MAX_OVENS && chefs_idle > 0) {
                int idx = found;
                ovens_used++;
                chefs_idle--;
                baking[idx] = 1;
                
                int cust_id = customers[idx].id;
                safe_print(current_time, "Chef", chef_id, "bakes for", cust_id);
                
                int bake_done = current_time + 2;
                
                // Wait 2 seconds (keep lock to ensure atomic 2-second operation)
                while (current_time < bake_done) {
                    pthread_cond_wait(&time_tick, &mutex);
                }
                
                ready_to_pay[idx] = 1;
                ovens_used--;
                chefs_idle++;
                pthread_cond_broadcast(&time_tick);
                work_done = 1;
            }
        }
        
        // Update last check time only if we didn't do work
        // If we did work, we can check again at the same time tick
        if (!work_done) {
            my_last_action_time = current_time;
        }
        
        pthread_mutex_unlock(&mutex);
    }
    
    return NULL;
}

void* timer_thread(void* arg) {
    pthread_mutex_lock(&mutex);
    
    while (customers_finished < num_customers) {
        pthread_mutex_unlock(&mutex);
        sleep(1);
        pthread_mutex_lock(&mutex);
        
        current_time++;
        pthread_cond_broadcast(&time_tick);
        pthread_cond_broadcast(&work_available);
    }
    
    pthread_mutex_unlock(&mutex);
    return NULL;
}

int main() {
    char line[256];
    
    // Read input
    while (fgets(line, sizeof(line), stdin)) {
        if (strncmp(line, "<EOF>", 5) == 0) break;
        
        int ts, id;
        char word[32];
        if (sscanf(line, "%d %31s %d", &ts, word, &id) == 3) {
            if (num_customers == 0) {
                start_time = ts;
                current_time = ts;
            }
            customers[num_customers].id = id;
            customers[num_customers].arrival_time = ts;
            customers[num_customers].idx = num_customers;
            num_customers++;
        }
    }
    
    if (num_customers == 0) return 0;
    
    // Start timer
    pthread_t timer;
    pthread_create(&timer, NULL, timer_thread, NULL);
    
    // Start chefs
    pthread_t chef_threads[MAX_CHEFS];
    for (int i = 0; i < MAX_CHEFS; i++) {
        int* id = malloc(sizeof(int));
        *id = i + 1;
        pthread_create(&chef_threads[i], NULL, chef_thread, id);
    }
    
    // Start customers
    pthread_t cust_threads[MAX_CUSTOMERS];
    for (int i = 0; i < num_customers; i++) {
        int* idx = malloc(sizeof(int));
        *idx = i;
        pthread_create(&cust_threads[i], NULL, customer_thread, idx);
    }
    
    // Wait for customers
    for (int i = 0; i < num_customers; i++) {
        pthread_join(cust_threads[i], NULL);
    }
    
    // Signal chefs to exit
    pthread_mutex_lock(&mutex);
    simulation_done = 1;
    pthread_cond_broadcast(&work_available);
    pthread_mutex_unlock(&mutex);
    
    // Wait for chefs
    for (int i = 0; i < MAX_CHEFS; i++) {
        pthread_join(chef_threads[i], NULL);
    }
    
    pthread_join(timer, NULL);
    
    return 0;
}
// ############## LLM Generated Code Ends ################