#include "cshark.h"

volatile sig_atomic_t stop_sniffing = 0;
volatile sig_atomic_t exit_program = 0;
int g_datalink_type = 0;

int main() {
    char selected_dev[256];
    int menu_choice = 0;
    
    signal(SIGINT, sigint_handler);
    
    while (!exit_program) {
        if (select_interface(selected_dev, sizeof(selected_dev)) == -1) {
            break;
        }
        
        while (!exit_program) {
            printf("\n[C-Shark] Interface '%s' selected. What's next?\n\n", selected_dev);
            printf("1. Start Sniffing (All Packets)\n");
            printf("2. Start Sniffing (With Filters)\n");
            printf("3. Inspect Last Session\n");
            printf("4. Exit C-Shark\n\n");
            printf("Enter choice: ");
            
            if (scanf("%d", &menu_choice) != 1) {
                printf("\nExiting C-Shark...\n");
                exit_program = 1;
                break;
            }
            
            // Clear input buffer
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF);
            
            switch (menu_choice) {
                case 1:
                    start_sniffing_all(selected_dev);
                    break;
                    
                case 2:
                    start_sniffing_filtered(selected_dev);
                    break;
                    
                case 3:
                    inspect_last_session();
                    break;
                    
                case 4:
                    printf("\n[C-Shark] Cleaning up and exiting...\n");
                    clear_packet_storage();
                    printf("Thank you for using C-Shark!\n");
                    exit_program = 1;
                    break;
                    
                default:
                    printf("Invalid choice. Please try again.\n");
            }
        }
    }
    
    return 0;
}