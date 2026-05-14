#include <stdio.h>

#include "checks.h"

int main(void) {
    printf("=== SECMON USERSPACE REPORT ===\n\n");

    printf("[1] Autoload / persistence check\n");
    autoload_check();
    printf("\n");

    printf("[2] Network backdoor check\n");
    network_check();
    printf("\n");

    printf("=== END OF USERSPACE REPORT ===\n");

    return 0;
}
