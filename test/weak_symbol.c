#include <stdio.h>

// Weak variable
int global_weak_var __attribute__((weak)) = 42;

// Wrapper for weak variable
static int get_global_weak_var(void) {
    return global_weak_var;
}

int main() {
    printf("Weak variable: %d\n", get_global_weak_var());
    return 0;
}
