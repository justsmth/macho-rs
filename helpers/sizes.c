#include <stdio.h>
#include <mach-o/loader.h>

int main(void) {
    printf("Sizeof mach_header_64: %d\n", sizeof(struct mach_header_64));
    printf("Sizeof segment_command_64: %d\n", sizeof(struct segment_command_64));
}
