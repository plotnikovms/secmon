#include "checks.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int suspicious_count = 0;

static int port_is_suspicious(unsigned int port) {
    switch (port) {
    case 1337:
    case 31337:
    case 4444:
    case 5555:
    case 6666:
    case 12345:
    case 54321:
        return 1;
    default:
        return 0;
    }
}

static void format_ipv4_address(unsigned int raw_address, char *buffer, size_t buffer_size) {
    unsigned char bytes[4];

    bytes[0] = raw_address & 0xff;
    bytes[1] = (raw_address >> 8) & 0xff;
    bytes[2] = (raw_address >> 16) & 0xff;
    bytes[3] = (raw_address >> 24) & 0xff;

    snprintf(
        buffer,
        buffer_size,
        "%u.%u.%u.%u",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3]
    );
}

static int ipv4_is_any_address(unsigned int raw_address) {
    return raw_address == 0;
}

static void check_tcp_file(const char *path) {
    FILE *file;
    char line[1024];

    file = fopen(path, "r");
    if (!file) {
        printf("INFO: failed to open %s: %s\n", path, strerror(errno));
        return;
    }

    printf("Scanning %s\n", path);

    if (!fgets(line, sizeof(line), file)) {
        fclose(file);
        return;
    }

    while (fgets(line, sizeof(line), file)) {
        unsigned int local_address;
        unsigned int local_port;
        unsigned int remote_address;
        unsigned int remote_port;
        unsigned int state;
        unsigned long inode;
        char local_ip[64];
        char remote_ip[64];

        int parsed = sscanf(
            line,
            " %*d: %x:%x %x:%x %x %*s %*s %*s %*s %*s %lu",
            &local_address,
            &local_port,
            &remote_address,
            &remote_port,
            &state,
            &inode
        );

        if (parsed != 6) {
            continue;
        }

        if (state != 0x0A) {
            continue;
        }

        format_ipv4_address(local_address, local_ip, sizeof(local_ip));
        format_ipv4_address(remote_address, remote_ip, sizeof(remote_ip));

        printf(
            "INFO: TCP LISTEN %s:%u inode=%lu\n",
            local_ip,
            local_port,
            inode
        );

        if (ipv4_is_any_address(local_address)) {
            printf(
                "INFO: TCP port %u listens on all IPv4 interfaces\n",
                local_port
            );
        }

        if (port_is_suspicious(local_port)) {
            suspicious_count++;

            printf(
                "SUSPICIOUS: TCP port %u is commonly used by backdoors\n",
                local_port
            );
        }
    }

    fclose(file);
}

static void check_udp_file(const char *path) {
    FILE *file;
    char line[1024];

    file = fopen(path, "r");
    if (!file) {
        printf("INFO: failed to open %s: %s\n", path, strerror(errno));
        return;
    }

    printf("Scanning %s\n", path);

    if (!fgets(line, sizeof(line), file)) {
        fclose(file);
        return;
    }

    while (fgets(line, sizeof(line), file)) {
        unsigned int local_address;
        unsigned int local_port;
        unsigned int remote_address;
        unsigned int remote_port;
        unsigned int state;
        unsigned long inode;
        char local_ip[64];

        int parsed = sscanf(
            line,
            " %*d: %x:%x %x:%x %x %*s %*s %*s %*s %*s %lu",
            &local_address,
            &local_port,
            &remote_address,
            &remote_port,
            &state,
            &inode
        );

        if (parsed != 6) {
            continue;
        }

        format_ipv4_address(local_address, local_ip, sizeof(local_ip));

        printf(
            "INFO: UDP socket %s:%u inode=%lu\n",
            local_ip,
            local_port,
            inode
        );

        if (ipv4_is_any_address(local_address)) {
            printf(
                "INFO: UDP port %u listens on all IPv4 interfaces\n",
                local_port
            );
        }

        if (port_is_suspicious(local_port)) {
            suspicious_count++;

            printf(
                "SUSPICIOUS: UDP port %u is commonly used by backdoors\n",
                local_port
            );
        }
    }

    fclose(file);
}

void network_check(void) {
    suspicious_count = 0;

    printf("Checking network sockets for possible backdoors...\n");

    check_tcp_file("/proc/net/tcp");
    check_udp_file("/proc/net/udp");

    if (suspicious_count == 0) {
        printf("OK: no suspicious network sockets found\n");
    } else {
        printf("WARNING: suspicious network sockets found: %d\n", suspicious_count);
    }
}
