#include "checks.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int suspicious_count = 0;

static int path_exists(const char *path) {
    struct stat path_stat;

    return stat(path, &path_stat) == 0;
}

static int path_is_regular_file(const char *path) {
    struct stat path_stat;

    if (stat(path, &path_stat) != 0) {
        return 0;
    }

    return S_ISREG(path_stat.st_mode);
}

static int path_is_directory(const char *path) {
    struct stat path_stat;

    if (stat(path, &path_stat) != 0) {
        return 0;
    }

    return S_ISDIR(path_stat.st_mode);
}

static int file_is_non_empty(const char *path) {
    struct stat path_stat;

    if (stat(path, &path_stat) != 0) {
        return 0;
    }

    return path_stat.st_size > 0;
}

static void check_sensitive_file(
    const char *path,
    const char *description,
    int suspicious_if_exists,
    int suspicious_if_non_empty
) {
    if (!path_exists(path)) {
        printf("OK: %s does not exist\n", path);
        return;
    }

    if (!path_is_regular_file(path)) {
        printf("INFO: %s exists, but is not a regular file\n", path);
        return;
    }

    printf("INFO: %s exists (%s)\n", path, description);

    if (suspicious_if_exists) {
        ++suspicious_count;
        printf("SUSPICIOUS: %s exists\n", path);
        return;
    }

    if (suspicious_if_non_empty && file_is_non_empty(path)) {
        ++suspicious_count;
        printf("SUSPICIOUS: %s is non-empty\n", path);
    }
}

static void check_directory_exists(const char *path, const char *description) {
    if (!path_exists(path)) {
        printf("INFO: %s does not exist\n", path);
        return;
    }

    if (!path_is_directory(path)) {
        ++suspicious_count;
        printf("SUSPICIOUS: %s exists, but is not a directory\n", path);
        return;
    }

    printf("INFO: %s exists (%s)\n", path, description);
}

static int name_is_hidden_or_suspicious(const char *name) {
    if (name[0] == '.') {
        return 1;
    }

    if (strstr(name, "rootkit") != NULL) {
        return 1;
    }

    if (strstr(name, "backdoor") != NULL) {
        return 1;
    }

    if (strstr(name, "hide") != NULL) {
        return 1;
    }

    if (strstr(name, "stealth") != NULL) {
        return 1;
    }

    return 0;
}

static void check_directory_entries(const char *path, const char *description) {
    DIR *directory;
    struct dirent *entry;
    int entry_count = 0;

    directory = opendir(path);
    if (!directory) {
        if (errno == ENOENT) {
            printf("INFO: %s does not exist\n", path);
        } else {
            printf("INFO: failed to open %s: %s\n", path, strerror(errno));
        }

        return;
    }

    printf("Scanning directory: %s (%s)\n", path, description);

    while ((entry = readdir(directory)) != NULL) {
        char full_path[4096];
        struct stat entry_stat;

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        ++entry_count;

        snprintf(
            full_path,
            sizeof(full_path),
            "%s/%s",
            path,
            entry->d_name
        );

        if (lstat(full_path, &entry_stat) != 0) {
            printf("INFO: failed to stat %s: %s\n", full_path, strerror(errno));
            continue;
        }

        printf("INFO: found %s\n", full_path);

        if (name_is_hidden_or_suspicious(entry->d_name)) {
            ++suspicious_count;
            printf("SUSPICIOUS: suspicious autoload entry name: %s\n", full_path);
        }

        if (S_ISLNK(entry_stat.st_mode)) {
            printf("INFO: %s is a symlink\n", full_path);
        }

        if (S_ISREG(entry_stat.st_mode) && (entry_stat.st_mode & S_IXUSR)) {
            printf("INFO: %s is executable\n", full_path);
        }
    }

    if (entry_count == 0) {
        printf("INFO: %s is empty\n", path);
    }

    closedir(directory);
}

void autoload_check(void) {
    suspicious_count = 0;

    printf("Checking autoload and persistence locations...\n");

    check_sensitive_file(
        "/etc/ld.so.preload",
        "forces dynamic linker to preload shared libraries",
        1,
        0
    );

    check_sensitive_file(
        "/etc/rc.local",
        "legacy startup script",
        0,
        1
    );

    check_sensitive_file(
        "/etc/crontab",
        "system-wide cron table",
        0,
        0
    );

    check_sensitive_file(
        "/etc/modules",
        "kernel modules loaded at boot",
        0,
        1
    );

    check_directory_exists(
        "/etc/modules-load.d",
        "kernel modules loaded at boot"
    );

    check_directory_exists(
        "/etc/modprobe.d",
        "kernel module options and aliases"
    );

    check_directory_exists(
        "/etc/cron.d",
        "system cron jobs"
    );

    check_directory_exists(
        "/etc/systemd/system",
        "systemd unit overrides and custom services"
    );

    printf("\n");

    check_directory_entries(
        "/etc/modules-load.d",
        "kernel module autoload configs"
    );

    check_directory_entries(
        "/etc/modprobe.d",
        "kernel module config files"
    );

    check_directory_entries(
        "/etc/cron.d",
        "cron persistence entries"
    );

    check_directory_entries(
        "/etc/systemd/system",
        "systemd persistence entries"
    );

    printf("\n");

    if (suspicious_count == 0) {
        printf("OK: no suspicious autoload entries found\n");
    } else {
        printf("WARNING: suspicious autoload entries found: %d\n", suspicious_count);
    }
}
