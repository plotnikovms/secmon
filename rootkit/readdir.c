#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    const char *path = ".";

    if (argc >= 2)
        path = argv[1];

    DIR *dir = opendir(path);
    if (dir == NULL) {
        fprintf(stderr, "opendir(%s) failed: %s\n", path, strerror(errno));
        return 1;
    }

    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        printf("%s\n", entry->d_name);
    }

    closedir(dir);
    return 0;
}
