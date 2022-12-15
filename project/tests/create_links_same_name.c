#include "fs/operations.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main() {

    char *path_copied_file = "/f1";

    assert(tfs_init(NULL) != -1);

    int f;

    f = tfs_open(path_copied_file, TFS_O_CREAT);
    assert(f != -1);
    tfs_close(f);

    f = tfs_link(path_copied_file, path_copied_file);
    assert(f == -1);

    f = tfs_sym_link(path_copied_file, path_copied_file);
    assert(f == -1);

    assert(tfs_destroy() == 0);

    printf("Successful test.\n");

    return 0;
}
