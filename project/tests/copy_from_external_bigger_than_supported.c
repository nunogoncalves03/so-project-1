#include "fs/operations.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main() {

    char *path_copied_file = "/f1";
    char *path_src = "tests/file_to_copy_1025.txt";

    assert(tfs_init(NULL) != -1);

    int f;

    // can't copy bigger file than supported
    f = tfs_copy_from_external_fs(path_src, path_copied_file);
    assert(f == -1);

    assert(tfs_destroy() == 0);

    // now create a new TFS with max block size = 1025

    tfs_params params = tfs_default_params();
    params.block_size = 1025;

    assert(tfs_init(&params) != -1);

    f = tfs_copy_from_external_fs(path_src, path_copied_file);
    assert(f != -1);

    assert(tfs_destroy() == 0);

    printf("Successful test.\n");

    return 0;
}
