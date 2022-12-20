#include "fs/operations.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main() {

    char *path_copied_file = "/f1";
    char *link_path = "/l1";
    char *path_src_1 = "tests/file_to_copy.txt";
    char *path_src_2 = "tests/empty_file.txt";
    char *str_ext_2 = "";
    char buffer[600];

    assert(tfs_init(NULL) != -1);

    int f;
    ssize_t r;

    f = tfs_copy_from_external_fs(path_src_1, path_copied_file);
    assert(f != -1);

    f = tfs_sym_link(path_copied_file, link_path);
    assert(f != -1);

    f = tfs_copy_from_external_fs(path_src_2, link_path);
    assert(f != -1);

    f = tfs_open(path_copied_file, 0);
    assert(f != -1);

    r = tfs_read(f, buffer, sizeof(buffer) - 1);
    assert(r == strlen(str_ext_2));
    assert(!memcmp(buffer, str_ext_2, strlen(str_ext_2)));

    tfs_close(f);

    assert(tfs_destroy() == 0);

    printf("Successful test.\n");

    return 0;
}
