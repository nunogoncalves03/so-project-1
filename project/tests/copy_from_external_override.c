#include "fs/operations.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main() {

    char *path_copied_file = "/f1";
    char *path_src_1 = "tests/file_to_copy.txt";
    char *str_ext_1 = "BBB!";
    char *path_src_2 = "tests/file_to_copy_over512.txt";
    char *str_ext_2 = "BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! "
        "BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! "
        "BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! "
        "BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! "
        "BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! "
        "BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! "
        "BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! BBB! "
        "BBB! BBB! BBB! BBB! BBB! ";
    char buffer[600];


    assert(tfs_init(NULL) != -1);

    int f, f2;
    ssize_t r;

    f = tfs_copy_from_external_fs(path_src_1, path_copied_file);
    assert(f != -1);

    f = tfs_open(path_copied_file, TFS_O_CREAT);
    assert(f != -1);

    r = tfs_read(f, buffer, sizeof(buffer) - 1);
    assert(r == strlen(str_ext_1));
    assert(!memcmp(buffer, str_ext_1, strlen(str_ext_1)));

    tfs_close(f);

    f2 = tfs_copy_from_external_fs(path_src_2, path_copied_file);
    assert(f2 != -1);

    memset(buffer, 0, sizeof(buffer));
    
    f = tfs_open(path_copied_file, TFS_O_CREAT);
    assert(f != -1);

    r = tfs_read(f, buffer, sizeof(buffer) - 1);
    assert(r == strlen(str_ext_2));
    assert(!memcmp(buffer, str_ext_2, strlen(str_ext_2)));

    printf("Successful test.\n");

    return 0;
}
