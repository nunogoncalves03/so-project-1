#include "fs/operations.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main() {

    char *path_1 = "/f1";
    char *path_2 = "/f2";
    char *path_src = "tests/file_to_copy.txt";

    tfs_params params = tfs_default_params();
    params.max_inode_count = 2;      // root + 1 file to be created
    params.max_open_files_count = 1; // only 1 file opened at a time

    assert(tfs_init(&params) != -1);

    int f, f2;

    // the only file to exist in the fs
    f = tfs_copy_from_external_fs(path_src, path_1);
    assert(f != -1);

    // try to create more files
    f = tfs_open(path_2, TFS_O_CREAT);
    assert(f == -1);

    // create hardlinks (use the same inode, so the capacity isn't exceeded)
    f2 = tfs_link(path_1, path_2);
    assert(f2 == 0);

    // open the new link (should be no problem, since the last open failed)
    f2 = tfs_open(path_2, TFS_O_CREAT);
    assert(f2 != -1);

    // can't open more files
    f = tfs_open(path_1, TFS_O_CREAT);
    assert(f == -1);

    // can't create symlinks, since they take 1 inode
    f = tfs_sym_link(path_1, "fail");
    assert(f == -1);

    // close file2
    assert(tfs_close(f2) == 0);

    // delete file2
    f = tfs_unlink(path_2);
    assert(f == 0);

    // still can't create more files (there's still a hardlink for the 1st file)
    f2 = tfs_open(path_2, TFS_O_CREAT);
    assert(f2 == -1);

    // delete the last hardlink
    f = tfs_unlink(path_1);
    assert(f == 0);

    // create a new file
    f = tfs_open(path_1, TFS_O_CREAT);
    assert(f != -1);

    assert(tfs_destroy() == 0);

    printf("Successful test.\n");

    return 0;
}
