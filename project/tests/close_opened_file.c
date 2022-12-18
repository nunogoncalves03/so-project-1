#include "../fs/operations.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main() {
    const char *file_path = "/f1";
    const char *link_path = "/l1";
    const char *link_path_2 = "/l2";

    assert(tfs_init(NULL) != -1);

    // Create file
    int fd = tfs_open(file_path, TFS_O_CREAT);
    assert(fd != -1);

    // Can't unlink file, since it's opened
    assert(tfs_unlink(file_path) == -1);

    // Create a hard link
    assert(tfs_link(file_path, link_path) == 0);

    // Unlink the original
    assert(tfs_unlink(file_path) == 0);

    // Create a symlink to l1
    assert(tfs_sym_link(link_path, link_path_2) == 0);

    // Symlink can be deleted since it only points to the opened file
    assert(tfs_unlink(link_path_2) == 0);

    // Can't delete l1, since it's the only hard link to the original file, and
    // it is still opened
    assert(tfs_unlink(link_path) == -1);

    // Close the file
    assert(tfs_close(fd) == 0);

    // Unlinking is now allowed
    assert(tfs_unlink(link_path) == 0);

    // Prove that the original file no longer exists
    assert(tfs_open(file_path, 0) == -1);
    assert(tfs_open(link_path, 0) == -1);

    assert(tfs_destroy() == 0);

    printf("Successful test.\n");
}
