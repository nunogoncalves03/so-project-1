#include "../fs/operations.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main() {
    const char *file_path = "/f1";
    const char *link_path_1 = "/l1";
    const char *str = "123";
    char buffer[0];

    assert(tfs_init(NULL) == 0);

    int fd = tfs_open(file_path, TFS_O_CREAT);
    assert(fd != -1);

    // Write str to file
    assert(tfs_write(fd, str, strlen(str)) == strlen(str));

    // Close file
    assert(tfs_close(fd) != -1);

    // Create symbolic link
    assert(tfs_sym_link(file_path, link_path_1) == 0);

    // Remove original file
    assert(tfs_unlink(file_path) != -1);

    // Link unusable - target no longer exists
    assert(tfs_open(link_path_1, TFS_O_APPEND) == -1);

    // Recreate target through opening link_path_1 with CREAT mode
    fd = tfs_open(link_path_1, TFS_O_CREAT);
    assert(fd != -1);

    // Confirm target is created and has no content
    assert(tfs_read(fd, buffer, sizeof(buffer)) == sizeof(buffer));

    assert(tfs_close(fd) != -1);

    // Link usable again - target was recreated
    assert(tfs_open(link_path_1, TFS_O_APPEND) != -1);

    assert(tfs_destroy() == 0);

    printf("Successful test.\n");

    return 0;
}
