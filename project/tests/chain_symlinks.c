#include "../fs/operations.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main() {
    const char *file_path = "/f1";
    const char *file_path_2 = "/f2";
    const char *link_path_1 = "/l1";
    const char *link_path_2 = "/l2";
    const char *link_path_3 = "/l3";
    const char *str_to_write = "12345";
    const char *str_to_write_2 = "6789";
    char buffer[600];

    assert(tfs_init(NULL) != -1);

    int fd = tfs_open(file_path, TFS_O_CREAT);
    assert(fd != -1);

    // Immediately close file
    assert(tfs_close(fd) != -1);

    // Create symbolic links
    assert(tfs_sym_link(file_path, link_path_1) == 0);

    assert(tfs_sym_link(link_path_1, link_path_2) == 0);

    assert(tfs_sym_link(link_path_2, link_path_3) == 0);

    // Remove original file
    assert(tfs_unlink(file_path) != -1);

    // Link unusable - target no longer exists
    assert(tfs_open(link_path_1, TFS_O_APPEND) == -1);

    assert(tfs_open(link_path_3, TFS_O_APPEND) == -1);

    // Create new file with same filename
    fd = tfs_open(file_path, TFS_O_CREAT);
    assert(fd != -1);

    assert(tfs_close(fd) != -1);

    // Link usable again - target was recreated
    assert(tfs_open(link_path_1, TFS_O_APPEND) != -1);

    assert(tfs_open(link_path_3, TFS_O_APPEND) != -1);

    // Write through link2
    assert((fd = tfs_open(link_path_2, TFS_O_CREAT)) != -1);
    assert(tfs_write(fd, str_to_write, strlen(str_to_write)) ==
           strlen(str_to_write));
    assert(tfs_close(fd) != -1);

    // Read through link3
    assert((fd = tfs_open(link_path_3, TFS_O_CREAT)) != -1);
    assert(tfs_read(fd, buffer, sizeof(buffer)) == strlen(str_to_write));
    assert(!memcmp(buffer, str_to_write, strlen(str_to_write)));
    assert(tfs_close(fd) != -1);

    // Remove link2
    assert(tfs_unlink(link_path_2) == 0);

    // link1 still usable
    assert(tfs_open(link_path_1, TFS_O_APPEND) != -1);

    // link3 broken
    assert(tfs_open(link_path_3, TFS_O_APPEND) == -1);

    // Create file2 and write str_to_write2
    assert((fd = tfs_open(file_path_2, TFS_O_CREAT)) != -1);
    assert(tfs_write(fd, str_to_write_2, strlen(str_to_write_2)) ==
           strlen(str_to_write_2));
    assert(tfs_close(fd) != -1);

    // Create link2 but now targeting path2
    assert(tfs_sym_link(file_path_2, link_path_2) == 0);

    memset(buffer, 0, sizeof(buffer));

    // Read through link3 the contents of file2 (link3 still points to link2)
    assert((fd = tfs_open(link_path_3, TFS_O_CREAT)) != -1);
    assert(tfs_read(fd, buffer, sizeof(buffer)) == strlen(str_to_write_2));
    assert(!memcmp(buffer, str_to_write_2, strlen(str_to_write_2)));

    memset(buffer, 0, sizeof(buffer));

    // Confirm that link1 still points to path1 and the content is str_to_write
    assert((fd = tfs_open(link_path_1, TFS_O_CREAT)) != -1);
    assert(tfs_read(fd, buffer, sizeof(buffer)) == strlen(str_to_write));
    assert(!memcmp(buffer, str_to_write, strlen(str_to_write)));

    printf("Successful test.\n");
}
