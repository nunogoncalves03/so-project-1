#include "fs/operations.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main() {

    char *link_name = "/l1";
    const char *str = "123";
    char buffer[4];

    assert(tfs_init(NULL) != -1);

    int f;
    ssize_t r;

    // link to a non existing file
    f = tfs_sym_link("/x", link_name);
    assert(f == 0);

    // create that target
    f = tfs_open("/x", TFS_O_CREAT);
    assert(f == 0);

    // write str to target
    r = tfs_write(f, str, strlen(str));
    assert(r == strlen(str));

    assert(tfs_close(f) == 0);

    // read str from link
    f = tfs_open(link_name, 0);
    assert(tfs_read(f, buffer, sizeof(buffer)) == r);
    assert(!memcmp(buffer, str, strlen(str)));

    assert(tfs_close(f) == 0);

    assert(tfs_destroy() == 0);

    printf("Successful test.\n");

    return 0;
}
