#include "fs/operations.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define MAX_OPEN_FILES 1000

void *thread_fn(void *arg) {
    int f;
    const char *path = (char *)arg;
    const char buffer[] = "ABC";
    char out[20];

    assert((f = tfs_open(path, TFS_O_CREAT)) != -1);

    assert(tfs_write(f, buffer, sizeof(buffer)) == sizeof(buffer));

    assert(tfs_close(f) == 0);

    assert((f = tfs_open(path, TFS_O_CREAT)) != -1);

    assert(tfs_read(f, out, sizeof(out)) == sizeof(buffer));
    assert(!memcmp(buffer, out, sizeof(buffer)));

    return NULL;
}

/* This test creates a file and then opens it a large amount of times. Every
thread writes to and reads from the file to make sure that the open file entries
are not being shared/corrupted and the offset is as it should be. */
int main() {

    pthread_t tid[MAX_OPEN_FILES];
    char *path_1 = "/f1";

    tfs_params params = tfs_default_params();
    params.max_open_files_count = MAX_OPEN_FILES;

    assert(tfs_init(&params) != -1);

    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        assert(pthread_create(&tid[i], NULL, thread_fn, (void *)path_1) == 0);
    }

    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        // wait for all threads to finish before destroying fs
        assert(pthread_join(tid[i], NULL) == 0);
    }

    assert(tfs_destroy() == 0);

    printf("Successful test.\n");

    return 0;
}
