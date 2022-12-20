#include "fs/operations.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N_THREADS 16
#define MAX_NAME 5
#define TARGET "/f0"

char *paths[N_THREADS + 1] = {"/f0",  "/f1",  "/f2",  "/f3",  "/f4",  "/f5",
                              "/f6",  "/f7",  "/f8",  "/f9",  "/f10", "/f11",
                              "/f12", "/f13", "/f14", "/f15", "/f16"};

void *create_link(void *arg) {
    const char *path = (char *)arg;

    assert((tfs_link(TARGET, path)) != -1);

    return NULL;
}

void *delete_link(void *arg) {
    const char *path = (char *)arg;

    assert((tfs_unlink(path)) != -1);

    return NULL;
}

/* This test creates links to the same file in several threads, and then unlinks
them all in different threads as well. */
int main() {

    pthread_t tid[N_THREADS + 1];
    char *src = "tests/file_to_copy.txt";

    assert(tfs_init(NULL) != -1);

    // create the file
    assert(tfs_copy_from_external_fs(src, TARGET) == 0);

    // create the links
    for (int i = 1; i < N_THREADS + 1; i++) {
        assert(pthread_create(&tid[i], NULL, create_link, (void *)paths[i]) ==
               0);
    }

    for (int i = 1; i < N_THREADS + 1; i++) {
        // wait for all threads to finish
        assert(pthread_join(tid[i], NULL) == 0);
    }

    for (int i = 0; i < N_THREADS + 1; i++) {
        // delete all the links, including the original file
        assert(pthread_create(&tid[i], NULL, delete_link, (void *)paths[i]) ==
               0);
    }

    for (int i = 0; i < N_THREADS + 1; i++) {
        // wait for all threads to finish
        assert(pthread_join(tid[i], NULL) == 0);
    }

    // confirm that all links got deleted (and the file aswell)
    int f;
    assert(tfs_link(TARGET, "error") == -1); // target doesn't exist anymore
    assert((f = tfs_open(TARGET, 0)) == -1);

    assert(tfs_destroy() == 0);

    printf("Successful test.\n");

    return 0;
}
