#include "fs/operations.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N_THREADS 16

void *create_file(void *arg) {
    int *f = malloc(sizeof(int));
    assert(f != NULL);

    const char *path = (char *)arg;

    assert((*f = tfs_open(path, TFS_O_CREAT)) != -1);

    return f;
}

/* This test tries to create and open the same file as many times the tfs will
support. As there can not be duplicates, the file will be only created once and
all the other threads will only open it. To make sure this is happening, after
creating/opening them all, we iterate over all the opened files and write 1 char
to each one, and at the end, read from the file to confirm that all threads
opened the same file and appended 1 char each.  */
int main() {

    pthread_t tid[N_THREADS];
    int *fhandle[N_THREADS];
    char buffer[N_THREADS + 1];
    char *path = "/f1";
    char *str = "1";

    assert(tfs_init(NULL) != -1);

    for (int i = 0; i < N_THREADS; i++) {
        assert(pthread_create(&tid[i], NULL, create_file, (void *)path) == 0);
    }

    for (int i = 0; i < N_THREADS; i++) {
        // wait for all threads to finish and save the fhandle they return in
        // its associated index at fhandle[]
        assert(pthread_join(tid[i], (void **)&fhandle[i]) == 0);
    }

    for (int i = 0; i < N_THREADS; i++) {
        // read until reaching the end of the file, then append str (1 char).
        // the number of char there are in the file at each iteration has to be
        // equal to the iteration number
        assert(tfs_read(*fhandle[i], buffer, N_THREADS + 1) == i);
        assert(tfs_write(*fhandle[i], str, 1) == 1);

        assert(tfs_close(*fhandle[i]) != -1);
        free(fhandle[i]);
    }

    int f;
    memset(buffer, 0, sizeof(buffer));

    // check file content
    assert((f = tfs_open(path, TFS_O_CREAT)) != -1);
    assert(tfs_read(f, buffer, sizeof(buffer)) == N_THREADS);

    assert(tfs_destroy() == 0);

    printf("Successful test.\n");

    return 0;
}
