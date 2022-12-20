#include "fs/operations.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N_THREADS 32
#define PATH "/f1"

typedef struct {
    int fhandle;
    char *str;
} data;

ssize_t bytes_read = 0;
pthread_mutex_t bytes_read_lock = PTHREAD_MUTEX_INITIALIZER;

void *_write(void *arg) {
    const data *args = (data *)arg;
    int fhandle = args->fhandle;
    char *str = args->str;

    assert(tfs_write(fhandle, str, strlen(str)) == strlen(str));

    return NULL;
}

void *_read(void *arg) {
    const data *args = (data *)arg;
    int fhandle = args->fhandle;
    char *str = args->str;
    char buffer[strlen(str)];
    ssize_t bytes;

    assert((bytes = tfs_read(fhandle, buffer, strlen(str))) == strlen(str));
    assert(pthread_mutex_lock(&bytes_read_lock) == 0);
    bytes_read += bytes;
    assert(pthread_mutex_unlock(&bytes_read_lock) == 0);

    return NULL;
}

/* This test tries to write and then read different number of bytes at the same
time in multiple threads. We need to make sure that, at the end, the number of
chars written/read in total are the expected (1024) */
int main() {

    pthread_t tid[N_THREADS];
    char buffer[1024 + 1];
    // block size = 1024, if we divide 1024 by 16, we get 64. Since we want to
    // be writing/reading different number of bytes, we can separate in 2 sizes,
    // 42 and 22 (for example). Half of the threads will be using 42, others 22.
    // Because we divided by 16, we will need 32 threads.
    char *str_42 = "..........................................";
    char *str_22 = "......................";

    assert(tfs_init(NULL) != -1);

    int f;
    assert((f = tfs_open(PATH, TFS_O_CREAT)) != -1);

    data data_42 = {.fhandle = f, .str = str_42};
    data data_22 = {.fhandle = f, .str = str_22};

    // threads that will write
    for (int i = 0; i < N_THREADS; i = i + 2) {
        assert(pthread_create(&tid[i], NULL, _write, (void *)&data_42) == 0);
        assert(pthread_create(&tid[i + 1], NULL, _write, (void *)&data_22) ==
               0);
    }

    for (int i = 0; i < N_THREADS; i++) {
        // wait for all threads to finish
        assert(pthread_join(tid[i], NULL) == 0);
    }

    // reset the offset to zero
    assert(tfs_close(f) == 0);
    assert((f = tfs_open(PATH, TFS_O_CREAT)) != -1);

    // threads that will read. Every thread will add the amount of bytes they
    // read to bytes_read
    for (int i = 0; i < N_THREADS; i = i + 2) {
        assert(pthread_create(&tid[i], NULL, _read, (void *)&data_42) == 0);
        assert(pthread_create(&tid[i + 1], NULL, _read, (void *)&data_22) == 0);
    }

    for (int i = 0; i < N_THREADS; i++) {
        // wait for all threads to finish
        assert(pthread_join(tid[i], NULL) == 0);
    }

    assert(bytes_read == 1024);
    assert(tfs_close(f) == 0);

    // check file content
    assert((f = tfs_open(PATH, TFS_O_CREAT)) != -1);

    assert(tfs_read(f, buffer, sizeof(buffer)) == 1024);

    assert(tfs_destroy() == 0);

    printf("Successful test.\n");

    return 0;
}
