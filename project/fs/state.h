#ifndef STATE_H
#define STATE_H

#include "config.h"
#include "operations.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

/**
 * Directory entry
 */
typedef struct {
    char d_name[MAX_FILE_NAME];
    int d_inumber;
} dir_entry_t;

typedef enum { T_FILE, T_DIRECTORY, T_SYM_LINK } inode_type;

/**
 * Inode
 */
typedef struct {
    inode_type i_node_type;

    size_t i_size;
    int i_data_block;
    int hard_links;

    pthread_rwlock_t lock;

    // in a more complete FS, more fields could exist here
} inode_t;

typedef enum { FREE = 0, TAKEN = 1 } allocation_state_t;

/**
 * Open file entry (in open file table)
 */
typedef struct {
    int of_inumber;
    size_t of_offset;

    pthread_mutex_t lock;
} open_file_entry_t;

extern open_file_entry_t *open_file_table;

int state_init(tfs_params);
int state_destroy(void);

size_t state_block_size(void);

int inode_create(inode_type n_type);
void inode_delete(int inumber);
inode_t *inode_get(int inumber);

int clear_dir_entry(inode_t *inode, char const *sub_name);
int add_dir_entry(inode_t *inode, char const *sub_name, int sub_inumber);
int find_in_dir(inode_t const *inode, char const *sub_name);

int data_block_alloc(void);
void data_block_free(int block_number);
void *data_block_get(int block_number);

int add_to_open_file_table(int inumber, size_t offset);
void remove_from_open_file_table(int fhandle);
open_file_entry_t *get_open_file_entry(int fhandle);
int is_file_opened(int inumber);

void mutex_init(pthread_mutex_t *lock);
void mutex_lock(pthread_mutex_t *lock);
void mutex_unlock(pthread_mutex_t *lock);
void mutex_destroy(pthread_mutex_t *lock);

void rwl_init(pthread_rwlock_t *lock);
void rwl_rdlock(pthread_rwlock_t *lock);
void rwl_wrlock(pthread_rwlock_t *lock);
void rwl_unlock(pthread_rwlock_t *lock);
void rwl_destroy(pthread_rwlock_t *lock);

#endif // STATE_H
