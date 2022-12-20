# Tests

### Brief explanation of each test created by us:

- `chain_symlinks`: Creates symlinks to symlinks, deletes midpoints and writes/reads from them.
- `close_opened_file`: Shows our choice in terms of what to do when trying to close an opened file.
- `copy_from_external_bigger_than_supported`: Shows how our program handles trying to copy an external file bigger than the data block. Also creates a TFS with custom data block size.
- `copy_from_external_maxsize`: Copies an external file with size equal to the max size supported by the TFS.
- `copy_from_external_override`: Copies an external file to an already existing file in the TFS.
- `copy_from_external_to_symlink`: Copies an external file to an existing file through a symlink and then reads from the original file.
- `create_links_same_name`: Tries to create links with the same name.
- `create_symlink_non_existing_target`: Creates a symlink to a non existing target.
- `full_capacity`: Creates a custom TFS with only 1 inode and 1 open file entry available.
- `mthreading_create_same_file`: Tries to create and open the same file as many times as the TFS will support in different threads.
- `mthreading_many_opens`: Creates a file and then opens it a large amount of times in different threads while reading and writing to it.
- `mthreading_read_write_same_file`: Tries to write and then read a different number of bytes at the same time in multiple threads.
- `mthreading_unlinking_same_file`: Creates links to the same file in several threads, and then unlinks them all in different threads as well.
- `open_CREAT_broken_symlink`: Creates a symlink, deletes its target and then recreates it through tfs_open with the flag TFS_O_CREAT.
- `remove_all_hard_links`: Creates hardlinks and unlinks all of them.
