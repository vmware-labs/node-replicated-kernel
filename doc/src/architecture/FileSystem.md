# File System

The NrFS is a simple, in-memory file system in nrk that supports some POSIX file
operations (`open`, `pread`, `pwrite`, `close`, *etc.*).

NrFS tracks files and directories by mapping each path to an inode number and
then mapping each inode number to an in-memory inode. Each inode holds either
directory or file metadata and a list of file pages. The entire data structure
is wrapped by CNR for concurrent access and replication.