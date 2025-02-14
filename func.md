# nfs

nfs_file_read
nfs_file_write
nfs_file_open
nfs4_file_open
nfs_getattr


# oom
SEC("tracepoint/oom/mark_victim

# process
tracepoint/syscalls/sys_exit_vfork
tracepoint/syscalls/sys_exit_clone3
tracepoint/sched/sched_process_fork
tracepoint/syscalls/sys_exit_fork
tracepoint/sched/sched_process_exit
tracepoint/sched/sched_process_fork
tracepoint/sched/sched_process_exec
tracepoint/syscalls/sys_exit_clone
release_task
khulnasoft_clone_fexit
khulnasoft_clone3_fexit
kernel_clone
_do_fork


# sync
khulnasoft_sync
tracepoint/syscalls/sys_enter_syncfs
tracepoint/syscalls/sys_enter_msync
tracepoint/syscalls/sys_enter_sync_file_range
tracepoint/syscalls/sys_enter_fsync
tracepoint/syscalls/sys_enter_fdatasync
tracepoint/syscalls/sys_enter_sync


# vfs

vfs_create
vfs_write
vfs_writev
vfs_read
vfs_readv
vfs_unlink
vfs_fsync
vfs_open

# netfilter

ip_rcv
ip_local_deliver_finish
ip_local_out
ip_forward
ip_output
ip_local_deliver
__ip_finish_output