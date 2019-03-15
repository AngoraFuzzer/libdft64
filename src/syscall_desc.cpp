#include "syscall_desc.h"
#include "branch_pred.h"
#include "syscall_struct.h"
#include "tagmap.h"

#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>

//#include <asm/fcntl.h>
//#include <asm/stat.h>
#include <linux/kexec.h>
#include <linux/mempolicy.h>
#include <linux/sysctl.h>

#include <err.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

// Linux:  /usr/include/x86_64-linux-gnu/asm/unistd_64.h

/* callbacks declaration */
static void post_read_hook(THREADID tid, syscall_ctx_t *);
static void post_fcntl_hook(THREADID tid, syscall_ctx_t *);
static void post_mmap_hook(THREADID tid, syscall_ctx_t *);
static void post_syslog_hook(THREADID tid, syscall_ctx_t *);
static void post_modify_ldt_hook(THREADID tid, syscall_ctx_t *);
static void post_quotactl_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_readv_hook(THREADID tid, syscall_ctx_t *);
static void post__sysctl_hook(THREADID tid, syscall_ctx_t *);
static void post_poll_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_rt_sigpending_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_getcwd_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_getgroups_hook(THREADID tid, syscall_ctx_t *);
static void post_mincore_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_getdents_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_getxattr_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_listxattr_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_io_getevents_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_get_mempolicy_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_lookup_dcookie_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_mq_timedreceive_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_readlinkat_hook(THREADID tid, syscall_ctx_t *);
static void post_epoll_wait_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_recvmmsg_hook(THREADID tid, syscall_ctx_t *ctx);

static void post_shmctl_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_accept_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_recvfrom_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_recvmsg_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_getsockopt_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_semctl_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_msgrcv_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_msgctl_hook(THREADID tid, syscall_ctx_t *ctx);

/* syscall descriptors */
syscall_desc_t syscall_desc[SYSCALL_MAX] = {
    /* __NR_read = 0 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_read_hook},
    /* __NR_write = 1 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_open = 2 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_close = 3 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_stat = 4 */
    {2, 0, 1, {0, sizeof(struct stat), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_fstat = 5 */
    {2, 0, 1, {0, sizeof(struct stat), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_lstat = 6 */
    {2, 0, 1, {0, sizeof(struct stat), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_poll = 7 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_poll_hook},
    /* __NR_lseek = 8 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mmap = 9 */
    {6, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_mmap_hook},
    /* __NR_mprotect = 10 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_munmap = 11 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_brk = 12 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_rt_sigaction = 13 */
    {3, 0, 1, {0, 0, sizeof(struct sigaction), 0, 0, 0}, NULL, NULL},
    /* __NR_rt_sigprocmask = 14 */
    {4, 0, 1, {0, sizeof(sigset_t), sizeof(sigset_t), 0, 0, 0}, NULL, NULL},
    /* __NR_rt_sigreturn = 15 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_ioctl = 16 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_pread64 = 17 */
    {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_read_hook},
    /* __NR_pwrite64 = 18 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_readv = 19 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_readv_hook},
    /* __NR_writev = 20 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_access = 21 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_pipe = 22 */
    {1, 0, 1, {sizeof(int) * 2, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_select = 23 */
    {5,
     0,
     1,
     {0, sizeof(fd_set), sizeof(fd_set), sizeof(fd_set), sizeof(struct timeval),
      0},
     NULL,
     NULL},
    /* __NR_sched_yield = 24 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mremap = 25 */
    {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_msync = 26 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mincore = 27 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_mincore_hook},
    /* __NR_madvise = 28 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_shmget = 29 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_shmat = 30 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_shmctl = 31 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_shmctl_hook},
    /* __NR_dup = 32 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_dup2 = 33 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_pause = 34 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_nanosleep = 35 */
    {2,
     0,
     1,
     {sizeof(struct timespec), sizeof(struct timespec), 0, 0, 0, 0},
     NULL,
     NULL},
    /* __NR_getitimer = 36 */
    {2, 0, 1, {0, sizeof(struct itimerval), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_alarm = 37 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_setitimer = 38 */
    {3, 0, 1, {0, 0, sizeof(struct itimerval), 0, 0, 0}, NULL, NULL},
    /* __NR_getpid = 39 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sendfile = 40 */
    {4, 0, 1, {0, 0, sizeof(off_t), 0, 0, 0}, NULL, NULL},
    /* __NR_socket = 41 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_connect = 42 */
    {3, 0, 1, {0, sizeof(struct sockaddr), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_accept = 43 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_accept_hook},
    /* __NR_sendto = 44 */
    {6, 0, 1, {0, 0, 0, 0, sizeof(struct sockaddr), 0}, NULL, NULL},
    /* __NR_recvfrom = 45 */
    {6, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_recvfrom_hook},
    /* __NR_sendmsg = 46 */
    {3, 0, 1, {0, sizeof(struct msghdr), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_recvmsg = 47 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_recvmsg_hook},
    /* __NR_shutdown = 48 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_bind = 49 */
    {3, 0, 1, {0, sizeof(struct sockaddr), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_listen = 50 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getsockname = 51 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_accept_hook},
    /* __NR_getpeername = 52 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_accept_hook},
    /* __NR_socketpair = 53 */
    {4, 0, 1, {0, 0, 0, sizeof(int) * 2, 0, 0}, NULL, NULL},
    /* __NR_setsockopt = 54 */
    {5, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getsockopt = 55 */
    {5, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_getsockopt_hook},
    /* __NR_clone = 56 */
    {4, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_fork = 57 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_vfork = 58 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_execve = 59 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_exit = 60 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_wait4 = 61 */
    {4, 0, 1, {0, sizeof(int), 0, sizeof(struct rusage), 0, 0}, NULL, NULL},
    /* __NR_kill = 62 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_uname = 63 */
    {1, 0, 1, {sizeof(struct utsname), 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_semget = 64 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_semop = 65 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_semctl = 66 */
    {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_semctl_hook},
    /* __NR_shmdt = 67 */
    {1, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_msgget = 68 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_msgsnd = 69 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_msgrcv = 70 */
    {5, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_msgrcv_hook},
    /* __NR_msgctl = 71 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_msgctl_hook},
    /* __NR_fcntl = 72 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_fcntl_hook},
    /* __NR_flock = 73 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_fsync = 74 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_fdatasync = 75 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_truncate = 76 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_ftruncate = 77 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getdents = 78 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_getdents_hook},
    /* __NR_getcwd = 79 */
    {2, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_getcwd_hook},
    /* __NR_chdir = 80 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_fchdir = 81 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_rename = 82 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mkdir = 83 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_rmdir = 84 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_creat = 85 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_link = 86 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_unlink = 87 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_symlink = 88 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_readlink = 89 */
    {3, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_chmod = 90 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_fchmod = 91 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_chown = 92 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_fchown = 93 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_lchown = 94 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_umask = 95 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_gettimeofday = 96 */
    {2,
     0,
     1,
     {sizeof(struct timeval), sizeof(struct timezone), 0, 0, 0, 0},
     NULL,
     NULL},
    /* __NR_getrlimit = 97 */
    {2, 0, 1, {0, sizeof(struct rlimit), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getrusage = 98 */
    {2, 0, 1, {0, sizeof(struct rusage), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sysinfo = 99 */
    {1, 0, 1, {sizeof(struct sysinfo), 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_times = 100 */
    {1, 0, 1, {sizeof(struct sysinfo), 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_ptrace = 101 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getuid = 102 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_syslog = 103 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_syslog_hook},
    /* __NR_getgid = 104 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_setuid = 105 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_setgid = 106 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_geteuid = 107 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getegid = 108 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_setpgid = 109 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getppid = 110 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getpgrp = 111 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_setsid = 112 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_setreuid = 113 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_setregid = 114 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getgroups = 115 */
    {2, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_getgroups_hook},
    /* __NR_setgroups = 116 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_setresuid = 117 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getresuid = 118 */
    {3,
     0,
     1,
     {sizeof(uid_t), sizeof(uid_t), sizeof(uid_t), 0, 0, 0},
     NULL,
     NULL},
    /* __NR_setresgid = 119 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getresgid = 120 */
    {3,
     0,
     1,
     {sizeof(git_t), sizeof(git_t), sizeof(git_t), 0, 0, 0},
     NULL,
     NULL},
    /* __NR_getpgid = 121 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_setfsuid = 122 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_setfsgid = 123 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getsid = 124 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_capget = 125 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_capset = 126 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_rt_sigpending = 127 */
    {2, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_rt_sigpending_hook},
    /* __NR_rt_sigtimedwait = 128 */
    {4, 0, 1, {0, sizeof(siginfo_t), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_rt_sigqueueinfo = 129 */
    {3, 0, 1, {0, 0, sizeof(siginfo_t), 0, 0, 0}, NULL, NULL},
    /* __NR_rt_sigsuspend = 130 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sigaltstack = 131 */
    {2, 0, 1, {0, sizeof(stack_t), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_utime = 132 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mknod = 133 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_uselib = 134 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_personality = 135 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_ustat = 136 */
    {2, 0, 1, {0, sizeof(struct ustat), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_statfs = 137 */
    {2, 0, 1, {0, sizeof(struct statfs), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_fstatfs = 138 */
    {2, 0, 1, {0, sizeof(struct statfs), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sysfs = 139 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getpriority = 140 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_setpriority = 141 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sched_setparam = 142 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sched_getparam = 143 */
    {2, 0, 1, {0, sizeof(struct sched_param), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sched_setscheduler = 144 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sched_getscheduler = 145 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sched_get_priority_max = 146 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sched_get_priority_min = 147 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sched_rr_get_interval = 148 */
    {2, 0, 1, {0, sizeof(struct timespec), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mlock = 149 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_munlock = 150 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mlockall = 151 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_munlockall = 152 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_vhangup = 153 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_modify_ldt = 154 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_modify_ldt_hook},
    /* __NR_pivot_root = 155 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR__sysctl = 156 */
    {1, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post__sysctl_hook},
    /* __NR_prctl = 157 */
    {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_arch_prctl = 158 */
    {2, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_adjtimex = 159 */
    {1, 0, 1, {sizeof(struct timex), 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_setrlimit = 160 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_chroot = 161 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sync = 162 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_acct = 163 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_settimeofday = 164 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mount = 165 */
    {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_umount2 = 166 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_swapon = 167 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_swapoff = 168 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_reboot = 169 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sethostname = 170 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_setdomainname = 171 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_iopl = 172 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_ioperm = 173 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_create_module = 174 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_init_module = 175 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_delete_module = 176 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_get_kernel_syms = 177 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_query_module = 178 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_quotactl = 179 */
    {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_quotactl_hook},
    /* __NR_nfsservctl = 180 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getpmsg = 181 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_putpmsg = 182 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_afs_syscall = 183 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_tuxcall = 184 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_security = 185 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_gettid = 186 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_readahead = 187 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_setxattr = 188 */
    {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_lsetxattr = 189 */
    {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_fsetxattr = 190 */
    {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getxattr = 191 */
    {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_getxattr_hook},
    /* __NR_lgetxattr = 192 */
    {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_getxattr_hook},
    /* __NR_fgetxattr = 193 */
    {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_getxattr_hook},
    /* __NR_listxattr = 194 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_listxattr_hook},
    /* __NR_llistxattr = 195 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_listxattr_hook},
    /* __NR_flistxattr = 196 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_listxattr_hook},
    /* __NR_removexattr = 197 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_lremovexattr = 198 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_fremovexattr = 199 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_tkill = 200 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_time = 201 */
    {1, 0, 1, {sizeof(time_t), 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_futex = 202 */
    {6, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sched_setaffinity = 203 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sched_getaffinity = 204 */
    {3, 0, 1, {0, 0, sizeof(cpu_set_t), 0, 0, 0}, NULL, NULL},
    /* __NR_set_thread_area = 205 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_io_setup = 206 */
    {2, 0, 1, {0, sizeof(aio_context_t), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_io_destroy = 207 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_io_getevents = 208 */
    {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_io_getevents_hook},
    /* __NR_io_submit = 209 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_io_cancel = 210 */
    {3, 0, 1, {0, 0, sizeof(struct io_event), 0, 0, 0}, NULL, NULL},
    /* __NR_get_thread_area = 211 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_lookup_dcookie = 212 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_lookup_dcookie_hook},
    /* __NR_epoll_create = 213 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_epoll_ctl_old = 214 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_epoll_wait_old = 215 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_remap_file_pages = 216 */
    {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getdents64 = 217 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_getdents_hook},
    /* __NR_set_tid_address = 218 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_restart_syscall = 219 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_semtimedop = 220 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_fadvise64 = 221 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_timer_create = 222 */
    {3, 0, 1, {0, 0, sizeof(timer_t), 0, 0, 0}, NULL, NULL},
    /* __NR_timer_settime = 223 */
    {4, 0, 1, {0, 0, 0, sizeof(struct itimerspec), 0, 0}, NULL, NULL},
    /* __NR_timer_gettime = 224 */
    {2, 0, 1, {0, sizeof(struct itimerspec), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_timer_getoverrun = 225 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_timer_delete = 226 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_clock_settime = 227 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_clock_gettime = 228 */
    {2, 0, 1, {0, sizeof(struct timespec), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_clock_getres = 229 */
    {2, 0, 1, {0, sizeof(struct timespec), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_clock_nanosleep = 230 */
    {4, 0, 1, {0, 0, 0, sizeof(struct timespec), 0, 0}, NULL, NULL},
    /* __NR_exit_group = 231 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_epoll_wait = 232 */
    {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_epoll_wait_hook},
    /* __NR_epoll_ctl = 233 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_tgkill = 234 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_utimes = 235 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_vserver = 236 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mbind = 237 */
    {6, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_set_mempolicy = 238 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_get_mempolicy = 239 */
    {5, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_get_mempolicy_hook},
    /* __NR_mq_open = 240 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mq_unlink = 241 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mq_timedsend = 242 */
    {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mq_timedreceive = 243 */
    {5, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_mq_timedreceive_hook},
    /* __NR_mq_notify = 244 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mq_getsetattr = 245 */
    {3, 0, 1, {0, 0, sizeof(struct mq_attr), 0, 0, 0}, NULL, NULL},
    /* __NR_kexec_load = 246 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_waitid = 247 */
    {5,
     0,
     1,
     {0, 0, sizeof(siginfo_t), 0, sizeof(struct rusage), 0},
     NULL,
     NULL},
    /* __NR_add_key = 248 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_request_key = 249 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_keyctl = 250 */
    {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_ioprio_set = 251 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_ioprio_get = 252 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_inotify_init = 253 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_inotify_add_watch = 254 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_inotify_rm_watch = 255 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_migrate_pages = 256 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_openat = 257 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mkdirat = 258 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mknodat = 259 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_fchownat = 260 */
    {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_futimesat = 261 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_newfstatat = 262 */
    {4, 0, 1, {0, 0, sizeof(struct stat), 0, 0, 0}, NULL, NULL},
    /* __NR_unlinkat = 263 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_renameat = 264 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_linkat = 265 */
    {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_symlinkat = 266 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_readlinkat = 267 */
    {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_readlinkat_hook},
    /* __NR_fchmodat = 268 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_faccessat = 269 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_pselect6 = 270 */
    {6,
     0,
     1,
     {0, sizeof(fd_set), sizeof(fd_set), sizeof(fd_set), 0, 0},
     NULL,
     NULL},
    /* __NR_ppoll = 271 */
    {5, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_poll_hook},
    /* __NR_unshare = 272 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_set_robust_list = 273 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_get_robust_list = 274 */
    {3,
     0,
     1,
     {0, sizeof(struct robust_list_head *), sizeof(size_t), 0, 0, 0},
     NULL,
     NULL},
    /* __NR_splice = 275 */
    {6, 0, 1, {0, sizeof(loff_t), 0, sizeof(loff_t), 0, 0}, NULL, NULL},
    /* __NR_tee = 276 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sync_file_range = 277 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_vmsplice = 278 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_move_pages = 279 */
    {6, 0, 1, {0, 0, 0, 0, sizeof(int), 0}, NULL, NULL},
    /* __NR_utimensat = 280 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_epoll_pwait = 281 */
    {6, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_signalfd = 282 */
    {3, 0, 1, {0, sizeof(sigset_t), 0, 0, 0, 0}, NULL, post_epoll_wait_hook},
    /* __NR_timerfd_create = 283 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_eventfd = 284 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_fallocate = 285 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_timerfd_settime = 286 */
    {4, 0, 1, {0, 0, 0, sizeof(struct itimerspec), 0, 0}, NULL, NULL},
    /* __NR_timerfd_gettime = 287 */
    {2, 0, 1, {0, sizeof(struct itimerspec), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_accept4 = 288 */
    {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_accept_hook},
    /* __NR_signalfd4 = 289 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_eventfd2 = 290 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_epoll_create1 = 291 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_dup3 = 292 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_pipe2 = 293 */
    {2, 0, 1, {sizeof(int) * 2, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_inotify_init1 = 294 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_preadv = 295 */
    {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_pwritev = 296 */
    {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_rt_tgsigqueueinfo = 297 */
    {4, 0, 1, {0, 0, 0, sizeof(siginfo_t), 0, 0}, NULL, NULL},
    /* __NR_perf_event_open = 298 */
    {5, 0, 1, {sizeof(struct perf_event_attr), 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_recvmmsg = 299 */
    {5, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_recvmmsg_hook},
    /* __NR_fanotify_init = 300 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_fanotify_mark = 301 */
    {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_prlimit64 = 302 */
    {4, 0, 1, {0, 0, 0, sizeof(struct rlimit), 0, 0}, NULL, NULL},
    /* __NR_name_to_handle_at = 303 */
    {5,
     0,
     1,
     {0, 0, sizeof(struct file_handle), sizeof(int), 0, 0},
     NULL,
     NULL},
    /* __NR_open_by_handle_at = 304 */
    {3, 0, 1, {0, 0, sizeof(struct file_handle), 0, 0, 0}, NULL, NULL},
    /* __NR_clock_adjtime = 305 */
    {2, 0, 1, {0, sizeof(struct timex), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_syncfs = 306 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sendmmsg = 307 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_setns = 308 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getcpu = 309 */
    {3,
     0,
     1,
     {sizeof(unsigned), sizeof(unsigned), sizeof(struct getcpu_cache), 0, 0, 0},
     NULL,
     NULL},
    /* __NR_process_vm_readv = 310 */
    {6, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_process_vm_writev = 311 */
    {6, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_kcmp = 312 */
    {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_finit_module = 313 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sched_setattr = 314 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sched_getattr = 315 */
    {4, 0, 1, {0, sizeof(struct sched_attr), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_renameat2 316 */
    /* __NR_seccomp 317 */
    /* __NR_getrandom 318 */
    /* __NR_memfd_create 319 */
    /* __NR_kexec_file_load 320 */
    /* __NR_bpf 321 */
    /* __NR_execveat 322 */
    /* __NR_userfaultfd 323 */
    /* __NR_membarrier 324 */
    /* __NR_mlock2 325 */
    /* __NR_copy_file_range 326 */
    /* __NR_preadv2 327 */
    /* __NR_pwritev2 328 */
    /* __NR_pkey_mprotect 329 */
    /* __NR_pkey_alloc 330 */
    /* __NR_pkey_free 331 */
    /* __NR_statx 332 */
    /* __NR_io_pgetevents 333 */
    /* __NR_rseq 334 */
};

/*
 * add a new pre-syscall callback into a syscall descriptor
 *
 * @desc:	the syscall descriptor
 * @pre:	function pointer to the pre-syscall handler
 *
 * returns:	0 on success, 1 on error
 */
int syscall_set_pre(syscall_desc_t *desc,
                    void (*pre)(THREADID, syscall_ctx_t *)) {
  /* sanity checks */
  if (unlikely((desc == NULL) | (pre == NULL)))
    /* return with failure */
    return 1;

  /* update the pre-syscall callback */
  desc->pre = pre;

  /* set the save arguments flag */
  desc->save_args = 1;

  /* success */
  return 0;
}

/*
 * add a new post-syscall callback into a syscall descriptor
 *
 * @desc:	the syscall descriptor
 * @pre:	function pointer to the post-syscall handler
 *
 * returns:	0 on success, 1 on error
 */
int syscall_set_post(syscall_desc_t *desc,
                     void (*post)(THREADID, syscall_ctx_t *)) {
  /* sanity checks */
  if (unlikely((desc == NULL) | (post == NULL)))
    /* return with failure */
    return 1;

  /* update the post-syscall callback */
  desc->post = post;

  /* set the save arguments flag */
  desc->save_args = 1;

  /* success */
  return 0;
}

/*
 * remove the pre-syscall callback from a syscall descriptor
 *
 * @desc:       the syscall descriptor
 *
 * returns:     0 on success, 1 on error
 */
int syscall_clr_pre(syscall_desc_t *desc) {
  /* sanity check */
  if (unlikely(desc == NULL))
    /* return with failure */
    return 1;

  /* clear the pre-syscall callback */
  desc->pre = NULL;

  /* check if we need to clear the save arguments flag */
  if (desc->post == NULL)
    /* clear */
    desc->save_args = 0;

  /* return with success */
  return 0;
}

/*
 * remove the post-syscall callback from a syscall descriptor
 *
 * @desc:       the syscall descriptor
 *
 * returns:     0 on success, 1 on error
 */
int syscall_clr_post(syscall_desc_t *desc) {
  /* sanity check */
  if (unlikely(desc == NULL))
    /* return with failure */
    return 1;

  /* clear the post-syscall callback */
  desc->post = NULL;

  /* check if we need to clear the save arguments flag */
  if (desc->pre == NULL)
    /* clear */
    desc->save_args = 0;

  /* return with success */
  return 0;
}

/* __NR_(p)read(64) and __NR_readlink post syscall hook */
static void post_read_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* read()/readlink() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

/* __NR_getgroups post syscall_hook */
static void post_getgroups_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* getgroups() was not successful */
  if ((long)ctx->ret <= 0 || (gid_t *)ctx->arg[SYSCALL_ARG1] == NULL)
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG1], (sizeof(gid_t) * (size_t)ctx->ret));
}

/* __NR_readlinkat post syscall hook */
static void post_readlinkat_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* readlinkat() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG2], (size_t)ctx->ret);
}

/* __NR_mmap post syscall hook */
static void post_mmap_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* the map offset */
  size_t offset = (size_t)ctx->arg[SYSCALL_ARG1];

  /* mmap() was not successful; optimized branch */
  if (unlikely((void *)ctx->ret == MAP_FAILED))
    return;

  /* estimate offset; optimized branch */
  if (unlikely(offset < PAGE_SZ))
    offset = PAGE_SZ;
  else
    offset = offset + PAGE_SZ - (offset % PAGE_SZ);

  /* grow downwards; optimized branch */
  if (unlikely((int)ctx->arg[SYSCALL_ARG3] & MAP_GROWSDOWN))
    /* fix starting address */
    ctx->ret = ctx->ret - offset;

  /* emulate the clear_tag() call */
  tagmap_clrn((size_t)ctx->ret, offset);
}

/* __NR_readv and __NR_preadv post syscall hook */
static void post_readv_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* iterators */
  int i;
  struct iovec *iov;

  /* bytes copied in a iovec structure */
  size_t iov_tot;

  /* total bytes copied */
  size_t tot = (size_t)ctx->ret;

  /* (p)readv() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* iterate the iovec structures */
  for (i = 0; i < (int)ctx->arg[SYSCALL_ARG2] && tot > 0; i++) {
    /* get an iovec  */
    iov = ((struct iovec *)ctx->arg[SYSCALL_ARG1]) + i;

    /* get the length of the iovec */
    iov_tot = (tot >= (size_t)iov->iov_len) ? (size_t)iov->iov_len : tot;

    /* clear the tag bits */
    tagmap_clrn((size_t)iov->iov_base, iov_tot);

    /* housekeeping */
    tot -= iov_tot;
  }
}

/* __NR_epoll_pwait post syscall hook */
static void post_epoll_wait_hook(THREADID tid, syscall_ctx_t *ctx) {

  /* epoll_pwait() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG1],
              sizeof(struct epoll_event) * (size_t)ctx->ret);
}

/* __NR_poll and __NR_ppoll post syscall hook */
static void post_poll_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* iterators */
  size_t i;
  struct pollfd *pfd;

  /* (p)poll() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* iterate the pollfd structures */
  for (i = 0; i < (size_t)ctx->arg[SYSCALL_ARG1]; i++) {
    /* get pollfd */
    pfd = ((struct pollfd *)ctx->arg[SYSCALL_ARG0]) + i;

    /* clear the tag bits */
    tagmap_clrn((size_t)&pfd->revents, sizeof(short));
  }
}

/* __NR_mq_timedreceive post syscall hook */
static void post_mq_timedreceive_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* mq_timedreceive() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);

  /* priority argument is supplied */
  if ((size_t *)ctx->arg[SYSCALL_ARG3] != NULL)
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG3], sizeof(size_t));
}

/* __NR_get_mempolicy */
static void post_get_mempolicy_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* get_mempolicy() was not successful; optimized branch */
  if (unlikely((long)ctx->ret < 0))
    return;

  /* flags is zero */
  if ((unsigned long)ctx->arg[SYSCALL_ARG4] == 0) {
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG0], sizeof(int));
    tagmap_clrn(ctx->arg[SYSCALL_ARG1], sizeof(unsigned long));
    /* done */
    return;
  }

  /* MPOL_F_MEMS_ALLOWED is set on flags */
  if (((unsigned long)ctx->arg[SYSCALL_ARG4] & MPOL_F_MEMS_ALLOWED) != 0) {
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG1], sizeof(unsigned long));
    /* done */
    return;
  }

  /* MPOL_F_ADDR is set on flags */
  if (((unsigned long)ctx->arg[SYSCALL_ARG4] & MPOL_F_ADDR) != 0 &&
      ((unsigned long)ctx->arg[SYSCALL_ARG4] & MPOL_F_NODE) == 0) {
    /* mode is provided */
    if ((int *)ctx->arg[SYSCALL_ARG0] != NULL)
      /* clear the tag bits */
      tagmap_clrn(ctx->arg[SYSCALL_ARG0], sizeof(int));

    /* nodemask is provided */
    if ((unsigned long *)ctx->arg[SYSCALL_ARG1] != NULL)
      /* clear the tag bits */
      tagmap_clrn(ctx->arg[SYSCALL_ARG1], sizeof(unsigned long));
    /* done */
    return;
  }

  /* MPOL_F_NODE & MPOL_F_ADDR is set on flags */
  if (((unsigned long)ctx->arg[SYSCALL_ARG4] & MPOL_F_ADDR) != 0 &&
      ((unsigned long)ctx->arg[SYSCALL_ARG4] & MPOL_F_NODE) != 0) {
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG0], sizeof(int));
    /* done */
    return;
  }

  /* MPOL_F_NODE is set on flags */
  if (((unsigned long)ctx->arg[SYSCALL_ARG4] & MPOL_F_NODE) != 0) {
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG0], sizeof(int));
    /* done */
    return;
  }
}

/* __NR_lookup_dcookie post syscall hook */
static void post_lookup_dcookie_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* lookup_dcookie() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

/* __NR_io_getevents post syscall hook */
static void post_io_getevents_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* io_getevents() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG3],
              sizeof(struct io_event) * (size_t)ctx->ret);

  /* timespec is specified */
  if ((struct timespec *)ctx->arg[SYSCALL_ARG4] != NULL)
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG4], sizeof(struct timespec));
}

/* __NR_(f, l)listxattr post syscall hook */
static void post_listxattr_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* *listxattr() was not successful; optimized branch */
  if ((long)ctx->ret <= 0 || (void *)ctx->arg[SYSCALL_ARG1] == NULL)
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

/* __NR_(f, l)getxattr post syscall hook */
static void post_getxattr_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* *getxattr() was not successful; optimized branch */
  if ((long)ctx->ret <= 0 || (void *)ctx->arg[SYSCALL_ARG2] == NULL)
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG2], (size_t)ctx->ret);
}

/* __NR_getdents post syscall hook */
static void post_getdents_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* getdents() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

/* __NR_mincore post syscall hook */
static void post_mincore_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* mincore() was not successful; optimized branch */
  if (unlikely((long)ctx->ret < 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG2],
              (((size_t)ctx->arg[SYSCALL_ARG1] + PAGE_SZ - 1) / PAGE_SZ));
}

/* __NR_getcwd post syscall hook */
static void post_getcwd_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* getcwd() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG0], (size_t)ctx->ret);
}

/* __NR_rt_sigpending post syscall hook */
static void post_rt_sigpending_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* rt_sigpending() was not successful; optimized branch */
  if (unlikely((long)ctx->ret < 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG0], (size_t)ctx->arg[SYSCALL_ARG1]);
}

/* __NR_quotactl post syscall hook */
static void post_quotactl_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* offset */
  size_t off;

  /* quotactl() was not successful; optimized branch */
  if (unlikely((long)ctx->ret < 0))
    return;

  /* different offset ranges */
  switch ((int)ctx->arg[SYSCALL_ARG0]) {
  case Q_GETFMT:
    off = sizeof(__u32);
    break;
  case Q_GETINFO:
    off = sizeof(struct if_dqinfo);
    break;
  case Q_GETQUOTA:
    off = sizeof(struct if_dqblk);
    break;
  case Q_XGETQSTAT:
    off = sizeof(struct fs_quota_stat);
    break;
  case Q_XGETQUOTA:
    off = sizeof(struct fs_disk_quota);
    break;
  default:
    /* nothing to do */
    return;
  }

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG3], off);
}

/* __NR_modify_ldt post syscall hook */
static void post_modify_ldt_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* modify_ldt() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

/* __NR_fcntl post syscall hook */
static void post_fcntl_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* fcntl() was not successful; optimized branch */
  if (unlikely((long)ctx->ret < 0))
    return;

  /* differentiate based on the cmd argument */
  switch ((int)ctx->arg[SYSCALL_ARG1]) {
  /* F_GETLK */
  case F_GETLK:
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG2], sizeof(struct flock));
    break;
  /* F_GETLK64 */
  /*
  case F_GETLK64:
    tagmap_clrn(ctx->arg[SYSCALL_ARG2], sizeof(struct flock64));
    break;
  */
  /* F_GETOWN_EX */
  case F_GETOWN_EX:
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG2], sizeof(struct f_owner_ex));
    break;
  default:
    /* nothing to do */
    break;
  }
}

/*
 * __NR_syslog post syscall hook
 *
 * NOTE: this is not related to syslog(3)
 * see klogctl(3)/syslog(2)
 */
static void post_syslog_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* syslog() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* differentiate based on the type */
  switch ((int)ctx->arg[SYSCALL_ARG0]) {
  case 2:
  case 3:
  case 4:
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
    break;
  default:
    /* nothing to do */
    return;
  }
}

/* __NR__sysctl post syscall hook */
static void post__sysctl_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* _sysctl arguments */
  struct __sysctl_args *sa;

  /* _sysctl() was not successful; optimized branch */
  if (unlikely((long)ctx->ret < 0))
    return;

  /* _sysctl arguments */
  sa = (struct __sysctl_args *)ctx->arg[SYSCALL_ARG0];

  /* clear the tag bits */
  tagmap_clrn((size_t)sa->newval, sa->newlen);

  /* save old value is specified */
  if (sa->oldval != NULL) {
    /* clear the tag bits */
    tagmap_clrn((size_t)sa->oldval, *sa->oldlenp);

    /* clear the tag bits */
    tagmap_clrn((size_t)sa->oldlenp, sizeof(size_t));
  }
}

/* __NR_recvmmsg post syscall hook */
static void post_recvmmsg_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* message headers; recvmsg(2) recvmmsg(2) */
  struct mmsghdr *msg;
  struct msghdr *m;

  /* iov bytes copied; recvmsg(2) */
  size_t iov_tot;

  /* iterators */
  size_t i, j;
  struct iovec *iov;

  /* total bytes received */
  size_t tot;

  /* recvmmsg() was not successful; optimized branch */
  if (unlikely((long)ctx->ret < 0))
    return;

  /* iterate the mmsghdr structures */
  for (i = 0; i < (size_t)ctx->ret; i++) {
    /* get the next mmsghdr structure */
    msg = ((struct mmsghdr *)ctx->arg[SYSCALL_ARG1]) + i;

    /* extract the message header */
    m = &msg->msg_hdr;

    /* source address specified */
    if (m->msg_name != NULL) {
      /* clear the tag bits */
      tagmap_clrn((size_t)m->msg_name, m->msg_namelen);

      /* clear the tag bits */
      tagmap_clrn((size_t)&m->msg_namelen, sizeof(int));
    }

    /* ancillary data specified */
    if (m->msg_control != NULL) {
      /* clear the tag bits */
      tagmap_clrn((size_t)m->msg_control, m->msg_controllen);

      /* clear the tag bits */
      tagmap_clrn((size_t)&m->msg_controllen, sizeof(int));
    }

    /* flags; clear the tag bits */
    tagmap_clrn((size_t)&m->msg_flags, sizeof(int));

    /* total bytes received; clear the tag bits */
    tot = (size_t)msg->msg_len;
    tagmap_clrn((size_t)&msg->msg_len, sizeof(unsigned));

    /* iterate the iovec structures */
    for (j = 0; j < m->msg_iovlen && tot > 0; j++) {
      /* get the next I/O vector */
      iov = &m->msg_iov[j];

      /* get the length of the iovec */
      iov_tot = (tot > (size_t)iov->iov_len) ? (size_t)iov->iov_len : tot;

      /* clear the tag bits */
      tagmap_clrn((size_t)iov->iov_base, iov_tot);

      /* housekeeping */
      tot -= iov_tot;
    }
  }

  /* timespec structure specified */
  if ((struct timespec *)ctx->arg[SYSCALL_ARG4] != NULL)
    ;
  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG4], sizeof(struct timespec));
}

static void post_msgctl_hook(THREADID tid, syscall_ctx_t *ctx) {
  if (unlikely((long)ctx->ret < 0))
    return;

  /* fix the cmd parameter */
  // ctx->arg[SYSCALL_ARG2] -= IPC_FIX;

  /* differentiate based on the cmd */
  switch ((int)ctx->arg[SYSCALL_ARG1]) {
  case IPC_STAT:
  case MSG_STAT:
    // case MSG_STAT_ANY:
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG2], sizeof(struct msqid_ds));
    break;
  case IPC_INFO:
  case MSG_INFO:
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG2], sizeof(struct msginfo));
    break;
  default:
    /* nothing to do */
    return;
  }
}

static void post_shmctl_hook(THREADID tid, syscall_ctx_t *ctx) {
  if (unlikely((long)ctx->ret < 0))
    return;

  /* fix the cmd parameter */
  // FIXME:
  // ctx->arg[SYSCALL_ARG2] -= IPC_FIX;

  /* differentiate based on the cmd */
  switch ((int)ctx->arg[SYSCALL_ARG1]) {
  case IPC_STAT:
  case SHM_STAT:
    // case SHM_STAT_ANY:
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG2], sizeof(struct shmid_ds));
    break;
  case IPC_INFO:
  case SHM_INFO:
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG2], sizeof(struct shminfo));
    break;
  default:
    /* nothing to do */
    return;
  }
}

static void post_semctl_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* semctl() was not successful; optimized branch */
  if (unlikely((long)ctx->ret < 0))
    return;

  /* get the semun structure */
  union semun *su;
  su = (union semun *)ctx->arg[SYSCALL_ARG4];

  /* fix the cmd parameter */
  // ctx->arg[SYSCALL_ARG2] -= IPC_FIX;

  /* differentiate based on the cmd */
  switch ((int)ctx->arg[SYSCALL_ARG2]) {
  case IPC_STAT:
  case SEM_STAT:
    // case SEM_STAT_ANY:
    /* clear the tag bits */
    tagmap_clrn((size_t)su->buf, sizeof(struct semid_ds));
    break;
  case IPC_INFO:
  case SEM_INFO:
    /* clear the tag bits */
    tagmap_clrn((size_t)su->buf, sizeof(struct seminfo));
    break;
  default:
    /* nothing to do */
    return;
  }
}

static void post_msgrcv_hook(THREADID tid, syscall_ctx_t *ctx) {
  if (unlikely((long)ctx->ret <= 0))
    return;
  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret + sizeof(long));
}

static void post_accept_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* not successful; optimized branch */
  if (unlikely((long)ctx->ret < 0))
    return;

  /* addr argument is provided */
  if ((void *)ctx->arg[SYSCALL_ARG1] != NULL) {
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG1], *((int *)ctx->arg[SYSCALL_ARG2]));

    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG2], sizeof(int));
  }
}

static void post_recvfrom_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);

  /* sockaddr argument is specified */
  if ((void *)ctx->arg[SYSCALL_ARG4] != NULL) {
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG4], *((int *)ctx->arg[SYSCALL_ARG5]));

    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG5], sizeof(int));
  }
}

static void post_getsockopt_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* not successful; optimized branch */
  if (unlikely((long)ctx->ret < 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG3], *((int *)ctx->arg[SYSCALL_ARG4]));

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG4], sizeof(int));
}

static void post_recvmsg_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;
  /* message header; recvmsg(2) */
  struct msghdr *msg;

  /* iov bytes copied; recvmsg(2) */
  size_t iov_tot;

  /* iterators */
  size_t i;
  struct iovec *iov;

  /* total bytes received */
  size_t tot;

  /* extract the message header */
  msg = (struct msghdr *)ctx->arg[SYSCALL_ARG1];

  /* source address specified */
  if (msg->msg_name != NULL) {
    /* clear the tag bits */
    tagmap_clrn((size_t)msg->msg_name, msg->msg_namelen);

    /* clear the tag bits */
    tagmap_clrn((size_t)&msg->msg_namelen, sizeof(int));
  }

  /* ancillary data specified */
  if (msg->msg_control != NULL) {
    /* clear the tag bits */
    tagmap_clrn((size_t)msg->msg_control, msg->msg_controllen);

    /* clear the tag bits */
    tagmap_clrn((size_t)&msg->msg_controllen, sizeof(int));
  }

  /* flags; clear the tag bits */
  tagmap_clrn((size_t)&msg->msg_flags, sizeof(int));

  /* total bytes received */
  tot = (size_t)ctx->ret;

  /* iterate the iovec structures */
  for (i = 0; i < msg->msg_iovlen && tot > 0; i++) {
    /* get the next I/O vector */
    iov = &msg->msg_iov[i];

    /* get the length of the iovec */
    iov_tot = (tot > (size_t)iov->iov_len) ? (size_t)iov->iov_len : tot;

    /* clear the tag bits */
    tagmap_clrn((size_t)iov->iov_base, iov_tot);

    /* housekeeping */
    tot -= iov_tot;
  }
}