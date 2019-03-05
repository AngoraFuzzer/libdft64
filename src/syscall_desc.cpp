/*-
 * Copyright (c) 2010, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2010.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * 23/02/2011:
 * 	some conflict arises when numaif.h is included before syscall_desc.h
 * 	the proposed fix was done by Georgios Portokalidis
 * 	(porto@cs.columbia.edu)
 */

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

#include <asm/fcntl.h>
#include <linux/kexec.h>
#include <linux/sysctl.h>

#include <err.h>
#include <linux/mempolicy.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <ustat.h>

#include "syscall_desc.h"
#include "tagmap.h"

/* threads context */
extern thread_ctx_t *threads_ctx;

/* syscall descriptors */
syscall_desc_t syscall_desc[SYSCALL_MAX] = {
    /* __NR_read = 0 */
    {3, 1, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_write = 1 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_open = 2 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_close = 3 */
    {1, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_stat = 4 */
    {2, 0, 1, {0, sizeof(struct stat), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_fstat = 5 */
    {2, 1, 1, {0, sizeof(struct stat), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_lstat = 6 */
    {2, 0, 1, {0, sizeof(struct stat), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_poll = 7 */
    {3, 1, 1, {sizeof(struct pollfd), 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_lseek = 8 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mmap = 9 */
    {6, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mprotect = 10 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_munmap = 11 */
    {2, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_brk = 12 */
    {1, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_rt_sigaction = 13 */
    {3, 0, 1, {0, 0, sizeof(struct sigaction), 0, 0, 0}, NULL, NULL},
    /* __NR_rt_sigprocmask = 14 */
    {4, 0, 1, {0, sizeof(sigset_t), sizeof(sigset_t), 0, 0, 0}, NULL, NULL},
    /* __NR_rt_sigreturn = 15 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_ioctl = 16 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_pread64 = 17 */
    {4, 1, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_pwrite64 = 18 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_readv = 19 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_writev = 20 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_access = 21 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_pipe = 22 */
    {1, 0, 1, {sizeof(int), 0, 0, 0, 0, 0}, NULL, NULL},
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
    {3, 1, 1, {0, 0, sizeof(unsigned char), 0, 0, 0}, NULL, NULL},
    /* __NR_madvise = 28 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_shmget = 29 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_shmat = 30 */
    {3, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_shmctl = 31 */
    {3, 0, 1, {0, 0, sizeof(struct shmid_ds), 0, 0, 0}, NULL, NULL},
    /* __NR_dup = 32 */
    {1, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_dup2 = 33 */
    {2, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
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
    {3,
     0,
     1,
     {0, sizeof(struct itimerval), sizeof(struct itimerval), 0, 0, 0},
     NULL,
     NULL},
    /* __NR_getpid = 39 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sendfile = 40 */
    {4, 0, 1, {0, 0, sizeof(off_t), 0, 0, 0}, NULL, NULL},
    /* __NR_socket = 41 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_connect = 42 */
    {3, 0, 1, {0, sizeof(struct sockaddr), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_accept = 43 */
    {3, 0, 1, {0, sizeof(struct sockaddr), sizeof(int), 0, 0, 0}, NULL, NULL},
    /* __NR_sendto = 44 */
    {6, 0, 1, {0, 0, 0, 0, sizeof(struct sockaddr), 0}, NULL, NULL},
    /* __NR_recvfrom = 45 */
    {6, 0, 1, {0, 0, 0, 0, sizeof(struct sockaddr), sizeof(int)}, NULL, NULL},
    /* __NR_sendmsg = 46 */
    {3, 0, 1, {0, sizeof(struct msghdr), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_recvmsg = 47 */
    {3, 0, 1, {0, sizeof(struct msghdr), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_shutdown = 48 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_bind = 49 */
    {3, 0, 1, {0, sizeof(struct sockaddr), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_listen = 50 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getsockname = 51 */
    {3, 0, 1, {0, sizeof(struct sockaddr), sizeof(int), 0, 0, 0}, NULL, NULL},
    /* __NR_getpeername = 52 */
    {3, 0, 1, {0, sizeof(struct sockaddr), sizeof(int), 0, 0, 0}, NULL, NULL},
    /* __NR_socketpair = 53 */
    {4, 0, 1, {0, 0, 0, sizeof(int), 0, 0}, NULL, NULL},
    /* __NR_setsockopt = 54 */
    {5, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getsockopt = 55 */
    {5, 0, 1, {0, 0, 0, 0, sizeof(int), 0}, NULL, NULL},
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
    {3, 0, 1, {0, sizeof(struct sembuf), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_semctl = 66 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_shmdt = 67 */
    {1, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_msgget = 68 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_msgsnd = 69 */
    {4, 0, 1, {0, sizeof(struct msgbuf), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_msgrcv = 70 */
    {5, 0, 1, {0, sizeof(struct msgbuf), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_msgctl = 71 */
    {3, 0, 1, {0, 0, sizeof(struct msqid_ds), 0, 0, 0}, NULL, NULL},
    /* __NR_fcntl = 72 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
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
    {3, 0, 1, {0, sizeof(struct linux_dirent), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getcwd = 79 */
    {2, 1, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
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
    {3, 1, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
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
    {2, 1, 1, {0, sizeof(gid_t), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_setgroups = 116 */
    {2, 0, 1, {0, sizeof(gid_t), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_setresuid = 117 */
    {3,
     0,
     1,
     {sizeof(uid_t), sizeof(uid_t), sizeof(uid_t), 0, 0, 0},
     NULL,
     NULL},
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
    {2, 1, 1, {sizeof(sigset_t), 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_rt_sigtimedwait = 128 */
    {4, 0, 1, {0, sizeof(siginfo_t), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_rt_sigqueueinfo = 129 */
    {3, 0, 1, {0, 0, sizeof(siginfo_t), 0, 0, 0}, NULL, NULL},
    /* __NR_rt_sigsuspend = 130 */
    {2, 0, 1, {sizeof(sigset_t), 0, 0, 0, 0, 0}, NULL, NULL},
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
    {2, 0, 1, {0, sizeof(struct sched_param), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sched_getparam = 143 */
    {2, 0, 1, {0, sizeof(struct sched_param), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sched_setscheduler = 144 */
    {3, 0, 1, {0, 0, sizeof(struct sched_param), 0, 0, 0}, NULL, NULL},
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
    {3, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_pivot_root = 155 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR__sysctl = 156 */
    {1, 1, 1, {sizeof(struct __sysctl_args), 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_prctl = 157 */
    {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_arch_prctl = 158 */
    {2, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_adjtimex = 159 */
    {1, 0, 1, {sizeof(struct timex), 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_setrlimit = 160 */
    {2, 0, 1, {0, sizeof(struct rlimit), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_chroot = 161 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sync = 162 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_acct = 163 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_settimeofday = 164 */
    {2,
     0,
     1,
     {sizeof(struct timeval), sizeof(struct timezone), 0, 0, 0, 0},
     NULL,
     NULL},
    /* __NR_mount = 165 */
    {5, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_umount2 = 166 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_swapon = 167 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_swapoff = 168 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_reboot = 169 */
    {4, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sethostname = 170 */
    {2, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_setdomainname = 171 */
    {2, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_iopl = 172 */
    {1, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_ioperm = 173 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_create_module = 174 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_init_module = 175 */
    {3, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_delete_module = 176 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_get_kernel_syms = 177 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_query_module = 178 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_quotactl = 179 */
    {4, 1, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
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
    {4, 1, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_lgetxattr = 192 */
    {4, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_fgetxattr = 193 */
    {4, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_listxattr = 194 */
    {3, 1, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_llistxattr = 195 */
    {3, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_flistxattr = 196 */
    {3, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
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
    {6,
     0,
     1,
     {sizeof(u32), 0, 0, sizeof(struct timespec), sizeof(u32), 0},
     NULL,
     NULL},
    /* __NR_sched_setaffinity = 203 */
    {3, 0, 1, {0, 0, sizeof(unsigned long), 0, 0, 0}, NULL, NULL},
    /* __NR_sched_getaffinity = 204 */
    {3, 0, 1, {0, 0, sizeof(unsigned long), 0, 0, 0}, NULL, NULL},
    /* __NR_set_thread_area = 205 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_io_setup = 206 */
    {2, 0, 1, {0, sizeof(aio_context_t), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_io_destroy = 207 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_io_getevents = 208 */
    {4, 1, 1, {0, 0, 0, sizeof(struct io_event), 0, 0}, NULL, NULL},
    /* __NR_io_submit = 209 */
    {3, 0, 1, {0, 0, sizeof(struct iocb), 0, 0, 0}, NULL, NULL},
    /* __NR_io_cancel = 210 */
    {3,
     0,
     1,
     {0, sizeof(struct iocb), sizeof(struct io_event), 0, 0, 0},
     NULL,
     NULL},
    /* __NR_get_thread_area = 211 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_lookup_dcookie = 212 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_epoll_create = 213 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_epoll_ctl_old = 214 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_epoll_wait_old = 215 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_remap_file_pages = 216 */
    {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_getdents64 = 217 */
    {3, 1, 1, {0, sizeof(struct linux_dirent), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_set_tid_address = 218 */
    {1, 0, 1, {sizeof(int), 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_restart_syscall = 219 */
    {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_semtimedop = 220 */
    {4, 0, 1, {0, sizeof(struct sembuf), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_fadvise64 = 221 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_timer_create = 222 */
    {3,
     0,
     1,
     {0, sizeof(struct sigevent), sizeof(timer_t), 0, 0, 0},
     NULL,
     NULL},
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
    {4, 1, 1, {0, sizeof(struct epoll_event), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_epoll_ctl = 233 */
    {4, 0, 1, {0, 0, 0, sizeof(struct epoll_event), 0, 0}, NULL, NULL},
    /* __NR_tgkill = 234 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_utimes = 235 */
    {2, 0, 1, {0, sizeof(struct timeval), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_vserver = 236 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mbind = 237 */
    {6, 0, 1, {0, 0, 0, sizeof(unsigned long), 0, 0}, NULL, NULL},
    /* __NR_set_mempolicy = 238 */
    {3, 0, 1, {0, sizeof(unsigned long), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_get_mempolicy = 239 */
    {5, 1, 1, {sizeof(int), sizeof(unsigned long), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mq_open = 240 */
    {4, 0, 1, {0, 0, 0, sizeof(struct mq_attr), 0, 0}, NULL, NULL},
    /* __NR_mq_unlink = 241 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mq_timedsend = 242 */
    {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mq_timedreceive = 243 */
    {5, 1, 1, {0, 0, 0, sizeof(unsigned int), 0, 0}, NULL, NULL},
    /* __NR_mq_notify = 244 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mq_getsetattr = 245 */
    {3, 0, 1, {0, 0, sizeof(struct mq_attr), 0, 0, 0}, NULL, NULL},
    /* __NR_kexec_load = 246 */
    {4, 0, 1, {0, 0, sizeof(struct kexec_segment), 0, 0, 0}, NULL, NULL},
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
    {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mkdirat = 258 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_mknodat = 259 */
    {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_fchownat = 260 */
    {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_futimesat = 261 */
    {3, 0, 1, {0, 0, sizeof(struct timeval), 0, 0, 0}, NULL, NULL},
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
    {4, 1, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_fchmodat = 268 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_faccessat = 269 */
    {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_pselect6 = 270 */
    {6,
     0,
     1,
     {0, sizeof(fd_set), sizeof(fd_set), sizeof(fd_set),
      sizeof(struct timespec), 0},
     NULL,
     NULL},
    /* __NR_ppoll = 271 */
    {5,
     0,
     1,
     {sizeof(struct pollfd), 0, sizeof(struct timespec), 0, 0, 0},
     NULL,
     NULL},
    /* __NR_unshare = 272 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_set_robust_list = 273 */
    {2, 0, 1, {sizeof(struct robust_list_head), 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_get_robust_list = 274 */
    {3,
     0,
     1,
     {0, sizeof(struct robust_list_head), sizeof(size_t), 0, 0, 0},
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
    {4, 0, 1, {0, 0, sizeof(struct timespec), 0, 0, 0}, NULL, NULL},
    /* __NR_epoll_pwait = 281 */
    {6, 0, 1, {0, sizeof(struct epoll_event), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_signalfd = 282 */
    {3, 0, 1, {0, sizeof(sigset_t), 0, 0, 0, 0}, NULL, NULL},
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
    {4, 0, 1, {0, sizeof(struct sockaddr), sizeof(int), 0, 0, 0}, NULL, NULL},
    /* __NR_signalfd4 = 289 */
    {4, 0, 1, {0, sizeof(sigset_t), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_eventfd2 = 290 */
    {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_epoll_create1 = 291 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_dup3 = 292 */
    {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_pipe2 = 293 */
    {2, 0, 1, {sizeof(int), 0, 0, 0, 0, 0}, NULL, NULL},
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
    {5,
     0,
     1,
     {0, sizeof(struct msghdr), 0, 0, sizeof(struct timespec), 0},
     NULL,
     NULL},
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
    {5,
     0,
     1,
     {0, 0, sizeof(struct file_handle), sizeof(int), 0, 0},
     NULL,
     NULL},
    /* __NR_clock_adjtime = 305 */
    {2, 0, 1, {0, sizeof(struct timex), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_syncfs = 306 */
    {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sendmmsg = 307 */
    {4, 0, 1, {0, sizeof(struct mmsghdr), 0, 0, 0, 0}, NULL, NULL},
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
    {3, 0, 1, {0, sizeof(struct sched_attr), 0, 0, 0, 0}, NULL, NULL},
    /* __NR_sched_getattr = 315 */
    {4, 0, 1, {0, sizeof(struct sched_attr), 0, 0, 0, 0}, NULL, NULL},
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
