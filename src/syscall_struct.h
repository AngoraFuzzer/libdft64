
#ifndef __SYSCALL_STRUCT_H__
#define __SYSCALL_STRUCT_H__
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/vfs.h>

#include <asm/ldt.h>
#include <asm/posix_types.h>
#include <linux/aio_abi.h>
#include <linux/futex.h>
#include <linux/mqueue.h>
#include <linux/perf_event.h>
#include <linux/utsname.h>
#include <sys/stat.h>

#include <signal.h>
#include <ustat.h>

/* page size in bytes */
#define PAGE_SZ 4096

#define Q_GETFMT 0x800004
#define Q_GETINFO 0x800005
#define Q_GETQUOTA 0x800007
#define Q_SETQUOTA 0x800008
#define XQM_CMD(x) (('X' << 8) + (x))
#define Q_XGETQUOTA XQM_CMD(3)
#define Q_XGETQSTAT XQM_CMD(5)

#define IPC_FIX 256

struct linux_dirent {
  unsigned long d_ino;
  unsigned long d_off;
  unsigned short d_reclen;
  char d_name[1];
};

struct getcpu_cache {
  unsigned long blob[128 / sizeof(long)];
};

typedef struct __user_cap_header_struct {
  __u32 version;
  int pid;
} * cap_user_header_t;

typedef struct __user_cap_data_struct {
  __u32 effective;
  __u32 permitted;
  __u32 inheritable;
} * cap_user_data_t;

struct sched_attr {
  __u32 size;

  __u32 sched_policy;
  __u64 sched_flags;

  /* SCHED_NORMAL, SCHED_BATCH */
  __s32 sched_nice;

  /* SCHED_FIFO, SCHED_RR */
  __u32 sched_priority;

  /* SCHED_DEADLINE (nsec) */
  __u64 sched_runtime;
  __u64 sched_deadline;
  __u64 sched_period;
};

struct if_dqinfo {
  __u64 dqi_bgrace;
  __u64 dqi_igrace;
  __u32 dqi_flags;
  __u32 dqi_valid;
};

struct if_dqblk {
  __u64 dqb_bhardlimit;
  __u64 dqb_bsoftlimit;
  __u64 dqb_curspace;
  __u64 dqb_ihardlimit;
  __u64 dqb_isoftlimit;
  __u64 dqb_curinodes;
  __u64 dqb_btime;
  __u64 dqb_itime;
  __u32 dqb_valid;
};

typedef struct fs_qfilestat {
  __u64 qfs_ino;
  __u64 qfs_nblks;
  __u32 qfs_nextents;
} fs_qfilestat_t;

struct fs_quota_stat {
  __s8 qs_version;
  __u16 qs_flag;
  __s8 qs_pad;
  fs_qfilestat_t qs_uquota;
  fs_qfilestat_t qs_gquota;
  __u32 qs_incoredqs;
  __s32 qs_btimelimit;
  __s32 qs_itimelimit;
  __s32 qs_rtbtimelimit;
  __u16 qs_bwarnlimit;
  __u16 qs_iwarnlimit;
};

struct fs_disk_quota {
  __s8 d_version;
  __s8 d_flags;
  __u16 d_fieldmask;
  __u32 d_id;
  __u64 d_blk_hardlimit;
  __u64 d_blk_softlimit;
  __u64 d_ino_hardlimit;
  __u64 d_ino_softlimit;
  __u64 d_bcount;
  __u64 d_icount;
  __s32 d_itimer;
  __s32 d_btimer;
  __u16 d_iwarns;
  __u16 d_bwarns;
  __s32 d_padding2;
  __u64 d_rtb_hardlimit;
  __u64 d_rtb_softlimit;
  __u64 d_rtbcount;
  __s32 d_rtbtimer;
  __u16 d_rtbwarns;
  __s16 d_padding3;
  char d_padding4[8];
};

struct file_handle {
  __u32 handle_bytes;
  int handle_type;
  /* file identifier */
  unsigned char f_handle[0];
};

typedef __u64 git_t;

#endif