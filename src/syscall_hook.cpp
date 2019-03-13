#include "syscall_hook.h"
#include "config.h"
#include "debug.h"
#include "tagmap.h"
#include <iostream>

extern syscall_desc_t syscall_desc[SYSCALL_MAX];

// By default.
#define NUM_FD_SET 5
static int fuzzing_fd[NUM_FD_SET] = {-1, -1, -1, -1, -1};
static u32 stdin_read_off = 0;
static bool tainted = false;

/* XXX: Latest Intel Pin (3.7) doesn't support pread64 and stat
 * (See $PIN_ROOT/intel64/runtime/pincrt/libc-dynamic.so) */
ssize_t pread64(int fd, void *buf, size_t nbyte, off64_t offset) {
  /* Since we must not change the file pointer preserve the value so that
  we can restore it later.  */
  int save_errno;
  ssize_t result;
  off64_t old_offset = lseek64(fd, 0, SEEK_CUR);
  if (old_offset == (off64_t)-1)
    return -1;
  /* Set to wanted position.  */
  if (lseek(fd, offset, SEEK_SET) == (off64_t)-1)
    return -1;
  /* Write out the data.  */
  result = read(fd, buf, nbyte);
  /* Now we have to restore the position.  If this fails we have to
     return this as an error.  But if the writing also failed we
     return this error.  */
  save_errno = errno;
  if (lseek(fd, old_offset, SEEK_SET) == (off64_t)-1) {
    if (result == -1)
      errno = save_errno;
    return -1;
  }
  errno = save_errno;
  return result;
}

bool is_tainted() { return tainted; }

static bool is_fuzzing_fd(int fd) {
  if (fd == STDIN_FILENO)
    return true;
  if (fd < 0)
    return false;
  for (int i = 0; i < NUM_FD_SET; i++) {
    if (fuzzing_fd[i] == fd) {
      return true;
    } else if (fuzzing_fd[i] < 0) {
      break;
    }
  }

  return false;
}

static void add_fuzzing_fd(int fd) {
  if (fd < 0)
    return;
  for (int i = 0; i < NUM_FD_SET; i++) {
    if (fuzzing_fd[i] == fd)
      return;
    if (fuzzing_fd[i] < 0) {
      fuzzing_fd[i] = fd;
      return;
    }
  }
  fuzzing_fd[0] = fd;
}

static void remove_fuzzing_fd(int fd) {
  if (fd < 0)
    return;
  int i;
  int k = -1;

  for (i = 0; i < NUM_FD_SET; i++) {
    if (fuzzing_fd[i] == fd) {
      k = i;
    } else if (fuzzing_fd[i] < 0) {
      break;
    }
  }
  if (k >= 0) {
    fuzzing_fd[k] = fuzzing_fd[i - 1];
    fuzzing_fd[i - 1] = -1;
  }
}

/* __NR_open post syscall hook */
static void post_open_hook(THREADID tid, syscall_ctx_t *ctx) {
  const int fd = ctx->ret;
  if (unlikely(fd < 0))
    return;
  const char *file_name = (char *)ctx->arg[SYSCALL_ARG0];
  if (strstr(file_name, FUZZING_INPUT_FILE) != NULL) {
    add_fuzzing_fd(fd);
    LOGD("[open] fd: %d : %s \n", fd, file_name);
  }
}

/* __NR_openat post syscall hook */
// int openat(int dirfd, const char *pathname, int flags, mode_t mode);
static void post_openat_hook(THREADID tid, syscall_ctx_t *ctx) {
  const int fd = ctx->ret;
  const char *file_name = (char *)ctx->arg[SYSCALL_ARG1];
  if (strstr(file_name, FUZZING_INPUT_FILE) != NULL) {
    add_fuzzing_fd(fd);
    LOGD("[openat] fd: %d : %s \n", fd, file_name);
  }
}

static void post_dup_hook(THREADID tid, syscall_ctx_t *ctx) {
  const int ret = ctx->ret;
  if (ret < 0)
    return;
  const int old_fd = ctx->arg[SYSCALL_ARG0];
  if (is_fuzzing_fd(old_fd)) {
    LOGD("[dup] fd: %d -> %d\n", old_fd, ret);
    add_fuzzing_fd(ret);
  }
}

static void post_dup2_hook(THREADID tid, syscall_ctx_t *ctx) {
  const int ret = ctx->ret;
  if (ret < 0)
    return;
  const int old_fd = ctx->arg[SYSCALL_ARG0];
  const int new_fd = ctx->arg[SYSCALL_ARG1];
  if (is_fuzzing_fd(old_fd)) {
    add_fuzzing_fd(new_fd);
    LOGD("[dup2] fd: %d -> %d\n", old_fd, new_fd);
  }
}

/* __NR_close post syscall hook */
static void post_close_hook(THREADID tid, syscall_ctx_t *ctx) {
  if (unlikely((long)ctx->ret < 0))
    return;
  const int fd = ctx->arg[SYSCALL_ARG0];
  if (is_fuzzing_fd(fd)) {
    remove_fuzzing_fd(fd);
    LOGD("[close] fd: %d \n", fd);
  }
}

static void post_read_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* read() was not successful; optimized branch */
  const size_t nr = ctx->ret;
  if (unlikely(nr <= 0))
    return;

  const int fd = ctx->arg[SYSCALL_ARG0];
  const ADDRINT buf = ctx->arg[SYSCALL_ARG1];
  char *pbuf = (char *)buf;
  size_t count = ctx->arg[SYSCALL_ARG2];

  /* taint-source */
  if (is_fuzzing_fd(fd)) {
    tainted = true;

    unsigned int read_off = 0;
    if (fd == STDIN_FILENO) {
      // maintain it by ourself
      read_off = stdin_read_off;
      stdin_read_off += nr;
    } else {
      // low-level POSIX file descriptor I/O.
      read_off = lseek(fd, 0, SEEK_CUR);
      read_off -= nr; // post
    }

    LOGD("[read] fd: %d, addr: %p, offset: %d, size: %lu / %lu\n", fd, pbuf,
         read_off, nr, count);

    /* set the tag markings */
    // Attn: use count replace nr
    // But count may be very very large!
    if (count > nr + 32) {
      count = nr + 32;
    }

    for (unsigned int i = 0; i < count; i++) {
      tag_t t = tag_alloc<tag_t>(read_off + i);
      tagmap_setb(buf + i, t);
      // LOGD("[read] %d, lb: %d,  %s\n", i, t, tag_sprint(t).c_str());
    }

    tagmap_setb_reg(tid, DFT_REG_RAX, 0, BDD_LEN_LB);

  } else {
    /* clear the tag markings */
    tagmap_clrn(buf, nr);
  }
}

/* __NR_pread64 post syscall hook */
static void post_pread64_hook(THREADID tid, syscall_ctx_t *ctx) {
  const size_t nr = ctx->ret;
  if (unlikely(nr <= 0))
    return;
  const int fd = ctx->arg[SYSCALL_ARG0];
  const ADDRINT buf = ctx->arg[SYSCALL_ARG1];
  size_t count = ctx->arg[SYSCALL_ARG2];
  const u32 read_off = ctx->arg[SYSCALL_ARG3];

  if (is_fuzzing_fd(fd)) {
    tainted = true;
    LOGD("[pread] fd: %d, offset: %d, size: %lu\n", fd, read_off, nr);
    if (count > nr + 32) {
      count = nr + 32;
    }
    /* set the tag markings */
    for (u32 i = 0; i < count; i++) {
      tag_t t = tag_alloc<tag_t>(read_off + i);
      tagmap_setb(buf + i, t);
    }
  } else {
    /* clear the tag markings */
    tagmap_clrn(buf, count);
  }
}

// void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t
// offset);
/* __NR_mmap post syscall hook */
static void post_mmap_hook(THREADID tid, syscall_ctx_t *ctx) {
  const ADDRINT ret = ctx->ret;
  const int fd = ctx->arg[SYSCALL_ARG4];
  const int prot = ctx->arg[SYSCALL_ARG2];
  // PROT_READ 0x1
  if ((void *)ret == (void *)-1 || !(prot & 0x1))
    return;
  const ADDRINT buf = ctx->arg[SYSCALL_ARG0];
  const size_t nr = ctx->arg[SYSCALL_ARG1];
  const off_t read_off = ctx->arg[SYSCALL_ARG5];
  // fprintf(stderr, "[mmap] fd: %d(%d), addr: %x, readoff: %ld, nr:%d \n", fd,
  //       is_fuzzing_fd(fd), buf, read_off, nr);
  if (is_fuzzing_fd(fd)) {
    tainted = true;
    LOGD("[mmap] fd: %d, offset: %ld, size: %lu\n", fd, read_off, nr);
    for (u32 i = 0; i < nr; i++) {
      tag_t t = tag_alloc<tag_t>(read_off + i);
      tagmap_setb(buf + i, t);
    }
  } else {
    tagmap_clrn(buf, nr);
  }
}

static void post_munmap_hook(THREADID tid, syscall_ctx_t *ctx) {
  const ADDRINT ret = ctx->ret;
  if ((void *)ret == (void *)-1)
    return;
  const ADDRINT buf = ctx->arg[SYSCALL_ARG0];
  const size_t nr = ctx->arg[SYSCALL_ARG1];

  // std::cerr <<"[munmap] addr: " << buf << ", nr: "<< nr << std::endl;
  tagmap_clrn(buf, nr);
}

void hook_file_syscall() {
  (void)syscall_set_post(&syscall_desc[__NR_open], post_open_hook);
  (void)syscall_set_post(&syscall_desc[__NR_openat], post_openat_hook);
  (void)syscall_set_post(&syscall_desc[__NR_dup], post_dup_hook);
  (void)syscall_set_post(&syscall_desc[__NR_dup2], post_dup2_hook);
  (void)syscall_set_post(&syscall_desc[__NR_dup3], post_dup2_hook);
  (void)syscall_set_post(&syscall_desc[__NR_close], post_close_hook);

  (void)syscall_set_post(&syscall_desc[__NR_read], post_read_hook);
  (void)syscall_set_post(&syscall_desc[__NR_pread64], post_pread64_hook);
  // (void)syscall_set_post(&syscall_desc[__NR_readv], post_readv_hook);
  // (void)syscall_set_post(&syscall_desc[__NR_mmap2], post_mmap2_hook);
  (void)syscall_set_post(&syscall_desc[__NR_mmap], post_mmap_hook);
  (void)syscall_set_post(&syscall_desc[__NR_munmap], post_munmap_hook);
}