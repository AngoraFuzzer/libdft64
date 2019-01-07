#include "hook.h"
#include <iostream>

//extern ins_desc_t ins_desc[XED_ICLASS_LAST];
extern syscall_desc_t syscall_desc[SYSCALL_MAX];
extern TagSet tag_set;
// By default.
#define NUM_FD_SET 10
static int fuzzing_fd[NUM_FD_SET] = {STDIN_FILENO, -1, -1, -1, -1,
                             -1, -1, -1, -1, -1};
static u32 stdin_read_off = 0;

bool is_tainted() {
  return (stdin_read_off > 0 || fuzzing_fd[1] > 0);
}

static bool is_fuzzing_fd(int fd) {
  if (fd < 0) return false;

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
  if (fd < 0) return;
  for (int i = 0; i < NUM_FD_SET; i++) {

    if (fuzzing_fd[i] == fd) return;

    if (fuzzing_fd[i] < 0) {
      fuzzing_fd[i] = fd;
    }
  }
  fuzzing_fd[0] = fd;
}

static void remove_fuzzing_fd(int fd) {
  if (fd < 0) return;
  int i;
  int k = 0;
  for (i = 0; i < NUM_FD_SET; i++) {
    if (fuzzing_fd[i] == fd) {
      k = i;
    } else if (fuzzing_fd[i] < 0) {
      break;
    }
  }
  fuzzing_fd[k] = fuzzing_fd[i-1];
  fuzzing_fd[i-1] = -1;
}

static void post_open_hook(syscall_ctx_t *ctx) {
  const int fd = ctx->ret;
  if (unlikely(fd < 0))
    return;
  const char* file_name = (char*)ctx->arg[SYSCALL_ARG0];
  if (strstr(file_name, FUZZING_INPUT_FILE) != NULL) {
    add_fuzzing_fd(fd);
  }
  fprintf(stderr, "[open] fd: %d(%d) : %s \n", fd, is_fuzzing_fd(fd), file_name);
}

static void post_close_hook(syscall_ctx_t *ctx) {
  if (unlikely((long)ctx->ret < 0))
    return;
  const int fd = ctx->arg[SYSCALL_ARG0];
  if (is_fuzzing_fd(fd)) {
    remove_fuzzing_fd(fd);
  }
  fprintf(stderr, "[close] fd: %d(%d) \n", fd, is_fuzzing_fd(fd));
}

static void post_read_hook(syscall_ctx_t *ctx) {
  /* read() was not successful; optimized branch */
  const size_t nr = ctx->ret;
  if (unlikely(nr <= 0))
    return;

  const int fd = ctx->arg[SYSCALL_ARG0];
  const ADDRINT buf = ctx->arg[SYSCALL_ARG1];
  /* taint-source */
  fprintf(stderr, "[read] fd: %d(%d) \n", fd, is_fuzzing_fd(fd));
  if (is_fuzzing_fd(fd)) {
    u32 read_off = 0;
    if (fd == STDIN_FILENO) {
      // maintain it by ourself
      read_off = stdin_read_off;
      stdin_read_off += nr;
    } else {
      // low-level POSIX file descriptor I/O.
      read_off = lseek(fd, 0, SEEK_CUR);
      read_off -= nr;      // post
    }
    fprintf(stderr, "readoff: %d, nr:%d\n", read_off, nr);
    /* set the tag markings */
    for (u32 i = 0; i < nr; i++) {
#ifdef USE_TREE_TAG
      tagmap_setb_with_tag(buf + i, tag_set.insert(read_off + i));
#else
      tag_off from = read_off + i;
      tag_off to = from + 1;
      tag_t new_tag = std::vector<tag_seg>{{from, to}};
      tagmap_setb_with_tag(buf + i, new_tag);
#endif
      //std::cout << hex << buf + i << ": " << tag_sprint(tagmap_getb(buf+i)) <<std::endl;
    }

  } else {
    /* clear the tag markings */
    tagmap_clrn(buf, nr);
  }
}

static void post_pread_hook(syscall_ctx_t *ctx) {
  const size_t nr = ctx->ret;
  if (unlikely(nr <= 0))
    return;
  const int fd = ctx->arg[SYSCALL_ARG0];
  const ADDRINT buf = ctx->arg[SYSCALL_ARG1];
  const u32 read_off = ctx->arg[SYSCALL_ARG3];
  fprintf(stderr, "[pread] fd: %d(%d), readoff: %d, nr:%d \n", fd, is_fuzzing_fd(fd), read_off, nr);
  if (is_fuzzing_fd(fd)) {
    /* set the tag markings */
    for (u32 i = 0; i < nr; i++) {
#ifdef USE_TREE_TAG
      tagmap_setb_with_tag(buf + i, tag_set.insert(read_off + i));
#else
      tag_off from = read_off + i;
      tag_off to = from + 1;
      tag_t new_tag = std::vector<tag_seg>{{from, to}};
      tagmap_setb_with_tag(buf + i, new_tag);
#endif
    }
  } else {
    /* clear the tag markings */
    tagmap_clrn(buf, nr);
  }
}

static void post_readv_hook(syscall_ctx_t *ctx) {
  std::cerr <<"[readv] still not support \n";
}

//void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t offset);
static void post_mmap_hook(syscall_ctx_t *ctx) {
  const ADDRINT ret = ctx->ret;
  const int fd = ctx->arg[SYSCALL_ARG4];
  const int prot = ctx->arg[SYSCALL_ARG2];
  //PROT_READ 0x1
  if ((void*)ret == (void*)-1 || !(prot & 0x1)) return;
  const ADDRINT buf = ctx->arg[SYSCALL_ARG0];
  const size_t nr = ctx->arg[SYSCALL_ARG1];
  const off_t read_off = ctx->arg[SYSCALL_ARG5];
  fprintf(stderr, "[mmap] fd: %d(%d), addr: %x, readoff: %ld, nr:%d \n", fd, is_fuzzing_fd(fd), buf, read_off, nr);
  if (is_fuzzing_fd(fd)) {
    for (u32 i = 0; i < nr; i++) {
#ifdef USE_TREE_TAG
      tagmap_setb_with_tag(buf + i, tag_set.insert(read_off + i));
#else
      tag_off from = read_off + i;
      tag_off to = from + 1;
      tag_t new_tag = std::vector<tag_seg>{{from, to}};
      tagmap_setb_with_tag(buf + i, new_tag);
#endif
    }
  } else {
    tagmap_clrn(buf, nr);
  }
}

//void *mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t pgoffset);
//pgoffset: offset of page = *4096 bytes
static void post_mmap2_hook(syscall_ctx_t *ctx) {
    const ADDRINT ret = ctx->ret;
    const int fd = ctx->arg[SYSCALL_ARG4];
    const int prot = ctx->arg[SYSCALL_ARG2];
    //PROT_READ 0x1
    if ((void*)ret == (void*)-1 || !(prot & 0x1)) return;
    const ADDRINT buf = ctx->arg[SYSCALL_ARG0];
    const size_t nr = ctx->arg[SYSCALL_ARG1];
    const off_t read_off = ctx->arg[SYSCALL_ARG5] * 4096;
    fprintf(stderr, "[mmap] fd: %d(%d), addr: %x, readoff: %ld, nr:%d \n", fd, is_fuzzing_fd(fd), buf, read_off, nr);
    if (is_fuzzing_fd(fd)) {
      for (u32 i = 0; i < nr; i++) {
#ifdef USE_TREE_TAG
        tagmap_setb_with_tag(buf + i, tag_set.insert(read_off + i));
#else
        tag_off from = read_off + i;
        tag_off to = from + 1;
        tag_t new_tag = std::vector<tag_seg>{{from, to}};
        tagmap_setb_with_tag(buf + i, new_tag);
#endif
      }
    } else {
      tagmap_clrn(buf, nr);
    }
}

static void post_munmap_hook(syscall_ctx_t *ctx) {
  const ADDRINT ret = ctx->ret;
  if ((void*)ret == (void*)-1) return;
  const ADDRINT buf = ctx->arg[SYSCALL_ARG0];
  const size_t nr = ctx->arg[SYSCALL_ARG1];

  std::cerr <<"[munmap] addr: " << buf << ", nr: "<< nr << std::endl;
  tagmap_clrn(buf, nr);
}

static void post_dup_hook(syscall_ctx_t *ctx) {
  const int ret = ctx->ret;
  if (ret < 0) return;
  const int oldfd = ctx->arg[SYSCALL_ARG0];
  std::cerr <<"[dup] \n";
  if (is_fuzzing_fd(oldfd)) {
    add_fuzzing_fd(ret);
  }
}

//int dup2(int oldfd, int newfd);
static void post_dup2_hook(syscall_ctx_t *ctx) {
  const int ret = ctx->ret;
  if (ret < 0) return;
  const int oldfd = ctx->arg[SYSCALL_ARG0];
  const int newfd = ctx->arg[SYSCALL_ARG1];
  std::cerr <<"[dup2] \n";
  if (is_fuzzing_fd(oldfd)) {
    add_fuzzing_fd(newfd);
  }
}


void hook_syscall() {
  (void)syscall_set_post(&syscall_desc[__NR_open], post_open_hook);
  // (void)syscall_set_post(&syscall_desc[__NR_creat], post_open_hook);
	(void)syscall_set_post(&syscall_desc[__NR_close], post_close_hook);
  (void)syscall_set_post(&syscall_desc[__NR_read], post_read_hook);
  (void)syscall_set_post(&syscall_desc[__NR_pread64], post_pread_hook);
	(void)syscall_set_post(&syscall_desc[__NR_readv], post_readv_hook);
	(void)syscall_set_post(&syscall_desc[__NR_mmap2], post_mmap2_hook);
	(void)syscall_set_post(&syscall_desc[__NR_mmap], post_mmap_hook);
	(void)syscall_set_post(&syscall_desc[__NR_munmap], post_munmap_hook);
	(void)syscall_set_post(&syscall_desc[__NR_dup2], post_dup_hook);
	(void)syscall_set_post(&syscall_desc[__NR_dup2], post_dup2_hook);
	(void)syscall_set_post(&syscall_desc[__NR_dup3], post_dup2_hook);
}
