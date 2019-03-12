#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

extern "C" {
void __attribute__((noinline)) __libdft_set_taint(void *p, unsigned int v) {
  printf("set: %p, %d\n", p, v);
}

void __attribute__((noinline)) __libdft_get_taint(void *p) {
  printf("get: %p\n", p);
}

void __attribute__((noinline)) __libdft_getval_taint(uint64_t v) {
  printf("getval: %lu\n", v);
}
}

void __attribute__((noinline)) foo(uint64_t v) { __libdft_get_taint(&v); }

int main(int argc, char **argv) {
  if (argc < 2)
    return 0;

  FILE *fp;
  char buf[255];
  size_t ret;

  fp = fopen(argv[1], "rb");

  if (!fp) {
    printf("st err\n");
    return 0;
  }
  int len = 20;
  // dfsan_read_label(&(len), sizeof *buf);
  ret = fread(buf, sizeof *buf, len, fp);

  fclose(fp);
  // printf("len is :%d\n", len);
  if (ret < len) {
    // printf("input fail \n");
    return 0;
  }

  uint64_t m = 0;
  __libdft_set_taint(&m, 8);
  __libdft_get_taint(&m);
  __libdft_getval_taint(m);

  uint16_t x = 0;
  __libdft_get_taint(&x);
  memcpy(&x, buf + 5, 2); // x 1 - 2
  __libdft_get_taint(&x);
  __libdft_getval_taint(x);

  uint64_t y = x + 2;
  __libdft_getval_taint(y);

  return 0;
}