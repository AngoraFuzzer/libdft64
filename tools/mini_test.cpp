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
  printf("buf before addr: %p\n", buf);
  ret = fread(buf, sizeof *buf, len, fp);
  printf("buf after addr: %p\n", buf);
  __libdft_get_taint(buf);

  /*
    fclose(fp);
    // printf("len is :%d\n", len);
    if (ret < len) {
      // printf("input fail \n");
      return 0;
    }

    uint16_t x = 0;
    __libdft_set_taint(buf, 1);
    __libdft_set_taint(buf + 1, 2);
    __libdft_set_taint(buf + 2, 3);
    __libdft_set_taint(buf + 5, 5);
    memcpy(&x, buf + 1, 2); // x 1 - 2

    printf("x addr: %p\n", &x);
    __libdft_get_taint(&x);

    uint64_t y = x + 2;
    __libdft_get_taint(&y);
    __libdft_getval_taint(y);
    // foo(y);

    int32_t y = 0;
    int32_t z = 0;
    uint32_t a = 0;

    memcpy(&y, buf + 4, 4); // y 4 - 7

    memcpy(&z, buf + 10, 4); // 10 - 13
    memcpy(&a, buf + 14, 4); // 14 - 17

    __libdft_get_taint(y);
    __libdft_get_taint(z);
    __libdft_get_taint(a);

    if (x == 12300 && z == -100000005 && y == 987654321 && a == 123456789) {

      printf("hey, you hit it \n");
      abort();
    }
    */
  return 0;
}