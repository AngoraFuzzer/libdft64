#include "stdio.h"
#include "stdint.h"
#include "stdlib.h"

int main (int argc, char** argv) {

  char x = 0;

  int ret = scanf("%c", &x);

  if (!ret) {
    return 1;
  }

  if (x == 123) {

    printf("hey, you hit it \n");
    abort();

  }
  
  return 0;
}
