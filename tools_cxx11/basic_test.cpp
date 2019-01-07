#include<iostream>

int main(int argc, char** argv) {

  if (argc > 3) {
    return 1;
  }

  if (argc > 5) {
    return 2;
  }

  if (argc > 7) {
    return 3;
  }

  if (argc > 9) {
    return 4;
  }

  if (argc > 11) {
    return 5;
  }

  int sum = 0;
  for (int i = 0; i < argc+100; i++) {
    sum += i;
  }

  return 0;
}
