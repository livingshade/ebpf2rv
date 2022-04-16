#include <stdint.h>
#include <stdio.h>

extern uint64_t JIT_CODE(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

int main() {
  const int SUM_RESULT = 5050; // from 1 to 100

  uint64_t result = JIT_CODE(0, 0, 0, 0, 0);

  printf("result is %lu\n", result);

  // check the result
  if (result != SUM_RESULT) {
    return 1;
  } else {
    return 0;
  }
}
