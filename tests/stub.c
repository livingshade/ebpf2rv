#include <stdint.h>

extern uint32_t* JIT_CODE;

typedef uint64_t (*ebpf_func_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

int main() {
    const int SUM_RESULT = 5050; // from 1 to 100

    // cast jit code to function
    ebpf_func_t func = (ebpf_func_t)JIT_CODE;
    uint64_t result = func(0, 0, 0, 0, 0);

    // check the result
    if(result != SUM_RESULT) {
        return 1;
    } else {
        return 0;
    }
}