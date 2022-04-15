#include <stdint.h>

static uint32_t JIT_CODE[] = {4236312851, 1126435, 8467491, 9517091, 18955299, 53555235, 54604835, 55654435, 6071, 1000834971, 4194415, 492819, 50412163, 42023427, 33634691, 25245955, 16856195, 8467459, 77955, 58786067, 32871, 0, 0, 0, 57005, 0, 48879, 0, 2989, 0, 49374, 0, };

#include <stdio.h>

typedef uint64_t (*ebpf_func_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

int main() {
    const int SUM_RESULT = 5050; // from 1 to 100

    // cast jit code to function
    ebpf_func_t func = (ebpf_func_t)JIT_CODE;
    uint64_t result = func(0, 0, 0, 0, 0);

    printf("result is %d\n", result);

    // check the result
    if(result != SUM_RESULT) {
        return 1;
    } else {
        return 0;
    }
}
