# ebpf2rv

ebpf2rv is a simple eBPF JIT for RV64

## notes

behaviors of lui() and auipc() in rvjit do not conform with normal assemblers.

e.g. after `lui a0, 1` the value of `a0` should be 4096. instead of writing `lui(A0, 1)`, you should use `lui(A0, 4096)`.
