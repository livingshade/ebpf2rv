# ebpf2rv

ebpf2rv is a simple eBPF JIT for RISC-V 64 utilizing RvJIT as its assembler. It is used in rCore to provide fast, stable and decent eBPF support.

## Building

This project serves as a library. Just add this as an dependency. In default, it does not require `std` to operate. If you wish, you could engage the test suit by running `python3 test.py`. Necessary tools for testing would be detected by the script. Including:

* `clang` compiler
* `llvm` toolchain (`llvm-objdump` is used)
* rust toolchain
* `riscv64-unknown-elf-gcc` and `qemu-riscv64` to run jitted riscv64 program.

## Usage

Assuming you've got your eBPF bytecode as `Vec<u64>`, a `JitContext` could be created by:

```rust
let mut ctx = JitContext::new(&insts);

// Compilation
compile(&mut ctx, &helpers, code_size);
```

Helper functions (see `man bpf-helpers`) as injected with their locations, in the form of a array of `u64`. After compilation, you could fetch the machine code by `ctx.get_rv_code()` and transform into a function pointer to execute. 

## Contribution

See [implementation](./docs/ebpf2rv.md) for implementation and furthur contribution.
