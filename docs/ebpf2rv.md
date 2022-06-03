# ebpf2rv Implementation Note

* Catalog
    * [Function Signature](#function-signature)
    * [Branching](#branching)
    * [Helper Functions](#helper-functions)
    * [Dispatching Table](#dispatching-table)
    * [Testing](#testing)

## Function Signature

Functions are compiled to the following signature: `(u64, u64, u64, u64, u64) -> u64`, corresponding to the ebpf function, passing `a1 ~ a5` as parameter. eBPF registers are mapped into riscv64 registers:

```
a1-a5 -> s1-s5
fp    -> fp 
```

Original riscv64 registers would be saved. Stack is limited to 1024 bytes, thus only such size would be allocated in the prologue of the function.

## Branching

In order to perform branching, we need an immediate number, which would, in turn, requires a instruction to load such immediate number and thus break the relative offset of branching destination. In this way, branching is emitted as placeholder and during epilogue, all destinations would be re-calculated and emit corresponding `jal` instruction.

Note that `call` is also the same.

## Helper Functions

Helper functions map is also generated to a specific location and relocation is done during generating the epilogue.

## Dispatching Table

All instructions are dispatched via `emit_instructions` function in `compile.rs`. It is recommended to look at the jit compiler in linux kernel to further modify this function to add new instructions. If you are looking for riscv64 instructions that does not existed, please visit `RvJIT` project instead. 

Currently, all `atom` related instructions are not supported.

You should use the `emit_xxx` wrapper of `JitContext` to make sure that instructions are emitted into the expecting location.

## Testing

`std` is required to enable testing. A specific eBPF program would be compiled via ebpf2rv and then injected the machine code into a C program by string concatenation. Then, the C program would be compiled and run in the qemu to test whether it gives the expecting program.

`test.py` would first compile `test_ebpf.c` into eBPF bytecode via `clang` and extracts all bytecode out, then calling rust to compile it into machine code, embedded into C program and compile the stub C program.