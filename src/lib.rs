#![no_std]

pub mod compile;
mod consts;

#[cfg(all(test, feature = "std"))]
mod test {
    extern crate std;

    use crate::compile::{JitContext, *};
    use std::io::Write;
    use std::vec::Vec;

    #[test]
    fn compile_sum_test() {
        // load eBPF program
        let prog = include_bytes!("../tests/test_ebpf.bin");

        // copy eBPF instruction
        let insns: Vec<u64> = prog
            .chunks_exact(8)
            .map(|x| {
                u64::from_le_bytes({
                    let mut buf: [u8; 8] = Default::default();
                    buf.copy_from_slice(x);
                    buf
                })
            })
            .collect();

        // create JIT context
        let mut ctx = JitContext::new(&insns);
        let helpers = [0xdeadu64, 0xbeef, 0xbad, 0xc0de];

        // compile and write to c stub code
        compile(&mut ctx, &helpers, 512);

        // create file to output generated machine code
        let mut stub_source = std::fs::File::create("tests/test_jit.c").unwrap();

        // write program header
        stub_source
            .write_all("#include <stdint.h>\n\n".as_bytes())
            .unwrap();

        // write machine code
        stub_source
            .write_all(
                "__attribute__((section(\".text\"))) __attribute__((aligned(16))) const uint32_t JIT_CODE[] = {".as_bytes(),
            )
            .unwrap();
        for inst in ctx.get_rv_code() {
            stub_source.write_fmt(format_args!("{}, ", &inst)).unwrap();
        }

        // write code
        stub_source.write_all("};\n".as_bytes()).unwrap();
        stub_source
            .write_fmt(format_args!(
                "uint32_t JIT_CODE_SIZE = {};\n",
                4 * ctx.get_rv_code().len()
            ))
            .unwrap();

        // let mut f = std::fs::File::create("jit.bin").unwrap();
        // let data = ctx.get_rv_code().as_slice();
        // let slice = unsafe {
        //     core::slice::from_raw_parts(
        //         data.as_ptr() as *const u8,
        //         data.len() * std::mem::size_of::<u32>(),
        //     )
        // };
        // f.write(slice).unwrap();
    }
}
