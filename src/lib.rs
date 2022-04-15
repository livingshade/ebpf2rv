pub mod compile;
mod consts;

#[cfg(test)]
mod test {
    use std::io::Write;

    use crate::compile::{JitContext, *};

    fn write_cstub(code: &[u32]) {
        let mut stub_source = std::fs::File::create("tests/jitcode.c").unwrap();

        // write program header
        stub_source
            .write_all("#include <stdint.h>\n\n".as_bytes())
            .unwrap();

        // write machine code
        stub_source
            .write_all("static uint32_t JIT_CODE[] = {".as_bytes())
            .unwrap();
        for inst in code {
            stub_source.write_fmt(format_args!("{}, ", &inst)).unwrap();
        }

        // write code
        stub_source.write_all("};\n".as_bytes()).unwrap();
    }

    #[test]
    fn compile_sum_test() {
        // load eBPF program
        let prog = include_bytes!("../tests/sum.bin");

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
        compile(&mut ctx, &helpers);
        write_cstub(ctx.get_rv_code().as_slice());
    }
}
