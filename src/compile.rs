extern crate alloc;

use crate::consts::*;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use std::format;

// this mapping is made consistent with linux BPF JIT for RV64
fn bpf_to_rv_reg(reg: u8) -> u8 {
    static REG_MAP: [u8; BPF_MAX_REGS] = [
        RV_REG_A5, // R0
        RV_REG_A0, // R1
        RV_REG_A1, // R2
        RV_REG_A2, // R3
        RV_REG_A3, // R4
        RV_REG_A4, // R5
        RV_REG_S1, // R6
        RV_REG_S2, // R7
        RV_REG_S3, // R8
        RV_REG_S4, // R9
        RV_REG_S5, // FP
    ];
    REG_MAP[reg as usize]
}

fn rv_reg_name(reg: u8) -> &'static str {
    static REG_NAMES: [&str; 32] = [
        "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "fp", "s1", "a0", "a1", "a2", "a3", "a4",
        "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
        "t5", "t6",
    ];
    REG_NAMES[reg as usize]
}

fn is_in_i32_range(v: i64) -> bool {
    -(1 << 31) <= v && v < (1 << 31)
}

fn is_in_i12_range(v: i32) -> bool {
    -(1 << 11) <= v && v < (1 << 11)
}

fn round_up(x: usize, d: usize) -> usize {
    ((x + d - 1) / d) * d
}

// type Helper = unsafe fn(u64, u64, u64, u64, u64) -> u64;

pub struct JitContext<'a> {
    bpf_insns: &'a [u64],
    bpf_pc: usize,
    source: Vec<String>,
    code_size: usize,
    pc_map: BTreeMap<usize, usize>,
    plt_loads: Vec<usize>,
    plt_offset: usize,
}

impl<'a> JitContext<'a> {
    pub fn new(bpf_insns: &'a [u64]) -> Self {
        Self {
            bpf_insns,
            bpf_pc: 0,
            source: vec![],
            code_size: 0,
            pc_map: BTreeMap::new(),
            plt_loads: vec![],
            plt_offset: 0,
        }
    }

    pub fn get_rv_source(&self) -> &Vec<String> {
        &self.source
    }

    pub fn comment(&mut self, msg: String) {
        self.source.push(msg);
    }

    fn emit_placeholder(&mut self, s: &str) {
        self.source.push(String::from(s));
        self.code_size += 4;
    }

    pub fn emit_lui(&mut self, rd: u8, imm: u32) {
        self.source
            .push(format!("lui {}, {}", rv_reg_name(rd), imm));
        self.code_size += 4;
    }

    pub fn emit_add(&mut self, rd: u8, rs1: u8, rs2: u8) {
        self.source.push(format!(
            "add {}, {}, {}",
            rv_reg_name(rd),
            rv_reg_name(rs1),
            rv_reg_name(rs2)
        ));
        self.code_size += 4;
    }
    pub fn emit_sub(&mut self, rd: u8, rs1: u8, rs2: u8) {
        self.source.push(format!(
            "sub {}, {}, {}",
            rv_reg_name(rd),
            rv_reg_name(rs1),
            rv_reg_name(rs2)
        ));
        self.code_size += 4;
    }

    pub fn emit_subw(&mut self, rd: u8, rs1: u8, rs2: u8) {
        self.source.push(format!(
            "subw {}, {}, {}",
            rv_reg_name(rd),
            rv_reg_name(rs1),
            rv_reg_name(rs2)
        ));
        self.code_size += 4;
    }

    pub fn emit_addi(&mut self, rd: u8, rs1: u8, imm: i32) {
        self.source.push(format!(
            "addi {}, {}, {}",
            rv_reg_name(rd),
            rv_reg_name(rs1),
            imm
        ));
        self.code_size += 4;
    }

    pub fn emit_addiw(&mut self, rd: u8, rs1: u8, imm: i32) {
        self.source.push(format!(
            "addiw {}, {}, {}",
            rv_reg_name(rd),
            rv_reg_name(rs1),
            imm
        ));
        self.code_size += 4;
    }

    pub fn emit_slli(&mut self, rd: u8, rs: u8, shamt: u8) {
        self.source.push(format!(
            "slli {}, {}, {}",
            rv_reg_name(rd),
            rv_reg_name(rs),
            shamt
        ));
        self.code_size += 4;
    }

    pub fn emit_srli(&mut self, rd: u8, rs: u8, shamt: u8) {
        self.source.push(format!(
            "srli {}, {}, {}",
            rv_reg_name(rd),
            rv_reg_name(rs),
            shamt
        ));
        self.code_size += 4;
    }

    pub fn emit_ld(&mut self, rd: u8, rs: u8, imm: i32) {
        self.source.push(format!(
            "ld {}, {}({})",
            rv_reg_name(rd),
            imm,
            rv_reg_name(rs)
        ));
        self.code_size += 4;
    }

    pub fn emit_jalr(&mut self, rd: u8, rs: u8, imm: i32) {
        self.source.push(format!(
            "jalr {}, {}({})",
            rv_reg_name(rd),
            imm,
            rv_reg_name(rs)
        ));
        self.code_size += 4;
    }

    // zero-extend a 32-bit value
    pub fn emit_zext_32(&mut self, rd: u8, rs: u8) {
        self.emit_slli(rd, rs, 32);
        self.emit_srli(rd, rd, 32);
    }

    // code generation for immediate is not straightforward.
    // this snippet is adapted from linux, see https://elixir.bootlin.com/linux/latest/source/arch/riscv/net/bpf_jit_comp64.c#L139
    pub fn emit_imm(&mut self, rd: u8, imm: i64) {
        let hi = (imm + (1 << 11)) >> 12;
        let lo = (((imm & 0xfff) << 52) >> 52) as i32;

        if is_in_i32_range(imm) {
            if hi != 0 {
                self.emit_lui(rd, hi as u32);
                self.emit_addiw(rd, rd, lo);
            } else {
                self.emit_addi(rd, RV_REG_ZERO, lo);
            }
            return;
        }

        let shift = hi.trailing_zeros() as u8; // find first bit
        self.emit_imm(rd, hi >> shift);

        self.emit_slli(rd, rd, shift + 12);
        if lo != 0 {
            self.emit_addi(rd, rd, lo);
        }
    }

    // dst stands for a eBPF register
    pub fn emit_load_imm64(&mut self, dst: u8, imm: i64) {
        self.pc_map.insert(self.bpf_pc - 1, self.code_size);
        self.source.push(format!("# LD_IMM_DW R{}, {}", dst, imm));

        let rd = bpf_to_rv_reg(dst);
        self.emit_imm(rd, imm);
    }

    pub fn emit_call(&mut self, imm: i32) {
        let rvoff = self.code_size;
        self.plt_loads.push(rvoff);
        self.emit_placeholder("auipc t1, %hi(plt)");
        self.emit_placeholder("addi t1, t1, %lo(plt)");
        // assume there are no more than 2048 / 8 = 256 helper functions
        self.emit_addi(RV_REG_T1, RV_REG_T1, imm * 8);
        self.emit_ld(RV_REG_T2, RV_REG_T1, 0);
        self.emit_jalr(RV_REG_RA, RV_REG_T2, 0);
        self.emit_addi(bpf_to_rv_reg(BPF_REG_R0), RV_REG_A0, 0); // move a0 -> R0
    }

    pub fn emit_exit(&mut self) {
        self.emit_addi(RV_REG_A0, bpf_to_rv_reg(BPF_REG_R0), 0); // move R0 -> a0
        self.emit_jalr(RV_REG_ZERO, RV_REG_RA, 0); // ret
    }

    fn fix_plt_load(&mut self, rvoff: usize) {
        // TODO
        self.comment(format!("# fix (auipc + addi) at offset {}", rvoff));
    }

    pub fn build_helper_fn_table(&mut self, helpers: &[u64]) {
        self.comment(String::from("# helpers table"));
        self.plt_offset = round_up(self.code_size, 8);

        for helper in helpers {
            self.comment(format!(".quad {:#016x}", helper));
        }

        let plt_loads = self.plt_loads.clone();
        for &off in &plt_loads {
            self.fix_plt_load(off);
        }
    }
}

pub fn compile(ctx: &mut JitContext) {
    let mut prev_imm: i32 = 0;
    let mut prev_dst: u8 = 0;
    let mut is_load_imm64 = false;

    for (i, &insn) in ctx.bpf_insns.iter().enumerate() {
        let op = (insn & 0xff) as u8;
        let dst = ((insn & 0x0f00) >> 8) as u8;
        let src = ((insn & 0xf000) >> 12) as u8;
        let off = (insn >> 16) as i16;
        let imm = (insn >> 32) as i32;
        ctx.bpf_pc = i;

        // process the only 16-bytes instruction: LD_IMM_DW
        if is_load_imm64 {
            is_load_imm64 = false;
            let imm64 = (prev_imm as u64) | ((imm as u64) << 32);
            ctx.emit_load_imm64(prev_dst, imm64 as i64);
            continue;
        }

        if op == LD_IMM_DW {
            prev_imm = imm;
            prev_dst = dst;
            is_load_imm64 = true;
            continue;
        }

        let is64 = (op & 0b111) == BPF_ALU64 as u8;
        let use_imm = (op & 8) == 0;
        let rd = bpf_to_rv_reg(dst);
        let mut rs = bpf_to_rv_reg(src);

        ctx.pc_map.insert(ctx.bpf_pc, ctx.code_size);
        ctx.comment(format!("# {}: {:#016x}", i, insn));

        match op {
            ALU_X_ADD | ALU_K_ADD | ALU64_X_ADD | ALU64_K_ADD => {
                if use_imm {
                    ctx.emit_imm(RV_REG_T1, imm as i64);
                    rs = RV_REG_T1;
                }
                ctx.emit_add(rd, rd, rs);
                if !is64 {
                    ctx.emit_zext_32(rd, rd);
                }
            }
            ALU_X_SUB | ALU_K_SUB | ALU64_X_SUB | ALU64_K_SUB => {
                if use_imm {
                    ctx.emit_imm(RV_REG_T1, imm as i64);
                    ctx.emit_sub(rd, rd, RV_REG_T1);
                } else {
                    if is64 {
                        ctx.emit_sub(rd, rd, rs);
                    } else {
                        ctx.emit_subw(rd, rd, rs);
                    }
                }
                if !is64 {
                    ctx.emit_zext_32(rd, rd);
                }
            }
            ALU_X_MOV | ALU64_X_MOV | ALU_K_MOV | ALU64_K_MOV => {
                if use_imm {
                    ctx.emit_imm(rd, imm as i64);
                } else {
                    ctx.emit_addi(rd, rs, 0);
                }
                if !is64 {
                    ctx.emit_zext_32(rd, rd);
                }
            }
            JMP_K_CALL => {
                ctx.emit_call(imm);
            }
            JMP_K_EXIT => {
                ctx.emit_exit();
            }
            _ => {
                ctx.comment(format!("# unimplemented BPF instruction: {:#016x}", insn));
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::{compile, JitContext};

    #[test]
    fn sum() {
        let prog = include_bytes!("../samples/sum.bin");
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

        let mut ctx = JitContext::new(&insns);
        compile(&mut ctx);

        let helpers = [0xdeadu64, 0xbeef, 0xbad, 0xc0de];
        ctx.build_helper_fn_table(&helpers);

        for rv_insn in ctx.get_rv_source() {
            println!("{}", rv_insn);
        }
    }
}
