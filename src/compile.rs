#[allow(unused)]
extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::consts::*;
use rvjit::rv32i::*;
use rvjit::rv32m::*;
use rvjit::rv64i::*;
use rvjit::rv64m::*;

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
    pub code: Vec<u32>,
    pub code_size: usize,
    pc_map: BTreeMap<usize, usize>,
    plt_loads: Vec<usize>, // for BPF call
    exits: Vec<usize>,     // for BPF exit
    jumps: Vec<(usize, usize)>, // for BPF jump, (bpf_pc, rv_off)
}

impl<'a> JitContext<'a> {
    pub fn new(bpf_insns: &'a [u64]) -> Self {
        Self {
            bpf_insns,
            bpf_pc: 0,
            code: Vec::new(),
            code_size: 0,
            pc_map: BTreeMap::new(),
            plt_loads: Vec::new(),
            exits: Vec::new(),
            jumps: Vec::new(),
        }
    }

    pub fn get_rv_code(&self) -> &Vec<u32> {
        &self.code
    }

    fn emit(&mut self, i: u32) {
        self.code.push(i);
        self.code_size += 4;
    }

    fn emit_placeholder(&mut self, _s: &str) {
        self.emit(0); // invalid instruction
    }

    pub fn emit_lui(&mut self, rd: u8, imm: u32) {
        self.emit(lui(rd, imm << 12)); // see notes
    }

    pub fn emit_add(&mut self, rd: u8, rs1: u8, rs2: u8) {
        self.emit(add(rd, rs1, rs2));
    }

    pub fn emit_sub(&mut self, rd: u8, rs1: u8, rs2: u8) {
        self.emit(sub(rd, rs1, rs2));
    }

    pub fn emit_mul(&mut self, rd: u8, rs1: u8, rs2: u8) {
        self.emit(mul(rd, rs1, rs2));
    }

    pub fn emit_mulw(&mut self, rd: u8, rs1: u8, rs2: u8) {
        self.emit(mulw(rd, rs1, rs2));
    }

    pub fn emit_divu(&mut self, rd: u8, rs1: u8, rs2: u8) {
        self.emit(divu(rd, rs1, rs2));
    }

    pub fn emit_divuw(&mut self, rd: u8, rs1: u8, rs2: u8) {
        self.emit(divuw(rd, rs1, rs2));
    }

    pub fn emit_remu(&mut self, rd: u8, rs1: u8, rs2: u8) {
        self.emit(remu(rd, rs1, rs2));
    }

    pub fn emit_remuw(&mut self, rd: u8, rs1: u8, rs2: u8) {
        self.emit(remuw(rd, rs1, rs2));
    }

    pub fn emit_and(&mut self, rd: u8, rs1: u8, rs2: u8) {
        self.emit(and(rd, rs1, rs2));
    }

    pub fn emit_or(&mut self, rd: u8, rs1: u8, rs2: u8) {
        self.emit(or(rd, rs1, rs2));
    }

    pub fn emit_subw(&mut self, rd: u8, rs1: u8, rs2: u8) {
        self.emit(subw(rd, rs1, rs2));
    }

    pub fn emit_addi(&mut self, rd: u8, rs1: u8, imm: i32) {
        self.emit(addi(rd, rs1, imm as u32));
    }

    pub fn emit_xor(&mut self, rd: u8, rs1: u8, rs2: u8) {
        self.emit(xor(rd, rs1, rs2))
    }

    pub fn emit_addiw(&mut self, rd: u8, rs1: u8, imm: i32) {
        self.emit(addiw(rd, rs1, imm as u32));
    }

    pub fn emit_slli(&mut self, rd: u8, rs: u8, shamt: u8) {
        self.emit(slli64(rd, rs, shamt));
    }

    pub fn emit_srli(&mut self, rd: u8, rs: u8, shamt: u8) {
        self.emit(srli64(rd, rs, shamt));
    }

    pub fn emit_lb(&mut self, rd: u8, rs: u8, imm: i32) {
        self.emit(lb(rd, rs, imm as u32));
    }

    pub fn emit_lbu(&mut self, rd: u8, rs: u8, imm: i32) {
        self.emit(lbu(rd, rs, imm as u32));
    }

    pub fn emit_lh(&mut self, rd: u8, rs: u8, imm: i32) {
        self.emit(lh(rd, rs, imm as u32));
    }

    pub fn emit_lhu(&mut self, rd: u8, rs: u8, imm: i32) {
        self.emit(lhu(rd, rs, imm as u32));
    }

    pub fn emit_lw(&mut self, rd: u8, rs: u8, imm: i32) {
        self.emit(lw(rd, rs, imm as u32));
    }

    pub fn emit_lwu(&mut self, rd: u8, rs: u8, imm: i32) {
        self.emit(lwu(rd, rs, imm as u32));
    }

    pub fn emit_ld(&mut self, rd: u8, rs: u8, imm: i32) {
        self.emit(ld(rd, rs, imm as u32));
    }

    pub fn emit_sb(&mut self, rs2: u8, rs1: u8, imm: i32) {
        self.emit(sb(rs1, rs2, imm as u32));
    }

    pub fn emit_sh(&mut self, rs2: u8, rs1: u8, imm: i32) {
        self.emit(sh(rs1, rs2, imm as u32));
    }

    pub fn emit_sw(&mut self, rs2: u8, rs1: u8, imm: i32) {
        self.emit(sw(rs1, rs2, imm as u32));
    }

    // NOTE: sd rs2, offset(rs1)
    pub fn emit_sd(&mut self, rs2: u8, rs1: u8, imm: i32) {
        self.emit(sd(rs1, rs2, imm as u32));
    }

    pub fn emit_jal(&mut self, rd: u8, imm: i32) {
        self.emit(jal(rd, imm as u32));
    }

    pub fn emit_jalr(&mut self, rd: u8, rs: u8, imm: i32) {
        self.emit(jalr(rd, rs, imm as u32));
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
        let lo = (((imm & 0xfff) << 52) >> 52) as i32; // sign extended

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
        let rvoff = self.code_size;
        self.exits.push(rvoff);
        self.emit_placeholder("j exit");
    }

    pub fn emit_jump(&mut self) {
        // eBPF jumps have 16-bit offset, which can span at most 2^16 * 8 = 2^19 bytes
        // this offset can be fit into the immediate field of RISC-V's jal instruction
        let rvoff = self.code_size;
        self.jumps.push((self.bpf_pc, rvoff));
        self.emit_placeholder("jal L?");
    }

    fn fixup_plt_load(&mut self, rvoff: usize, plt_offset: usize) {
        let rel_off = (plt_offset - rvoff) as i32;
        let hi = (rel_off + (1 << 11)) >> 12;
        let lo = rel_off & 0xfff;
        let i = rvoff / 4;
        self.code[i] = auipc(RV_REG_T1, (hi as u32) << 12); // see notes
        self.code[i + 1] = addi(RV_REG_T1, RV_REG_T1, lo as u32);
    }

    pub fn build_helper_fn_table(&mut self, helpers: &[u64]) {
        // pad zero to satisfy 16 bytes alignment
        while self.code_size % 16 != 0 {
            self.emit(0);
        }
        let plt_offset = self.code_size;

        for &helper in helpers {
            let lo = helper as u32;
            let hi = (helper >> 32) as u32;
            self.emit(lo);
            self.emit(hi);
        }

        // TODO: omit clone of Vec
        let plt_loads = self.plt_loads.clone();
        for off in plt_loads {
            self.fixup_plt_load(off, plt_offset);
        }
    }

    fn fixup_exit(&mut self, rvoff: usize, real_exit: usize) {
        let i = rvoff / 4;
        self.code[i] = jal(RV_REG_ZERO, (real_exit - rvoff) as u32);
    }

    fn fixup_jump(&mut self, bpf_pc: usize, rvoff: usize) {
        let bpf_insn = self.bpf_insns[bpf_pc];
        let insn_off = (bpf_insn >> 16) as i16;
        // NOTE: offset of eBPF jump is relative to the next instruction
        let dst_pc = bpf_pc as isize + 1 + (insn_off as isize);
        let dst_rvoff = *self.pc_map.get(&(dst_pc as usize)).unwrap();
        let delta = dst_rvoff as isize - rvoff as isize;
        let i = rvoff / 4;
        self.code[i] = jal(RV_REG_ZERO, delta as u32);
    }

    pub fn emit_prologue(&mut self, stack_size: usize) {
        self.emit_addi(RV_REG_SP, RV_REG_SP, -56);
        self.emit_sd(RV_REG_RA, RV_REG_SP, 48);
        self.emit_sd(RV_REG_FP, RV_REG_SP, 40);
        self.emit_sd(RV_REG_S1, RV_REG_SP, 32);
        self.emit_sd(RV_REG_S2, RV_REG_SP, 24);
        self.emit_sd(RV_REG_S3, RV_REG_SP, 16);
        self.emit_sd(RV_REG_S4, RV_REG_SP, 8);
        self.emit_sd(RV_REG_S5, RV_REG_SP, 0);

        // set frame pointer (s0)
        self.emit_addi(RV_REG_FP, RV_REG_SP, 56);

        // set BPF_REG_FP and allocate stack space for eBPF code
        self.emit_addi(bpf_to_rv_reg(BPF_REG_FP), RV_REG_SP, 0);

        // currently we limit stack size to 1024 bytes
        let stack_size = (round_up(stack_size, 8) as i32).min(1024);
        self.emit_addi(RV_REG_SP, RV_REG_SP, -stack_size);
    }

    pub fn emit_epilogue(&mut self) {
        let real_exit = self.code_size;
        let exits = self.exits.clone();
        for off in exits {
            self.fixup_exit(off, real_exit);
        }

        let jumps = self.jumps.clone();
        for (pc, off) in jumps {
            self.fixup_jump(pc, off);
        }

        // return value: move R0 to a0
        self.emit_addi(RV_REG_A0, bpf_to_rv_reg(BPF_REG_R0), 0);

        // restore stack pointer from frame pointer
        self.emit_addi(RV_REG_SP, RV_REG_FP, 0);
        self.emit_ld(RV_REG_S5, RV_REG_SP, -56);
        self.emit_ld(RV_REG_S4, RV_REG_SP, -48);
        self.emit_ld(RV_REG_S3, RV_REG_SP, -40);
        self.emit_ld(RV_REG_S2, RV_REG_SP, -32);
        self.emit_ld(RV_REG_S1, RV_REG_SP, -24);
        self.emit_ld(RV_REG_FP, RV_REG_SP, -16);
        self.emit_ld(RV_REG_RA, RV_REG_SP, -8);
        self.emit_jalr(RV_REG_ZERO, RV_REG_RA, 0); // ret
    }
}

fn emit_instructions(ctx: &mut JitContext) {
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
            let imm64 = (prev_imm as u32 as u64) | ((imm as u32 as u64) << 32);
            ctx.emit_load_imm64(prev_dst, imm64 as i64);
            continue;
        }

        if op == LD_IMM_DW {
            prev_imm = imm;
            prev_dst = dst;
            is_load_imm64 = true;
            continue;
        }

        let is64 = match (op & 0b111) as u32 {
            BPF_JMP | BPF_ALU64 => true,
            _ => false,
        };
        let use_imm = (op & 8) == 0;
        let mut rd = bpf_to_rv_reg(dst);
        let mut rs = bpf_to_rv_reg(src);

        ctx.pc_map.insert(ctx.bpf_pc, ctx.code_size);

        // helpers
        let c_emit_t1_imm = |ctx: &mut JitContext, rs: &mut u8| {
            if use_imm {
                ctx.emit_imm(RV_REG_T1, imm as i64);
                *rs = RV_REG_T1;
            }
        };
        let c_emit_zext32 = |ctx: &mut JitContext, rd: u8| {
            if !is64 {
                ctx.emit_zext_32(rd, rd);
            }
        };
        let c_emit_br_reg32 = |ctx: &mut JitContext, rs: &mut u8, rd: &mut u8| {
            if !is64 {
                ctx.emit_zext_32(RV_REG_T1, *rs);
                ctx.emit_zext_32(RV_REG_T2, *rd);
                *rs = RV_REG_T1;
                *rd = RV_REG_T2;
            }
        };

        match op {
            ALU_X_ADD | ALU_K_ADD | ALU64_X_ADD | ALU64_K_ADD => {
                c_emit_t1_imm(ctx, &mut rs);
                ctx.emit_add(rd, rd, rs);
                c_emit_zext32(ctx, rd);
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
                c_emit_zext32(ctx, rd);
            }
            ALU_X_AND | ALU64_X_AND | ALU_K_AND | ALU64_K_AND => {
                c_emit_t1_imm(ctx, &mut rs);
                ctx.emit_and(rd, rd, rs);
                c_emit_zext32(ctx, rd);
            }
            ALU_X_OR | ALU64_X_OR | ALU_K_OR | ALU64_K_OR => {
                c_emit_t1_imm(ctx, &mut rs);
                ctx.emit_or(rd, rd, rs);
                c_emit_zext32(ctx, rd);
            }
            ALU_X_XOR | ALU64_X_XOR | ALU_K_XOR | ALU64_K_XOR => {
                c_emit_t1_imm(ctx, &mut rs);
                ctx.emit_xor(rd, rd, rs);
                c_emit_zext32(ctx, rd);
            }
            ALU_X_MUL | ALU64_X_MUL | ALU_K_MUL | ALU64_K_MUL => {
                c_emit_t1_imm(ctx, &mut rs);
                if is64 {
                    ctx.emit_mul(rd, rd, rs);
                } else {
                    ctx.emit_mulw(rd, rd, rs);
                }
                c_emit_zext32(ctx, rd);
            }
            ALU_X_DIV | ALU64_X_DIV | ALU_K_DIV | ALU64_K_DIV => {
                c_emit_t1_imm(ctx, &mut rs);
                if is64 {
                    ctx.emit_divu(rd, rd, rs);
                } else {
                    ctx.emit_divuw(rd, rd, rs);
                }
                c_emit_zext32(ctx, rd);
            }
            ALU_X_MOD | ALU64_X_MOD | ALU_K_MOD | ALU64_K_MOD => {
                c_emit_t1_imm(ctx, &mut rs);
                if is64 {
                    ctx.emit_remu(rd, rd, rs);
                } else {
                    ctx.emit_remuw(rd, rd, rs);
                }
                c_emit_zext32(ctx, rd);
            }
            ALU_X_MOV | ALU64_X_MOV | ALU_K_MOV | ALU64_K_MOV => {
                if use_imm {
                    ctx.emit_imm(rd, imm as i64);
                } else {
                    ctx.emit_addi(rd, rs, 0);
                }
                c_emit_zext32(ctx, rd);
            }
            // TODO: 32 bit shifts
            ALU64_X_LSH | ALU64_K_LSH => {
                if use_imm {
                    ctx.emit_slli(rd, rd, imm as u8);
                } else {
                    ctx.emit(sll(rd, rd, rs));
                }
            }
            ALU64_X_RSH | ALU64_K_RSH => {
                if use_imm {
                    ctx.emit_srli(rd, rd, imm as u8);
                } else {
                    ctx.emit(srl(rd, rd, rs));
                }
            }
            ALU64_X_ARSH | ALU64_K_ARSH => {
                if use_imm {
                    ctx.emit(srai64(rd, rd, imm as u8));
                } else {
                    ctx.emit(sra(rd, rd, rs));
                }
            }
            LDX_MEM_B | LDX_MEM_H | LDX_MEM_W | LDX_MEM_DW => {
                let mut load_insn_imm = off as i32;
                if !is_in_i12_range(load_insn_imm) {
                    ctx.emit_imm(RV_REG_T2, off as i64);
                    ctx.emit_add(RV_REG_T2, RV_REG_T2, rs);
                    load_insn_imm = 0;
                    rs = RV_REG_T2;
                }

                let size_mod = (op & 0b11000) as u32;
                // NOTE: should we sign extend the result?
                match size_mod {
                    BPF_B => ctx.emit_lbu(rd, rs, load_insn_imm),
                    BPF_H => ctx.emit_lhu(rd, rs, load_insn_imm),
                    BPF_W => ctx.emit_lwu(rd, rs, load_insn_imm),
                    BPF_DW => ctx.emit_ld(rd, rs, load_insn_imm),
                    _ => unreachable!()
                }
            }
            ST_MEM_B | ST_MEM_H | ST_MEM_W | ST_MEM_DW |
            STX_MEM_B | STX_MEM_H | STX_MEM_W | STX_MEM_DW => {
                let mut store_insn_imm = off as i32;
                let rs1= if !is_in_i12_range(store_insn_imm) {
                    ctx.emit_imm(RV_REG_T1, off as i64);
                    ctx.emit_add(RV_REG_T1, RV_REG_T1, rd);
                    store_insn_imm = 0;
                    RV_REG_T1
                } else {
                    rd
                };

                let use_st_imm = (op & 0b111) == BPF_ST as u8;
                let rs2 = if use_st_imm {
                    ctx.emit_imm(RV_REG_T2, imm as i64);
                    RV_REG_T2
                } else {
                    rs
                };

                let size_mod = (op & 0b11000) as u32;
                match size_mod {
                    BPF_B => ctx.emit_sb(rs2, rs1, store_insn_imm),
                    BPF_H => ctx.emit_sh(rs2, rs1, store_insn_imm),
                    BPF_W => ctx.emit_sw(rs2, rs1, store_insn_imm),
                    BPF_DW => ctx.emit_sd(rs2, rs1, store_insn_imm),
                    _ => unreachable!()
                }
            }
            JMP_X_JA | JMP_K_JA => {
                ctx.emit_jump();
            }
            JMP_X_JEQ | JMP_K_JEQ | JMP32_X_JEQ | JMP32_K_JEQ => {
                c_emit_t1_imm(ctx, &mut rs);
                c_emit_br_reg32(ctx, &mut rs, &mut rd);
                ctx.emit(bne(8, rs, rd)); // dst != src
                ctx.emit_jump();
            }
            JMP_X_JGT | JMP_K_JGT | JMP32_X_JGT | JMP32_K_JGT => {
                c_emit_t1_imm(ctx, &mut rs);
                c_emit_br_reg32(ctx, &mut rs, &mut rd);
                ctx.emit(bgeu(8, rs, rd)); // dst <= src (unsigned)
                ctx.emit_jump();
            }
            JMP_X_JGE | JMP_K_JGE | JMP32_X_JGE | JMP32_K_JGE => {
                c_emit_t1_imm(ctx, &mut rs);
                c_emit_br_reg32(ctx, &mut rs, &mut rd);
                ctx.emit(bltu(8, rd, rs)); // dst < src (unsigned)
                ctx.emit_jump();
            }
            JMP_X_JSET | JMP_K_JSET | JMP32_X_JSET | JMP32_K_JSET => {
                c_emit_t1_imm(ctx, &mut rs);
                ctx.emit_and(RV_REG_T1, rs, rd);
                c_emit_zext32(ctx, RV_REG_T1);
                ctx.emit(beq(8, RV_REG_T1, RV_REG_ZERO)); // dst & src == 0
                ctx.emit_jump();
            }
            JMP_X_JNE | JMP_K_JNE | JMP32_X_JNE | JMP32_K_JNE => {
                c_emit_t1_imm(ctx, &mut rs);
                c_emit_br_reg32(ctx, &mut rs, &mut rd);
                ctx.emit(beq(8, rs, rd)); // dst == src
                ctx.emit_jump();
            }
            JMP_X_JSGT | JMP_K_JSGT | JMP32_X_JSGT | JMP32_K_JSGT => {
                c_emit_t1_imm(ctx, &mut rs);
                c_emit_br_reg32(ctx, &mut rs, &mut rd);
                // NOTE: 8 stands for two RISC-V instructions (self + jal)
                ctx.emit(bge(8, rs, rd)); // dst <= src (signed)
                ctx.emit_jump();
            }
            JMP_X_JSGE | JMP_K_JSGE | JMP32_X_JSGE | JMP32_K_JSGE => {
                c_emit_t1_imm(ctx, &mut rs);
                c_emit_br_reg32(ctx, &mut rs, &mut rd);
                ctx.emit(blt(8, rd, rs)); // dst < src (signed)
                ctx.emit_jump();
            }
            JMP_X_JLT | JMP_K_JLT | JMP32_X_JLT | JMP32_K_JLT => {
                c_emit_t1_imm(ctx, &mut rs);
                c_emit_br_reg32(ctx, &mut rs, &mut rd);
                ctx.emit(bgeu(8, rd, rs)); // dst >= src (unsigned)
                ctx.emit_jump();
            }
            JMP_X_JLE | JMP_K_JLE | JMP32_X_JLE | JMP32_K_JLE => {
                c_emit_t1_imm(ctx, &mut rs);
                c_emit_br_reg32(ctx, &mut rs, &mut rd);
                ctx.emit(bltu(8, rs, rd)); // dst > src (unsigned)
                ctx.emit_jump();
            }
            JMP_X_JSLT | JMP_K_JSLT | JMP32_X_JSLT | JMP32_K_JSLT => {
                c_emit_t1_imm(ctx, &mut rs);
                c_emit_br_reg32(ctx, &mut rs, &mut rd);
                ctx.emit(bge(8, rd, rs)); // dst >= src (signed)
                ctx.emit_jump();
            }
            JMP_X_JSLE | JMP_K_JSLE | JMP32_X_JSLE | JMP32_K_JSLE => {
                c_emit_t1_imm(ctx, &mut rs);
                c_emit_br_reg32(ctx, &mut rs, &mut rd);
                ctx.emit(blt(8, rs, rd)); // dst > src (signed)
                ctx.emit_jump();
            }
            JMP_K_CALL => {
                ctx.emit_call(imm);
            }
            JMP_K_EXIT => {
                ctx.emit_exit();
            }
            _ => {
                todo!("unimplemented eBPF instruction op = {:#x}", op)
            }
        }
    }
}

pub fn compile(ctx: &mut JitContext, helpers: &[u64], stack_size: usize) {
    ctx.emit_prologue(stack_size);
    emit_instructions(ctx);
    ctx.emit_epilogue();
    ctx.build_helper_fn_table(helpers);
}
