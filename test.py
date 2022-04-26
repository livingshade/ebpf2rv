from asyncio.subprocess import PIPE
from os import remove, system, unlink
import subprocess
import re


def extract(content, out_file):
    # TODO: better regex
    for line in content.splitlines():
        match = re.match('\s+\d+:', line)  # match line number
        if match is None:
            continue
        octets = re.findall('[0-9a-f]{2}', line[match.end():])
        n = len(octets)
        if n >= 16:
            # we assume this is the only 16 bytes long BPF instruction
            out_file.write(
                bytes(map(lambda s: int('0x' + s, base=16), octets[:16])))
        elif n >= 8:
            out_file.write(
                bytes(map(lambda s: int('0x' + s, base=16), octets[:8])))


def info(message: str):
    print('\033[34minfo\033[0m:', message)


def succ(message: str):
    print('\033[32msucc\033[0m:', message)


def fail(message: str):
    print('\033[31mfail\033[0m:', message)


def check_process(subprocess, message_if_fail):
    if subprocess.returncode != 0:
        fail(message_if_fail)
        fail(subprocess.stderr.decode('utf-8'))
        exit(1)
    else:
        return subprocess


def check_requirement():
    def check_exec(name):
        info('Checking tool "{}"'.format(name))
        check_process(subprocess.run([name, '--version'], stdout=PIPE,
                      stderr=PIPE), 'Unable to find required tool "{}"'.format(name))
    check_exec('clang')
    check_exec('llvm-objdump')
    check_exec('cargo')
    check_exec('riscv64-unknown-elf-gcc')
    check_exec('qemu-riscv64')


if __name__ == '__main__':
    check_requirement()

    info('Compiling into eBPF bytecode')
    check_process(subprocess.run(['clang', '-target', 'bpf', '-O0', '-c',
                                  'tests/test_ebpf.c', '-o', 'tests/test_ebpf.o'], stdout=PIPE, stderr=PIPE), 'failed to compile source code into ebpf bytecode')
    objdump = check_process(subprocess.run(['llvm-objdump', '--triple=bpf',
                                            '-S', 'tests/test_ebpf.o'], stdout=PIPE, stderr=PIPE), 'failed to dump ebpf bytecode').stdout.decode('utf-8')
    with open('tests/test_ebpf.bin', 'wb') as of:
        extract(objdump, of)

    info('Invoking "cargo test", generate stub code')
    check_process(subprocess.run(['cargo', 'test', '--quiet'],
                  stdout=PIPE, stderr=PIPE), 'cargo test executation failed')

    info('Compiling riscv64 target file')
    check_process(subprocess.run(['riscv64-unknown-elf-gcc', '-O1',
                                  'tests/test.c', 'tests/test_jit.c', '-o', 'tests/test.bin'], stdout=PIPE, stderr=PIPE), "failed to compile code into riscv64 elf")

    info('Invoking qemu-riscv64, QEMU output:\n')
    check_process(subprocess.run(
        ['qemu-riscv64', 'tests/test.bin'], stderr=PIPE), "TEST FAILED")
    print()
    succ('ALL TEST PASSED, CONGRATULATIONS')

    info('Cleaning up, removing generated files')
    # system('rm tests/*.o tests/*.bin tests/test_jit.c')
