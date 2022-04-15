from asyncio.subprocess import PIPE
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
        fail(subprocess.stderr.encode('utf-8'))
        exit(1)
    else:
        return subprocess


if __name__ == '__main__':
    info('Compiling into eBPF bytecode')
    check_process(subprocess.run(['clang', '-target', 'bpf', '-O1', '-c',
                                  'tests/test_ebpf.c', '-o', 'tests/test_ebpf.o'], stdout=PIPE, stderr=PIPE), 'failed to compile source code into ebpf bytecode')
    objdump = check_process(subprocess.run(['llvm-objdump', '--triple=bpf',
                                            '-S', 'tests/test_ebpf.o'], stdout=PIPE, stderr=PIPE), 'failed to dump ebpf bytecode').stdout.decode('utf-8')
    with open('tests/test_ebpf.bin', 'wb') as of:
        extract(objdump, of)

    info('Invoking "cargo test", generate stub code')
    check_process(subprocess.run(['cargo', 'test', '--quiet'],
                  stdout=PIPE, stderr=PIPE), 'cargo test executation failed')

    info('Compiling riscv64 target file')
    check_process(subprocess.run(['riscv64-unknown-elf-gcc',
                                  'tests/test.c', '-o', 'tests/test.bin'], stdout=PIPE, stderr=PIPE), "failed to compile code into riscv64 elf")

    info('Invoking qemu-riscv64, ==> QEMU OUTPUT')
    check_process(subprocess.run(
        ['qemu-riscv64', 'tests/test.bin'], stderr=PIPE), "TEST FAILED")

    succ('ALL TEST PASSED, CONGRATULATIONS')
