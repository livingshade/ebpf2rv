'''
extract eBPF binary instructions from llvm-objdump
'''
import sys
import re

def extract(content, out_file):
    # TODO: better regex
    for line in content.splitlines():
        match = re.match('\s+\d+:', line) # match line number
        if match is None:
            continue
        octets = re.findall('[0-9a-f]{2}', line[match.end():])
        print(octets)
        n = len(octets)
        if n >= 16:
            # we assume this is the only 16 bytes long BPF instruction
            out_file.write(bytes(map(lambda s: int('0x' + s, base=16), octets[:16])))
        elif n >= 8:
            out_file.write(bytes(map(lambda s: int('0x' + s, base=16), octets[:8])))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: llvm-objdump --triple=bpf -S example.o | python3 extract_code.py out.bin')
        exit()
    
    out_name = sys.argv[1]
    with open(out_name, 'wb') as f:
        disasm = sys.stdin.read()
        extract(disasm, f)
