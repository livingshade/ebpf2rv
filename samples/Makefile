.PHONY: sum

sum: sum.bin

sum.o: sum.c
	clang -target bpf -O1 -c $< -o $@

disasm: sum.o
	llvm-objdump --triple=bpf -S $<

sum.bin: sum.o
	llvm-objdump --triple=bpf -S $< | python3 extract_code.py $@

clean:
	rm -rf sum.o sum.bin
