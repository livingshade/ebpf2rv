ebpf: sum.bin
	clang -target bpf -O1 -c sum.c -o sum.o
	llvm-objdump --triple=bpf -S sum.o | python3 extract_code.py sum.bin
	rm sum.o

stub: stub.bin
# todo

clean:
	rm -rf sum.o sum.bin
