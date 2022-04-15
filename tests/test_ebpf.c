static long (*bpf_trace_printk)(const char* fmt, int fmt_size, long p1, long p2, long p3) = (void*) 6;

int main()
{
    int sum = 0;
    for (int i = 1; i <= 100; i++)
        sum += i;
    // bpf_trace_printk("hello from ebpf, the sum from 1 to 100 is : {}\n", 48, sum, 0, 0);
    return sum;
}
