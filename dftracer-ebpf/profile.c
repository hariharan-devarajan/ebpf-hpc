
#include <linux/sched.h>
#include <uapi/linux/limits.h>
#include <uapi/linux/ptrace.h>
struct key_t {
    u64 ip;
    s64 pid;
};
BPF_HASH(fn_map, struct key_t, u64, 256);
BPF_HASH(pid_map, u32, u64);


int trace_dftracer_get_pid(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64 tsp = bpf_ktime_get_ns() / 1000;
    bpf_trace_printk("Tracing PID \%d",pid);
    pid_map.update(&pid, &tsp);
    return 0;
}
int trace_dftracer_remove_pid(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    bpf_trace_printk("Stop tracing PID \%d",pid);
    pid_map.delete(&pid);
    struct key_t key = {};
    key.pid = -1;
    u64 zero = 1000;
    u64* value = fn_map.lookup_or_init(&key, &zero);
    return 0;
}


int do_count(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* start_ts = pid_map.lookup(&pid);
    if (start_ts == 0)                                      
        return 0;
    u64 zero = 0;
    struct key_t key = {};
    key.pid = pid;
    key.ip = PT_REGS_IP(ctx);
    u64* value = fn_map.lookup_or_init(&key, &zero);
    ++(*value);
    return 0;
}
