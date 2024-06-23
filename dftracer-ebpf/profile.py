from __future__ import print_function
import os
from collections import defaultdict
from datetime import datetime, timedelta
import argparse
import pathlib

from bcc import ArgString, BPF, USDT
from bcc.utils import printb
from time import sleep, strftime

examples = """examples:
    
"""
parser = argparse.ArgumentParser(
    description="Profile io calls in given interval",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)
parser.add_argument(
    "-d", "--interval", default=1, help="Profiling interval for trace in seconds"
)
args = parser.parse_args()

TASK_COMM_LEN = 16
bpf_text = """
#include <linux/sched.h>
#include <uapi/linux/limits.h>
#include <uapi/linux/ptrace.h>
struct key_t {
    u64 ip;
    u32 pid;
};
BPF_HASH(fn_map, struct key_t, u64, 256);
BPF_HASH(pid_map, u32, u64);


int trace_dftracer_get_pid(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64 tsp = bpf_ktime_get_ns() / 1000;
    bpf_trace_printk(\"Tracing PID \%d\",pid);
    pid_map.update(&pid, &tsp);
    return 0;
}
int trace_dftracer_remove_pid(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    bpf_trace_printk(\"Stop tracing PID \%d\",pid);
    pid_map.delete(&pid);
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
"""
so_dict = {
    "mpi": "/usr/lib/aarch64-linux-gnu/openmpi/lib/libmpi.so",
    "user": "/Users/hariharandev1/Library/CloudStorage/OneDrive-LLNL/projects/ebpf-hpc/dftracer-ebpf/build/test",
}

functions = {
    "sys": [
        ("openat"),
        ("read"),
        ("write"),
        ("close"),
        ("copy_file_range"),
        ("execve"),
        ("execveat"),
        ("exit"),
        ("faccessat"),
        ("fcntl"),
        ("fallocate"),
        ("fdatasync"),
        ("flock"),
        ("fsopen"),
        ("fstatfs"),
        ("fsync"),
        ("ftruncate"),
        ("io_pgetevents"),
        ("lseek"),
        ("memfd_create"),
        ("migrate_pages"),
        ("mlock"),
        ("mmap"),
        ("msync"),
        ("pread64"),
        ("preadv"),
        ("preadv2"),
        ("pwrite64"),
        ("pwritev"),
        ("pwritev2"),
        ("readahead"),
        ("readlinkat"),
        ("readv"),
        ("renameat"),
        ("renameat2"),
        ("statfs"),
        ("statx"),
        ("sync"),
        ("sync_file_range"),
        ("syncfs"),
        ("writev"),
    ],
    "os_cache": [
        ("add_to_page_cache_lru"),
        ("mark_page_accessed"),
        ("account_page_dirtied"),
        ("mark_buffer_dirty"),
        ("do_page_cache_ra"),
        ("__page_cache_alloc"),
    ],
    "ext4": [
        ("ext4_file_write_iter"),
        ("ext4_file_open"),
        ("ext4_sync_file"),
        ("ext4_alloc_da_blocks"),
        ("ext4_da_release_space"),
        ("ext4_da_reserve_space"),
        ("ext4_da_write_begin"),
        ("ext4_da_write_end"),
        ("ext4_discard_preallocations"),
        ("ext4_fallocate"),
        ("ext4_free_blocks"),
        ("ext4_readpage"),
        ("ext4_remove_blocks"),
        ("ext4_sync_fs"),
        ("ext4_truncate"),
        ("ext4_write_begin"),
        ("ext4_write_end"),
        ("ext4_writepage"),
        ("ext4_writepages"),
        ("ext4_zero_range"),
    ],
    "vfs": [
        ("^vfs_.*"),
    ],
    "c": [
        ("open"),
        ("open64"),
        ("creat"),
        ("creat64"),
        ("close_range"),
        ("closefrom"),
        ("close"),
        ("read"),
        ("pread"),
        ("pread64"),
        ("write"),
        ("pwrite"),
        ("pwrite64"),
        ("lseek"),
        ("lseek64"),
        ("fdopen"),
        ("fileno"),
        ("fileno_unlocked"),
        ("mmap"),
        ("mmap64"),
        ("munmap"),
        ("msync"),
        ("mremap"),
        ("madvise"),
        ("shm_open"),
        ("shm_unlink"),
        ("memfd_create"),
        ("fsync"),
        ("fdatasync"),
        ("fcntl"),
        ("malloc"),
        ("calloc"),
        ("realloc"),
        ("posix_memalign"),
        ("valloc"),
        ("memalign"),
        ("pvalloc"),
        ("aligned_alloc"),
        ("free"),
    ],
}
# load BPF program

dir = pathlib.Path(__file__).parent.resolve()
usdt_ctx = USDT(path=f"{dir}/build/libdftracer_ebpf.so")
f = open("profile.c", "w")
f.write(bpf_text)
f.close()
b = BPF(text=bpf_text, usdt_contexts=[usdt_ctx])
b.attach_uprobe(
    name=f"{dir}/build/libdftracer_ebpf.so",
    sym="dftracer_get_pid",
    fn_name="trace_dftracer_get_pid",
)
b.attach_uprobe(
    name=f"{dir}/build/libdftracer_ebpf.so",
    sym="dftracer_remove_pid",
    fn_name="trace_dftracer_remove_pid",
)

for cat, fns in functions.items():
    for fn in fns:
        if "sys" in cat:
            fnname = b.get_syscall_prefix().decode() + fn
            b.attach_kprobe(event_re=fnname, fn_name=f"do_count")
        elif cat in ["os_cache", "ext4", "vfs"]:
            b.attach_kprobe(event_re=fn, fn_name=f"do_count")
        elif cat in ["c"]:
            library = cat
            if cat in so_dict:
                library = so_dict[cat]
            b.attach_uprobe(name=library, sym=fn, fn_name=f"do_count")

print("\n%-16s %-26s %-26s %8s" % ("INTERVAL", "PID", "FUNC", "COUNT"))
count = 0
exiting = False
while True:
    has_events = False
    try:
        sleep(args.interval)
    except KeyboardInterrupt:
        exiting = True
    counts = b.get_table("fn_map")

    for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
        fname = b.sym(k.ip, k.pid).decode()
        if "unknown" in fname:
            fname = b.ksym(k.ip).decode()
        print("%9d-%9d-%8s-%9d" % (count * args.interval, k.pid, fname, v.value))
        has_events = count
    counts.clear()
    count += 1
    if exiting or (count - has_events > 10):
        print("Detaching...")
        exit()
