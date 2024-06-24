from __future__ import print_function
from bcc import ArgString, BPF, USDT
from bcc.utils import printb
from time import sleep, strftime
import argparse
import signal
import os
from collections import defaultdict
import time
from datetime import datetime, timedelta

# arguments
examples = """examples:
    

"""
parser = argparse.ArgumentParser(
    description="Time functions and print latency as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)

parser.add_argument(
    "-T",
    "--timestamp",
    action="store_true",
    default=True,
    help="include timestamp on output",
)
parser.add_argument(
    "-U", "--print-uid", action="store_true", default=True, help="print UID column"
)
parser.add_argument(
    "-x", "--failed", action="store_true", help="only show failed opens"
)
parser.add_argument("-p", "--pid", help="trace this PID only")
parser.add_argument("-t", "--tid", help="trace this TID only")
parser.add_argument("--cgroupmap", help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap", help="trace mount namespaces in this BPF map only")
parser.add_argument("-u", "--uid", help="trace this UID only")
parser.add_argument("-d", "--duration", help="total duration of trace in seconds")
parser.add_argument(
    "-n", "--name", type=ArgString, help="only print process names containing this name"
)
parser.add_argument("--ebpf", action="store_true", default=True, help=argparse.SUPPRESS)
parser.add_argument(
    "-e",
    "--extended_fields",
    action="store_true",
    default=True,
    help="show extended fields",
)
parser.add_argument(
    "-f",
    "--flag_filter",
    action="append",
    help="filter on flags argument (e.g., O_WRONLY)",
)
parser.add_argument(
    "-F",
    "--full-path",
    action="store_true",
    help="show full path for an open file with relative path",
)
parser.add_argument(
    "-b",
    "--buffer-pages",
    type=int,
    default=64,
    help="size of the perf ring buffer "
    "(must be a power of two number of pages and defaults to 64)",
)
args = parser.parse_args()
debug = 0
if args.duration:
    args.duration = timedelta(seconds=int(args.duration))
flag_filter_mask = 0
for flag in args.flag_filter or []:
    if not flag.startswith("O_"):
        exit("Bad flag: %s" % flag)
    try:
        flag_filter_mask |= getattr(os, flag)
    except AttributeError:
        exit("Bad flag: %s" % flag)


def bail(error):
    print("Error: " + error)
    exit(1)


# define BPF program


# signal handler
def signal_ignore(signal, frame):
    print()


# load BPF program
import pathlib

dir = pathlib.Path(__file__).parent.resolve()
print(f"including dir {dir}/src")

TASK_COMM_LEN = 16
NAME_MAX = 256

bpf_header = """
#include <linux/sched.h>
#include <uapi/linux/limits.h>
#include <uapi/linux/ptrace.h>

enum EventPhase {
    PHASE_BEGIN = 1,
    PHASE_END = 2,
    PHASE_INSTANT = 3,
};

struct Filename {
    char fname[NAME_MAX];
};

//BPF_PERF_OUTPUT(events);
BPF_RINGBUF_OUTPUT(events, 1 << 16);
BPF_HASH(pid_map, u32, u64);
BPF_HASH(temp_file_map, u64, const char*);

"""

bpf_utils = """
static char *df_strcpy(char *dest, const char *src) {
  char *tmp = dest;

  while ((*dest++ = *src++) != \'\\0\')
    /* nothing */;
  return tmp;
}

static u64 get_current_time(u64* start) {
    u64 current_time = bpf_ktime_get_ns() / 1000;
    if (current_time <= *start) return 0;
    else return current_time - *start;
}
static u64 get_current_time2(u64 *current_time, u64 *start) {
    if (*current_time <= *start) return 0;
    else return *current_time - *start;
}

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
"""

bpf_fn_sys_template = """
struct entry_CATEGORY_FUNCTION_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                        
    char process[TASK_COMM_LEN];                                           
    ENTRY_ARGS_DECL;
};
struct exit_CATEGORY_FUNCTION_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    EXIT_ARGS_DECL;
};                                                                         


RETURN syscall__trace_entry_FUNCTION(struct pt_regs *ctx ENTRY_ARGS) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry_CATEGORY_FUNCTION_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = CATEGORY_FUNCTION_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    ARGS_INPUT_SET
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_CATEGORY_FUNCTION_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry_CATEGORY_FUNCTION_event_t)); 
  }
  return 0;
}

RETURN CATEGORY__trace_exit_FUNCTION(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit_CATEGORY_FUNCTION_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = CATEGORY_FUNCTION_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
  ARGS_OUTPUT_SET
  events.ringbuf_output(&exit_event, sizeof(struct exit_CATEGORY_FUNCTION_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit_CATEGORY_FUNCTION_event_t));   
  return 0;
}
"""


bpf_fn_os_cache_template = """
struct entry_CATEGORY_FUNCTION_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                    
    char process[TASK_COMM_LEN];                                    
    ENTRY_ARGS_DECL;
};        
struct exit_CATEGORY_FUNCTION_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    EXIT_ARGS_DECL;    
};                                                          


RETURN entry_trace_FUNCTION(struct pt_regs *ctx ENTRY_ARGS) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_CATEGORY_FUNCTION_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = CATEGORY_FUNCTION_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    ARGS_INPUT_SET
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_CATEGORY_FUNCTION_event_t), 0);
  }
  return 0;
}

RETURN exit_trace_FUNCTION(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_CATEGORY_FUNCTION_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = CATEGORY_FUNCTION_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
  ARGS_OUTPUT_SET  
  events.ringbuf_output(&exit_event, sizeof(struct exit_CATEGORY_FUNCTION_event_t), 0);
  return 0;
}
"""

bpf_events_enum = """
enum EventType {
  EVENT_TYPES
};
"""

# Openat structures

bpf_openat_entry_args_struct = """
  int flags;
  int dfd;
  char fname[NAME_MAX];
"""

bpf_openat_exit_args_struct = """
  int fd;
"""

bpf_openat_fn_return = "int"

bpf_openat_entry_args = ", int dfd, const char *filename, int flags"

bpf_openat_args_input_set = """
    event.flags = flags;
    event.dfd = dfd;
    int len = bpf_probe_read_user_str(&event.fname, sizeof(event.fname), filename);
    temp_file_map.update(&event.id, &event.fname);
"""

bpf_openat_output_set = """
    exit_event.fd = PT_REGS_RC(ctx);
    temp_file_map.delete(&exit_event.id);
"""

# Open structures

bpf_open_entry_args_struct = """
  int flags;
  char fname[NAME_MAX];
"""

bpf_open_exit_args_struct = """
  int fd;
"""

bpf_open_fn_return = "int"

bpf_open_entry_args = ", const char *filename, int flags"

bpf_open_args_input_set = """
    event.flags = flags;
    int len = bpf_probe_read_user_str(&event.fname, sizeof(event.fname), filename);
    temp_file_map.update(&event.id, &event.fname);
"""

bpf_open_output_set = """
    exit_event.fd = PT_REGS_RC(ctx);
"""

# read structures

bpf_read_entry_args_struct = """
  u64 count;
  int fd;
  char fname[NAME_MAX];
"""

bpf_read_exit_args_struct = """
  s64 size;
"""

bpf_read_fn_return = "int"

bpf_read_entry_args = ", int fd, void *data, u64 count"

bpf_read_args_input_set = """
    event.count = count;
    event.fd = fd;
"""

bpf_read_output_set = """
    exit_event.size = PT_REGS_RC(ctx);
"""

# pread structures

bpf_pread_entry_args_struct = """
  u64 count;
  s64 offset;
  int fd;
  char fname[NAME_MAX];
"""

bpf_pread_exit_args_struct = """
  s64 size;
"""

bpf_pread_fn_return = "int"

bpf_pread_entry_args = ", int fd, void *data, u64 count, s64 offset"

bpf_pread_args_input_set = """
    event.count = count;
    event.offset = offset;
    event.fd = fd;
"""

bpf_pread_output_set = """
    exit_event.size = PT_REGS_RC(ctx);
"""

# write structures

bpf_write_entry_args_struct = """
  u64 count;
  int fd;
  char fname[NAME_MAX];
"""

bpf_write_exit_args_struct = """
  s64 size;
"""

bpf_write_fn_return = "int"

bpf_write_entry_args = ", int fd, const void *data, u64 count"

bpf_write_args_input_set = """
    event.count = count;
    event.fd = fd;
"""

bpf_write_output_set = """
    exit_event.size = PT_REGS_RC(ctx);
"""
# pwrite structures

bpf_pwrite_entry_args_struct = """
  u64 count;
  s64 offset;
  int fd;
  char fname[NAME_MAX];
"""

bpf_pwrite_exit_args_struct = """
  s64 size;
"""

bpf_pwrite_fn_return = "int"

bpf_pwrite_entry_args = ", int fd, const void *data, u64 count, s64 offset"

bpf_pwrite_args_input_set = """
    event.count = count;
    event.offset = offset;
    event.fd = fd;
"""

bpf_pwrite_output_set = """
    exit_event.size = PT_REGS_RC(ctx);
"""


# close structures

bpf_close_entry_args_struct = """
  int fd;
  char fname[NAME_MAX];
"""

bpf_close_exit_args_struct = """
  int ret;
"""

bpf_close_fn_return = "int"

bpf_close_entry_args = ", int fd"

bpf_close_args_input_set = """
    event.fd = fd;
"""

bpf_close_output_set = """
    exit_event.ret = PT_REGS_RC(ctx);

"""


# generic_fd structures

bpf_generic_fd_entry_args_struct = """
  char fname[NAME_MAX];
"""

bpf_generic_fd_exit_args_struct = """
  int ret;
"""

bpf_generic_fd_fn_return = "int"

bpf_generic_fd_entry_args = ", int fd"

bpf_generic_fd_args_input_set = """
    struct Filename *filename = file_map.lookup(&fd);
    if (filename != 0) {
        int len = bpf_probe_read_kernel_str(&event.fname, sizeof(event.fname), filename->fname);
    }
"""

bpf_generic_fd_output_set = """
    exit_event.ret = PT_REGS_RC(ctx);

"""


b_temp = BPF(text="")
keep_args = True
ext4_read_fn = ""
# if BPF.get_kprobe_functions(b"ext4_file_read_iter"):
#     ext4_read_fn = "ext4_file_read_iter"
# else:
#     ext4_read_fn = "generic_file_read_iter"

so_dict = {
    "mpi": "/usr/lib/aarch64-linux-gnu/openmpi/lib/libmpi.so",
    "user": "/Users/hariharandev1/Library/CloudStorage/OneDrive-LLNL/projects/ebpf-hpc/dftracer-ebpf/build/test",
}
exec = so_dict["user"]
symbols = (
    os.popen(f"nm {exec} | grep \" T \" | awk {{'print $3'}}")
    .read()
    .strip()
    .split("\n")
)

kprobe_functions = {
    b_temp.get_syscall_prefix().decode(): [
        (
            "openat",
            keep_args,
            bpf_openat_entry_args_struct,
            bpf_openat_exit_args_struct,
            bpf_openat_entry_args,
            bpf_openat_args_input_set,
            bpf_openat_output_set,
            bpf_openat_fn_return,
        ),
        (
            "read",
            keep_args,
            bpf_read_entry_args_struct,
            bpf_read_exit_args_struct,
            bpf_read_entry_args,
            bpf_read_args_input_set,
            bpf_read_output_set,
            bpf_read_fn_return,
        ),
        (
            "write",
            keep_args,
            bpf_write_entry_args_struct,
            bpf_write_exit_args_struct,
            bpf_write_entry_args,
            bpf_write_args_input_set,
            bpf_write_output_set,
            bpf_write_fn_return,
        ),
        (
            "close",
            keep_args,
            bpf_close_entry_args_struct,
            bpf_close_exit_args_struct,
            bpf_close_entry_args,
            bpf_close_args_input_set,
            bpf_close_output_set,
            bpf_close_fn_return,
        ),
        ("copy_file_range", False, None, None, None, None, None, None),
        ("execve", False, None, None, None, None, None, None),
        ("execveat", False, None, None, None, None, None, None),
        ("exit", False, None, None, None, None, None, None),
        ("faccessat", False, None, None, None, None, None, None),
        ("fcntl", False, None, None, None, None, None, None),
        ("fallocate", False, None, None, None, None, None, None),
        ("fdatasync", False, None, None, None, None, None, None),
        ("flock", False, None, None, None, None, None, None),
        ("fsopen", False, None, None, None, None, None, None),
        ("fstatfs", False, None, None, None, None, None, None),
        ("fsync", False, None, None, None, None, None, None),
        ("ftruncate", False, None, None, None, None, None, None),
        ("io_pgetevents", False, None, None, None, None, None, None),
        ("lseek", False, None, None, None, None, None, None),
        ("memfd_create", False, None, None, None, None, None, None),
        ("migrate_pages", False, None, None, None, None, None, None),
        ("mlock", False, None, None, None, None, None, None),
        ("mmap", False, None, None, None, None, None, None),
        ("msync", False, None, None, None, None, None, None),
        ("pread64", False, None, None, None, None, None, None),
        ("preadv", False, None, None, None, None, None, None),
        ("preadv2", False, None, None, None, None, None, None),
        ("pwrite64", False, None, None, None, None, None, None),
        ("pwritev", False, None, None, None, None, None, None),
        ("pwritev2", False, None, None, None, None, None, None),
        ("readahead", False, None, None, None, None, None, None),
        ("readlinkat", False, None, None, None, None, None, None),
        ("readv", False, None, None, None, None, None, None),
        ("renameat", False, None, None, None, None, None, None),
        ("renameat2", False, None, None, None, None, None, None),
        ("statfs", False, None, None, None, None, None, None),
        ("statx", False, None, None, None, None, None, None),
        ("sync", False, None, None, None, None, None, None),
        ("sync_file_range", False, None, None, None, None, None, None),
        ("syncfs", False, None, None, None, None, None, None),
        ("writev", False, None, None, None, None, None, None),
        #                                            ("kmem_cache_alloc", False, None, None, None, None, None, None),
        #                                            ("shmem_alloc_inode", False, None, None, None, None, None, None),
        # ("open", None, None, None, None)
    ],
    "os_cache": [
        ("add_to_page_cache_lru", False, None, None, None, None, None, None),
        ("mark_page_accessed", False, None, None, None, None, None, None),
        ("account_page_dirtied", False, None, None, None, None, None, None),
        ("mark_buffer_dirty", False, None, None, None, None, None, None),
        ("do_page_cache_ra", False, None, None, None, None, None, None),
        ("__page_cache_alloc", False, None, None, None, None, None, None),
    ],
    "ext4": [
        (ext4_read_fn, False, None, None, None, None, None, None),
        ("ext4_file_write_iter", False, None, None, None, None, None, None),
        ("ext4_file_open", False, None, None, None, None, None, None),
        ("ext4_sync_file", False, None, None, None, None, None, None),
        ("ext4_alloc_da_blocks", False, None, None, None, None, None, None),
        ("ext4_da_release_space", False, None, None, None, None, None, None),
        ("ext4_da_reserve_space", False, None, None, None, None, None, None),
        ("ext4_da_write_begin", False, None, None, None, None, None, None),
        ("ext4_da_write_end", False, None, None, None, None, None, None),
        ("ext4_discard_preallocations", False, None, None, None, None, None, None),
        ("ext4_fallocate", False, None, None, None, None, None, None),
        ("ext4_free_blocks", False, None, None, None, None, None, None),
        ("ext4_readpage", False, None, None, None, None, None, None),
        ("ext4_remove_blocks", False, None, None, None, None, None, None),
        ("ext4_sync_fs", False, None, None, None, None, None, None),
        ("ext4_truncate", False, None, None, None, None, None, None),
        ("ext4_write_begin", False, None, None, None, None, None, None),
        ("ext4_write_end", False, None, None, None, None, None, None),
        ("ext4_writepage", False, None, None, None, None, None, None),
        ("ext4_writepages", False, None, None, None, None, None, None),
        ("ext4_zero_range", False, None, None, None, None, None, None),
    ],
    "vfs": [
        ("^vfs_.*", False, None, None, None, None, None, None),
    ],
    "c": [
        (
            "open",
            True,
            bpf_open_entry_args_struct,
            bpf_open_exit_args_struct,
            bpf_open_entry_args,
            bpf_open_args_input_set,
            bpf_open_output_set,
            bpf_open_fn_return,
        ),
        (
            "open64",
            True,
            bpf_open_entry_args_struct,
            bpf_open_exit_args_struct,
            bpf_open_entry_args,
            bpf_open_args_input_set,
            bpf_open_output_set,
            bpf_open_fn_return,
        ),
        (
            "creat",
            True,
            bpf_open_entry_args_struct,
            bpf_open_exit_args_struct,
            bpf_open_entry_args,
            bpf_open_args_input_set,
            bpf_open_output_set,
            bpf_open_fn_return,
        ),
        (
            "creat64",
            True,
            bpf_open_entry_args_struct,
            bpf_open_exit_args_struct,
            bpf_open_entry_args,
            bpf_open_args_input_set,
            bpf_open_output_set,
            bpf_open_fn_return,
        ),
        ("close_range", False, None, None, None, None, None, None),
        ("closefrom", False, None, None, None, None, None, None),
        (
            "close",
            True,
            bpf_close_entry_args_struct,
            bpf_close_exit_args_struct,
            bpf_close_entry_args,
            bpf_close_args_input_set,
            bpf_close_output_set,
            bpf_close_fn_return,
        ),
        (
            "read",
            True,
            bpf_read_entry_args_struct,
            bpf_read_exit_args_struct,
            bpf_read_entry_args,
            bpf_read_args_input_set,
            bpf_read_output_set,
            bpf_read_fn_return,
        ),
        (
            "pread",
            True,
            bpf_pread_entry_args_struct,
            bpf_pread_exit_args_struct,
            bpf_pread_entry_args,
            bpf_pread_args_input_set,
            bpf_pread_output_set,
            bpf_pread_fn_return,
        ),
        (
            "pread64",
            True,
            bpf_pread_entry_args_struct,
            bpf_pread_exit_args_struct,
            bpf_pread_entry_args,
            bpf_pread_args_input_set,
            bpf_pread_output_set,
            bpf_pread_fn_return,
        ),
        (
            "write",
            True,
            bpf_write_entry_args_struct,
            bpf_write_exit_args_struct,
            bpf_write_entry_args,
            bpf_write_args_input_set,
            bpf_write_output_set,
            bpf_write_fn_return,
        ),
        (
            "pwrite",
            True,
            bpf_pwrite_entry_args_struct,
            bpf_pwrite_exit_args_struct,
            bpf_pwrite_entry_args,
            bpf_pwrite_args_input_set,
            bpf_pwrite_output_set,
            bpf_pwrite_fn_return,
        ),
        (
            "pwrite64",
            True,
            bpf_pwrite_entry_args_struct,
            bpf_pwrite_exit_args_struct,
            bpf_pwrite_entry_args,
            bpf_pwrite_args_input_set,
            bpf_pwrite_output_set,
            bpf_pwrite_fn_return,
        ),
        ("lseek", False, None, None, None, None, None, None),
        ("lseek64", False, None, None, None, None, None, None),
        ("fdopen", False, None, None, None, None, None, None),
        ("fileno", False, None, None, None, None, None, None),
        ("fileno_unlocked", False, None, None, None, None, None, None),
        ("mmap", False, None, None, None, None, None, None),
        ("mmap64", False, None, None, None, None, None, None),
        ("munmap", False, None, None, None, None, None, None),
        ("msync", False, None, None, None, None, None, None),
        ("mremap", False, None, None, None, None, None, None),
        ("madvise", False, None, None, None, None, None, None),
        ("shm_open", False, None, None, None, None, None, None),
        ("shm_unlink", False, None, None, None, None, None, None),
        ("memfd_create", False, None, None, None, None, None, None),
        ("fsync", False, None, None, None, None, None, None),
        ("fdatasync", False, None, None, None, None, None, None),
        ("fcntl", False, None, None, None, None, None, None),
        ("malloc", False, None, None, None, None, None, None),
        ("calloc", False, None, None, None, None, None, None),
        ("realloc", False, None, None, None, None, None, None),
        ("posix_memalign", False, None, None, None, None, None, None),
        ("valloc", False, None, None, None, None, None, None),
        ("memalign", False, None, None, None, None, None, None),
        ("pvalloc", False, None, None, None, None, None, None),
        ("aligned_alloc", False, None, None, None, None, None, None),
        ("free", False, None, None, None, None, None, None),
    ],
    "mpi": [
        ("MPI_File_set_size", False, None, None, None, None, None, None),
        ("MPI_File_iread_at", False, None, None, None, None, None, None),
        ("MPI_File_iread", False, None, None, None, None, None, None),
        ("MPI_File_iread_shared", False, None, None, None, None, None, None),
        ("MPI_File_iwrite_at", False, None, None, None, None, None, None),
        ("MPI_File_iwrite", False, None, None, None, None, None, None),
        ("MPI_File_iwrite_shared", False, None, None, None, None, None, None),
        ("MPI_File_open", False, None, None, None, None, None, None),
        ("MPI_File_read_all_begin", False, None, None, None, None, None, None),
        ("MPI_File_read_all", False, None, None, None, None, None, None),
        ("MPI_File_read_at_all", False, None, None, None, None, None, None),
        ("MPI_File_read_at_all_begin", False, None, None, None, None, None, None),
        ("MPI_File_read_at", False, None, None, None, None, None, None),
        ("MPI_File_read", False, None, None, None, None, None, None),
        ("MPI_File_read_ordered_begin", False, None, None, None, None, None, None),
        ("MPI_File_read_ordered", False, None, None, None, None, None, None),
        ("MPI_File_read_shared", False, None, None, None, None, None, None),
        ("MPI_File_set_view", False, None, None, None, None, None, None),
        ("MPI_File_sync", False, None, None, None, None, None, None),
        ("MPI_File_write_all_begin", False, None, None, None, None, None, None),
        ("MPI_File_write_all", False, None, None, None, None, None, None),
        ("MPI_File_write_at_all_begin", False, None, None, None, None, None, None),
        ("MPI_File_write_at_all", False, None, None, None, None, None, None),
        ("MPI_File_write_at", False, None, None, None, None, None, None),
        ("MPI_File_write", False, None, None, None, None, None, None),
        ("MPI_File_write_ordered_begin", False, None, None, None, None, None, None),
        ("MPI_File_write_ordered", False, None, None, None, None, None, None),
        ("MPI_File_write_shared", False, None, None, None, None, None, None),
        ("MPI_Finalized", False, None, None, None, None, None, None),
        ("MPI_Init", False, None, None, None, None, None, None),
        ("MPI_Finalize", False, None, None, None, None, None, None),
        ("MPI_Comm_rank", False, None, None, None, None, None, None),
        ("MPI_Comm_size", False, None, None, None, None, None, None),
        ("MPI_Init_thread", False, None, None, None, None, None, None),
        ("MPI_Get_processor_name", False, None, None, None, None, None, None),
        ("MPI_Comm_set_errhandler", False, None, None, None, None, None, None),
        ("MPI_Barrier", False, None, None, None, None, None, None),
        ("MPI_Bcast", False, None, None, None, None, None, None),
        ("MPI_Gather", False, None, None, None, None, None, None),
        ("MPI_Gatherv", False, None, None, None, None, None, None),
        ("MPI_Scatterv", False, None, None, None, None, None, None),
        ("MPI_Allgather", False, None, None, None, None, None, None),
        ("MPI_Allgatherv", False, None, None, None, None, None, None),
        ("MPI_Alltoall", False, None, None, None, None, None, None),
        ("MPI_Reduce", False, None, None, None, None, None, None),
        ("MPI_Allreduce", False, None, None, None, None, None, None),
        ("MPI_Reduce_scatter", False, None, None, None, None, None, None),
        ("MPI_Scan", False, None, None, None, None, None, None),
        ("MPI_Type_commit", False, None, None, None, None, None, None),
        ("MPI_Type_create_darray", False, None, None, None, None, None, None),
        ("MPI_File_get_size", False, None, None, None, None, None, None),
        ("MPI_Cart_rank", False, None, None, None, None, None, None),
        ("MPI_Cart_create", False, None, None, None, None, None, None),
        ("MPI_Cart_get", False, None, None, None, None, None, None),
        ("MPI_Cart_shift", False, None, None, None, None, None, None),
        ("MPI_Wait", False, None, None, None, None, None, None),
        ("MPI_Send", False, None, None, None, None, None, None),
        ("MPI_Recv", False, None, None, None, None, None, None),
        ("MPI_Sendrecv", False, None, None, None, None, None, None),
        ("MPI_Isend", False, None, None, None, None, None, None),
        ("MPI_Irecv", False, None, None, None, None, None, None),
        ("MPI_Waitall", False, None, None, None, None, None, None),
        ("MPI_Waitsome", False, None, None, None, None, None, None),
        ("MPI_Waitany", False, None, None, None, None, None, None),
        ("MPI_Ssend", False, None, None, None, None, None, None),
        ("MPI_Comm_split", False, None, None, None, None, None, None),
        ("MPI_Comm_dup", False, None, None, None, None, None, None),
        ("MPI_Comm_create", False, None, None, None, None, None, None),
        ("MPI_File_seek", False, None, None, None, None, None, None),
        ("MPI_File_seek_shared", False, None, None, None, None, None, None),
        ("MPI_Ibcast", False, None, None, None, None, None, None),
        ("MPI_Test", False, None, None, None, None, None, None),
        ("MPI_Testall", False, None, None, None, None, None, None),
        ("MPI_Testsome", False, None, None, None, None, None, None),
        ("MPI_Testany", False, None, None, None, None, None, None),
        ("MPI_Ireduce", False, None, None, None, None, None, None),
        ("MPI_Igather", False, None, None, None, None, None, None),
        ("MPI_Iscatter", False, None, None, None, None, None, None),
        ("MPI_Ialltoall", False, None, None, None, None, None, None),
        ("MPI_Comm_free", False, None, None, None, None, None, None),
        ("MPI_Cart_sub", False, None, None, None, None, None, None),
        ("MPI_Comm_split_type", False, None, None, None, None, None, None),
    ],
    "user": [(sym, False, None, None, None, None, None, None) for sym in symbols],
}

event_index = {}

event_type_enum = ""
functions_bpf = ""
fn_count = 1
open_fn_idx = {}
read_fn_idx = {}
pread_fn_idx = {}
write_fn_idx = {}
pwrite_fn_idx = {}
close_fn_idx = {}
for cat, functions in kprobe_functions.items():
    for (
        fn,
        has_args,
        entry_struct,
        exit_struct,
        entry_fn_args,
        entry_assign,
        exit_assign,
        ret,
    ) in functions:
        specific = ""
        func = fn
        if "sys" in cat:
            specific = bpf_fn_sys_template
        elif cat in ["os_cache", "ext4", "c", "mpi", "user"]:
            specific = bpf_fn_os_cache_template
        elif cat in ["vfs"]:
            specific = bpf_fn_os_cache_template
            func = cat
        if has_args:
            specific = specific.replace("ENTRY_ARGS_DECL", entry_struct)
            specific = specific.replace("EXIT_ARGS_DECL", exit_struct)
            specific = specific.replace("ENTRY_ARGS", entry_fn_args)
            specific = specific.replace("ARGS_INPUT_SET", entry_assign)
            specific = specific.replace("ARGS_OUTPUT_SET", exit_assign)
            specific = specific.replace("RETURN", ret)
            if fn in ["open", "open64", "creat", "creat64"]:
                open_fn_idx[fn_count] = True
            elif fn in ["read"]:
                read_fn_idx[fn_count] = True
            elif fn in ["pread", "pread64"]:
                pread_fn_idx[fn_count] = True
            elif fn in ["write"]:
                write_fn_idx[fn_count] = True
            elif fn in ["pwrite", "pwrite64"]:
                pwrite_fn_idx[fn_count] = True
            elif fn in ["close"]:
                close_fn_idx[fn_count] = True
        else:
            specific = specific.replace("ENTRY_ARGS_DECL", "")
            specific = specific.replace("EXIT_ARGS_DECL", "")
            specific = specific.replace("ENTRY_ARGS", "")
            specific = specific.replace("ARGS_INPUT_SET", "")
            specific = specific.replace("ARGS_OUTPUT_SET", "")
            specific = specific.replace("RETURN", "int")

        specific = specific.replace("CATEGORY", cat)
        specific = specific.replace("FUNCTION", func)
        functions_bpf += specific
        event_type_enum += f"""
            {cat}_{func}_type={fn_count},
        """
        event_index[fn_count] = [f"{cat}", f"{func}"]
        fn_count += 1

bpf_events_enum = bpf_events_enum.replace("EVENT_TYPES", event_type_enum)

bpf_text = bpf_header + bpf_events_enum + bpf_utils + functions_bpf
bpf_text = bpf_text.replace("TASK_COMM_LEN", str(TASK_COMM_LEN))
bpf_text = bpf_text.replace("NAME_MAX", str(NAME_MAX))
# print(bpf_text)


usdt_ctx = USDT(path=f"{dir}/build/libdftracer_ebpf.so")

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
for cat, functions in kprobe_functions.items():
    for (
        fn,
        has_args,
        entry_struct,
        exit_struct,
        entry_fn_args,
        entry_assign,
        exit_assign,
        ret,
    ) in functions:
        try:
            # if "sys" in cat:
            #     fnname = cat + fn
            #     b.attach_kprobe(event=fnname, fn_name=f"syscall__trace_entry_{fn}")
            #     b.attach_kretprobe(event=fnname, fn_name=f"{cat}__trace_exit_{fn}")
            # elif cat in ["os_cache", "ext4"]:
            #     fnname = fn
            #     b.attach_kprobe(event=fnname, fn_name=f"entry_trace_{fn}")
            #     b.attach_kretprobe(event=fnname, fn_name=f"exit_trace_{fn}")
            # elif cat in ["vfs"]:
            #     fnname = fn
            #     b.attach_kprobe(event_re=fnname, fn_name=f"entry_trace_{cat}")
            #     b.attach_kretprobe(event_re=fnname, fn_name=f"exit_trace_{cat}")
            # el
            if cat in ["c", "mpi"]:
                library = cat
                if cat in so_dict:
                    library = so_dict[cat]
                b.attach_uprobe(name=library, sym=fn, fn_name=f"entry_trace_{fn}")
                b.attach_uretprobe(name=library, sym=fn, fn_name=f"exit_trace_{fn}")
            elif cat in ["user"]:
                exec = cat
                if cat in so_dict:
                    exec = so_dict[cat]
                b.attach_uprobe(name=exec, sym=fn, fn_name=f"entry_trace_{fn}")
                b.attach_uretprobe(name=exec, sym=fn, fn_name=f"exit_trace_{fn}")
        except Exception as err:
            print(f"Unable to create probe for {cat} and {fn} {err}")
            pass


# https://github.com/iovisor/bcc/blob/v0.18.0/tools/readahead.py
# https://github.com/iovisor/bcc/blob/v0.18.0/examples/tracing/vfsreadlat.py

matched = b.num_open_kprobes()
print(f"{matched} functions matched")

initial_ts = 0


class EventType(object):
    EVENT_ENTRY = 0
    EVENT_END = 1


entries = defaultdict(list)

import ctypes


class Eventype(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_int),
        ("phase", ctypes.c_int),
        ("id", ctypes.c_uint64),
        ("ts", ctypes.c_uint64),
    ]


class GenericStartEvent(Eventype):
    _fields_ = [
        ("uid", ctypes.c_uint32),
        ("process", ctypes.c_char * TASK_COMM_LEN),
    ]


class GenericEndEvent(Eventype):
    pass


class OpenAtEventBegin(GenericStartEvent):
    _fields_ = [
        ("flags", ctypes.c_int),
        ("dfd", ctypes.c_int),
        ("fname", ctypes.c_char * NAME_MAX),
    ]


class OpenAtEventEnd(GenericEndEvent):
    _fields_ = [
        ("fd", ctypes.c_int),
    ]


class OpenEventBegin(GenericStartEvent):
    _fields_ = [
        ("flags", ctypes.c_int),
        ("fname", ctypes.c_char * NAME_MAX),
    ]


class OpenEventEnd(OpenAtEventEnd):
    pass


class CloseEventBegin(GenericStartEvent):
    _fields_ = [
        ("fd", ctypes.c_int),
    ]


class CloseEventEnd(GenericEndEvent):
    _fields_ = [
        ("ret", ctypes.c_int),
    ]


class RWEventBegin(GenericStartEvent):
    _fields_ = [
        ("count", ctypes.c_uint64),
        ("fd", ctypes.c_int),
    ]


class RWEventEnd(GenericEndEvent):
    _fields_ = [
        ("size", ctypes.c_int64),
    ]


class PRWEventBegin(GenericStartEvent):
    _fields_ = [
        ("count", ctypes.c_uint64),
        ("offset", ctypes.c_int64),
        ("fd", ctypes.c_int),
    ]


class PRWEventEnd(GenericEndEvent):
    _fields_ = [
        ("size", ctypes.c_int64),
    ]


index = 1


def handle_single_event(event):
    global index, event_index
    obj = {
        "id": index,
        "ts": event.ts,
        "pid": event.id >> 32,
        "tid": event.id & 0xFFFFFF,
        "ph": "i",
        "name": event_index[event.name][0] + " " + event_index[event.name][1],
        "cat": event_index[event.name][0],
        "args": {},
    }
    return obj


def handle_event(begin, end):
    global index, event_index
    obj = {
        "id": index,
        "ts": begin.ts,
        "dur": end.ts - begin.ts,
        "ph": "X",
        "pid": end.id >> 32,
        "tid": end.id & 0xFFFFFF,
        "name": event_index[end.name][0] + " " + event_index[end.name][1],
        "cat": event_index[end.name][0],
        "args": {
        },
    }
    if begin.name == 1:
        obj["args"]["fname"] = begin.fname.decode()
        obj["args"]["dfd"] = begin.dfd
        obj["args"]["flags"] = begin.flags
        obj["args"]["fd"] = end.fd
    elif begin.name in open_fn_idx:
        obj["args"]["fname"] = begin.fname.decode()
        obj["args"]["flags"] = begin.flags
        obj["args"]["fd"] = end.fd
    elif begin.name in close_fn_idx:
        obj["args"]["fd"] = begin.fd
        obj["args"]["ret"] = end.ret
    elif begin.name in read_fn_idx or begin.name in write_fn_idx:
        obj["args"]["fd"] = begin.fd
        obj["args"]["count"] = begin.count
        obj["args"]["size"] = end.size
    elif begin.name in pread_fn_idx or begin.name in pwrite_fn_idx:
        obj["args"]["fd"] = begin.fd
        obj["args"]["count"] = begin.count
        obj["args"]["offset"] = begin.offset
        obj["args"]["size"] = end.size
    index += 1
    return obj


stack = {}
group_idx = 0
extract_bits = lambda num, k, p: int(bin(num)[2:][p : p + k], 2)
try:
    os.remove("trace.pfw")
except OSError:
    pass

import logging

logging.basicConfig(
    level=logging.INFO,
    handlers=[
        logging.FileHandler("trace.pfw", mode="a", encoding="utf-8"),
    ],
    format="%(message)s",
)
logging.info("[")
import json

last_updated = datetime.now()


# process event
def print_event(cpu, data, size):
    global last_updated
    last_updated = datetime.now()
    global index, stack, group_idx
    basic_event = ctypes.cast(data, ctypes.POINTER(Eventype)).contents
    if basic_event.name == 1:
        if basic_event.phase == 1:
            event = ctypes.cast(data, ctypes.POINTER(OpenAtEventBegin)).contents
        else:
            event = ctypes.cast(data, ctypes.POINTER(OpenAtEventEnd)).contents
    elif basic_event.name in open_fn_idx:
        if basic_event.phase == 1:
            event = ctypes.cast(data, ctypes.POINTER(OpenEventBegin)).contents
        else:
            event = ctypes.cast(data, ctypes.POINTER(OpenEventEnd)).contents
    elif basic_event.name in close_fn_idx:
        if basic_event.phase == 1:
            event = ctypes.cast(data, ctypes.POINTER(CloseEventBegin)).contents
        else:
            event = ctypes.cast(data, ctypes.POINTER(CloseEventEnd)).contents
    elif basic_event.name in read_fn_idx or basic_event.name in write_fn_idx:
        if basic_event.phase == 1:
            event = ctypes.cast(data, ctypes.POINTER(RWEventBegin)).contents
        else:
            event = ctypes.cast(data, ctypes.POINTER(RWEventEnd)).contents
    elif basic_event.name in pread_fn_idx or basic_event.name in pwrite_fn_idx:
        if basic_event.phase == 1:
            event = ctypes.cast(data, ctypes.POINTER(PRWEventBegin)).contents
        else:
            event = ctypes.cast(data, ctypes.POINTER(PRWEventEnd)).contents
    else:
        if basic_event.phase == 2:
            event = ctypes.cast(data, ctypes.POINTER(GenericEndEvent)).contents
        else:
            event = ctypes.cast(data, ctypes.POINTER(GenericStartEvent)).contents
    if event.id not in stack:
        stack[event.id] = {}
    if event.name not in stack[event.id]:
        stack[event.id][event.name] = []
    if event.phase == 1:  # BEGIN
        stack[event.id][event.name].append(event)
    elif event.phase == 2:  # END
        begin = stack[event.id][event.name].pop()
        val = handle_event(begin, event)
        logging.info(json.dumps(val))
    elif event.phase == 3:  # INSTANT
        val = handle_single_event(event)
        logging.info(json.dumps(val))
    return
    global initial_ts

    skip = False

    # split return value into FD and errno columns
    if event.ret >= 0:
        fd_s = event.ret
        err = 0
    else:
        fd_s = -1
        err = -event.ret

    if not initial_ts:
        initial_ts = event.ts

    if args.failed and (event.ret >= 0):
        skip = True

    if args.name and bytes(args.name) not in event.comm:
        skip = True

    if not skip:
        if args.timestamp:
            delta = event.ts - initial_ts
            printb(b"%-14.9f" % (float(delta) / 1000000), nl="")

        if args.print_uid:
            printb(b"%-6d" % event.uid, nl="")

        printb(
            b"%-6d %-16s %4d %3d "
            % (
                event.id & 0xFFFFFFFF if args.tid else event.id >> 32,
                event.comm,
                fd_s,
                err,
            ),
            nl="",
        )

        # if args.extended_fields:
        #     printb(b"%08o " % event.flags, nl="")

        if not args.full_path:
            printb(b"%s" % event.name)
        else:
            paths = entries[event.id]
            paths.reverse()
            printb(b"%s" % os.path.join(*paths))

    if args.full_path:
        try:
            del entries[event.id]
        except Exception:
            pass


# loop with callback to print_event
b["events"].open_ring_buffer(print_event)
interval = timedelta(seconds=int(120))
while True:
    try:
        is_processing = False
        # b.ring_buffer_poll()
        b.ring_buffer_consume()
        time.sleep(0.5)
        if datetime.now() - last_updated > interval:
            print("Idling for 120 secs. Exiting.")
            exit()
    except KeyboardInterrupt:
        exit()
