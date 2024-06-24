from __future__ import print_function
import subprocess
import os
from os import listdir
from os.path import isfile, join
import platform
from collections import defaultdict
from datetime import datetime, timedelta
import argparse
import pathlib
import logging
from logging import FileHandler, Formatter
import json
import ctypes
from ctypes import *
from ctypes.util import find_library
import shutil

from time import sleep, strftime

from bcc import ArgString, BPF, USDT
from bcc.utils import printb

dir = pathlib.Path(__file__).parent.resolve()
examples = """examples:
    
"""
parser = argparse.ArgumentParser(
    description="Trace I/O",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)
parser.add_argument(
    "-i",
    "--install",
    default=f"{dir}/build",
    help="Directory where dftracer-ebpf is built.",
)
parser.add_argument(
    "-a",
    "--app",
    default="",
    help="Executable for the test",
)
parser.add_argument(
    "-l",
    "--logfile",
    default="dftracer.log",
    help="Log file to store the tool logging",
)
parser.add_argument(
    "-o",
    "--output",
    default="trace.pfw",
    help="Location to store trace file",
)


args = parser.parse_args()

if args.app == "":
    args.app = f"{args.install}/df_tracer_test"

try:
    os.remove(args.output)
except OSError:
    pass


try:
    os.remove(args.logfile)
except OSError:
    pass

# Setup logging
LOG_FORMAT = "%(asctime)s [%(levelname)s]: %(message)s in %(pathname)s:%(lineno)d"
tool_log = logging.getLogger("dftracer.tool")
tool_log.setLevel(logging.DEBUG)
tool_file_handler = FileHandler(args.logfile)
tool_file_handler.setLevel(logging.DEBUG)
tool_file_handler.setFormatter(Formatter(LOG_FORMAT))
tool_log.addHandler(tool_file_handler)

tool_stream_handler = logging.StreamHandler()
tool_stream_handler.setLevel(logging.INFO)
tool_stream_handler.setFormatter(Formatter(LOG_FORMAT))
tool_log.addHandler(tool_stream_handler)

trace_log = logging.getLogger("dftracer.trace")
trace_log.setLevel(logging.INFO)
trace_file_handler = FileHandler(args.output)
trace_file_handler.setLevel(logging.INFO)
trace_file_handler.setFormatter(Formatter("%(message)s"))
trace_log.addHandler(trace_file_handler)

# define constants for both BPF and python tool
TASK_COMM_LEN = 16
NAME_MAX = 256

bpf_header = """
/* Header for BPF */
#include <linux/sched.h>
#include <uapi/linux/limits.h>
#include <uapi/linux/ptrace.h>
"""

bpf_data_structure = """
struct filename_t {
    char fname[NAME_MAX];
};
enum event_type_t {
  EVENT_TYPES
};
"""

bpf_outputs = """
BPF_RINGBUF_OUTPUT(events, 1 << 16); // store the events in ring buffer
BPF_HASH(pid_map, u32, u64); // store pid to be traced
BPF_HASH(temp_file_map, u64, struct filename_t); // map filenames to id:pid + tgid
BPF_HASH(start_time_map, u64, u64); // map start time to id:pid + tgid
//BPF_STACK_TRACE(stack_traces, 16384);
"""

bpf_utils = """
/* This method checks if the function should be traced. */
static u64* is_traced(u32 *pid) {
    u64* start_ts = pid_map.lookup(pid);
    return start_ts;
}

/* Start a and stop application tracing*/
int trace_dftracer_get_pid(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64 tsp = bpf_ktime_get_ns();
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


bpf_probe_template = """
struct CATEGORY_FUNCTION_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[TASK_COMM_LEN];
    DFTRACER_ARGS_DECL
};

DFTRACER_ARGS_STRUCT

int CATEGORY__FUNCTION_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    DFTRACER_ARGS_ENTRY
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int CATEGORY__FUNCTION_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct CATEGORY_FUNCTION_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = CATEGORY_FUNCTION_type;
    DFTRACER_STACK_SET
    DFTRACER_ARGS_EXIT
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct CATEGORY_FUNCTION_event_t), 0);
    return 0;
}
"""

bpf_kernel_stack = """
    //event.stack_id = stack_traces.get_stackid(ctx, 0);
"""
bpf_user_stack = """
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
"""


class LINKMAP(Structure):
    _fields_ = [("l_addr", c_void_p), ("l_name", c_char_p)]


libdl = CDLL(find_library("dl"))
dlinfo = libdl.dlinfo
dlinfo.argtypes = c_void_p, c_int, c_void_p
dlinfo.restype = c_int


def get_library_path(name):
    lmptr = c_void_p()
    library = CDLL(find_library(name))
    dlinfo(library._handle, 2, byref(lmptr))
    return cast(lmptr, POINTER(LINKMAP)).contents.l_name.decode()


event_index = {}
fn_count = 1
event_type_enum = ""
event_completed = {}


class Symbol:
    def __init__(
        self,
        cat,
        name,
        bpf_name=None,
        regex_name=None,
        is_regex=False,
        is_kernel=False,
        has_args=False,
        args_decl="",
        args_struct="",
        args_entry="",
        args_exit="",
    ):
        global fn_count, event_type_enum, event_index, event_completed
        self.cat = cat
        self.name = name
        self.has_args = has_args
        self.template = bpf_probe_template
        self.is_regex = is_regex
        self.args_decl = args_decl
        self.args_struct = args_struct
        self.args_entry = args_entry
        self.args_exit = args_exit
        self.is_kernel = is_kernel
        if f"{cat}_{name}" not in event_completed:
            event_type_enum += f"""
                {cat}_{name}_type={fn_count},
            """
            event_index[fn_count] = [f"{cat}", f"{name}"]
            event_completed[f"{cat}_{name}"] = 1
            fn_count += 1

        if not regex_name:
            regex_name = name
        self.regex_name = regex_name
        self.bpf_name = bpf_name
        if bpf_name:
            self.probe_event = bpf_name + regex_name
        else:
            self.probe_event = regex_name
        tool_log.info(f"Probe event for {cat} {name} is {self.probe_event}")
        self.entry_event = f"{cat}__{name}_entry"
        self.exit_event = f"{cat}__{name}_exit"
        if has_args:
            self.template = self.template.replace("DFTRACER_ARGS_DECL", args_decl)
            self.template = self.template.replace("DFTRACER_ARGS_STRUCT", args_struct)
            self.template = self.template.replace("DFTRACER_ARGS_ENTRY", args_entry)
            self.template = self.template.replace("DFTRACER_ARGS_EXIT", args_exit)
        else:
            self.template = self.template.replace("DFTRACER_ARGS_DECL", "")
            self.template = self.template.replace("DFTRACER_ARGS_STRUCT", "")
            self.template = self.template.replace("DFTRACER_ARGS_ENTRY", "")
            self.template = self.template.replace("DFTRACER_ARGS_EXIT", "")
        if is_kernel:
            self.template = self.template.replace(
                "DFTRACER_STACK_SET", bpf_kernel_stack
            )
        else:
            self.template = self.template.replace("DFTRACER_STACK_SET", bpf_user_stack)
        self.template = self.template.replace("CATEGORY", cat)
        self.template = self.template.replace("FUNCTION", name)

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name


class Category:
    def __init__(
        self,
        name,
        is_kernel,
        bpf_name=None,
        fn_cat_name=None,
        fn_prefix=None,
        load_symbols=False,
        symbols=None,
        path=None,
    ):
        self.name = name
        self.is_kernel = is_kernel
        if not fn_cat_name:
            fn_cat_name = name
        if not fn_prefix:
            fn_prefix = name
        self.bpf_name = bpf_name
        if not path:
            path = get_library_path(name)
        self.path = path
        if not load_symbols and symbols is None:
            tool_log.error("define symbols if load_symbols is not set")
            exit(1)
        if symbols:
            self.symbols = [
                Symbol(
                    symbol.cat,
                    symbol.name,
                    bpf_name=bpf_name,
                    is_kernel=is_kernel,
                    regex_name=symbol.regex_name,
                    is_regex=symbol.is_regex,
                    has_args=symbol.has_args,
                    args_decl=symbol.args_decl,
                    args_struct=symbol.args_struct,
                    args_entry=symbol.args_entry,
                    args_exit=symbol.args_exit,
                )
                for symbol in symbols
            ]
        else:
            if is_kernel:
                kernel_path = f"/sys/kernel/debug/tracing/events/{name}"
                symbols = list(
                    set(
                        [
                            f.replace(f"{fn_prefix}_enter_", "").replace(
                                f"{fn_prefix}_exit_", ""
                            )
                            for f in listdir(kernel_path)
                            if join(kernel_path, f)
                        ]
                    )
                )
            else:
                symbols = (
                    os.popen(f"nm {path} | grep \" T \" | awk {{'print $3'}}")
                    .read()
                    .strip()
                    .split("\n")
                )
            self.symbols = [
                Symbol(fn_cat_name, sym, is_kernel=is_kernel) for sym in symbols
            ]
            tool_log.debug(f"Loaded symbols {self.symbols} for category {name}")

    def __str__(self) -> str:
        return json.dumps({"name": self.name, "symbols": str(self.symbols)})


b_temp = BPF(text="")

probes = [
    Category(
        "syscalls",
        is_kernel=True,
        bpf_name=b_temp.get_syscall_prefix().decode(),
        fn_cat_name="syscall",
        symbols=set(
            [
                Symbol("syscall", "openat"),
                Symbol("syscall", "read"),
                Symbol("syscall", "write"),
                Symbol("syscall", "close"),
                Symbol("syscall", "copy_file_range"),
                Symbol("syscall", "execve"),
                Symbol("syscall", "execveat"),
                Symbol("syscall", "exit"),
                Symbol("syscall", "faccessat"),
                Symbol("syscall", "fallocate"),
                Symbol("syscall", "fdatasync"),
                Symbol("syscall", "flock"),
                Symbol("syscall", "fsopen"),
                Symbol("syscall", "fstatfs"),
                Symbol("syscall", "fsync"),
                Symbol("syscall", "ftruncate"),
                Symbol("syscall", "io_pgetevents"),
                Symbol("syscall", "lseek"),
                Symbol("syscall", "memfd_create"),
                Symbol("syscall", "migrate_pages"),
                Symbol("syscall", "mlock"),
                Symbol("syscall", "mmap"),
                Symbol("syscall", "msync"),
                Symbol("syscall", "pread64"),
                Symbol("syscall", "preadv"),
                Symbol("syscall", "preadv2"),
                Symbol("syscall", "pwrite64"),
                Symbol("syscall", "pwritev"),
                Symbol("syscall", "pwritev2"),
                Symbol("syscall", "readahead"),
                Symbol("syscall", "readlinkat"),
                Symbol("syscall", "readv"),
                Symbol("syscall", "renameat"),
                Symbol("syscall", "renameat2"),
                Symbol("syscall", "statfs"),
                Symbol("syscall", "statx"),
                Symbol("syscall", "sync"),
                Symbol("syscall", "sync_file_range"),
                Symbol("syscall", "syncfs"),
                Symbol("syscall", "writev"),
            ]
        ),
    ),
    Category(
        "os_cache",
        is_kernel=True,
        symbols=set(
            [
                Symbol("os_cache", "add_to_page_cache_lru"),
                Symbol("os_cache", "mark_page_accessed"),
                Symbol("os_cache", "account_page_dirtied"),
                Symbol("os_cache", "mark_buffer_dirty"),
                Symbol("os_cache", "do_page_cache_ra"),
                Symbol("os_cache", "__page_cache_alloc"),
            ]
        ),
    ),
    Category(
        "ext4",
        is_kernel=True,
        symbols=set(
            [
                Symbol("ext4", "ext4_file_write_iter"),
                Symbol("ext4", "ext4_file_open"),
                Symbol("ext4", "ext4_sync_file"),
                Symbol("ext4", "ext4_alloc_da_blocks"),
                Symbol("ext4", "ext4_da_release_space"),
                Symbol("ext4", "ext4_da_reserve_space"),
                Symbol("ext4", "ext4_da_write_begin"),
                Symbol("ext4", "ext4_da_write_end"),
                Symbol("ext4", "ext4_discard_preallocations"),
                Symbol("ext4", "ext4_fallocate"),
                Symbol("ext4", "ext4_free_blocks"),
                Symbol("ext4", "ext4_readpage"),
                Symbol("ext4", "ext4_remove_blocks"),
                Symbol("ext4", "ext4_sync_fs"),
                Symbol("ext4", "ext4_truncate"),
                Symbol("ext4", "ext4_write_begin"),
                Symbol("ext4", "ext4_write_end"),
                Symbol("ext4", "ext4_writepage"),
                Symbol("ext4", "ext4_writepages"),
                Symbol("ext4", "ext4_zero_range"),
            ]
        ),
    ),
    Category(
        "vfs",
        is_kernel=True,
        symbols=set(
            [
                Symbol("vfs", "vfs", regex_name="^vfs_.*", is_regex=True),
            ]
        ),
    ),
    Category(
        "c",
        is_kernel=False,
        symbols=set(
            [
                Symbol("c", "open"),
                Symbol("c", "open64"),
                Symbol("c", "creat"),
                Symbol("c", "creat64"),
                Symbol("c", "close_range"),
                Symbol("c", "closefrom"),
                Symbol("c", "close"),
                Symbol("c", "read"),
                Symbol("c", "pread"),
                Symbol("c", "pread64"),
                Symbol("c", "fdopen"),
                Symbol("c", "fileno"),
                Symbol("c", "fileno_unlocked"),
                Symbol("c", "mmap"),
                Symbol("c", "munmap"),
                Symbol("c", "msync"),
                Symbol("c", "mremap"),
                Symbol("c", "madvise"),
                Symbol("c", "shm_open"),
                Symbol("c", "shm_unlink"),
                Symbol("c", "memfd_create"),
                Symbol("c", "fsync"),
                Symbol("c", "fdatasync"),
                Symbol("c", "fcntl"),
                Symbol("c", "malloc"),
                Symbol("c", "calloc"),
                Symbol("c", "realloc"),
                Symbol("c", "posix_memalign"),
                Symbol("c", "valloc"),
                Symbol("c", "memalign"),
                Symbol("c", "pvalloc"),
                Symbol("c", "aligned_alloc"),
                Symbol("c", "free"),
            ]
        ),
    ),
    Category(
        "mpi",
        is_kernel=False,
        symbols=set(
            [
                Symbol("mpi", "MPI_File_set_size"),
                Symbol("mpi", "MPI_File_iread_at"),
                Symbol("mpi", "MPI_File_iread"),
                Symbol("mpi", "MPI_File_iread_shared"),
                Symbol("mpi", "MPI_File_iwrite_at"),
                Symbol("mpi", "MPI_File_iwrite"),
                Symbol("mpi", "MPI_File_iwrite_shared"),
                Symbol("mpi", "MPI_File_open"),
                Symbol("mpi", "MPI_File_read_all_begin"),
                Symbol("mpi", "MPI_File_read_all"),
                Symbol("mpi", "MPI_File_read_at_all"),
                Symbol("mpi", "MPI_File_read_at_all_begin"),
                Symbol("mpi", "MPI_File_read_at"),
                Symbol("mpi", "MPI_File_read"),
                Symbol("mpi", "MPI_File_read_ordered_begin"),
                Symbol("mpi", "MPI_File_read_ordered"),
                Symbol("mpi", "MPI_File_read_shared"),
                Symbol("mpi", "MPI_File_set_view"),
                Symbol("mpi", "MPI_File_sync"),
                Symbol("mpi", "MPI_File_write_all_begin"),
                Symbol("mpi", "MPI_File_write_all"),
                Symbol("mpi", "MPI_File_write_at_all_begin"),
                Symbol("mpi", "MPI_File_write_at_all"),
                Symbol("mpi", "MPI_File_write_at"),
                Symbol("mpi", "MPI_File_write"),
                Symbol("mpi", "MPI_File_write_ordered_begin"),
                Symbol("mpi", "MPI_File_write_ordered"),
                Symbol("mpi", "MPI_File_write_shared"),
                Symbol("mpi", "MPI_Finalized"),
                Symbol("mpi", "MPI_Init"),
                Symbol("mpi", "MPI_Finalize"),
                Symbol("mpi", "MPI_Comm_rank"),
                Symbol("mpi", "MPI_Comm_size"),
                Symbol("mpi", "MPI_Init_thread"),
                Symbol("mpi", "MPI_Get_processor_name"),
                Symbol("mpi", "MPI_Comm_set_errhandler"),
                Symbol("mpi", "MPI_Barrier"),
                Symbol("mpi", "MPI_Bcast"),
                Symbol("mpi", "MPI_Gather"),
                Symbol("mpi", "MPI_Gatherv"),
                Symbol("mpi", "MPI_Scatterv"),
                Symbol("mpi", "MPI_Allgather"),
                Symbol("mpi", "MPI_Allgatherv"),
                Symbol("mpi", "MPI_Alltoall"),
                Symbol("mpi", "MPI_Reduce"),
                Symbol("mpi", "MPI_Allreduce"),
                Symbol("mpi", "MPI_Reduce_scatter"),
                Symbol("mpi", "MPI_Scan"),
                Symbol("mpi", "MPI_Type_commit"),
                Symbol("mpi", "MPI_Type_create_darray"),
                Symbol("mpi", "MPI_File_get_size"),
                Symbol("mpi", "MPI_Cart_rank"),
                Symbol("mpi", "MPI_Cart_create"),
                Symbol("mpi", "MPI_Cart_get"),
                Symbol("mpi", "MPI_Cart_shift"),
                Symbol("mpi", "MPI_Wait"),
                Symbol("mpi", "MPI_Send"),
                Symbol("mpi", "MPI_Recv"),
                Symbol("mpi", "MPI_Sendrecv"),
                Symbol("mpi", "MPI_Isend"),
                Symbol("mpi", "MPI_Irecv"),
                Symbol("mpi", "MPI_Waitall"),
                Symbol("mpi", "MPI_Waitsome"),
                Symbol("mpi", "MPI_Waitany"),
                Symbol("mpi", "MPI_Ssend"),
                Symbol("mpi", "MPI_Comm_split"),
                Symbol("mpi", "MPI_Comm_dup"),
                Symbol("mpi", "MPI_Comm_create"),
                Symbol("mpi", "MPI_File_seek"),
                Symbol("mpi", "MPI_File_seek_shared"),
                Symbol("mpi", "MPI_Ibcast"),
                Symbol("mpi", "MPI_Test"),
                Symbol("mpi", "MPI_Testall"),
                Symbol("mpi", "MPI_Testsome"),
                Symbol("mpi", "MPI_Testany"),
                Symbol("mpi", "MPI_Ireduce"),
                Symbol("mpi", "MPI_Igather"),
                Symbol("mpi", "MPI_Iscatter"),
                Symbol("mpi", "MPI_Ialltoall"),
                Symbol("mpi", "MPI_Comm_free"),
                Symbol("mpi", "MPI_Cart_sub"),
                Symbol("mpi", "MPI_Comm_split_type"),
            ]
        ),
    ),
    Category(
        os.path.basename(args.app),
        is_kernel=False,
        path=args.app,
        load_symbols=True,
    ),
]

tool_log.info(f"Loading {len(probes)} categories")

bpf_text = bpf_header
bpf_text += bpf_data_structure.replace("EVENT_TYPES", event_type_enum)
bpf_text += bpf_outputs
bpf_text += bpf_utils
for category in probes:
    for symbol in category.symbols:
        bpf_text += symbol.template


bpf_text = bpf_text.replace("TASK_COMM_LEN", str(TASK_COMM_LEN))
bpf_text = bpf_text.replace("NAME_MAX", str(NAME_MAX))

f = open("trace.c", "w")
f.write(bpf_text)
f.close()

tool_log.info(f"Written  trace.c for BPF code.")
b = BPF(text=bpf_text)

b.attach_uprobe(
    name=f"{args.install}/libdftracer_ebpf.so",
    sym="dftracer_get_pid",
    fn_name="trace_dftracer_get_pid",
)
b.attach_uprobe(
    name=f"{args.install}/libdftracer_ebpf.so",
    sym="dftracer_remove_pid",
    fn_name="trace_dftracer_remove_pid",
)
for category in probes:
    for symbol in category.symbols:
        try:
            if category.is_kernel:
                if symbol.is_regex:
                    b.attach_kprobe(
                        event_re=symbol.probe_event, fn_name=symbol.entry_event
                    )
                    b.attach_kretprobe(
                        event_re=symbol.probe_event, fn_name=symbol.exit_event
                    )
                else:
                    b.attach_kprobe(
                        event=symbol.probe_event, fn_name=symbol.entry_event
                    )
                    b.attach_kretprobe(
                        event=symbol.probe_event, fn_name=symbol.exit_event
                    )
            else:
                b.attach_uprobe(
                    name=category.path,
                    sym=symbol.probe_event,
                    fn_name=symbol.entry_event,
                )
                b.attach_uretprobe(
                    name=category.path,
                    sym=symbol.probe_event,
                    fn_name=symbol.exit_event,
                )
        except Exception as err:
            print(f"Unable to create probe for {symbol.probe_event} {err}")
            exit(0)
            pass

tool_log.info(
    f"Loaded {len(probes)} categories with {b.num_open_kprobes()} kprobes and NEED CALCULATE uprobes"
)

index = 0


class Event(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_int),
        ("id", ctypes.c_uint64),
        ("start_time", ctypes.c_uint64),
        ("duration", ctypes.c_uint64),
        # ("stack_id", ctypes.c_int),
        ("process", ctypes.c_char * TASK_COMM_LEN),
    ]

    def derive(self, index, parent=None):
        self.obj = {
            "id": index,
            "pid": ctypes.c_uint32(self.id).value,
            "tid": ctypes.c_uint32(self.id >> 32).value,
            "ph": "X",
            "ts": self.start_time,
            "dur": self.duration,
            "name": event_index[self.name][0] + " " + event_index[self.name][1],
            "cat": event_index[self.name][0],
        }
        if parent:
            self.obj["p"] = parent


last_updated = datetime.now()
first_event = False
# _traces = b["stack_traces"]
index = 0
# stack_map = {}


def print_event(cpu, data, size):
    global last_updated, first_event, index, stack_map, stack_traces
    first_event = True
    last_updated = datetime.now()
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    parent = None
    event.derive(index)
    # if len(stack_traces) > 0:
    #     try:
    #         current = 0
    #         for addr in stack_traces.walk(event.stack_id):
    #             fname = b.sym(addr, event.obj["pid"], show_module=True).decode()
    #             if "unknown" in fname:
    #                 fname = b.ksym(addr, show_module=True).decode()
    #             if current == 0:
    #                 parent = {"id": addr, "name": fname}
    #                 break
    #     except Exception as err:
    #         tool_log.error(f"Unable to access trace. Skipping.")
    # event.derive(index, parent=parent)
    trace_log.info(json.dumps(event.obj))
    index += 1
    return 0


trace_log.info("[")
print("Run the workload")

b["events"].open_ring_buffer(print_event)
interval = timedelta(seconds=int(5))
while True:
    try:
        is_processing = False
        # b.ring_buffer_poll()
        b.ring_buffer_consume()
        sleep(0.5)
        if first_event and datetime.now() - last_updated > interval:
            print(f"Idling for {interval} secs. Exiting.")
            exit()
    except KeyboardInterrupt:
        exit()
