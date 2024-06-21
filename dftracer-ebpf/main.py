from __future__ import print_function
from bcc import ArgString, BPF, USDT
from bcc.utils import printb
from time import sleep, strftime
import argparse
import signal
import os
from collections import defaultdict
from datetime import datetime, timedelta

# arguments
examples = """examples:
    

"""
parser = argparse.ArgumentParser(
    description="Time functions and print latency as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("-T", "--timestamp", action="store_true", default=True,
    help="include timestamp on output")
parser.add_argument("-U", "--print-uid", action="store_true", default=True,
    help="print UID column")
parser.add_argument("-x", "--failed", action="store_true",
    help="only show failed opens")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-t", "--tid",
    help="trace this TID only")
parser.add_argument("--cgroupmap",
    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
    help="trace mount namespaces in this BPF map only")
parser.add_argument("-u", "--uid",
    help="trace this UID only")
parser.add_argument("-d", "--duration",
    help="total duration of trace in seconds")
parser.add_argument("-n", "--name",
    type=ArgString,
    help="only print process names containing this name")
parser.add_argument("--ebpf", action="store_true", default=True,
    help=argparse.SUPPRESS)
parser.add_argument("-e", "--extended_fields", action="store_true",default=True,
    help="show extended fields")
parser.add_argument("-f", "--flag_filter", action="append",
    help="filter on flags argument (e.g., O_WRONLY)")
parser.add_argument("-F", "--full-path", action="store_true",
    help="show full path for an open file with relative path")
parser.add_argument("-b", "--buffer-pages", type=int, default=64,
    help="size of the perf ring buffer "
        "(must be a power of two number of pages and defaults to 64)")
args = parser.parse_args()
debug = 0
if args.duration:
    args.duration = timedelta(seconds=int(args.duration))
flag_filter_mask = 0
for flag in args.flag_filter or []:
    if not flag.startswith('O_'):
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

TASK_COMM_LEN=16
NAME_MAX=256

bpf_header="""
#include <linux/sched.h>
#include <uapi/linux/limits.h>
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(events);
BPF_HASH(pid_map, u32, u32);
"""

bpf_utils = """
static char *df_strcpy(char *dest, const char *src) {
  char *tmp = dest;

  while ((*dest++ = *src++) != \'\\0\')
    /* nothing */;
  return tmp;
}

int trace_dftracer_get_pid(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    bpf_trace_printk(\"Tracing PID \%d\",pid);
    pid_map.update(&pid, &pid);
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

bpf_fn_template = """

enum EventPhase {
    PHASE_BEGIN = 0,
    PHASE_END = 1
};

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


int syscall__trace_entry_FUNCTION(struct pt_regs *ctx ENTRY_ARGS) {
  struct entry_CATEGORY_FUNCTION_event_t event = {};   
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = CATEGORY_FUNCTION_type;         
    event.phase = PHASE_BEGIN;                 
    event.id = bpf_get_current_pid_tgid();
    u32 pid = event.id;
    u32* trace = pid_map.lookup(&pid);
    if (trace == 0)                                      
        return 0;
    event.uid = bpf_get_current_uid_gid();                                        
    ARGS_INPUT_SET
    event.ts = bpf_ktime_get_ns();
    events.perf_submit(ctx, &event, sizeof(struct entry_CATEGORY_FUNCTION_event_t)); 
  }
  return 0;
}

int CATEGORY__trace_exit_FUNCTION(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns();
  struct exit_CATEGORY_FUNCTION_event_t exit_event = {};
  exit_event.id = bpf_get_current_pid_tgid(); 
  u32 pid = exit_event.id;
  u32* trace = pid_map.lookup(&pid);
  if (trace == 0)                                      
    return 0;                              
  
  exit_event.name = CATEGORY_FUNCTION_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = tsp;
  ARGS_OUTPUT_SET  
  events.perf_submit(ctx, &exit_event, sizeof(struct exit_CATEGORY_FUNCTION_event_t));   
  return 0;
}
"""

bpf_events_enum = """
enum EventType {
  EVENT_TYPES
};
"""


bpf_openat_entry_args_struct = """
  int flags;
  int dfd;
  char fname[NAME_MAX];
"""

bpf_openat_exit_args_struct = """
  int ret;
"""

bpf_openat_entry_args = ", int dfd, const char *filename, int flags"

bpf_openat_args_input_set = """
    event.flags = flags;
    event.dfd = dfd;
    int len = bpf_probe_read_user_str(&event.fname, sizeof(event.fname), filename);
    bpf_trace_printk(\"%s %d\", event.fname, len);
"""

bpf_openat_output_set = """
    exit_event.ret = PT_REGS_RC(ctx);   
"""

b_temp = BPF(text = "")
kprobe_functions = {
     b_temp.get_syscall_prefix().decode(): [("openat", True, bpf_openat_entry_args_struct, bpf_openat_exit_args_struct, bpf_openat_entry_args,bpf_openat_args_input_set, bpf_openat_output_set),
                                            #("open", None, None, None, None)
                                            ]
}

event_index = {}

event_type_enum = ""
functions_bpf = ""
fn_count = 1
for cat, functions in kprobe_functions.items():
    for fn, has_args, entry_struct, exit_struct, entry_fn_args, entry_assign, exit_assign in functions:
        specific = bpf_fn_template
        if has_args:
            specific = specific.replace("ENTRY_ARGS_DECL", entry_struct)
            specific = specific.replace("EXIT_ARGS_DECL", exit_struct)
            specific = specific.replace("ENTRY_ARGS", entry_fn_args)
            specific = specific.replace("ARGS_INPUT_SET", entry_assign)
            specific = specific.replace("ARGS_OUTPUT_SET", exit_assign)
        else:            
            specific = specific.replace("ENTRY_ARGS_DECL", "")
            specific = specific.replace("EXIT_ARGS_DECL","")
            specific = specific.replace("ENTRY_ARGS", "")
            specific = specific.replace("ARGS_INPUT_SET", "")
            specific = specific.replace("ARGS_OUTPUT_SET", "")
        specific = specific.replace("CATEGORY", cat)
        specific = specific.replace("FUNCTION", fn)
        functions_bpf += specific
        event_type_enum += f"""
            {cat}_{fn}_type={fn_count},
        """
        event_index[fn_count] = [f"{cat}",f"{fn}"]
        fn_count+=1

bpf_events_enum = bpf_events_enum.replace("EVENT_TYPES", event_type_enum)

bpf_text = bpf_header + bpf_events_enum + bpf_utils + functions_bpf
bpf_text = bpf_text.replace("TASK_COMM_LEN",str(TASK_COMM_LEN))
bpf_text = bpf_text.replace("NAME_MAX",str(NAME_MAX))
print(bpf_text)


usdt_ctx = USDT(path=f"{dir}/build/libdftracer_ebpf.so")

b = BPF(text = bpf_text, usdt_contexts=[usdt_ctx])

b.attach_uprobe(name=f"{dir}/build/libdftracer_ebpf.so", sym="dftracer_get_pid", fn_name="trace_dftracer_get_pid")
b.attach_uprobe(name=f"{dir}/build/libdftracer_ebpf.so", sym="dftracer_remove_pid", fn_name="trace_dftracer_remove_pid")
for cat, functions in kprobe_functions.items():
    for fn, has_args, entry_struct, exit_struct, entry_fn_args, entry_assign, exit_assign in functions:
        fnname = cat + fn
        b.attach_kprobe(event=fnname, fn_name=f"syscall__trace_entry_{fn}")
        b.attach_kretprobe(event=fnname, fn_name=f"{cat}__trace_exit_{fn}")


matched = b.num_open_kprobes()

if matched == 0:
    print("0 functions matched by \"%s\". Exiting." % args.pattern)
    exit()

initial_ts = 0

class EventType(object):
    EVENT_ENTRY = 0
    EVENT_END = 1

entries = defaultdict(list)

import ctypes

class Eventype(ctypes.Structure):
    _fields_ = [
        ('name', ctypes.c_int),
        ('phase', ctypes.c_int),
        ('id', ctypes.c_uint64),
        ('ts', ctypes.c_uint64),
    ]

class OpenAtEventBegin(ctypes.Structure):
    _fields_ = [
        ('name', ctypes.c_int),
        ('phase', ctypes.c_int),
        ('id', ctypes.c_uint64),
        ('ts', ctypes.c_uint64),
        ('uid', ctypes.c_uint32),
        ('process', ctypes.c_char * TASK_COMM_LEN), 
        ('flags', ctypes.c_int),
        ('dfd', ctypes.c_int),
        ('fname', ctypes.c_char * NAME_MAX), 
    ]
class OpenAtEventEnd(ctypes.Structure):
    _fields_ = [
        ('name', ctypes.c_int),
        ('phase', ctypes.c_int),
        ('id', ctypes.c_uint64),
        ('ts', ctypes.c_uint64),
        ('ret', ctypes.c_int),
    ]

class GenericEvent(ctypes.Structure):
    _fields_ = [
        ('name', ctypes.c_int),
        ('phase', ctypes.c_int),
        ('id', ctypes.c_uint64),
        ('ts', ctypes.c_uint64),
        ('uid', ctypes.c_uint32),
        ('process', ctypes.c_char * TASK_COMM_LEN) 
    ]

index = 1

def handle_event(name, begin, end, level, group_idx):
    global index
    obj = {"id":index}
    has_begin = begin is not None
    has_end = end is not None
    phase = "X"
    obj["ts"] = 0
    id = 0
    begin_event = None
    end_event = None
    if has_begin:
        begin_event = ctypes.cast(begin, ctypes.POINTER(OpenAtEventBegin)).contents
    if has_end:
        end_event = ctypes.cast(end, ctypes.POINTER(OpenAtEventEnd)).contents
    if not (has_begin and has_end):
        phase = "i"
        if has_begin:
            obj["ts"] = begin_event.ts
            obj["pid"] = begin_event.id >> 32
            obj["tid"] = begin_event.id & 0xffffff
            obj["name"] = event_index[begin_event.name][1]
            obj["cat"] = event_index[begin_event.name][0]
        else:
            obj["ts"] = end_event.ts
            obj["pid"] = end_event.id >> 32
            obj["tid"] = end_event.id & 0xffffff
            obj["name"] = event_index[end_event.name][1]
            obj["cat"] = event_index[end_event.name][0]
    else:
        obj["ts"] = begin_event.ts
        obj["pid"] = begin_event.id >> 32
        obj["tid"] = begin_event.id & 0xffffff
        obj["name"] = event_index[begin_event.name][1]
        obj["cat"] = event_index[begin_event.name][0]
    obj["ph"] = phase
    obj["args"] = {"level":level,"group_idx":group_idx}
    if (name == 1):
        if has_begin:
            
            obj["args"]["fname"] = begin_event.fname.decode()
            obj["args"]["dfd"] = begin_event.dfd
            obj["args"]["flags"] = begin_event.flags
        if has_end:
            
            obj["args"]["ret"] = end_event.ret
    index += 1
    return obj

stack = {}
group_idx = 0
extract_bits = lambda num, k, p: int(bin(num)[2:][p:p+k], 2)
# process event
def print_event(cpu, data, size):
    global index, stack, group_idx
    event_type = ctypes.cast(data, ctypes.POINTER(Eventype)).contents
    if event_type.phase == 0: # BEGIN
        if event_type.id not in stack or len(stack[event_type.id]) == 0:
            group_idx+=1
        if event_type.id not in stack:
            stack[event_type.id] = []
        stack[event_type.id].append(data)
    else:
        level = 0
        if event_type.id not in stack or len(stack[event_type.id]) == 0:
            print(handle_event(event_type.name, None, data,level,group_idx))
        else:
            level = len(stack[event_type.id])
            begin = stack[event_type.id].pop(-1)
            print(handle_event(event_type.name, begin, data,level,group_idx))
    return 
    global initial_ts

    skip = False
    
    # split return value into FD and errno columns
    if event.ret >= 0:
        fd_s = event.ret
        err = 0
    else:
        fd_s = -1
        err = - event.ret

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
        

        printb(b"%-6d %-16s %4d %3d " %
                (event.id & 0xffffffff if args.tid else event.id >> 32,
                event.comm, fd_s, err), nl="")

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
            del(entries[event.id])
        except Exception:
            pass

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=args.buffer_pages)
start_time = datetime.now()
exit_count = 1
while not args.duration or datetime.now() - start_time < args.duration:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
    if exit_count > 10:
        exit()
    exit_count+=1