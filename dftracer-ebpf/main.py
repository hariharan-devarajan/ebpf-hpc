from __future__ import print_function
from bcc import ArgString, BPF
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

EVENT_NAME_MAX=32
PATH_NAME_MAX=32

bpf_header="""
#include <linux/sched.h>
#include <uapi/linux/limits.h>
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(events);
"""

bpf_utils = """
static char *df_strcpy(char *dest, const char *src) {
  char *tmp = dest;

  while ((*dest++ = *src++) != \'\\0\')
    /* nothing */;
  return tmp;
}
"""

bpf_fn_template = """

ARG_STRUCT

struct event_CATEGORY_FUNCTION_event_t {                                        
    enum EventType name;                                                      
    u64 id;                                                                    
    u64 ts;                                                                    
    u64 dur;                                                                   
    u32 uid;                                                                   
    char process[EVENT_NAME_MAX];                                              
    ARGS_DECL;
};                                                                           
BPF_HASH(info_CATEGORY_FUNCTION_i, u64, struct event_CATEGORY_FUNCTION_event_t);

int CATEGORY__trace_entry_FUNCTION(struct pt_regs *ctx ENTRY_ARGS) {
  struct event_CATEGORY_FUNCTION_event_t event = {};                              
  event.id = bpf_get_current_pid_tgid();                                       
  event.uid = bpf_get_current_uid_gid();                                       
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  event.name = CATEGORY_FUNCTION_type;
  if (status == 0) {
    ARGS_INPUT_SET
    event.ts = bpf_ktime_get_ns();
    info_CATEGORY_FUNCTION_i.update(&event.id, &event);
  }
  return 0;
}

int CATEGORY__trace_exit_FUNCTION(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns();
  u64 id = bpf_get_current_pid_tgid();                                         
  struct event_CATEGORY_FUNCTION_event_t *event;                                   
  event = info_CATEGORY_FUNCTION_i.lookup(&id);
  if (event == 0)                                                               
    return 0;                                                                  
  event->dur = tsp - event->ts;   
  ARGS_OUTPUT_SET
  events.perf_submit(ctx, event, sizeof(struct event_CATEGORY_FUNCTION_event_t));
  info_CATEGORY_FUNCTION_i.delete(&id);
  return 0;
}
"""
bpf_output_set = "event->args.ret = PT_REGS_RC(ctx);"


bpf_events_enum = """
enum EventType {
  EVENT_TYPES
};
"""


bpf_openat_args_struct = """
struct CATEGORY_FUNCTION_args_t {
  int flags;
  int ret;
  int dfd;
  char fname[PATH_NAME_MAX];
};
"""

bpf_openat_entry_args = ", int dfd, const char __user *fname, int flags"

bpf_openat_args_input_set = """
    event.args.flags = flags;
    event.args.dfd = dfd;
    bpf_probe_read_user_str(&event.args.fname, sizeof(event.args.fname), (void *)fname);
    event.args.fname[PATH_NAME_MAX-1]=\'\\0\';
    bpf_trace_printk(\"\%s\", event.args.fname);
"""
b_temp = BPF(text = "")
kprobe_functions = {
     b_temp.get_syscall_prefix().decode(): [("openat", bpf_openat_args_struct, bpf_openat_args_input_set,bpf_openat_entry_args),
                                            ("open", None, None, None)]
}

event_index = {}

event_type_enum = ""
functions_bpf = ""
fn_count = 1
for cat, functions in kprobe_functions.items():
    for fn, struct, args_set, entry_args in functions:
        specific = bpf_fn_template
        if struct:
            specific = specific.replace("ARG_STRUCT", struct)
            specific = specific.replace("ARGS_DECL", "struct CATEGORY_FUNCTION_args_t args;")
            specific = specific.replace("ARGS_INPUT_SET", args_set)
            specific = specific.replace("ARGS_OUTPUT_SET", bpf_output_set)
            specific = specific.replace("ENTRY_ARGS", entry_args)
        else:
            specific = specific.replace("ARG_STRUCT", "")
            specific = specific.replace("ARGS_DECL", "")
            specific = specific.replace("ARGS_INPUT_SET", "")
            specific = specific.replace("ARGS_OUTPUT_SET", "")
            specific = specific.replace("ENTRY_ARGS", "")
        specific = specific.replace("CATEGORY", cat)
        specific = specific.replace("FUNCTION", fn)
        functions_bpf += specific
        event_type_enum += f"""
            {cat}_{fn}_type={fn_count},
        """
        event_index[fn_count] = f"{cat}/{fn}"
        fn_count+=1

bpf_events_enum = bpf_events_enum.replace("EVENT_TYPES", event_type_enum)

bpf_text = bpf_header + bpf_events_enum + bpf_utils + functions_bpf
bpf_text = bpf_text.replace("EVENT_NAME_MAX",str(EVENT_NAME_MAX))
bpf_text = bpf_text.replace("PATH_NAME_MAX",str(PATH_NAME_MAX))
print(bpf_text)




b = BPF(text = bpf_text)

for cat, functions in kprobe_functions.items():
    for fn, _, _, _ in functions:
        fnname = cat + fn
        b.attach_kprobe(event=fnname, fn_name=f"{cat}__trace_entry_{fn}")
        b.attach_kretprobe(event=fnname, fn_name=f"{cat}__trace_exit_{fn}")

matched = b.num_open_kprobes()

if matched == 0:
    print("0 functions matched by \"%s\". Exiting." % args.pattern)
    exit()

initial_ts = 0

# header
if args.timestamp:
    print("%-14s" % ("TIME(s)"), end="")
if args.print_uid:
    print("%-6s" % ("UID"), end="")
print("%-6s %-16s %4s %3s " %
      ("TID" if args.tid else "PID", "COMM", "FD", "ERR"), end="")
if args.extended_fields:
    print("%-9s" % ("FLAGS"), end="")
print("PATH")

class EventType(object):
    EVENT_ENTRY = 0
    EVENT_END = 1

entries = defaultdict(list)

import ctypes

class Eventype(ctypes.Structure):
    _fields_ = [
        ('name', ctypes.c_int),
        
    ]
class OpenatArgs(ctypes.Structure):
    _fields_ = [
        ('flags', ctypes.c_int),
        ('ret', ctypes.c_int),
        ('dfd', ctypes.c_int),
        ('fname', ctypes.c_char * PATH_NAME_MAX),
    ]
class OpenAtEvent(ctypes.Structure):
    _fields_ = [
        ('name', ctypes.c_int),
        ('id', ctypes.c_uint64),
        ('ts', ctypes.c_uint64),
        ('dur', ctypes.c_uint64),
        ('uid', ctypes.c_uint32),
        ('process', ctypes.c_char * EVENT_NAME_MAX),
        ('args', OpenatArgs)        
    ]

class GenericEvent(ctypes.Structure):
    _fields_ = [
        ('name', ctypes.c_int),
        ('id', ctypes.c_uint64),
        ('ts', ctypes.c_uint64),
        ('dur', ctypes.c_uint64),
        ('uid', ctypes.c_uint32),
        ('process', ctypes.c_char * EVENT_NAME_MAX) 
    ]


extract_bits = lambda num, k, p: int(bin(num)[2:][p:p+k], 2)
# process event
def print_event(cpu, data, size):
    event_type = ctypes.cast(data, ctypes.POINTER(Eventype)).contents
    if (event_type.name == 1):
        event = ctypes.cast(data, ctypes.POINTER(OpenAtEvent)).contents
        tid = event.id & 0xffffffff 
        pid = event.id >> 32
        print(pid, " ", tid, " ",event_index[event.name], " ", event.process, " ", event.args.fname, " ", event.args.ret, " ", event.args.dfd, " ", event.args.flags)
    else:
        event = ctypes.cast(data, ctypes.POINTER(GenericEvent)).contents
        tid = event.id & 0xffffffff 
        pid = event.id >> 32
        print(pid, " ", tid, " ",event_index[event.name], " ", event.process)
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