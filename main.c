
#include <linux/sched.h>
#include <uapi/linux/limits.h>
#include <uapi/linux/ptrace.h>

enum EventPhase {
    PHASE_BEGIN = 1,
    PHASE_END = 2,
    PHASE_INSTANT = 3,
};

//BPF_PERF_OUTPUT(events);
BPF_RINGBUF_OUTPUT(events, 1 << 16);
BPF_HASH(pid_map, u32, u64);
BPF_HASH(temp_file_map, u64, const char*);
BPF_HASH(file_map, s32, const char*);


enum EventType {
  
            __arm64_sys__openat_type=1,
        
            __arm64_sys__read_type=2,
        
            __arm64_sys__write_type=3,
        
            __arm64_sys__close_type=4,
        
            __arm64_sys__copy_file_range_type=5,
        
            __arm64_sys__execve_type=6,
        
            __arm64_sys__execveat_type=7,
        
            __arm64_sys__exit_type=8,
        
            __arm64_sys__faccessat_type=9,
        
            __arm64_sys__fcntl_type=10,
        
            __arm64_sys__fallocate_type=11,
        
            __arm64_sys__fdatasync_type=12,
        
            __arm64_sys__flock_type=13,
        
            __arm64_sys__fsopen_type=14,
        
            __arm64_sys__fstatfs_type=15,
        
            __arm64_sys__fsync_type=16,
        
            __arm64_sys__ftruncate_type=17,
        
            __arm64_sys__io_pgetevents_type=18,
        
            __arm64_sys__lseek_type=19,
        
            __arm64_sys__memfd_create_type=20,
        
            __arm64_sys__migrate_pages_type=21,
        
            __arm64_sys__mlock_type=22,
        
            __arm64_sys__mmap_type=23,
        
            __arm64_sys__msync_type=24,
        
            __arm64_sys__pread64_type=25,
        
            __arm64_sys__preadv_type=26,
        
            __arm64_sys__preadv2_type=27,
        
            __arm64_sys__pwrite64_type=28,
        
            __arm64_sys__pwritev_type=29,
        
            __arm64_sys__pwritev2_type=30,
        
            __arm64_sys__readahead_type=31,
        
            __arm64_sys__readlinkat_type=32,
        
            __arm64_sys__readv_type=33,
        
            __arm64_sys__renameat_type=34,
        
            __arm64_sys__renameat2_type=35,
        
            __arm64_sys__statfs_type=36,
        
            __arm64_sys__statx_type=37,
        
            __arm64_sys__sync_type=38,
        
            __arm64_sys__sync_file_range_type=39,
        
            __arm64_sys__syncfs_type=40,
        
            __arm64_sys__writev_type=41,
        
            os_cache_add_to_page_cache_lru_type=42,
        
            os_cache_mark_page_accessed_type=43,
        
            os_cache_account_page_dirtied_type=44,
        
            os_cache_mark_buffer_dirty_type=45,
        
            os_cache_do_page_cache_ra_type=46,
        
            os_cache___page_cache_alloc_type=47,
        
            ext4_ext4_file_read_iter_type=48,
        
            ext4_ext4_file_write_iter_type=49,
        
            ext4_ext4_file_open_type=50,
        
            ext4_ext4_sync_file_type=51,
        
            c_open_type=52,
        
            c_open64_type=53,
        
            c_creat_type=54,
        
            c_creat64_type=55,
        
            c_close_range_type=56,
        
            c_closefrom_type=57,
        
            c_close_type=58,
        
            c_read_type=59,
        
            c_pread_type=60,
        
            c_pread64_type=61,
        
            c_write_type=62,
        
            c_pwrite_type=63,
        
            c_pwrite64_type=64,
        
            c_lseek_type=65,
        
            c_lseek64_type=66,
        
            c_fdopen_type=67,
        
            c_fileno_type=68,
        
            c_fileno_unlocked_type=69,
        
            c_mmap_type=70,
        
            c_mmap64_type=71,
        
            c_munmap_type=72,
        
            c_msync_type=73,
        
            c_mremap_type=74,
        
            c_madvise_type=75,
        
            c_shm_open_type=76,
        
            c_shm_unlink_type=77,
        
            c_memfd_create_type=78,
        
            c_fsync_type=79,
        
            c_fdatasync_type=80,
        
            c_fcntl_type=81,
        
            c_malloc_type=82,
        
            c_calloc_type=83,
        
            c_realloc_type=84,
        
            c_posix_memalign_type=85,
        
            c_valloc_type=86,
        
            c_memalign_type=87,
        
            c_pvalloc_type=88,
        
            c_aligned_alloc_type=89,
        
            c_free_type=90,
        
            mpi_MPI_File_set_size_type=91,
        
            mpi_MPI_File_iread_at_type=92,
        
            mpi_MPI_File_iread_type=93,
        
            mpi_MPI_File_iread_shared_type=94,
        
            mpi_MPI_File_iwrite_at_type=95,
        
            mpi_MPI_File_iwrite_type=96,
        
            mpi_MPI_File_iwrite_shared_type=97,
        
            mpi_MPI_File_open_type=98,
        
            mpi_MPI_File_read_all_begin_type=99,
        
            mpi_MPI_File_read_all_type=100,
        
            mpi_MPI_File_read_at_all_type=101,
        
            mpi_MPI_File_read_at_all_begin_type=102,
        
            mpi_MPI_File_read_at_type=103,
        
            mpi_MPI_File_read_type=104,
        
            mpi_MPI_File_read_ordered_begin_type=105,
        
            mpi_MPI_File_read_ordered_type=106,
        
            mpi_MPI_File_read_shared_type=107,
        
            mpi_MPI_File_set_view_type=108,
        
            mpi_MPI_File_sync_type=109,
        
            mpi_MPI_File_write_all_begin_type=110,
        
            mpi_MPI_File_write_all_type=111,
        
            mpi_MPI_File_write_at_all_begin_type=112,
        
            mpi_MPI_File_write_at_all_type=113,
        
            mpi_MPI_File_write_at_type=114,
        
            mpi_MPI_File_write_type=115,
        
            mpi_MPI_File_write_ordered_begin_type=116,
        
            mpi_MPI_File_write_ordered_type=117,
        
            mpi_MPI_File_write_shared_type=118,
        
            mpi_MPI_Finalized_type=119,
        
            mpi_MPI_Init_type=120,
        
            mpi_MPI_Finalize_type=121,
        
            mpi_MPI_Comm_rank_type=122,
        
            mpi_MPI_Comm_size_type=123,
        
            mpi_MPI_Init_thread_type=124,
        
            mpi_MPI_Get_processor_name_type=125,
        
            mpi_MPI_Comm_set_errhandler_type=126,
        
            mpi_MPI_Barrier_type=127,
        
            mpi_MPI_Bcast_type=128,
        
            mpi_MPI_Gather_type=129,
        
            mpi_MPI_Gatherv_type=130,
        
            mpi_MPI_Scatterv_type=131,
        
            mpi_MPI_Allgather_type=132,
        
            mpi_MPI_Allgatherv_type=133,
        
            mpi_MPI_Alltoall_type=134,
        
            mpi_MPI_Reduce_type=135,
        
            mpi_MPI_Allreduce_type=136,
        
            mpi_MPI_Reduce_scatter_type=137,
        
            mpi_MPI_Scan_type=138,
        
            mpi_MPI_Type_commit_type=139,
        
            mpi_MPI_Type_create_darray_type=140,
        
            mpi_MPI_File_get_size_type=141,
        
            mpi_MPI_Cart_rank_type=142,
        
            mpi_MPI_Cart_create_type=143,
        
            mpi_MPI_Cart_get_type=144,
        
            mpi_MPI_Cart_shift_type=145,
        
            mpi_MPI_Wait_type=146,
        
            mpi_MPI_Send_type=147,
        
            mpi_MPI_Recv_type=148,
        
            mpi_MPI_Sendrecv_type=149,
        
            mpi_MPI_Isend_type=150,
        
            mpi_MPI_Irecv_type=151,
        
            mpi_MPI_Waitall_type=152,
        
            mpi_MPI_Waitsome_type=153,
        
            mpi_MPI_Waitany_type=154,
        
            mpi_MPI_Ssend_type=155,
        
            mpi_MPI_Comm_split_type=156,
        
            mpi_MPI_Comm_dup_type=157,
        
            mpi_MPI_Comm_create_type=158,
        
            mpi_MPI_File_seek_type=159,
        
            mpi_MPI_File_seek_shared_type=160,
        
            mpi_MPI_Ibcast_type=161,
        
            mpi_MPI_Test_type=162,
        
            mpi_MPI_Testall_type=163,
        
            mpi_MPI_Testsome_type=164,
        
            mpi_MPI_Testany_type=165,
        
            mpi_MPI_Ireduce_type=166,
        
            mpi_MPI_Igather_type=167,
        
            mpi_MPI_Iscatter_type=168,
        
            mpi_MPI_Ialltoall_type=169,
        
            mpi_MPI_Comm_free_type=170,
        
            mpi_MPI_Cart_sub_type=171,
        
            mpi_MPI_Comm_split_type_type=172,
        
            user__Z10gen_randomB5cxx11i_type=173,
        
            user__fini_type=174,
        
            user__init_type=175,
        
            user__start_type=176,
        
            user_main_type=177,
        
};

static char *df_strcpy(char *dest, const char *src) {
  char *tmp = dest;

  while ((*dest++ = *src++) != '\0')
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
    bpf_trace_printk("Tracing PID \%d",pid);
    pid_map.update(&pid, &tsp);
    return 0;
}
int trace_dftracer_remove_pid(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    bpf_trace_printk("Stop tracing PID \%d",pid);
    pid_map.delete(&pid);
    return 0;
}

struct entry___arm64_sys__openat_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    
  int flags;
  int dfd;
  char fname[256];
;
};
struct exit___arm64_sys__openat_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    
  int ret;
;
};                                                                         


int syscall__trace_entry_openat(struct pt_regs *ctx , int dfd, const char *filename, int flags) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__openat_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__openat_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.flags = flags;
    event.dfd = dfd;
    int len = bpf_probe_read_user_str(&event.fname, sizeof(event.fname), filename);
    temp_file_map.update(&event.id, &event.fname);

    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__openat_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__openat_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_openat(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__openat_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__openat_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
  
    exit_event.ret = PT_REGS_RC(ctx);
    const char **filename = temp_file_map.lookup(&exit_event.id);
    if (filename != 0) {
        file_map.update(&exit_event.ret, filename);
        temp_file_map.delete(&exit_event.id);
    }
  
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__openat_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__openat_event_t));   
  return 0;
}

struct entry___arm64_sys__read_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    
  u32 count;
  char fname[256];
;
};
struct exit___arm64_sys__read_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    
  int ret;
;
};                                                                         


int syscall__trace_entry_read(struct pt_regs *ctx , int fd, void *data, u32 count) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__read_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__read_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.count = count;
    const char **filename = file_map.lookup(&fd);
    if (filename != 0) {
        int len = bpf_probe_read_kernel_str(&event.fname, sizeof(event.fname), *filename);
    }

    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__read_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__read_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_read(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__read_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__read_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
  
    exit_event.ret = PT_REGS_RC(ctx);
  
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__read_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__read_event_t));   
  return 0;
}

struct entry___arm64_sys__write_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    
  u32 count;
  char fname[256];
;
};
struct exit___arm64_sys__write_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    
  int ret;
;
};                                                                         


int syscall__trace_entry_write(struct pt_regs *ctx , int fd, const void *data, u32 count) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__write_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__write_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.count = count;
    const char **filename = file_map.lookup(&fd);
    if (filename != 0) {
        int len = bpf_probe_read_kernel_str(&event.fname, sizeof(event.fname), *filename);
    }

    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__write_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__write_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_write(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__write_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__write_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
  
    exit_event.ret = PT_REGS_RC(ctx);
  
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__write_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__write_event_t));   
  return 0;
}

struct entry___arm64_sys__close_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    
  char fname[256];
;
};
struct exit___arm64_sys__close_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    
  int ret;
;
};                                                                         


int syscall__trace_entry_close(struct pt_regs *ctx , int fd) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__close_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__close_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    const char **filename = file_map.lookup(&fd);
    if (filename != 0) {
        int len = bpf_probe_read_kernel_str(&event.fname, sizeof(event.fname), *filename);
    }

    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__close_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__close_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_close(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__close_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__close_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
  
    exit_event.ret = PT_REGS_RC(ctx);

  
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__close_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__close_event_t));   
  return 0;
}

struct entry___arm64_sys__copy_file_range_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__copy_file_range_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_copy_file_range(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__copy_file_range_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__copy_file_range_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__copy_file_range_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__copy_file_range_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_copy_file_range(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__copy_file_range_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__copy_file_range_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__copy_file_range_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__copy_file_range_event_t));   
  return 0;
}

struct entry___arm64_sys__execve_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__execve_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_execve(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__execve_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__execve_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__execve_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__execve_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_execve(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__execve_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__execve_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__execve_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__execve_event_t));   
  return 0;
}

struct entry___arm64_sys__execveat_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__execveat_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_execveat(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__execveat_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__execveat_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__execveat_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__execveat_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_execveat(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__execveat_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__execveat_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__execveat_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__execveat_event_t));   
  return 0;
}

struct entry___arm64_sys__exit_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__exit_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_exit(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__exit_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__exit_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__exit_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__exit_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_exit(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__exit_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__exit_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__exit_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__exit_event_t));   
  return 0;
}

struct entry___arm64_sys__faccessat_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__faccessat_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_faccessat(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__faccessat_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__faccessat_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__faccessat_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__faccessat_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_faccessat(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__faccessat_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__faccessat_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__faccessat_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__faccessat_event_t));   
  return 0;
}

struct entry___arm64_sys__fcntl_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__fcntl_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_fcntl(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__fcntl_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__fcntl_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__fcntl_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__fcntl_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_fcntl(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__fcntl_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__fcntl_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__fcntl_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__fcntl_event_t));   
  return 0;
}

struct entry___arm64_sys__fallocate_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__fallocate_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_fallocate(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__fallocate_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__fallocate_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__fallocate_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__fallocate_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_fallocate(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__fallocate_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__fallocate_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__fallocate_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__fallocate_event_t));   
  return 0;
}

struct entry___arm64_sys__fdatasync_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__fdatasync_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_fdatasync(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__fdatasync_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__fdatasync_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__fdatasync_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__fdatasync_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_fdatasync(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__fdatasync_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__fdatasync_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__fdatasync_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__fdatasync_event_t));   
  return 0;
}

struct entry___arm64_sys__flock_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__flock_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_flock(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__flock_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__flock_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__flock_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__flock_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_flock(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__flock_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__flock_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__flock_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__flock_event_t));   
  return 0;
}

struct entry___arm64_sys__fsopen_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__fsopen_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_fsopen(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__fsopen_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__fsopen_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__fsopen_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__fsopen_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_fsopen(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__fsopen_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__fsopen_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__fsopen_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__fsopen_event_t));   
  return 0;
}

struct entry___arm64_sys__fstatfs_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__fstatfs_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_fstatfs(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__fstatfs_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__fstatfs_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__fstatfs_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__fstatfs_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_fstatfs(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__fstatfs_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__fstatfs_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__fstatfs_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__fstatfs_event_t));   
  return 0;
}

struct entry___arm64_sys__fsync_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__fsync_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_fsync(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__fsync_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__fsync_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__fsync_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__fsync_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_fsync(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__fsync_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__fsync_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__fsync_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__fsync_event_t));   
  return 0;
}

struct entry___arm64_sys__ftruncate_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__ftruncate_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_ftruncate(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__ftruncate_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__ftruncate_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__ftruncate_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__ftruncate_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_ftruncate(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__ftruncate_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__ftruncate_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__ftruncate_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__ftruncate_event_t));   
  return 0;
}

struct entry___arm64_sys__io_pgetevents_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__io_pgetevents_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_io_pgetevents(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__io_pgetevents_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__io_pgetevents_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__io_pgetevents_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__io_pgetevents_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_io_pgetevents(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__io_pgetevents_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__io_pgetevents_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__io_pgetevents_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__io_pgetevents_event_t));   
  return 0;
}

struct entry___arm64_sys__lseek_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__lseek_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_lseek(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__lseek_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__lseek_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__lseek_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__lseek_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_lseek(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__lseek_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__lseek_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__lseek_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__lseek_event_t));   
  return 0;
}

struct entry___arm64_sys__memfd_create_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__memfd_create_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_memfd_create(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__memfd_create_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__memfd_create_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__memfd_create_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__memfd_create_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_memfd_create(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__memfd_create_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__memfd_create_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__memfd_create_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__memfd_create_event_t));   
  return 0;
}

struct entry___arm64_sys__migrate_pages_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__migrate_pages_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_migrate_pages(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__migrate_pages_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__migrate_pages_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__migrate_pages_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__migrate_pages_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_migrate_pages(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__migrate_pages_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__migrate_pages_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__migrate_pages_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__migrate_pages_event_t));   
  return 0;
}

struct entry___arm64_sys__mlock_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__mlock_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_mlock(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__mlock_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__mlock_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__mlock_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__mlock_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_mlock(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__mlock_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__mlock_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__mlock_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__mlock_event_t));   
  return 0;
}

struct entry___arm64_sys__mmap_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__mmap_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_mmap(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__mmap_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__mmap_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__mmap_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__mmap_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_mmap(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__mmap_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__mmap_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__mmap_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__mmap_event_t));   
  return 0;
}

struct entry___arm64_sys__msync_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__msync_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_msync(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__msync_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__msync_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__msync_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__msync_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_msync(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__msync_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__msync_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__msync_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__msync_event_t));   
  return 0;
}

struct entry___arm64_sys__pread64_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__pread64_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_pread64(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__pread64_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__pread64_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__pread64_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__pread64_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_pread64(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__pread64_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__pread64_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__pread64_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__pread64_event_t));   
  return 0;
}

struct entry___arm64_sys__preadv_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__preadv_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_preadv(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__preadv_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__preadv_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__preadv_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__preadv_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_preadv(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__preadv_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__preadv_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__preadv_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__preadv_event_t));   
  return 0;
}

struct entry___arm64_sys__preadv2_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__preadv2_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_preadv2(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__preadv2_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__preadv2_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__preadv2_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__preadv2_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_preadv2(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__preadv2_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__preadv2_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__preadv2_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__preadv2_event_t));   
  return 0;
}

struct entry___arm64_sys__pwrite64_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__pwrite64_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_pwrite64(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__pwrite64_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__pwrite64_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__pwrite64_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__pwrite64_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_pwrite64(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__pwrite64_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__pwrite64_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__pwrite64_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__pwrite64_event_t));   
  return 0;
}

struct entry___arm64_sys__pwritev_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__pwritev_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_pwritev(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__pwritev_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__pwritev_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__pwritev_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__pwritev_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_pwritev(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__pwritev_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__pwritev_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__pwritev_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__pwritev_event_t));   
  return 0;
}

struct entry___arm64_sys__pwritev2_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__pwritev2_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_pwritev2(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__pwritev2_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__pwritev2_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__pwritev2_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__pwritev2_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_pwritev2(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__pwritev2_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__pwritev2_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__pwritev2_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__pwritev2_event_t));   
  return 0;
}

struct entry___arm64_sys__readahead_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__readahead_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_readahead(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__readahead_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__readahead_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__readahead_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__readahead_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_readahead(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__readahead_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__readahead_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__readahead_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__readahead_event_t));   
  return 0;
}

struct entry___arm64_sys__readlinkat_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__readlinkat_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_readlinkat(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__readlinkat_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__readlinkat_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__readlinkat_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__readlinkat_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_readlinkat(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__readlinkat_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__readlinkat_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__readlinkat_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__readlinkat_event_t));   
  return 0;
}

struct entry___arm64_sys__readv_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__readv_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_readv(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__readv_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__readv_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__readv_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__readv_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_readv(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__readv_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__readv_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__readv_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__readv_event_t));   
  return 0;
}

struct entry___arm64_sys__renameat_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__renameat_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_renameat(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__renameat_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__renameat_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__renameat_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__renameat_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_renameat(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__renameat_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__renameat_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__renameat_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__renameat_event_t));   
  return 0;
}

struct entry___arm64_sys__renameat2_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__renameat2_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_renameat2(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__renameat2_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__renameat2_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__renameat2_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__renameat2_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_renameat2(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__renameat2_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__renameat2_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__renameat2_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__renameat2_event_t));   
  return 0;
}

struct entry___arm64_sys__statfs_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__statfs_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_statfs(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__statfs_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__statfs_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__statfs_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__statfs_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_statfs(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__statfs_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__statfs_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__statfs_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__statfs_event_t));   
  return 0;
}

struct entry___arm64_sys__statx_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__statx_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_statx(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__statx_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__statx_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__statx_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__statx_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_statx(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__statx_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__statx_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__statx_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__statx_event_t));   
  return 0;
}

struct entry___arm64_sys__sync_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__sync_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_sync(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__sync_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__sync_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__sync_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__sync_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_sync(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__sync_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__sync_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__sync_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__sync_event_t));   
  return 0;
}

struct entry___arm64_sys__sync_file_range_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__sync_file_range_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_sync_file_range(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__sync_file_range_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__sync_file_range_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__sync_file_range_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__sync_file_range_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_sync_file_range(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__sync_file_range_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__sync_file_range_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__sync_file_range_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__sync_file_range_event_t));   
  return 0;
}

struct entry___arm64_sys__syncfs_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__syncfs_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_syncfs(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__syncfs_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__syncfs_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__syncfs_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__syncfs_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_syncfs(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__syncfs_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__syncfs_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__syncfs_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__syncfs_event_t));   
  return 0;
}

struct entry___arm64_sys__writev_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                              
    ;
};
struct exit___arm64_sys__writev_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                             
    ;
};                                                                         


int syscall__trace_entry_writev(struct pt_regs *ctx ) {
  
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct entry___arm64_sys__writev_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = __arm64_sys__writev_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                        
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry___arm64_sys__writev_event_t), 0);
    //events.perf_submit(ctx, &event, sizeof(struct entry___arm64_sys__writev_event_t)); 
  }
  return 0;
}

int __arm64_sys___trace_exit_writev(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid(); 
  u32 pid = id;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;       
  struct exit___arm64_sys__writev_event_t exit_event = {};                       
  exit_event.id = id;
  exit_event.name = __arm64_sys__writev_type;
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit___arm64_sys__writev_event_t), 0);
  //events.perf_submit(ctx, &exit_event, sizeof(struct exit___arm64_sys__writev_event_t));   
  return 0;
}

struct entry_os_cache_add_to_page_cache_lru_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_os_cache_add_to_page_cache_lru_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_add_to_page_cache_lru(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_os_cache_add_to_page_cache_lru_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = os_cache_add_to_page_cache_lru_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_os_cache_add_to_page_cache_lru_event_t), 0);
  }
  return 0;
}

int exit_trace_add_to_page_cache_lru(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_os_cache_add_to_page_cache_lru_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = os_cache_add_to_page_cache_lru_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_os_cache_add_to_page_cache_lru_event_t), 0);
  return 0;
}

struct entry_os_cache_mark_page_accessed_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_os_cache_mark_page_accessed_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_mark_page_accessed(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_os_cache_mark_page_accessed_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = os_cache_mark_page_accessed_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_os_cache_mark_page_accessed_event_t), 0);
  }
  return 0;
}

int exit_trace_mark_page_accessed(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_os_cache_mark_page_accessed_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = os_cache_mark_page_accessed_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_os_cache_mark_page_accessed_event_t), 0);
  return 0;
}

struct entry_os_cache_account_page_dirtied_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_os_cache_account_page_dirtied_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_account_page_dirtied(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_os_cache_account_page_dirtied_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = os_cache_account_page_dirtied_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_os_cache_account_page_dirtied_event_t), 0);
  }
  return 0;
}

int exit_trace_account_page_dirtied(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_os_cache_account_page_dirtied_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = os_cache_account_page_dirtied_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_os_cache_account_page_dirtied_event_t), 0);
  return 0;
}

struct entry_os_cache_mark_buffer_dirty_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_os_cache_mark_buffer_dirty_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_mark_buffer_dirty(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_os_cache_mark_buffer_dirty_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = os_cache_mark_buffer_dirty_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_os_cache_mark_buffer_dirty_event_t), 0);
  }
  return 0;
}

int exit_trace_mark_buffer_dirty(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_os_cache_mark_buffer_dirty_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = os_cache_mark_buffer_dirty_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_os_cache_mark_buffer_dirty_event_t), 0);
  return 0;
}

struct entry_os_cache_do_page_cache_ra_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_os_cache_do_page_cache_ra_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_do_page_cache_ra(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_os_cache_do_page_cache_ra_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = os_cache_do_page_cache_ra_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_os_cache_do_page_cache_ra_event_t), 0);
  }
  return 0;
}

int exit_trace_do_page_cache_ra(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_os_cache_do_page_cache_ra_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = os_cache_do_page_cache_ra_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_os_cache_do_page_cache_ra_event_t), 0);
  return 0;
}

struct entry_os_cache___page_cache_alloc_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_os_cache___page_cache_alloc_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace___page_cache_alloc(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_os_cache___page_cache_alloc_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = os_cache___page_cache_alloc_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_os_cache___page_cache_alloc_event_t), 0);
  }
  return 0;
}

int exit_trace___page_cache_alloc(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_os_cache___page_cache_alloc_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = os_cache___page_cache_alloc_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_os_cache___page_cache_alloc_event_t), 0);
  return 0;
}

struct entry_ext4_ext4_file_read_iter_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_ext4_ext4_file_read_iter_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_ext4_file_read_iter(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_ext4_ext4_file_read_iter_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = ext4_ext4_file_read_iter_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_ext4_ext4_file_read_iter_event_t), 0);
  }
  return 0;
}

int exit_trace_ext4_file_read_iter(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_ext4_ext4_file_read_iter_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = ext4_ext4_file_read_iter_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_ext4_ext4_file_read_iter_event_t), 0);
  return 0;
}

struct entry_ext4_ext4_file_write_iter_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_ext4_ext4_file_write_iter_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_ext4_file_write_iter(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_ext4_ext4_file_write_iter_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = ext4_ext4_file_write_iter_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_ext4_ext4_file_write_iter_event_t), 0);
  }
  return 0;
}

int exit_trace_ext4_file_write_iter(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_ext4_ext4_file_write_iter_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = ext4_ext4_file_write_iter_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_ext4_ext4_file_write_iter_event_t), 0);
  return 0;
}

struct entry_ext4_ext4_file_open_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_ext4_ext4_file_open_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_ext4_file_open(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_ext4_ext4_file_open_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = ext4_ext4_file_open_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_ext4_ext4_file_open_event_t), 0);
  }
  return 0;
}

int exit_trace_ext4_file_open(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_ext4_ext4_file_open_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = ext4_ext4_file_open_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_ext4_ext4_file_open_event_t), 0);
  return 0;
}

struct entry_ext4_ext4_sync_file_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_ext4_ext4_sync_file_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_ext4_sync_file(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_ext4_ext4_sync_file_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = ext4_ext4_sync_file_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_ext4_ext4_sync_file_event_t), 0);
  }
  return 0;
}

int exit_trace_ext4_sync_file(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_ext4_ext4_sync_file_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = ext4_ext4_sync_file_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_ext4_ext4_sync_file_event_t), 0);
  return 0;
}

struct entry_c_open_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    
  int flags;
  char fname[256];
;
};        
struct exit_c_open_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    
  int ret;
;    
};                                                          


int entry_trace_open(struct pt_regs *ctx , const char *filename, int flags) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_open_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_open_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.flags = flags;
    int len = bpf_probe_read_user_str(&event.fname, sizeof(event.fname), filename);
    temp_file_map.update(&event.id, &event.fname);

    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_open_event_t), 0);
  }
  return 0;
}

int exit_trace_open(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_open_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_open_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
  
    exit_event.ret = PT_REGS_RC(ctx);
    const char **filename = temp_file_map.lookup(&exit_event.id);
    if (filename != 0) {
        file_map.update(&exit_event.ret, filename);
        temp_file_map.delete(&exit_event.id);
    }
  
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_open_event_t), 0);
  return 0;
}

struct entry_c_open64_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    
  int flags;
  char fname[256];
;
};        
struct exit_c_open64_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    
  int ret;
;    
};                                                          


int entry_trace_open64(struct pt_regs *ctx , const char *filename, int flags) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_open64_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_open64_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.flags = flags;
    int len = bpf_probe_read_user_str(&event.fname, sizeof(event.fname), filename);
    temp_file_map.update(&event.id, &event.fname);

    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_open64_event_t), 0);
  }
  return 0;
}

int exit_trace_open64(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_open64_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_open64_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
  
    exit_event.ret = PT_REGS_RC(ctx);
    const char **filename = temp_file_map.lookup(&exit_event.id);
    if (filename != 0) {
        file_map.update(&exit_event.ret, filename);
        temp_file_map.delete(&exit_event.id);
    }
  
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_open64_event_t), 0);
  return 0;
}

struct entry_c_creat_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    
  int flags;
  char fname[256];
;
};        
struct exit_c_creat_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    
  int ret;
;    
};                                                          


int entry_trace_creat(struct pt_regs *ctx , const char *filename, int flags) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_creat_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_creat_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.flags = flags;
    int len = bpf_probe_read_user_str(&event.fname, sizeof(event.fname), filename);
    temp_file_map.update(&event.id, &event.fname);

    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_creat_event_t), 0);
  }
  return 0;
}

int exit_trace_creat(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_creat_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_creat_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
  
    exit_event.ret = PT_REGS_RC(ctx);
    const char **filename = temp_file_map.lookup(&exit_event.id);
    if (filename != 0) {
        file_map.update(&exit_event.ret, filename);
        temp_file_map.delete(&exit_event.id);
    }
  
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_creat_event_t), 0);
  return 0;
}

struct entry_c_creat64_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    
  int flags;
  char fname[256];
;
};        
struct exit_c_creat64_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    
  int ret;
;    
};                                                          


int entry_trace_creat64(struct pt_regs *ctx , const char *filename, int flags) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_creat64_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_creat64_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.flags = flags;
    int len = bpf_probe_read_user_str(&event.fname, sizeof(event.fname), filename);
    temp_file_map.update(&event.id, &event.fname);

    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_creat64_event_t), 0);
  }
  return 0;
}

int exit_trace_creat64(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_creat64_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_creat64_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
  
    exit_event.ret = PT_REGS_RC(ctx);
    const char **filename = temp_file_map.lookup(&exit_event.id);
    if (filename != 0) {
        file_map.update(&exit_event.ret, filename);
        temp_file_map.delete(&exit_event.id);
    }
  
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_creat64_event_t), 0);
  return 0;
}

struct entry_c_close_range_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_close_range_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_close_range(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_close_range_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_close_range_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_close_range_event_t), 0);
  }
  return 0;
}

int exit_trace_close_range(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_close_range_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_close_range_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_close_range_event_t), 0);
  return 0;
}

struct entry_c_closefrom_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_closefrom_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_closefrom(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_closefrom_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_closefrom_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_closefrom_event_t), 0);
  }
  return 0;
}

int exit_trace_closefrom(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_closefrom_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_closefrom_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_closefrom_event_t), 0);
  return 0;
}

struct entry_c_close_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    
  char fname[256];
;
};        
struct exit_c_close_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    
  int ret;
;    
};                                                          


int entry_trace_close(struct pt_regs *ctx , int fd) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_close_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_close_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    const char **filename = file_map.lookup(&fd);
    if (filename != 0) {
        int len = bpf_probe_read_kernel_str(&event.fname, sizeof(event.fname), *filename);
    }

    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_close_event_t), 0);
  }
  return 0;
}

int exit_trace_close(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_close_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_close_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
  
    exit_event.ret = PT_REGS_RC(ctx);

  
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_close_event_t), 0);
  return 0;
}

struct entry_c_read_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    
  u32 count;
  char fname[256];
;
};        
struct exit_c_read_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    
  int ret;
;    
};                                                          


int entry_trace_read(struct pt_regs *ctx , int fd, void *data, u32 count) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_read_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_read_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.count = count;
    const char **filename = file_map.lookup(&fd);
    if (filename != 0) {
        int len = bpf_probe_read_kernel_str(&event.fname, sizeof(event.fname), *filename);
    }

    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_read_event_t), 0);
  }
  return 0;
}

int exit_trace_read(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_read_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_read_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
  
    exit_event.ret = PT_REGS_RC(ctx);
  
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_read_event_t), 0);
  return 0;
}

struct entry_c_pread_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    
  u32 count;
  s64 offset;
  char fname[256];
;
};        
struct exit_c_pread_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    
  int ret;
;    
};                                                          


int entry_trace_pread(struct pt_regs *ctx , int fd, void *data, u32 count, s64 offset) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_pread_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_pread_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.count = count;
    event.offset = offset;
    const char **filename = file_map.lookup(&fd);
    if (filename != 0) {
        int len = bpf_probe_read_kernel_str(&event.fname, sizeof(event.fname), *filename);
    }

    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_pread_event_t), 0);
  }
  return 0;
}

int exit_trace_pread(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_pread_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_pread_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
  
    exit_event.ret = PT_REGS_RC(ctx);
  
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_pread_event_t), 0);
  return 0;
}

struct entry_c_pread64_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    
  u32 count;
  s64 offset;
  char fname[256];
;
};        
struct exit_c_pread64_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    
  int ret;
;    
};                                                          


int entry_trace_pread64(struct pt_regs *ctx , int fd, void *data, u32 count, s64 offset) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_pread64_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_pread64_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.count = count;
    event.offset = offset;
    const char **filename = file_map.lookup(&fd);
    if (filename != 0) {
        int len = bpf_probe_read_kernel_str(&event.fname, sizeof(event.fname), *filename);
    }

    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_pread64_event_t), 0);
  }
  return 0;
}

int exit_trace_pread64(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_pread64_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_pread64_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
  
    exit_event.ret = PT_REGS_RC(ctx);
  
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_pread64_event_t), 0);
  return 0;
}

struct entry_c_write_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    
  u32 count;
  char fname[256];
;
};        
struct exit_c_write_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    
  int ret;
;    
};                                                          


int entry_trace_write(struct pt_regs *ctx , int fd, const void *data, u32 count) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_write_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_write_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.count = count;
    const char **filename = file_map.lookup(&fd);
    if (filename != 0) {
        int len = bpf_probe_read_kernel_str(&event.fname, sizeof(event.fname), *filename);
    }

    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_write_event_t), 0);
  }
  return 0;
}

int exit_trace_write(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_write_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_write_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
  
    exit_event.ret = PT_REGS_RC(ctx);
  
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_write_event_t), 0);
  return 0;
}

struct entry_c_pwrite_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    
  u32 count;
  s64 offset;
  char fname[256];
;
};        
struct exit_c_pwrite_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    
  int ret;
;    
};                                                          


int entry_trace_pwrite(struct pt_regs *ctx , int fd, const void *data, u32 count, s64 offset) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_pwrite_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_pwrite_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.count = count;
    event.offset = offset;
    const char **filename = file_map.lookup(&fd);
    if (filename != 0) {
        int len = bpf_probe_read_kernel_str(&event.fname, sizeof(event.fname), *filename);
    }

    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_pwrite_event_t), 0);
  }
  return 0;
}

int exit_trace_pwrite(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_pwrite_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_pwrite_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
  
    exit_event.ret = PT_REGS_RC(ctx);
  
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_pwrite_event_t), 0);
  return 0;
}

struct entry_c_pwrite64_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    
  u32 count;
  s64 offset;
  char fname[256];
;
};        
struct exit_c_pwrite64_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    
  int ret;
;    
};                                                          


int entry_trace_pwrite64(struct pt_regs *ctx , int fd, const void *data, u32 count, s64 offset) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_pwrite64_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_pwrite64_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.count = count;
    event.offset = offset;
    const char **filename = file_map.lookup(&fd);
    if (filename != 0) {
        int len = bpf_probe_read_kernel_str(&event.fname, sizeof(event.fname), *filename);
    }

    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_pwrite64_event_t), 0);
  }
  return 0;
}

int exit_trace_pwrite64(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_pwrite64_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_pwrite64_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
  
    exit_event.ret = PT_REGS_RC(ctx);
  
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_pwrite64_event_t), 0);
  return 0;
}

struct entry_c_lseek_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_lseek_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_lseek(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_lseek_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_lseek_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_lseek_event_t), 0);
  }
  return 0;
}

int exit_trace_lseek(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_lseek_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_lseek_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_lseek_event_t), 0);
  return 0;
}

struct entry_c_lseek64_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_lseek64_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_lseek64(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_lseek64_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_lseek64_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_lseek64_event_t), 0);
  }
  return 0;
}

int exit_trace_lseek64(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_lseek64_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_lseek64_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_lseek64_event_t), 0);
  return 0;
}

struct entry_c_fdopen_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_fdopen_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_fdopen(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_fdopen_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_fdopen_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_fdopen_event_t), 0);
  }
  return 0;
}

int exit_trace_fdopen(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_fdopen_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_fdopen_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_fdopen_event_t), 0);
  return 0;
}

struct entry_c_fileno_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_fileno_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_fileno(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_fileno_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_fileno_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_fileno_event_t), 0);
  }
  return 0;
}

int exit_trace_fileno(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_fileno_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_fileno_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_fileno_event_t), 0);
  return 0;
}

struct entry_c_fileno_unlocked_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_fileno_unlocked_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_fileno_unlocked(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_fileno_unlocked_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_fileno_unlocked_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_fileno_unlocked_event_t), 0);
  }
  return 0;
}

int exit_trace_fileno_unlocked(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_fileno_unlocked_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_fileno_unlocked_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_fileno_unlocked_event_t), 0);
  return 0;
}

struct entry_c_mmap_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_mmap_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_mmap(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_mmap_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_mmap_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_mmap_event_t), 0);
  }
  return 0;
}

int exit_trace_mmap(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_mmap_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_mmap_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_mmap_event_t), 0);
  return 0;
}

struct entry_c_mmap64_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_mmap64_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_mmap64(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_mmap64_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_mmap64_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_mmap64_event_t), 0);
  }
  return 0;
}

int exit_trace_mmap64(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_mmap64_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_mmap64_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_mmap64_event_t), 0);
  return 0;
}

struct entry_c_munmap_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_munmap_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_munmap(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_munmap_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_munmap_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_munmap_event_t), 0);
  }
  return 0;
}

int exit_trace_munmap(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_munmap_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_munmap_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_munmap_event_t), 0);
  return 0;
}

struct entry_c_msync_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_msync_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_msync(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_msync_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_msync_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_msync_event_t), 0);
  }
  return 0;
}

int exit_trace_msync(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_msync_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_msync_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_msync_event_t), 0);
  return 0;
}

struct entry_c_mremap_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_mremap_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_mremap(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_mremap_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_mremap_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_mremap_event_t), 0);
  }
  return 0;
}

int exit_trace_mremap(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_mremap_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_mremap_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_mremap_event_t), 0);
  return 0;
}

struct entry_c_madvise_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_madvise_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_madvise(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_madvise_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_madvise_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_madvise_event_t), 0);
  }
  return 0;
}

int exit_trace_madvise(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_madvise_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_madvise_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_madvise_event_t), 0);
  return 0;
}

struct entry_c_shm_open_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_shm_open_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_shm_open(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_shm_open_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_shm_open_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_shm_open_event_t), 0);
  }
  return 0;
}

int exit_trace_shm_open(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_shm_open_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_shm_open_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_shm_open_event_t), 0);
  return 0;
}

struct entry_c_shm_unlink_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_shm_unlink_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_shm_unlink(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_shm_unlink_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_shm_unlink_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_shm_unlink_event_t), 0);
  }
  return 0;
}

int exit_trace_shm_unlink(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_shm_unlink_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_shm_unlink_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_shm_unlink_event_t), 0);
  return 0;
}

struct entry_c_memfd_create_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_memfd_create_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_memfd_create(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_memfd_create_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_memfd_create_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_memfd_create_event_t), 0);
  }
  return 0;
}

int exit_trace_memfd_create(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_memfd_create_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_memfd_create_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_memfd_create_event_t), 0);
  return 0;
}

struct entry_c_fsync_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_fsync_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_fsync(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_fsync_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_fsync_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_fsync_event_t), 0);
  }
  return 0;
}

int exit_trace_fsync(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_fsync_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_fsync_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_fsync_event_t), 0);
  return 0;
}

struct entry_c_fdatasync_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_fdatasync_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_fdatasync(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_fdatasync_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_fdatasync_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_fdatasync_event_t), 0);
  }
  return 0;
}

int exit_trace_fdatasync(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_fdatasync_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_fdatasync_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_fdatasync_event_t), 0);
  return 0;
}

struct entry_c_fcntl_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_fcntl_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_fcntl(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_fcntl_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_fcntl_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_fcntl_event_t), 0);
  }
  return 0;
}

int exit_trace_fcntl(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_fcntl_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_fcntl_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_fcntl_event_t), 0);
  return 0;
}

struct entry_c_malloc_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_malloc_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_malloc(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_malloc_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_malloc_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_malloc_event_t), 0);
  }
  return 0;
}

int exit_trace_malloc(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_malloc_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_malloc_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_malloc_event_t), 0);
  return 0;
}

struct entry_c_calloc_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_calloc_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_calloc(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_calloc_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_calloc_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_calloc_event_t), 0);
  }
  return 0;
}

int exit_trace_calloc(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_calloc_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_calloc_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_calloc_event_t), 0);
  return 0;
}

struct entry_c_realloc_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_realloc_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_realloc(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_realloc_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_realloc_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_realloc_event_t), 0);
  }
  return 0;
}

int exit_trace_realloc(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_realloc_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_realloc_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_realloc_event_t), 0);
  return 0;
}

struct entry_c_posix_memalign_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_posix_memalign_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_posix_memalign(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_posix_memalign_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_posix_memalign_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_posix_memalign_event_t), 0);
  }
  return 0;
}

int exit_trace_posix_memalign(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_posix_memalign_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_posix_memalign_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_posix_memalign_event_t), 0);
  return 0;
}

struct entry_c_valloc_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_valloc_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_valloc(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_valloc_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_valloc_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_valloc_event_t), 0);
  }
  return 0;
}

int exit_trace_valloc(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_valloc_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_valloc_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_valloc_event_t), 0);
  return 0;
}

struct entry_c_memalign_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_memalign_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_memalign(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_memalign_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_memalign_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_memalign_event_t), 0);
  }
  return 0;
}

int exit_trace_memalign(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_memalign_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_memalign_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_memalign_event_t), 0);
  return 0;
}

struct entry_c_pvalloc_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_pvalloc_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_pvalloc(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_pvalloc_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_pvalloc_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_pvalloc_event_t), 0);
  }
  return 0;
}

int exit_trace_pvalloc(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_pvalloc_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_pvalloc_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_pvalloc_event_t), 0);
  return 0;
}

struct entry_c_aligned_alloc_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_aligned_alloc_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_aligned_alloc(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_aligned_alloc_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_aligned_alloc_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_aligned_alloc_event_t), 0);
  }
  return 0;
}

int exit_trace_aligned_alloc(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_aligned_alloc_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_aligned_alloc_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_aligned_alloc_event_t), 0);
  return 0;
}

struct entry_c_free_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_c_free_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_free(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_c_free_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = c_free_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_c_free_event_t), 0);
  }
  return 0;
}

int exit_trace_free(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_c_free_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = c_free_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_c_free_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_set_size_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_set_size_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_set_size(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_set_size_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_set_size_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_set_size_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_set_size(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_set_size_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_set_size_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_set_size_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_iread_at_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_iread_at_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_iread_at(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_iread_at_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_iread_at_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_iread_at_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_iread_at(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_iread_at_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_iread_at_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_iread_at_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_iread_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_iread_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_iread(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_iread_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_iread_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_iread_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_iread(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_iread_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_iread_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_iread_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_iread_shared_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_iread_shared_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_iread_shared(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_iread_shared_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_iread_shared_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_iread_shared_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_iread_shared(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_iread_shared_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_iread_shared_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_iread_shared_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_iwrite_at_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_iwrite_at_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_iwrite_at(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_iwrite_at_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_iwrite_at_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_iwrite_at_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_iwrite_at(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_iwrite_at_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_iwrite_at_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_iwrite_at_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_iwrite_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_iwrite_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_iwrite(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_iwrite_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_iwrite_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_iwrite_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_iwrite(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_iwrite_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_iwrite_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_iwrite_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_iwrite_shared_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_iwrite_shared_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_iwrite_shared(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_iwrite_shared_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_iwrite_shared_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_iwrite_shared_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_iwrite_shared(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_iwrite_shared_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_iwrite_shared_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_iwrite_shared_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_open_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_open_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_open(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_open_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_open_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_open_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_open(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_open_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_open_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_open_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_read_all_begin_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_read_all_begin_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_read_all_begin(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_read_all_begin_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_read_all_begin_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_read_all_begin_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_read_all_begin(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_read_all_begin_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_read_all_begin_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_read_all_begin_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_read_all_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_read_all_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_read_all(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_read_all_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_read_all_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_read_all_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_read_all(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_read_all_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_read_all_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_read_all_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_read_at_all_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_read_at_all_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_read_at_all(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_read_at_all_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_read_at_all_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_read_at_all_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_read_at_all(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_read_at_all_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_read_at_all_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_read_at_all_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_read_at_all_begin_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_read_at_all_begin_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_read_at_all_begin(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_read_at_all_begin_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_read_at_all_begin_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_read_at_all_begin_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_read_at_all_begin(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_read_at_all_begin_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_read_at_all_begin_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_read_at_all_begin_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_read_at_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_read_at_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_read_at(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_read_at_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_read_at_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_read_at_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_read_at(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_read_at_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_read_at_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_read_at_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_read_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_read_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_read(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_read_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_read_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_read_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_read(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_read_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_read_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_read_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_read_ordered_begin_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_read_ordered_begin_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_read_ordered_begin(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_read_ordered_begin_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_read_ordered_begin_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_read_ordered_begin_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_read_ordered_begin(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_read_ordered_begin_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_read_ordered_begin_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_read_ordered_begin_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_read_ordered_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_read_ordered_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_read_ordered(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_read_ordered_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_read_ordered_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_read_ordered_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_read_ordered(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_read_ordered_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_read_ordered_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_read_ordered_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_read_shared_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_read_shared_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_read_shared(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_read_shared_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_read_shared_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_read_shared_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_read_shared(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_read_shared_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_read_shared_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_read_shared_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_set_view_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_set_view_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_set_view(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_set_view_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_set_view_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_set_view_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_set_view(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_set_view_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_set_view_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_set_view_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_sync_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_sync_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_sync(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_sync_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_sync_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_sync_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_sync(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_sync_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_sync_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_sync_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_write_all_begin_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_write_all_begin_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_write_all_begin(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_write_all_begin_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_write_all_begin_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_write_all_begin_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_write_all_begin(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_write_all_begin_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_write_all_begin_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_write_all_begin_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_write_all_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_write_all_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_write_all(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_write_all_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_write_all_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_write_all_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_write_all(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_write_all_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_write_all_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_write_all_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_write_at_all_begin_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_write_at_all_begin_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_write_at_all_begin(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_write_at_all_begin_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_write_at_all_begin_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_write_at_all_begin_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_write_at_all_begin(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_write_at_all_begin_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_write_at_all_begin_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_write_at_all_begin_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_write_at_all_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_write_at_all_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_write_at_all(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_write_at_all_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_write_at_all_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_write_at_all_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_write_at_all(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_write_at_all_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_write_at_all_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_write_at_all_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_write_at_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_write_at_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_write_at(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_write_at_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_write_at_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_write_at_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_write_at(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_write_at_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_write_at_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_write_at_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_write_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_write_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_write(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_write_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_write_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_write_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_write(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_write_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_write_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_write_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_write_ordered_begin_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_write_ordered_begin_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_write_ordered_begin(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_write_ordered_begin_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_write_ordered_begin_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_write_ordered_begin_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_write_ordered_begin(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_write_ordered_begin_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_write_ordered_begin_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_write_ordered_begin_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_write_ordered_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_write_ordered_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_write_ordered(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_write_ordered_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_write_ordered_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_write_ordered_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_write_ordered(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_write_ordered_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_write_ordered_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_write_ordered_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_write_shared_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_write_shared_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_write_shared(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_write_shared_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_write_shared_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_write_shared_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_write_shared(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_write_shared_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_write_shared_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_write_shared_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Finalized_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Finalized_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Finalized(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Finalized_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Finalized_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Finalized_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Finalized(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Finalized_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Finalized_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Finalized_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Init_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Init_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Init(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Init_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Init_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Init_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Init(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Init_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Init_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Init_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Finalize_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Finalize_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Finalize(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Finalize_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Finalize_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Finalize_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Finalize(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Finalize_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Finalize_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Finalize_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Comm_rank_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Comm_rank_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Comm_rank(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Comm_rank_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Comm_rank_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Comm_rank_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Comm_rank(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Comm_rank_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Comm_rank_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Comm_rank_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Comm_size_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Comm_size_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Comm_size(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Comm_size_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Comm_size_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Comm_size_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Comm_size(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Comm_size_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Comm_size_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Comm_size_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Init_thread_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Init_thread_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Init_thread(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Init_thread_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Init_thread_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Init_thread_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Init_thread(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Init_thread_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Init_thread_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Init_thread_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Get_processor_name_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Get_processor_name_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Get_processor_name(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Get_processor_name_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Get_processor_name_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Get_processor_name_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Get_processor_name(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Get_processor_name_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Get_processor_name_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Get_processor_name_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Comm_set_errhandler_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Comm_set_errhandler_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Comm_set_errhandler(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Comm_set_errhandler_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Comm_set_errhandler_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Comm_set_errhandler_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Comm_set_errhandler(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Comm_set_errhandler_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Comm_set_errhandler_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Comm_set_errhandler_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Barrier_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Barrier_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Barrier(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Barrier_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Barrier_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Barrier_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Barrier(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Barrier_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Barrier_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Barrier_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Bcast_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Bcast_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Bcast(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Bcast_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Bcast_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Bcast_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Bcast(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Bcast_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Bcast_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Bcast_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Gather_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Gather_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Gather(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Gather_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Gather_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Gather_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Gather(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Gather_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Gather_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Gather_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Gatherv_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Gatherv_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Gatherv(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Gatherv_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Gatherv_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Gatherv_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Gatherv(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Gatherv_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Gatherv_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Gatherv_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Scatterv_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Scatterv_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Scatterv(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Scatterv_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Scatterv_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Scatterv_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Scatterv(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Scatterv_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Scatterv_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Scatterv_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Allgather_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Allgather_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Allgather(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Allgather_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Allgather_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Allgather_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Allgather(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Allgather_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Allgather_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Allgather_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Allgatherv_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Allgatherv_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Allgatherv(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Allgatherv_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Allgatherv_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Allgatherv_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Allgatherv(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Allgatherv_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Allgatherv_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Allgatherv_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Alltoall_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Alltoall_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Alltoall(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Alltoall_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Alltoall_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Alltoall_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Alltoall(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Alltoall_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Alltoall_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Alltoall_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Reduce_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Reduce_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Reduce(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Reduce_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Reduce_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Reduce_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Reduce(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Reduce_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Reduce_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Reduce_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Allreduce_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Allreduce_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Allreduce(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Allreduce_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Allreduce_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Allreduce_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Allreduce(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Allreduce_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Allreduce_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Allreduce_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Reduce_scatter_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Reduce_scatter_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Reduce_scatter(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Reduce_scatter_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Reduce_scatter_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Reduce_scatter_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Reduce_scatter(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Reduce_scatter_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Reduce_scatter_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Reduce_scatter_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Scan_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Scan_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Scan(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Scan_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Scan_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Scan_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Scan(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Scan_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Scan_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Scan_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Type_commit_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Type_commit_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Type_commit(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Type_commit_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Type_commit_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Type_commit_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Type_commit(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Type_commit_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Type_commit_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Type_commit_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Type_create_darray_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Type_create_darray_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Type_create_darray(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Type_create_darray_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Type_create_darray_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Type_create_darray_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Type_create_darray(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Type_create_darray_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Type_create_darray_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Type_create_darray_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_get_size_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_get_size_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_get_size(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_get_size_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_get_size_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_get_size_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_get_size(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_get_size_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_get_size_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_get_size_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Cart_rank_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Cart_rank_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Cart_rank(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Cart_rank_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Cart_rank_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Cart_rank_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Cart_rank(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Cart_rank_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Cart_rank_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Cart_rank_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Cart_create_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Cart_create_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Cart_create(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Cart_create_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Cart_create_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Cart_create_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Cart_create(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Cart_create_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Cart_create_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Cart_create_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Cart_get_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Cart_get_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Cart_get(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Cart_get_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Cart_get_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Cart_get_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Cart_get(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Cart_get_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Cart_get_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Cart_get_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Cart_shift_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Cart_shift_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Cart_shift(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Cart_shift_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Cart_shift_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Cart_shift_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Cart_shift(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Cart_shift_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Cart_shift_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Cart_shift_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Wait_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Wait_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Wait(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Wait_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Wait_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Wait_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Wait(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Wait_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Wait_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Wait_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Send_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Send_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Send(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Send_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Send_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Send_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Send(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Send_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Send_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Send_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Recv_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Recv_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Recv(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Recv_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Recv_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Recv_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Recv(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Recv_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Recv_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Recv_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Sendrecv_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Sendrecv_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Sendrecv(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Sendrecv_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Sendrecv_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Sendrecv_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Sendrecv(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Sendrecv_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Sendrecv_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Sendrecv_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Isend_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Isend_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Isend(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Isend_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Isend_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Isend_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Isend(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Isend_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Isend_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Isend_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Irecv_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Irecv_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Irecv(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Irecv_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Irecv_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Irecv_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Irecv(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Irecv_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Irecv_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Irecv_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Waitall_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Waitall_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Waitall(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Waitall_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Waitall_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Waitall_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Waitall(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Waitall_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Waitall_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Waitall_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Waitsome_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Waitsome_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Waitsome(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Waitsome_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Waitsome_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Waitsome_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Waitsome(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Waitsome_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Waitsome_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Waitsome_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Waitany_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Waitany_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Waitany(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Waitany_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Waitany_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Waitany_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Waitany(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Waitany_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Waitany_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Waitany_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Ssend_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Ssend_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Ssend(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Ssend_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Ssend_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Ssend_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Ssend(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Ssend_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Ssend_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Ssend_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Comm_split_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Comm_split_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Comm_split(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Comm_split_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Comm_split_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Comm_split_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Comm_split(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Comm_split_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Comm_split_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Comm_split_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Comm_dup_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Comm_dup_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Comm_dup(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Comm_dup_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Comm_dup_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Comm_dup_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Comm_dup(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Comm_dup_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Comm_dup_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Comm_dup_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Comm_create_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Comm_create_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Comm_create(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Comm_create_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Comm_create_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Comm_create_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Comm_create(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Comm_create_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Comm_create_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Comm_create_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_seek_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_seek_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_seek(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_seek_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_seek_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_seek_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_seek(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_seek_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_seek_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_seek_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_File_seek_shared_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_File_seek_shared_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_File_seek_shared(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_File_seek_shared_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_File_seek_shared_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_File_seek_shared_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_File_seek_shared(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_File_seek_shared_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_File_seek_shared_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_File_seek_shared_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Ibcast_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Ibcast_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Ibcast(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Ibcast_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Ibcast_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Ibcast_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Ibcast(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Ibcast_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Ibcast_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Ibcast_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Test_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Test_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Test(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Test_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Test_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Test_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Test(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Test_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Test_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Test_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Testall_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Testall_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Testall(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Testall_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Testall_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Testall_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Testall(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Testall_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Testall_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Testall_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Testsome_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Testsome_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Testsome(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Testsome_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Testsome_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Testsome_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Testsome(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Testsome_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Testsome_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Testsome_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Testany_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Testany_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Testany(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Testany_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Testany_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Testany_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Testany(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Testany_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Testany_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Testany_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Ireduce_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Ireduce_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Ireduce(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Ireduce_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Ireduce_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Ireduce_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Ireduce(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Ireduce_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Ireduce_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Ireduce_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Igather_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Igather_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Igather(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Igather_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Igather_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Igather_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Igather(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Igather_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Igather_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Igather_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Iscatter_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Iscatter_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Iscatter(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Iscatter_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Iscatter_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Iscatter_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Iscatter(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Iscatter_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Iscatter_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Iscatter_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Ialltoall_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Ialltoall_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Ialltoall(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Ialltoall_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Ialltoall_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Ialltoall_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Ialltoall(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Ialltoall_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Ialltoall_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Ialltoall_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Comm_free_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Comm_free_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Comm_free(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Comm_free_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Comm_free_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Comm_free_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Comm_free(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Comm_free_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Comm_free_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Comm_free_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Cart_sub_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Cart_sub_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Cart_sub(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Cart_sub_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Cart_sub_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Cart_sub_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Cart_sub(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Cart_sub_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Cart_sub_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Cart_sub_event_t), 0);
  return 0;
}

struct entry_mpi_MPI_Comm_split_type_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_mpi_MPI_Comm_split_type_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_MPI_Comm_split_type(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_mpi_MPI_Comm_split_type_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = mpi_MPI_Comm_split_type_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_mpi_MPI_Comm_split_type_event_t), 0);
  }
  return 0;
}

int exit_trace_MPI_Comm_split_type(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_mpi_MPI_Comm_split_type_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = mpi_MPI_Comm_split_type_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_mpi_MPI_Comm_split_type_event_t), 0);
  return 0;
}

struct entry_user__Z10gen_randomB5cxx11i_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_user__Z10gen_randomB5cxx11i_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace__Z10gen_randomB5cxx11i(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_user__Z10gen_randomB5cxx11i_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = user__Z10gen_randomB5cxx11i_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_user__Z10gen_randomB5cxx11i_event_t), 0);
  }
  return 0;
}

int exit_trace__Z10gen_randomB5cxx11i(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_user__Z10gen_randomB5cxx11i_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = user__Z10gen_randomB5cxx11i_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_user__Z10gen_randomB5cxx11i_event_t), 0);
  return 0;
}

struct entry_user__fini_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_user__fini_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace__fini(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_user__fini_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = user__fini_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_user__fini_event_t), 0);
  }
  return 0;
}

int exit_trace__fini(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_user__fini_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = user__fini_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_user__fini_event_t), 0);
  return 0;
}

struct entry_user__init_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_user__init_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace__init(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_user__init_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = user__init_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_user__init_event_t), 0);
  }
  return 0;
}

int exit_trace__init(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_user__init_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = user__init_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_user__init_event_t), 0);
  return 0;
}

struct entry_user__start_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_user__start_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace__start(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_user__start_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = user__start_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_user__start_event_t), 0);
  }
  return 0;
}

int exit_trace__start(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_user__start_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = user__start_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_user__start_event_t), 0);
  return 0;
}

struct entry_user_main_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                     
    u64 id;                                                                    
    u64 ts;                                                                   
    u32 uid;                                                                   
    char process[16];                                           
    ;
};        
struct exit_user_main_event_t {                                        
    enum EventType name;
    enum EventPhase phase;                                                    
    u64 id;                                                                    
    u64 ts;                                                        
    ;    
};                                                          


int entry_trace_main(struct pt_regs *ctx ) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;  
  struct entry_user_main_event_t event = {};
  event.id = id;
  int status = bpf_get_current_comm(&event.process, sizeof(event.process));    
  if (status == 0) {
    event.name = user_main_type;         
    event.phase = PHASE_BEGIN;
    event.uid = bpf_get_current_uid_gid();                                       
    
    event.ts = get_current_time(start_ts);
    events.ringbuf_output(&event, sizeof(struct entry_user_main_event_t), 0);
  }
  return 0;
}

int exit_trace_main(struct pt_regs *ctx) {
  u64 tsp = bpf_ktime_get_ns() / 1000;
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;
  u64 start = 0;
  u64* start_ts = pid_map.lookup(&pid);
  if (start_ts == 0)                                      
    return 0;
  struct exit_user_main_event_t exit_event = {};
  exit_event.id = id;
  exit_event.name = user_main_type;         
  exit_event.phase = PHASE_END;
  exit_event.ts = get_current_time2(&tsp, start_ts);
    
  events.ringbuf_output(&exit_event, sizeof(struct exit_user_main_event_t), 0);
  return 0;
}
