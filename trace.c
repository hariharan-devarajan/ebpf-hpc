
/* Header for BPF */
#include <linux/sched.h>
#include <uapi/linux/limits.h>
#include <uapi/linux/ptrace.h>

struct filename_t {
    char fname[256];
};
enum event_type_t {
  
                syscall_openat_type=1,
            
                syscall_read_type=2,
            
                syscall_write_type=3,
            
                syscall_close_type=4,
            
                syscall_copy_file_range_type=5,
            
                syscall_execve_type=6,
            
                syscall_execveat_type=7,
            
                syscall_exit_type=8,
            
                syscall_faccessat_type=9,
            
                syscall_fallocate_type=10,
            
                syscall_fdatasync_type=11,
            
                syscall_flock_type=12,
            
                syscall_fsopen_type=13,
            
                syscall_fstatfs_type=14,
            
                syscall_fsync_type=15,
            
                syscall_ftruncate_type=16,
            
                syscall_io_pgetevents_type=17,
            
                syscall_lseek_type=18,
            
                syscall_memfd_create_type=19,
            
                syscall_migrate_pages_type=20,
            
                syscall_mlock_type=21,
            
                syscall_mmap_type=22,
            
                syscall_msync_type=23,
            
                syscall_pread64_type=24,
            
                syscall_preadv_type=25,
            
                syscall_preadv2_type=26,
            
                syscall_pwrite64_type=27,
            
                syscall_pwritev_type=28,
            
                syscall_pwritev2_type=29,
            
                syscall_readahead_type=30,
            
                syscall_readlinkat_type=31,
            
                syscall_readv_type=32,
            
                syscall_renameat_type=33,
            
                syscall_renameat2_type=34,
            
                syscall_statfs_type=35,
            
                syscall_statx_type=36,
            
                syscall_sync_type=37,
            
                syscall_sync_file_range_type=38,
            
                syscall_syncfs_type=39,
            
                syscall_writev_type=40,
            
                os_cache_add_to_page_cache_lru_type=41,
            
                os_cache_mark_page_accessed_type=42,
            
                os_cache_account_page_dirtied_type=43,
            
                os_cache_mark_buffer_dirty_type=44,
            
                os_cache_do_page_cache_ra_type=45,
            
                os_cache___page_cache_alloc_type=46,
            
                ext4_ext4_file_write_iter_type=47,
            
                ext4_ext4_file_open_type=48,
            
                ext4_ext4_sync_file_type=49,
            
                ext4_ext4_alloc_da_blocks_type=50,
            
                ext4_ext4_da_release_space_type=51,
            
                ext4_ext4_da_reserve_space_type=52,
            
                ext4_ext4_da_write_begin_type=53,
            
                ext4_ext4_da_write_end_type=54,
            
                ext4_ext4_discard_preallocations_type=55,
            
                ext4_ext4_fallocate_type=56,
            
                ext4_ext4_free_blocks_type=57,
            
                ext4_ext4_readpage_type=58,
            
                ext4_ext4_remove_blocks_type=59,
            
                ext4_ext4_sync_fs_type=60,
            
                ext4_ext4_truncate_type=61,
            
                ext4_ext4_write_begin_type=62,
            
                ext4_ext4_write_end_type=63,
            
                ext4_ext4_writepage_type=64,
            
                ext4_ext4_writepages_type=65,
            
                ext4_ext4_zero_range_type=66,
            
                ext4_vfs_type=67,
            
                c_open_type=68,
            
                c_open64_type=69,
            
                c_creat_type=70,
            
                c_creat64_type=71,
            
                c_close_range_type=72,
            
                c_closefrom_type=73,
            
                c_close_type=74,
            
                c_read_type=75,
            
                c_pread_type=76,
            
                c_pread64_type=77,
            
                c_fdopen_type=78,
            
                c_fileno_type=79,
            
                c_fileno_unlocked_type=80,
            
                c_mmap_type=81,
            
                c_munmap_type=82,
            
                c_msync_type=83,
            
                c_mremap_type=84,
            
                c_madvise_type=85,
            
                c_shm_open_type=86,
            
                c_shm_unlink_type=87,
            
                c_memfd_create_type=88,
            
                c_fsync_type=89,
            
                c_fdatasync_type=90,
            
                c_fcntl_type=91,
            
                c_malloc_type=92,
            
                c_calloc_type=93,
            
                c_realloc_type=94,
            
                c_posix_memalign_type=95,
            
                c_valloc_type=96,
            
                c_memalign_type=97,
            
                c_pvalloc_type=98,
            
                c_aligned_alloc_type=99,
            
                c_free_type=100,
            
                mpi_MPI_File_set_size_type=101,
            
                mpi_MPI_File_iread_at_type=102,
            
                mpi_MPI_File_iread_type=103,
            
                mpi_MPI_File_iread_shared_type=104,
            
                mpi_MPI_File_iwrite_at_type=105,
            
                mpi_MPI_File_iwrite_type=106,
            
                mpi_MPI_File_iwrite_shared_type=107,
            
                mpi_MPI_File_open_type=108,
            
                mpi_MPI_File_read_all_begin_type=109,
            
                mpi_MPI_File_read_all_type=110,
            
                mpi_MPI_File_read_at_all_type=111,
            
                mpi_MPI_File_read_at_all_begin_type=112,
            
                mpi_MPI_File_read_at_type=113,
            
                mpi_MPI_File_read_type=114,
            
                mpi_MPI_File_read_ordered_begin_type=115,
            
                mpi_MPI_File_read_ordered_type=116,
            
                mpi_MPI_File_read_shared_type=117,
            
                mpi_MPI_File_set_view_type=118,
            
                mpi_MPI_File_sync_type=119,
            
                mpi_MPI_File_write_all_begin_type=120,
            
                mpi_MPI_File_write_all_type=121,
            
                mpi_MPI_File_write_at_all_begin_type=122,
            
                mpi_MPI_File_write_at_all_type=123,
            
                mpi_MPI_File_write_at_type=124,
            
                mpi_MPI_File_write_type=125,
            
                mpi_MPI_File_write_ordered_begin_type=126,
            
                mpi_MPI_File_write_ordered_type=127,
            
                mpi_MPI_File_write_shared_type=128,
            
                mpi_MPI_Finalized_type=129,
            
                mpi_MPI_Init_type=130,
            
                mpi_MPI_Finalize_type=131,
            
                mpi_MPI_Comm_rank_type=132,
            
                mpi_MPI_Comm_size_type=133,
            
                mpi_MPI_Init_thread_type=134,
            
                mpi_MPI_Get_processor_name_type=135,
            
                mpi_MPI_Comm_set_errhandler_type=136,
            
                mpi_MPI_Barrier_type=137,
            
                mpi_MPI_Bcast_type=138,
            
                mpi_MPI_Gather_type=139,
            
                mpi_MPI_Gatherv_type=140,
            
                mpi_MPI_Scatterv_type=141,
            
                mpi_MPI_Allgather_type=142,
            
                mpi_MPI_Allgatherv_type=143,
            
                mpi_MPI_Alltoall_type=144,
            
                mpi_MPI_Reduce_type=145,
            
                mpi_MPI_Allreduce_type=146,
            
                mpi_MPI_Reduce_scatter_type=147,
            
                mpi_MPI_Scan_type=148,
            
                mpi_MPI_Type_commit_type=149,
            
                mpi_MPI_Type_create_darray_type=150,
            
                mpi_MPI_File_get_size_type=151,
            
                mpi_MPI_Cart_rank_type=152,
            
                mpi_MPI_Cart_create_type=153,
            
                mpi_MPI_Cart_get_type=154,
            
                mpi_MPI_Cart_shift_type=155,
            
                mpi_MPI_Wait_type=156,
            
                mpi_MPI_Send_type=157,
            
                mpi_MPI_Recv_type=158,
            
                mpi_MPI_Sendrecv_type=159,
            
                mpi_MPI_Isend_type=160,
            
                mpi_MPI_Irecv_type=161,
            
                mpi_MPI_Waitall_type=162,
            
                mpi_MPI_Waitsome_type=163,
            
                mpi_MPI_Waitany_type=164,
            
                mpi_MPI_Ssend_type=165,
            
                mpi_MPI_Comm_split_type=166,
            
                mpi_MPI_Comm_dup_type=167,
            
                mpi_MPI_Comm_create_type=168,
            
                mpi_MPI_File_seek_type=169,
            
                mpi_MPI_File_seek_shared_type=170,
            
                mpi_MPI_Ibcast_type=171,
            
                mpi_MPI_Test_type=172,
            
                mpi_MPI_Testall_type=173,
            
                mpi_MPI_Testsome_type=174,
            
                mpi_MPI_Testany_type=175,
            
                mpi_MPI_Ireduce_type=176,
            
                mpi_MPI_Igather_type=177,
            
                mpi_MPI_Iscatter_type=178,
            
                mpi_MPI_Ialltoall_type=179,
            
                mpi_MPI_Comm_free_type=180,
            
                mpi_MPI_Cart_sub_type=181,
            
                mpi_MPI_Comm_split_type_type=182,
            
                df_tracer_test__Z10gen_randomB5cxx11i_type=183,
            
                df_tracer_test__fini_type=184,
            
                df_tracer_test__init_type=185,
            
                df_tracer_test__start_type=186,
            
                df_tracer_test_main_type=187,
            
};

BPF_RINGBUF_OUTPUT(events, 1 << 16); // store the events in ring buffer
BPF_HASH(pid_map, u32, u64); // store pid to be traced
BPF_HASH(temp_file_map, u64, struct filename_t); // map filenames to id:pid + tgid
BPF_HASH(start_time_map, u64, u64); // map start time to id:pid + tgid
//BPF_STACK_TRACE(stack_traces, 16384);

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


struct syscall_msync_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__msync_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__msync_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_msync_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_msync_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_msync_event_t), 0);
    return 0;
}

struct syscall_flock_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__flock_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__flock_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_flock_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_flock_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_flock_event_t), 0);
    return 0;
}

struct syscall_pread64_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__pread64_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__pread64_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_pread64_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_pread64_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_pread64_event_t), 0);
    return 0;
}

struct syscall_preadv_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__preadv_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__preadv_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_preadv_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_preadv_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_preadv_event_t), 0);
    return 0;
}

struct syscall_fsopen_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__fsopen_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__fsopen_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_fsopen_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_fsopen_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_fsopen_event_t), 0);
    return 0;
}

struct syscall_mmap_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__mmap_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__mmap_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_mmap_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_mmap_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_mmap_event_t), 0);
    return 0;
}

struct syscall_lseek_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__lseek_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__lseek_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_lseek_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_lseek_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_lseek_event_t), 0);
    return 0;
}

struct syscall_openat_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__openat_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__openat_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_openat_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_openat_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_openat_event_t), 0);
    return 0;
}

struct syscall_migrate_pages_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__migrate_pages_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__migrate_pages_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_migrate_pages_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_migrate_pages_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_migrate_pages_event_t), 0);
    return 0;
}

struct syscall_write_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__write_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__write_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_write_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_write_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_write_event_t), 0);
    return 0;
}

struct syscall_read_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__read_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__read_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_read_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_read_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_read_event_t), 0);
    return 0;
}

struct syscall_ftruncate_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__ftruncate_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__ftruncate_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_ftruncate_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_ftruncate_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_ftruncate_event_t), 0);
    return 0;
}

struct syscall_close_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__close_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__close_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_close_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_close_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_close_event_t), 0);
    return 0;
}

struct syscall_mlock_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__mlock_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__mlock_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_mlock_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_mlock_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_mlock_event_t), 0);
    return 0;
}

struct syscall_copy_file_range_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__copy_file_range_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__copy_file_range_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_copy_file_range_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_copy_file_range_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_copy_file_range_event_t), 0);
    return 0;
}

struct syscall_io_pgetevents_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__io_pgetevents_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__io_pgetevents_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_io_pgetevents_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_io_pgetevents_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_io_pgetevents_event_t), 0);
    return 0;
}

struct syscall_exit_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__exit_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__exit_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_exit_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_exit_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_exit_event_t), 0);
    return 0;
}

struct syscall_fsync_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__fsync_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__fsync_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_fsync_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_fsync_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_fsync_event_t), 0);
    return 0;
}

struct syscall_preadv2_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__preadv2_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__preadv2_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_preadv2_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_preadv2_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_preadv2_event_t), 0);
    return 0;
}

struct syscall_execve_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__execve_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__execve_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_execve_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_execve_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_execve_event_t), 0);
    return 0;
}

struct syscall_memfd_create_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__memfd_create_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__memfd_create_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_memfd_create_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_memfd_create_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_memfd_create_event_t), 0);
    return 0;
}

struct syscall_fallocate_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__fallocate_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__fallocate_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_fallocate_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_fallocate_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_fallocate_event_t), 0);
    return 0;
}

struct syscall_faccessat_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__faccessat_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__faccessat_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_faccessat_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_faccessat_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_faccessat_event_t), 0);
    return 0;
}

struct syscall_fdatasync_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__fdatasync_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__fdatasync_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_fdatasync_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_fdatasync_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_fdatasync_event_t), 0);
    return 0;
}

struct syscall_pwrite64_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__pwrite64_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__pwrite64_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_pwrite64_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_pwrite64_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_pwrite64_event_t), 0);
    return 0;
}

struct syscall_pwritev_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__pwritev_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__pwritev_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_pwritev_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_pwritev_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_pwritev_event_t), 0);
    return 0;
}

struct syscall_pwritev2_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__pwritev2_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__pwritev2_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_pwritev2_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_pwritev2_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_pwritev2_event_t), 0);
    return 0;
}

struct syscall_fstatfs_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__fstatfs_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__fstatfs_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_fstatfs_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_fstatfs_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_fstatfs_event_t), 0);
    return 0;
}

struct syscall_readahead_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__readahead_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__readahead_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_readahead_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_readahead_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_readahead_event_t), 0);
    return 0;
}

struct syscall_readlinkat_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__readlinkat_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__readlinkat_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_readlinkat_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_readlinkat_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_readlinkat_event_t), 0);
    return 0;
}

struct syscall_readv_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__readv_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__readv_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_readv_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_readv_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_readv_event_t), 0);
    return 0;
}

struct syscall_renameat_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__renameat_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__renameat_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_renameat_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_renameat_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_renameat_event_t), 0);
    return 0;
}

struct syscall_renameat2_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__renameat2_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__renameat2_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_renameat2_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_renameat2_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_renameat2_event_t), 0);
    return 0;
}

struct syscall_statfs_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__statfs_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__statfs_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_statfs_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_statfs_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_statfs_event_t), 0);
    return 0;
}

struct syscall_statx_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__statx_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__statx_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_statx_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_statx_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_statx_event_t), 0);
    return 0;
}

struct syscall_sync_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__sync_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__sync_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_sync_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_sync_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_sync_event_t), 0);
    return 0;
}

struct syscall_execveat_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__execveat_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__execveat_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_execveat_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_execveat_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_execveat_event_t), 0);
    return 0;
}

struct syscall_sync_file_range_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__sync_file_range_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__sync_file_range_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_sync_file_range_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_sync_file_range_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_sync_file_range_event_t), 0);
    return 0;
}

struct syscall_syncfs_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__syncfs_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__syncfs_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_syncfs_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_syncfs_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_syncfs_event_t), 0);
    return 0;
}

struct syscall_writev_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int syscall__writev_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int syscall__writev_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct syscall_writev_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = syscall_writev_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct syscall_writev_event_t), 0);
    return 0;
}

struct os_cache_do_page_cache_ra_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int os_cache__do_page_cache_ra_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int os_cache__do_page_cache_ra_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct os_cache_do_page_cache_ra_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = os_cache_do_page_cache_ra_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct os_cache_do_page_cache_ra_event_t), 0);
    return 0;
}

struct os_cache_add_to_page_cache_lru_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int os_cache__add_to_page_cache_lru_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int os_cache__add_to_page_cache_lru_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct os_cache_add_to_page_cache_lru_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = os_cache_add_to_page_cache_lru_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct os_cache_add_to_page_cache_lru_event_t), 0);
    return 0;
}

struct os_cache_mark_buffer_dirty_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int os_cache__mark_buffer_dirty_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int os_cache__mark_buffer_dirty_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct os_cache_mark_buffer_dirty_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = os_cache_mark_buffer_dirty_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct os_cache_mark_buffer_dirty_event_t), 0);
    return 0;
}

struct os_cache_account_page_dirtied_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int os_cache__account_page_dirtied_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int os_cache__account_page_dirtied_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct os_cache_account_page_dirtied_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = os_cache_account_page_dirtied_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct os_cache_account_page_dirtied_event_t), 0);
    return 0;
}

struct os_cache_mark_page_accessed_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int os_cache__mark_page_accessed_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int os_cache__mark_page_accessed_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct os_cache_mark_page_accessed_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = os_cache_mark_page_accessed_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct os_cache_mark_page_accessed_event_t), 0);
    return 0;
}

struct os_cache___page_cache_alloc_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int os_cache____page_cache_alloc_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int os_cache____page_cache_alloc_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct os_cache___page_cache_alloc_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = os_cache___page_cache_alloc_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct os_cache___page_cache_alloc_event_t), 0);
    return 0;
}

struct ext4_ext4_write_end_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__ext4_write_end_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__ext4_write_end_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_ext4_write_end_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_ext4_write_end_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_ext4_write_end_event_t), 0);
    return 0;
}

struct ext4_ext4_writepages_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__ext4_writepages_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__ext4_writepages_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_ext4_writepages_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_ext4_writepages_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_ext4_writepages_event_t), 0);
    return 0;
}

struct ext4_ext4_sync_fs_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__ext4_sync_fs_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__ext4_sync_fs_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_ext4_sync_fs_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_ext4_sync_fs_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_ext4_sync_fs_event_t), 0);
    return 0;
}

struct ext4_ext4_zero_range_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__ext4_zero_range_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__ext4_zero_range_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_ext4_zero_range_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_ext4_zero_range_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_ext4_zero_range_event_t), 0);
    return 0;
}

struct ext4_ext4_remove_blocks_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__ext4_remove_blocks_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__ext4_remove_blocks_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_ext4_remove_blocks_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_ext4_remove_blocks_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_ext4_remove_blocks_event_t), 0);
    return 0;
}

struct ext4_ext4_truncate_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__ext4_truncate_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__ext4_truncate_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_ext4_truncate_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_ext4_truncate_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_ext4_truncate_event_t), 0);
    return 0;
}

struct ext4_ext4_write_begin_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__ext4_write_begin_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__ext4_write_begin_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_ext4_write_begin_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_ext4_write_begin_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_ext4_write_begin_event_t), 0);
    return 0;
}

struct ext4_ext4_writepage_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__ext4_writepage_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__ext4_writepage_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_ext4_writepage_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_ext4_writepage_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_ext4_writepage_event_t), 0);
    return 0;
}

struct ext4_ext4_da_write_end_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__ext4_da_write_end_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__ext4_da_write_end_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_ext4_da_write_end_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_ext4_da_write_end_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_ext4_da_write_end_event_t), 0);
    return 0;
}

struct ext4_ext4_discard_preallocations_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__ext4_discard_preallocations_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__ext4_discard_preallocations_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_ext4_discard_preallocations_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_ext4_discard_preallocations_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_ext4_discard_preallocations_event_t), 0);
    return 0;
}

struct ext4_ext4_fallocate_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__ext4_fallocate_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__ext4_fallocate_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_ext4_fallocate_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_ext4_fallocate_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_ext4_fallocate_event_t), 0);
    return 0;
}

struct ext4_ext4_free_blocks_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__ext4_free_blocks_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__ext4_free_blocks_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_ext4_free_blocks_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_ext4_free_blocks_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_ext4_free_blocks_event_t), 0);
    return 0;
}

struct ext4_ext4_readpage_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__ext4_readpage_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__ext4_readpage_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_ext4_readpage_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_ext4_readpage_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_ext4_readpage_event_t), 0);
    return 0;
}

struct ext4_ext4_da_write_begin_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__ext4_da_write_begin_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__ext4_da_write_begin_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_ext4_da_write_begin_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_ext4_da_write_begin_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_ext4_da_write_begin_event_t), 0);
    return 0;
}

struct ext4_ext4_file_open_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__ext4_file_open_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__ext4_file_open_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_ext4_file_open_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_ext4_file_open_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_ext4_file_open_event_t), 0);
    return 0;
}

struct ext4_ext4_da_reserve_space_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__ext4_da_reserve_space_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__ext4_da_reserve_space_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_ext4_da_reserve_space_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_ext4_da_reserve_space_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_ext4_da_reserve_space_event_t), 0);
    return 0;
}

struct ext4_ext4_file_write_iter_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__ext4_file_write_iter_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__ext4_file_write_iter_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_ext4_file_write_iter_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_ext4_file_write_iter_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_ext4_file_write_iter_event_t), 0);
    return 0;
}

struct ext4_ext4_da_release_space_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__ext4_da_release_space_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__ext4_da_release_space_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_ext4_da_release_space_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_ext4_da_release_space_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_ext4_da_release_space_event_t), 0);
    return 0;
}

struct ext4_ext4_alloc_da_blocks_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__ext4_alloc_da_blocks_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__ext4_alloc_da_blocks_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_ext4_alloc_da_blocks_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_ext4_alloc_da_blocks_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_ext4_alloc_da_blocks_event_t), 0);
    return 0;
}

struct ext4_ext4_sync_file_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__ext4_sync_file_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__ext4_sync_file_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_ext4_sync_file_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_ext4_sync_file_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_ext4_sync_file_event_t), 0);
    return 0;
}

struct ext4_vfs_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int ext4__vfs_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int ext4__vfs_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct ext4_vfs_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = ext4_vfs_type;
    
    //event.stack_id = stack_traces.get_stackid(ctx, 0);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct ext4_vfs_event_t), 0);
    return 0;
}

struct c_shm_unlink_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__shm_unlink_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__shm_unlink_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_shm_unlink_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_shm_unlink_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_shm_unlink_event_t), 0);
    return 0;
}

struct c_fdatasync_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__fdatasync_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__fdatasync_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_fdatasync_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_fdatasync_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_fdatasync_event_t), 0);
    return 0;
}

struct c_fileno_unlocked_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__fileno_unlocked_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__fileno_unlocked_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_fileno_unlocked_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_fileno_unlocked_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_fileno_unlocked_event_t), 0);
    return 0;
}

struct c_read_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__read_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__read_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_read_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_read_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_read_event_t), 0);
    return 0;
}

struct c_posix_memalign_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__posix_memalign_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__posix_memalign_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_posix_memalign_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_posix_memalign_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_posix_memalign_event_t), 0);
    return 0;
}

struct c_munmap_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__munmap_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__munmap_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_munmap_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_munmap_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_munmap_event_t), 0);
    return 0;
}

struct c_memfd_create_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__memfd_create_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__memfd_create_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_memfd_create_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_memfd_create_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_memfd_create_event_t), 0);
    return 0;
}

struct c_memalign_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__memalign_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__memalign_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_memalign_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_memalign_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_memalign_event_t), 0);
    return 0;
}

struct c_fileno_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__fileno_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__fileno_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_fileno_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_fileno_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_fileno_event_t), 0);
    return 0;
}

struct c_shm_open_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__shm_open_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__shm_open_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_shm_open_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_shm_open_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_shm_open_event_t), 0);
    return 0;
}

struct c_realloc_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__realloc_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__realloc_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_realloc_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_realloc_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_realloc_event_t), 0);
    return 0;
}

struct c_mmap_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__mmap_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__mmap_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_mmap_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_mmap_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_mmap_event_t), 0);
    return 0;
}

struct c_valloc_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__valloc_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__valloc_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_valloc_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_valloc_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_valloc_event_t), 0);
    return 0;
}

struct c_msync_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__msync_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__msync_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_msync_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_msync_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_msync_event_t), 0);
    return 0;
}

struct c_pvalloc_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__pvalloc_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__pvalloc_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_pvalloc_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_pvalloc_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_pvalloc_event_t), 0);
    return 0;
}

struct c_malloc_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__malloc_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__malloc_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_malloc_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_malloc_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_malloc_event_t), 0);
    return 0;
}

struct c_fdopen_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__fdopen_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__fdopen_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_fdopen_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_fdopen_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_fdopen_event_t), 0);
    return 0;
}

struct c_mremap_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__mremap_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__mremap_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_mremap_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_mremap_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_mremap_event_t), 0);
    return 0;
}

struct c_fcntl_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__fcntl_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__fcntl_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_fcntl_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_fcntl_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_fcntl_event_t), 0);
    return 0;
}

struct c_fsync_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__fsync_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__fsync_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_fsync_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_fsync_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_fsync_event_t), 0);
    return 0;
}

struct c_madvise_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__madvise_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__madvise_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_madvise_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_madvise_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_madvise_event_t), 0);
    return 0;
}

struct c_aligned_alloc_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__aligned_alloc_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__aligned_alloc_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_aligned_alloc_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_aligned_alloc_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_aligned_alloc_event_t), 0);
    return 0;
}

struct c_free_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__free_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__free_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_free_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_free_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_free_event_t), 0);
    return 0;
}

struct c_pread64_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__pread64_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__pread64_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_pread64_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_pread64_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_pread64_event_t), 0);
    return 0;
}

struct c_creat_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__creat_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__creat_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_creat_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_creat_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_creat_event_t), 0);
    return 0;
}

struct c_creat64_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__creat64_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__creat64_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_creat64_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_creat64_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_creat64_event_t), 0);
    return 0;
}

struct c_close_range_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__close_range_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__close_range_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_close_range_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_close_range_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_close_range_event_t), 0);
    return 0;
}

struct c_closefrom_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__closefrom_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__closefrom_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_closefrom_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_closefrom_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_closefrom_event_t), 0);
    return 0;
}

struct c_open_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__open_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__open_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_open_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_open_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_open_event_t), 0);
    return 0;
}

struct c_close_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__close_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__close_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_close_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_close_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_close_event_t), 0);
    return 0;
}

struct c_open64_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__open64_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__open64_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_open64_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_open64_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_open64_event_t), 0);
    return 0;
}

struct c_calloc_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__calloc_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__calloc_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_calloc_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_calloc_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_calloc_event_t), 0);
    return 0;
}

struct c_pread_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int c__pread_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int c__pread_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct c_pread_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = c_pread_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct c_pread_event_t), 0);
    return 0;
}

struct mpi_MPI_Wait_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Wait_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Wait_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Wait_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Wait_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Wait_event_t), 0);
    return 0;
}

struct mpi_MPI_Send_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Send_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Send_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Send_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Send_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Send_event_t), 0);
    return 0;
}

struct mpi_MPI_Recv_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Recv_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Recv_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Recv_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Recv_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Recv_event_t), 0);
    return 0;
}

struct mpi_MPI_Sendrecv_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Sendrecv_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Sendrecv_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Sendrecv_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Sendrecv_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Sendrecv_event_t), 0);
    return 0;
}

struct mpi_MPI_Isend_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Isend_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Isend_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Isend_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Isend_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Isend_event_t), 0);
    return 0;
}

struct mpi_MPI_Irecv_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Irecv_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Irecv_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Irecv_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Irecv_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Irecv_event_t), 0);
    return 0;
}

struct mpi_MPI_Waitall_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Waitall_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Waitall_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Waitall_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Waitall_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Waitall_event_t), 0);
    return 0;
}

struct mpi_MPI_Waitsome_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Waitsome_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Waitsome_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Waitsome_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Waitsome_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Waitsome_event_t), 0);
    return 0;
}

struct mpi_MPI_Finalize_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Finalize_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Finalize_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Finalize_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Finalize_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Finalize_event_t), 0);
    return 0;
}

struct mpi_MPI_Waitany_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Waitany_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Waitany_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Waitany_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Waitany_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Waitany_event_t), 0);
    return 0;
}

struct mpi_MPI_Ssend_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Ssend_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Ssend_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Ssend_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Ssend_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Ssend_event_t), 0);
    return 0;
}

struct mpi_MPI_Comm_split_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Comm_split_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Comm_split_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Comm_split_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Comm_split_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Comm_split_event_t), 0);
    return 0;
}

struct mpi_MPI_Comm_dup_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Comm_dup_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Comm_dup_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Comm_dup_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Comm_dup_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Comm_dup_event_t), 0);
    return 0;
}

struct mpi_MPI_Init_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Init_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Init_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Init_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Init_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Init_event_t), 0);
    return 0;
}

struct mpi_MPI_Comm_create_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Comm_create_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Comm_create_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Comm_create_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Comm_create_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Comm_create_event_t), 0);
    return 0;
}

struct mpi_MPI_File_seek_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_seek_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_seek_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_seek_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_seek_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_seek_event_t), 0);
    return 0;
}

struct mpi_MPI_File_write_ordered_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_write_ordered_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_write_ordered_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_write_ordered_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_write_ordered_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_write_ordered_event_t), 0);
    return 0;
}

struct mpi_MPI_File_seek_shared_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_seek_shared_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_seek_shared_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_seek_shared_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_seek_shared_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_seek_shared_event_t), 0);
    return 0;
}

struct mpi_MPI_File_write_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_write_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_write_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_write_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_write_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_write_event_t), 0);
    return 0;
}

struct mpi_MPI_Ibcast_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Ibcast_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Ibcast_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Ibcast_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Ibcast_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Ibcast_event_t), 0);
    return 0;
}

struct mpi_MPI_Test_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Test_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Test_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Test_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Test_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Test_event_t), 0);
    return 0;
}

struct mpi_MPI_Testall_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Testall_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Testall_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Testall_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Testall_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Testall_event_t), 0);
    return 0;
}

struct mpi_MPI_Testsome_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Testsome_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Testsome_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Testsome_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Testsome_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Testsome_event_t), 0);
    return 0;
}

struct mpi_MPI_Testany_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Testany_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Testany_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Testany_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Testany_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Testany_event_t), 0);
    return 0;
}

struct mpi_MPI_Ireduce_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Ireduce_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Ireduce_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Ireduce_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Ireduce_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Ireduce_event_t), 0);
    return 0;
}

struct mpi_MPI_Igather_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Igather_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Igather_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Igather_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Igather_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Igather_event_t), 0);
    return 0;
}

struct mpi_MPI_File_read_shared_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_read_shared_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_read_shared_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_read_shared_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_read_shared_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_read_shared_event_t), 0);
    return 0;
}

struct mpi_MPI_Iscatter_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Iscatter_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Iscatter_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Iscatter_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Iscatter_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Iscatter_event_t), 0);
    return 0;
}

struct mpi_MPI_Ialltoall_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Ialltoall_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Ialltoall_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Ialltoall_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Ialltoall_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Ialltoall_event_t), 0);
    return 0;
}

struct mpi_MPI_Comm_free_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Comm_free_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Comm_free_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Comm_free_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Comm_free_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Comm_free_event_t), 0);
    return 0;
}

struct mpi_MPI_File_read_at_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_read_at_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_read_at_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_read_at_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_read_at_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_read_at_event_t), 0);
    return 0;
}

struct mpi_MPI_Cart_sub_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Cart_sub_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Cart_sub_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Cart_sub_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Cart_sub_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Cart_sub_event_t), 0);
    return 0;
}

struct mpi_MPI_File_read_all_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_read_all_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_read_all_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_read_all_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_read_all_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_read_all_event_t), 0);
    return 0;
}

struct mpi_MPI_Comm_split_type_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Comm_split_type_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Comm_split_type_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Comm_split_type_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Comm_split_type_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Comm_split_type_event_t), 0);
    return 0;
}

struct mpi_MPI_File_read_all_begin_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_read_all_begin_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_read_all_begin_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_read_all_begin_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_read_all_begin_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_read_all_begin_event_t), 0);
    return 0;
}

struct mpi_MPI_File_open_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_open_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_open_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_open_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_open_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_open_event_t), 0);
    return 0;
}

struct mpi_MPI_File_iwrite_shared_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_iwrite_shared_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_iwrite_shared_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_iwrite_shared_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_iwrite_shared_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_iwrite_shared_event_t), 0);
    return 0;
}

struct mpi_MPI_File_iwrite_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_iwrite_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_iwrite_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_iwrite_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_iwrite_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_iwrite_event_t), 0);
    return 0;
}

struct mpi_MPI_File_set_size_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_set_size_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_set_size_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_set_size_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_set_size_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_set_size_event_t), 0);
    return 0;
}

struct mpi_MPI_File_iwrite_at_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_iwrite_at_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_iwrite_at_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_iwrite_at_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_iwrite_at_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_iwrite_at_event_t), 0);
    return 0;
}

struct mpi_MPI_File_iread_shared_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_iread_shared_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_iread_shared_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_iread_shared_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_iread_shared_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_iread_shared_event_t), 0);
    return 0;
}

struct mpi_MPI_File_iread_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_iread_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_iread_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_iread_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_iread_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_iread_event_t), 0);
    return 0;
}

struct mpi_MPI_File_iread_at_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_iread_at_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_iread_at_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_iread_at_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_iread_at_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_iread_at_event_t), 0);
    return 0;
}

struct mpi_MPI_Finalized_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Finalized_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Finalized_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Finalized_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Finalized_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Finalized_event_t), 0);
    return 0;
}

struct mpi_MPI_File_write_shared_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_write_shared_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_write_shared_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_write_shared_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_write_shared_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_write_shared_event_t), 0);
    return 0;
}

struct mpi_MPI_File_write_ordered_begin_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_write_ordered_begin_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_write_ordered_begin_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_write_ordered_begin_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_write_ordered_begin_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_write_ordered_begin_event_t), 0);
    return 0;
}

struct mpi_MPI_File_write_at_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_write_at_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_write_at_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_write_at_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_write_at_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_write_at_event_t), 0);
    return 0;
}

struct mpi_MPI_File_sync_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_sync_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_sync_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_sync_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_sync_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_sync_event_t), 0);
    return 0;
}

struct mpi_MPI_File_set_view_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_set_view_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_set_view_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_set_view_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_set_view_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_set_view_event_t), 0);
    return 0;
}

struct mpi_MPI_File_read_ordered_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_read_ordered_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_read_ordered_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_read_ordered_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_read_ordered_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_read_ordered_event_t), 0);
    return 0;
}

struct mpi_MPI_File_read_ordered_begin_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_read_ordered_begin_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_read_ordered_begin_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_read_ordered_begin_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_read_ordered_begin_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_read_ordered_begin_event_t), 0);
    return 0;
}

struct mpi_MPI_File_read_at_all_begin_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_read_at_all_begin_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_read_at_all_begin_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_read_at_all_begin_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_read_at_all_begin_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_read_at_all_begin_event_t), 0);
    return 0;
}

struct mpi_MPI_File_read_at_all_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_read_at_all_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_read_at_all_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_read_at_all_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_read_at_all_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_read_at_all_event_t), 0);
    return 0;
}

struct mpi_MPI_Init_thread_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Init_thread_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Init_thread_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Init_thread_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Init_thread_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Init_thread_event_t), 0);
    return 0;
}

struct mpi_MPI_Gather_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Gather_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Gather_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Gather_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Gather_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Gather_event_t), 0);
    return 0;
}

struct mpi_MPI_Bcast_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Bcast_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Bcast_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Bcast_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Bcast_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Bcast_event_t), 0);
    return 0;
}

struct mpi_MPI_Barrier_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Barrier_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Barrier_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Barrier_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Barrier_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Barrier_event_t), 0);
    return 0;
}

struct mpi_MPI_Comm_set_errhandler_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Comm_set_errhandler_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Comm_set_errhandler_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Comm_set_errhandler_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Comm_set_errhandler_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Comm_set_errhandler_event_t), 0);
    return 0;
}

struct mpi_MPI_Get_processor_name_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Get_processor_name_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Get_processor_name_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Get_processor_name_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Get_processor_name_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Get_processor_name_event_t), 0);
    return 0;
}

struct mpi_MPI_Comm_size_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Comm_size_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Comm_size_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Comm_size_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Comm_size_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Comm_size_event_t), 0);
    return 0;
}

struct mpi_MPI_Comm_rank_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Comm_rank_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Comm_rank_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Comm_rank_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Comm_rank_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Comm_rank_event_t), 0);
    return 0;
}

struct mpi_MPI_File_write_at_all_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_write_at_all_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_write_at_all_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_write_at_all_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_write_at_all_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_write_at_all_event_t), 0);
    return 0;
}

struct mpi_MPI_File_write_at_all_begin_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_write_at_all_begin_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_write_at_all_begin_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_write_at_all_begin_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_write_at_all_begin_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_write_at_all_begin_event_t), 0);
    return 0;
}

struct mpi_MPI_File_write_all_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_write_all_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_write_all_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_write_all_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_write_all_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_write_all_event_t), 0);
    return 0;
}

struct mpi_MPI_File_write_all_begin_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_write_all_begin_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_write_all_begin_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_write_all_begin_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_write_all_begin_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_write_all_begin_event_t), 0);
    return 0;
}

struct mpi_MPI_File_read_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_read_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_read_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_read_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_read_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_read_event_t), 0);
    return 0;
}

struct mpi_MPI_Gatherv_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Gatherv_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Gatherv_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Gatherv_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Gatherv_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Gatherv_event_t), 0);
    return 0;
}

struct mpi_MPI_Scatterv_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Scatterv_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Scatterv_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Scatterv_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Scatterv_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Scatterv_event_t), 0);
    return 0;
}

struct mpi_MPI_Allgather_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Allgather_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Allgather_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Allgather_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Allgather_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Allgather_event_t), 0);
    return 0;
}

struct mpi_MPI_Allgatherv_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Allgatherv_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Allgatherv_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Allgatherv_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Allgatherv_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Allgatherv_event_t), 0);
    return 0;
}

struct mpi_MPI_Alltoall_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Alltoall_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Alltoall_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Alltoall_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Alltoall_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Alltoall_event_t), 0);
    return 0;
}

struct mpi_MPI_Reduce_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Reduce_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Reduce_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Reduce_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Reduce_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Reduce_event_t), 0);
    return 0;
}

struct mpi_MPI_Allreduce_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Allreduce_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Allreduce_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Allreduce_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Allreduce_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Allreduce_event_t), 0);
    return 0;
}

struct mpi_MPI_Reduce_scatter_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Reduce_scatter_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Reduce_scatter_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Reduce_scatter_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Reduce_scatter_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Reduce_scatter_event_t), 0);
    return 0;
}

struct mpi_MPI_Scan_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Scan_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Scan_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Scan_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Scan_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Scan_event_t), 0);
    return 0;
}

struct mpi_MPI_Type_commit_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Type_commit_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Type_commit_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Type_commit_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Type_commit_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Type_commit_event_t), 0);
    return 0;
}

struct mpi_MPI_Type_create_darray_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Type_create_darray_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Type_create_darray_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Type_create_darray_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Type_create_darray_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Type_create_darray_event_t), 0);
    return 0;
}

struct mpi_MPI_File_get_size_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_File_get_size_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_File_get_size_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_File_get_size_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_File_get_size_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_File_get_size_event_t), 0);
    return 0;
}

struct mpi_MPI_Cart_rank_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Cart_rank_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Cart_rank_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Cart_rank_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Cart_rank_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Cart_rank_event_t), 0);
    return 0;
}

struct mpi_MPI_Cart_create_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Cart_create_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Cart_create_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Cart_create_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Cart_create_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Cart_create_event_t), 0);
    return 0;
}

struct mpi_MPI_Cart_get_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Cart_get_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Cart_get_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Cart_get_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Cart_get_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Cart_get_event_t), 0);
    return 0;
}

struct mpi_MPI_Cart_shift_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int mpi__MPI_Cart_shift_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int mpi__MPI_Cart_shift_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct mpi_MPI_Cart_shift_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = mpi_MPI_Cart_shift_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct mpi_MPI_Cart_shift_event_t), 0);
    return 0;
}

struct df_tracer_test__Z10gen_randomB5cxx11i_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int df_tracer_test___Z10gen_randomB5cxx11i_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int df_tracer_test___Z10gen_randomB5cxx11i_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct df_tracer_test__Z10gen_randomB5cxx11i_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = df_tracer_test__Z10gen_randomB5cxx11i_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct df_tracer_test__Z10gen_randomB5cxx11i_event_t), 0);
    return 0;
}

struct df_tracer_test__fini_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int df_tracer_test___fini_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int df_tracer_test___fini_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct df_tracer_test__fini_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = df_tracer_test__fini_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct df_tracer_test__fini_event_t), 0);
    return 0;
}

struct df_tracer_test__init_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int df_tracer_test___init_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int df_tracer_test___init_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct df_tracer_test__init_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = df_tracer_test__init_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct df_tracer_test__init_event_t), 0);
    return 0;
}

struct df_tracer_test__start_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int df_tracer_test___start_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int df_tracer_test___start_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct df_tracer_test__start_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = df_tracer_test__start_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct df_tracer_test__start_event_t), 0);
    return 0;
}

struct df_tracer_test_main_event_t {
    enum event_type_t name;
    u64 id;                                                                    
    u64 start_time;
    u64 duration;
    //int stack_id;
    char process[16];
    
};



int df_tracer_test__main_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    if (is_traced(&pid) == 0) return 0;
    
    u64 start_time = bpf_ktime_get_ns();
    start_time_map.update(&id, &start_time);
    return 0;
}

int df_tracer_test__main_exit(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64* app_start_time = is_traced(&pid);
    if (app_start_time == 0) return 0;
    u64* start_time = start_time_map.lookup(&id);
    if (start_time == 0) return 0;
    struct df_tracer_test_main_event_t event = {};
    event.id = id;
    event.start_time = (*start_time - *app_start_time) / 1000;
    event.duration = (end_time - *start_time) / 1000;
    event.name = df_tracer_test_main_type;
    
   // event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    
    bpf_get_current_comm(&event.process, sizeof(event.process));
    events.ringbuf_output(&event, sizeof(struct df_tracer_test_main_event_t), 0);
    return 0;
}
