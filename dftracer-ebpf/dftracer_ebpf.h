#ifndef DFTRACER_EBPF_PRELOAD_H
#define DFTRACER_EBPF_PRELOAD_H
__attribute__((visibility("default"))) extern int dftracer_get_pid();

__attribute__((visibility("default"))) extern int dftracer_remove_pid();

extern void __attribute__((constructor)) dftracer_ebpf_init(void);

extern void __attribute__((destructor)) dftracer_ebpf_fini(void);

#endif // DFTRACER_EBPF_PRELOAD_H