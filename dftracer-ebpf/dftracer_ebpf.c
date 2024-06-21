
#include "dftracer_ebpf.h"
__attribute__((visibility("default"))) int dftracer_get_pid() {
  return getpid();
}
__attribute__((visibility("default"))) int dftracer_remove_pid() {
  return getpid();
}

void dftracer_ebpf_init(void) {
  printf("Constructor Loaded");
  dftracer_get_pid();
}

void dftracer_ebpf_fini(void) {
  printf("Desctructor Loaded");
  dftracer_remove_pid();
}