#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main() {
  int fd1;
  char buf[128] = "hello";
  fd1 = open("/Users/hariharandev1/Library/CloudStorage/OneDrive-LLNL/projects/"
             "ebpf-hpc/file.dat",
             O_WRONLY | O_CREAT, 777);
  if (fd1 == -1) {
    perror("File cannot be opened");
    return -1;
  }
  write(fd1, buf, strlen(buf));
  close(fd1);
  return 0;
}