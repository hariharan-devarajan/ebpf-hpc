#include <chrono>
#include <cstdio>
#include <fcntl.h>
#include <mpi.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <unistd.h>

class Timer {
public:
  Timer() : elapsed_time(0) {}
  void resumeTime() { t1 = std::chrono::high_resolution_clock::now(); }
  double pauseTime() {
    auto t2 = std::chrono::high_resolution_clock::now();
    elapsed_time += std::chrono::duration<double>(t2 - t1).count();
    return elapsed_time;
  }
  double getElapsedTime() { return elapsed_time; }

private:
  std::chrono::high_resolution_clock::time_point t1;
  double elapsed_time;
};
std::string gen_random(const int len) {
  static const char alphanum[] = "0123456789"
                                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "abcdefghijklmnopqrstuvwxyz";
  std::string tmp_s;
  tmp_s.reserve(len);

  for (int i = 0; i < len; ++i) {
    tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];
  }

  return tmp_s;
}
int main(int argc, char *argv[]) {
  MPI_Init(&argc, &argv);
  int my_rank, comm_size;
  MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
  MPI_Comm_size(MPI_COMM_WORLD, &comm_size);
  if (argc < 6) {
    fprintf(stderr, "usage test <NUM FILES> <NUM OPS> <TS> <DIR> <IS_TRACE>");
    return -1;
  }
  int files = atoi(argv[1]);
  int ops = atoi(argv[2]);
  int ts = atoi(argv[3]);
  std::string dir = std::string(argv[4]);
  int trace = atoi(argv[5]);
  std::string data = gen_random(ts);
  Timer open_timer = Timer();
  Timer write_timer = Timer();
  Timer close_timer = Timer();
  for (int file_idx = 0; file_idx < files; ++file_idx) {

    std::string filename = dir + "/file_" + std::to_string(file_idx) + ".dat";

    open_timer.resumeTime();
    int fd = open(filename.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 777);
    open_timer.pauseTime();
    for (int op_idx = 0; op_idx < ops; ++op_idx) {
      write_timer.resumeTime();
      write(fd, data.c_str(), ts);
      write_timer.pauseTime();
    }
    close_timer.resumeTime();
    close(fd);
    close_timer.pauseTime();
  }
  double open_time = open_timer.getElapsedTime();
  double total_open_time;
  MPI_Reduce(&open_time, &total_open_time, 1, MPI_DOUBLE, MPI_SUM, 0,
             MPI_COMM_WORLD);
  double close_time = close_timer.getElapsedTime();
  double total_close_time;
  MPI_Reduce(&close_time, &total_close_time, 1, MPI_DOUBLE, MPI_SUM, 0,
             MPI_COMM_WORLD);
  double write_time = write_timer.getElapsedTime();
  double total_write_time;
  MPI_Reduce(&write_time, &total_write_time, 1, MPI_DOUBLE, MPI_SUM, 0,
             MPI_COMM_WORLD);
  if (my_rank == 0) {
    printf("%d,%d,%d,%d,%f,%f,%f\n", comm_size, trace, ops, ts,
           total_open_time / comm_size, total_close_time / comm_size,
           total_write_time / comm_size);
  }
  MPI_Finalize();
  return 0;
}