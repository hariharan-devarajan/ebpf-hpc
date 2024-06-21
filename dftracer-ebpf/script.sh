#!/bin/bash
pushd build
echo "comm_size,trace,ops,ts,open,close,write"

for trace in 0 1; do
  if [[ "$trace" == "0" ]]; then
    PRELOAD=""
  else    
    PRELOAD="-env LD_PRELOAD $PWD/libdftracer_ebpf.so"
  fi
  for procs in 1 2 4; do
    for ts in 1 $((4*1024)) $((16*1024)) $((64*1024)) $((256*1024)); do
    
        rm -rf file*.dat
        mpirun -n $procs ${PRELOAD} ./test 128 128 $ts $PWD $trace
    done
  done
done
popd
