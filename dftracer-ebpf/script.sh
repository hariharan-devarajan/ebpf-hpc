#!/bin/bash
pushd build
echo "iter,comm_size,trace,ops,ts,open,close,write,read"



for procs in 1; do
  for ts in $((4*1024)) $((16*1024)) $((64*1024)) $((256*1024)); do
    for trace in 1; do
        if [[ "$trace" == "0" ]]; then
            PRELOAD=""
            PRELOAD_ENV=""
        else    
            PRELOAD="$PWD/libdftracer_ebpf.so"
            PRELOAD_ENV="-x LD_PRELOAD=$PWD/libdftracer_ebpf.so"
        fi
        for i in {1..25}; do
            echo -n "$i,"
            rm -rf file*.dat
            mpirun -np $procs ${PRELOAD_ENV} ./test 128 128 $ts $PWD $trace
            exit 0
        done
    done
   
  done
done
popd
