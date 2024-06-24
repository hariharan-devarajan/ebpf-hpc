FROM ubuntu:latest

RUN apt-get update
RUN apt-get install -y apt-transport-https ca-certificates curl clang llvm jq \
    libelf-dev libpcap-dev libbfd-dev binutils-dev build-essential make \
    linux-tools-common linux-tools-$(uname -r) \
    bpfcc-tools python3-pip python3.10-venv