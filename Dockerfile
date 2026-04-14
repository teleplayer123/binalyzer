FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install core tools, Python, and AFL++ dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    binutils \
    gdb \
    strace \
    ltrace \
    curl \
    build-essential \
    clang \
    llvm \
    git \
    libtool \
    libtool-bin \
    automake \
    bison \
    libglib2.0-dev \
    # AFL++ specific package
    afl++ \
    radare2 \
    nano \
    vim \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Install specialized analysis libraries
RUN pip3 install --no-cache-dir \
    openai \
    lief \
    capstone \
    pyelftools \
    networkx \
    r2pipe --break-system-packages

RUN useradd -m analyst
USER analyst
WORKDIR /home/analyst

COPY ./src /home/analyst

# Setup directories for the fuzzer
RUN mkdir -p /home/analyst/fuzz_in /home/analyst/fuzz_out /home/analyst/target_binaries
RUN cp $(which xz) /home/analyst/target_binaries/xz.bin

CMD ["bash"]
