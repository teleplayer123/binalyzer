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
    wget \
    build-essential \
    clang \
    llvm \
    git \
    libtool \
    libtool-bin \
    automake \
    bison \
    libglib2.0-dev \
    radare2 \
    nano \
    vim \
    xz-utils \
    nasm \
    gcc \
    afl++ \
    python3-tiktoken \
    && rm -rf /var/lib/apt/lists/*

# Install specialized analysis libraries
RUN pip3 install --no-cache-dir \
    openai \
    lief \
    capstone \
    pyelftools \
    numpy \
    scipy \
    r2pipe --break-system-packages

RUN useradd -m analyst
USER analyst
WORKDIR /home/analyst

COPY ./src /home/analyst

# Cache tiktoken for offline use
RUN python3 -c "import tiktoken; tiktoken.get_encoding('cl100k_base')"

RUN echo export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 >> /home/analyst/.bashrc

# Setup directories
RUN mkdir -p /home/analyst/target /home/analyst/db /home/analyst/logs /home/analyst/fuzz_in /home/analyst/fuzz_out
# Copy xz binary for testing
RUN cp $(which xz) /home/analyst/target/xz.bin

CMD ["bash"]
