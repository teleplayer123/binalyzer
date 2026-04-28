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

# Download cl100k_base tiktoken to store locally
RUN mkdir -p /home/analyst/tiktoken_cache
RUN wget -P /home/analyst/tiktoken_cache "https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken"
# expected hash: 223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7
# Create env variable to point to tiktoken
RUN echo export TIKTOKEN_CACHE_DIR=/home/analyst/tiktoken_cache >> /home/analyst/.bashrc


# Setup directories
RUN mkdir -p /home/analyst/target /home/analyst/db /home/analyst/logs
# Copy xz binary for testing
RUN cp $(which xz) /home/analyst/target/xz.bin

CMD ["bash"]
