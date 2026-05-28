FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libdpdk-dev \
        dpdk \
        dpdk-dev \
        clang \
        libclang-dev \
        llvm-dev \
        libnuma-dev \
        python3 \
        python3-pyelftools \
        ca-certificates \
        curl \
        git \
        gdb \
        sudo \
        kmod \
        pciutils \
        iproute2 \
        ethtool \
    && rm -rf /var/lib/apt/lists/*

ARG RUST_TOOLCHAIN=stable
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain ${RUST_TOOLCHAIN} --profile minimal \
            --component rustfmt --component clippy --component rust-analyzer
ENV PATH=/root/.cargo/bin:${PATH}
ENV LIBCLANG_PATH=/usr/lib/llvm-18/lib

WORKDIR /workspaces/quicktcp
