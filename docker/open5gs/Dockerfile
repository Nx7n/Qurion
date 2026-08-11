FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    meson \
    ninja-build \
    cmake \
    pkg-config \
    libsctp-dev \
    lksctp-tools \
    libgnutls28-dev \
    libgcrypt20-dev \
    libidn11-dev \
    libidn2-dev \
    libmongoc-dev \
    libbson-dev \
    libyaml-dev \
    libmicrohttpd-dev \
    libcurl4-openssl-dev \
    libssl-dev \
    libtalloc-dev \
    libnghttp2-dev \
    bison \
    flex \
    python3 \
    python3-pip \
    iproute2 \
    iputils-ping \
    net-tools \
    tcpdump \
    tshark \
    vim \
    nano \
    gdb \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY docker/open5gs/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /work

ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash"]