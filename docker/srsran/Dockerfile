FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    pkg-config \
    libsctp-dev \
    lksctp-tools \
    libfftw3-dev \
    libmbedtls-dev \
    libboost-program-options-dev \
    libconfig++-dev \
    libuhd-dev \
    libzmq3-dev \
    libczmq-dev \
    libpcsclite-dev \
    libusb-1.0-0-dev \
    libgtest-dev \
    libyaml-cpp-dev \
    iproute2 \
    iputils-ping \
    net-tools \
    tcpdump \
    tshark \
    vim \
    nano \
    ca-certificates

WORKDIR /work

COPY src/srsran /work/srsran

WORKDIR /work/srsran

RUN mkdir -p build

WORKDIR /work/srsran/build

RUN cmake .. \
    -DENABLE_ZEROMQ=ON \
    -DCMAKE_BUILD_TYPE=Release

RUN make -j$(nproc)

RUN make install

RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/srsran.conf

RUN ldconfig

WORKDIR /

CMD ["bash"]