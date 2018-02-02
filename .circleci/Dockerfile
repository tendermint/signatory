FROM debian:stretch

RUN apt-get update && \
    apt-get install -y curl file gcc g++ git make openssh-client \
    autoconf automake cmake libtool libcurl4-openssl-dev libssl-dev \
    libelf-dev libdw-dev binutils-dev zlib1g-dev libiberty-dev wget \
    xz-utils pkg-config python libclang-3.8 libclang-3.8-dev

ENV YUBIHSM2_SDK_VERSION 1.0.1-debian9-amd64
RUN wget https://developers.yubico.com/YubiHSM2/Releases/yubihsm2-sdk-$YUBIHSM2_SDK_VERSION.tar.gz && \
    tar zxf yubihsm2-sdk-$YUBIHSM2_SDK_VERSION.tar.gz && \
    rm yubihsm2-sdk-$YUBIHSM2_SDK_VERSION.tar.gz && \
    dpkg -i yubihsm2-sdk/libyubihsm*.deb && \
    rm -r yubihsm2-sdk

ENV KCOV_VERSION 33
RUN wget https://github.com/SimonKagstrom/kcov/archive/v$KCOV_VERSION.tar.gz && \
    tar xzf v$KCOV_VERSION.tar.gz && \
    rm v$KCOV_VERSION.tar.gz && \
    cd kcov-$KCOV_VERSION && \
    mkdir build && cd build && \
    cmake .. && make && make install && \
    cd ../.. && rm -rf kcov-$KCOV_VERSION

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

ENV PATH "$PATH:/root/.cargo/bin"
ENV RUSTFLAGS "-C link-dead-code"
ENV CFG_RELEASE_CHANNEL "nightly"

RUN rustup update && \
    rustup install nightly && \
    rustup default nightly && \
    cargo install rustfmt-nightly --vers 0.3.7 --force

RUN bash -l -c 'echo $(rustc --print sysroot)/lib >> /etc/ld.so.conf'
RUN bash -l -c 'echo /usr/local/lib >> /etc/ld.so.conf'
RUN ldconfig
