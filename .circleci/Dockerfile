FROM centos:7.4.1708

# Install/update RPMs
RUN yum update -y
RUN yum groupinstall -y "Development Tools"
RUN yum install -y curl libssl-dev python clang libclang-dev

# Install YubiHSM2 SDK
ENV YUBIHSM2_SDK_VERSION 1.0.1-centos7-amd64
RUN curl -O https://developers.yubico.com/YubiHSM2/Releases/yubihsm2-sdk-$YUBIHSM2_SDK_VERSION.tar.gz && \
    tar zxf yubihsm2-sdk-$YUBIHSM2_SDK_VERSION.tar.gz && \
    rm yubihsm2-sdk-$YUBIHSM2_SDK_VERSION.tar.gz && \
    cp -r yubihsm2-sdk/lib/* /usr/local/lib64/ && \
    cp -r yubihsm2-sdk/include/* /usr/local/include/ && \
    rm -r yubihsm2-sdk

ENV PATH "$PATH:/root/.cargo/bin"
ENV RUSTFLAGS "-C link-dead-code"
ENV CFG_RELEASE_CHANNEL "nightly"
ENV RUST_NIGHTLY_VERSION "nightly-2018-02-04"
ENV RUSTFMT_NIGHTLY_VERSION "0.3.7"

# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
RUN rustup update && \
    rustup install $RUST_NIGHTLY_VERSION && \
    rustup default $RUST_NIGHTLY_VERSION

RUN bash -l -c "echo $(rustc --print sysroot)/lib >> /etc/ld.so.conf"
RUN bash -l -c "echo /usr/local/lib >> /etc/ld.so.conf"
RUN ldconfig

RUN cargo install rustfmt-nightly --vers $RUSTFMT_NIGHTLY_VERSION --force
