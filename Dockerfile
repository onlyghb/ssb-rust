FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
ARG SINGBOX_VERSION=1.14.3
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && case "$TARGETARCH" in amd64|arm64) arch="$TARGETARCH";; *) exit 1;; esac \
    && mkdir -p /opt/ssb/data \
    && curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${arch}.tar.gz" \
       | tar -xz -C /opt/ssb/data --strip-components=1 "sing-box-${SINGBOX_VERSION}-linux-${arch}/sing-box" \
    && mv /opt/ssb/data/sing-box /usr/local/bin/sing-box \
    && apt-get purge -y --auto-remove curl && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/ssb /opt/ssb/ssb
WORKDIR /opt/ssb
ENV SSB_DIR=/opt/ssb
ENTRYPOINT ["/opt/ssb/ssb"]
CMD ["run-core"]
