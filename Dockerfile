# syntax=docker/dockerfile:1
# findinfo — Linux 镜像：自带 13 个 GitHub 工具 + 镜像内编译 onepass/ENScan
#
#   docker build -t findinfo:latest .
#   docker run --rm -it --cap-add=NET_RAW --network=host \
#     -v $PWD/config:/opt/findinfo/config \
#     -v findinfo-data:/data findinfo:latest doctor

############ 1) onepass（Rust）
FROM rust:1-slim AS onepass-build
WORKDIR /src
COPY rust/onepass/Cargo.toml rust/onepass/Cargo.lock ./
COPY rust/onepass/src ./src
RUN cargo build --release

############ 2) ENScan_GO（Go；源不可达时跳过，不阻塞镜像）
FROM golang:1.23-slim AS enscan-build
RUN mkdir -p /out
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates >/dev/null \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/mssky9527/ENScan_GO.git /src \
 && cd /src && GOFLAGS=-mod=mod go build -trimpath -ldflags '-s -w' -o /out/enscan . \
 || echo '[docker] enscan 构建跳过（源不可达）：entity 阶段不可用，其余不受影响'

############ 3) 运行时
FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    FINDINFO_HOME=/data

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl unzip ca-certificates libpcap0.8 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/findinfo
COPY . /opt/findinfo

# 12 个 GitHub 工具 -> /usr/local/bin（core.tool 的 PATH 兜底）
RUN bash scripts/setup-linux.sh --prefix /usr/local/bin --no-onepass --no-enscan

COPY --from=onepass-build /src/target/release/onepass /usr/local/bin/onepass
COPY --from=enscan-build /out/ /tmp/enscan-out/
RUN if [ -f /tmp/enscan-out/enscan ]; then install -m 0755 /tmp/enscan-out/enscan /usr/local/bin/enscan; fi \
 && rm -rf /tmp/enscan-out \
 && chmod +x scripts/*.sh \
 && mkdir -p /data

VOLUME ["/data"]
ENTRYPOINT ["python3", "/opt/findinfo/findinfo.py"]
CMD ["--help"]
