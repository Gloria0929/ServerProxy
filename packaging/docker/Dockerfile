# ServerProxy 容器镜像：多阶段构建（sing-box 内核 + Go 控制面）。
# 不锁定 #syntax 指令，避免构建环境额外拉取 dockerfile 前端镜像。

# ---- 1) 内核：复用官方 sing-box 镜像，直接取二进制 ----
FROM ghcr.io/sagernet/sing-box:latest AS kernel

# ---- 2) 构建：编译控制面（前端产物已随 go:embed 提交于仓库） ----
FROM golang:1.27-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sp ./cmd/sp

# ---- 3) 运行：最小镜像 + 证书/时区 ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /out/sp /usr/local/bin/sp
COPY --from=kernel /usr/local/bin/sing-box /usr/local/bin/sing-box

ENV SP_DATA_DIR=/var/lib/serverproxy
VOLUME ["/var/lib/serverproxy"]
EXPOSE 9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:9090/ || exit 1

# 子命令可覆盖：docker run <image> version / status / check ...
ENTRYPOINT ["/usr/local/bin/sp"]
CMD ["serve", "--listen", "0.0.0.0:9090", "--data-dir", "/var/lib/serverproxy", "--core", "singbox"]