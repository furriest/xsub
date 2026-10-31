# syntax=docker/dockerfile:1
# xsub в контейнере: подписки, сторож узлов и ядро Xray. Собирается из того же
# исходника, что и релизы, — версия xsub в образе равна тегу сборки.
#
#   docker build -t xsub .
#
# Установка и запуск — через docker compose (см. README и docker-compose.yml).

# ---------- xsub ----------
FROM golang:1.24-alpine AS xsub
WORKDIR /src
COPY go.mod ./
COPY third_party ./third_party/
COPY *.go ./
COPY index.html ./
ARG VERSION=dev
ARG REPO=furriest/xsub
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.defaultRepo=${REPO}" \
      -o /out/xsub .

# ---------- ядро Xray ----------
FROM alpine:3.22 AS xray
ARG XRAY_VERSION=26.10.31
ARG TARGETARCH
RUN apk add --no-cache curl unzip
RUN set -e; \
    mkdir -p /out; \
    case "$TARGETARCH" in \
      amd64) asset=64 ;; \
      arm64) asset=arm64-v8a ;; \
      *) echo "неподдержанная платформа: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-${asset}.zip" -o /tmp/xray.zip; \
    unzip -p /tmp/xray.zip xray > /out/xray; \
    chmod 755 /out/xray; \
    /out/xray version

# ---------- образ ----------
FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=xsub /out/xsub /usr/local/bin/xsub
COPY --from=xray /out/xray /usr/local/bin/xray
COPY docker/xsub-entrypoint docker/xsub-xray-run docker/xsub-xray-restart /usr/local/bin/
RUN chmod 755 /usr/local/bin/xsub-entrypoint /usr/local/bin/xsub-xray-run /usr/local/bin/xsub-xray-restart
ENV XSUB_SERVER=1 \
    XRAY_CONFDIR=/data/xray
VOLUME /data
EXPOSE 1080/tcp 1080/udp 8099/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD wget -qO- http://127.0.0.1:8099/ >/dev/null 2>&1 || exit 1
ENTRYPOINT ["/usr/local/bin/xsub-entrypoint"]
