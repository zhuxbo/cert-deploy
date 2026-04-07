# Nginx E2E 测试容器
# 用法: docker build --build-arg DISTRO=ubuntu -t test-nginx docker/test/nginx/
# 支持: ubuntu, debian, alpine, rocky
ARG DISTRO=ubuntu

# ============================================================
# Ubuntu
# ============================================================
FROM ubuntu:24.04 AS base-ubuntu
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx openssl curl jq ca-certificates bash bats socat \
    && rm -rf /var/lib/apt/lists/*
# Ubuntu nginx: sites-enabled 已由默认配置 include
RUN mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled

# ============================================================
# Debian
# ============================================================
FROM debian:12 AS base-debian
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx openssl curl jq ca-certificates bash bats socat \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled

# ============================================================
# Alpine
# ============================================================
FROM alpine:3.21 AS base-alpine
RUN apk add --no-cache \
    nginx openssl curl jq ca-certificates bash bats socat

# ============================================================
# Rocky Linux
# ============================================================
FROM rockylinux:9 AS base-rocky
RUN dnf install -y epel-release && \
    dnf install -y --allowerasing nginx openssl curl jq ca-certificates bash git socat && \
    dnf clean all
# Rocky: 从源码安装 bats
RUN git clone --depth 1 https://github.com/bats-core/bats-core.git /tmp/bats-core && \
    /tmp/bats-core/install.sh /usr/local && \
    rm -rf /tmp/bats-core

# ============================================================
# 最终阶段
# ============================================================
FROM base-${DISTRO} AS final

# 创建所需目录
RUN mkdir -p \
    /etc/nginx/ssl \
    /etc/nginx/sites-available \
    /etc/nginx/sites-enabled \
    /etc/nginx/conf.d \
    /opt/sslctl/sites \
    /opt/sslctl/logs \
    /opt/sslctl/backup \
    /opt/sslctl/certs \
    /var/www/html

# 生成自签名证书
RUN openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/default.key \
    -out /etc/nginx/ssl/default.crt \
    -subj "/CN=test.example.com"

# 创建 SSL 站点配置
RUN printf 'server {\n\
    listen 443 ssl;\n\
    server_name test.example.com;\n\
    ssl_certificate /etc/nginx/ssl/default.crt;\n\
    ssl_certificate_key /etc/nginx/ssl/default.key;\n\
    root /var/www/html;\n\
    location / { return 200 "Hello from E2E Test"; add_header Content-Type text/plain; }\n\
}\n' > /etc/nginx/sites-available/test.example.com.conf

# 启用站点：sites-enabled 符号链接 + conf.d/http.d 复制（覆盖所有发行版差异）
# Alpine nginx 的 conf.d/ 在顶层 include（非 http{} 内），server{} 需放入 http.d/
RUN ln -sf /etc/nginx/sites-available/test.example.com.conf /etc/nginx/sites-enabled/test.example.com.conf 2>/dev/null; \
    if [ -d /etc/nginx/http.d ]; then \
        cp /etc/nginx/sites-available/test.example.com.conf /etc/nginx/http.d/test.example.com.conf; \
    else \
        cp /etc/nginx/sites-available/test.example.com.conf /etc/nginx/conf.d/test.example.com.conf; \
    fi; \
    true

WORKDIR /opt/sslctl
CMD ["tail", "-f", "/dev/null"]
