# Apache E2E 测试容器
# 用法: docker build --build-arg DISTRO=ubuntu -t test-apache docker/test/apache/
# 支持: ubuntu, debian, alpine, rocky
ARG DISTRO=ubuntu

# ============================================================
# Ubuntu
# ============================================================
FROM ubuntu:24.04 AS base-ubuntu
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 openssl curl jq ca-certificates bash bats \
    && rm -rf /var/lib/apt/lists/*
# 启用 SSL 模块和 sites-enabled
RUN a2enmod ssl && mkdir -p /etc/apache2/sites-available /etc/apache2/sites-enabled /etc/apache2/ssl
# 生成自签名证书
RUN openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 \
    -keyout /etc/apache2/ssl/default.key \
    -out /etc/apache2/ssl/default.crt \
    -subj "/CN=test.example.com"
# 创建虚拟主机配置
RUN printf '<VirtualHost *:443>\n\
    ServerName test.example.com\n\
    SSLEngine on\n\
    SSLCertificateFile /etc/apache2/ssl/default.crt\n\
    SSLCertificateKeyFile /etc/apache2/ssl/default.key\n\
    DocumentRoot /var/www/html\n\
</VirtualHost>\n' > /etc/apache2/sites-available/test.example.com.conf
RUN a2ensite test.example.com.conf 2>/dev/null || \
    ln -sf /etc/apache2/sites-available/test.example.com.conf /etc/apache2/sites-enabled/test.example.com.conf

# ============================================================
# Debian
# ============================================================
FROM debian:12 AS base-debian
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 openssl curl jq ca-certificates bash bats \
    && rm -rf /var/lib/apt/lists/*
RUN a2enmod ssl && mkdir -p /etc/apache2/sites-available /etc/apache2/sites-enabled /etc/apache2/ssl
RUN openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 \
    -keyout /etc/apache2/ssl/default.key \
    -out /etc/apache2/ssl/default.crt \
    -subj "/CN=test.example.com"
RUN printf '<VirtualHost *:443>\n\
    ServerName test.example.com\n\
    SSLEngine on\n\
    SSLCertificateFile /etc/apache2/ssl/default.crt\n\
    SSLCertificateKeyFile /etc/apache2/ssl/default.key\n\
    DocumentRoot /var/www/html\n\
</VirtualHost>\n' > /etc/apache2/sites-available/test.example.com.conf
RUN a2ensite test.example.com.conf 2>/dev/null || \
    ln -sf /etc/apache2/sites-available/test.example.com.conf /etc/apache2/sites-enabled/test.example.com.conf

# ============================================================
# Alpine
# ============================================================
FROM alpine:3.21 AS base-alpine
RUN apk add --no-cache \
    apache2 apache2-ssl openssl curl jq ca-certificates bash bats
RUN mkdir -p /etc/apache2/ssl /etc/apache2/conf.d
RUN openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 \
    -keyout /etc/apache2/ssl/default.key \
    -out /etc/apache2/ssl/default.crt \
    -subj "/CN=test.example.com"
RUN printf '<VirtualHost *:443>\n\
    ServerName test.example.com\n\
    SSLEngine on\n\
    SSLCertificateFile /etc/apache2/ssl/default.crt\n\
    SSLCertificateKeyFile /etc/apache2/ssl/default.key\n\
    DocumentRoot /var/www/html\n\
</VirtualHost>\n' > /etc/apache2/conf.d/test.example.com.conf

# ============================================================
# Rocky Linux
# ============================================================
FROM rockylinux:9 AS base-rocky
RUN dnf install -y epel-release && \
    dnf install -y httpd mod_ssl openssl curl jq ca-certificates bash git && \
    dnf clean all
# 从源码安装 bats
RUN git clone --depth 1 https://github.com/bats-core/bats-core.git /tmp/bats-core && \
    /tmp/bats-core/install.sh /usr/local && \
    rm -rf /tmp/bats-core
RUN mkdir -p /etc/httpd/ssl /etc/httpd/conf.d
RUN openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 \
    -keyout /etc/httpd/ssl/default.key \
    -out /etc/httpd/ssl/default.crt \
    -subj "/CN=test.example.com"
RUN printf '<VirtualHost *:443>\n\
    ServerName test.example.com\n\
    SSLEngine on\n\
    SSLCertificateFile /etc/httpd/ssl/default.crt\n\
    SSLCertificateKeyFile /etc/httpd/ssl/default.key\n\
    DocumentRoot /var/www/html\n\
</VirtualHost>\n' > /etc/httpd/conf.d/test.example.com.conf

# ============================================================
# 最终阶段
# ============================================================
FROM base-${DISTRO} AS final

# 创建所需目录
RUN mkdir -p \
    /opt/sslctl/sites \
    /opt/sslctl/logs \
    /opt/sslctl/backup \
    /opt/sslctl/certs \
    /var/www/html

WORKDIR /opt/sslctl
CMD ["tail", "-f", "/dev/null"]
