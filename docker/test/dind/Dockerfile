# DinD E2E 测试容器
# 用法: docker build -t test-dind docker/test/dind/
FROM docker:dind

RUN apk add --no-cache bash curl jq bats socat openssl

RUN mkdir -p \
    /opt/sslctl/sites \
    /opt/sslctl/logs \
    /opt/sslctl/backup \
    /opt/sslctl/certs

WORKDIR /opt/sslctl
