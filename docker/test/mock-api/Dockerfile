FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY main.go .
RUN go build -o mock-api .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/mock-api /usr/local/bin/
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=3s CMD wget -q --spider http://localhost:8080/health || exit 1
CMD ["mock-api"]
