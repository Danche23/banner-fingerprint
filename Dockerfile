# 第一阶段：构建
FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /server ./cmd/server && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /client ./cmd/client

# 第二阶段：server 运行镜像
FROM alpine:3.19 AS server
RUN apk add --no-cache ca-certificates wget && \
    addgroup -g 10001 appgroup && \
    adduser -D -u 10001 -G appgroup appuser
WORKDIR /app
COPY --from=builder /server /app/server
COPY --from=builder /build/rules /app/rules
RUN chown -R appuser:appgroup /app && chmod 755 /app/server
USER appuser
EXPOSE 8080
CMD ["/app/server"]

# 第三阶段：client 运行镜像
FROM alpine:3.19 AS client
RUN apk add --no-cache ca-certificates && \
    addgroup -g 10002 clientgroup && \
    adduser -D -u 10002 -G clientgroup clientuser
WORKDIR /app
COPY --from=builder /client /app/client
RUN chown -R clientuser:clientgroup /app && chmod 755 /app/client
USER clientuser
ENTRYPOINT ["/app/client"]
