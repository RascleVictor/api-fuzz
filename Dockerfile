FROM golang:1.24 AS go_builder

WORKDIR /build

COPY go.mod ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o api-fuzz

FROM alpine:3.21

WORKDIR /app

RUN mkdir -p /app/config
RUN adduser -D -u 1000 -s /sbin/nologin app
COPY --chown=app:app entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

USER app

COPY --from=go_builder /build/api-fuzz /app/api-fuzz

ENTRYPOINT ["/app/entrypoint.sh"]
