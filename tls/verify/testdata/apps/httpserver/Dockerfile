FROM golang:1.15 as webapp-builder
    WORKDIR /go/src/github.com/gebv/grpc-conn-err-human-msg
    COPY go.mod .
    # COPY go.sum .
    RUN go mod download
    COPY . .
    RUN go build -v -o /webapp ./main.go

FROM alpine:3.11 as webapp
    RUN apk update && apk add --no-cache git ca-certificates tzdata make dbus && update-ca-certificates
    RUN dbus-uuidgen > /etc/machine-id
    RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2
    WORKDIR /
    COPY --from=webapp-builder /webapp .
    ENTRYPOINT /webapp
