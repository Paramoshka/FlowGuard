FROM ubuntu:22.04 AS buid_bpf
WORKDIR /src
COPY  . /src
RUN apt update -y && \
    apt install -y gcc make clang libbpf-dev
RUN make

FROM golang:1.23 AS build_go
WORKDIR /src
COPY  . /src
RUN go mod download
RUN cd /src/cmd/flowguard && \
    go build -o /src/flowguard && \
    chmod +x /src/flowguard

FROM debian:12-slim
COPY --from=buid_bpf /src/build /app
COPY --from=build_go /src/flowguard /app/flowguard
COPY config.yaml /app/config.yaml
ENTRYPOINT ["/app/flowguard"]
