ARG BASE=github.com/wencaiwulue/kubevpn

FROM golang:1.18 AS builder

COPY . /go/src/$BASE

WORKDIR /go/src/$BASE

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o envoy-xds-server /go/src/$BASE/cmd/mesh

FROM ubuntu:latest

RUN sed -i s@/security.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list \
    && sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list
RUN apt-get clean && apt-get update && apt-get install -y wget dnsutils vim curl  \
    net-tools iptables iputils-ping lsof iproute2 tcpdump

WORKDIR /app

COPY --from=builder /go/src/$BASE/envoy-xds-server /bin/envoy-xds-server