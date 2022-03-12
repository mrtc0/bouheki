FROM ubuntu:21.10 as builder

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update
RUN apt-get install -y \
  wget \
  build-essential \
  libbpf-dev \
  clang \
  gcc-multilib \
  llvm \
  zlib1g-dev \
  libelf-dev \
  linux-tools-generic \
  linux-tools-common \
  linux-headers-$(uname -r) \
  linux-tools-$(uname -r)

RUN wget https://go.dev/dl/go1.17.5.linux-amd64.tar.gz -O /tmp/go1.17.5.linux-amd64.tar.gz
RUN rm -rf /usr/local/go && \
  tar -C /usr/local -xzf /tmp/go1.17.5.linux-amd64.tar.gz && \
  ln -sf /usr/local/go/bin/go /usr/bin/go
RUN mkdir -p /go/{bin,src}

FROM builder AS build
ENV GOPATH=/go
WORKDIR /go/src/github.com/mrtc0/bouheki
COPY . ./
RUN make build

FROM ubuntu:21.10
RUN apt-get update
RUN apt-get install -y libelf-dev && apt-get clean && rm -rf /var/lib/apt/lists/
COPY --from=build /go/src/github.com/mrtc0/bouheki/build/bouheki /usr/local/bin/bouheki
RUN chmod +x /usr/local/bin/bouheki

ENTRYPOINT ["/usr/local/bin/bouheki"]
