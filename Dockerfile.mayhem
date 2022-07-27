FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential autoconf \
        libtool \
        git \
        bison \
        flex \
        python3 \
        python3-pip \
        wget 

COPY . /repo
WORKDIR /repo
RUN autoreconf -i
RUN ./configure --disable-maintainer-mode --prefix=/install
RUN make -j8
RUN make install

FROM ubuntu:20.04 as package
COPY --from=builder /install /install
