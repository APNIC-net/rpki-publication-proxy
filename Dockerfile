FROM ubuntu:16.04

ENV HOSTNAME asdf

RUN apt-get update -y
RUN apt-get install -y \
    libhttp-daemon-perl \
    liblist-moreutils-perl \
    libwww-perl \
    libcarp-always-perl \
    cpanminus \
    libssl-dev \
    libyaml-perl \
    libxml-libxml-perl \
    libio-capture-perl \
    make
RUN apt-get install -y wget
RUN apt-get install -y patch
RUN apt-get install -y gcc
COPY cms.diff .
RUN wget https://ftp.openssl.org/source/old/1.0.1/openssl-1.0.1m.tar.gz \
    && tar xf openssl-1.0.1m.tar.gz \
    && cd openssl-1.0.1m \
    && patch -p0 < /cms.diff \
    && ./config enable-rfc3779 \
    && make \
    && make install
COPY . /root/rpki-publication-proxy
RUN cd /root/rpki-publication-proxy/ && perl Makefile.PL && make && make install
RUN rm -rf /root/rpki-publication-proxy/
CMD ["sh", "-c", "perl -MCarp::Always /usr/local/bin/rpki-publication-proxy-server $HOSTNAME $PORT $HANDLE $DBPATH"]

