FROM ubuntu:16.04

RUN apt-get update \
    && apt-get -y upgrade \
    && apt-get -y install build-essential gcc-multilib g++-multilib wget build-essential \
    && apt-get clean


ENV PIN_TAR_NAME=pin-3.7-97619-g0d0c92f4f-gcc-linux
ENV PIN_ROOT=/${PIN_TAR_NAME}

RUN wget http://software.intel.com/sites/landingpage/pintool/downloads/${PIN_TAR_NAME}.tar.gz \
    && tar xvf ${PIN_TAR_NAME}.tar.gz

RUN mkdir -p libdft
COPY . libdft
WORKDIR libdft
RUN make
COPY ./env.init /opt/

VOLUME ["/data"]
WORKDIR /
ENTRYPOINT [ "/opt/env.init" ]