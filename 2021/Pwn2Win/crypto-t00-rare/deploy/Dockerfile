FROM ubuntu:focal

# xinetd
RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y lib32z1 xinetd wget

ARG DEBIAN_FRONTEND=noninteractive

# Sage and dependencies
RUN apt-get install -y sagemath

RUN apt-get install -y hashcash

RUN useradd -u 8888 -m pwn

USER pwn

COPY ./share/* /home/pwn/

COPY ./xinetd /etc/xinetd.d/sage-service

CMD ["/usr/sbin/xinetd", "-dontfork"]
