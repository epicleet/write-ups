# All the files must be read only, except run.py

FROM ubuntu:focal

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y qemu-system-x86 hashcash python3 lib32z1 xinetd

RUN useradd -u 8888 -m pwn

COPY ./share/ /home/pwn/

# RUN chown pwn -R /home/pwn/* && chmod 444 /home/pwn/OVMF.fd \
#     && chmod 444 /home/pwn/contents/* && chmod 444 /home/pwn/run.py && chmod +x /home/pwn/run.py

RUN chown -R root:pwn /home/pwn && chmod 750 /home/pwn \
    && chmod 440 /home/pwn/OVMF.fd \
    && chmod 440 /home/pwn/contents/* && chmod 450 /home/pwn/run.py 
    # && chmod +x /home/pwn/run.py

USER pwn

COPY ./xinetd /etc/xinetd.d/pwn-service

CMD ["/usr/sbin/xinetd", "-dontfork"]
