FROM ubuntu:focal

# xinetd
RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y lib32z1 xinetd wget

# Julia and dependencies
RUN wget https://julialang-s3.julialang.org/bin/linux/x64/1.6/julia-1.6.0-linux-x86_64.tar.gz \
    && tar -xvzf julia-1.6.0-linux-x86_64.tar.gz \
    && cp -r julia-1.6.0 /opt/ \
    && ln -s /opt/julia-1.6.0/bin/julia /usr/local/bin/julia \
    && rm -rf julia-1.6.0*

RUN useradd -u 8888 -m pwn

USER pwn

COPY ./install-dependencies.jl /home/pwn

COPY ./share/* /home/pwn/

COPY ./xinetd /etc/xinetd.d/julia-service

RUN julia /home/pwn/install-dependencies.jl

CMD ["/usr/sbin/xinetd", "-dontfork"]
