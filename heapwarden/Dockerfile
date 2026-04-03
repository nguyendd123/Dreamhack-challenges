FROM ubuntu:22.04@sha256:3ba65aa20f86a0fad9df2b2c259c613df006b2e6d0bfcc8a146afb8c525a9751

RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*
RUN useradd -m -d /home/pwn pwn

WORKDIR /home/pwn
COPY heapwarden /home/pwn/heapwarden
COPY data /home/pwn/data
COPY flag /flag

RUN chmod 0555 /home/pwn/heapwarden && \
    chmod 0444 /flag && \
    chmod -R 0555 /home/pwn/data && \
    chown root:root /flag

USER pwn
EXPOSE 31337
CMD ["socat","TCP-LISTEN:31337,reuseaddr,fork","EXEC:/home/pwn/heapwarden,stderr"]