FROM ubuntu:20.04@sha256:a0d9e826ab87bd665cfc640598a871b748b4b70a01a4f3d174d4fb02adad07a9

RUN apt update && apt install socat -y && adduser user --disabled-password

WORKDIR /home/user

COPY flag /home/user/flag
COPY Lazenca.Bank /home/user/Lazenca.Bank

RUN chown -R root:user /home/user && \
    chmod -R 750 /home/user && \
    chmod 744 /home/user/flag

USER user
EXPOSE 8888

ENTRYPOINT ["socat", "TCP-LISTEN:8888,reuseaddr,fork","exec:\"./Lazenca.Bank\",nofork,stderr"]

