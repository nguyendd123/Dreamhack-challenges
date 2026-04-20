FROM ubuntu:focal-20220113

ENV USER integer_compressor
ENV CHALL_PORT 7777

RUN apt-get update && apt-get install -y socat
RUN adduser $USER

COPY --chown=$USER:$USER ./deploy/main /home/$USER/
COPY --chown=$USER:$USER ./deploy/flag.txt /home/$USER/

RUN chmod 750 /home/$USER/main
RUN chmod 440 /home/$USER/flag.txt

WORKDIR /home/$USER
USER $USER
EXPOSE $CHALL_PORT
CMD socat TCP-LISTEN:$CHALL_PORT,reuseaddr,fork EXEC:/home/$USER/main