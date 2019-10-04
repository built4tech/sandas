FROM ubuntu:latest
MAINTAINER Carlos M <carlos_munozgarrido@mcafee.com>

RUN apt-get update -q && apt-get install -y \
    software-properties-common \
    rsyslog

COPY ./conf/rsyslog.conf /etc/
COPY ./conf/sandas.conf /etc/rsyslog.d/

CMD service rsyslog start && tail -f /dev/null