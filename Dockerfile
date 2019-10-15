FROM ubuntu:latest
MAINTAINER Carlos M <carlos_munozgarrido@mcafee.com>


# Actualizo indices e instalo paquetes necesarios
RUN apt-get update -q && apt-get install -y \
    software-properties-common \
    cron \
    rsyslog

# Copio los archivos de configuracion del servicio rsyslog apuntando a Sandas
COPY ./conf/rsyslog.conf /etc/
COPY ./conf/sandas.conf /etc/rsyslog.d/

# Copio el archivo de rotacion y el job de cron
COPY ./scripts/rotate.sh /root
COPY ./scripts/monitorsyslog.sh /root
COPY ./scripts/initiate.sh /root
COPY ./scripts/cronjob /etc/cron.d

# Asigno perrmisos de ejecucion al archivo de rotacion y al job de cron
RUN chmod 755 /root/rotate.sh
RUN chmod 755 /root/monitorsyslog.sh
RUN chmod 755 /root/initiate.sh
RUN chmod 755 /etc/cron.d/cronjob


# Aplico el trabajo de cron para rotar los logs
RUN crontab /etc/cron.d/cronjob

# CMD service rsyslog start && service cron start && tail -f /dev/null
CMD service rsyslog start && service cron start && /root/initiate.sh && /bin/bash