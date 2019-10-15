#!/bin/bash
if [ ! "$(/bin/pidof rsyslogd)" ]

then

  echo $(/bin/date +%y%m%d) " " $(/bin/date +%H%M%S) " Daemon died" >> /var/log/cron.log
  rm -f /run/rsyslogd.pid
  /etc/init.d/rsyslog start >> /var/log/cron.log

else

  echo $(/bin/date +%y%m%d) " " $(/bin/date +%H%M%S) " Daemon alive" >> /var/log/cron.log

  /etc/init.d/rsyslog status >> /var/log/cron.log

fi