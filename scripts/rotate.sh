#!/bin/bash

file=/etc/rsyslog.d/sandas.conf
filename=sandas.conf
backup_path=/tmp

current_date=$(date +%Y%m%d)
conf_date=$(head -n1 $file)
old_date=$(echo ${conf_date:1})

echo $(/bin/date +%y%m%d) " " $(/bin/date +%H%M%S) " Rotacion configuracion syslog" >> /var/log/cron.log

echo
echo Configuration file          : $file
echo Configuration file date     : $old_date
echo Current date                : $current_date

echo
echo ... Creating backup
cp $file $backup_path'/'$filename'_'$old_date
echo
echo ... Changig conf file with current date
sed -i 's/'$old_date'/'$current_date'/g' $file

echo
echo ... Restarting rsyslog service
/etc/init.d/rsyslog stop >> /var/log/cron.log
rm -f /run/rsyslogd.pid
/etc/init.d/rsyslog start >> /var/log/cron.log
echo
echo Process Ended
echo $(/bin/date +%y%m%d) " " $(/bin/date +%H%M%S) " Fin del proceso" >> /var/log/cron.log
