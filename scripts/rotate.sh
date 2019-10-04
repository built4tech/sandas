#!/bin/bash

file=/etc/rsyslog.d/sandas.conf
filename=sandas.conf
backup_path=/tmp

current_date=$(date +%Y%m%d)
conf_date=$(head -n1 $file)
old_date=$(echo ${conf_date:1})


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
service rsyslog stop
rm -f /run/rsyslogd.pid
service rsyslog start
echo
echo Process Ended
