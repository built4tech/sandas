#!/bin/bash
CHECK=`ps -aux | grep getevents.py | grep -v grep | wc -l`
if [ $CHECK -eq 0 ]
then
cd /home/c.munoz/code
python3 /home/c.munoz/code/getevents.py -ip 192.168.200.2 -u NGCP -p Security.4u &
fi