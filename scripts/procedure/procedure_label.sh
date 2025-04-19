#!/bin/bash
python /usr/src/app/manage.py label 30 >> /var/fil/log/log.txt 2>&1

count=$(ls /var/fil/data/raw/*.csv | wc -l)
if [[ ("$count" < 120) ]]
then
	echo " DELETE DENY " >> logging/log.txt
else
	find /var/fil/data/raw -name "*.csv" -type f -mtime +30 -delete
	echo " DELETE SUCCESSFULL " >> logging/log.txt
fi
