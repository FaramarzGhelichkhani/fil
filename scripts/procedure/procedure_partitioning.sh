#!/bin/bash
python manage.py making_clusters 80 >> /var/fil/log/log_making_clusters.txt 2>&1 &
