#!/bin/sh
set -e

DB_HOST=$(grep "DB_HOST="     .env.prod | cut -d '=' -f 2)
export DB_HOST
DB_PORT=$(grep "DB_PORT="     .env.prod | cut -d '=' -f 2)
export DB_PORT
IS_PRODUCTION=$(grep "IS_PRODUCTION=" .env.prod | cut -d '=' -f 2)
export IS_PRODUCTION
SERVER_NAME=$(grep "SERVER_NAME=" .env.prod | cut -d '=' -f 2)
export SERVER_NAME


if [ "$DATABASE" = "postgres" ]
then
    echo "Waiting for postgres..."
    
    while ! nc -z $DB_HOST $DB_PORT; do
      sleep 0.1
    done

    echo "PostgreSQL started"
fi

python manage.py migrate
python manage.py collectstatic --no-input --clear

if [ "$IS_PRODUCTION" = "True"  ]
then 
  python manage.py consume_input_messages  >> /var/fil/log/log_consume_input_messages.txt  2>&1 &
  python manage.py result_check >> /var/fil/log/log_consume_check_message.txt 2>&1 &
fi

exec "$@"
    