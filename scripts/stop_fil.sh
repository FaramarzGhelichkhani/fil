#!/bin/bash

set -e

DIR=$2

if [[ "$DIR" == "" ]]; then
    echo "Please Specify 'DIR' as argument two!"
    exit 1
fi


machine=$1
case $machine in
    "fil-test")
	#Stoping fil
	docker-compose -f $DIR/fil/docker/base/docker-compose.yml down
	
	#Stoping redis, postgres
	docker-compose -f $DIR/fil/docker/require_service/docker-compose.yml down

	#Stoping hub
	docker-compose -f $DIR/fil/docker/hub/docker-compose.yml down

	#Stoping webserver, mlflow, kafka
	docker-compose -f $DIR/fil/docker/common_service/docker-compose.yml down

	#show result
	docker ps
        ;;
    "fil02")
	#Stoping fil
	docker-compose -f $DIR/fil/docker/base/docker-compose.yml down

	#Stoping hub
	docker-compose -f $DIR/fil/docker/hub/docker-compose.yml down

	#Stoping webserver, mlflow, kafka
	docker-compose -f $DIR/fil/docker/common_service/docker-compose.yml down

	#show result
	docker ps	    
	;;
    "fil01")
	#Stoping fil
	docker-compose -f $DIR/fil/docker/base/docker-compose.yml down

	#Stoping webserver, mlflow, kafka
	docker-compose -f $DIR/fil/docker/common_service/docker-compose.yml down

	#show result
	docker ps
	;;
    "fil-hourly")
	#Stoping fil
	docker compose -f $DIR/fil/docker/base/docker-compose.yml down

	#Stoping webserver, mlflow, kafka
	docker compose -f $DIR/fil/docker/common_service/docker-compose.yml down

	#show result
	docker ps    
	;;
    *)
        echo "Please Specify 'machine' as arguments one!"
        ;;
esac

