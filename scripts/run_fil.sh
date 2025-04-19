#!/bin/bash

set -e

DIR=$2

if [[ "$DIR" == "" ]]; then
    echo "Please Specify 'machine', 'DIR' as argument one, two!"
    exit 1
fi


#Create Netowrk
docker network ls|grep network_webserver      > /dev/null || docker network create network_webserver
docker network ls|grep network_comman_service > /dev/null || docker network create network_comman_service

#Create Volume
docker volume ls|grep fil_static_volume  > /dev/null || docker volume create fil_static_volume

machine=$1
case $machine in
    "fil-test")
	export HOST_IP=172.30.113.242

	#Starting postgres, redis
	docker-compose -f $DIR/fil/docker/require_service/docker-compose.yml up -d postgres redis
	docker-compose -f $DIR/fil/docker/require_service/docker-compose.yml restart postgres redis

	#Starting hub
	#docker-compose -f $DIR/fil/docker/hub/docker-compose.yml up -d hub
	#docker-compose -f $DIR/fil/docker/hub/docker-compose.yml restart hub

	#Starting fil
        docker-compose -f $DIR/fil/docker/base/docker-compose.yml up -d fil
        docker-compose -f $DIR/fil/docker/base/docker-compose.yml restart fil

	#Starting webserver, mlflow, kafka
	docker-compose -f $DIR/fil/docker/common_service/docker-compose.yml build -q
	docker-compose -f $DIR/fil/docker/common_service/docker-compose.yml up -d mlflow kafka webserver
	docker-compose -f $DIR/fil/docker/common_service/docker-compose.yml restart mlflow kafka webserver
	
	sleep 5
	echo "---------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
	docker ps
	echo "---------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
	;;
    "fil-development")
	export HOST_IP=172.18.5.125
        #Starting postgres, redis
        docker compose -f $DIR/fil/docker/require_service/docker-compose.yml up -d postgres redis
        docker compose -f $DIR/fil/docker/require_service/docker-compose.yml restart postgres redis
	
	#Starting fil
	docker compose -f $DIR/fil/docker/base/docker-compose.yml up -d fil
	docker compose -f $DIR/fil/docker/base/docker-compose.yml restart fil

	#Starting hub
	#docker compose -f $DIR/fil/docker/hub/docker-compose.yml up -d hub
	#docker compose -f $DIR/fil/docker/hub/docker-compose.yml restart hub

	#Starting webserver, mlflow, kafka
	docker compose -f $DIR/fil/docker/common_service/docker-compose.yml build -q
	docker compose -f $DIR/fil/docker/common_service/docker-compose.yml up -d mlflow kafka #webserver
	docker compose -f $DIR/fil/docker/common_service/docker-compose.yml restart mlflow kafka #webserver
	
	sleep 5
	echo "---------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
	docker ps
	echo "---------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
	;;
	"fil-production")
	export HOST_IP=172.18.5.157
        #Starting postgres, redis
        docker compose -f $DIR/fil/docker/require_service/docker-compose.yml up -d postgres redis
        docker compose -f $DIR/fil/docker/require_service/docker-compose.yml restart postgres redis
	
	#Starting kafka
	docker compose -f $DIR/fil/docker/common_service/docker-compose.yml up -d kafka
	docker compose -f $DIR/fil/docker/common_service/docker-compose.yml restart kafka

	#Starting fil
	docker compose -f $DIR/fil/docker/base/docker-compose.yml up -d fil
	docker compose -f $DIR/fil/docker/base/docker-compose.yml restart fil
	
	#Starting webserver
	docker compose -f $DIR/fil/docker/common_service/docker-compose.yml build -q
	docker compose -f $DIR/fil/docker/common_service/docker-compose.yml up -d  webserver
	docker compose -f $DIR/fil/docker/common_service/docker-compose.yml restart webserver
	
	sleep 5
	echo "---------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
	docker ps
	echo "---------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
	;;
    *)
        echo "Please Specify 'machine' as arguments one!"
        ;;
esac

