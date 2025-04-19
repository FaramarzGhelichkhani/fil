#!/bin/sh
docker volume create fil_static_volume  # for:  (webserver) using (fil)_static_file
docker network create network_comman_service # for: (fil) using (kafka, db, cache)
docker network create network_webserver   #for:  (fil, mlflow, hub) using (webserver)
