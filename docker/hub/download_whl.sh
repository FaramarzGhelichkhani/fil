#!/bin/bash
read app_name
# Step 1: Run Docker container
container_id=$(docker run -d jupyterhub/jupyterhub:latest tail -f /dev/null)

# Step 2: Download file inside container
docker exec $container_id pwd
docker exec $container_id python3 -m pip download --proxy http://172.30.112.9:6060 $app_name -d packages

echo "Download package $app_name complete"
# Step 3: Copy file from container to local machine
docker cp $container_id:/srv/jupyterhub/packages ./tmp
mv ./tmp/* packages/
rm -r ./tmp
ls packages
# Step 5: Clean up - stop and remove the Docker container
docker stop $container_id
docker rm $container_id
