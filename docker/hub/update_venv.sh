#!/bin/bash
read app_name

sudo docker build -f Dockerfile.venv -t jupyterhub-venv .
# Step 1: Run Docker container
container_id=$(sudo docker run -d jupyterhub-venv tail -f /dev/null)

# Step 2: Download file inside container
sudo docker exec $container_id pwd
sudo docker exec $container_id /usr/src/app/venv/bin/python -m pip install --proxy http://172.30.112.9:6060 $app_name

echo "Download package $app_name complete"
# Step 3: Copy file from container to local machine
sudo docker cp $container_id:/usr/src/app/venv .

# Step 5: Clean up - stop and remove the Docker container
sudo docker stop $container_id
sudo docker rm $container_id
rsync -av ./venv fil02:/opt/fil-docker/hub/
