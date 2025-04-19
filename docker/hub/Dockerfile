# pull official base image
FROM jupyterhub/jupyterhub:latest

# set work directory
WORKDIR /usr/src/app
RUN pip install --proxy http://172.30.112.9:6060 notebook
COPY jupyterhub_config.py /etc/jupyterhub/jupyterhub_config.py

COPY fil/requirements.txt ./requirements.txt
RUN python -m pip install --proxy http://172.30.112.9:6060 --upgrade pip

ENV https_proxy='http://172.30.112.9:6060'
ENV http_proxy='http://172.30.112.9:6060'

RUN apt-get update
RUN apt-get install -y python3.10-venv tzdata vim
				       

ENV https_proxy=
ENV http_proxy=

RUN ln -fs /usr/share/zoneinfo/Asia/Tehran /etc/localtime 
RUN python -m venv venv
#COPY ./hub/venv ./venv
RUN venv/bin/python -m pip install --proxy http://172.30.112.9:6060 -r requirements.txt

RUN venv/bin/python -m pip install --proxy http://172.30.112.9:6060 jupyter
#RUN ipython kernel install --name "local-venv" --user

ENV TZ="Asia/Tehran"

