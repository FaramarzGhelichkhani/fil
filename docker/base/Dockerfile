FROM  python:3.8-slim-buster

WORKDIR /usr/src/app

RUN mkdir -p /opt/venv
COPY venv /opt/venv
COPY ./docker/base/requirements.txt ./requirements.txt
COPY ./docker/base/requirements.apt .
#COPY ./docker/base/sources.list /etc/apt/sources.list

ENV https_proxy='http://172.30.112.9:6060'
ENV http_proxy='http://172.30.112.9:6060'


# Install system dependencies
RUN apt-get update \
  && cat requirements.apt | xargs -I {} apt-get install {} -y \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

   
ENV PATH="/opt/venv/bin:$PATH"
ENV VIRTUAL_ENV=/opt/venv

#RUN source /opt/venv/bin/activate


#Copy pip config requirement file
#RUN mkdir -p $HOME/.pip
#COPY pip.conf $HOME/.pip/pip.conf
#COPY ./docker/base/pip.conf /etc/pip.conf

RUN python -m pip install --proxy http://172.30.112.9:6060 --upgrade pip
RUN python -m pip install --proxy http://172.30.112.9:6060 -r requirements.txt

RUN python -m pip install --upgrade pip  \
    && python -m pip install -r requirements.txt

CMD ["python"]
