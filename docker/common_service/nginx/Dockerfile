FROM nginx:stable

# 1. generate self-signed certificate & key
RUN openssl req \
    -x509 \
    -nodes \
    -days 3650 \
    -subj "/C=CA/ST=QC/O=Yaftar, Inc./CN=query_parser.yaftar.ir" \
    -addext "subjectAltName=DNS:query_parser.yaftar.ir" \
    -newkey rsa:2048 \
    -out /etc/ssl/certs/nginx-selfsigned.crt \
    -keyout /etc/ssl/private/nginx-selfsigned.key;

# 2. set proper conf file
RUN rm /etc/nginx/conf.d/default.conf
COPY ./nginx_443.conf /etc/nginx/conf.d/
COPY ./error502.html /user/share/nginx/html/
RUN mkdir /etc/nginx/conf.d/location.d
RUN mkdir -p /etc/ssl/certs/
COPY ./dhparam.pem /etc/ssl/certs/dhparam.pem
ENV TZ="Asia/Tehran"
