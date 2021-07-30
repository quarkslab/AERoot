FROM python:3.9-alpine3.14

RUN apk update && apk add --no-cache gdb

COPY . /opt/aeroot
WORKDIR /opt/aeroot

RUN python setup.py install

ENTRYPOINT ["aeroot"]
