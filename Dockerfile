FROM python:3.6

RUN mkdir -p /usr/src/app

WORKDIR /usr/src/app

COPY . .

RUN python setup.py install

RUN mkdir /tmp/certs

WORKDIR /tmp/certs
