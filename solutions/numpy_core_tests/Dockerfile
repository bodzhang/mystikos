#FROM python:3.10-rc-slim

FROM ubuntu:18.04
WORKDIR /

RUN apt update &&\
    apt install -y build-essential libssl-dev zlib1g-dev libncurses5-dev libncursesw5-dev \
        libreadline-dev libsqlite3-dev libgdbm-dev libdb5.3-dev libbz2-dev \
        libexpat1-dev liblzma-dev libffi-dev git

RUN git clone --branch 3.8 https://github.com/python/cpython
WORKDIR /cpython
RUN ./configure --with-pydebug && make -j -s && make install
RUN pip3 install numpy pytest hypothesis &&\
    ln -sf /bin/bash /bin/sh

WORKDIR /app
COPY ./app.py .

ENV PYTHONUNBUFFERED=1

CMD ["/usr/local/bin/python3", "/app/app.py"]
