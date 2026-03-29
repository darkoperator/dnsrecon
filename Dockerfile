FROM python:alpine@sha256:faee120f7885a06fcc9677922331391fa690d911c020abb9e8025ff3d908e510
RUN apk add --no-cache build-base libffi-dev libxml2-dev libxslt-dev
WORKDIR /app
COPY . /app
RUN /usr/local/bin/python -m pip install --upgrade pip
RUN /usr/local/bin/python --version
RUN pip3 install --no-cache-dir .
ENTRYPOINT ["dnsrecon"]
