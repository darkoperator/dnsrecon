FROM python:alpine@sha256:5a824eb82cc75361f98611f3cfc5091ea33f10a6ccea4d4ebdabbc523b9a1614
RUN apk add --no-cache build-base libffi-dev libxml2-dev libxslt-dev
WORKDIR /app
COPY . /app
RUN /usr/local/bin/python -m pip install --upgrade pip
RUN /usr/local/bin/python --version
RUN pip3 install --no-cache-dir .
ENTRYPOINT ["dnsrecon"]
