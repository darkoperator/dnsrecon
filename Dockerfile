FROM python:alpine
WORKDIR /app
COPY . /app
RUN apk add --no-cache build-base libffi-dev libxml2-dev libxslt-dev
RUN /usr/local/bin/python -m pip install --upgrade pip
RUN /usr/local/bin/python --version
RUN pip3 install --no-cache-dir .
ENTRYPOINT ["dnsrecon"]
