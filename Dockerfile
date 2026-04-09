FROM python:alpine@sha256:6f873e340e6786787a632c919ecfb1d2301eb33ccfbe9f0d0add16cbc0892116
RUN apk add --no-cache build-base libffi-dev libxml2-dev libxslt-dev
WORKDIR /app
COPY . /app
RUN /usr/local/bin/python -m pip install --upgrade pip
RUN /usr/local/bin/python --version
RUN pip3 install --no-cache-dir .
ENTRYPOINT ["dnsrecon"]
