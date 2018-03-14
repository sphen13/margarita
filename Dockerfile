FROM ubuntu:16.04

RUN mkdir /app
WORKDIR /app

RUN apt-get update && \
    apt-get install --no-install-recommends -y git \
    gcc \
    build-essential \
    python \
    python-dev \
    python-setuptools \
    python-pip \
    python-lxml \
    libxml2 \
    libxml2-dev \
    libxslt1-dev \
    libxmlsec1-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY requirements.txt /app
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

RUN git clone --depth 1 https://github.com/wdas/reposado && \
    cp -R reposado/code/reposadolib reposadolib && \
    rm -rf reposado

COPY . /app
CMD python margarita.py -p 5000
