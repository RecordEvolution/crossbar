# This Dockerfile is for development purposes only.
# It can be used to quickly setup a dev environment on a local laptop.

FROM python

RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y \
    git \
    libgirepository1.0-dev gcc libcairo2-dev pkg-config python3-dev gir1.2-gtk-3.0 \
    build-essential \
    libsnappy-dev \
    libunwind-dev


RUN pip install git+https://github.com/vmprof/vmprof-python

RUN git clone https://github.com/crossbario/crossbar.git

WORKDIR /crossbar

RUN cd /crossbar && make install

