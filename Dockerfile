FROM python:3.9
RUN apt-get update
RUN apt-get install -y make software-properties-common curl
RUN curl -sL https://deb.nodesource.com/setup_16.x | bash -
RUN python -m pip install --upgrade pip
RUN python -m pip install --upgrade setuptools
RUN pip install coveralls bandit
RUN apt-get update
RUN apt-get -y install libsasl2-dev libldap2-dev xvfb nodejs
WORKDIR /app
COPY . /app/
