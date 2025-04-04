# Base Image Selection
ARG BASE_IMAGE=registry.ddbuild.io/images/base/gbi-ubuntu_2204:release

# Lemur Builder
FROM $BASE_IMAGE as builder

ARG CI_COMMIT_SHA

USER root

RUN curl -sL https://deb.nodesource.com/setup_18.x | bash -
RUN apt-get install -y --no-install-recommends libpq-dev curl build-essential locales libffi-dev libsasl2-dev libldap2-dev \
        dh-autoreconf git python3-dev python3-pip python3-venv python3-wheel nodejs unzip make

# Download Lemur source code
RUN echo "Getting code from COMMIT SHA $CI_COMMIT_SHA"
RUN curl -OL "https://github.com/DataDog/lemur/archive/$CI_COMMIT_SHA.zip"
RUN mkdir -p /opt/lemur && \
    unzip $CI_COMMIT_SHA.zip && mv lemur-$CI_COMMIT_SHA/* /opt/lemur/

WORKDIR /opt/lemur

# Disable unused Lemur plugins
COPY ./files/disable_plugins.patch /opt/lemur
RUN patch -p0 -i disable_plugins.patch && rm -rf disable_plugins.patch

RUN npm config set registry http://registry.npmjs.org/ && \
    npm install npm -g && \
    echo "Running with nodejs:" && node -v && \
    python3 -m venv /opt/venv && \
    echo "Running with python:" && /opt/venv/bin/python3 -c 'import sys, platform; print("sys.platform == {}, platform.machine == {}, platform.python_version == {}".format(sys.platform, platform.machine(), platform.python_version()))' && \
    /opt/venv/bin/python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel && \
    # ddtrace is required to automatically instrument lemur to emit traces
    /opt/venv/bin/python3 -m pip install --no-cache-dir ddtrace && \
    /opt/venv/bin/python3 -m pip install --no-cache-dir -e . && \
    # install the statsd plugin required to emit metrics to datadog
    /opt/venv/bin/python3 -m pip install --no-cache-dir -e /opt/lemur/lemur/plugins/lemur_statsd && \
    npm install --unsafe-perm && \
    node_modules/.bin/gulp --cwd /opt/lemur build && \
    node_modules/.bin/gulp --cwd /opt/lemur package && \
    npm cache clean --force && \
    rm -rf node_modules

# Install requirement overrides. Required for FIPS mode.
RUN echo "Installing requirement overrides:" && /opt/venv/bin/python3 -c 'import sys, platform; print("sys.platform == {}, platform.machine == {}, platform.python_version == {}".format(sys.platform, platform.machine(), platform.python_version()))'
RUN /opt/venv/bin/python3 -m pip install --no-cache-dir --no-deps --force-reinstall -r requirements-overrides.txt

# Lemur Application
FROM $BASE_IMAGE

# FIPS mode
ARG FIPS_ENABLED=false
LABEL IS_FIPS=$FIPS_ENABLED

USER root

RUN apt-get update && apt-get -y install jq

COPY --from=builder /opt/lemur /opt/lemur
COPY --from=builder /opt/venv /opt/venv

RUN clean-apt install python3 python3-distutils haveged curl postgresql-client openssl &&\
    chown -R dog:dog /opt

ENV FIPS_ENABLED=$FIPS_ENABLED

USER dog
