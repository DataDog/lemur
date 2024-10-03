FROM python:3.8-alpine

ARG VERSION
ARG URLCONTEXT

ENV uid 1337
ENV gid 1337
ENV user lemur
ENV group lemur

RUN addgroup -S ${group} -g ${gid}
RUN adduser -D -S ${user} -G ${group} -u ${uid}
RUN apk add --no-cache --update python3 py-pip libldap postgresql-client nginx supervisor curl tzdata openssl bash build-base libstdc++ libc6-compat
RUN apk --update add --virtual build-dependencies \
                git \
                tar \
                curl \
                python3-dev \
                npm \
                bash \
                musl-dev \
                cargo \
                gcc \
                autoconf \
                automake \
                libtool \
                make \
                nasm  \
                zlib-dev \
                postgresql-dev \
                # libressl-dev  \
                libffi-dev \
                cyrus-sasl-dev \
                openldap-dev
USER root
RUN mkdir -p /opt/lemur /home/lemur/.lemur
COPY lemur-dev.tar.gz /opt/lemur
WORKDIR /opt/lemur
RUN tar -xvzf lemur-dev.tar.gz

RUN pip3 install --upgrade pip
RUN pip3 install --upgrade setuptools
RUN mkdir -p /run/nginx/ /etc/nginx/ssl/
RUN chown -R $user:$group /opt/lemur/ /home/lemur/.lemur/

COPY entrypoint /
COPY supervisor.conf /
COPY nginx/nginx.conf /etc/nginx/
COPY nginx/default.conf /etc/nginx/conf.d/
COPY nginx/default-ssl.conf /etc/nginx/conf.d/

RUN echo "Running with python:" && python -c 'import platform; print(platform.python_version())'
RUN echo "Running with nodejs:" && node -v
RUN npm install --unsafe-perm
RUN pip3 install -e .
RUN node_modules/.bin/gulp build
RUN node_modules/.bin/gulp package --urlContextPath=${URLCONTEXT}
RUN apk del build-dependencies

COPY src/lemur.conf.py /home/lemur/.lemur/lemur.conf.py
RUN echo ${PWD} && ls -lR
RUN chown -R $user:$group /opt/lemur/ /home/lemur/.lemur/

RUN chmod +x /entrypoint
WORKDIR /

HEALTHCHECK --interval=12s --timeout=12s --start-period=30s \
CMD curl --fail http://localhost:80/api/1/healthcheck | grep -q ok || exit 1
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/server.key -out /etc/nginx/ssl/server.crt -subj "/C=US/ST=NY/L=New York/O=Eng/CN=www.example.com"

# Use this to stop the container in case of a crash loop and use
# "docker exec -it docker-lemur-1 bash" to troubleshoot.
# CMD ["tail", "-f", "/dev/null"]

ENTRYPOINT ["/entrypoint"]

CMD ["/usr/bin/supervisord","-c","supervisor.conf"]
