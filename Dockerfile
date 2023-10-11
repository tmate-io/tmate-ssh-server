FROM alpine:3.17.4 AS build

RUN apk add --no-cache \
	autoconf \
	automake \
	cmake \
	g++ \
	gcc \
	git \
	libevent \
	libevent-dev \
	libssh-dev \
	linux-headers \
	make \
	msgpack-c \
	msgpack-c-dev \
	ncurses-dev \
	ncurses-libs \
	openssl \
	openssl-dev \
	zlib \
	zlib-dev


WORKDIR /src/tmate-ssh-server
COPY . /src/tmate-ssh-server

RUN set -ex; \
	./autogen.sh; \
	./configure --prefix=/usr CFLAGS="-D_GNU_SOURCE"; \
	make -j "$(nproc)"; \
	make install

### Minimal run-time image
FROM alpine:3.16

RUN apk add --no-cache \
	bash \
	gdb \
	libevent \
	libssh \
	msgpack-c \
	ncurses-libs \
	openssl \
	zlib

COPY --from=build /usr/bin/tmate-ssh-server /usr/bin/

# TODO not run as root. Instead, use capabilities.

COPY docker-entrypoint.sh /usr/local/bin

EXPOSE 2200
ENTRYPOINT ["docker-entrypoint.sh"]
