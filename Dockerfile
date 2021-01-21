FROM alpine:3.13 AS build

RUN apk add --no-cache msgpack-c ncurses-libs libevent libexecinfo openssl zlib

RUN apk add --no-cache \
	autoconf \
	automake \
	cmake \
	g++ \
	gcc \
	git \
	libevent-dev \
	libexecinfo-dev \
	linux-headers \
	make \
	msgpack-c-dev \
	ncurses-dev \
	openssl-dev \
	zlib-dev

RUN apk add --no-cache libssh-dev

RUN mkdir -p /src/tmate-ssh-server
COPY . /src/tmate-ssh-server

RUN set -ex; \
	cd /src/tmate-ssh-server; \
	./autogen.sh; \
	./configure --prefix=/usr CFLAGS="-D_GNU_SOURCE"; \
	make -j "$(nproc)"; \
	make install

### Minimal run-time image
FROM alpine:3.13

RUN apk add --no-cache \
	bash \
	gdb \
	libevent \
	libexecinfo \
	libssh \
	msgpack-c \
	ncurses-libs \
	openssl \
	zlib

COPY --from=build /usr/lib/libssh.so.* /usr/lib/
COPY --from=build /usr/bin/tmate-ssh-server /usr/bin/

# TODO not run as root. Instead, use capabilities.

COPY docker-entrypoint.sh /usr/local/bin

EXPOSE 2200
ENTRYPOINT ["docker-entrypoint.sh"]
