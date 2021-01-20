FROM alpine:3.9 AS build

RUN apk add --no-cache msgpack-c ncurses-libs libevent libexecinfo openssl zlib

RUN apk add --no-cache git wget cmake make gcc g++ linux-headers zlib-dev openssl-dev \
		automake autoconf libevent-dev ncurses-dev msgpack-c-dev libexecinfo-dev

RUN set -ex; \
	mkdir -p /src/libssh/build; \
	cd /src; \
	wget -O libssh.tar.xz https://www.libssh.org/files/0.9/libssh-0.9.5.tar.xz; \
	tar -xf libssh.tar.xz -C /src/libssh --strip-components=1; \
	cd /src/libssh/build; \
	cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr -DWITH_SFTP=OFF ..; \
	make -j "$(nproc)"; \
	make install

RUN mkdir -p /src/tmate-ssh-server
COPY . /src/tmate-ssh-server

RUN set -ex; \
	cd /src/tmate-ssh-server; \
	./autogen.sh; \
	./configure --prefix=/usr CFLAGS="-D_GNU_SOURCE"; \
	make -j "$(nproc)"; \
	make install

### Minimal run-time image
FROM alpine:3.9

RUN apk add --no-cache msgpack-c ncurses-libs libevent libexecinfo openssl zlib gdb bash

COPY --from=build /usr/lib/libssh.so.* /usr/lib/
COPY --from=build /usr/bin/tmate-ssh-server /usr/bin/

# TODO not run as root. Instead, use capabilities.

COPY docker-entrypoint.sh /usr/local/bin

EXPOSE 2200
ENTRYPOINT ["docker-entrypoint.sh"]
