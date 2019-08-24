FROM alpine:3.9

RUN apk add --no-cache msgpack-c ncurses-libs libevent libexecinfo openssl zlib

RUN set -ex; \
	apk add --no-cache --virtual .build-deps \
		git wget cmake make gcc g++ linux-headers zlib-dev openssl-dev \
		automake autoconf libevent-dev ncurses-dev msgpack-c-dev libexecinfo-dev; \
	\
	mkdir -p /src/libssh/build; \
	cd /src; \
	wget -O libssh.tar.xz https://www.libssh.org/files/0.9/libssh-0.9.0.tar.xz; \
	tar -xf libssh.tar.xz -C /src/libssh --strip-components=1; \
	cd /src/libssh/build; \
	cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr -DWITH_SFTP=OFF ..; \
	make -j "$(nproc)"; \
	make install ;\
	\
	mkdir -p /src/; \
	cd /src/; \
	git clone https://github.com/tmate-io/tmate-ssh-server.git; \
	cd tmate-ssh-server; \
	./autogen.sh; \
	./configure --prefix=/usr CFLAGS="-D_GNU_SOURCE"; \
	make -j "$(nproc)"; \
	make install ;\
	rm -rf /src; \
	apk del .build-deps

# TODO not run as root. Instead, use capabilities.

COPY docker-entrypoint.sh /usr/local/bin

EXPOSE 2200
ENTRYPOINT ["docker-entrypoint.sh"]
