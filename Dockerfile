# tmate-ssh-server, see https://tmate.io/
#
# Example usage:
#
#     docker run --privileged --rm -i -p 22:22 \
#     -v /etc/tmate/keys:/daemon-keys \
#     -v /etc/tmate/authorized_keys:/authorized-keys \
#     varac/tmate-ssh-server \
#     /bin/sh -c "/sbin/tmate-ssh-server -k /daemon-keys -a /authorized-keys -b 0.0.0.0 -p 22 -v -v -v -h SERVER_FQDN"

FROM debian:jessie-slim

# Locales
RUN mkdir -p /usr/share/locale/locale.alias && ln -s /etc/locale.alias /usr/share/locale/locale.alias
RUN apt-get update && apt-get install -y locales \
    && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
ENV LANG en_US.utf8

RUN apt-get install -y git build-essential automake cmake pkg-config libssl-dev zlib1g-dev libevent-dev libncurses5-dev \
	&& rm -rf /var/lib/apt/lists/*

RUN mkdir /src && cd /src/ &&\
        # Latest libssh requires cmake >= 3.3.0 which is not available in jessie.
	# jessie-backports provides 3.6.2 but this pulls too many dependencies in.
	git clone -b libssh-0.7.6 git://git.libssh.org/projects/libssh.git &&\
	git clone https://github.com/msgpack/msgpack-c.git &&\
	git clone https://github.com/tmate-io/tmate-ssh-server.git

RUN cd /src/libssh &&\
	mkdir build && cd build && cmake .. && make install
RUN cd /src/msgpack-c &&\
	mkdir build && cd build && cmake .. && make install

RUN cd /src/tmate-ssh-server &&\
	sh autogen.sh && PKG_CONFIG_PATH=/usr/local/lib/pkgconfig ./configure && make

RUN cp /src/tmate-ssh-server/tmate-ssh-server /sbin/

# Clean up
RUN rm -rf /src
RUN apt-get --auto-remove purge -y git build-essential automake cmake pkg-config libssl-dev zlib1g-dev libncurses5-dev

ENV LD_LIBRARY_PATH=/usr/local/lib
