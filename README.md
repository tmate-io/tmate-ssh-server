tmate server side
==================

tmate-ssh-server is the server side part of [tmate.io](http://tmate.io/).

Usage
-----

See on [tmate.io](http://tmate.io/).

Docker image
-----------

A docker image is provided:
[`tmate/tmate-ssh-server`](https://hub.docker.com/r/tmate/tmate-ssh-server)

The following environment variables are used to configure the server:

* `SSH_KEYS_PATH` (mandatory): The path where the ssh keys are located.
* `HAS_WEBSOCKET`: set to `1` if the tmate-websocket server exists (for HTML5
  clients).
* `USE_PROXY_PROTOCOL`: set to `1` if the ssh server is behind a load balancer
  that uses the [proxy protocol](http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) enabled.
  This is useful to get client real IPs.
* `SSH_HOSTNAME`: configures the SSH hostname to advertise to tmate hosts.
* `SSH_PORT_LISTEN`: port on which the SSH server should listen on.
* `SSH_PORT_ADVERTISE`: configures the SSH port to advertise to tmate hosts.
  Defaults to `SSH_PORT_LISTEN`.

Note that you need to add the *SYS_ADMIN* capability to the container.
This is needed to create nested containers (namespaces) to secure sessions.

License
--------

MIT license.
