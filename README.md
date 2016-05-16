tmate server side
==================

tmate-slave is the server side part of [tmate.io](http://tmate.io/).

Usage
-----
```shell
# tmate-slave -p 12345 -l /var/log/tmate-slave.log
```

* **-p** port on which to listen
* **-l** log file
* **-v** verbose output

See also [tmate.io](http://tmate.io/).

RPM
---
RHEL 7 (and derivative) users can build an RPM to install tmate-slave using the `tmate-slave.spec` file in the `SPEC` directory.  This will build the `tmate-slave` binary, set up keys (if necessary), and create a client config file in `/etc/tmate-slave/tmate.config.sample`.

The default configuration will use the options defined in `/etc/sysconfig/tmate-slave` to listen on port 22000 and log to `/var/log/messages`.

Per Fedora and Red Hat packaging guidelines, the daemon will **not** be enabled or started automatically.  To enable and start:
```shell
$ sudo systemctl enable tmate-slave
$ sudo systemctl start tmate-slave
```

Contributions
-------------

* Chef cookbook by [JJ Asghar](https://github.com/jjasghar): [https://github.com/jjasghar/chef-tmate-slave](https://github.com/jjasghar/chef-tmate-slave)
* Custom host:port support by [Paolo Mainardi](https://github.com/paolomainardi)
* RHEL 7 (and derivatives) RPM by [Scott Merrill](https://github.com/skpy)

License
--------

MIT license.
