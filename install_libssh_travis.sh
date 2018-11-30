#!/bin/sh

wget 'https://www.libssh.org/files/0.8/libssh-0.8.5.tar.xz'
tar -xJf libssh-0.8.5.tar.xz
mkdir libssh-build
cd libssh-build
cmake ../libssh-0.8.5
make
sudo make install
