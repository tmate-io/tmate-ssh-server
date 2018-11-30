#!/bin/sh

wget 'https://github.com/msgpack/msgpack-c/archive/cpp-3.1.1.tar.gz'
tar -xzf cpp-3.1.1.tar.gz
cd msgpack-c-cpp-3.1.1
cmake .
make
sudo make install
