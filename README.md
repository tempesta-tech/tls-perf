# TLS handshakes benchmarking tool

A tool to stress test the TLS handshake by triggering processor intensive
cryptographic computations on the server side.

Inspired by and partially based on THC-SSL-DOS tool (see the fork of the
original tool at https://github.com/azet/thc-tls-dos). The key differences
from the THC tool are:

1. this benchmark does TLS handshake only and quickly resets TCP connection.
   It doesn't try to send or read any data or execute a renegotiation.

2. this benchmark is multi-threaded and with better `epoll()` based IO, more
   efficient state machine and less looping. Multi-threading is required for
   ECC handshakes with the cryptographic calculations more expensive on
   the client side than on the server side.

3. Much richer statistics.


# Usage

## Build
```
$ make
g++ -O2 -march=native -mtune=native -Wall -DL1DSZ=64  -c main.cc -o main.o
g++ -o tls-perf main.o -lpthread -lssl -lcrypto
```

## Help
```
$ ./tls-perf --help

./tls-perf [options] <ip> <port>
  -h,--help    Print this help and exit.
  -d,--debug   Run in debug mode.
  -l <n>       Limit parallel connections for each thread (default: 1).
  -t <n>       Number of threads (default: 1).
  -T,--to      Duration of the test (in seconds)
  -c <cipher>  Force cipher choice (default: ECDHE-ECDSA-AES128-GCM-SHA256).

127.0.0.1:443 address is used by default.

To list available ciphers run command:
$ nmap --script ssl-enum-ciphers -p <PORT> <IP>
```

## Run
```
$ ./tls-perf -l 200 -t 10 -T 10 192.168.100.4 9443
set open files limit to 2040
Use cipher 'ECDHE-ECDSA-AES128-GCM-SHA256'
( All peers are active, start to gather statistics )
TLS hs in progress 1996 [0 h/s], TCP open conns 1996 [0 hs in progress], Errors 0
TLS hs in progress 2000 [1179 h/s], TCP open conns 2000 [0 hs in progress], Errors 0
TLS hs in progress 1998 [823 h/s], TCP open conns 2000 [0 hs in progress], Errors 0
TLS hs in progress 1996 [1132 h/s], TCP open conns 1996 [0 hs in progress], Errors 0
TLS hs in progress 1998 [876 h/s], TCP open conns 1998 [0 hs in progress], Errors 0
TLS hs in progress 2000 [756 h/s], TCP open conns 2000 [0 hs in progress], Errors 0
TLS hs in progress 2000 [821 h/s], TCP open conns 2000 [0 hs in progress], Errors 0
TLS hs in progress 2000 [867 h/s], TCP open conns 2000 [0 hs in progress], Errors 0
TLS hs in progress 2000 [758 h/s], TCP open conns 2000 [0 hs in progress], Errors 0
TLS hs in progress 2000 [814 h/s], TCP open conns 2000 [0 hs in progress], Errors 0
MEASURES (seconds) 10; MAX h/s 1179; 99P h/s 1179; 95P h/s 1179; AVG h/s 800; MIN h/s 756
```
