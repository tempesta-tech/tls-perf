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
$ ./tls-perf -l 100 -t 2 -T 10 192.168.100.4 9443
Use cipher 'ECDHE-ECDSA-AES128-GCM-SHA256'
( All peers are active, start to gather statistics )
TLS hs in progress 98 [1748 h/s], TCP open conns 98 [102 hs in progress], Errors 0
TLS hs in progress 186 [2399 h/s], TCP open conns 186 [13 hs in progress], Errors 0
TLS hs in progress 129 [2666 h/s], TCP open conns 129 [71 hs in progress], Errors 0
TLS hs in progress 173 [2379 h/s], TCP open conns 173 [13 hs in progress], Errors 0
TLS hs in progress 190 [1990 h/s], TCP open conns 191 [5 hs in progress], Errors 0
TLS hs in progress 196 [2407 h/s], TCP open conns 196 [4 hs in progress], Errors 0
TLS hs in progress 163 [2568 h/s], TCP open conns 163 [37 hs in progress], Errors 0
TLS hs in progress 158 [2606 h/s], TCP open conns 158 [16 hs in progress], Errors 0
TLS hs in progress 179 [2287 h/s], TCP open conns 179 [13 hs in progress], Errors 0
TLS hs in progress 185 [2168 h/s], TCP open conns 185 [14 hs in progress], Errors 0
MEASURES (seconds) 10:	 MAX h/s 2666; AVG h/s 2319; 95P h/s 1748; MIN h/s 1748
LATENCY (microseconds):	 MIN 18; AVG 39; 95P 55; MAX 275
```

`95P` parameters in resulting statistics show 95'th percentilie: 95% of TLS
handshakes per second measurements are better than the number and 95% of TLS
handshakes require less microsendos than the number.
