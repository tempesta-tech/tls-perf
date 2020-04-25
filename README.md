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

**tls-perf** starts to establish new connections slowly and prints
```
( All peers are active, start to gather statistics )
```
This time all the requested peers managing all the requested connections are
active and **tls-perf** starts to gather statistics for the final report. Thus,
you might seem smaller number for `MEASURES` than you saw per-second statistic
lines.

The slow start also warms up all the caches of the benchmarked system, so
you don't need to make additional load before the benchmark.


```
$ ./tls-perf -l 100 -t 2 -T 10 192.168.100.4 443
Use cipher 'ECDHE-ECDSA-AES128-GCM-SHA256'
TLS hs in progress 313 [647 h/s], TCP open conns 313 [354 hs in progress], Errors 0
TLS hs in progress 644 [537 h/s], TCP open conns 644 [540 hs in progress], Errors 0
TLS hs in progress 801 [580 h/s], TCP open conns 802 [980 hs in progress], Errors 0
( All peers are active, start to gather statistics )
TLS hs in progress 1134 [596 h/s], TCP open conns 1134 [866 hs in progress], Errors 0
TLS hs in progress 1093 [614 h/s], TCP open conns 1093 [907 hs in progress], Errors 0
TLS hs in progress 1045 [807 h/s], TCP open conns 1045 [953 hs in progress], Errors 0
TLS hs in progress 1225 [666 h/s], TCP open conns 1225 [775 hs in progress], Errors 0
TLS hs in progress 1175 [854 h/s], TCP open conns 1175 [825 hs in progress], Errors 0
TLS hs in progress 1103 [790 h/s], TCP open conns 1103 [897 hs in progress], Errors 0
TLS hs in progress 1079 [689 h/s], TCP open conns 1079 [916 hs in progress], Errors 0
MEASURES (seconds) 7:	 MAX h/s 854; AVG h/s 715; 95P h/s 596; MIN h/s 596
LATENCY (microseconds):	 MIN 33; AVG 72; 95P 104; MAX 3334
```

`95P` parameters in resulting statistics show 95'th percentile: 95% of TLS
handshakes per second measurements are better than the number and 95% of TLS
handshakes require less microseconds than the number.
