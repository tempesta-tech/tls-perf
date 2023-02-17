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

## Using custom openssl build
Provide `Makefile.local` with two variables:
```
SSL_INCLUDE := /path/to/ssl/include/dir
SSL_LIBDIR  := /path/to/ssl/libdir
```

This would add specified directories to compiler/linker search paths and also would
add rpath to the resulting binary.

## Help
```
$ ./tls-perf --help

./tls-perf [options] <ip> <port>
  -h,--help            Print this help and exit
  -d,--debug           Run in debug mode
  -q,--quiet           Show less statistics in the run time
  -l <N>               Limit parallel connections for each thread (default: 1)
  -n <N>               Total number of handshakes to establish
  -t <N>               Number of threads (default: 1).
  -T,--to              Duration of the test (in seconds)
  -c <cipher>          Force cipher choice
                       (use `openssl ciphers` to list available cipher suites),
  -C <curve>           Force specific curve for elliptic curve algorithms (use
                       `openssl ecparam -list_curves` to list available curves).
  -V,--tls <version>   Set TLS version for handshake:
                       '1.2', '1.3' or 'any' for both (default: '1.2')
  -K,--tickets <mode>  Process TLS Session tickets and session resumption,
                       'on', 'off' or 'advertise', (default: 'off')
  -F,--keylogfile <f>  File to dump keys for traffic analysers
  -s,--sni <servernameindicator>  SNI to use for the given <ip>

127.0.0.1:443 address is used by default.

To list available ciphers on a remote peer use:
$ nmap --script ssl-enum-ciphers -p <PORT> <IP>

```

## Examples

Bechmark TLS v1.3 handshakes for 10 seconds through 8 threads with 100
concurrent connections in each tread:
```
./tls-perf -T 10 -l 100 -t 8 --tls 1.3 192.168.76.7 8081
```

Bechmark 100 handshakes, leave TLS version and cipher choice for OpenSSL:
```
./tls-perf -n 100 --tls any ::1 8081
```

## Run

**tls-perf** starts to establish new connections slowly and prints
```
( All peers are active, start to gather statistics )
```
This time all the requested peers managing all the requested connections are
active and **tls-perf** starts to gather statistics for the final report. Thus,
you might see smaller number for `MEASURES` than you saw per-second statistic
lines.

The slow start also warms up all the caches of the benchmarked system, so
you don't need to make additional load before the benchmark.

```
$ ./tls-perf -l 1000 -t 2 -T 10 192.168.100.4 443
Running TLS benchmark with following settings:
Host:        192.168.100.4 : 443
TLS version: 1.2
Cipher:      ECDHE-ECDSA-AES128-GCM-SHA256
TLS tickets: off
Duration:    3000

set open files limit to 2008
TLS hs in progress 252 [382 h/s], TCP open conns 252 [146 hs in progress], Errors 0
TLS hs in progress 400 [495 h/s], TCP open conns 400 [497 hs in progress], Errors 0
TLS hs in progress 549 [620 h/s], TCP open conns 549 [932 hs in progress], Errors 0
( All peers are active, start to gather statistics )
TLS hs in progress 834 [448 h/s], TCP open conns 834 [1071 hs in progress], Errors 0
TLS hs in progress 945 [548 h/s], TCP open conns 945 [1055 hs in progress], Errors 0
TLS hs in progress 908 [529 h/s], TCP open conns 908 [1092 hs in progress], Errors 0
TLS hs in progress 946 [603 h/s], TCP open conns 946 [1047 hs in progress], Errors 0
TLS hs in progress 969 [615 h/s], TCP open conns 969 [1031 hs in progress], Errors 0
TLS hs in progress 994 [618 h/s], TCP open conns 994 [1006 hs in progress], Errors 0
TLS hs in progress 941 [585 h/s], TCP open conns 941 [1059 hs in progress], Errors 0
========================================
 TOTAL:                  SECONDS 7; HANDSHAKES 5443
 MEASURES (seconds):     MAX h/s 618; AVG h/s 561; 95P h/s 448; MIN h/s 448
 LATENCY (microseconds): MIN 26; AVG 50; 95P 74; MAX 3945
```

`95P` parameters in resulting statistics show 95'th percentile: 95% of TLS
handshakes per second measurements are better than the number and 95% of TLS
handshakes require less microseconds than the number.
