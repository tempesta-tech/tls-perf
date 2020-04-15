# TLS handshakes benchnarking tool

A tool to stress test the TLS handshake by triggering processor intensive
cryptographic computations on the server side.

Inspired by [THC-SSL-DOS](https://thc.org/thc-ssl-dos/) tool (see the fork
of the originat tool at https://github.com/azet/thc-tls-dos). The key
differences from the THC tool are:

1. this benchmark does TLS handshake only and quickly resets TCP connection.
   It doesn't try to send or read any data or execute renegitiation.

2. this benchmark is multithreded and with better `epoll()` based IO, more
   efficient state machine and less looping. Multithreading is required for
   ECC handshakes with the cryptographic calculations more expensive on
   the client side than on the server side.
