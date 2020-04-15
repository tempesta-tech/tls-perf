# TLS handshakes benchnarking tool

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
