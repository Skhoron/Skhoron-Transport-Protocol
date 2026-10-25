STP — Skhoron Transport Protocol

A transport engine that determines which network to send a request through based on the URL
(clearnet / Tor / I2P), and actually connects through it.

Status

Network| Status
Tor| Works. SOCKS5 to local "tor" (127.0.0.1:9050)
I2P| Works. SOCKS5 to local "i2pd" (127.0.0.1:4447)
Clearnet| NOT implemented. "stream_open()" returns an explicit error
Skhoron| NOT implemented (and the Skhoron node network itself is not being built in this project)

Build

make        # build ./stp
make test   # run 34 unit tests for router.c

Usage

./stp https://example.com                    # dry-run by default
./stp --live http://xyz.onion                # actually connect through Tor