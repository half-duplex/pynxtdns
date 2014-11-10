# pynxtdns
A Python DNS to NXT API bridge

## Why
The hyperboria network doesn't really have DNS at the moment. Someone suggested using NXT (http://nxt.org/) as a backing, but the only existing bridge is in .NET which I don't like.

## NXT
NXT's "alias" functionality can be used as a key-value store. In this case, a domain name like uppit.hype would have an alias of type URI and name "4973uppit", and the value would be the IPv6 address of the site/node.

## Setup
Change the constants in pynxtdns.py to point to a NXT server web interface and run on the port/interface you want. I run the script behind a caching/forwarding bind9 server for my network.

### bind9
Here's my named.conf section to forward .hype lookups:
```
zone "hype" IN {
    type forward;
    forward only;
    forwarders { 127.0.0.1 port 1053; };
};
```

### systemd
Copy pynxtdns.service to /etc/systemd/system/ and adjust as necessary.
