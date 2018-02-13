# slimDNS: Simple, Lightweight Implementation of Multicast DNS

## Why slimDNS?

slimDNS is a pure Python implementation of multicast DNS (mDNS) and DNS Service
Discovery (DNS-SD) targetting memory-constrained devices such as those runing
MicroPython. It supports both advertising and discovery of hostnames and services
and aims to be compliant with the parts of the mDNS and DNS-SD specifications
that it implements, even if it fails to implement all features.

## Design principles

Many devices running MicroPython have very small amounts of RAM. Such devices
are likely to only be offering a very small set of services.

- Avoid duplication of data
- Don't keep data longer than needed
- Don't cache data that can be reconstructed
- Optimise for the limited cases.
