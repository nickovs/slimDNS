# slimDNS: Simple, Lightweight Implementation of Multicast DNS

## Why slimDNS?

slimDNS is a pure Python implementation of multicast DNS (mDNS) and
DNS Service Discovery (DNS-SD) targeting memory-constrained devices
such as those running MicroPython. The goal of this project is to allow
MicroPython users to have their networked devices, and the services
that they offer, more easily discoverable.

slimDNS directly supports both advertising and discovery of hostnames
and it also can be used for the advertising and discovery of
services. It aims to be compliant with the parts of the mDNS and
DNS-SD specifications that it implements, even if it fails to
implement all features.

## Quick Start

In order to use slimDNS in the simplest possible way all that is necessary is to create a `SlimDNSServer` object with the local IP address and a hostname and tell the server to serve that address:

```Python
import network
import slimDNS
sta_if = network.WLAN(network.STA_IF)
local_addr = sta_if.ifconfig()[0]
server = SlimDNSServer(local_addr, "micropython")
server.run_forever()
```

Of course this isn't actually terribly useful, since without having _multithreading_ support you now can't do anything else. In practice a much more likely model is to create the `SlimDNSServer` object, find out its server socket and add this to the list of sockets that you are going to be checking with the `select` call in your own _runloop_. When data is avilable on the that socket you can call the `process_waiting_packets()` method to let the server do its stuff.

```Python
server = SlimDNSServer(local_addr, "micropython")
...
while (running):
    read_sockets = [server.sock, other_socket, ...]
    (r, _, _) = select(read_sockets, [], [])
    ...
    if server.sock in r:
      server.process_waiting_packets()

```

The `SlimDNSServer` object also supports lookup of names over mDNS using the `resolve_mdns_address()` method:

```Python
host_address_bytes = server.resolve_mdns_address("something.local")
```



## Design principles

Many devices running MicroPython have very small amounts of RAM. Such
devices are likely to only be offering a small set of services on a
single network interface. In order to support these devices the design
philosophy of slimDNS includes the following principles.

- The code should comply with the relevant mDNS and DNS-SD
  specifications wherever there is a "MUST" or "MUST NOT". If the
  specification says that an implementation "SHOULD" or "SHOULD NOT"
  do something then we will do it if we can do so with minimal memory
  footprint. Otherwise all bets are off and when in doubt we lean
  towards minimising memory footprint over most other criteria.

- Avoid duplication of data. Most packet handling is done using
  memoryview objects to avoid making copies of data.

- Don't keep data longer than strictly needed. This means that in
   general we don't cache things, especially if they can be
   reconstructed from data that we have to keep.

- Optimise for the core use cases. For instance while the user can use
  the existing code to construct the necessary packets for DNS-SD we do
  not provide a complete implementation since many users will not need
  this. Similarly, we do not provide a _runloop_ since if you are
  offering a network service you probably already have one.
