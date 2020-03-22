#!/usr/bin/env python3

import sys
import slimDNS

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(Usage {} local_addr local_host.format(sys.argv[0]))
        sys.exit(1)
    local_addr = sys.argv[1]
    local_host = sys.argv[2]
    server = slimDNS.SlimDNSServer(local_addr, local_host)
    server.run_forever()
