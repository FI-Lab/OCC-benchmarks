#!/bin/bash

perf stat -e L1-dcache-load-misses -e L1-dcache-loads -e cpu-cycles -e cache-misses -e cache-references ./OCC-benchmarks_app -i pktio_0,pktio_16 -r /root/open-estuary/packages.bak/odp/odp1.2/example/OCC-benchmarks/dt_search/rules/acl2_2_0.5_-0.1_1K -l /root/open-estuary/packages.bak/odp/odp1.2/example/OCC-benchmarks/acl21K.fib -k /root/open-estuary/packages.bak/odp/odp1.2/example/OCC-benchmarks/ac/snort-key
