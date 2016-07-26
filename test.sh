#!/bin/bash
./OCC_fwd_app -i pktio_0 -r ./dt_search/rules/acl3_2_0.5_-0.1_10K -l ./acl310K.fib -k ./ac/snort-key -c 0,8
wc paddr/*
