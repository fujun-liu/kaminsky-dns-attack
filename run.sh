#!/bin/bash

echo 'Running pacgen for kaminsky attack'

./pacgen -p dns_query_payload -t udp_header_query -i ip_header_query -e eth_header_query
