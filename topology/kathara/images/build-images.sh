#!/bin/sh
# Build the four custom images used by the lab.
set -e
docker build -t re-lab/squid  images/squid
docker build -t re-lab/web    images/web
docker build -t re-lab/modsec images/modsec
docker build -t re-lab/dns    images/dns
echo "done. (kathara/frr and kathara/base are pulled automatically)"
