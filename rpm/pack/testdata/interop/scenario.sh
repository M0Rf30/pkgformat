#!/bin/sh
# Installs and removes the packages in the current directory in a throwaway
# container, in the order that fires every trigger, and prints the log.
set -e
rm -f /tmp/order.log
rpm -i --nodeps --nosignature "$1"
echo "--- install bar" >> /tmp/order.log
rpm -i --nodeps --nosignature "$2"
echo "--- remove bar" >> /tmp/order.log
rpm -e bar
echo "--- remove trig" >> /tmp/order.log
rpm -e trig
cat /tmp/order.log
