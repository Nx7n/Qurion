#!/bin/sh
set -e

# Start Open5GS UPF in background
/work/open5gs/build/src/upf/open5gs-upfd \
    -c /usr/local/etc/open5gs/upf.yaml &

UPF_PID=$!

# Wait for ogstun 
echo "Waiting for ogstun..."

while ! ip link show ogstun >/dev/null 2>&1; do
    sleep 1
done

echo "ogstun detected."

# UE gateway address
ip addr add 10.45.0.1/16 dev ogstun 2>/dev/null || true
ip link set ogstun up

echo "ogstun configured:"
ip addr show ogstun

wait $UPF_PID