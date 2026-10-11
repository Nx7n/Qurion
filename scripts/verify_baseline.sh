#!/bin/bash
# verify_baseline.sh — Phase 1 Baseline S6a Connectivity Verification
#
# Checks Open5GS containers, verifies MME–HSS Diameter peering,
# and captures baseline S6a traffic.

set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
CAPTURE_DIR="captures"
BASELINE_PCAP="${CAPTURE_DIR}/s6a-baseline.pcap"
CAPTURE_SECONDS="${1:-30}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[✓]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

echo "================================================================="
echo " Phase 1 — Baseline S6a Verification"
echo "================================================================="
echo ""

# Step 1: Check Docker containers
echo "--- Step 1: Container Health Check ---"
REQUIRED_CONTAINERS="mongodb hss mme sgwc sgwu pcrf smf nrf"
ALL_UP=true

for svc in $REQUIRED_CONTAINERS; do
    if docker compose -f "$COMPOSE_FILE" ps --format '{{.Name}} {{.State}}' 2>/dev/null | grep -q "$svc.*running"; then
        pass "$svc is running"
    else
        fail "$svc is NOT running"
        ALL_UP=false
    fi
done

if [ "$ALL_UP" = false ]; then
    warn "Some containers are down. Start them with:"
    echo "  docker compose up -d mongodb nrf hss mme sgwc sgwu pcrf smf"
    echo ""
    warn "Continuing anyway to check what's available..."
fi
echo ""

# Step 2: Check Diameter connectivity between MME and HSS
echo "--- Step 2: Diameter S6a Peer State ---"

# Check HSS freeDiameter peer state
if docker exec hss test -f /work/open5gs/build/src/hss/open5gs-hssd 2>/dev/null; then
    pass "HSS binary exists"
else
    fail "HSS binary not found"
fi

if docker exec mme test -f /work/open5gs/build/src/mme/open5gs-mmed 2>/dev/null; then
    pass "MME binary exists"
else
    fail "MME binary not found"
fi

# Check if HSS and MME can reach each other on port 3868
HSS_IP=$(grep HSS_IP .env | cut -d= -f2)
MME_IP=$(grep MME_IP .env | cut -d= -f2)

echo "  HSS IP: $HSS_IP"
echo "  MME IP: $MME_IP"

if docker exec mme bash -c "echo > /dev/tcp/${HSS_IP}/3868" 2>/dev/null; then
    pass "MME can reach HSS on port 3868 (Diameter)"
else
    warn "MME cannot reach HSS on port 3868 (may still be starting)"
fi

if docker exec hss bash -c "echo > /dev/tcp/${MME_IP}/3868" 2>/dev/null; then
    pass "HSS can reach MME on port 3868 (Diameter)"
else
    warn "HSS cannot reach MME on port 3868 (may still be starting)"
fi
echo ""

# Step 3: Check HSS logs for Diameter peer connection
echo "--- Step 3: Diameter Peer Logs ---"
echo "  HSS recent logs (looking for Diameter peer state):"
docker logs hss --tail 20 2>&1 | grep -i -E "peer|diameter|connected|s6a|CER|CEA" | tail -5 || warn "No Diameter peer logs found in HSS"

echo ""
echo "  MME recent logs (looking for Diameter peer state):"
docker logs mme --tail 20 2>&1 | grep -i -E "peer|diameter|connected|s6a|CER|CEA" | tail -5 || warn "No Diameter peer logs found in MME"
echo ""

# Step 4: Capture baseline S6a traffic
echo "--- Step 4: Baseline Traffic Capture ---"
mkdir -p "$CAPTURE_DIR"

echo "  Capturing S6a traffic for ${CAPTURE_SECONDS}s to ${BASELINE_PCAP}..."
echo "  Filter: Diameter on port 3868 between HSS ($HSS_IP) and MME ($MME_IP)"

# Capture on the Docker network
docker exec -d mme bash -c "timeout ${CAPTURE_SECONDS} tcpdump -i any -w /captures/s6a-baseline.pcap 'port 3868' 2>/dev/null || true"

echo "  Waiting ${CAPTURE_SECONDS} seconds for capture..."
sleep "$CAPTURE_SECONDS"

# Copy the pcap out if it was captured inside the container
if docker cp mme:/captures/s6a-baseline.pcap "${BASELINE_PCAP}" 2>/dev/null; then
    PCAP_SIZE=$(stat -f%z "${BASELINE_PCAP}" 2>/dev/null || stat -c%s "${BASELINE_PCAP}" 2>/dev/null || echo "0")
    if [ "$PCAP_SIZE" -gt 0 ] 2>/dev/null; then
        pass "Baseline capture saved: ${BASELINE_PCAP} (${PCAP_SIZE} bytes)"
    else
        warn "Capture file is empty — no Diameter traffic detected during capture window"
    fi
else
    warn "Could not copy capture file — tcpdump may not have run"
    echo "  Try manually: docker exec mme tcpdump -i any -c 100 -w /tmp/s6a.pcap 'port 3868'"
fi

echo ""

# Step 5: Summary
echo "--- Step 5: Summary ---"
echo ""
if [ "$ALL_UP" = true ]; then
    pass "All required containers are running"
else
    fail "Some containers are not running"
fi

echo ""
echo "Next steps:"
echo "  1. If containers are down: docker compose up -d"
echo "  2. Register a test UE via WebUI at http://localhost:3000"
echo "     IMSI: 999700000000001, Key: 465B5CE8B199B49FAA5F0A2EE238A6BC"
echo "     OPc: E8ED289DEBA952E4283B54E88E6183CA"
echo "  3. Attach UE: docker compose up srsue"
echo "  4. Verify S6a AIR/AIA in the pcap: tshark -r ${BASELINE_PCAP} -Y diameter"
echo ""
echo "================================================================="
