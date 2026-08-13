#!/bin/bash

set -e

echo "Starting MongoDB..."
docker compose up -d mongodb

echo ""
echo "Waiting for MongoDB..."
until docker exec mongodb mongosh --quiet --eval 'db.adminCommand("ping").ok' 2>/dev/null | grep -q 1; do
    sleep 2
done

echo ""
echo "MongoDB ready"


echo "Starting core network..."
docker compose up -d nrf hss upf sgwu sgwc smf pcrf mme

echo ""
echo "Waiting for core..."
sleep 5

echo ""
echo "Starting srsENB..."
docker compose up -d srsenb

echo ""
echo "Wait for eNB..."
sleep 5

echo ""
echo "Starting srsUE..."
docker compose up -d srsue

echo ""
echo "======== LTE CORE + eNB + UE started ========"