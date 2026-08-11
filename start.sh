#!/bin/bash

set -e

echo "Starting core network..."
docker compose up -d mongodb nrf hss upf sgwu sgwc smf pcrf mme

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