#!/bin/bash
set -e

cd /work/open5gs

# Configure only once
if [ ! -f build/build.ninja ]; then
    meson setup build
fi

# Build any changed source files
ninja -C build

# Install runtime files (TLS, configs, binaries)
ninja -C build install

exec "$@"