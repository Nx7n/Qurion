FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    LD_LIBRARY_PATH=/usr/local/lib

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build git pkg-config libssl-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# liboqs-python is a Python binding; build the native liboqs library in the image
# so the runtime does not need to download or compile crypto dependencies.
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
 && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_BUILD_ONLY_LIB=ON \
 && cmake --build /tmp/liboqs/build --parallel 2 \
 && cmake --install /tmp/liboqs/build \
 && ldconfig \
 && rm -rf /tmp/liboqs

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY src/crypto/ /app/src/crypto/
COPY src/diameter/ /app/src/diameter/
COPY src/gateway/ /app/src/gateway/
COPY src/protocol/ /app/src/protocol/
COPY src/telemetry/ /app/src/telemetry/

CMD ["python", "src/gateway/qurion_proxy.py", "--help"]
