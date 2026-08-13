# Qurion

**Post-Quantum Protection of Diameter S6a Authentication Vectors**

Qurion is a research-oriented LTE security framework focused on protecting **Diameter S6a authentication vectors** against future quantum-enabled attacks.

The project extends a practical LTE/EPC test environment with a post-quantum cryptographic protection mechanism at the **application layer**, allowing authentication vectors to remain protected even when Diameter traffic passes through trusted intermediary networks or agents.

The implementation is designed to operate alongside existing LTE infrastructure while minimizing changes to the underlying authentication procedure.

---

## Overview

In LTE roaming, authentication between the Mobility Management Entity (MME) and the Home Subscriber Server (HSS) uses the Diameter **S6a** interface.

The authentication procedure involves the exchange of Authentication-Information-Request (AIR) and Authentication-Information-Answer (AIA) messages. The AIA may contain authentication vectors required for authenticating the subscriber.

Although Diameter deployments can use transport-layer security mechanisms such as TLS or IPsec, roaming architectures may involve multiple trusted intermediaries.

Qurion investigates an additional protection layer that secures the **authentication-vector payload itself**, rather than relying solely on the security of the communication channel.

The project explores:

- Post-quantum key establishment
- Post-quantum digital signatures
- Application-layer protection of authentication vectors
- Compatibility with existing Diameter S6a procedures
- Protection across intermediary Diameter agents
- Certificate-based operator authentication
- Downgrade and capability detection
- Legacy fallback mechanisms

---

## Architecture

The experimental environment uses an LTE/EPC stack to reproduce the relevant S6a authentication workflow.

The environment can include components such as:

- HSS
- MME
- Diameter agents
- PCRF
- SGW-C
- SGW-U
- SMF
- UPF
- NRF
- srsRAN eNodeB
- srsRAN UE
- MongoDB

These components provide the surrounding LTE environment required to exercise and evaluate the proposed S6a protection mechanism.

The core research focus, however, is the protection of **Diameter S6a authentication vectors**, rather than the implementation of a complete LTE core network.

---

## Repository Structure

```text
qurion/
├── configs/
│   ├── freeDiameter/
│   ├── hss/
│   ├── mme/
│   ├── nrf/
│   ├── pcrf/
│   ├── smf/
│   ├── open5gs/
│   └── srsran/
│
├── docker/
│   ├── open5gs/
│   ├── open5gs-webui/
│   └── upf/
│
├── src/
│   ├── open5gs/
│   └── srsran/
│
├── scripts/
│
├── captures/
│
├── mongo/
│
├── docker-compose.yml
├── start.sh
├── .env.example
├── .gitignore
└── README.md
```

The `src/open5gs` and `src/srsran` directories contain source code used by the project and are maintained as Git submodules. Their generated build and installation directories are excluded from version control.

---

### Setup

### 1. Prerequisites

Qurion is intended to run on a Linux system with Docker support.

Install the following:

- Docker
- Docker Compose
- Git
- GNU Make
- CMake
- GCC/G++
- Internet connectivity for downloading dependencies and base images

Recommended system resources:

- 4+ CPU cores
- 8 GB+ RAM
- 20 GB+ available storage

Verify the installation:

```bash
docker --version
docker compose version
git --version
cmake --version
gcc --version
```

---

### 2. Clone the Repository

Clone the repository:

```bash
git clone <repository-url>
cd qurion
```

Initialize and download the required Git submodules:

```bash
git submodule update --init --recursive
```



---

### 3. Configure the Environment

Create the local environment configuration from the provided template:

```bash
cp .env.example .env
```

Review the configuration:

```bash
cat .env
```

The `.env` file contains the static Docker network addresses used by the LTE/EPC test environment.

A typical configuration contains:

```env
TEST_NETWORK=172.18.0.0/24

MONGO_IP=172.18.0.3
HSS_IP=172.18.0.4
NRF_IP=172.18.0.5
MME_IP=172.18.0.6
SMF_IP=172.18.0.7
SGWC_IP=172.18.0.8
SGWU_IP=172.18.0.9
UPF_IP=172.18.0.2
PCRF_IP=172.18.0.10
```

The actual values should match the addresses referenced by the configuration files under `configs/`.


---

### 4. Build the Open5GS and Web UI Images

The Open5GS-based services and Web UI are built locally from the repository.

Build them using:

```bash
docker compose build
```

To force a clean rebuild without using Docker's build cache:

```bash
docker compose build --no-cache
```
---

### 5. Build the srsRAN Images

The `srsenb` and `srsue` services use pre-built local Docker images:

```text
srsran_dia
srsue_dia
```

These images are not built by `docker compose build`, because the corresponding services use `image:` rather than `build:` in `docker-compose.yml`.

Build the required srsRAN images using the Dockerfiles and source provided by the project.

```bash
docker build -f docker/srsran/Dockerfile -t srsran_dia .
docker build -f docker/srsue/Dockerfile -t srsue_dia .
```

After building them, verify that both images are available locally:

```bash
docker images | grep -E 'srsran_dia|srsue_dia'
```

Both images must be present before starting the complete LTE test environment.

---

### 6. Start the Environment

The recommended way to start Qurion is through the provided startup script:

```bash
chmod +x start.sh
./start.sh
```

The startup script starts the required services in the appropriate order so that dependencies such as the HSS, MME and eNodeB are available before the UE attempts to attach.

The environment can also be started directly using Docker Compose:

```bash
docker compose up -d
```

However, `start.sh` is recommended for the complete LTE test workflow.

---

## Research Scope

The primary objective of Qurion is **not** to reproduce an entire production LTE network.

The LTE/EPC environment provides a realistic platform for evaluating the security mechanism under an actual Diameter S6a authentication workflow.

The research focuses on:

1. Protecting authentication vectors at the application layer.
2. Reducing exposure of authentication vectors to trusted intermediaries.
3. Applying post-quantum cryptography to the protection mechanism.
4. Maintaining compatibility with existing Diameter-based LTE infrastructure.
5. Evaluating the cryptographic and operational overhead introduced by the mechanism.
6. Detecting unsupported or downgraded security capabilities.

---



## Project Status

Qurion is an experimental research project investigating post-quantum protection for LTE Diameter S6a authentication vectors.

The surrounding LTE/EPC environment is used primarily as the testbed for evaluating the proposed mechanism.

The implementation and evaluation focus on the interaction between:

```text
LTE Authentication
        │
        ▼
Diameter S6a
        │
        ▼
Authentication Vectors
        │
        ▼
Post-Quantum Protection
        │
        ▼
Secure Authentication Exchange
```

---

