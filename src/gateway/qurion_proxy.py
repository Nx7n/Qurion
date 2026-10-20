import asyncio
import logging
import yaml
import sys
import struct
import base64
import json
import os
import hashlib
import time
import uuid
from dataclasses import dataclass
from typing import Optional
from src.certificates.trust_store import TrustStore

from src.diameter.avp_codec import (
    DiameterMessage, DiameterAVP, AVPBuilder,
    AVP_AUTH_INFO, AVP_E_UTRAN_VECTOR,
    AVP_QURION_CAPABILITY, QURION_VENDOR_ID,
)
from src.gateway.hss_agent import HSSAgent
from src.gateway.mme_agent import MMEAgent
from src.telemetry.events import EventLogger, TelemetryEvent, EventType
from src.crypto.kem import generate_keypair as kem_keygen
from src.crypto.signatures import generate_signing_keypair as sig_keygen
from src.protocol.capability import (
    AlgorithmSuite, CapabilityFlags, CapabilityState, NegotiationAction,
    QurionCapability, decide_action,
)
from src.certificates.operator_cert import OperatorCertificate
from src.diameter.peer_cache import PeerCapabilityCache, PeerCacheEntry

# Defensive limits for incoming Diameter messages.
MAX_DIAMETER_MESSAGE_SIZE = 1024 * 1024  # 1 MiB
MESSAGE_READ_TIMEOUT = 120.0               # seconds per complete message

logger = logging.getLogger("qurion_proxy")

@dataclass
class QurionProxyConfig:
    listen_host: str
    listen_port: int
    upstream_host: str
    upstream_port: int
    mode: str
    operator_id: str
    realm: str
    peer_kem_pub: Optional[bytes] = None
    capability_enabled: bool = True
    require_qurion: bool = False

def negotiated_suite_name(local: QurionCapability | None, peer: QurionCapability) -> str | None:
    if local is None:
        return None
    params = local.negotiate(peer)
    return params.selected_suite.value if params else None


class QurionProxy:
    CER_CEA_COMMAND = 257
    REQUIRED_FLAGS = (
    CapabilityFlags.PROTECTED_AV
    | CapabilityFlags.OPERATOR_AUTH
    )

    def __init__(self, config: QurionProxyConfig, agent, event_logger: EventLogger,
                 local_capability: QurionCapability | None = None,
                 peer_certificate: OperatorCertificate | None = None,
                 peer_signing_pub: bytes | None = None):
        self.config = config
        self.agent = agent
        self.event_logger = event_logger
        self.local_capability = local_capability
        self.peer_certificate = peer_certificate
        self.peer_signing_pub = peer_signing_pub
        self.server = None
        # Process-local cache used to detect capability disappearance on reconnect.
        self.peer_capability_cache = PeerCapabilityCache(default_ttl=3600.0)
        # Keep a process-lifetime downgrade latch even after cache metadata expires.
        self.known_capable_peers: set[tuple[str, str]] = set()

    def _peer_key(self) -> tuple[str, str]:
        return (getattr(self.agent, "peer_operator_id", None) or "",
                getattr(self.agent, "peer_realm", None) or "")

    def _log_capability(self, event_type: EventType, *, success: bool, detail: str,
                        metadata: dict | None = None) -> None:
        peer = "@".join(x for x in self._peer_key() if x) or None
        self.event_logger.log(TelemetryEvent(
            event_type=event_type, timestamp=time.monotonic(), wall_clock=time.time(),
            correlation_id=str(uuid.uuid4()), peer_id=peer,
            metadata={"mode": self.config.mode, "detail": detail, **(metadata or {})},
            success=success,
        ))
        log_message = f"QURION_EVENT event={event_type.value} mode={self.config.mode} peer={peer or 'unknown'} detail={detail}"
        if success:
            logger.info(log_message)
        else:
            logger.warning(log_message)

    @staticmethod
    def _capability_avps(message: DiameterMessage) -> list[DiameterAVP]:
        return [a for a in message.avps
                if a.code == AVP_QURION_CAPABILITY and a.vendor_id == QURION_VENDOR_ID]

    def _origin_identity(self, message: DiameterMessage) -> tuple[str, str]:
        hosts = [a.data.decode("utf-8", errors="strict") for a in message.avps if a.code == 264]
        realms = [a.data.decode("utf-8", errors="strict") for a in message.avps if a.code == 296]
        if len(hosts) != 1 or len(realms) != 1 or not hosts[0] or not realms[0]:
            raise ValueError("CER/CEA must contain exactly one Origin-Host and Origin-Realm")
        return hosts[0], realms[0]

    def _validate_peer_capability(self, avp: DiameterAVP) -> QurionCapability:
        if self.peer_certificate is None or self.peer_signing_pub is None:
            raise ValueError("No pinned peer certificate/signing key configured")
        cap = QurionCapability.deserialize(avp.data)
        cert = self.peer_certificate
        fingerprint = hashlib.sha256(cert.serialize()).digest()
        if (cap.operator_id, cap.realm) != (cert.operator_id, cert.realm):
            raise ValueError("Capability identity does not match pinned peer certificate")
        if cap.cert_fingerprint != fingerprint:
            raise ValueError("Capability certificate fingerprint mismatch")
        if not cap.verify_signature(self.peer_signing_pub):
            raise ValueError("Capability signature verification failed")
        if self.local_capability is None:
            raise ValueError("Local Qurion capability is not configured")
        # Signature and identity are valid even if the peer advertises a
        # protocol/suite we cannot use; that is an UNSUPPORTED negotiation,
        # not a malformed or unauthenticated capability.
        return cap

    def _record_peer_capability(self, message: DiameterMessage, state: dict) -> None:
        caps = self._capability_avps(message)
        peer_key = self._peer_key()
        if len(caps) > 1:
            state["peer_state"] = CapabilityState.INVALID
            raise ValueError("Duplicate Qurion capability AVPs")
        if not caps:
            if self.config.require_qurion or (peer_key[0] and (
                peer_key in self.known_capable_peers
                or self.peer_capability_cache.is_known_peer(*peer_key)
            )):
                state["peer_state"] = CapabilityState.DOWNGRADE
                self._log_capability(EventType.PQC_DOWNGRADE_DETECTED, success=False,
                                     detail="Previously capable peer omitted capability AVP")
                raise ValueError("PQC downgrade detected")
            state["peer_state"] = CapabilityState.UNSUPPORTED
            self._log_capability(
                EventType.CAPABILITY_DOWNGRADE if self.config.capability_enabled else EventType.CAPABILITY_NEGOTIATION,
                success=not self.config.capability_enabled,
                detail="Peer did not advertise Qurion capability",
                metadata={"decision": "classical_fallback" if self.config.capability_enabled else "passthrough"},
            )
            return
        try:
            cap = self._validate_peer_capability(caps[0])
            if self._origin_identity(message) != (cap.operator_id, cap.realm):
                raise ValueError("Diameter Origin-Host/Origin-Realm do not match capability identity")
        except Exception as exc:
            state["peer_state"] = CapabilityState.INVALID
            self._log_capability(EventType.CAPABILITY_INVALID, success=False, detail=str(exc))
            raise ValueError("Invalid or untrusted peer capability") from exc
        state["peer_capability"] = cap
        params = self.local_capability.negotiate(cap) if self.local_capability else None
        compatible = (
            params is not None
            and (params.flags & self.REQUIRED_FLAGS) == self.REQUIRED_FLAGS
        )
        self.known_capable_peers.add((cap.operator_id, cap.realm))
        self.peer_capability_cache.update(PeerCacheEntry(
            operator_id=cap.operator_id,
            realm=cap.realm,
            protocol_versions=[cap.protocol_version],
            supported_suites=[suite.value if isinstance(suite, AlgorithmSuite) else str(suite)
                              for suite in cap.supported_suites],
            last_negotiation=time.time(),
            key_id=None,
            cert_fingerprint=cap.cert_fingerprint,
            created_at=time.time(),
            expires_at=time.time() + 3600.0,
        ))
        if self.config.capability_enabled and compatible:
            state["peer_state"] = CapabilityState.SUPPORTED
            self._log_capability(EventType.CAPABILITY_NEGOTIATION, success=True,
                                 detail="Qurion capability validated and negotiated",
                                 metadata={"suite": negotiated_suite_name(self.local_capability, cap)})
        elif self.config.capability_enabled:
            state["peer_state"] = CapabilityState.UNSUPPORTED
            self._log_capability(EventType.CAPABILITY_DOWNGRADE, success=False,
                                 detail="Peer capability is valid but no compatible suite/required flags exist",
                                 metadata={"decision": "classical_fallback"})
        else:
            state["peer_state"] = CapabilityState.UNSUPPORTED
            self._log_capability(EventType.CAPABILITY_DOWNGRADE, success=False,
                                 detail="Local Qurion capability is disabled",
                                 metadata={"decision": "classical_fallback"})

    def _prepare_capability_message(self, message: DiameterMessage, direction: str, state: dict) -> None:
        if message.command_code != 257 or message.application_id != 0:
            return
        is_cap = lambda a: a.code == AVP_QURION_CAPABILITY and a.vendor_id == QURION_VENDOR_ID
        if message.is_request and direction == "client->upstream":
            if self.config.mode == "mme":
                # Replace any client-supplied extension with our own signed advertisement.
                message.avps = [a for a in message.avps if not is_cap(a)]
                if self.config.capability_enabled and self.local_capability:
                    message.avps.append(AVPBuilder.build_capability_avp(self.local_capability.serialize()))
                state["cer_seen"] = True
            elif self.config.mode == "hss":
                self._record_peer_capability(message, state)
        elif not message.is_request and direction == "upstream->client":
            if self.config.mode == "hss":
                message.avps = [a for a in message.avps if not is_cap(a)]
                if (self.config.capability_enabled and self.local_capability
                        and state.get("peer_state") is CapabilityState.SUPPORTED):
                    message.avps.append(AVPBuilder.build_capability_avp(self.local_capability.serialize()))
            elif self.config.mode == "mme":
                self._record_peer_capability(message, state)

    async def handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        client_addr = client_writer.get_extra_info('peername')
        logger.info(f"[{self.config.mode.upper()}] Client connected from {client_addr}")
        
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                self.config.upstream_host, self.config.upstream_port
            )
            logger.info(f"[{self.config.mode.upper()}] Connected upstream to {self.config.upstream_host}:{self.config.upstream_port}")
        except Exception as e:
            logger.error(f"[{self.config.mode.upper()}] Failed to connect upstream: {e}")
            client_writer.close()
            await client_writer.wait_closed()
            return

        connection_state = {"peer_state": CapabilityState.UNSUPPORTED, "peer_capability": None, "cer_seen": False}

        async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, direction: str):
            try:
                while True:
                     # Read and validate one complete Diameter message.
                    async def read_diameter_message():
                        header = await reader.readexactly(20)

                        # Diameter Message Length occupies bytes 1–3.
                        msg_len = int.from_bytes(header[1:4], "big")

                        if msg_len < 20:
                            raise ValueError(
                                f"Invalid Diameter message length: {msg_len}"
                            )

                        if msg_len > MAX_DIAMETER_MESSAGE_SIZE:
                            raise ValueError(
                                f"Diameter message exceeds limit: "
                                f"{msg_len} bytes"
                            )

                        body = await reader.readexactly(msg_len - 20)
                        return header + body

                    try:
                        raw_msg = await asyncio.wait_for(
                            read_diameter_message(),
                            timeout=MESSAGE_READ_TIMEOUT,
                        )
                    except asyncio.TimeoutError:
                        logger.warning(
                            "Timed out reading Diameter message from %s",
                            direction,
                        )
                        break
                    except asyncio.IncompleteReadError:
                        # EOF or a truncated header/body.
                        logger.warning(
                            "Incomplete Diameter message from %s",
                            direction,
                        )
                        break
                    except ValueError as exc:
                        logger.warning(
                            "Rejecting invalid Diameter message from %s: %s",
                            direction,
                            exc,
                        )
                        break

                   
                    # Decode before forwarding. Never forward malformed
                    # Diameter messages unchanged.
                    try:
                        diam_msg = DiameterMessage.decode(raw_msg)
                    except Exception as exc:
                        logger.warning(
                            "Dropping undecodable Diameter message (%s)",
                            type(exc).__name__,
                        )
                        break

                    if diam_msg.command_code == self.CER_CEA_COMMAND and diam_msg.application_id == 0:
                        try:
                            self._prepare_capability_message(diam_msg, direction, connection_state)
                            raw_msg = diam_msg.encode()
                        except Exception as exc:
                            logger.error("CER/CEA capability negotiation failed; dropping connection (%s)", type(exc).__name__)
                            break

                    is_s6a_aia = (
                        diam_msg.command_code == 318
                        and diam_msg.application_id == 16777251
                        and not diam_msg.is_request
                    )

                    must_process_aia = (
                        is_s6a_aia
                        and direction == "upstream->client"
                        and self.config.mode in ("hss", "mme")
                    )

                    if must_process_aia:
                        peer_state = connection_state.get("peer_state", CapabilityState.UNSUPPORTED)
                        action = decide_action(self.config.capability_enabled, peer_state)
                        protected_present = any(
                            a.code == 1002 and a.vendor_id == QURION_VENDOR_ID
                            for a in diam_msg.avps
                        )
                        if action is NegotiationAction.REJECT:
                            logger.error("Refusing AIA under invalid/downgraded capability state")
                            break
                        if action in (NegotiationAction.FALLBACK, NegotiationAction.PASSTHROUGH):
                            if protected_present:
                                logger.error("Protected AIA received without successful capability negotiation")
                                break
                            logger.info("AIA passed through using %s policy", action.value)
                        else:
                            try:
                                if self.config.mode == "hss":
                                    if not self.config.peer_kem_pub:
                                        raise ValueError("Peer KEM public key is unavailable")
                                    diam_msg = self.agent.process_outgoing_aia(diam_msg, self.config.peer_kem_pub)
                                else:
                                    diam_msg = self.agent.process_incoming_aia(diam_msg)
                                raw_msg = diam_msg.encode()
                                logger.info("S6a AIA processing succeeded in %s mode", self.config.mode.upper())
                            except Exception as exc:
                                logger.error("S6a AIA security processing failed; dropping message (%s)", type(exc).__name__)
                                break

                    # Reached only after successful decoding and, when
                    # required, successful protection or verification.
                    writer.write(raw_msg)
                    await writer.drain()


            except asyncio.IncompleteReadError:
                pass
            except ConnectionResetError:
                pass
            except Exception as e:
                logger.error(f"Pipe error in {direction}: {e}")
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

       
        pipe_tasks = [
            asyncio.create_task(
                pipe(client_reader, upstream_writer, "client->upstream")
            ),
            asyncio.create_task(
                pipe(upstream_reader, client_writer, "upstream->client")
            ),
        ]

        try:
            await asyncio.wait(
                pipe_tasks,
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            for task in pipe_tasks:
                if not task.done():
                    task.cancel()

            await asyncio.gather(*pipe_tasks, return_exceptions=True)

            for writer in (client_writer, upstream_writer):
                writer.close()

            await asyncio.gather(
                client_writer.wait_closed(),
                upstream_writer.wait_closed(),
                return_exceptions=True,
            )


    async def start(self):
        self.server = await asyncio.start_server(
            self.handle_client, self.config.listen_host, self.config.listen_port
        )
        addrs = ', '.join(str(sock.getsockname()) for sock in self.server.sockets)
        logger.info(f"Qurion [{self.config.mode.upper()}] proxy listening on {addrs}")
        async with self.server:
            await self.server.serve_forever()

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("Proxy server stopped.")

def load_keys(role: str, qurion_dir: str):
    key_file = os.path.join(qurion_dir, f"{role}_keys.json")
    if not os.path.exists(key_file):
        raise FileNotFoundError(f"Key file {key_file} not found. Run scripts/generate_keys.py first.")
    with open(key_file, "r") as f:
        data = json.load(f)
    return {
        "kem_pub": base64.b64decode(data["kem_public_key"]),
        "kem_priv": base64.b64decode(data["kem_secret_key"]),
        "sign_pub": base64.b64decode(data["signing_public_key"]),
        "sign_priv": base64.b64decode(data["signing_secret_key"]),
        "operator_id": data["operator_id"],
        "realm": data["realm"]
    }


def load_pinned_certificate(role: str, cert_dir: str, keys: dict) -> OperatorCertificate:
    cert_path = os.path.join(cert_dir, f"{role}_operator_cert.json")
    if not os.path.isfile(cert_path):
        raise FileNotFoundError(f"Pinned operator certificate not found: {cert_path}")
    with open(cert_path, "rb") as f:
        cert = OperatorCertificate.deserialize(f.read())
    if (not cert.is_valid() or cert.issuer_id != cert.operator_id
            or not cert.verify_signature(cert.signing_pub)
            or not cert.check_key_usage("SIGNING")
            or not cert.check_key_usage("KEM")):
        raise ValueError(f"Invalid or untrusted self-signed operator certificate: {cert_path}")
    if (cert.operator_id, cert.realm) != (keys["operator_id"], keys["realm"]):
        raise ValueError(f"Certificate identity mismatch for {role}")
    if cert.signing_pub != keys["sign_pub"] or cert.kem_pub != keys["kem_pub"]:
        raise ValueError(f"Certificate public keys do not match {role} key configuration")
    return cert

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Qurion Post-Quantum S6a Proxy")
    parser.add_argument("--config", default="configs/qurion/proxy.yaml", help="Path to proxy configuration")
    parser.add_argument("--mode", choices=["hss", "mme"], required=True, help="Proxy mode: hss or mme")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    with open(args.config, 'r') as f:
        conf_data = yaml.safe_load(f)

    mode_conf = conf_data.get(args.mode)
    if not mode_conf:
        logger.error(f"Configuration for mode '{args.mode}' not found.")
        sys.exit(1)

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    qurion_dir = os.path.join(project_root, "configs", "qurion")
    
    local_keys = load_keys(args.mode, qurion_dir)
    peer_mode = "mme" if args.mode == "hss" else "hss"
    peer_keys = load_keys(peer_mode, qurion_dir)
    cert_dir = os.path.join(project_root, "configs", "certificates")
    local_cert = load_pinned_certificate(args.mode, cert_dir, local_keys)
    peer_cert = load_pinned_certificate(peer_mode, cert_dir, peer_keys)

    # Build the trust store from certificates that have already passed
    # startup pinning and key-configuration validation.
    trusted_issuers = {
        local_cert.operator_id: local_cert.signing_pub,
        peer_cert.operator_id: peer_cert.signing_pub,
    }

    trust_store = TrustStore(trusted_issuers=trusted_issuers)

    for cert in (local_cert, peer_cert):
        if not trust_store.add_trusted_certificate(cert):
            raise ValueError(
                f"Failed to register trusted operator certificate: "
                f"{cert.operator_id}@{cert.realm}"
            )

    # Confirm both identities are available for their required operations.
    if trust_store.verify_peer(
        peer_cert.operator_id, peer_cert.realm, "SIGNING"
    ) is None:
        raise ValueError("Peer certificate failed signing trust validation")

    if trust_store.verify_peer(
        peer_cert.operator_id, peer_cert.realm, "KEM"
    ) is None:
        raise ValueError("Peer certificate failed KEM trust validation")

    local_capability = QurionCapability(
        supported_suites=[AlgorithmSuite.QURION_V1],
        flags=(CapabilityFlags.PROTECTED_AV | CapabilityFlags.OPERATOR_AUTH ),
        operator_id=local_keys["operator_id"], realm=local_keys["realm"],
        cert_fingerprint=hashlib.sha256(local_cert.serialize()).digest(),
    )
    local_capability.sign(local_keys["sign_priv"])

    config = QurionProxyConfig(
        listen_host=mode_conf['listen_host'],
        listen_port=mode_conf['listen_port'],
        upstream_host=mode_conf['upstream_host'],
        upstream_port=mode_conf['upstream_port'],
        mode=args.mode,
        operator_id=local_keys["operator_id"],
        realm=local_keys["realm"],
        peer_kem_pub=peer_keys["kem_pub"],
        capability_enabled=bool(mode_conf.get("capability_enabled", True)),
        require_qurion=bool(mode_conf.get("require_qurion", False)),
    )

    event_logger = EventLogger()

    if args.mode == 'hss':
        agent = HSSAgent(
            config.operator_id,
            config.realm,
            local_keys["sign_priv"],
            local_keys["sign_pub"],
            local_keys["kem_priv"],
            local_keys["kem_pub"],
            trust_store, None, None,
            peer_operator_id=peer_keys["operator_id"],
            peer_realm=peer_keys["realm"],
        )
    else:
        agent = MMEAgent(
            config.operator_id,
            config.realm,
            local_keys["sign_priv"],
            local_keys["sign_pub"],
            local_keys["kem_priv"],
            local_keys["kem_pub"],
            trust_store, None, None,
            peer_operator_id=peer_keys["operator_id"],
            peer_realm=peer_keys["realm"],
            peer_signing_pub=peer_keys["sign_pub"],
        )

    proxy = QurionProxy(
        config, agent, event_logger, local_capability=local_capability,
        peer_certificate=peer_cert, peer_signing_pub=peer_cert.signing_pub,
    )

    try:
        asyncio.run(proxy.start())
    except KeyboardInterrupt:
        logger.info("Proxy shutting down...")

if __name__ == "__main__":
    main()
