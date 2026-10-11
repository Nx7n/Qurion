import hashlib
from dataclasses import dataclass
import asyncio

import pytest

from src.crypto.signatures import generate_signing_keypair
from src.diameter.avp_codec import DiameterMessage, DiameterAVP, AVPBuilder, AVP_QURION_CAPABILITY, QURION_VENDOR_ID
from src.gateway.qurion_proxy import QurionProxy, QurionProxyConfig
from src.protocol.capability import (
    AlgorithmSuite, CapabilityFlags, CapabilityState, NegotiationAction,
    QurionCapability, decide_action,
)
from src.telemetry.events import EventLogger, EventType


@dataclass
class FakeCertificate:
    operator_id: str
    realm: str
    raw: bytes

    def serialize(self) -> bytes:
        return self.raw


class DummyAgent:
    def __init__(self, peer_operator_id: str, peer_realm: str = "localdomain"):
        self.peer_operator_id = peer_operator_id
        self.peer_realm = peer_realm


def make_capability(operator_id: str, realm: str = "localdomain"):
    public_key, private_key = generate_signing_keypair()
    cert = FakeCertificate(operator_id, realm, f"pinned:{operator_id}@{realm}".encode())
    cap = QurionCapability(
        supported_suites=[AlgorithmSuite.QURION_V1],
        flags=(CapabilityFlags.PROTECTED_AV | CapabilityFlags.KEY_EXCHANGE | CapabilityFlags.OPERATOR_AUTH),
        operator_id=operator_id,
        realm=realm,
        cert_fingerprint=hashlib.sha256(cert.serialize()).digest(),
    )
    cap.sign(private_key)
    return cap, public_key, private_key, cert


def origin_avps(operator_id: str, realm: str = "localdomain"):
    return [
        DiameterAVP(264, 0x40, None, operator_id.encode()),
        DiameterAVP(296, 0x40, None, realm.encode()),
    ]


def make_proxy(mode, local_cap, peer_cap, peer_pub, peer_cert, enabled=True):
    config = QurionProxyConfig(
        listen_host="127.0.0.1", listen_port=0,
        upstream_host="127.0.0.1", upstream_port=0,
        mode=mode, operator_id=local_cap.operator_id,
        realm=local_cap.realm, capability_enabled=enabled,
    )
    agent = DummyAgent(peer_cap.operator_id, peer_cap.realm)
    return QurionProxy(
        config, agent, EventLogger(), local_capability=local_cap,
        peer_certificate=peer_cert, peer_signing_pub=peer_pub,
    )


def test_signed_capability_round_trip_and_tamper_rejection():
    cap, public_key, _, _ = make_capability("mme.localdomain")
    decoded = QurionCapability.deserialize(cap.serialize())
    assert decoded.verify_signature(public_key)
    decoded.realm = "attacker.invalid"
    assert not decoded.verify_signature(public_key)


def test_three_state_policy_mapping():
    assert decide_action(True, CapabilityState.SUPPORTED) is NegotiationAction.PROTECT
    assert decide_action(True, CapabilityState.UNSUPPORTED) is NegotiationAction.FALLBACK
    assert decide_action(False, CapabilityState.UNSUPPORTED) is NegotiationAction.PASSTHROUGH
    assert decide_action(True, CapabilityState.DOWNGRADE) is NegotiationAction.REJECT
    assert decide_action(True, CapabilityState.INVALID) is NegotiationAction.REJECT



def test_capability_negotiation_over_cer_cea_path():
    hss_cap, hss_pub, _, hss_cert = make_capability("hss.localdomain")
    mme_cap, mme_pub, _, mme_cert = make_capability("mme.localdomain")

    mme_proxy = make_proxy("mme", mme_cap, hss_cap, hss_pub, hss_cert)
    hss_proxy = make_proxy("hss", hss_cap, mme_cap, mme_pub, mme_cert)

    mme_state = {"peer_state": CapabilityState.UNSUPPORTED}
    hss_state = {"peer_state": CapabilityState.UNSUPPORTED}

    # MME creates CER and advertises its signed capability.
    cer = DiameterMessage(
        command_code=257,
        application_id=0,
        is_request=True,
        avps=origin_avps("mme.localdomain"),
    )

    mme_proxy._prepare_capability_message(
        cer, "client->upstream", mme_state
    )

    cer_caps = [
        avp for avp in cer.avps
        if avp.code == AVP_QURION_CAPABILITY
        and avp.vendor_id == QURION_VENDOR_ID
    ]
    assert len(cer_caps) == 1

    advertised_mme = QurionCapability.deserialize(cer_caps[0].data)
    assert advertised_mme.operator_id == "mme.localdomain"
    assert advertised_mme.verify_signature(mme_pub)

    # HSS receives and validates the MME's CER capability.
    hss_proxy._prepare_capability_message(
        cer, "client->upstream", hss_state
    )
    assert hss_state["peer_state"] is CapabilityState.SUPPORTED
    assert hss_state["peer_capability"].operator_id == "mme.localdomain"

    # HSS creates CEA and advertises its own capability.
    cea = DiameterMessage(
        command_code=257,
        application_id=0,
        is_request=False,
        avps=origin_avps("hss.localdomain"),
    )

    hss_proxy._prepare_capability_message(
        cea, "upstream->client", hss_state
    )

    cea_caps = [
        avp for avp in cea.avps
        if avp.code == AVP_QURION_CAPABILITY
        and avp.vendor_id == QURION_VENDOR_ID
    ]
    assert len(cea_caps) == 1

    advertised_hss = QurionCapability.deserialize(cea_caps[0].data)
    assert advertised_hss.operator_id == "hss.localdomain"
    assert advertised_hss.verify_signature(hss_pub)

    # MME receives CEA and validates HSS's capability.
    mme_proxy._prepare_capability_message(
        cea, "upstream->client", mme_state
    )

    assert mme_state["peer_state"] is CapabilityState.SUPPORTED
    assert mme_state["peer_capability"].operator_id == "hss.localdomain"

    assert (
        mme_state["peer_capability"].negotiate(mme_cap).selected_suite
        == AlgorithmSuite.QURION_V1
    )
    assert (
        hss_state["peer_capability"].negotiate(hss_cap).selected_suite
        == AlgorithmSuite.QURION_V1
    )



def test_missing_capability_falls_back_first_time_then_detects_downgrade():
    peer_cap, peer_pub, _, peer_cert = make_capability("mme.localdomain")
    local_cap, _, _, _ = make_capability("hss.localdomain")
    proxy = make_proxy("hss", local_cap, peer_cap, peer_pub, peer_cert)

    first_state = {"peer_state": CapabilityState.UNSUPPORTED}
    empty_cer = DiameterMessage(command_code=257, application_id=0, is_request=True)
    proxy._record_peer_capability(empty_cer, first_state)
    assert first_state["peer_state"] is CapabilityState.UNSUPPORTED
    assert decide_action(True, first_state["peer_state"]) is NegotiationAction.FALLBACK

    # A valid advertisement establishes the peer as known-capable.
    good_cer = DiameterMessage(command_code=257, application_id=0, is_request=True,
                               avps=origin_avps("mme.localdomain") + [AVPBuilder.build_capability_avp(peer_cap.serialize())])
    proxy._record_peer_capability(good_cer, {"peer_state": CapabilityState.UNSUPPORTED})

    later_state = {"peer_state": CapabilityState.UNSUPPORTED}
    with pytest.raises(ValueError, match="downgrade"):
        proxy._record_peer_capability(empty_cer, later_state)
    assert later_state["peer_state"] is CapabilityState.DOWNGRADE
    assert proxy.event_logger.get_events(EventType.PQC_DOWNGRADE_DETECTED)


def test_invalid_signature_is_not_treated_as_legacy_fallback():
    peer_cap, peer_pub, _, peer_cert = make_capability("mme.localdomain")
    local_cap, _, _, _ = make_capability("hss.localdomain")
    peer_cap.signature = b"\x00" * len(peer_cap.signature)
    proxy = make_proxy("hss", local_cap, peer_cap, peer_pub, peer_cert)
    state = {"peer_state": CapabilityState.UNSUPPORTED}
    message = DiameterMessage(command_code=257, application_id=0, is_request=True,
                              avps=origin_avps("mme.localdomain") + [AVPBuilder.build_capability_avp(peer_cap.serialize())])
    with pytest.raises(ValueError, match="Invalid or untrusted"):
        proxy._record_peer_capability(message, state)
    assert state["peer_state"] is CapabilityState.INVALID
    assert proxy.event_logger.get_events(EventType.CAPABILITY_INVALID)


def test_valid_but_incompatible_suite_falls_back_instead_of_being_malformed():
    peer_cap, peer_pub, peer_priv, peer_cert = make_capability("mme.localdomain")
    peer_cap.supported_suites = ["QURION-FUTURE-SUITE"]
    peer_cap.signature = b""
    peer_cap.sign(peer_priv)
    local_cap, _, _, _ = make_capability("hss.localdomain")
    proxy = make_proxy("hss", local_cap, peer_cap, peer_pub, peer_cert)
    state = {"peer_state": CapabilityState.UNSUPPORTED}
    message = DiameterMessage(
        command_code=257, application_id=0, is_request=True,
        avps=origin_avps("mme.localdomain") + [AVPBuilder.build_capability_avp(peer_cap.serialize())],
    )
    proxy._record_peer_capability(message, state)
    assert state["peer_state"] is CapabilityState.UNSUPPORTED
    assert decide_action(True, state["peer_state"]) is NegotiationAction.FALLBACK


def test_required_qurion_policy_rejects_missing_capability_on_first_contact():
    peer_cap, peer_pub, _, peer_cert = make_capability("mme.localdomain")
    local_cap, _, _, _ = make_capability("hss.localdomain")
    proxy = make_proxy("hss", local_cap, peer_cap, peer_pub, peer_cert)
    proxy.config.require_qurion = True
    state = {"peer_state": CapabilityState.UNSUPPORTED}
    with pytest.raises(ValueError, match="downgrade"):
        proxy._record_peer_capability(
            DiameterMessage(command_code=257, application_id=0, is_request=True), state
        )
    assert state["peer_state"] is CapabilityState.DOWNGRADE



def test_handle_client_tcp_cer_cea_capability_exchange():
    """Exercise signed CER/CEA negotiation through both real TCP proxy paths."""

    async def scenario():
        hss_cap, hss_pub, _, hss_cert = make_capability("hss.localdomain")
        mme_cap, mme_pub, _, mme_cert = make_capability("mme.localdomain")

        hss_proxy = make_proxy(
            "hss", hss_cap, mme_cap, mme_pub, mme_cert
        )
        mme_proxy = make_proxy(
            "mme", mme_cap, hss_cap, hss_pub, hss_cert
        )

        backend_seen = {}

        async def read_diameter_message(reader):
            header = await reader.readexactly(20)
            length = int.from_bytes(header[1:4], "big")

            assert 20 <= length <= 1024 * 1024
            body = await reader.readexactly(length - 20)

            return DiameterMessage.decode(header + body)

        async def mock_hss_backend(reader, writer):
            try:
                cer = await read_diameter_message(reader)
                backend_seen["cer"] = cer

                # The mock HSS returns its ordinary CEA. The HSS proxy
                # must add its capability after validating the MME's CER.
                cea = DiameterMessage(
                    command_code=257,
                    application_id=0,
                    is_request=False,
                    avps=origin_avps("hss.localdomain"),
                )

                writer.write(cea.encode())
                await writer.drain()

                # Keep the connection alive until the test client closes.
                await reader.read()
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        backend_server = await asyncio.start_server(
            mock_hss_backend, "127.0.0.1", 0
        )
        backend_port = backend_server.sockets[0].getsockname()[1]

        hss_proxy.config.upstream_host = "127.0.0.1"
        hss_proxy.config.upstream_port = backend_port

        hss_server = None
        mme_server = None
        client_writer = None

        try:
            hss_server = await asyncio.start_server(
                hss_proxy.handle_client, "127.0.0.1", 0
            )
            hss_port = hss_server.sockets[0].getsockname()[1]

            mme_proxy.config.upstream_host = "127.0.0.1"
            mme_proxy.config.upstream_port = hss_port

            mme_server = await asyncio.start_server(
                mme_proxy.handle_client, "127.0.0.1", 0
            )
            mme_port = mme_server.sockets[0].getsockname()[1]

            client_reader, client_writer = await asyncio.open_connection(
                "127.0.0.1", mme_port
            )

            # Send a real encoded CER through the MME proxy.
            cer = DiameterMessage(
                command_code=257,
                application_id=0,
                is_request=True,
                avps=origin_avps("mme.localdomain"),
            )
            client_writer.write(cer.encode())
            await client_writer.drain()

            # Read the CEA forwarded back through both proxies.
            cea = await asyncio.wait_for(
                read_diameter_message(client_reader),
                timeout=3.0,
            )

            assert cea.command_code == 257
            assert cea.application_id == 0
            assert cea.is_request is False

            # Confirm the mock HSS received the MME proxy's advertisement.
            forwarded_cer = backend_seen["cer"]
            mme_caps = [
                avp for avp in forwarded_cer.avps
                if avp.code == AVP_QURION_CAPABILITY
                and avp.vendor_id == QURION_VENDOR_ID
            ]
            assert len(mme_caps) == 1

            advertised_mme = QurionCapability.deserialize(
                mme_caps[0].data
            )
            assert advertised_mme.operator_id == "mme.localdomain"
            assert advertised_mme.verify_signature(mme_pub)

            # Confirm the HSS proxy added its own advertisement to the CEA.
            hss_caps = [
                avp for avp in cea.avps
                if avp.code == AVP_QURION_CAPABILITY
                and avp.vendor_id == QURION_VENDOR_ID
            ]
            assert len(hss_caps) == 1

            advertised_hss = QurionCapability.deserialize(
                hss_caps[0].data
            )
            assert advertised_hss.operator_id == "hss.localdomain"
            assert advertised_hss.verify_signature(hss_pub)

            # The HSS only advertises its capability after accepting the
            # MME's capability; receiving it at the client also confirms
            # that the MME proxy accepted and forwarded the CEA.
            hss_events = hss_proxy.event_logger.get_events(
                EventType.CAPABILITY_NEGOTIATION
            )
            mme_events = mme_proxy.event_logger.get_events(
                EventType.CAPABILITY_NEGOTIATION
            )

            assert any(
                event.success
                and event.metadata.get("detail")
                == "Qurion capability validated and negotiated"
                for event in hss_events
            )
            assert any(
                event.success
                and event.metadata.get("detail")
                == "Qurion capability validated and negotiated"
                for event in mme_events
            )

        finally:
            if client_writer is not None:
                client_writer.close()
                try:
                    await client_writer.wait_closed()
                except Exception:
                    pass

            for server in (mme_server, hss_server, backend_server):
                if server is not None:
                    server.close()

            for server in (mme_server, hss_server, backend_server):
                if server is not None:
                    await server.wait_closed()

    asyncio.run(scenario())



def test_tcp_reconnect_without_capability_is_rejected():
    """A previously capable peer cannot silently downgrade on reconnect."""

    async def scenario():
        hss_cap, _, _, _ = make_capability("hss.localdomain")
        mme_cap, mme_pub, _, mme_cert = make_capability("mme.localdomain")

        hss_proxy = make_proxy(
            "hss", hss_cap, mme_cap, mme_pub, mme_cert
        )

        forwarded_cers = []

        async def read_message(reader):
            header = await reader.readexactly(20)
            length = int.from_bytes(header[1:4], "big")
            if not 20 <= length <= 1024 * 1024:
                raise ValueError(f"Invalid Diameter length: {length}")
            body = await reader.readexactly(length - 20)
            return DiameterMessage.decode(header + body)

        async def backend_handler(reader, writer):
            try:
                cer = await read_message(reader)
                forwarded_cers.append(cer)

                cea = DiameterMessage(
                    command_code=257,
                    application_id=0,
                    is_request=False,
                    avps=origin_avps("hss.localdomain"),
                )
                writer.write(cea.encode())
                await writer.drain()

                await reader.read()
            except (asyncio.IncompleteReadError, ConnectionError):
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        backend = await asyncio.start_server(
            backend_handler, "127.0.0.1", 0
        )
        backend_port = backend.sockets[0].getsockname()[1]

        hss_proxy.config.upstream_host = "127.0.0.1"
        hss_proxy.config.upstream_port = backend_port

        proxy_server = await asyncio.start_server(
            hss_proxy.handle_client, "127.0.0.1", 0
        )
        proxy_port = proxy_server.sockets[0].getsockname()[1]

        try:
            # Connection 1: valid capability establishes peer trust state.
            reader1, writer1 = await asyncio.open_connection(
                "127.0.0.1", proxy_port
            )

            valid_cer = DiameterMessage(
                command_code=257,
                application_id=0,
                is_request=True,
                avps=origin_avps("mme.localdomain") + [
                    AVPBuilder.build_capability_avp(
                        mme_cap.serialize()
                    )
                ],
            )

            writer1.write(valid_cer.encode())
            await writer1.drain()

            cea = await asyncio.wait_for(
                read_message(reader1), timeout=3
            )
            assert cea.command_code == 257
            assert cea.is_request is False
            assert len(forwarded_cers) == 1

            writer1.close()
            await writer1.wait_closed()

            # Connection 2: the same peer omits its previously advertised
            # capability. The proxy must reject it before forwarding.
            reader2, writer2 = await asyncio.open_connection(
                "127.0.0.1", proxy_port
            )

            legacy_cer = DiameterMessage(
                command_code=257,
                application_id=0,
                is_request=True,
                avps=origin_avps("mme.localdomain"),
            )

            writer2.write(legacy_cer.encode())
            await writer2.drain()

            received = await asyncio.wait_for(
                reader2.read(4096), timeout=3
            )

            assert received == b"", (
                "Proxy forwarded a response after a capability downgrade"
            )
            assert len(forwarded_cers) == 1, (
                "Downgraded CER was forwarded to the HSS backend"
            )

            writer2.close()
            await writer2.wait_closed()

            assert (
                hss_proxy.peer_capability_cache.is_known_peer(
                    "mme.localdomain", "localdomain"
                )
            )

        finally:
            proxy_server.close()
            backend.close()
            await proxy_server.wait_closed()
            await backend.wait_closed()

    asyncio.run(scenario())



def test_tcp_end_to_end_protected_aia_roundtrip():
    import asyncio

    from src.crypto.kem import generate_keypair as kem_keygen
    from src.diameter.avp_codec import (
        AVP_RAND,
        AVP_XRES,
        AVP_AUTN,
        AVP_KASME,
        AVP_QURION_PROTECTED_AV,
    )
    from src.gateway.hss_agent import HSSAgent
    from src.gateway.mme_agent import MMEAgent

    async def scenario():
        hss_cap, hss_pub, hss_priv, hss_cert = make_capability(
            "hss.localdomain"
        )
        mme_cap, mme_pub, mme_priv, mme_cert = make_capability(
            "mme.localdomain"
        )

        hss_kem_pub, hss_kem_priv = kem_keygen()
        mme_kem_pub, mme_kem_priv = kem_keygen()

        hss_agent = HSSAgent(
            operator_id="hss.localdomain",
            realm="localdomain",
            signing_key=hss_priv,
            signing_pub=hss_pub,
            kem_key=hss_kem_priv,
            kem_pub=hss_kem_pub,
            trust_store=None,
            peer_cache=None,
            anomaly_detector=None,
            peer_operator_id="mme.localdomain",
            peer_realm="localdomain",
        )

        mme_agent = MMEAgent(
            operator_id="mme.localdomain",
            realm="localdomain",
            signing_key=mme_priv,
            signing_pub=mme_pub,
            kem_key=mme_kem_priv,
            kem_pub=mme_kem_pub,
            trust_store=None,
            peer_cache=None,
            anomaly_detector=None,
            peer_operator_id="hss.localdomain",
            peer_realm="localdomain",
            peer_signing_pub=hss_pub,
        )

        captured_from_hss = []

        async def read_frame(reader):
            header = await reader.readexactly(20)
            length = int.from_bytes(header[1:4], "big")
            if length < 20:
                raise ValueError(f"Invalid Diameter length: {length}")
            return header + await reader.readexactly(length - 20)

        async def mock_hss(reader, writer):
            try:
                cer = DiameterMessage.decode(await read_frame(reader))
                assert cer.command_code == 257
                assert cer.is_request

                cea = DiameterMessage(
                    command_code=257,
                    application_id=0,
                    is_request=False,
                    avps=origin_avps("hss.localdomain"),
                )
                writer.write(cea.encode())
                await writer.drain()

                air = DiameterMessage.decode(await read_frame(reader))
                assert air.command_code == 318
                assert air.application_id == 16777251
                assert air.is_request

                vectors = AVPBuilder.build_s6a_auth_vector(
                    b"R" * 16,
                    b"X" * 8,
                    b"A" * 16,
                    b"K" * 32,
                )

                aia = DiameterMessage(
                    command_code=318,
                    application_id=16777251,
                    is_request=False,
                    avps=[
                        DiameterAVP(
                            268, 0x40, None, (2001).to_bytes(4, "big")
                        ),
                        *vectors,
                    ],
                )
                writer.write(aia.encode())
                await writer.drain()

                # Keep the backend alive until the client disconnects.
                await reader.read()
            finally:
                writer.close()
                await writer.wait_closed()

        backend_server = await asyncio.start_server(
            mock_hss, "127.0.0.1", 0
        )
        backend_port = backend_server.sockets[0].getsockname()[1]

        hss_proxy = QurionProxy(
            QurionProxyConfig(
                listen_host="127.0.0.1",
                listen_port=0,
                upstream_host="127.0.0.1",
                upstream_port=backend_port,
                mode="hss",
                operator_id="hss.localdomain",
                realm="localdomain",
                peer_kem_pub=mme_kem_pub,
            ),
            hss_agent,
            EventLogger(),
            local_capability=hss_cap,
            peer_certificate=mme_cert,
            peer_signing_pub=mme_pub,
        )

        hss_server = await asyncio.start_server(
            hss_proxy.handle_client, "127.0.0.1", 0
        )
        hss_port = hss_server.sockets[0].getsockname()[1]

        # A transparent TCP tap between the two proxies. It records the
        # exact Diameter frames sent by the HSS proxy before MME decryption.
        async def tap_handler(client_reader, client_writer):
            upstream_reader, upstream_writer = await asyncio.open_connection(
                "127.0.0.1", hss_port
            )

            async def pump(reader, writer, capture=False):
                while True:
                    try:
                        frame = await read_frame(reader)
                    except asyncio.IncompleteReadError:
                        return
                    if capture:
                        captured_from_hss.append(frame)
                    writer.write(frame)
                    await writer.drain()

            tasks = [
                asyncio.create_task(
                    pump(client_reader, upstream_writer)
                ),
                asyncio.create_task(
                    pump(upstream_reader, client_writer, capture=True)
                ),
            ]
            try:
                _, pending = await asyncio.wait(
                    tasks, return_when=asyncio.FIRST_COMPLETED
                )
                for task in pending:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
            finally:
                upstream_writer.close()
                client_writer.close()
                await asyncio.gather(
                    upstream_writer.wait_closed(),
                    client_writer.wait_closed(),
                    return_exceptions=True,
                )

        tap_server = await asyncio.start_server(
            tap_handler, "127.0.0.1", 0
        )
        tap_port = tap_server.sockets[0].getsockname()[1]

        mme_proxy = QurionProxy(
            QurionProxyConfig(
                listen_host="127.0.0.1",
                listen_port=0,
                upstream_host="127.0.0.1",
                upstream_port=tap_port,
                mode="mme",
                operator_id="mme.localdomain",
                realm="localdomain",
            ),
            mme_agent,
            EventLogger(),
            local_capability=mme_cap,
            peer_certificate=hss_cert,
            peer_signing_pub=hss_pub,
        )

        mme_server = await asyncio.start_server(
            mme_proxy.handle_client, "127.0.0.1", 0
        )
        mme_port = mme_server.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", mme_port
            )

            cer = DiameterMessage(
                command_code=257,
                application_id=0,
                is_request=True,
                avps=origin_avps("mme.localdomain"),
            )
            writer.write(cer.encode())
            await writer.drain()

            cea = DiameterMessage.decode(await read_frame(reader))
            assert cea.command_code == 257
            assert not cea.is_request
            assert cea.find_avp(
                AVP_QURION_CAPABILITY, QURION_VENDOR_ID
            ) is not None

            air = DiameterMessage(
                command_code=318,
                application_id=16777251,
                is_request=True,
            )
            writer.write(air.encode())
            await writer.drain()

            recovered_aia = DiameterMessage.decode(
                await asyncio.wait_for(read_frame(reader), timeout=5)
            )
            assert recovered_aia.command_code == 318
            assert not recovered_aia.is_request

            # The MME-facing side must contain the recovered vectors.
            recovered_codes = {avp.code for avp in recovered_aia.avps}
            assert {AVP_RAND, AVP_XRES, AVP_AUTN, AVP_KASME} <= recovered_codes
            assert recovered_aia.find_avp(
                AVP_QURION_PROTECTED_AV, QURION_VENDOR_ID
            ) is None

            # Inspect the exact frames captured on the HSS-to-MME link.
            wire_aia = [
                DiameterMessage.decode(frame)
                for frame in captured_from_hss
                if (
                    DiameterMessage.decode(frame).command_code == 318
                    and not DiameterMessage.decode(frame).is_request
                )
            ]
            assert len(wire_aia) == 1

            protected_aia = wire_aia[0]
            assert protected_aia.find_avp(
                AVP_QURION_PROTECTED_AV, QURION_VENDOR_ID
            ) is not None
            assert not any(
                avp.code in {AVP_RAND, AVP_XRES, AVP_AUTN, AVP_KASME}
                for avp in protected_aia.avps
            )

            writer.close()
            await writer.wait_closed()
        finally:
            for server in (mme_server, tap_server, hss_server, backend_server):
                server.close()
            await asyncio.gather(
                *(
                    server.wait_closed()
                    for server in (
                        mme_server, tap_server, hss_server, backend_server
                    )
                ),
                return_exceptions=True,
            )

    asyncio.run(scenario())
