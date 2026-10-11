
import asyncio

import pytest

from src.diameter.avp_codec import DiameterMessage
from src.gateway.qurion_proxy import QurionProxy, QurionProxyConfig



def force_protected_action(monkeypatch):
    """Exercise the protected-AIA path without simulating CER/CEA."""
    from src.gateway import qurion_proxy

    protected_actions = [
        action
        for action in qurion_proxy.NegotiationAction
        if action.name not in {"REJECT", "FALLBACK", "PASSTHROUGH"}
    ]
    assert len(protected_actions) == 1, (
        "Expected exactly one protection action; inspect NegotiationAction "
        "if this assertion fails."
    )

    monkeypatch.setattr(
        qurion_proxy,
        "decide_action",
        lambda *args, **kwargs: protected_actions[0],
    )



class FakeWriter:
    def __init__(self):
        self.written = []
        self.closed = False

    def get_extra_info(self, name):
        return ("127.0.0.1", 12345) if name == "peername" else None

    def write(self, data):
        self.written.append(data)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


class BlockingReader:
    """Keep the opposite pipe alive until the proxy cancels it."""

    async def readexactly(self, n):
        await asyncio.Event().wait()


class AIAReader:
    """Provide one valid AIA, then EOF."""

    def __init__(self, data):
        self.data = data
        self.offset = 0

    async def readexactly(self, n):
        remaining = len(self.data) - self.offset

        if remaining < n:
            raise asyncio.IncompleteReadError(
                self.data[self.offset:],
                n,
            )

        result = self.data[self.offset:self.offset + n]
        self.offset += n
        return result


class FailingMMEAgent:
    def process_incoming_aia(self, message):
        raise ValueError("simulated verification failure")


class UnexpectedHSSAgent:
    def process_outgoing_aia(self, message, peer_kem_pub):
        pytest.fail("HSS agent must not run without a peer KEM key")


def make_aia():
    return DiameterMessage(
        command_code=318,
        application_id=16777251,
        is_request=False,
    ).encode()


def make_config(mode, peer_kem_pub=None):
    return QurionProxyConfig(
        listen_host="127.0.0.1",
        listen_port=0,
        upstream_host="127.0.0.1",
        upstream_port=3868,
        mode=mode,
        operator_id="test-local",
        realm="test.example",
        peer_kem_pub=peer_kem_pub,
    )


def run_proxy_case(monkeypatch, mode, agent, peer_kem_pub=None):
    raw_aia = make_aia()
    upstream_reader = AIAReader(raw_aia)
    upstream_writer = FakeWriter()
    client_writer = FakeWriter()

    async def fake_open_connection(host, port):
        return upstream_reader, upstream_writer

    monkeypatch.setattr(
        asyncio,
        "open_connection",
        fake_open_connection,
    )

    proxy = QurionProxy(
        make_config(mode, peer_kem_pub),
        agent,
        event_logger=None,
    )

    asyncio.run(
        proxy.handle_client(
            BlockingReader(),
            client_writer,
        )
    )

    return raw_aia, client_writer



def test_mme_does_not_forward_aia_when_verification_fails(monkeypatch):
    force_protected_action(monkeypatch)

    raw_aia, client_writer = run_proxy_case(
        monkeypatch,
        mode="mme",
        agent=FailingMMEAgent(),
        peer_kem_pub=b"test-peer-key",
    )

    assert raw_aia not in client_writer.written
    assert client_writer.written == []
    assert client_writer.closed


def test_hss_does_not_forward_aia_without_peer_key(monkeypatch):
    force_protected_action(monkeypatch)

    raw_aia, client_writer = run_proxy_case(
        monkeypatch,
        mode="hss",
        agent=UnexpectedHSSAgent(),
        peer_kem_pub=None,
    )

    assert raw_aia not in client_writer.written
    assert client_writer.written == []
    assert client_writer.closed
