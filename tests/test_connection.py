import asyncio
from unittest.mock import MagicMock

import pytest

from rscp_lib.RscpConnection import RscpConnection, RscpConnectionException
from rscp_lib.RscpEncryption import RscpEncryption
from rscp_lib.RscpFrame import RscpFrame
from rscp_lib.RscpValue import RscpValue
from tests.conftest import connection_module


class _FakeSocketNamespace:
    """Stand-in for the ``socket`` module as seen by RscpConnection.

    Patched in *only* on that module so pytest-asyncio's event loop — which
    also uses the real ``socket.socket`` for its self-pipe — is unaffected.
    """

    AF_INET = 2
    SOCK_STREAM = 1
    error = OSError

    def __init__(self, sock):
        self._sock = sock

    def socket(self, *args, **kwargs):
        return self._sock


# ---- Helpers --------------------------------------------------------------


@pytest.fixture
def mock_sock(monkeypatch):
    sock = MagicMock()
    monkeypatch.setattr(connection_module(), "socket", _FakeSocketNamespace(sock))
    return sock


async def _connect_ok():
    loop = asyncio.get_running_loop()

    async def fake_sock_connect(sock, addr):
        return None

    loop.sock_connect = fake_sock_connect


def _auth_response(level=10):
    v = RscpValue().withTagName("TAG_RSCP_AUTHENTICATION", level)
    return RscpFrame().packFrame(v)


def _non_auth_response():
    v = RscpValue().withTagName("TAG_EMS_REQ_POWER_PV", None)
    return RscpFrame().packFrame(v)


# ---- Basic state ---------------------------------------------------------


def test_construct_default():
    c = RscpConnection("h")
    assert not c.is_connected()
    assert not c.is_authorized()


def test_disconnect_when_not_connected_is_noop():
    c = RscpConnection("h")
    c.disconnect()
    assert not c.is_connected()


async def test_send_on_disconnected_returns_false():
    c = RscpConnection("h")
    assert await c.send(b"data") is False


# ---- connect() -----------------------------------------------------------


async def test_connect_success_and_second_call_returns_false(mock_sock):
    await _connect_ok()
    c = RscpConnection("1.2.3.4", 5033)
    assert await c.connect() is True
    assert c.is_connected()
    # Second call is rejected
    assert await c.connect() is False
    c.disconnect()
    assert not c.is_connected()


async def test_connect_success_resets_cipher(mock_sock):
    await _connect_ok()
    cipher = RscpEncryption("pw")
    # Roll the IV forward so reset() has something to do
    cipher.encrypt(b"A" * 32)
    c = RscpConnection("h", ciphersuite=cipher)
    assert await c.connect() is True


async def test_connect_timeout_raises(mock_sock):
    conn_asyncio = connection_module().asyncio

    original = conn_asyncio.wait_for

    async def fake(coro, timeout):
        coro.close()
        raise TimeoutError("fake timeout")

    conn_asyncio.wait_for = fake
    try:
        c = RscpConnection("h")
        with pytest.raises(RscpConnectionException):
            await c.connect()
        assert not c.is_connected()
    finally:
        conn_asyncio.wait_for = original


async def test_connect_oserror_raises(mock_sock):
    conn_asyncio = connection_module().asyncio

    original = conn_asyncio.wait_for

    async def fake(coro, timeout):
        coro.close()
        raise OSError("refused")

    conn_asyncio.wait_for = fake
    try:
        c = RscpConnection("h")
        with pytest.raises(RscpConnectionException):
            await c.connect()
    finally:
        conn_asyncio.wait_for = original


# ---- send / receive ------------------------------------------------------


async def test_send_and_receive_no_cipher(mock_sock):
    await _connect_ok()
    loop = asyncio.get_running_loop()

    sent = []

    async def fake_sendall(sock, data):
        sent.append(data)

    async def fake_recv(sock, n):
        return b"hello"

    loop.sock_sendall = fake_sendall
    loop.sock_recv = fake_recv

    c = RscpConnection("h")
    await c.connect()
    assert await c.send(b"ping") is True
    assert sent == [b"ping"]
    assert await c.receive() == b"hello"


async def test_send_and_receive_with_cipher(mock_sock):
    await _connect_ok()
    loop = asyncio.get_running_loop()

    # Build the encrypted payload as the peer would see it
    peer_cipher = RscpEncryption("pw")
    response_plain = RscpFrame().packFrame(
        [
            RscpValue().withTagName("TAG_EMS_REQ_POWER_PV", None),
            RscpValue().withTagName("TAG_EMS_REQ_POWER_BAT", None),
        ]
    )
    assert len(response_plain) == RscpEncryption.BLOCK_SIZE
    response_encrypted = peer_cipher.encrypt(response_plain)

    sent = []

    async def fake_sendall(sock, data):
        sent.append(data)

    async def fake_recv(sock, n):
        return response_encrypted

    loop.sock_sendall = fake_sendall
    loop.sock_recv = fake_recv

    own_cipher = RscpEncryption("pw")
    c = RscpConnection("h", ciphersuite=own_cipher)
    await c.connect()

    await c.send(b"Q" * 32)
    # Encrypted payload reached the wire
    assert sent[0] != b"Q" * 32
    assert len(sent[0]) == 32

    received = await c.receive()
    assert received == response_plain


async def test_receive_with_cipher_reassembles_a_fragmented_frame(mock_sock):
    await _connect_ok()
    loop = asyncio.get_running_loop()

    values = [
        RscpValue().withTagName("TAG_EMS_REQ_POWER_PV", None) for _ in range(3)
    ]
    response_plain = RscpFrame().packFrame(values)
    peer_cipher = RscpEncryption("pw")
    response_encrypted = peer_cipher.encrypt(response_plain)
    assert len(response_encrypted) == RscpEncryption.BLOCK_SIZE * 2
    chunks = iter(
        (
            response_encrypted[: RscpEncryption.BLOCK_SIZE],
            response_encrypted[RscpEncryption.BLOCK_SIZE :],
        )
    )

    async def fake_recv(sock, n):
        return next(chunks)

    loop.sock_recv = fake_recv

    c = RscpConnection("h", ciphersuite=RscpEncryption("pw"))
    await c.connect()
    received = await c.receive()

    assert received[: len(response_plain)] == response_plain


async def test_receive_with_cipher_raises_when_peer_closes_mid_frame(mock_sock):
    await _connect_ok()
    loop = asyncio.get_running_loop()

    values = [
        RscpValue().withTagName("TAG_EMS_REQ_POWER_PV", None) for _ in range(3)
    ]
    encrypted_response = RscpEncryption("pw").encrypt(RscpFrame().packFrame(values))

    chunks = iter((encrypted_response[: RscpEncryption.BLOCK_SIZE], b""))

    async def fake_recv(sock, n):
        return next(chunks)

    loop.sock_recv = fake_recv

    c = RscpConnection("h", ciphersuite=RscpEncryption("pw"))
    await c.connect()

    with pytest.raises(RscpConnectionException, match="complete RSCP frame"):
        await c.receive()


async def test_receive_with_cipher_wrong_key_raises_instead_of_hanging(mock_sock):
    await _connect_ok()
    loop = asyncio.get_running_loop()

    # Peer encrypts with a different key -> decrypted header is garbage.
    encrypted_response = RscpEncryption("other-key").encrypt(_non_auth_response())
    calls = []

    async def fake_recv(sock, n):
        calls.append(n)
        if len(calls) > 1:
            raise AssertionError("receive() must not wait for more data")
        return encrypted_response

    loop.sock_recv = fake_recv

    c = RscpConnection("h", ciphersuite=RscpEncryption("pw"))
    await c.connect()

    with pytest.raises(RscpConnectionException, match="magic"):
        await c.receive()
    assert not c.is_connected()


async def test_receive_with_cipher_keeps_bytes_of_the_next_frame(mock_sock):
    await _connect_ok()
    loop = asyncio.get_running_loop()

    frame_1 = RscpFrame().packFrame(
        [RscpValue().withTagName("TAG_EMS_REQ_POWER_PV", None) for _ in range(3)]
    )
    frame_2 = _auth_response(level=10)
    peer_cipher = RscpEncryption("pw")
    encrypted_1 = peer_cipher.encrypt(frame_1)
    encrypted_2 = peer_cipher.encrypt(frame_2)
    split = len(encrypted_1) + RscpEncryption.BLOCK_SIZE // 2

    # Frame 1 plus half of frame 2's first block arrive together, the rest later.
    stream = encrypted_1 + encrypted_2
    chunks = iter((stream[:split], stream[split:]))

    async def fake_recv(sock, n):
        return next(chunks)

    loop.sock_recv = fake_recv

    c = RscpConnection("h", ciphersuite=RscpEncryption("pw"))
    await c.connect()

    received_1 = await c.receive()
    received_2 = await c.receive()

    assert received_1[: len(frame_1)] == frame_1
    assert received_2[: len(frame_2)] == frame_2


async def test_receive_with_cipher_two_frames_in_one_chunk(mock_sock):
    await _connect_ok()
    loop = asyncio.get_running_loop()

    frame_1 = _non_auth_response()
    frame_2 = _auth_response(level=10)
    peer_cipher = RscpEncryption("pw")
    stream = peer_cipher.encrypt(frame_1) + peer_cipher.encrypt(frame_2)
    calls = []

    async def fake_recv(sock, n):
        calls.append(n)
        if len(calls) > 1:
            raise AssertionError("second frame must come from the buffer")
        return stream

    loop.sock_recv = fake_recv

    c = RscpConnection("h", ciphersuite=RscpEncryption("pw"))
    await c.connect()

    assert (await c.receive())[: len(frame_1)] == frame_1
    assert (await c.receive())[: len(frame_2)] == frame_2


async def test_send_oserror_disconnects_and_raises(mock_sock):
    await _connect_ok()
    loop = asyncio.get_running_loop()

    async def fake_sendall(sock, data):
        raise OSError("broken pipe")

    loop.sock_sendall = fake_sendall

    c = RscpConnection("h")
    await c.connect()
    with pytest.raises(RscpConnectionException):
        await c.send(b"data")
    assert not c.is_connected()


async def test_receive_oserror_disconnects_and_raises(mock_sock):
    await _connect_ok()
    loop = asyncio.get_running_loop()

    async def fake_recv(sock, n):
        raise OSError("reset")

    loop.sock_recv = fake_recv

    c = RscpConnection("h")
    await c.connect()
    with pytest.raises(RscpConnectionException):
        await c.receive()
    assert not c.is_connected()


# ---- authorize() ---------------------------------------------------------


async def test_authorize_success(mock_sock):
    await _connect_ok()
    loop = asyncio.get_running_loop()

    sent = []
    response = _auth_response(level=10)

    async def fake_sendall(sock, data):
        sent.append(data)

    async def fake_recv(sock, n):
        return response

    loop.sock_sendall = fake_sendall
    loop.sock_recv = fake_recv

    c = RscpConnection("h", username="alice", password="pw")
    await c.connect()
    assert await c.authorize() is True
    assert c.is_authorized()


async def test_authorize_credentials_override(mock_sock):
    await _connect_ok()
    loop = asyncio.get_running_loop()

    response = _auth_response(level=5)

    async def fake_sendall(sock, data):
        pass

    async def fake_recv(sock, n):
        return response

    loop.sock_sendall = fake_sendall
    loop.sock_recv = fake_recv

    c = RscpConnection("h")
    await c.connect()
    # No credentials stored yet — pass them in
    assert await c.authorize(username="alice", password="pw") is True


async def test_authorize_failure(mock_sock):
    await _connect_ok()
    loop = asyncio.get_running_loop()

    response = _non_auth_response()

    async def fake_sendall(sock, data):
        pass

    async def fake_recv(sock, n):
        return response

    loop.sock_sendall = fake_sendall
    loop.sock_recv = fake_recv

    c = RscpConnection("h", username="alice", password="pw")
    await c.connect()
    assert await c.authorize() is False
    assert not c.is_authorized()
