import pytest

from rscp_lib.RscpEncryption import NoPadding, RscpEncryption


def test_round_trip_32_bytes():
    enc = RscpEncryption("password")
    dec = RscpEncryption("password")
    plaintext = b"A" * 32
    ct = enc.encrypt(plaintext)
    assert dec.decrypt(ct) == plaintext


def test_iv_advances_between_operations():
    enc = RscpEncryption("pw")
    ct1 = enc.encrypt(b"A" * 32)
    ct2 = enc.encrypt(b"A" * 32)
    # Same plaintext, different IV (rolled forward from previous ciphertext)
    assert ct1 != ct2


def test_reset_restores_iv():
    enc = RscpEncryption("pw")
    ct1 = enc.encrypt(b"B" * 32)
    enc.reset()
    ct2 = enc.encrypt(b"B" * 32)
    assert ct1 == ct2


def test_decrypt_non_block_length_returns_none():
    enc = RscpEncryption("pw")
    # Length not a multiple of BLOCK_SIZE (32)
    assert enc.decrypt(b"A" * 5) is None


def test_no_padding_decode_is_identity():
    pad = NoPadding(RscpEncryption.BLOCK_SIZE)
    data = b"some-bytes-content"
    assert pad.decode(data) == data


def test_oversized_key_raises():
    # Library raises when key length exceeds KEY_SIZE
    with pytest.raises(Exception):
        RscpEncryption("x" * (RscpEncryption.KEY_SIZE + 1))


def test_key_shorter_than_keysize_is_padded_and_works():
    a = RscpEncryption("short")
    b = RscpEncryption("short")
    pt = b"C" * 32
    assert b.decrypt(a.encrypt(pt)) == pt
