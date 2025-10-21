# tests/test_roundtrip.py
import os
from io import BytesIO
from lockbox.crypto import random_bytes, AEAD_KEY_LEN
from lockbox.stream import encrypt_stream, decrypt_stream

def roundtrip(msg: bytes):
    key = random_bytes(AEAD_KEY_LEN)
    enc = b"".join(encrypt_stream(BytesIO(msg), key, chunk_size=8192))
    dec = b"".join(decrypt_stream(BytesIO(enc), key))
    assert dec == msg

def test_small():
    roundtrip(b"hello world")

def test_random_sizes():
    for n in [1, 31, 32, 33, 4095, 4096, 4097, 100_000]:
        roundtrip(os.urandom(n))
