# src/lockbox/stream.py
from __future__ import annotations
from typing import BinaryIO, Iterable
from .crypto import aead_encrypt, aead_decrypt

def encrypt_stream(in_f: BinaryIO, key: bytes, chunk_size: int) -> Iterable[bytes]:
    # Each chunk is independently AEAD-encrypted with a fresh nonce
    while True:
        chunk = in_f.read(chunk_size)
        if not chunk:
            break
        nonce, ct = aead_encrypt(chunk, key)
        yield len(nonce).to_bytes(1, "big") + nonce + len(ct).to_bytes(4, "big") + ct

def decrypt_stream(in_f: BinaryIO, key: bytes) -> Iterable[bytes]:
    import struct
    while True:
        nlen = in_f.read(1)
        if not nlen:
            break
        nonce_len = nlen[0]
        nonce = in_f.read(nonce_len)
        (ct_len,) = struct.unpack(">I", in_f.read(4))
        ct = in_f.read(ct_len)
        yield aead_decrypt(nonce, ct, key)
