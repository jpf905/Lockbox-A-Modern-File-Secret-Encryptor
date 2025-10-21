# tests/test_header.py
from lockbox.header import Header, loads_with_length

def test_header_roundtrip():
    hdr = Header(version=1, mode="password", aead="xchacha20poly1305",
                 kdf="argon2id", salt_hex="aa"*16, filename="foo.txt", chunk_size=65536, nonce_hex="")
    blob = hdr.dumps_with_length()
    hdr2, rest = loads_with_length(blob)
    assert rest == b""
    assert hdr2.version == 1
    assert hdr2.kdf == "argon2id"
