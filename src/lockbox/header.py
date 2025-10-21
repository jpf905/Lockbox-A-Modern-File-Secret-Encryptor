# src/lockbox/header.py
from __future__ import annotations
from dataclasses import dataclass, asdict
import json
from typing import Optional, List

@dataclass
class Recipient:
    pk_hex: str             # recipient public key (hex)
    wrapped_key_hex: str    # sealed content key (hex)

@dataclass
class Header:
    version: int
    mode: str               # "password" | "keypair"
    aead: str               # "xchacha20poly1305"
    kdf: Optional[str] = None          # "argon2id" for password mode
    salt_hex: Optional[str] = None
    opslimit: Optional[int] = None     # KDF params (optional to persist)
    memlimit_mb: Optional[int] = None
    nonce_hex: str = ""
    recipients: Optional[List[Recipient]] = None
    filename: Optional[str] = None
    chunk_size: int = 64 * 1024

    def dumps_with_length(self) -> bytes:
        blob = json.dumps(asdict(self), separators=(",", ":")).encode()
        return len(blob).to_bytes(4, "big") + blob

def loads_with_length(data: bytes) -> tuple[Header, bytes]:
    (n,) = int.from_bytes(data[:4], "big"),
    body = data[4:4+n[0]] if isinstance(n, tuple) else data[4:4+n]
    rest = data[4+ (n[0] if isinstance(n, tuple) else n):]
    hdr = json.loads(body.decode())
    hdr["recipients"] = [Recipient(**r) for r in (hdr.get("recipients") or [])]
    return Header(**hdr), rest
