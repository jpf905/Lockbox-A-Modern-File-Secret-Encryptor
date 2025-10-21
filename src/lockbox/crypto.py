# src/lockbox/crypto.py
from __future__ import annotations
from typing import Tuple, Optional       # ✅ add Optional here
from nacl import utils, pwhash
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
)
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey


AEAD_KEY_LEN = 32
NONCE_LEN = 24
SALT_LEN = 16

def random_bytes(n: int) -> bytes:
    return utils.random(n)

def aead_encrypt(plaintext: bytes, key: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    nonce = utils.random(NONCE_LEN)
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
    return nonce, ct

def aead_decrypt(nonce: bytes, ciphertext: bytes, key: bytes, aad: bytes = b"") -> bytes:
    return crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, key)

def derive_key_argon2id(
    passphrase: bytes,
    salt: bytes,
    ops: Optional[int] = None,
    mem_mb: Optional[int] = None
) -> bytes:
    
    # Use PyNaCl's Argon2id constants unless overridden
    opslimit = pwhash.argon2id.OPSLIMIT_MODERATE if ops is None else ops
    memlimit = pwhash.argon2id.MEMLIMIT_MODERATE if mem_mb is None else mem_mb * 1024 * 1024
    return pwhash.argon2id.kdf(AEAD_KEY_LEN, passphrase, salt, opslimit=opslimit, memlimit=memlimit)

def seal_for(pk_hex: str, content_key: bytes) -> bytes:
    box = SealedBox(PublicKey(bytes.fromhex(pk_hex)))
    return box.encrypt(content_key)

def unseal_with(sk_hex: str, wrapped: bytes) -> bytes:
    box = SealedBox(PrivateKey(bytes.fromhex(sk_hex)))
    return box.decrypt(wrapped)

def gen_keypair() -> tuple[str, str]:
    sk = PrivateKey.generate()
    pk = sk.public_key
    return pk.encode().hex(), sk.encode().hex()

def gen_signing_keypair() -> tuple[str, str]:
    sk = SigningKey.generate()
    vk = sk.verify_key
    return vk.encode().hex(), sk.encode().hex()

def sign_detached(sk_hex: str, data: bytes) -> bytes:
    sk = SigningKey(bytes.fromhex(sk_hex))
    return sk.sign(data).signature

def verify_detached(vk_hex: str, data: bytes, sig: bytes) -> bool:
    vk = VerifyKey(bytes.fromhex(vk_hex))
    try:
        vk.verify(data, sig)
        return True
    except Exception:
        return False
    