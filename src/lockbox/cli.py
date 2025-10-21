# src/lockbox/cli.py
from __future__ import annotations
import sys
import pathlib
import getpass
import typer
from rich import print
from .crypto import (
    random_bytes, derive_key_argon2id, gen_keypair, seal_for, unseal_with,
    gen_signing_keypair, sign_detached, verify_detached, AEAD_KEY_LEN, SALT_LEN,
)
from .header import Header, Recipient, loads_with_length
from .stream import encrypt_stream
from typing import Optional 

app = typer.Typer(help="Lockbox — modern file & secret encryptor")

@app.command()
def genkey()-> None:
    """Generate X25519 keypair (public to stdout, secret to stderr)."""
    pk_hex, sk_hex = gen_keypair()
    print(pk_hex)
    print(sk_hex, file=sys.stderr)

@app.command()
def gensign()-> None:
    """Generate Ed25519 signing keypair (verify key to stdout, secret to stderr)."""
    vk_hex, sk_hex = gen_signing_keypair()
    print(vk_hex)
    print(sk_hex, file=sys.stderr)

@app.command()
def encrypt(input: pathlib.Path,
            out: pathlib.Path = typer.Option(None, help="Output path; defaults to .lbx"),
            recipient: list[str] = typer.Option([], help="Recipient public key(s) hex"),
            chunk_size: int = 64*1024)-> None:
    data_f = input.open("rb")
    target = out or input.with_suffix(input.suffix + ".lbx")

    if recipient:
        # keypair mode: envelope
        content_key = random_bytes(AEAD_KEY_LEN)
        recs = [Recipient(pk_hex=r, wrapped_key_hex=seal_for(r, content_key).hex())
                for r in recipient]
        # header first
        header = Header(version=1, mode="keypair", aead="xchacha20poly1305",
                        recipients=recs, filename=input.name, chunk_size=chunk_size, nonce_hex="")
        with target.open("wb") as f:
            f.write(header.dumps_with_length())
            for piece in encrypt_stream(data_f, content_key, chunk_size):
                f.write(piece)
    else:
        # password mode
        salt = random_bytes(SALT_LEN)
        pw = getpass.getpass("Passphrase: ").encode()
        key = derive_key_argon2id(pw, salt)
        header = Header(version=1, mode="password", aead="xchacha20poly1305",
                        kdf="argon2id", salt_hex=salt.hex(), filename=input.name,
                        chunk_size=chunk_size, nonce_hex="")
        with target.open("wb") as f:
            f.write(header.dumps_with_length())
            for piece in encrypt_stream(data_f, key, chunk_size):
                f.write(piece)

    print(f"[green]Encrypted → {target}[/green]")

@app.command()
def decrypt(input: pathlib.Path,
            out: pathlib.Path = typer.Option(None, help="Output file"),
            sk: str = typer.Option("", help="Secret key hex (for keypair mode)"))-> None:
    raw = input.read_bytes()
    header, payload = loads_with_length(raw)
    if header.mode == "password":
        salt = bytes.fromhex(header.salt_hex or "")
        pw = getpass.getpass("Passphrase: ").encode()
        key = derive_key_argon2id(pw, salt)
    else:
        if not sk:
            raise typer.BadParameter("Provide --sk <secret-hex> for keypair mode.")
        # Try to open with first recipient this key can decrypt
        content_key = None
        for r in header.recipients or []:
            try:
                content_key = unseal_with(sk, bytes.fromhex(r.wrapped_key_hex))
                break
            except Exception:
                continue
        if content_key is None:
            raise typer.Exit(code=2)
        key = content_key

    # stream decode
    from io import BytesIO
    buf = BytesIO(payload)
    out_path = out or input.with_suffix(".dec")
    with open(out_path, "wb") as f:
        from .stream import decrypt_stream
        for chunk in decrypt_stream(buf, key):
            f.write(chunk)
    print(f"[green]Decrypted → {out_path}[/green]")

@app.command()
def sign(input: pathlib.Path, sk: str, out: Optional[pathlib.Path] = None) -> None:
    data = input.read_bytes()
    sig = sign_detached(sk, data)
    out = out or input.with_suffix(input.suffix + ".sig")
    out.write_bytes(sig)
    print(f"[green]Wrote signature → {out}[/green]")
    
@app.command()
def verify(input: pathlib.Path, sig: pathlib.Path, vk: str)-> None:
    ok = verify_detached(vk, input.read_bytes(), sig.read_bytes())
    print("[green]VALID[/green]" if ok else "[red]INVALID[/red]")
    