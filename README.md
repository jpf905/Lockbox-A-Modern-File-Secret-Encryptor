## **Lockbox — A Modern File & Secret Encryptor**

![Lockbox CI](https://github.com/jpf905/Lockbox-A-Modern-File-Secret-Encryptor/actions/workflows/ci.yml/badge.svg)


**Lockbox** is a lightweight, modern encryption toolkit designed for secure file protection and secret sharing.  
It combines strong cryptography (XChaCha20-Poly1305, Argon2id, X25519, Ed25519) with a simple CLI interface — built entirely in Python.  
This project demonstrates skills in **cybersecurity, cryptography, and secure software engineering**.

---

### **Features**

* **Password-based Encryption** — Protect files with a user-defined passphrase using Argon2id key derivation  
* **Public-Key Encryption** — Encrypt for multiple recipients with X25519 keys (secure file sharing)  
* **Digital Signatures** — Sign and verify data using Ed25519  
* **Streaming Encryption** — Encrypt large files without loading them into memory  
* **Strong Cryptographic Primitives** — XChaCha20-Poly1305 AEAD  
* **CLI Interface** built with [Typer](https://typer.tiangolo.com) and [Rich](https://github.com/Textualize/rich)  

---

### **Example Output**

Below is an example of **Lockbox** in action — showing password-based encryption, decryption, and signature verification from the command line.

```bash
$ echo "cybersecurity portfolio demo" > demo.txt

$ python -m lockbox.cli encrypt demo.txt
Passphrase: ********
Encrypted → demo.txt.lbx

$ python -m lockbox.cli decrypt demo.txt.lbx
Passphrase: ********
Decrypted → demo.dec

$ cat demo.dec
cybersecurity portfolio demo

$ python -m lockbox.cli gensign > verify.hex 2> sign.hex
$ python -m lockbox.cli sign demo.txt --sk $(cat sign.hex)
Wrote signature → demo.txt.sig

$ python -m lockbox.cli verify demo.txt --sig demo.txt.sig --vk $(cat verify.hex)
VALID
