import os

import nacl.public
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF


def generate_x25519_keypair():
    """Generate an ephemeral X25519 keypair for a session."""
    private_key = nacl.public.PrivateKey.generate()
    public_key = private_key.public_key
    return private_key, public_key


def derive_session_key(
    my_private: nacl.public.PrivateKey,
    peer_public: nacl.public.PublicKey,
) -> bytes:
    """
    Derive a shared session key via X25519 Diffie-Hellman.
    Both peers compute the same secret without sending it over the wire.
    """
    box = nacl.public.Box(my_private, peer_public)
    shared = bytes(box._shared_key)  # 32 bytes shared secret
    session_key = HKDF(shared, 32, b'archipel-v1', SHA256)
    return session_key  # 32 bytes = AES-256 key


def encrypt(session_key: bytes, plaintext: bytes) -> dict:
    """
    Encrypt with AES-256-GCM.
    Returns nonce + ciphertext + auth_tag required to decrypt.
    """
    nonce = os.urandom(12)  # 96-bit nonce, must be unique per key
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {
        'nonce': nonce.hex(),
        'ciphertext': ciphertext.hex(),
        'tag': tag.hex(),
    }


def decrypt(session_key: bytes, nonce: str, ciphertext: str, tag: str) -> bytes:
    """Decrypt and verify integrity (raises ValueError if tag is invalid)."""
    nonce_b = bytes.fromhex(nonce)
    ciphertext_b = bytes.fromhex(ciphertext)
    tag_b = bytes.fromhex(tag)

    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce_b)
    plaintext = cipher.decrypt(ciphertext_b)
    cipher.verify(tag_b)
    return plaintext
