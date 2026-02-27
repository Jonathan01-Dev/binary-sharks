import os

import nacl.encoding
import nacl.signing


def _default_key_path() -> str:
    return os.getenv('NODE_KEY_PATH', './keys/node.key')


def generate_keypair():
    """Genere une paire de cles Ed25519 pour ce noeud."""
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    return signing_key, verify_key


def save_keypair(signing_key, path=None):
    """Sauvegarde la cle privee sur disque (dossier keys/ ignore par Git)."""
    path = path or _default_key_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(bytes(signing_key))  # 32 bytes
    print(f'[OK] Cle sauvegardee : {path}')


def load_keypair(path=None):
    """Charge la cle depuis le disque, ou en genere une nouvelle."""
    path = path or _default_key_path()
    if os.path.exists(path):
        with open(path, 'rb') as f:
            signing_key = nacl.signing.SigningKey(f.read())
    else:
        signing_key, _ = generate_keypair()
        save_keypair(signing_key, path)
    return signing_key, signing_key.verify_key


def node_id(verify_key):
    """Retourne l'ID unique du noeud = cle publique en hex (32 bytes)."""
    return verify_key.encode(nacl.encoding.HexEncoder).decode()
