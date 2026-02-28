import asyncio
import json

import nacl.public

from src.crypto.cipher import decrypt, derive_session_key, encrypt, generate_x25519_keypair
from src.crypto.keys import load_keypair, node_id as get_node_id
from src.network.peer_table import PeerTable


class ChatService:
    def __init__(self, peer_table: PeerTable):
        self.peers = peer_table
        self.sk, self.vk = load_keypair()
        self.my_id = get_node_id(self.vk)
        self.sessions = {}  # "node_id:port" -> session_key

    def _session_key_id(self, peer_id: str, peer_port: int) -> str:
        return f'{peer_id}:{peer_port}'

    def _resolve_peer(self, peer_id: str, peer_port: int | None = None):
        candidates = [p for p in self.peers.alive() if p.node_id == peer_id]
        if peer_port is not None:
            candidates = [p for p in candidates if p.tcp_port == peer_port]
        return candidates[0] if candidates else None

    async def _get_session(self, peer_id: str, peer_port: int | None = None) -> bytes:
        """Get or create a session key for a peer."""
        peer = self._resolve_peer(peer_id, peer_port)
        if not peer:
            raise ValueError(f'Pair introuvable : {peer_id} (port={peer_port})')

        sid = self._session_key_id(peer.node_id, peer.tcp_port)
        if sid in self.sessions:
            return self.sessions[sid]

        my_priv, my_pub = generate_x25519_keypair()
        peer_pub_bytes = await self._exchange_keys(peer, bytes(my_pub))
        peer_pub = nacl.public.PublicKey(peer_pub_bytes)
        session_key = derive_session_key(my_priv, peer_pub)
        self.sessions[sid] = session_key
        return session_key

    async def send(self, peer_id: str, text: str, peer_port: int | None = None):
        """Send an encrypted message to a peer."""
        peer = self._resolve_peer(peer_id, peer_port)
        if not peer:
            raise ValueError(f'Pair introuvable : {peer_id} (port={peer_port})')

        session_key = await self._get_session(peer_id, peer_port)
        encrypted = encrypt(session_key, text.encode())

        payload = json.dumps({'type': 'MSG', 'from': self.my_id, **encrypted})
        sig = self.sk.sign(payload.encode()).signature.hex()
        final = json.dumps({'type': 'MSG', 'payload': payload, 'sig': sig})

        ack = await self._send_tcp(peer.node_id, final.encode(), peer_port=peer.tcp_port)
        print(f'[CHAT] Message envoye a {peer.node_id[:12]}...:{peer.tcp_port} (chiffre) ack={ack}')

    async def receive(self, raw: dict, sender_ip: str) -> str:
        """Receive and decrypt a message."""
        payload = json.loads(raw['payload'])

        sender_id = payload['from']

        # Preferred path: session indexed directly by sender_id.
        session_key = self.sessions.get(sender_id)

        # Fallback path: session indexed by sender_id:peer_port if peer is known.
        if not session_key:
            sender_peer = self._resolve_peer(sender_id)
            if sender_peer:
                sid = self._session_key_id(sender_id, sender_peer.tcp_port)
                session_key = self.sessions.get(sid)

        if not session_key:
            raise ValueError('Session inconnue - handshake requis')

        plaintext = decrypt(
            session_key,
            payload['nonce'],
            payload['ciphertext'],
            payload['tag'],
        )
        return plaintext.decode()

    async def _exchange_keys(self, peer, my_pub_bytes: bytes) -> bytes:
        """Exchange ephemeral X25519 public keys through TCP (simplified)."""
        reader, writer, target = await self._open_peer_connection(peer.ip, peer.tcp_port)
        try:
            msg = json.dumps({'type': 'KEY_EXCHANGE', 'from': self.my_id, 'pub': my_pub_bytes.hex()}).encode()
            writer.write(len(msg).to_bytes(4, 'big') + msg)
            await writer.drain()

            len_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=8)
            resp = json.loads(await asyncio.wait_for(reader.readexactly(int.from_bytes(len_bytes, 'big')), timeout=8))
            if 'pub' not in resp:
                raise RuntimeError(f'Reponse KEY_EXCHANGE invalide depuis {target[0]}:{target[1]}')
            return bytes.fromhex(resp['pub'])
        except asyncio.TimeoutError as exc:
            raise RuntimeError(f'Handshake timeout vers {target[0]}:{target[1]}') from exc
        finally:
            writer.close()
            await writer.wait_closed()

    async def _send_tcp(self, peer_id: str, data: bytes, peer_port: int | None = None):
        peer = self._resolve_peer(peer_id, peer_port)
        if not peer:
            raise ValueError(f'Pair hors ligne : {peer_id} (port={peer_port})')

        reader, writer, _target = await self._open_peer_connection(peer.ip, peer.tcp_port)
        try:
            writer.write(len(data).to_bytes(4, 'big') + data)
            await writer.drain()

            ack = None
            try:
                len_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=5)
                resp = json.loads(await asyncio.wait_for(reader.readexactly(int.from_bytes(len_bytes, 'big')), timeout=5))
                ack = resp.get('status', 'UNKNOWN')
            except Exception:
                ack = 'NO_RESPONSE'

            return ack
        finally:
            writer.close()
            await writer.wait_closed()

    async def _open_peer_connection(self, ip: str, port: int):
        target = (ip, port)
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=6)
            return reader, writer, target
        except asyncio.TimeoutError as exc:
            raise RuntimeError(f'Connexion timeout vers {ip}:{port}') from exc
        except OSError as exc:
            if getattr(exc, 'winerror', None) == 121 and ip != '127.0.0.1':
                # Windows may intermittently fail on discovered interfaces; try loopback in single-host demos.
                reader, writer = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', port), timeout=6)
                return reader, writer, ('127.0.0.1', port)

            msg = f'Connexion impossible vers {ip}:{port}'
            if getattr(exc, 'winerror', None):
                msg = f'{msg} (WinError {exc.winerror})'
            raise RuntimeError(msg) from exc
