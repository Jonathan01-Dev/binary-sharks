import asyncio
import json
import socket
import struct
import time

from src.crypto.keys import load_keypair, node_id as get_node_id
from src.network.peer_table import PeerTable


MCAST_GRP = '239.255.42.99'
MCAST_PORT = 6000


class DiscoveryService:
    def __init__(self, tcp_port: int, peer_table: PeerTable):
        self.tcp_port = tcp_port
        self.peers = peer_table
        self.sk, self.vk = load_keypair()
        self.my_id = get_node_id(self.vk)

    def _build_hello(self) -> bytes:
        payload = json.dumps(
            {
                'type': 'HELLO',
                'node_id': self.my_id,
                'tcp_port': self.tcp_port,
                'ts': time.time(),
            }
        ).encode()
        return payload

    async def broadcast_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        print(f'[DISCOVERY] Broadcast on {MCAST_GRP}:{MCAST_PORT}')
        while True:
            sock.sendto(self._build_hello(), (MCAST_GRP, MCAST_PORT))
            print(f'[HELLO] Broadcast sent - node {self.my_id[:12]}...')
            await asyncio.sleep(30)

    async def listen_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', MCAST_PORT))

        mreq = struct.pack('4sL', socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.setblocking(False)
        loop = asyncio.get_event_loop()
        print('[DISCOVERY] Listening multicast...')

        while True:
            try:
                data, addr = await loop.sock_recvfrom(sock, 4096)
                msg = json.loads(data.decode())
                if not (
                    msg.get('node_id') == self.my_id
                    and int(msg.get('tcp_port', -1)) == self.tcp_port
                ):
                    self.peers.upsert(msg['node_id'], addr[0], msg['tcp_port'])
                    print(f'[PEER] Found {msg["node_id"][:12]}... @ {addr[0]}:{msg["tcp_port"]}')
            except BlockingIOError:
                await asyncio.sleep(1)
            except Exception as e:
                print(f'[DISCOVERY] Listen error: {e}')
                await asyncio.sleep(1)

    async def start(self):
        await asyncio.gather(self.broadcast_loop(), self.listen_loop())

