import time
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Peer:
    node_id: str
    ip: str
    tcp_port: int
    last_seen: float = field(default_factory=time.time)


class PeerTable:
    def __init__(self, timeout=90):
        self._peers: Dict[str, Peer] = {}
        self.timeout = timeout

    def upsert(self, node_id, ip, tcp_port):
        key = f"{node_id}:{tcp_port}"
        self._peers[key] = Peer(node_id, ip, tcp_port, time.time())

    def alive(self) -> List[Peer]:
        now = time.time()
        return [p for p in self._peers.values() if now - p.last_seen < self.timeout]

    def remove_dead(self):
        dead = [nid for nid, p in self._peers.items() if time.time() - p.last_seen >= self.timeout]
        for nid in dead:
            del self._peers[nid]
            print(f'[PEER] Node removed (timeout): {nid[:12]}...')
