import asyncio
import json
import os

from src.network.peer_table import PeerTable
from src.transfer.chunker import reassemble, verify_chunk


class Downloader:
    def __init__(self, peer_table: PeerTable, session_keys: dict):
        self.peers = peer_table
        self.sessions = session_keys  # node_id -> session_key

    async def download(self, manifest: dict, output_dir: str = './downloads'):
        """Download a file chunk by chunk from peers."""
        file_id = manifest['file_id']
        nb_chunks = manifest['nb_chunks']
        chunk_map = {c['index']: c for c in manifest['chunks']}
        received = {}
        peers = self.peers.alive()

        if not peers:
            raise RuntimeError('Aucun pair disponible pour le telechargement')

        print(f'[DL] Start - {nb_chunks} chunks to download')

        sem = asyncio.Semaphore(3)

        async def fetch_chunk(idx: int):
            async with sem:
                for _attempt in range(3):
                    peer = peers[idx % len(peers)]
                    try:
                        data = await self._request_chunk(peer, file_id, idx)
                        if verify_chunk(data, chunk_map[idx]['hash']):
                            received[idx] = data
                            print(f'[DL] Chunk {idx + 1}/{nb_chunks} OK')
                            return
                        print(f'[DL] Chunk {idx} corrupted - retry')
                    except Exception as e:
                        print(f'[DL] Chunk {idx} error via {peer.ip}: {e}')
                print(f'[DL] FAIL chunk {idx} after 3 attempts')

        await asyncio.gather(*[fetch_chunk(i) for i in range(nb_chunks)])

        if len(received) != nb_chunks:
            raise RuntimeError(f'Chunks manquants : {nb_chunks - len(received)}')

        output_path = os.path.join(output_dir, manifest['filename'])
        final_hash = reassemble(received, nb_chunks, output_path)
        print(f'[DL] File completed: {output_path}')
        print(f'[DL] SHA-256: {final_hash}')
        print(f'[DL] Expected: {file_id}')
        print(f'[DL] Integrity: {"OK" if final_hash == file_id else "ERROR"}')
        return output_path

    async def _request_chunk(self, peer, file_id: str, idx: int) -> bytes:
        reader, writer = await asyncio.open_connection(peer.ip, peer.tcp_port)
        req = json.dumps({'type': 'CHUNK_REQ', 'file_id': file_id, 'chunk_idx': idx}).encode()
        writer.write(len(req).to_bytes(4, 'big') + req)
        await writer.drain()

        len_bytes = await reader.readexactly(4)
        resp = json.loads(await reader.readexactly(int.from_bytes(len_bytes, 'big')))

        writer.close()
        await writer.wait_closed()

        if resp.get('status') != 'OK':
            raise ValueError(f'Chunk refuse: {resp.get("status")}')
        return bytes.fromhex(resp['data'])
