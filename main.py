import argparse
import asyncio
import json
import os
import socket
from pathlib import Path

import nacl.public
from dotenv import load_dotenv

from src.crypto.cipher import derive_session_key, generate_x25519_keypair
from src.crypto.keys import load_keypair, node_id as get_node_id
from src.messaging.chat import ChatService
from src.network.discovery import DiscoveryService
from src.network.peer_table import PeerTable
from src.network.tcp_server import TCPServer
from src.transfer.chunker import split_file
from src.transfer.downloader import Downloader


def load_manifest(manifest_path: str) -> dict:
    with open(manifest_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_manifest(manifest: dict, out_dir: str = './manifests') -> str:
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{manifest['file_id']}.json")
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2)
    return out_path


async def peer_monitor(peers: PeerTable):
    while True:
        peers.remove_dead()
        alive = peers.alive()
        if alive:
            print('[PEERS] Active peers:')
            for p in alive:
                print(f'  - {p.node_id[:12]}... @ {p.ip}:{p.tcp_port}')
        else:
            print('[PEERS] No peer discovered yet')
        await asyncio.sleep(10)


async def run_start(port: int, shared_files: list[str]):
    peers = PeerTable()
    discovery = DiscoveryService(port, peers)
    tcp = TCPServer(port)
    chat = ChatService(peers)

    # file_id -> {chunk_index: bytes}
    shared_chunks: dict[str, dict[int, bytes]] = {}

    def register_shared_file(filepath: str):
        manifest, chunks = split_file(filepath)
        shared_chunks[manifest['file_id']] = chunks
        manifest_path = save_manifest(manifest)
        print(f"[SEND] Sharing: {filepath}")
        print(f"[SEND] file_id: {manifest['file_id']}")
        print(f"[SEND] chunks: {manifest['nb_chunks']}")
        print(f"[SEND] manifest: {manifest_path}")

    async def on_chunk_req(msg: dict, _addr):
        file_id = msg.get('file_id')
        chunk_idx = msg.get('chunk_idx')

        if file_id not in shared_chunks:
            return {'status': 'NOT_FOUND_FILE'}
        if chunk_idx not in shared_chunks[file_id]:
            return {'status': 'NOT_FOUND_CHUNK'}

        data = shared_chunks[file_id][chunk_idx]
        return {'status': 'OK', 'data': data.hex()}

    async def on_key_exchange(msg: dict, addr):
        sender_id = msg.get('from')
        peer_pub_hex = msg.get('pub')
        if not sender_id or not peer_pub_hex:
            return {'status': 'ERROR', 'reason': 'invalid key exchange payload'}

        my_priv, my_pub = generate_x25519_keypair()
        peer_pub = nacl.public.PublicKey(bytes.fromhex(peer_pub_hex))
        session_key = derive_session_key(my_priv, peer_pub)
        chat.sessions[sender_id] = session_key

        return {'status': 'OK', 'pub': bytes(my_pub).hex()}

    async def on_msg(msg: dict, addr):
        try:
            text = await chat.receive(msg, addr[0])
            payload = json.loads(msg['payload'])
            sender = payload.get('from', 'unknown')
            print(f'[CHAT] recv {addr[0]}:{addr[1]} -> local:{port} | {sender[:12]}... says: {text}')
            return {'status': 'OK'}
        except Exception as e:
            print(f'[CHAT] Receive error: {e}')
            return {'status': 'ERROR', 'reason': str(e)}

    tcp.register('CHUNK_REQ', on_chunk_req)
    tcp.register('KEY_EXCHANGE', on_key_exchange)
    tcp.register('MSG', on_msg)

    for filepath in shared_files:
        register_shared_file(filepath)

    async def udp_chat_server():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', port))
        sock.setblocking(False)
        loop = asyncio.get_event_loop()
        print(f'[UDP] Chat listener on port {port}')
        while True:
            data, addr = await loop.sock_recvfrom(sock, 1024 * 1024)
            try:
                msg = json.loads(data.decode())
                mtype = msg.get('type')

                if mtype == 'CHUNK_REQ_UDP':
                    file_id = msg.get('file_id')
                    chunk_idx = msg.get('chunk_idx')

                    if file_id not in shared_chunks:
                        resp = {'type': 'CHUNK_RESP_UDP', 'status': 'NOT_FOUND_FILE'}
                    elif chunk_idx not in shared_chunks[file_id]:
                        resp = {'type': 'CHUNK_RESP_UDP', 'status': 'NOT_FOUND_CHUNK'}
                    else:
                        chunk_bytes = shared_chunks[file_id][chunk_idx]
                        # UDP datagram size is limited; keep payload under practical MTU limits.
                        if len(chunk_bytes) > 60000:
                            resp = {'type': 'CHUNK_RESP_UDP', 'status': 'TOO_LARGE_UDP'}
                        else:
                            data_hex = chunk_bytes.hex()
                            resp = {'type': 'CHUNK_RESP_UDP', 'status': 'OK', 'data': data_hex}

                    await loop.sock_sendto(sock, json.dumps(resp).encode(), addr)
                    continue

                sender = msg.get('from', 'unknown')
                text = msg.get('text', '')
                print(f'[UDP-CHAT] recv {addr[0]}:{addr[1]} -> local:{port} | {sender[:12]}... says: {text}')
            except Exception as e:
                print(f'[UDP] Receive error: {e}')

    print(f'[ARCHIPEL] Node start on port {port}')
    await asyncio.gather(discovery.start(), tcp.start(), udp_chat_server(), peer_monitor(peers))


def cmd_send(filepath: str):
    manifest, _chunks = split_file(filepath)
    manifest_path = save_manifest(manifest)
    print(f"[SEND] Prepared file: {filepath}")
    print(f"[SEND] file_id: {manifest['file_id']}")
    print(f"[SEND] chunks: {manifest['nb_chunks']}")
    print(f"[SEND] manifest: {manifest_path}")
    print('[SEND] Run start command on sender node with --share to serve chunks.')


async def cmd_download(port: int, manifest_path: str, wait_seconds: int, output_dir: str, transport: str):
    manifest = load_manifest(manifest_path)

    peers = PeerTable()
    discovery = DiscoveryService(port, peers)
    tcp = TCPServer(port)

    async def noop_handler(_msg, _addr):
        return {'status': 'NOT_IMPLEMENTED'}

    tcp.register('CHUNK_REQ', noop_handler)

    print(f'[DL] Starting temporary node on port {port} to discover peers...')
    discovery_task = asyncio.create_task(discovery.start())
    tcp_task = asyncio.create_task(tcp.start())

    try:
        await asyncio.sleep(wait_seconds)
        alive = peers.alive()
        print(f'[DL] Discovered peers: {len(alive)}')
        for p in alive:
            print(f'  - {p.node_id[:12]}... @ {p.ip}:{p.tcp_port}')

        if not alive:
            # Local single-PC fallback for demo mode.
            peers.upsert('local-sender', '127.0.0.1', 7901)
            print('[DL] Fallback route injected: 127.0.0.1:7901')

        downloader = Downloader(peers, session_keys={})
        await downloader.download(manifest, output_dir=output_dir, transport=transport)
    finally:
        discovery_task.cancel()
        tcp_task.cancel()
        await asyncio.gather(discovery_task, tcp_task, return_exceptions=True)


async def cmd_msg_udp(port: int, peer_ip: str, peer_port: int, text: str):
    _sk, vk = load_keypair()
    my_id = get_node_id(vk)

    payload = json.dumps({'type': 'MSG_UDP', 'from': my_id, 'text': text}).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(payload, (peer_ip, peer_port))
    finally:
        sock.close()

    print(f'[UDP] Sent to {peer_ip}:{peer_port}')


async def cmd_msg(
    port: int,
    peer_id: str,
    text: str,
    wait_seconds: int,
    peer_port: int | None,
    peer_ip: str | None,
):
    peers = PeerTable()
    discovery = DiscoveryService(port, peers)
    tcp = TCPServer(port)
    chat = ChatService(peers)

    async def on_key_exchange(msg: dict, addr):
        sender_id = msg.get('from')
        peer_pub_hex = msg.get('pub')
        if not sender_id or not peer_pub_hex:
            return {'status': 'ERROR', 'reason': 'invalid key exchange payload'}

        my_priv, my_pub = generate_x25519_keypair()
        peer_pub = nacl.public.PublicKey(bytes.fromhex(peer_pub_hex))
        session_key = derive_session_key(my_priv, peer_pub)
        chat.sessions[sender_id] = session_key
        return {'status': 'OK', 'pub': bytes(my_pub).hex()}

    async def on_msg(msg: dict, addr):
        try:
            value = await chat.receive(msg, addr[0])
            payload = json.loads(msg['payload'])
            sender = payload.get('from', 'unknown')
            print(f'[CHAT] recv {addr[0]}:{addr[1]} -> local:{port} | {sender[:12]}... says: {value}')
            return {'status': 'OK'}
        except Exception as e:
            return {'status': 'ERROR', 'reason': str(e)}

    tcp.register('KEY_EXCHANGE', on_key_exchange)
    tcp.register('MSG', on_msg)

    print(f'[MSG] Starting temporary node on port {port} to discover peers...')
    discovery_task = asyncio.create_task(discovery.start())
    tcp_task = asyncio.create_task(tcp.start())

    try:
        await asyncio.sleep(wait_seconds)
        if peer_ip and peer_port is not None:
            peers.upsert(peer_id, peer_ip, peer_port)
            print(f'[MSG] Route injected: {peer_ip}:{peer_port}')
        elif peer_port is not None:
            targeted = any(p.node_id == peer_id and p.tcp_port == peer_port for p in peers.alive())
            if not targeted:
                print(
                    '[MSG] Peer not discovered yet for this id/port. '
                    'Retry with higher --wait-seconds or pass --peer-ip.'
                )
        await chat.send(peer_id, text, peer_port=peer_port)
        print('[MSG] Sent')
    finally:
        discovery_task.cancel()
        tcp_task.cancel()
        await asyncio.gather(discovery_task, tcp_task, return_exceptions=True)


def parse_args():
    load_dotenv()

    parser = argparse.ArgumentParser(description='Archipel - P2P file transfer + encrypted chat')
    sub = parser.add_subparsers(dest='command', required=False)

    p_start = sub.add_parser('start', help='Start node (discovery + tcp server)')
    p_start.add_argument('--port', type=int, default=int(os.getenv('NODE_PORT', '7777')))
    p_start.add_argument('--share', nargs='*', default=[], help='File path(s) to share')

    p_send = sub.add_parser('send', help='Prepare manifest for a file')
    p_send.add_argument('filepath', help='Path of file to prepare')

    p_dl = sub.add_parser('download', help='Download file using manifest + peers')
    p_dl.add_argument('manifest', help='Manifest JSON path')
    p_dl.add_argument('--port', type=int, default=int(os.getenv('NODE_PORT', '7777')))
    p_dl.add_argument('--wait-seconds', type=int, default=20, help='Discovery wait before download')
    p_dl.add_argument('--output-dir', default='./downloads')
    p_dl.add_argument('--transport', choices=['tcp', 'udp'], default='tcp', help='Chunk transfer transport')

    p_msg = sub.add_parser('msg', help='Send encrypted message to a peer id')
    p_msg.add_argument('peer_id', help='Target node id (hex)')
    p_msg.add_argument('text', help='Message text')
    p_msg.add_argument('--port', type=int, default=int(os.getenv('NODE_PORT', '7777')))
    p_msg.add_argument('--wait-seconds', type=int, default=12, help='Discovery wait before send')
    p_msg.add_argument('--peer-port', type=int, default=None, help='Target peer TCP port (recommended when node_id duplicates exist)')
    p_msg.add_argument('--peer-ip', type=str, default=None, help='Target peer IP (manual route when multicast discovery fails)')

    p_msg_udp = sub.add_parser('msg-udp', help='Send UDP message (no encryption)')
    p_msg_udp.add_argument('peer_ip', help='Target peer IPv4')
    p_msg_udp.add_argument('text', help='Message text')
    p_msg_udp.add_argument('--peer-port', type=int, required=True, help='Target peer UDP port')
    p_msg_udp.add_argument('--port', type=int, default=int(os.getenv('NODE_PORT', '7777')))

    parser.add_argument('--port', type=int, default=None, help=argparse.SUPPRESS)

    return parser.parse_args()


def main():
    args = parse_args()

    if args.command == 'start':
        shared_files = [str(Path(p).resolve()) for p in args.share]
        asyncio.run(run_start(args.port, shared_files))
        return

    if args.command == 'send':
        cmd_send(str(Path(args.filepath).resolve()))
        return

    if args.command == 'download':
        asyncio.run(
            cmd_download(
                port=args.port,
                manifest_path=str(Path(args.manifest).resolve()),
                wait_seconds=args.wait_seconds,
                output_dir=args.output_dir,
                transport=args.transport,
            )
        )
        return

    if args.command == 'msg':
        asyncio.run(
            cmd_msg(
                port=args.port,
                peer_id=args.peer_id,
                text=args.text,
                wait_seconds=args.wait_seconds,
                peer_port=args.peer_port,
                peer_ip=args.peer_ip,
            )
        )
        return

    if args.command == 'msg-udp':
        asyncio.run(
            cmd_msg_udp(
                port=args.port,
                peer_ip=args.peer_ip,
                peer_port=args.peer_port,
                text=args.text,
            )
        )
        return

    if args.port is not None:
        asyncio.run(run_start(args.port, []))
        return

    print('Use one of: start | send | download | msg | msg-udp')


if __name__ == '__main__':
    main()












