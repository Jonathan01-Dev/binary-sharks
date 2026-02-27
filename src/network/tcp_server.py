import asyncio
import json


class TCPServer:
    def __init__(self, port: int):
        self.port = port
        self.handlers = {}

    def register(self, msg_type: str, callback):
        self.handlers[msg_type] = callback

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        print(f'[TCP] Incoming connection from {addr}')
        try:
            while True:
                len_bytes = await reader.readexactly(4)
                msg_len = int.from_bytes(len_bytes, 'big')
                raw = await reader.readexactly(msg_len)
                msg = json.loads(raw.decode())
                handler = self.handlers.get(msg.get('type'))
                if handler:
                    response = await handler(msg, addr)
                    if response:
                        resp_bytes = json.dumps(response).encode()
                        writer.write(len(resp_bytes).to_bytes(4, 'big') + resp_bytes)
                        await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            print(f'[TCP] Connection closed: {addr}')
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self):
        server = await asyncio.start_server(self.handle_client, '0.0.0.0', self.port)
        print(f'[TCP] Server started on port {self.port}')
        async with server:
            await server.serve_forever()
