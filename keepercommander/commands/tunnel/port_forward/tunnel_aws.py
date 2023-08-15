import asyncio
import base64
import collections
import json
import logging
import secrets
import ssl
from typing import Optional

import websockets
from websockets.client import WebSocketClientProtocol

from .tunnel import ITunnel

ENDPOINT = 'wss://c9scndh3wi.execute-api.us-west-2.amazonaws.com/production'
MAX_PACKET_SIZE = 31 * 1024
MAX_BUFFER_SIZE = 24 * 1024


class AwsTunnel(ITunnel):
    logger = logging.getLogger('keeper.aws_tunnel')

    def __init__(self, room_id: str):
        self.room_id = room_id
        self.user_id = base64.b64encode(secrets.token_bytes(8)).decode()
        self.ws = None    # type: Optional[WebSocketClientProtocol]
        self.verify_cert = True
        self.pair_id: Optional[str] = None
        self.input_queue = asyncio.Queue()
        self.output_queue = asyncio.Queue()
        self.acknowledged = asyncio.Event()

    @property
    def is_connected(self) -> bool:
        return self.ws is not None and self.pair_id is not None

    async def ws_writer(self):
        ws = self.ws
        queue = collections.deque()
        while ws.open:
            try:
                buffer = self.input_queue.get_nowait()
                self.input_queue.task_done()
                if buffer:
                    queue.append(buffer)
            except asyncio.QueueEmpty:
                if len(queue) == 0:
                    buffer = await self.input_queue.get()
                    if buffer:
                        queue.append(buffer)

            if not ws.open:
                return

            if len(queue) == 0:
                continue

            message = {
                'PairConnection': self.pair_id,
                'Command': 'DATA',
                'Data': []
            }

            left = MAX_PACKET_SIZE
            while len(queue) > 0:
                buffer = queue.popleft()
                b64buffer = base64.b64encode(buffer).decode()
                if len(b64buffer) + 6 < left:
                    message['Data'].append(b64buffer)
                    left -= len(b64buffer) + 6
                else:
                    queue.insert(0, buffer)
                    break

            frame = json.dumps(message)
            self.acknowledged.clear()
            await self.ws.send(frame)
            try:
                await asyncio.wait_for(self.acknowledged.wait(), timeout=0.5)
            except asyncio.TimeoutError:
                self.logger.debug('Timed out getting ACK')
                self.acknowledged.set()

        while not self.input_queue.empty():
            _ = self.input_queue.get_nowait()
            self.input_queue.task_done()

    async def ws_reader(self, connected_evt: asyncio.Event):
        self.acknowledged.set()
        ws = self.ws
        async for frame in ws:
            try:
                message = json.loads(frame)
            except Exception as e:
                self.logger.warning('JSON parse error: %s', e)
                continue

            pair_id = message.get('PairConnection')
            command = message.get('Command')
            if command in ('HELO', 'EHLO'):
                self.pair_id = pair_id
                if command == 'HELO':
                    message['Command'] = 'EHLO'
                    frame = json.dumps(message)
                    await self.ws.send(frame)
                connected_evt.set()
                connected_evt = None
            else:
                if command in ('ACK', 'NAK'):
                    self.acknowledged.set()
                    if command == 'NAK':
                        self.logger.warning('Message has not been delivered with error: %s', message.get('Error'))
                elif command == 'DATA':
                    if pair_id == self.pair_id:
                        data = message.get('Data')
                        if isinstance(data, list):
                            for message in data:
                                buffer = base64.b64decode(message)
                                await self.output_queue.put(buffer)
                    elif self.pair_id is not None:
                        self.logger.warning('Invalid pair_id "%s". Expected "%s"', pair_id, self.pair_id)

    async def connect(self) -> None:
        await self.disconnect()
        headers = {
            'Authorization': f'DYNAMO-TUNNEL request_id={self.room_id},user_id={self.user_id}'
        }
        ssl_context = ssl.SSLContext()
        ssl_context.verify_mode = ssl.CERT_REQUIRED if self.verify_cert else ssl.CERT_NONE
        self.ws = await websockets.connect(ENDPOINT, extra_headers=headers, ssl=ssl_context, ping_interval=5 * 60)
        self.pair_id = None
        on_connected = asyncio.Event()
        t1 = asyncio.create_task(self.ws_reader(on_connected))
        t2 = asyncio.create_task(on_connected.wait())
        done, active = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        if len(done) == 1 and t2 in done:
            _ = asyncio.create_task(self.ws_writer())
            logging.info('Tunnel %s connected.', self.user_id)
        else:
            await self.disconnect()

    async def disconnect(self) -> None:
        if self.ws:
            await self.ws.close()
            self.ws = None
        self.pair_id = None
        await self.input_queue.put(b'')
        self.acknowledged.set()
        while not self.output_queue.empty():
            _ = self.output_queue.get_nowait()
            self.output_queue.task_done()

    async def read(self, timeout: int = -1) -> bytes:
        if timeout > 0:
            buffer = await asyncio.wait_for(self.output_queue.get(), timeout)
        else:
            buffer = await self.output_queue.get()
        self.output_queue.task_done()
        return buffer

    async def write(self, data: bytes) -> None:
        if self.is_connected:
            while len(data) > 0:
                buffer = data[:MAX_BUFFER_SIZE]
                data = data[MAX_BUFFER_SIZE:]
                await self.input_queue.put(buffer)
        else:
            raise Exception('Not connected')
