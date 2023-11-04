import asyncio
import json

from websockets.client import WebSocketClientProtocol

from keepercommander import utils
from keepercommander.utils import is_json
from .tunnel import ITunnel


class ConnectedTunnel(ITunnel):
    def __init__(self, ws):
        self.ws = ws                         # type: WebSocketClientProtocol
        self.input_queue = asyncio.Queue()
        self.output_queue = asyncio.Queue()
        self._disconnect_requested = False

    def connect(self):    # type: () -> None
        pass

    def is_connected(self):
        return True

    def disconnect(self):   # type: () -> None
        self._disconnect_requested = True

    async def ws_reader(self):
        ws = self.ws
        async for frame in ws:
            if isinstance(frame, str):
                if is_json(frame):
                    frame = json.loads(frame)
                    frame_data = frame.get('data')
                else:
                    data = utils.base64_url_decode(frame)

                    await self.output_queue.put(data)

    async def ws_writer(self):
        while not self._disconnect_requested:
            frame = await self.input_queue.get()
            if frame:
                if isinstance(frame, bytes):
                    frame = utils.base64_url_encode(frame)
                await self.ws.send(frame)
        await self.ws.close()

    async def read(self, timeout = -1):
        if timeout > 0:
            buffer = await asyncio.wait_for(self.output_queue.get(), timeout)
        else:
            buffer = await self.output_queue.get()
        self.output_queue.task_done()
        return buffer

    async def write(self, data):
        if self.is_connected:
            if len(data) > 0:
                await self.input_queue.put(data)
