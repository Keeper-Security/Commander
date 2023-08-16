import asyncio

from websockets.client import WebSocketClientProtocol

from .tunnel import ITunnel


class ConnectedTunnel(ITunnel):
    def __init__(self, ws):
        self.ws = ws    # type: WebSocketClientProtocol
        self.input_queue = asyncio.Queue()
        self.output_queue = asyncio.Queue()
        self._disconnect_requested = False

    def connect(self) -> None:
        pass

    def is_connected(self):
        return True

    def disconnect(self) -> None:
        self._disconnect_requested = True

    async def ws_reader(self):
        ws = self.ws
        async for frame in ws:
            await self.output_queue.put(frame)

    async def ws_writer(self):
        while not self._disconnect_requested:
            frame = await self.input_queue.get()
            if frame:
                await self.ws.send(frame)

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
                await self.input_queue.put(data)
