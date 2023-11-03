import abc
import asyncio


class ITunnel(abc.ABC):
    @abc.abstractmethod
    async def connect(self) -> None:
        pass

    @abc.abstractmethod
    def disconnect(self) -> None:
        pass

    @property
    @abc.abstractmethod
    def is_connected(self) -> bool:
        pass

    @abc.abstractmethod
    async def read(self, timeout: int = -1) -> bytes:
        pass

    @abc.abstractmethod
    async def write(self, data: bytes) -> None:
        pass


class LocalTunnel(ITunnel):
    def __init__(self, own: asyncio.Queue, other: asyncio.Queue):
        self._own = own
        self._other = other
        self._connected = False

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def connect(self) -> None:
        self._connected = True

    def disconnect(self) -> None:
        self._connected = False

    async def write(self, data: bytes) -> None:
        await self._other.put(data)

    async def read(self, timeout: int = -1) -> bytes:
        if timeout > 0:
            buffer = await asyncio.wait_for(self._own.get(), timeout)
        else:
            buffer = await self._own.get()
        self._own.task_done()
        return buffer
