import abc
import asyncio


class ITunnel(abc.ABC):
    @abc.abstractmethod
    async def connect(self):   # type: () -> None
        pass

    @abc.abstractmethod
    def disconnect(self):      # type: () -> None
        pass

    @property
    @abc.abstractmethod
    def is_connected(self):    # type: () -> bool
        pass

    @abc.abstractmethod
    async def read(self, timeout = -1):  # type: (int) -> bytes
        pass

    @abc.abstractmethod
    async def write(self, data):  # type: (bytes) -> None
        pass


class LocalTunnel(ITunnel):
    def __init__(self, own, other):   # type: (asyncio.Queue, asyncio.Queue) -> None
        self._own = own
        self._other = other
        self._connected = False

    @property
    def is_connected(self):
        return self._connected

    async def connect(self):
        self._connected = True

    def disconnect(self):
        self._connected = False

    async def write(self, data):
        await self._other.put(data)

    async def read(self, timeout = -1):
        if timeout > 0:
            buffer = await asyncio.wait_for(self._own.get(), timeout)
        else:
            buffer = await self._own.get()
        self._own.task_done()
        return buffer
