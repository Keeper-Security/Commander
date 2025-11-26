from __future__ import annotations
from typing import Any, Optional


class DAGException(Exception):

    def __init__(self, msg: Any, uid: Optional[str] = None):
        if not isinstance(msg, str):
            msg = str(msg)

        self.msg = msg
        self.uid = uid

        super().__init__(self.msg)

    def __str__(self):
        return self.msg

    def __repr__(self):
        return self.msg


class DAGKeyIsEncryptedException(DAGException):
    pass


class DAGDataEdgeNotFoundException(DAGException):
    pass


class DAGDeletionException(DAGException):
    pass


class DAGConfirmException(DAGException):
    pass


class DAGPathException(DAGException):
    pass


class DAGVertexAlreadyExistsException(DAGException):
    pass


class DAGContentException(DAGException):
    pass


class DAGDefaultGraphException(DAGException):
    pass


class DAGIllegalEdgeException(DAGException):
    pass


class DAGKeyException(DAGException):
    pass


class DAGDataException(DAGException):
    pass


class DAGVertexException(DAGException):
    pass


class DAGEdgeException(DAGException):
    pass


class DAGCorruptException(DAGException):
    pass


class DAGConnectionException(DAGException):
    pass
