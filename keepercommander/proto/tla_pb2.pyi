from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class TimerNotificationType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    NOTIFICATION_OFF: _ClassVar[TimerNotificationType]
    NOTIFY_OWNER: _ClassVar[TimerNotificationType]
    NOTIFY_PRIVILEGED_USERS: _ClassVar[TimerNotificationType]
NOTIFICATION_OFF: TimerNotificationType
NOTIFY_OWNER: TimerNotificationType
NOTIFY_PRIVILEGED_USERS: TimerNotificationType

class TLAProperties(_message.Message):
    __slots__ = ("expiration", "timerNotificationType", "rotateOnExpiration")
    EXPIRATION_FIELD_NUMBER: _ClassVar[int]
    TIMERNOTIFICATIONTYPE_FIELD_NUMBER: _ClassVar[int]
    ROTATEONEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    expiration: int
    timerNotificationType: TimerNotificationType
    rotateOnExpiration: bool
    def __init__(self, expiration: _Optional[int] = ..., timerNotificationType: _Optional[_Union[TimerNotificationType, str]] = ..., rotateOnExpiration: bool = ...) -> None: ...
