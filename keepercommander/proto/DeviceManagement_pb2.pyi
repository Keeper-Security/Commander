import APIRequest_pb2 as _APIRequest_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class DeviceActionType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DA_INVALID: _ClassVar[DeviceActionType]
    DA_LOGOUT: _ClassVar[DeviceActionType]
    DA_REMOVE: _ClassVar[DeviceActionType]
    DA_LOCK: _ClassVar[DeviceActionType]
    DA_UNLOCK: _ClassVar[DeviceActionType]
    DA_DEVICE_ACCOUNT_LOCK: _ClassVar[DeviceActionType]
    DA_DEVICE_ACCOUNT_UNLOCK: _ClassVar[DeviceActionType]
    DA_LINK: _ClassVar[DeviceActionType]
    DA_UNLINK: _ClassVar[DeviceActionType]

class DeviceActionStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INVALID: _ClassVar[DeviceActionStatus]
    SUCCESS: _ClassVar[DeviceActionStatus]
    NOT_ALLOWED: _ClassVar[DeviceActionStatus]

class ClientType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    NONE: _ClassVar[ClientType]
    ANDROID: _ClassVar[ClientType]
    BLACKBERRY: _ClassVar[ClientType]
    BLACKBERRY10: _ClassVar[ClientType]
    DESKTOP: _ClassVar[ClientType]
    IOS: _ClassVar[ClientType]
    MAC_APP: _ClassVar[ClientType]
    WEB_APP: _ClassVar[ClientType]
    WINDOWS_PHONE: _ClassVar[ClientType]
    SURFACE: _ClassVar[ClientType]
    WIN8: _ClassVar[ClientType]
    IE_EXTENSION: _ClassVar[ClientType]
    CHROME_EXTENSION: _ClassVar[ClientType]
    FIREFOX_EXTENSION: _ClassVar[ClientType]
    SAFARI_EXTENSION: _ClassVar[ClientType]
    DOCOMO: _ClassVar[ClientType]
    UNKNOWN: _ClassVar[ClientType]
    SERVER: _ClassVar[ClientType]
    COMMANDER: _ClassVar[ClientType]
    BRIDGE: _ClassVar[ClientType]
    ENTERPRISE_MANAGEMENT_CONSOLE: _ClassVar[ClientType]
    EDGE_EXTENSION: _ClassVar[ClientType]
    SUPPORT_TOOL: _ClassVar[ClientType]
    SSO_CONNECT: _ClassVar[ClientType]
    DESKTOP_ELECTRON: _ClassVar[ClientType]
    PASSWORD_IMPORTER: _ClassVar[ClientType]
    CHAT: _ClassVar[ClientType]
    MAC_APP_ELECTRON: _ClassVar[ClientType]
    CHAT_IOS: _ClassVar[ClientType]
    CHAT_ANDROID: _ClassVar[ClientType]
    CHAT_WINDOWS: _ClassVar[ClientType]
    CHAT_MAC: _ClassVar[ClientType]
    SCIM: _ClassVar[ClientType]
    LAMBDA: _ClassVar[ClientType]
    CONNECTWISE_CONTROL_HELPER: _ClassVar[ClientType]
    ENTERPRISE_CLIENT_TOOL: _ClassVar[ClientType]
    SECRETS_MANAGER_JS: _ClassVar[ClientType]
    SECRETS_MANAGER_PYTHON: _ClassVar[ClientType]
    SECRETS_MANAGER_GO: _ClassVar[ClientType]
    SECRETS_MANAGER_JAVA: _ClassVar[ClientType]
    SECRETS_MANAGER_NET: _ClassVar[ClientType]

class ClientTypeCategory(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CAT_NONE: _ClassVar[ClientTypeCategory]
    CAT_ADMIN: _ClassVar[ClientTypeCategory]
    CAT_DESKTOP: _ClassVar[ClientTypeCategory]
    CAT_EXTENSION: _ClassVar[ClientTypeCategory]
    CAT_MOBILE: _ClassVar[ClientTypeCategory]
    CAT_OTHER: _ClassVar[ClientTypeCategory]
    CAT_WEB_VAULT: _ClassVar[ClientTypeCategory]
    CAT_CHAT_DESKTOP: _ClassVar[ClientTypeCategory]
    CAT_CHAT_MOBILE: _ClassVar[ClientTypeCategory]
    CAT_SECRETS_MANAGER: _ClassVar[ClientTypeCategory]
DA_INVALID: DeviceActionType
DA_LOGOUT: DeviceActionType
DA_REMOVE: DeviceActionType
DA_LOCK: DeviceActionType
DA_UNLOCK: DeviceActionType
DA_DEVICE_ACCOUNT_LOCK: DeviceActionType
DA_DEVICE_ACCOUNT_UNLOCK: DeviceActionType
DA_LINK: DeviceActionType
DA_UNLINK: DeviceActionType
INVALID: DeviceActionStatus
SUCCESS: DeviceActionStatus
NOT_ALLOWED: DeviceActionStatus
NONE: ClientType
ANDROID: ClientType
BLACKBERRY: ClientType
BLACKBERRY10: ClientType
DESKTOP: ClientType
IOS: ClientType
MAC_APP: ClientType
WEB_APP: ClientType
WINDOWS_PHONE: ClientType
SURFACE: ClientType
WIN8: ClientType
IE_EXTENSION: ClientType
CHROME_EXTENSION: ClientType
FIREFOX_EXTENSION: ClientType
SAFARI_EXTENSION: ClientType
DOCOMO: ClientType
UNKNOWN: ClientType
SERVER: ClientType
COMMANDER: ClientType
BRIDGE: ClientType
ENTERPRISE_MANAGEMENT_CONSOLE: ClientType
EDGE_EXTENSION: ClientType
SUPPORT_TOOL: ClientType
SSO_CONNECT: ClientType
DESKTOP_ELECTRON: ClientType
PASSWORD_IMPORTER: ClientType
CHAT: ClientType
MAC_APP_ELECTRON: ClientType
CHAT_IOS: ClientType
CHAT_ANDROID: ClientType
CHAT_WINDOWS: ClientType
CHAT_MAC: ClientType
SCIM: ClientType
LAMBDA: ClientType
CONNECTWISE_CONTROL_HELPER: ClientType
ENTERPRISE_CLIENT_TOOL: ClientType
SECRETS_MANAGER_JS: ClientType
SECRETS_MANAGER_PYTHON: ClientType
SECRETS_MANAGER_GO: ClientType
SECRETS_MANAGER_JAVA: ClientType
SECRETS_MANAGER_NET: ClientType
CAT_NONE: ClientTypeCategory
CAT_ADMIN: ClientTypeCategory
CAT_DESKTOP: ClientTypeCategory
CAT_EXTENSION: ClientTypeCategory
CAT_MOBILE: ClientTypeCategory
CAT_OTHER: ClientTypeCategory
CAT_WEB_VAULT: ClientTypeCategory
CAT_CHAT_DESKTOP: ClientTypeCategory
CAT_CHAT_MOBILE: ClientTypeCategory
CAT_SECRETS_MANAGER: ClientTypeCategory

class Device(_message.Message):
    __slots__ = ("encryptedDeviceToken", "deviceName", "devicePlatform", "deviceStatus", "loginState", "clientVersion", "clientType", "clientTypeCategory", "clientFormFactor", "lastModifiedTime")
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    DEVICENAME_FIELD_NUMBER: _ClassVar[int]
    DEVICEPLATFORM_FIELD_NUMBER: _ClassVar[int]
    DEVICESTATUS_FIELD_NUMBER: _ClassVar[int]
    LOGINSTATE_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    CLIENTTYPE_FIELD_NUMBER: _ClassVar[int]
    CLIENTTYPECATEGORY_FIELD_NUMBER: _ClassVar[int]
    CLIENTFORMFACTOR_FIELD_NUMBER: _ClassVar[int]
    LASTMODIFIEDTIME_FIELD_NUMBER: _ClassVar[int]
    encryptedDeviceToken: bytes
    deviceName: str
    devicePlatform: str
    deviceStatus: _APIRequest_pb2.DeviceStatus
    loginState: _APIRequest_pb2.LoginState
    clientVersion: str
    clientType: ClientType
    clientTypeCategory: ClientTypeCategory
    clientFormFactor: _APIRequest_pb2.ClientFormFactor
    lastModifiedTime: int
    def __init__(self, encryptedDeviceToken: _Optional[bytes] = ..., deviceName: _Optional[str] = ..., devicePlatform: _Optional[str] = ..., deviceStatus: _Optional[_Union[_APIRequest_pb2.DeviceStatus, str]] = ..., loginState: _Optional[_Union[_APIRequest_pb2.LoginState, str]] = ..., clientVersion: _Optional[str] = ..., clientType: _Optional[_Union[ClientType, str]] = ..., clientTypeCategory: _Optional[_Union[ClientTypeCategory, str]] = ..., clientFormFactor: _Optional[_Union[_APIRequest_pb2.ClientFormFactor, str]] = ..., lastModifiedTime: _Optional[int] = ...) -> None: ...

class DeviceGroup(_message.Message):
    __slots__ = ("devices",)
    DEVICES_FIELD_NUMBER: _ClassVar[int]
    devices: _containers.RepeatedCompositeFieldContainer[Device]
    def __init__(self, devices: _Optional[_Iterable[_Union[Device, _Mapping]]] = ...) -> None: ...

class DeviceUserResponse(_message.Message):
    __slots__ = ("deviceGroups",)
    DEVICEGROUPS_FIELD_NUMBER: _ClassVar[int]
    deviceGroups: _containers.RepeatedCompositeFieldContainer[DeviceGroup]
    def __init__(self, deviceGroups: _Optional[_Iterable[_Union[DeviceGroup, _Mapping]]] = ...) -> None: ...

class DeviceActionRequest(_message.Message):
    __slots__ = ("deviceAction",)
    DEVICEACTION_FIELD_NUMBER: _ClassVar[int]
    deviceAction: _containers.RepeatedCompositeFieldContainer[DeviceAction]
    def __init__(self, deviceAction: _Optional[_Iterable[_Union[DeviceAction, _Mapping]]] = ...) -> None: ...

class DeviceAction(_message.Message):
    __slots__ = ("deviceActionType", "encryptedDeviceToken")
    DEVICEACTIONTYPE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    deviceActionType: DeviceActionType
    encryptedDeviceToken: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, deviceActionType: _Optional[_Union[DeviceActionType, str]] = ..., encryptedDeviceToken: _Optional[_Iterable[bytes]] = ...) -> None: ...

class DeviceActionResponse(_message.Message):
    __slots__ = ("deviceActionResult", "deviceGroups")
    DEVICEACTIONRESULT_FIELD_NUMBER: _ClassVar[int]
    DEVICEGROUPS_FIELD_NUMBER: _ClassVar[int]
    deviceActionResult: _containers.RepeatedCompositeFieldContainer[DeviceActionResult]
    deviceGroups: _containers.RepeatedCompositeFieldContainer[DeviceGroup]
    def __init__(self, deviceActionResult: _Optional[_Iterable[_Union[DeviceActionResult, _Mapping]]] = ..., deviceGroups: _Optional[_Iterable[_Union[DeviceGroup, _Mapping]]] = ...) -> None: ...

class DeviceActionResult(_message.Message):
    __slots__ = ("deviceActionType", "encryptedDeviceToken", "deviceActionStatus")
    DEVICEACTIONTYPE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    DEVICEACTIONSTATUS_FIELD_NUMBER: _ClassVar[int]
    deviceActionType: DeviceActionType
    encryptedDeviceToken: _containers.RepeatedScalarFieldContainer[bytes]
    deviceActionStatus: DeviceActionStatus
    def __init__(self, deviceActionType: _Optional[_Union[DeviceActionType, str]] = ..., encryptedDeviceToken: _Optional[_Iterable[bytes]] = ..., deviceActionStatus: _Optional[_Union[DeviceActionStatus, str]] = ...) -> None: ...

class DeviceRenameRequest(_message.Message):
    __slots__ = ("deviceRename",)
    DEVICERENAME_FIELD_NUMBER: _ClassVar[int]
    deviceRename: _containers.RepeatedCompositeFieldContainer[DeviceRename]
    def __init__(self, deviceRename: _Optional[_Iterable[_Union[DeviceRename, _Mapping]]] = ...) -> None: ...

class DeviceRename(_message.Message):
    __slots__ = ("encryptedDeviceToken", "deviceNewName")
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    DEVICENEWNAME_FIELD_NUMBER: _ClassVar[int]
    encryptedDeviceToken: bytes
    deviceNewName: str
    def __init__(self, encryptedDeviceToken: _Optional[bytes] = ..., deviceNewName: _Optional[str] = ...) -> None: ...

class DeviceRenameResponse(_message.Message):
    __slots__ = ("deviceRenameResult", "deviceGroups")
    DEVICERENAMERESULT_FIELD_NUMBER: _ClassVar[int]
    DEVICEGROUPS_FIELD_NUMBER: _ClassVar[int]
    deviceRenameResult: _containers.RepeatedCompositeFieldContainer[DeviceRenameResult]
    deviceGroups: _containers.RepeatedCompositeFieldContainer[DeviceGroup]
    def __init__(self, deviceRenameResult: _Optional[_Iterable[_Union[DeviceRenameResult, _Mapping]]] = ..., deviceGroups: _Optional[_Iterable[_Union[DeviceGroup, _Mapping]]] = ...) -> None: ...

class DeviceRenameResult(_message.Message):
    __slots__ = ("encryptedDeviceToken", "deviceNewName", "deviceActionStatus")
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    DEVICENEWNAME_FIELD_NUMBER: _ClassVar[int]
    DEVICEACTIONSTATUS_FIELD_NUMBER: _ClassVar[int]
    encryptedDeviceToken: bytes
    deviceNewName: str
    deviceActionStatus: DeviceActionStatus
    def __init__(self, encryptedDeviceToken: _Optional[bytes] = ..., deviceNewName: _Optional[str] = ..., deviceActionStatus: _Optional[_Union[DeviceActionStatus, str]] = ...) -> None: ...

class DeviceAdminRequest(_message.Message):
    __slots__ = ("enterpriseUserIds",)
    ENTERPRISEUSERIDS_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserIds: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, enterpriseUserIds: _Optional[_Iterable[int]] = ...) -> None: ...

class DeviceAdminResponse(_message.Message):
    __slots__ = ("deviceUserList",)
    DEVICEUSERLIST_FIELD_NUMBER: _ClassVar[int]
    deviceUserList: _containers.RepeatedCompositeFieldContainer[DeviceUserList]
    def __init__(self, deviceUserList: _Optional[_Iterable[_Union[DeviceUserList, _Mapping]]] = ...) -> None: ...

class DeviceUserList(_message.Message):
    __slots__ = ("enterpriseUserId", "deviceGroups")
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    DEVICEGROUPS_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    deviceGroups: _containers.RepeatedCompositeFieldContainer[DeviceGroup]
    def __init__(self, enterpriseUserId: _Optional[int] = ..., deviceGroups: _Optional[_Iterable[_Union[DeviceGroup, _Mapping]]] = ...) -> None: ...

class DeviceAdminActionRequest(_message.Message):
    __slots__ = ("deviceAdminAction",)
    DEVICEADMINACTION_FIELD_NUMBER: _ClassVar[int]
    deviceAdminAction: _containers.RepeatedCompositeFieldContainer[DeviceAdminAction]
    def __init__(self, deviceAdminAction: _Optional[_Iterable[_Union[DeviceAdminAction, _Mapping]]] = ...) -> None: ...

class DeviceAdminAction(_message.Message):
    __slots__ = ("deviceActionType", "enterpriseUserId", "encryptedDeviceToken")
    DEVICEACTIONTYPE_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    deviceActionType: DeviceActionType
    enterpriseUserId: int
    encryptedDeviceToken: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, deviceActionType: _Optional[_Union[DeviceActionType, str]] = ..., enterpriseUserId: _Optional[int] = ..., encryptedDeviceToken: _Optional[_Iterable[bytes]] = ...) -> None: ...

class DeviceAdminActionResponse(_message.Message):
    __slots__ = ("deviceAdminActionResults",)
    DEVICEADMINACTIONRESULTS_FIELD_NUMBER: _ClassVar[int]
    deviceAdminActionResults: _containers.RepeatedCompositeFieldContainer[DeviceAdminActionResult]
    def __init__(self, deviceAdminActionResults: _Optional[_Iterable[_Union[DeviceAdminActionResult, _Mapping]]] = ...) -> None: ...

class DeviceAdminActionResult(_message.Message):
    __slots__ = ("deviceActionType", "enterpriseUserId", "encryptedDeviceToken", "deviceActionStatus")
    DEVICEACTIONTYPE_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    DEVICEACTIONSTATUS_FIELD_NUMBER: _ClassVar[int]
    deviceActionType: DeviceActionType
    enterpriseUserId: int
    encryptedDeviceToken: _containers.RepeatedScalarFieldContainer[bytes]
    deviceActionStatus: DeviceActionStatus
    def __init__(self, deviceActionType: _Optional[_Union[DeviceActionType, str]] = ..., enterpriseUserId: _Optional[int] = ..., encryptedDeviceToken: _Optional[_Iterable[bytes]] = ..., deviceActionStatus: _Optional[_Union[DeviceActionStatus, str]] = ...) -> None: ...
