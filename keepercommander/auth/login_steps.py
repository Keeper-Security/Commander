import abc
import enum
from typing import Optional, Sequence


class ILoginStep(abc.ABC):
    @abc.abstractmethod
    def cancel(self):
        pass

    def is_final(self):
        return False


class DeviceApprovalChannel(enum.Enum):
    Email = enum.auto()
    KeeperPush = enum.auto()
    TwoFactor = enum.auto()


class TwoFactorDuration(enum.IntEnum):
    EveryLogin = enum.auto()
    Every12Hours = enum.auto()
    Every24Hours = enum.auto()
    EveryDay = enum.auto()
    Every30Days = enum.auto()
    Forever = enum.auto()


class TwoFactorChannel(enum.Enum):
    Other = enum.auto()
    Authenticator = enum.auto()
    TextMessage = enum.auto()
    DuoSecurity = enum.auto()
    RSASecurID = enum.auto()
    KeeperDNA = enum.auto()
    SecurityKey = enum.auto()
    Backup = enum.auto()


class TwoFactorPushAction(enum.Enum):
    DuoPush = enum.auto()
    DuoTextMessage = enum.auto()
    DuoVoiceCall = enum.auto()
    TextMessage = enum.auto()
    KeeperDna = enum.auto()


class DataKeyShareChannel(enum.Enum):
    KeeperPush = enum.auto()
    AdminApproval = enum.auto()


class LoginStepDeviceApproval(ILoginStep, abc.ABC):
    @property
    @abc.abstractmethod
    def username(self):
        pass

    @abc.abstractmethod
    def send_push(self, channel):    # type: (DeviceApprovalChannel) -> None
        pass

    @abc.abstractmethod
    def send_code(self, channel, code):    # type: (DeviceApprovalChannel, str) -> None
        pass

    @abc.abstractmethod
    def resume(self):    # type: () -> None
        pass


class TwoFactorChannelInfo:
    def __init__(self) -> None:
        self.channel_type: TwoFactorChannel = TwoFactorChannel.Other
        self.channel_name = ''
        self.channel_uid = b''
        self.phone = None      # type: Optional[str]
        self.max_expiration: TwoFactorDuration = TwoFactorDuration.EveryLogin
        self.challenge = ''


class LoginStepTwoFactor(ILoginStep, abc.ABC):
    def __init__(self) -> None:
        self.duration: TwoFactorDuration = TwoFactorDuration.EveryLogin

    def get_max_duration(self):   # type: () -> TwoFactorDuration
        return TwoFactorDuration.Forever

    @abc.abstractmethod
    def get_channels(self):   # type: () -> Sequence[TwoFactorChannelInfo]
        pass

    @abc.abstractmethod
    def get_channel_push_actions(self, channel_uid):   # type: (bytes) -> Sequence[TwoFactorPushAction]
        pass

    @abc.abstractmethod
    def send_push(self, channel_uid, action):   # type: (bytes, TwoFactorPushAction) -> None
        pass

    @abc.abstractmethod
    def send_code(self, channel_uid: bytes, code: str) -> None:
        pass

    @abc.abstractmethod
    def resume(self) -> None:
        pass


class LoginStepSsoDataKey(ILoginStep, abc.ABC):
    @staticmethod
    def get_channels():   # type: () -> Sequence[DataKeyShareChannel]
        return DataKeyShareChannel.KeeperPush, DataKeyShareChannel.AdminApproval

    @abc.abstractmethod
    def request_data_key(self, channel):   # type: (DataKeyShareChannel)  -> None
        pass

    @abc.abstractmethod
    def resume(self):    # type: () -> None
        pass


class LoginStepPassword(ILoginStep, abc.ABC):
    @property
    @abc.abstractmethod
    def username(self):    # type: () -> str
        pass

    @abc.abstractmethod
    def forgot_password(self):    # type: () -> None
        pass

    @abc.abstractmethod
    def verify_password(self, password):    # type: (str) -> None
        pass

    @abc.abstractmethod
    def verify_biometric_key(self, biometric_key):   # type: (bytes) -> None
        pass


class LoginStepError(ILoginStep):
    def __init__(self, code, message):   # type: (str, str) -> None
        self.code = code
        self.message = message

    def is_final(self) -> bool:
        return True


class LoginStepSsoToken(ILoginStep, abc.ABC):
    @abc.abstractmethod
    def set_sso_token(self, token):    # type: (str) -> None
        pass

    @abc.abstractmethod
    def login_with_password(self):   # type: () -> None
        pass

    @property
    @abc.abstractmethod
    def is_cloud_sso(self):     # type: () -> bool
        pass

    @property
    @abc.abstractmethod
    def is_provider_login(self):     # type: () -> bool
        pass

    @property
    @abc.abstractmethod
    def login_name(self):    # type: () -> str
        pass

    @property
    @abc.abstractmethod
    def sso_login_url(self):    # type: () -> str
        pass


class LoginUi(abc.ABC):
    @abc.abstractmethod
    def on_device_approval(self, step):   # type: (LoginStepDeviceApproval) -> None
        pass

    @abc.abstractmethod
    def on_two_factor(self, step):        # type: (LoginStepTwoFactor) -> None
        pass

    @abc.abstractmethod
    def on_password(self, step):          # type: (LoginStepPassword) -> None
        pass

    @abc.abstractmethod
    def on_sso_redirect(self, step):      # type: (LoginStepSsoToken) -> None
        pass

    @abc.abstractmethod
    def on_sso_data_key(self, step):      # type: (LoginStepSsoDataKey) -> None
        pass
