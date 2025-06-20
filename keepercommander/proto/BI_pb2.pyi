from google.protobuf import struct_pb2 as _struct_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Currency(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    UNKNOWN: _ClassVar[Currency]
    USD: _ClassVar[Currency]
    GBP: _ClassVar[Currency]
    JPY: _ClassVar[Currency]
    EUR: _ClassVar[Currency]
    AUD: _ClassVar[Currency]
    CAD: _ClassVar[Currency]

class GradientIntegrationStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    NOTCONNECTED: _ClassVar[GradientIntegrationStatus]
    PENDING: _ClassVar[GradientIntegrationStatus]
    CONNECTED: _ClassVar[GradientIntegrationStatus]
    NONE: _ClassVar[GradientIntegrationStatus]

class EventType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    UNKNOWN_TRACKING_EVENT_TYPE: _ClassVar[EventType]
    TRACKING_POPUP_DISPLAYED: _ClassVar[EventType]
    TRACKING_POPUP_ACCEPTED: _ClassVar[EventType]
    TRACKING_POPUP_DISMISSED: _ClassVar[EventType]
    TRACKING_POPUP_PAID: _ClassVar[EventType]
    TRACKING_PUSH_CLICKED: _ClassVar[EventType]
UNKNOWN: Currency
USD: Currency
GBP: Currency
JPY: Currency
EUR: Currency
AUD: Currency
CAD: Currency
NOTCONNECTED: GradientIntegrationStatus
PENDING: GradientIntegrationStatus
CONNECTED: GradientIntegrationStatus
NONE: GradientIntegrationStatus
UNKNOWN_TRACKING_EVENT_TYPE: EventType
TRACKING_POPUP_DISPLAYED: EventType
TRACKING_POPUP_ACCEPTED: EventType
TRACKING_POPUP_DISMISSED: EventType
TRACKING_POPUP_PAID: EventType
TRACKING_PUSH_CLICKED: EventType

class ValidateSessionTokenRequest(_message.Message):
    __slots__ = ["encryptedSessionToken", "returnMcEnterpiseIds", "ip"]
    ENCRYPTEDSESSIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    RETURNMCENTERPISEIDS_FIELD_NUMBER: _ClassVar[int]
    IP_FIELD_NUMBER: _ClassVar[int]
    encryptedSessionToken: bytes
    returnMcEnterpiseIds: bool
    ip: str
    def __init__(self, encryptedSessionToken: _Optional[bytes] = ..., returnMcEnterpiseIds: bool = ..., ip: _Optional[str] = ...) -> None: ...

class ValidateSessionTokenResponse(_message.Message):
    __slots__ = ["username", "userId", "enterpriseUserId", "status", "statusMessage", "mcEnterpriseIds", "hasMSPPermission", "deletedMcEnterpriseIds"]
    class Status(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
        VALID: _ClassVar[ValidateSessionTokenResponse.Status]
        NOT_VALID: _ClassVar[ValidateSessionTokenResponse.Status]
        EXPIRED: _ClassVar[ValidateSessionTokenResponse.Status]
        IP_BLOCKED: _ClassVar[ValidateSessionTokenResponse.Status]
        INVALID_CLIENT_VERSION: _ClassVar[ValidateSessionTokenResponse.Status]
    VALID: ValidateSessionTokenResponse.Status
    NOT_VALID: ValidateSessionTokenResponse.Status
    EXPIRED: ValidateSessionTokenResponse.Status
    IP_BLOCKED: ValidateSessionTokenResponse.Status
    INVALID_CLIENT_VERSION: ValidateSessionTokenResponse.Status
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    USERID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    STATUSMESSAGE_FIELD_NUMBER: _ClassVar[int]
    MCENTERPRISEIDS_FIELD_NUMBER: _ClassVar[int]
    HASMSPPERMISSION_FIELD_NUMBER: _ClassVar[int]
    DELETEDMCENTERPRISEIDS_FIELD_NUMBER: _ClassVar[int]
    username: str
    userId: int
    enterpriseUserId: int
    status: ValidateSessionTokenResponse.Status
    statusMessage: str
    mcEnterpriseIds: _containers.RepeatedScalarFieldContainer[int]
    hasMSPPermission: bool
    deletedMcEnterpriseIds: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, username: _Optional[str] = ..., userId: _Optional[int] = ..., enterpriseUserId: _Optional[int] = ..., status: _Optional[_Union[ValidateSessionTokenResponse.Status, str]] = ..., statusMessage: _Optional[str] = ..., mcEnterpriseIds: _Optional[_Iterable[int]] = ..., hasMSPPermission: bool = ..., deletedMcEnterpriseIds: _Optional[_Iterable[int]] = ...) -> None: ...

class SubscriptionStatusRequest(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class SubscriptionStatusResponse(_message.Message):
    __slots__ = ["autoRenewal", "currentPaymentMethod", "checkoutLink", "licenseCreateDate", "isDistributor", "isLegacyMsp", "licenseStats", "gradientStatus", "hideTrialBanner", "gradientLastSyncDate", "gradientNextSyncDate", "isGradientMappingPending"]
    AUTORENEWAL_FIELD_NUMBER: _ClassVar[int]
    CURRENTPAYMENTMETHOD_FIELD_NUMBER: _ClassVar[int]
    CHECKOUTLINK_FIELD_NUMBER: _ClassVar[int]
    LICENSECREATEDATE_FIELD_NUMBER: _ClassVar[int]
    ISDISTRIBUTOR_FIELD_NUMBER: _ClassVar[int]
    ISLEGACYMSP_FIELD_NUMBER: _ClassVar[int]
    LICENSESTATS_FIELD_NUMBER: _ClassVar[int]
    GRADIENTSTATUS_FIELD_NUMBER: _ClassVar[int]
    HIDETRIALBANNER_FIELD_NUMBER: _ClassVar[int]
    GRADIENTLASTSYNCDATE_FIELD_NUMBER: _ClassVar[int]
    GRADIENTNEXTSYNCDATE_FIELD_NUMBER: _ClassVar[int]
    ISGRADIENTMAPPINGPENDING_FIELD_NUMBER: _ClassVar[int]
    autoRenewal: AutoRenewal
    currentPaymentMethod: PaymentMethod
    checkoutLink: str
    licenseCreateDate: int
    isDistributor: bool
    isLegacyMsp: bool
    licenseStats: _containers.RepeatedCompositeFieldContainer[LicenseStats]
    gradientStatus: GradientIntegrationStatus
    hideTrialBanner: bool
    gradientLastSyncDate: str
    gradientNextSyncDate: str
    isGradientMappingPending: bool
    def __init__(self, autoRenewal: _Optional[_Union[AutoRenewal, _Mapping]] = ..., currentPaymentMethod: _Optional[_Union[PaymentMethod, _Mapping]] = ..., checkoutLink: _Optional[str] = ..., licenseCreateDate: _Optional[int] = ..., isDistributor: bool = ..., isLegacyMsp: bool = ..., licenseStats: _Optional[_Iterable[_Union[LicenseStats, _Mapping]]] = ..., gradientStatus: _Optional[_Union[GradientIntegrationStatus, str]] = ..., hideTrialBanner: bool = ..., gradientLastSyncDate: _Optional[str] = ..., gradientNextSyncDate: _Optional[str] = ..., isGradientMappingPending: bool = ...) -> None: ...

class LicenseStats(_message.Message):
    __slots__ = ["type", "available", "used"]
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
        LICENSE_STAT_UNKNOWN: _ClassVar[LicenseStats.Type]
        MSP_BASE: _ClassVar[LicenseStats.Type]
        MC_BUSINESS: _ClassVar[LicenseStats.Type]
        MC_BUSINESS_PLUS: _ClassVar[LicenseStats.Type]
        MC_ENTERPRISE: _ClassVar[LicenseStats.Type]
        MC_ENTERPRISE_PLUS: _ClassVar[LicenseStats.Type]
    LICENSE_STAT_UNKNOWN: LicenseStats.Type
    MSP_BASE: LicenseStats.Type
    MC_BUSINESS: LicenseStats.Type
    MC_BUSINESS_PLUS: LicenseStats.Type
    MC_ENTERPRISE: LicenseStats.Type
    MC_ENTERPRISE_PLUS: LicenseStats.Type
    TYPE_FIELD_NUMBER: _ClassVar[int]
    AVAILABLE_FIELD_NUMBER: _ClassVar[int]
    USED_FIELD_NUMBER: _ClassVar[int]
    type: LicenseStats.Type
    available: int
    used: int
    def __init__(self, type: _Optional[_Union[LicenseStats.Type, str]] = ..., available: _Optional[int] = ..., used: _Optional[int] = ...) -> None: ...

class AutoRenewal(_message.Message):
    __slots__ = ["nextOn", "daysLeft", "isTrial"]
    NEXTON_FIELD_NUMBER: _ClassVar[int]
    DAYSLEFT_FIELD_NUMBER: _ClassVar[int]
    ISTRIAL_FIELD_NUMBER: _ClassVar[int]
    nextOn: int
    daysLeft: int
    isTrial: bool
    def __init__(self, nextOn: _Optional[int] = ..., daysLeft: _Optional[int] = ..., isTrial: bool = ...) -> None: ...

class PaymentMethod(_message.Message):
    __slots__ = ["type", "card", "sepa", "paypal", "failedBilling", "vendor", "purchaseOrder"]
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
        CARD: _ClassVar[PaymentMethod.Type]
        SEPA: _ClassVar[PaymentMethod.Type]
        PAYPAL: _ClassVar[PaymentMethod.Type]
        NONE: _ClassVar[PaymentMethod.Type]
        VENDOR: _ClassVar[PaymentMethod.Type]
        PURCHASEORDER: _ClassVar[PaymentMethod.Type]
    CARD: PaymentMethod.Type
    SEPA: PaymentMethod.Type
    PAYPAL: PaymentMethod.Type
    NONE: PaymentMethod.Type
    VENDOR: PaymentMethod.Type
    PURCHASEORDER: PaymentMethod.Type
    class Card(_message.Message):
        __slots__ = ["last4", "brand"]
        LAST4_FIELD_NUMBER: _ClassVar[int]
        BRAND_FIELD_NUMBER: _ClassVar[int]
        last4: str
        brand: str
        def __init__(self, last4: _Optional[str] = ..., brand: _Optional[str] = ...) -> None: ...
    class Sepa(_message.Message):
        __slots__ = ["last4", "country"]
        LAST4_FIELD_NUMBER: _ClassVar[int]
        COUNTRY_FIELD_NUMBER: _ClassVar[int]
        last4: str
        country: str
        def __init__(self, last4: _Optional[str] = ..., country: _Optional[str] = ...) -> None: ...
    class Paypal(_message.Message):
        __slots__ = []
        def __init__(self) -> None: ...
    class Vendor(_message.Message):
        __slots__ = ["name"]
        NAME_FIELD_NUMBER: _ClassVar[int]
        name: str
        def __init__(self, name: _Optional[str] = ...) -> None: ...
    class PurchaseOrder(_message.Message):
        __slots__ = ["name"]
        NAME_FIELD_NUMBER: _ClassVar[int]
        name: str
        def __init__(self, name: _Optional[str] = ...) -> None: ...
    TYPE_FIELD_NUMBER: _ClassVar[int]
    CARD_FIELD_NUMBER: _ClassVar[int]
    SEPA_FIELD_NUMBER: _ClassVar[int]
    PAYPAL_FIELD_NUMBER: _ClassVar[int]
    FAILEDBILLING_FIELD_NUMBER: _ClassVar[int]
    VENDOR_FIELD_NUMBER: _ClassVar[int]
    PURCHASEORDER_FIELD_NUMBER: _ClassVar[int]
    type: PaymentMethod.Type
    card: PaymentMethod.Card
    sepa: PaymentMethod.Sepa
    paypal: PaymentMethod.Paypal
    failedBilling: bool
    vendor: PaymentMethod.Vendor
    purchaseOrder: PaymentMethod.PurchaseOrder
    def __init__(self, type: _Optional[_Union[PaymentMethod.Type, str]] = ..., card: _Optional[_Union[PaymentMethod.Card, _Mapping]] = ..., sepa: _Optional[_Union[PaymentMethod.Sepa, _Mapping]] = ..., paypal: _Optional[_Union[PaymentMethod.Paypal, _Mapping]] = ..., failedBilling: bool = ..., vendor: _Optional[_Union[PaymentMethod.Vendor, _Mapping]] = ..., purchaseOrder: _Optional[_Union[PaymentMethod.PurchaseOrder, _Mapping]] = ...) -> None: ...

class SubscriptionMspPricingRequest(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class SubscriptionMspPricingResponse(_message.Message):
    __slots__ = ["addons", "filePlans"]
    ADDONS_FIELD_NUMBER: _ClassVar[int]
    FILEPLANS_FIELD_NUMBER: _ClassVar[int]
    addons: _containers.RepeatedCompositeFieldContainer[Addon]
    filePlans: _containers.RepeatedCompositeFieldContainer[FilePlan]
    def __init__(self, addons: _Optional[_Iterable[_Union[Addon, _Mapping]]] = ..., filePlans: _Optional[_Iterable[_Union[FilePlan, _Mapping]]] = ...) -> None: ...

class SubscriptionMcPricingRequest(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class SubscriptionMcPricingResponse(_message.Message):
    __slots__ = ["basePlans", "addons", "filePlans"]
    BASEPLANS_FIELD_NUMBER: _ClassVar[int]
    ADDONS_FIELD_NUMBER: _ClassVar[int]
    FILEPLANS_FIELD_NUMBER: _ClassVar[int]
    basePlans: _containers.RepeatedCompositeFieldContainer[BasePlan]
    addons: _containers.RepeatedCompositeFieldContainer[Addon]
    filePlans: _containers.RepeatedCompositeFieldContainer[FilePlan]
    def __init__(self, basePlans: _Optional[_Iterable[_Union[BasePlan, _Mapping]]] = ..., addons: _Optional[_Iterable[_Union[Addon, _Mapping]]] = ..., filePlans: _Optional[_Iterable[_Union[FilePlan, _Mapping]]] = ...) -> None: ...

class BasePlan(_message.Message):
    __slots__ = ["id", "cost"]
    ID_FIELD_NUMBER: _ClassVar[int]
    COST_FIELD_NUMBER: _ClassVar[int]
    id: int
    cost: Cost
    def __init__(self, id: _Optional[int] = ..., cost: _Optional[_Union[Cost, _Mapping]] = ...) -> None: ...

class Addon(_message.Message):
    __slots__ = ["id", "cost", "amountConsumed"]
    ID_FIELD_NUMBER: _ClassVar[int]
    COST_FIELD_NUMBER: _ClassVar[int]
    AMOUNTCONSUMED_FIELD_NUMBER: _ClassVar[int]
    id: int
    cost: Cost
    amountConsumed: int
    def __init__(self, id: _Optional[int] = ..., cost: _Optional[_Union[Cost, _Mapping]] = ..., amountConsumed: _Optional[int] = ...) -> None: ...

class FilePlan(_message.Message):
    __slots__ = ["id", "cost"]
    ID_FIELD_NUMBER: _ClassVar[int]
    COST_FIELD_NUMBER: _ClassVar[int]
    id: int
    cost: Cost
    def __init__(self, id: _Optional[int] = ..., cost: _Optional[_Union[Cost, _Mapping]] = ...) -> None: ...

class Cost(_message.Message):
    __slots__ = ["amount", "amountPer", "currency"]
    class AmountPer(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
        UNKNOWN: _ClassVar[Cost.AmountPer]
        MONTH: _ClassVar[Cost.AmountPer]
        USER_MONTH: _ClassVar[Cost.AmountPer]
        USER_CONSUMED_MONTH: _ClassVar[Cost.AmountPer]
        ENDPOINT_MONTH: _ClassVar[Cost.AmountPer]
    UNKNOWN: Cost.AmountPer
    MONTH: Cost.AmountPer
    USER_MONTH: Cost.AmountPer
    USER_CONSUMED_MONTH: Cost.AmountPer
    ENDPOINT_MONTH: Cost.AmountPer
    AMOUNT_FIELD_NUMBER: _ClassVar[int]
    AMOUNTPER_FIELD_NUMBER: _ClassVar[int]
    CURRENCY_FIELD_NUMBER: _ClassVar[int]
    amount: float
    amountPer: Cost.AmountPer
    currency: Currency
    def __init__(self, amount: _Optional[float] = ..., amountPer: _Optional[_Union[Cost.AmountPer, str]] = ..., currency: _Optional[_Union[Currency, str]] = ...) -> None: ...

class InvoiceSearchRequest(_message.Message):
    __slots__ = ["size", "startingAfterId", "allInvoicesUnfiltered"]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    STARTINGAFTERID_FIELD_NUMBER: _ClassVar[int]
    ALLINVOICESUNFILTERED_FIELD_NUMBER: _ClassVar[int]
    size: int
    startingAfterId: int
    allInvoicesUnfiltered: bool
    def __init__(self, size: _Optional[int] = ..., startingAfterId: _Optional[int] = ..., allInvoicesUnfiltered: bool = ...) -> None: ...

class InvoiceSearchResponse(_message.Message):
    __slots__ = ["invoices"]
    INVOICES_FIELD_NUMBER: _ClassVar[int]
    invoices: _containers.RepeatedCompositeFieldContainer[Invoice]
    def __init__(self, invoices: _Optional[_Iterable[_Union[Invoice, _Mapping]]] = ...) -> None: ...

class Invoice(_message.Message):
    __slots__ = ["id", "invoiceNumber", "invoiceDate", "licenseCount", "totalCost", "invoiceType"]
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
        UNKNOWN: _ClassVar[Invoice.Type]
        NEW: _ClassVar[Invoice.Type]
        RENEWAL: _ClassVar[Invoice.Type]
        UPGRADE: _ClassVar[Invoice.Type]
        RESTORE: _ClassVar[Invoice.Type]
        ASSOCIATION: _ClassVar[Invoice.Type]
        OVERAGE: _ClassVar[Invoice.Type]
    UNKNOWN: Invoice.Type
    NEW: Invoice.Type
    RENEWAL: Invoice.Type
    UPGRADE: Invoice.Type
    RESTORE: Invoice.Type
    ASSOCIATION: Invoice.Type
    OVERAGE: Invoice.Type
    class Cost(_message.Message):
        __slots__ = ["amount", "currency"]
        AMOUNT_FIELD_NUMBER: _ClassVar[int]
        CURRENCY_FIELD_NUMBER: _ClassVar[int]
        amount: float
        currency: Currency
        def __init__(self, amount: _Optional[float] = ..., currency: _Optional[_Union[Currency, str]] = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    INVOICENUMBER_FIELD_NUMBER: _ClassVar[int]
    INVOICEDATE_FIELD_NUMBER: _ClassVar[int]
    LICENSECOUNT_FIELD_NUMBER: _ClassVar[int]
    TOTALCOST_FIELD_NUMBER: _ClassVar[int]
    INVOICETYPE_FIELD_NUMBER: _ClassVar[int]
    id: int
    invoiceNumber: str
    invoiceDate: int
    licenseCount: int
    totalCost: Invoice.Cost
    invoiceType: Invoice.Type
    def __init__(self, id: _Optional[int] = ..., invoiceNumber: _Optional[str] = ..., invoiceDate: _Optional[int] = ..., licenseCount: _Optional[int] = ..., totalCost: _Optional[_Union[Invoice.Cost, _Mapping]] = ..., invoiceType: _Optional[_Union[Invoice.Type, str]] = ...) -> None: ...

class VaultInvoicesListRequest(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class VaultInvoicesListResponse(_message.Message):
    __slots__ = ["invoices"]
    INVOICES_FIELD_NUMBER: _ClassVar[int]
    invoices: _containers.RepeatedCompositeFieldContainer[VaultInvoice]
    def __init__(self, invoices: _Optional[_Iterable[_Union[VaultInvoice, _Mapping]]] = ...) -> None: ...

class VaultInvoice(_message.Message):
    __slots__ = ["id", "invoiceNumber", "dateCreated", "total", "purchaseType"]
    ID_FIELD_NUMBER: _ClassVar[int]
    INVOICENUMBER_FIELD_NUMBER: _ClassVar[int]
    DATECREATED_FIELD_NUMBER: _ClassVar[int]
    TOTAL_FIELD_NUMBER: _ClassVar[int]
    PURCHASETYPE_FIELD_NUMBER: _ClassVar[int]
    id: int
    invoiceNumber: str
    dateCreated: int
    total: Invoice.Cost
    purchaseType: Invoice.Type
    def __init__(self, id: _Optional[int] = ..., invoiceNumber: _Optional[str] = ..., dateCreated: _Optional[int] = ..., total: _Optional[_Union[Invoice.Cost, _Mapping]] = ..., purchaseType: _Optional[_Union[Invoice.Type, str]] = ...) -> None: ...

class InvoiceDownloadRequest(_message.Message):
    __slots__ = ["invoiceNumber"]
    INVOICENUMBER_FIELD_NUMBER: _ClassVar[int]
    invoiceNumber: str
    def __init__(self, invoiceNumber: _Optional[str] = ...) -> None: ...

class InvoiceDownloadResponse(_message.Message):
    __slots__ = ["link", "fileName"]
    LINK_FIELD_NUMBER: _ClassVar[int]
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    link: str
    fileName: str
    def __init__(self, link: _Optional[str] = ..., fileName: _Optional[str] = ...) -> None: ...

class VaultInvoiceDownloadLinkRequest(_message.Message):
    __slots__ = ["invoiceNumber"]
    INVOICENUMBER_FIELD_NUMBER: _ClassVar[int]
    invoiceNumber: str
    def __init__(self, invoiceNumber: _Optional[str] = ...) -> None: ...

class VaultInvoiceDownloadLinkResponse(_message.Message):
    __slots__ = ["link", "fileName"]
    LINK_FIELD_NUMBER: _ClassVar[int]
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    link: str
    fileName: str
    def __init__(self, link: _Optional[str] = ..., fileName: _Optional[str] = ...) -> None: ...

class ReportingDailySnapshotRequest(_message.Message):
    __slots__ = ["month", "year"]
    MONTH_FIELD_NUMBER: _ClassVar[int]
    YEAR_FIELD_NUMBER: _ClassVar[int]
    month: int
    year: int
    def __init__(self, month: _Optional[int] = ..., year: _Optional[int] = ...) -> None: ...

class ReportingDailySnapshotResponse(_message.Message):
    __slots__ = ["records", "mcEnterprises"]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    MCENTERPRISES_FIELD_NUMBER: _ClassVar[int]
    records: _containers.RepeatedCompositeFieldContainer[SnapshotRecord]
    mcEnterprises: _containers.RepeatedCompositeFieldContainer[SnapshotMcEnterprise]
    def __init__(self, records: _Optional[_Iterable[_Union[SnapshotRecord, _Mapping]]] = ..., mcEnterprises: _Optional[_Iterable[_Union[SnapshotMcEnterprise, _Mapping]]] = ...) -> None: ...

class SnapshotRecord(_message.Message):
    __slots__ = ["date", "mcEnterpriseId", "maxLicenseCount", "maxFilePlanTypeId", "maxBasePlanId", "addons"]
    class Addon(_message.Message):
        __slots__ = ["maxAddonId", "units"]
        MAXADDONID_FIELD_NUMBER: _ClassVar[int]
        UNITS_FIELD_NUMBER: _ClassVar[int]
        maxAddonId: int
        units: int
        def __init__(self, maxAddonId: _Optional[int] = ..., units: _Optional[int] = ...) -> None: ...
    DATE_FIELD_NUMBER: _ClassVar[int]
    MCENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    MAXLICENSECOUNT_FIELD_NUMBER: _ClassVar[int]
    MAXFILEPLANTYPEID_FIELD_NUMBER: _ClassVar[int]
    MAXBASEPLANID_FIELD_NUMBER: _ClassVar[int]
    ADDONS_FIELD_NUMBER: _ClassVar[int]
    date: int
    mcEnterpriseId: int
    maxLicenseCount: int
    maxFilePlanTypeId: int
    maxBasePlanId: int
    addons: _containers.RepeatedCompositeFieldContainer[SnapshotRecord.Addon]
    def __init__(self, date: _Optional[int] = ..., mcEnterpriseId: _Optional[int] = ..., maxLicenseCount: _Optional[int] = ..., maxFilePlanTypeId: _Optional[int] = ..., maxBasePlanId: _Optional[int] = ..., addons: _Optional[_Iterable[_Union[SnapshotRecord.Addon, _Mapping]]] = ...) -> None: ...

class SnapshotMcEnterprise(_message.Message):
    __slots__ = ["id", "name"]
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    id: int
    name: str
    def __init__(self, id: _Optional[int] = ..., name: _Optional[str] = ...) -> None: ...

class MappingAddonsRequest(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class MappingAddonsResponse(_message.Message):
    __slots__ = ["addons", "filePlans"]
    ADDONS_FIELD_NUMBER: _ClassVar[int]
    FILEPLANS_FIELD_NUMBER: _ClassVar[int]
    addons: _containers.RepeatedCompositeFieldContainer[MappingItem]
    filePlans: _containers.RepeatedCompositeFieldContainer[MappingItem]
    def __init__(self, addons: _Optional[_Iterable[_Union[MappingItem, _Mapping]]] = ..., filePlans: _Optional[_Iterable[_Union[MappingItem, _Mapping]]] = ...) -> None: ...

class MappingItem(_message.Message):
    __slots__ = ["id", "name"]
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    id: int
    name: str
    def __init__(self, id: _Optional[int] = ..., name: _Optional[str] = ...) -> None: ...

class GradientValidateKeyRequest(_message.Message):
    __slots__ = ["gradientKey"]
    GRADIENTKEY_FIELD_NUMBER: _ClassVar[int]
    gradientKey: str
    def __init__(self, gradientKey: _Optional[str] = ...) -> None: ...

class GradientValidateKeyResponse(_message.Message):
    __slots__ = ["success", "message"]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    success: bool
    message: str
    def __init__(self, success: bool = ..., message: _Optional[str] = ...) -> None: ...

class GradientSaveRequest(_message.Message):
    __slots__ = ["gradientKey", "enterpriseUserId"]
    GRADIENTKEY_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    gradientKey: str
    enterpriseUserId: int
    def __init__(self, gradientKey: _Optional[str] = ..., enterpriseUserId: _Optional[int] = ...) -> None: ...

class GradientSaveResponse(_message.Message):
    __slots__ = ["success", "status", "message"]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    success: bool
    status: GradientIntegrationStatus
    message: str
    def __init__(self, success: bool = ..., status: _Optional[_Union[GradientIntegrationStatus, str]] = ..., message: _Optional[str] = ...) -> None: ...

class GradientRemoveRequest(_message.Message):
    __slots__ = ["enterpriseUserId"]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    def __init__(self, enterpriseUserId: _Optional[int] = ...) -> None: ...

class GradientRemoveResponse(_message.Message):
    __slots__ = ["success", "message"]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    success: bool
    message: str
    def __init__(self, success: bool = ..., message: _Optional[str] = ...) -> None: ...

class GradientSyncRequest(_message.Message):
    __slots__ = ["enterpriseUserId"]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    def __init__(self, enterpriseUserId: _Optional[int] = ...) -> None: ...

class GradientSyncResponse(_message.Message):
    __slots__ = ["success", "status", "message"]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    success: bool
    status: GradientIntegrationStatus
    message: str
    def __init__(self, success: bool = ..., status: _Optional[_Union[GradientIntegrationStatus, str]] = ..., message: _Optional[str] = ...) -> None: ...

class NetPromoterScoreSurveySubmissionRequest(_message.Message):
    __slots__ = ["survey_score", "notes"]
    SURVEY_SCORE_FIELD_NUMBER: _ClassVar[int]
    NOTES_FIELD_NUMBER: _ClassVar[int]
    survey_score: int
    notes: str
    def __init__(self, survey_score: _Optional[int] = ..., notes: _Optional[str] = ...) -> None: ...

class NetPromoterScoreSurveySubmissionResponse(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class NetPromoterScorePopupScheduleRequest(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class NetPromoterScorePopupScheduleResponse(_message.Message):
    __slots__ = ["show_popup"]
    SHOW_POPUP_FIELD_NUMBER: _ClassVar[int]
    show_popup: bool
    def __init__(self, show_popup: bool = ...) -> None: ...

class NetPromoterScorePopupDismissalRequest(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class NetPromoterScorePopupDismissalResponse(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class KCMLicenseRequest(_message.Message):
    __slots__ = ["enterpriseUserId"]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    def __init__(self, enterpriseUserId: _Optional[int] = ...) -> None: ...

class KCMLicenseResponse(_message.Message):
    __slots__ = ["message"]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    message: str
    def __init__(self, message: _Optional[str] = ...) -> None: ...

class EventRequest(_message.Message):
    __slots__ = ["eventType", "eventValue", "eventTime", "attributes"]
    EVENTTYPE_FIELD_NUMBER: _ClassVar[int]
    EVENTVALUE_FIELD_NUMBER: _ClassVar[int]
    EVENTTIME_FIELD_NUMBER: _ClassVar[int]
    ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    eventType: EventType
    eventValue: str
    eventTime: int
    attributes: _struct_pb2.Struct
    def __init__(self, eventType: _Optional[_Union[EventType, str]] = ..., eventValue: _Optional[str] = ..., eventTime: _Optional[int] = ..., attributes: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ...) -> None: ...

class EventsRequest(_message.Message):
    __slots__ = ["event"]
    EVENT_FIELD_NUMBER: _ClassVar[int]
    event: _containers.RepeatedCompositeFieldContainer[EventRequest]
    def __init__(self, event: _Optional[_Iterable[_Union[EventRequest, _Mapping]]] = ...) -> None: ...

class CustomerCaptureRequest(_message.Message):
    __slots__ = ["pageUrl", "tree", "hash", "image", "pageLoadTime", "keyId", "test"]
    PAGEURL_FIELD_NUMBER: _ClassVar[int]
    TREE_FIELD_NUMBER: _ClassVar[int]
    HASH_FIELD_NUMBER: _ClassVar[int]
    IMAGE_FIELD_NUMBER: _ClassVar[int]
    PAGELOADTIME_FIELD_NUMBER: _ClassVar[int]
    KEYID_FIELD_NUMBER: _ClassVar[int]
    TEST_FIELD_NUMBER: _ClassVar[int]
    pageUrl: str
    tree: str
    hash: str
    image: str
    pageLoadTime: str
    keyId: str
    test: bool
    def __init__(self, pageUrl: _Optional[str] = ..., tree: _Optional[str] = ..., hash: _Optional[str] = ..., image: _Optional[str] = ..., pageLoadTime: _Optional[str] = ..., keyId: _Optional[str] = ..., test: bool = ...) -> None: ...

class CustomerCaptureResponse(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...
