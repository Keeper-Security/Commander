from google.protobuf import struct_pb2 as _struct_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Currency(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UNKNOWN: _ClassVar[Currency]
    USD: _ClassVar[Currency]
    GBP: _ClassVar[Currency]
    JPY: _ClassVar[Currency]
    EUR: _ClassVar[Currency]
    AUD: _ClassVar[Currency]
    CAD: _ClassVar[Currency]

class GradientIntegrationStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    NOTCONNECTED: _ClassVar[GradientIntegrationStatus]
    PENDING: _ClassVar[GradientIntegrationStatus]
    CONNECTED: _ClassVar[GradientIntegrationStatus]
    NONE: _ClassVar[GradientIntegrationStatus]

class EventType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UNKNOWN_TRACKING_EVENT_TYPE: _ClassVar[EventType]
    TRACKING_POPUP_DISPLAYED: _ClassVar[EventType]
    TRACKING_POPUP_ACCEPTED: _ClassVar[EventType]
    TRACKING_POPUP_DISMISSED: _ClassVar[EventType]
    TRACKING_POPUP_PAID: _ClassVar[EventType]
    TRACKING_PUSH_CLICKED: _ClassVar[EventType]
    CONSOLE_ACTION: _ClassVar[EventType]
    VAULT_ACTION: _ClassVar[EventType]

class PurchaseProductType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    upgradeToEnterprise: _ClassVar[PurchaseProductType]
    addUsers: _ClassVar[PurchaseProductType]
    addStorage: _ClassVar[PurchaseProductType]
    addAudit: _ClassVar[PurchaseProductType]
    addBreachWatch: _ClassVar[PurchaseProductType]
    addCompliance: _ClassVar[PurchaseProductType]
    addChat: _ClassVar[PurchaseProductType]
    addPAM: _ClassVar[PurchaseProductType]
    addSilverSupport: _ClassVar[PurchaseProductType]
    addPlatinumSupport: _ClassVar[PurchaseProductType]
    addKEPM: _ClassVar[PurchaseProductType]
    addNhi: _ClassVar[PurchaseProductType]

class IdentifierType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UNKNOWN_IDENTIFIER_TYPE: _ClassVar[IdentifierType]
    IOS_ID: _ClassVar[IdentifierType]
    ANDROID_GOOGLE_PLAY_ID: _ClassVar[IdentifierType]
    ANDROID_APP_SET_ID: _ClassVar[IdentifierType]
    ANDROID_ID: _ClassVar[IdentifierType]
    AMAZON_ADVERTISING_ID: _ClassVar[IdentifierType]
    OPEN_ADVERTISING_ID: _ClassVar[IdentifierType]
    SINGULAR_DEVICE_ID: _ClassVar[IdentifierType]
    CLIENT_DEFINED_ID: _ClassVar[IdentifierType]
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
CONSOLE_ACTION: EventType
VAULT_ACTION: EventType
upgradeToEnterprise: PurchaseProductType
addUsers: PurchaseProductType
addStorage: PurchaseProductType
addAudit: PurchaseProductType
addBreachWatch: PurchaseProductType
addCompliance: PurchaseProductType
addChat: PurchaseProductType
addPAM: PurchaseProductType
addSilverSupport: PurchaseProductType
addPlatinumSupport: PurchaseProductType
addKEPM: PurchaseProductType
addNhi: PurchaseProductType
UNKNOWN_IDENTIFIER_TYPE: IdentifierType
IOS_ID: IdentifierType
ANDROID_GOOGLE_PLAY_ID: IdentifierType
ANDROID_APP_SET_ID: IdentifierType
ANDROID_ID: IdentifierType
AMAZON_ADVERTISING_ID: IdentifierType
OPEN_ADVERTISING_ID: IdentifierType
SINGULAR_DEVICE_ID: IdentifierType
CLIENT_DEFINED_ID: IdentifierType

class ValidateSessionTokenRequest(_message.Message):
    __slots__ = ("encryptedSessionToken", "returnMcEnterpiseIds", "ip")
    ENCRYPTEDSESSIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    RETURNMCENTERPISEIDS_FIELD_NUMBER: _ClassVar[int]
    IP_FIELD_NUMBER: _ClassVar[int]
    encryptedSessionToken: bytes
    returnMcEnterpiseIds: bool
    ip: str
    def __init__(self, encryptedSessionToken: _Optional[bytes] = ..., returnMcEnterpiseIds: bool = ..., ip: _Optional[str] = ...) -> None: ...

class ValidateSessionTokenResponse(_message.Message):
    __slots__ = ("username", "userId", "enterpriseUserId", "status", "statusMessage", "mcEnterpriseIds", "hasMSPPermission", "deletedMcEnterpriseIds")
    class Status(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
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
    __slots__ = ()
    def __init__(self) -> None: ...

class SubscriptionStatusResponse(_message.Message):
    __slots__ = ("autoRenewal", "currentPaymentMethod", "checkoutLink", "licenseCreateDate", "isDistributor", "isLegacyMsp", "licenseStats", "gradientStatus", "hideTrialBanner", "gradientLastSyncDate", "gradientNextSyncDate", "isGradientMappingPending", "nhi", "freeKsmApiCallsCount", "ksm")
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
    NHI_FIELD_NUMBER: _ClassVar[int]
    FREEKSMAPICALLSCOUNT_FIELD_NUMBER: _ClassVar[int]
    KSM_FIELD_NUMBER: _ClassVar[int]
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
    nhi: NhiBilling
    freeKsmApiCallsCount: int
    ksm: KsmBilling
    def __init__(self, autoRenewal: _Optional[_Union[AutoRenewal, _Mapping]] = ..., currentPaymentMethod: _Optional[_Union[PaymentMethod, _Mapping]] = ..., checkoutLink: _Optional[str] = ..., licenseCreateDate: _Optional[int] = ..., isDistributor: bool = ..., isLegacyMsp: bool = ..., licenseStats: _Optional[_Iterable[_Union[LicenseStats, _Mapping]]] = ..., gradientStatus: _Optional[_Union[GradientIntegrationStatus, str]] = ..., hideTrialBanner: bool = ..., gradientLastSyncDate: _Optional[str] = ..., gradientNextSyncDate: _Optional[str] = ..., isGradientMappingPending: bool = ..., nhi: _Optional[_Union[NhiBilling, _Mapping]] = ..., freeKsmApiCallsCount: _Optional[int] = ..., ksm: _Optional[_Union[KsmBilling, _Mapping]] = ...) -> None: ...

class KsmBilling(_message.Message):
    __slots__ = ("billingStartTimestamp", "billingEndTimestamp", "currentTierId", "enterpriseBlocks", "currentTierCeiling")
    BILLINGSTARTTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    BILLINGENDTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    CURRENTTIERID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEBLOCKS_FIELD_NUMBER: _ClassVar[int]
    CURRENTTIERCEILING_FIELD_NUMBER: _ClassVar[int]
    billingStartTimestamp: int
    billingEndTimestamp: int
    currentTierId: int
    enterpriseBlocks: int
    currentTierCeiling: int
    def __init__(self, billingStartTimestamp: _Optional[int] = ..., billingEndTimestamp: _Optional[int] = ..., currentTierId: _Optional[int] = ..., enterpriseBlocks: _Optional[int] = ..., currentTierCeiling: _Optional[int] = ...) -> None: ...

class NhiBilling(_message.Message):
    __slots__ = ("billingStartTimestamp", "billingEndTimestamp", "currentTierId", "enterpriseBlocks", "currentTierCeiling", "billingPeriods")
    BILLINGSTARTTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    BILLINGENDTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    CURRENTTIERID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEBLOCKS_FIELD_NUMBER: _ClassVar[int]
    CURRENTTIERCEILING_FIELD_NUMBER: _ClassVar[int]
    BILLINGPERIODS_FIELD_NUMBER: _ClassVar[int]
    billingStartTimestamp: int
    billingEndTimestamp: int
    currentTierId: int
    enterpriseBlocks: int
    currentTierCeiling: int
    billingPeriods: _containers.RepeatedCompositeFieldContainer[NhiBillingPeriod]
    def __init__(self, billingStartTimestamp: _Optional[int] = ..., billingEndTimestamp: _Optional[int] = ..., currentTierId: _Optional[int] = ..., enterpriseBlocks: _Optional[int] = ..., currentTierCeiling: _Optional[int] = ..., billingPeriods: _Optional[_Iterable[_Union[NhiBillingPeriod, _Mapping]]] = ...) -> None: ...

class NhiBillingPeriod(_message.Message):
    __slots__ = ("startTimestamp", "endTimestamp")
    STARTTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    ENDTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    startTimestamp: int
    endTimestamp: int
    def __init__(self, startTimestamp: _Optional[int] = ..., endTimestamp: _Optional[int] = ...) -> None: ...

class LicenseStats(_message.Message):
    __slots__ = ("type", "available", "used")
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        LICENSE_STAT_UNKNOWN: _ClassVar[LicenseStats.Type]
        MSP_BASE: _ClassVar[LicenseStats.Type]
        MC_BUSINESS: _ClassVar[LicenseStats.Type]
        MC_BUSINESS_PLUS: _ClassVar[LicenseStats.Type]
        MC_ENTERPRISE: _ClassVar[LicenseStats.Type]
        MC_ENTERPRISE_PLUS: _ClassVar[LicenseStats.Type]
        B2B_BUSINESS_STARTER: _ClassVar[LicenseStats.Type]
        B2B_BUSINESS: _ClassVar[LicenseStats.Type]
        B2B_ENTERPRISE: _ClassVar[LicenseStats.Type]
    LICENSE_STAT_UNKNOWN: LicenseStats.Type
    MSP_BASE: LicenseStats.Type
    MC_BUSINESS: LicenseStats.Type
    MC_BUSINESS_PLUS: LicenseStats.Type
    MC_ENTERPRISE: LicenseStats.Type
    MC_ENTERPRISE_PLUS: LicenseStats.Type
    B2B_BUSINESS_STARTER: LicenseStats.Type
    B2B_BUSINESS: LicenseStats.Type
    B2B_ENTERPRISE: LicenseStats.Type
    TYPE_FIELD_NUMBER: _ClassVar[int]
    AVAILABLE_FIELD_NUMBER: _ClassVar[int]
    USED_FIELD_NUMBER: _ClassVar[int]
    type: LicenseStats.Type
    available: int
    used: int
    def __init__(self, type: _Optional[_Union[LicenseStats.Type, str]] = ..., available: _Optional[int] = ..., used: _Optional[int] = ...) -> None: ...

class AutoRenewal(_message.Message):
    __slots__ = ("nextOn", "daysLeft", "isTrial")
    NEXTON_FIELD_NUMBER: _ClassVar[int]
    DAYSLEFT_FIELD_NUMBER: _ClassVar[int]
    ISTRIAL_FIELD_NUMBER: _ClassVar[int]
    nextOn: int
    daysLeft: int
    isTrial: bool
    def __init__(self, nextOn: _Optional[int] = ..., daysLeft: _Optional[int] = ..., isTrial: bool = ...) -> None: ...

class PaymentMethod(_message.Message):
    __slots__ = ("type", "card", "sepa", "paypal", "failedBilling", "vendor", "purchaseOrder")
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
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
        __slots__ = ("last4", "brand")
        LAST4_FIELD_NUMBER: _ClassVar[int]
        BRAND_FIELD_NUMBER: _ClassVar[int]
        last4: str
        brand: str
        def __init__(self, last4: _Optional[str] = ..., brand: _Optional[str] = ...) -> None: ...
    class Sepa(_message.Message):
        __slots__ = ("last4", "country")
        LAST4_FIELD_NUMBER: _ClassVar[int]
        COUNTRY_FIELD_NUMBER: _ClassVar[int]
        last4: str
        country: str
        def __init__(self, last4: _Optional[str] = ..., country: _Optional[str] = ...) -> None: ...
    class Paypal(_message.Message):
        __slots__ = ()
        def __init__(self) -> None: ...
    class Vendor(_message.Message):
        __slots__ = ("name",)
        NAME_FIELD_NUMBER: _ClassVar[int]
        name: str
        def __init__(self, name: _Optional[str] = ...) -> None: ...
    class PurchaseOrder(_message.Message):
        __slots__ = ("name",)
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
    __slots__ = ()
    def __init__(self) -> None: ...

class SubscriptionMspPricingResponse(_message.Message):
    __slots__ = ("addons", "filePlans")
    ADDONS_FIELD_NUMBER: _ClassVar[int]
    FILEPLANS_FIELD_NUMBER: _ClassVar[int]
    addons: _containers.RepeatedCompositeFieldContainer[Addon]
    filePlans: _containers.RepeatedCompositeFieldContainer[FilePlan]
    def __init__(self, addons: _Optional[_Iterable[_Union[Addon, _Mapping]]] = ..., filePlans: _Optional[_Iterable[_Union[FilePlan, _Mapping]]] = ...) -> None: ...

class SubscriptionMcPricingRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class SubscriptionMcPricingResponse(_message.Message):
    __slots__ = ("basePlans", "addons", "filePlans")
    BASEPLANS_FIELD_NUMBER: _ClassVar[int]
    ADDONS_FIELD_NUMBER: _ClassVar[int]
    FILEPLANS_FIELD_NUMBER: _ClassVar[int]
    basePlans: _containers.RepeatedCompositeFieldContainer[BasePlan]
    addons: _containers.RepeatedCompositeFieldContainer[Addon]
    filePlans: _containers.RepeatedCompositeFieldContainer[FilePlan]
    def __init__(self, basePlans: _Optional[_Iterable[_Union[BasePlan, _Mapping]]] = ..., addons: _Optional[_Iterable[_Union[Addon, _Mapping]]] = ..., filePlans: _Optional[_Iterable[_Union[FilePlan, _Mapping]]] = ...) -> None: ...

class BasePlan(_message.Message):
    __slots__ = ("id", "cost")
    ID_FIELD_NUMBER: _ClassVar[int]
    COST_FIELD_NUMBER: _ClassVar[int]
    id: int
    cost: Cost
    def __init__(self, id: _Optional[int] = ..., cost: _Optional[_Union[Cost, _Mapping]] = ...) -> None: ...

class Addon(_message.Message):
    __slots__ = ("id", "cost", "amountConsumed")
    ID_FIELD_NUMBER: _ClassVar[int]
    COST_FIELD_NUMBER: _ClassVar[int]
    AMOUNTCONSUMED_FIELD_NUMBER: _ClassVar[int]
    id: int
    cost: Cost
    amountConsumed: int
    def __init__(self, id: _Optional[int] = ..., cost: _Optional[_Union[Cost, _Mapping]] = ..., amountConsumed: _Optional[int] = ...) -> None: ...

class FilePlan(_message.Message):
    __slots__ = ("id", "cost")
    ID_FIELD_NUMBER: _ClassVar[int]
    COST_FIELD_NUMBER: _ClassVar[int]
    id: int
    cost: Cost
    def __init__(self, id: _Optional[int] = ..., cost: _Optional[_Union[Cost, _Mapping]] = ...) -> None: ...

class Cost(_message.Message):
    __slots__ = ("amount", "amountPer", "currency", "contactSales")
    class AmountPer(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[Cost.AmountPer]
        MONTH: _ClassVar[Cost.AmountPer]
        USER_MONTH: _ClassVar[Cost.AmountPer]
        USER_CONSUMED_MONTH: _ClassVar[Cost.AmountPer]
        ENDPOINT_MONTH: _ClassVar[Cost.AmountPer]
        USER_YEAR: _ClassVar[Cost.AmountPer]
        USER_CONSUMED_YEAR: _ClassVar[Cost.AmountPer]
        YEAR: _ClassVar[Cost.AmountPer]
        ENDPOINT_YEAR: _ClassVar[Cost.AmountPer]
    UNKNOWN: Cost.AmountPer
    MONTH: Cost.AmountPer
    USER_MONTH: Cost.AmountPer
    USER_CONSUMED_MONTH: Cost.AmountPer
    ENDPOINT_MONTH: Cost.AmountPer
    USER_YEAR: Cost.AmountPer
    USER_CONSUMED_YEAR: Cost.AmountPer
    YEAR: Cost.AmountPer
    ENDPOINT_YEAR: Cost.AmountPer
    AMOUNT_FIELD_NUMBER: _ClassVar[int]
    AMOUNTPER_FIELD_NUMBER: _ClassVar[int]
    CURRENCY_FIELD_NUMBER: _ClassVar[int]
    CONTACTSALES_FIELD_NUMBER: _ClassVar[int]
    amount: float
    amountPer: Cost.AmountPer
    currency: Currency
    contactSales: bool
    def __init__(self, amount: _Optional[float] = ..., amountPer: _Optional[_Union[Cost.AmountPer, str]] = ..., currency: _Optional[_Union[Currency, str]] = ..., contactSales: bool = ...) -> None: ...

class InvoiceSearchRequest(_message.Message):
    __slots__ = ("size", "startingAfterId", "allInvoicesUnfiltered")
    SIZE_FIELD_NUMBER: _ClassVar[int]
    STARTINGAFTERID_FIELD_NUMBER: _ClassVar[int]
    ALLINVOICESUNFILTERED_FIELD_NUMBER: _ClassVar[int]
    size: int
    startingAfterId: int
    allInvoicesUnfiltered: bool
    def __init__(self, size: _Optional[int] = ..., startingAfterId: _Optional[int] = ..., allInvoicesUnfiltered: bool = ...) -> None: ...

class InvoiceSearchResponse(_message.Message):
    __slots__ = ("invoices",)
    INVOICES_FIELD_NUMBER: _ClassVar[int]
    invoices: _containers.RepeatedCompositeFieldContainer[Invoice]
    def __init__(self, invoices: _Optional[_Iterable[_Union[Invoice, _Mapping]]] = ...) -> None: ...

class Invoice(_message.Message):
    __slots__ = ("id", "invoiceNumber", "invoiceDate", "licenseCount", "totalCost", "invoiceType")
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
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
        __slots__ = ("amount", "currency")
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
    __slots__ = ()
    def __init__(self) -> None: ...

class VaultInvoicesListResponse(_message.Message):
    __slots__ = ("invoices",)
    INVOICES_FIELD_NUMBER: _ClassVar[int]
    invoices: _containers.RepeatedCompositeFieldContainer[VaultInvoice]
    def __init__(self, invoices: _Optional[_Iterable[_Union[VaultInvoice, _Mapping]]] = ...) -> None: ...

class VaultInvoice(_message.Message):
    __slots__ = ("id", "invoiceNumber", "dateCreated", "total", "purchaseType")
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
    __slots__ = ("invoiceNumber",)
    INVOICENUMBER_FIELD_NUMBER: _ClassVar[int]
    invoiceNumber: str
    def __init__(self, invoiceNumber: _Optional[str] = ...) -> None: ...

class InvoiceDownloadResponse(_message.Message):
    __slots__ = ("link", "fileName")
    LINK_FIELD_NUMBER: _ClassVar[int]
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    link: str
    fileName: str
    def __init__(self, link: _Optional[str] = ..., fileName: _Optional[str] = ...) -> None: ...

class VaultInvoiceDownloadLinkRequest(_message.Message):
    __slots__ = ("invoiceNumber",)
    INVOICENUMBER_FIELD_NUMBER: _ClassVar[int]
    invoiceNumber: str
    def __init__(self, invoiceNumber: _Optional[str] = ...) -> None: ...

class VaultInvoiceDownloadLinkResponse(_message.Message):
    __slots__ = ("link", "fileName")
    LINK_FIELD_NUMBER: _ClassVar[int]
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    link: str
    fileName: str
    def __init__(self, link: _Optional[str] = ..., fileName: _Optional[str] = ...) -> None: ...

class ReportingDailySnapshotRequest(_message.Message):
    __slots__ = ("month", "year")
    MONTH_FIELD_NUMBER: _ClassVar[int]
    YEAR_FIELD_NUMBER: _ClassVar[int]
    month: int
    year: int
    def __init__(self, month: _Optional[int] = ..., year: _Optional[int] = ...) -> None: ...

class ReportingDailySnapshotResponse(_message.Message):
    __slots__ = ("records", "mcEnterprises")
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    MCENTERPRISES_FIELD_NUMBER: _ClassVar[int]
    records: _containers.RepeatedCompositeFieldContainer[SnapshotRecord]
    mcEnterprises: _containers.RepeatedCompositeFieldContainer[SnapshotMcEnterprise]
    def __init__(self, records: _Optional[_Iterable[_Union[SnapshotRecord, _Mapping]]] = ..., mcEnterprises: _Optional[_Iterable[_Union[SnapshotMcEnterprise, _Mapping]]] = ...) -> None: ...

class SnapshotRecord(_message.Message):
    __slots__ = ("date", "mcEnterpriseId", "maxLicenseCount", "maxFilePlanTypeId", "maxBasePlanId", "addons")
    class Addon(_message.Message):
        __slots__ = ("maxAddonId", "units")
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
    __slots__ = ("id", "name")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    id: int
    name: str
    def __init__(self, id: _Optional[int] = ..., name: _Optional[str] = ...) -> None: ...

class MappingAddonsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class MappingAddonsResponse(_message.Message):
    __slots__ = ("addons", "filePlans")
    ADDONS_FIELD_NUMBER: _ClassVar[int]
    FILEPLANS_FIELD_NUMBER: _ClassVar[int]
    addons: _containers.RepeatedCompositeFieldContainer[MappingItem]
    filePlans: _containers.RepeatedCompositeFieldContainer[MappingItem]
    def __init__(self, addons: _Optional[_Iterable[_Union[MappingItem, _Mapping]]] = ..., filePlans: _Optional[_Iterable[_Union[MappingItem, _Mapping]]] = ...) -> None: ...

class MappingItem(_message.Message):
    __slots__ = ("id", "name")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    id: int
    name: str
    def __init__(self, id: _Optional[int] = ..., name: _Optional[str] = ...) -> None: ...

class GradientValidateKeyRequest(_message.Message):
    __slots__ = ("gradientKey",)
    GRADIENTKEY_FIELD_NUMBER: _ClassVar[int]
    gradientKey: str
    def __init__(self, gradientKey: _Optional[str] = ...) -> None: ...

class GradientValidateKeyResponse(_message.Message):
    __slots__ = ("success", "message")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    success: bool
    message: str
    def __init__(self, success: bool = ..., message: _Optional[str] = ...) -> None: ...

class GradientSaveRequest(_message.Message):
    __slots__ = ("gradientKey", "enterpriseUserId")
    GRADIENTKEY_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    gradientKey: str
    enterpriseUserId: int
    def __init__(self, gradientKey: _Optional[str] = ..., enterpriseUserId: _Optional[int] = ...) -> None: ...

class GradientSaveResponse(_message.Message):
    __slots__ = ("success", "status", "message")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    success: bool
    status: GradientIntegrationStatus
    message: str
    def __init__(self, success: bool = ..., status: _Optional[_Union[GradientIntegrationStatus, str]] = ..., message: _Optional[str] = ...) -> None: ...

class GradientRemoveRequest(_message.Message):
    __slots__ = ("enterpriseUserId",)
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    def __init__(self, enterpriseUserId: _Optional[int] = ...) -> None: ...

class GradientRemoveResponse(_message.Message):
    __slots__ = ("success", "message")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    success: bool
    message: str
    def __init__(self, success: bool = ..., message: _Optional[str] = ...) -> None: ...

class GradientSyncRequest(_message.Message):
    __slots__ = ("enterpriseUserId",)
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    def __init__(self, enterpriseUserId: _Optional[int] = ...) -> None: ...

class GradientSyncResponse(_message.Message):
    __slots__ = ("success", "status", "message")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    success: bool
    status: GradientIntegrationStatus
    message: str
    def __init__(self, success: bool = ..., status: _Optional[_Union[GradientIntegrationStatus, str]] = ..., message: _Optional[str] = ...) -> None: ...

class NetPromoterScoreSurveySubmissionRequest(_message.Message):
    __slots__ = ("survey_score", "notes")
    SURVEY_SCORE_FIELD_NUMBER: _ClassVar[int]
    NOTES_FIELD_NUMBER: _ClassVar[int]
    survey_score: int
    notes: str
    def __init__(self, survey_score: _Optional[int] = ..., notes: _Optional[str] = ...) -> None: ...

class NetPromoterScoreSurveySubmissionResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class NetPromoterScorePopupScheduleRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class NetPromoterScorePopupScheduleResponse(_message.Message):
    __slots__ = ("show_popup",)
    SHOW_POPUP_FIELD_NUMBER: _ClassVar[int]
    show_popup: bool
    def __init__(self, show_popup: bool = ...) -> None: ...

class NetPromoterScorePopupDismissalRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class NetPromoterScorePopupDismissalResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class KCMLicenseRequest(_message.Message):
    __slots__ = ("enterpriseUserId",)
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    enterpriseUserId: int
    def __init__(self, enterpriseUserId: _Optional[int] = ...) -> None: ...

class KCMLicenseResponse(_message.Message):
    __slots__ = ("message",)
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    message: str
    def __init__(self, message: _Optional[str] = ...) -> None: ...

class EventRequest(_message.Message):
    __slots__ = ("eventType", "eventValue", "eventTime", "attributes")
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
    __slots__ = ("event",)
    EVENT_FIELD_NUMBER: _ClassVar[int]
    event: _containers.RepeatedCompositeFieldContainer[EventRequest]
    def __init__(self, event: _Optional[_Iterable[_Union[EventRequest, _Mapping]]] = ...) -> None: ...

class EventResponse(_message.Message):
    __slots__ = ("index", "status")
    INDEX_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    index: int
    status: bool
    def __init__(self, index: _Optional[int] = ..., status: bool = ...) -> None: ...

class EventsResponse(_message.Message):
    __slots__ = ("response",)
    RESPONSE_FIELD_NUMBER: _ClassVar[int]
    response: _containers.RepeatedCompositeFieldContainer[EventResponse]
    def __init__(self, response: _Optional[_Iterable[_Union[EventResponse, _Mapping]]] = ...) -> None: ...

class CustomerCaptureRequest(_message.Message):
    __slots__ = ("pageUrl", "tree", "hash", "image", "pageLoadTime", "keyId", "test", "issueType", "notes")
    PAGEURL_FIELD_NUMBER: _ClassVar[int]
    TREE_FIELD_NUMBER: _ClassVar[int]
    HASH_FIELD_NUMBER: _ClassVar[int]
    IMAGE_FIELD_NUMBER: _ClassVar[int]
    PAGELOADTIME_FIELD_NUMBER: _ClassVar[int]
    KEYID_FIELD_NUMBER: _ClassVar[int]
    TEST_FIELD_NUMBER: _ClassVar[int]
    ISSUETYPE_FIELD_NUMBER: _ClassVar[int]
    NOTES_FIELD_NUMBER: _ClassVar[int]
    pageUrl: str
    tree: str
    hash: str
    image: str
    pageLoadTime: str
    keyId: str
    test: bool
    issueType: str
    notes: str
    def __init__(self, pageUrl: _Optional[str] = ..., tree: _Optional[str] = ..., hash: _Optional[str] = ..., image: _Optional[str] = ..., pageLoadTime: _Optional[str] = ..., keyId: _Optional[str] = ..., test: bool = ..., issueType: _Optional[str] = ..., notes: _Optional[str] = ...) -> None: ...

class CustomerCaptureResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class Error(_message.Message):
    __slots__ = ("code", "message", "extras")
    class ExtrasEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    CODE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    EXTRAS_FIELD_NUMBER: _ClassVar[int]
    code: str
    message: str
    extras: _containers.ScalarMap[str, str]
    def __init__(self, code: _Optional[str] = ..., message: _Optional[str] = ..., extras: _Optional[_Mapping[str, str]] = ...) -> None: ...

class QuotePurchase(_message.Message):
    __slots__ = ("quoteTotal", "includedTax", "includedOtherAddons", "taxAmount", "taxLabel", "purchaseIdentifier")
    QUOTETOTAL_FIELD_NUMBER: _ClassVar[int]
    INCLUDEDTAX_FIELD_NUMBER: _ClassVar[int]
    INCLUDEDOTHERADDONS_FIELD_NUMBER: _ClassVar[int]
    TAXAMOUNT_FIELD_NUMBER: _ClassVar[int]
    TAXLABEL_FIELD_NUMBER: _ClassVar[int]
    PURCHASEIDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    quoteTotal: float
    includedTax: bool
    includedOtherAddons: bool
    taxAmount: float
    taxLabel: str
    purchaseIdentifier: str
    def __init__(self, quoteTotal: _Optional[float] = ..., includedTax: bool = ..., includedOtherAddons: bool = ..., taxAmount: _Optional[float] = ..., taxLabel: _Optional[str] = ..., purchaseIdentifier: _Optional[str] = ...) -> None: ...

class PurchaseOptions(_message.Message):
    __slots__ = ("inConsole", "externalCheckout")
    INCONSOLE_FIELD_NUMBER: _ClassVar[int]
    EXTERNALCHECKOUT_FIELD_NUMBER: _ClassVar[int]
    inConsole: bool
    externalCheckout: bool
    def __init__(self, inConsole: bool = ..., externalCheckout: bool = ...) -> None: ...

class AddonPurchaseOptions(_message.Message):
    __slots__ = ("storage", "audit", "breachwatch", "chat", "compliance", "professionalServicesSilver", "professionalServicesPlatinum", "pam", "epm", "secretsManager", "connectionManager", "remoteBrowserIsolation", "nhiTier")
    STORAGE_FIELD_NUMBER: _ClassVar[int]
    AUDIT_FIELD_NUMBER: _ClassVar[int]
    BREACHWATCH_FIELD_NUMBER: _ClassVar[int]
    CHAT_FIELD_NUMBER: _ClassVar[int]
    COMPLIANCE_FIELD_NUMBER: _ClassVar[int]
    PROFESSIONALSERVICESSILVER_FIELD_NUMBER: _ClassVar[int]
    PROFESSIONALSERVICESPLATINUM_FIELD_NUMBER: _ClassVar[int]
    PAM_FIELD_NUMBER: _ClassVar[int]
    EPM_FIELD_NUMBER: _ClassVar[int]
    SECRETSMANAGER_FIELD_NUMBER: _ClassVar[int]
    CONNECTIONMANAGER_FIELD_NUMBER: _ClassVar[int]
    REMOTEBROWSERISOLATION_FIELD_NUMBER: _ClassVar[int]
    NHITIER_FIELD_NUMBER: _ClassVar[int]
    storage: PurchaseOptions
    audit: PurchaseOptions
    breachwatch: PurchaseOptions
    chat: PurchaseOptions
    compliance: PurchaseOptions
    professionalServicesSilver: PurchaseOptions
    professionalServicesPlatinum: PurchaseOptions
    pam: PurchaseOptions
    epm: PurchaseOptions
    secretsManager: PurchaseOptions
    connectionManager: PurchaseOptions
    remoteBrowserIsolation: PurchaseOptions
    nhiTier: PurchaseOptions
    def __init__(self, storage: _Optional[_Union[PurchaseOptions, _Mapping]] = ..., audit: _Optional[_Union[PurchaseOptions, _Mapping]] = ..., breachwatch: _Optional[_Union[PurchaseOptions, _Mapping]] = ..., chat: _Optional[_Union[PurchaseOptions, _Mapping]] = ..., compliance: _Optional[_Union[PurchaseOptions, _Mapping]] = ..., professionalServicesSilver: _Optional[_Union[PurchaseOptions, _Mapping]] = ..., professionalServicesPlatinum: _Optional[_Union[PurchaseOptions, _Mapping]] = ..., pam: _Optional[_Union[PurchaseOptions, _Mapping]] = ..., epm: _Optional[_Union[PurchaseOptions, _Mapping]] = ..., secretsManager: _Optional[_Union[PurchaseOptions, _Mapping]] = ..., connectionManager: _Optional[_Union[PurchaseOptions, _Mapping]] = ..., remoteBrowserIsolation: _Optional[_Union[PurchaseOptions, _Mapping]] = ..., nhiTier: _Optional[_Union[PurchaseOptions, _Mapping]] = ...) -> None: ...

class AvailablePurchaseOptions(_message.Message):
    __slots__ = ("basePlan", "users", "addons")
    BASEPLAN_FIELD_NUMBER: _ClassVar[int]
    USERS_FIELD_NUMBER: _ClassVar[int]
    ADDONS_FIELD_NUMBER: _ClassVar[int]
    basePlan: PurchaseOptions
    users: PurchaseOptions
    addons: AddonPurchaseOptions
    def __init__(self, basePlan: _Optional[_Union[PurchaseOptions, _Mapping]] = ..., users: _Optional[_Union[PurchaseOptions, _Mapping]] = ..., addons: _Optional[_Union[AddonPurchaseOptions, _Mapping]] = ...) -> None: ...

class UpgradeLicenseStatusRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class UpgradeLicenseStatusResponse(_message.Message):
    __slots__ = ("allowPurchaseFromConsole", "purchaseOptions", "error")
    ALLOWPURCHASEFROMCONSOLE_FIELD_NUMBER: _ClassVar[int]
    PURCHASEOPTIONS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    allowPurchaseFromConsole: bool
    purchaseOptions: AvailablePurchaseOptions
    error: Error
    def __init__(self, allowPurchaseFromConsole: bool = ..., purchaseOptions: _Optional[_Union[AvailablePurchaseOptions, _Mapping]] = ..., error: _Optional[_Union[Error, _Mapping]] = ...) -> None: ...

class UpgradeLicenseQuotePurchaseRequest(_message.Message):
    __slots__ = ("productType", "quantity", "tier")
    PRODUCTTYPE_FIELD_NUMBER: _ClassVar[int]
    QUANTITY_FIELD_NUMBER: _ClassVar[int]
    TIER_FIELD_NUMBER: _ClassVar[int]
    productType: PurchaseProductType
    quantity: int
    tier: int
    def __init__(self, productType: _Optional[_Union[PurchaseProductType, str]] = ..., quantity: _Optional[int] = ..., tier: _Optional[int] = ...) -> None: ...

class UpgradeLicenseQuotePurchaseResponse(_message.Message):
    __slots__ = ("success", "quotePurchase", "viewSummaryLink", "error")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    QUOTEPURCHASE_FIELD_NUMBER: _ClassVar[int]
    VIEWSUMMARYLINK_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    success: bool
    quotePurchase: QuotePurchase
    viewSummaryLink: str
    error: Error
    def __init__(self, success: bool = ..., quotePurchase: _Optional[_Union[QuotePurchase, _Mapping]] = ..., viewSummaryLink: _Optional[str] = ..., error: _Optional[_Union[Error, _Mapping]] = ...) -> None: ...

class UpgradeLicenseCompletePurchaseRequest(_message.Message):
    __slots__ = ("productType", "quantity", "quotePurchase", "tier")
    PRODUCTTYPE_FIELD_NUMBER: _ClassVar[int]
    QUANTITY_FIELD_NUMBER: _ClassVar[int]
    QUOTEPURCHASE_FIELD_NUMBER: _ClassVar[int]
    TIER_FIELD_NUMBER: _ClassVar[int]
    productType: PurchaseProductType
    quantity: int
    quotePurchase: QuotePurchase
    tier: int
    def __init__(self, productType: _Optional[_Union[PurchaseProductType, str]] = ..., quantity: _Optional[int] = ..., quotePurchase: _Optional[_Union[QuotePurchase, _Mapping]] = ..., tier: _Optional[int] = ...) -> None: ...

class UpgradeLicenseCompletePurchaseResponse(_message.Message):
    __slots__ = ("success", "invoiceNumber", "error", "quotePurchase")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    INVOICENUMBER_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    QUOTEPURCHASE_FIELD_NUMBER: _ClassVar[int]
    success: bool
    invoiceNumber: str
    error: Error
    quotePurchase: QuotePurchase
    def __init__(self, success: bool = ..., invoiceNumber: _Optional[str] = ..., error: _Optional[_Union[Error, _Mapping]] = ..., quotePurchase: _Optional[_Union[QuotePurchase, _Mapping]] = ...) -> None: ...

class EnterpriseBasePlan(_message.Message):
    __slots__ = ("baseplanVersion", "cost")
    class EnterpriseBasePlanVersion(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[EnterpriseBasePlan.EnterpriseBasePlanVersion]
        BUSINESS_STARTER: _ClassVar[EnterpriseBasePlan.EnterpriseBasePlanVersion]
        BUSINESS: _ClassVar[EnterpriseBasePlan.EnterpriseBasePlanVersion]
        ENTERPRISE: _ClassVar[EnterpriseBasePlan.EnterpriseBasePlanVersion]
    UNKNOWN: EnterpriseBasePlan.EnterpriseBasePlanVersion
    BUSINESS_STARTER: EnterpriseBasePlan.EnterpriseBasePlanVersion
    BUSINESS: EnterpriseBasePlan.EnterpriseBasePlanVersion
    ENTERPRISE: EnterpriseBasePlan.EnterpriseBasePlanVersion
    BASEPLANVERSION_FIELD_NUMBER: _ClassVar[int]
    COST_FIELD_NUMBER: _ClassVar[int]
    baseplanVersion: EnterpriseBasePlan.EnterpriseBasePlanVersion
    cost: Cost
    def __init__(self, baseplanVersion: _Optional[_Union[EnterpriseBasePlan.EnterpriseBasePlanVersion, str]] = ..., cost: _Optional[_Union[Cost, _Mapping]] = ...) -> None: ...

class SubscriptionEnterprisePricingRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class NhiTierPlan(_message.Message):
    __slots__ = ("tierId", "nhiCeiling", "cost", "productId", "nhiFloor")
    TIERID_FIELD_NUMBER: _ClassVar[int]
    NHICEILING_FIELD_NUMBER: _ClassVar[int]
    COST_FIELD_NUMBER: _ClassVar[int]
    PRODUCTID_FIELD_NUMBER: _ClassVar[int]
    NHIFLOOR_FIELD_NUMBER: _ClassVar[int]
    tierId: int
    nhiCeiling: int
    cost: Cost
    productId: int
    nhiFloor: int
    def __init__(self, tierId: _Optional[int] = ..., nhiCeiling: _Optional[int] = ..., cost: _Optional[_Union[Cost, _Mapping]] = ..., productId: _Optional[int] = ..., nhiFloor: _Optional[int] = ...) -> None: ...

class SubscriptionEnterprisePricingResponse(_message.Message):
    __slots__ = ("basePlans", "addons", "filePlans", "nhiTierPlans")
    BASEPLANS_FIELD_NUMBER: _ClassVar[int]
    ADDONS_FIELD_NUMBER: _ClassVar[int]
    FILEPLANS_FIELD_NUMBER: _ClassVar[int]
    NHITIERPLANS_FIELD_NUMBER: _ClassVar[int]
    basePlans: _containers.RepeatedCompositeFieldContainer[EnterpriseBasePlan]
    addons: _containers.RepeatedCompositeFieldContainer[Addon]
    filePlans: _containers.RepeatedCompositeFieldContainer[FilePlan]
    nhiTierPlans: _containers.RepeatedCompositeFieldContainer[NhiTierPlan]
    def __init__(self, basePlans: _Optional[_Iterable[_Union[EnterpriseBasePlan, _Mapping]]] = ..., addons: _Optional[_Iterable[_Union[Addon, _Mapping]]] = ..., filePlans: _Optional[_Iterable[_Union[FilePlan, _Mapping]]] = ..., nhiTierPlans: _Optional[_Iterable[_Union[NhiTierPlan, _Mapping]]] = ...) -> None: ...

class SingularDeviceIdentifier(_message.Message):
    __slots__ = ("id", "idType")
    ID_FIELD_NUMBER: _ClassVar[int]
    IDTYPE_FIELD_NUMBER: _ClassVar[int]
    id: str
    idType: IdentifierType
    def __init__(self, id: _Optional[str] = ..., idType: _Optional[_Union[IdentifierType, str]] = ...) -> None: ...

class SingularSharedData(_message.Message):
    __slots__ = ("platform", "osVersion", "make", "model", "locale", "build", "appIdentifier", "attAuthorizationStatus")
    PLATFORM_FIELD_NUMBER: _ClassVar[int]
    OSVERSION_FIELD_NUMBER: _ClassVar[int]
    MAKE_FIELD_NUMBER: _ClassVar[int]
    MODEL_FIELD_NUMBER: _ClassVar[int]
    LOCALE_FIELD_NUMBER: _ClassVar[int]
    BUILD_FIELD_NUMBER: _ClassVar[int]
    APPIDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    ATTAUTHORIZATIONSTATUS_FIELD_NUMBER: _ClassVar[int]
    platform: str
    osVersion: str
    make: str
    model: str
    locale: str
    build: str
    appIdentifier: str
    attAuthorizationStatus: int
    def __init__(self, platform: _Optional[str] = ..., osVersion: _Optional[str] = ..., make: _Optional[str] = ..., model: _Optional[str] = ..., locale: _Optional[str] = ..., build: _Optional[str] = ..., appIdentifier: _Optional[str] = ..., attAuthorizationStatus: _Optional[int] = ...) -> None: ...

class SingularSessionRequest(_message.Message):
    __slots__ = ("deviceIdentifiers", "sharedData", "applicationVersion", "install", "installTime", "updateTime", "installSource", "installReceipt", "openuri", "ddlEnabled", "singularLinkResolveRequired", "installRef", "metaRef", "attributionToken")
    DEVICEIDENTIFIERS_FIELD_NUMBER: _ClassVar[int]
    SHAREDDATA_FIELD_NUMBER: _ClassVar[int]
    APPLICATIONVERSION_FIELD_NUMBER: _ClassVar[int]
    INSTALL_FIELD_NUMBER: _ClassVar[int]
    INSTALLTIME_FIELD_NUMBER: _ClassVar[int]
    UPDATETIME_FIELD_NUMBER: _ClassVar[int]
    INSTALLSOURCE_FIELD_NUMBER: _ClassVar[int]
    INSTALLRECEIPT_FIELD_NUMBER: _ClassVar[int]
    OPENURI_FIELD_NUMBER: _ClassVar[int]
    DDLENABLED_FIELD_NUMBER: _ClassVar[int]
    SINGULARLINKRESOLVEREQUIRED_FIELD_NUMBER: _ClassVar[int]
    INSTALLREF_FIELD_NUMBER: _ClassVar[int]
    METAREF_FIELD_NUMBER: _ClassVar[int]
    ATTRIBUTIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    deviceIdentifiers: _containers.RepeatedCompositeFieldContainer[SingularDeviceIdentifier]
    sharedData: SingularSharedData
    applicationVersion: str
    install: bool
    installTime: int
    updateTime: int
    installSource: str
    installReceipt: str
    openuri: str
    ddlEnabled: bool
    singularLinkResolveRequired: bool
    installRef: str
    metaRef: str
    attributionToken: str
    def __init__(self, deviceIdentifiers: _Optional[_Iterable[_Union[SingularDeviceIdentifier, _Mapping]]] = ..., sharedData: _Optional[_Union[SingularSharedData, _Mapping]] = ..., applicationVersion: _Optional[str] = ..., install: bool = ..., installTime: _Optional[int] = ..., updateTime: _Optional[int] = ..., installSource: _Optional[str] = ..., installReceipt: _Optional[str] = ..., openuri: _Optional[str] = ..., ddlEnabled: bool = ..., singularLinkResolveRequired: bool = ..., installRef: _Optional[str] = ..., metaRef: _Optional[str] = ..., attributionToken: _Optional[str] = ...) -> None: ...

class SingularEventRequest(_message.Message):
    __slots__ = ("deviceIdentifiers", "sharedData", "eventName")
    DEVICEIDENTIFIERS_FIELD_NUMBER: _ClassVar[int]
    SHAREDDATA_FIELD_NUMBER: _ClassVar[int]
    EVENTNAME_FIELD_NUMBER: _ClassVar[int]
    deviceIdentifiers: _containers.RepeatedCompositeFieldContainer[SingularDeviceIdentifier]
    sharedData: SingularSharedData
    eventName: str
    def __init__(self, deviceIdentifiers: _Optional[_Iterable[_Union[SingularDeviceIdentifier, _Mapping]]] = ..., sharedData: _Optional[_Union[SingularSharedData, _Mapping]] = ..., eventName: _Optional[str] = ...) -> None: ...

class ActivePamCountRequest(_message.Message):
    __slots__ = ("enterpriseId",)
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    enterpriseId: int
    def __init__(self, enterpriseId: _Optional[int] = ...) -> None: ...

class ActivePamCountResponse(_message.Message):
    __slots__ = ("pamCount",)
    PAMCOUNT_FIELD_NUMBER: _ClassVar[int]
    pamCount: int
    def __init__(self, pamCount: _Optional[int] = ...) -> None: ...

class NhiEnterpriseRequest(_message.Message):
    __slots__ = ("enterpriseId", "startTime", "endTime")
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    STARTTIME_FIELD_NUMBER: _ClassVar[int]
    ENDTIME_FIELD_NUMBER: _ClassVar[int]
    enterpriseId: int
    startTime: int
    endTime: int
    def __init__(self, enterpriseId: _Optional[int] = ..., startTime: _Optional[int] = ..., endTime: _Optional[int] = ...) -> None: ...

class NhiMetricsRequest(_message.Message):
    __slots__ = ("enterpriseIds", "startTime", "endTime", "enterprises")
    ENTERPRISEIDS_FIELD_NUMBER: _ClassVar[int]
    STARTTIME_FIELD_NUMBER: _ClassVar[int]
    ENDTIME_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISES_FIELD_NUMBER: _ClassVar[int]
    enterpriseIds: _containers.RepeatedScalarFieldContainer[int]
    startTime: int
    endTime: int
    enterprises: _containers.RepeatedCompositeFieldContainer[NhiEnterpriseRequest]
    def __init__(self, enterpriseIds: _Optional[_Iterable[int]] = ..., startTime: _Optional[int] = ..., endTime: _Optional[int] = ..., enterprises: _Optional[_Iterable[_Union[NhiEnterpriseRequest, _Mapping]]] = ...) -> None: ...
