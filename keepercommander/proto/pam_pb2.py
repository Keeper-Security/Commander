# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: pam.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from . import enterprise_pb2 as enterprise__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\tpam.proto\x12\x06Router\x1a\x10\x65nterprise.proto\"\x83\x01\n\x13PAMRotationSchedule\x12\x11\n\trecordUid\x18\x01 \x01(\x0c\x12\x18\n\x10\x63onfigurationUid\x18\x02 \x01(\x0c\x12\x15\n\rcontrollerUid\x18\x03 \x01(\x0c\x12\x14\n\x0cscheduleData\x18\x04 \x01(\t\x12\x12\n\nnoSchedule\x18\x05 \x01(\x08\"N\n\x1cPAMRotationSchedulesResponse\x12.\n\tschedules\x18\x01 \x03(\x0b\x32\x1b.Router.PAMRotationSchedule\"+\n\x14PAMOnlineControllers\x12\x13\n\x0b\x63ontrollers\x18\x01 \x03(\x0c\"9\n\x10PAMRotateRequest\x12\x12\n\nrequestUid\x18\x01 \x01(\x0c\x12\x11\n\trecordUid\x18\x02 \x01(\x0c\"D\n\x16PAMControllersResponse\x12*\n\x0b\x63ontrollers\x18\x01 \x03(\x0b\x32\x15.Router.PAMController\"=\n\x13PAMRemoveController\x12\x15\n\rcontrollerUid\x18\x01 \x01(\x0c\x12\x0f\n\x07message\x18\x02 \x01(\t\"O\n\x1bPAMRemoveControllerResponse\x12\x30\n\x0b\x63ontrollers\x18\x01 \x03(\x0b\x32\x1b.Router.PAMRemoveController\"@\n\x10PAMModifyRequest\x12,\n\noperations\x18\x01 \x03(\x0b\x32\x18.Router.PAMDataOperation\"\xa1\x01\n\x10PAMDataOperation\x12/\n\roperationType\x18\x01 \x01(\x0e\x32\x18.Router.PAMOperationType\x12\x33\n\rconfiguration\x18\x02 \x01(\x0b\x32\x1c.Router.PAMConfigurationData\x12\'\n\x07\x65lement\x18\x03 \x01(\x0b\x32\x16.Router.PAMElementData\"e\n\x14PAMConfigurationData\x12\x18\n\x10\x63onfigurationUid\x18\x01 \x01(\x0c\x12\x0e\n\x06nodeId\x18\x02 \x01(\x03\x12\x15\n\rcontrollerUid\x18\x03 \x01(\x0c\x12\x0c\n\x04\x64\x61ta\x18\x04 \x01(\x0c\"E\n\x0ePAMElementData\x12\x12\n\nelementUid\x18\x01 \x01(\x0c\x12\x11\n\tparentUid\x18\x02 \x01(\x0c\x12\x0c\n\x04\x64\x61ta\x18\x03 \x01(\x0c\"p\n\x19PAMElementOperationResult\x12\x12\n\nelementUid\x18\x01 \x01(\x0c\x12.\n\x06result\x18\x02 \x01(\x0e\x32\x1e.Router.PAMOperationResultType\x12\x0f\n\x07message\x18\x03 \x01(\t\"E\n\x0fPAMModifyResult\x12\x32\n\x07results\x18\x01 \x03(\x0b\x32!.Router.PAMElementOperationResult\"{\n\nPAMElement\x12\x12\n\nelementUid\x18\x01 \x01(\x0c\x12\x0c\n\x04\x64\x61ta\x18\x02 \x01(\x0c\x12\x0f\n\x07\x63reated\x18\x03 \x01(\x03\x12\x14\n\x0clastModified\x18\x04 \x01(\x03\x12$\n\x08\x63hildren\x18\x05 \x03(\x0b\x32\x12.Router.PAMElement\"#\n\x14PAMGenericUidRequest\x12\x0b\n\x03uid\x18\x01 \x01(\x0c\"%\n\x15PAMGenericUidsRequest\x12\x0c\n\x04uids\x18\x01 \x03(\x0c\"\xae\x01\n\x10PAMConfiguration\x12\x18\n\x10\x63onfigurationUid\x18\x01 \x01(\x0c\x12\x0e\n\x06nodeId\x18\x02 \x01(\x03\x12\x15\n\rcontrollerUid\x18\x03 \x01(\x0c\x12\x0c\n\x04\x64\x61ta\x18\x04 \x01(\x0c\x12\x0f\n\x07\x63reated\x18\x05 \x01(\x03\x12\x14\n\x0clastModified\x18\x06 \x01(\x03\x12$\n\x08\x63hildren\x18\x07 \x03(\x0b\x32\x12.Router.PAMElement\"E\n\x11PAMConfigurations\x12\x30\n\x0e\x63onfigurations\x18\x01 \x03(\x0b\x32\x18.Router.PAMConfiguration\"\xe8\x01\n\rPAMController\x12\x15\n\rcontrollerUid\x18\x01 \x01(\x0c\x12\x16\n\x0e\x63ontrollerName\x18\x02 \x01(\t\x12\x13\n\x0b\x64\x65viceToken\x18\x03 \x01(\t\x12\x12\n\ndeviceName\x18\x04 \x01(\t\x12\x0e\n\x06nodeId\x18\x05 \x01(\x03\x12\x0f\n\x07\x63reated\x18\x06 \x01(\x03\x12\x14\n\x0clastModified\x18\x07 \x01(\x03\x12\x16\n\x0e\x61pplicationUid\x18\x08 \x01(\x0c\x12\x30\n\rappClientType\x18\t \x01(\x0e\x32\x19.Enterprise.AppClientType\"%\n\x12\x43ontrollerResponse\x12\x0f\n\x07payload\x18\x01 \x01(\t*@\n\x10PAMOperationType\x12\x07\n\x03\x41\x44\x44\x10\x00\x12\n\n\x06UPDATE\x10\x01\x12\x0b\n\x07REPLACE\x10\x02\x12\n\n\x06\x44\x45LETE\x10\x03*p\n\x16PAMOperationResultType\x12\x0f\n\x0bPOT_SUCCESS\x10\x00\x12\x15\n\x11POT_UNKNOWN_ERROR\x10\x01\x12\x16\n\x12POT_ALREADY_EXISTS\x10\x02\x12\x16\n\x12POT_DOES_NOT_EXIST\x10\x03*H\n\x15\x43ontrollerMessageType\x12\x0f\n\x0b\x43MT_GENERAL\x10\x00\x12\x0e\n\nCMT_ROTATE\x10\x01\x12\x0e\n\nCMT_STREAM\x10\x02\x42\x1f\n\x18\x63om.keepersecurity.protoB\x03PAMb\x06proto3')

_PAMOPERATIONTYPE = DESCRIPTOR.enum_types_by_name['PAMOperationType']
PAMOperationType = enum_type_wrapper.EnumTypeWrapper(_PAMOPERATIONTYPE)
_PAMOPERATIONRESULTTYPE = DESCRIPTOR.enum_types_by_name['PAMOperationResultType']
PAMOperationResultType = enum_type_wrapper.EnumTypeWrapper(_PAMOPERATIONRESULTTYPE)
_CONTROLLERMESSAGETYPE = DESCRIPTOR.enum_types_by_name['ControllerMessageType']
ControllerMessageType = enum_type_wrapper.EnumTypeWrapper(_CONTROLLERMESSAGETYPE)
ADD = 0
UPDATE = 1
REPLACE = 2
DELETE = 3
POT_SUCCESS = 0
POT_UNKNOWN_ERROR = 1
POT_ALREADY_EXISTS = 2
POT_DOES_NOT_EXIST = 3
CMT_GENERAL = 0
CMT_ROTATE = 1
CMT_STREAM = 2


_PAMROTATIONSCHEDULE = DESCRIPTOR.message_types_by_name['PAMRotationSchedule']
_PAMROTATIONSCHEDULESRESPONSE = DESCRIPTOR.message_types_by_name['PAMRotationSchedulesResponse']
_PAMONLINECONTROLLERS = DESCRIPTOR.message_types_by_name['PAMOnlineControllers']
_PAMROTATEREQUEST = DESCRIPTOR.message_types_by_name['PAMRotateRequest']
_PAMCONTROLLERSRESPONSE = DESCRIPTOR.message_types_by_name['PAMControllersResponse']
_PAMREMOVECONTROLLER = DESCRIPTOR.message_types_by_name['PAMRemoveController']
_PAMREMOVECONTROLLERRESPONSE = DESCRIPTOR.message_types_by_name['PAMRemoveControllerResponse']
_PAMMODIFYREQUEST = DESCRIPTOR.message_types_by_name['PAMModifyRequest']
_PAMDATAOPERATION = DESCRIPTOR.message_types_by_name['PAMDataOperation']
_PAMCONFIGURATIONDATA = DESCRIPTOR.message_types_by_name['PAMConfigurationData']
_PAMELEMENTDATA = DESCRIPTOR.message_types_by_name['PAMElementData']
_PAMELEMENTOPERATIONRESULT = DESCRIPTOR.message_types_by_name['PAMElementOperationResult']
_PAMMODIFYRESULT = DESCRIPTOR.message_types_by_name['PAMModifyResult']
_PAMELEMENT = DESCRIPTOR.message_types_by_name['PAMElement']
_PAMGENERICUIDREQUEST = DESCRIPTOR.message_types_by_name['PAMGenericUidRequest']
_PAMGENERICUIDSREQUEST = DESCRIPTOR.message_types_by_name['PAMGenericUidsRequest']
_PAMCONFIGURATION = DESCRIPTOR.message_types_by_name['PAMConfiguration']
_PAMCONFIGURATIONS = DESCRIPTOR.message_types_by_name['PAMConfigurations']
_PAMCONTROLLER = DESCRIPTOR.message_types_by_name['PAMController']
_CONTROLLERRESPONSE = DESCRIPTOR.message_types_by_name['ControllerResponse']
PAMRotationSchedule = _reflection.GeneratedProtocolMessageType('PAMRotationSchedule', (_message.Message,), {
  'DESCRIPTOR' : _PAMROTATIONSCHEDULE,
  '__module__' : 'pam_pb2'
  # @@protoc_insertion_point(class_scope:Router.PAMRotationSchedule)
  })
_sym_db.RegisterMessage(PAMRotationSchedule)

PAMRotationSchedulesResponse = _reflection.GeneratedProtocolMessageType('PAMRotationSchedulesResponse', (_message.Message,), {
  'DESCRIPTOR' : _PAMROTATIONSCHEDULESRESPONSE,
  '__module__' : 'pam_pb2'
  # @@protoc_insertion_point(class_scope:Router.PAMRotationSchedulesResponse)
  })
_sym_db.RegisterMessage(PAMRotationSchedulesResponse)

PAMOnlineControllers = _reflection.GeneratedProtocolMessageType('PAMOnlineControllers', (_message.Message,), {
  'DESCRIPTOR' : _PAMONLINECONTROLLERS,
  '__module__' : 'pam_pb2'
  # @@protoc_insertion_point(class_scope:Router.PAMOnlineControllers)
  })
_sym_db.RegisterMessage(PAMOnlineControllers)

PAMRotateRequest = _reflection.GeneratedProtocolMessageType('PAMRotateRequest', (_message.Message,), {
  'DESCRIPTOR' : _PAMROTATEREQUEST,
  '__module__' : 'pam_pb2'
  # @@protoc_insertion_point(class_scope:Router.PAMRotateRequest)
  })
_sym_db.RegisterMessage(PAMRotateRequest)

PAMControllersResponse = _reflection.GeneratedProtocolMessageType('PAMControllersResponse', (_message.Message,), {
  'DESCRIPTOR' : _PAMCONTROLLERSRESPONSE,
  '__module__' : 'pam_pb2'
  # @@protoc_insertion_point(class_scope:Router.PAMControllersResponse)
  })
_sym_db.RegisterMessage(PAMControllersResponse)

PAMRemoveController = _reflection.GeneratedProtocolMessageType('PAMRemoveController', (_message.Message,), {
  'DESCRIPTOR' : _PAMREMOVECONTROLLER,
  '__module__' : 'pam_pb2'
  # @@protoc_insertion_point(class_scope:Router.PAMRemoveController)
  })
_sym_db.RegisterMessage(PAMRemoveController)

PAMRemoveControllerResponse = _reflection.GeneratedProtocolMessageType('PAMRemoveControllerResponse', (_message.Message,), {
  'DESCRIPTOR' : _PAMREMOVECONTROLLERRESPONSE,
  '__module__' : 'pam_pb2'
  # @@protoc_insertion_point(class_scope:Router.PAMRemoveControllerResponse)
  })
_sym_db.RegisterMessage(PAMRemoveControllerResponse)

PAMModifyRequest = _reflection.GeneratedProtocolMessageType('PAMModifyRequest', (_message.Message,), {
  'DESCRIPTOR' : _PAMMODIFYREQUEST,
  '__module__' : 'pam_pb2'
  # @@protoc_insertion_point(class_scope:Router.PAMModifyRequest)
  })
_sym_db.RegisterMessage(PAMModifyRequest)

PAMDataOperation = _reflection.GeneratedProtocolMessageType('PAMDataOperation', (_message.Message,), {
  'DESCRIPTOR' : _PAMDATAOPERATION,
  '__module__' : 'pam_pb2'
  # @@protoc_insertion_point(class_scope:Router.PAMDataOperation)
  })
_sym_db.RegisterMessage(PAMDataOperation)

PAMConfigurationData = _reflection.GeneratedProtocolMessageType('PAMConfigurationData', (_message.Message,), {
  'DESCRIPTOR' : _PAMCONFIGURATIONDATA,
  '__module__' : 'pam_pb2'
  # @@protoc_insertion_point(class_scope:Router.PAMConfigurationData)
  })
_sym_db.RegisterMessage(PAMConfigurationData)

PAMElementData = _reflection.GeneratedProtocolMessageType('PAMElementData', (_message.Message,), {
  'DESCRIPTOR' : _PAMELEMENTDATA,
  '__module__' : 'pam_pb2'
  # @@protoc_insertion_point(class_scope:Router.PAMElementData)
  })
_sym_db.RegisterMessage(PAMElementData)

PAMElementOperationResult = _reflection.GeneratedProtocolMessageType('PAMElementOperationResult', (_message.Message,), {
  'DESCRIPTOR' : _PAMELEMENTOPERATIONRESULT,
  '__module__' : 'pam_pb2'
  # @@protoc_insertion_point(class_scope:Router.PAMElementOperationResult)
  })
_sym_db.RegisterMessage(PAMElementOperationResult)

PAMModifyResult = _reflection.GeneratedProtocolMessageType('PAMModifyResult', (_message.Message,), {
  'DESCRIPTOR' : _PAMMODIFYRESULT,
  '__module__' : 'pam_pb2'
  # @@protoc_insertion_point(class_scope:Router.PAMModifyResult)
  })
_sym_db.RegisterMessage(PAMModifyResult)

PAMElement = _reflection.GeneratedProtocolMessageType('PAMElement', (_message.Message,), {
  'DESCRIPTOR' : _PAMELEMENT,
  '__module__' : 'pam_pb2'
  # @@protoc_insertion_point(class_scope:Router.PAMElement)
  })
_sym_db.RegisterMessage(PAMElement)

PAMGenericUidRequest = _reflection.GeneratedProtocolMessageType('PAMGenericUidRequest', (_message.Message,), {
  'DESCRIPTOR' : _PAMGENERICUIDREQUEST,
  '__module__' : 'pam_pb2'
  # @@protoc_insertion_point(class_scope:Router.PAMGenericUidRequest)
  })
_sym_db.RegisterMessage(PAMGenericUidRequest)

PAMGenericUidsRequest = _reflection.GeneratedProtocolMessageType('PAMGenericUidsRequest', (_message.Message,), {
  'DESCRIPTOR' : _PAMGENERICUIDSREQUEST,
  '__module__' : 'pam_pb2'
  # @@protoc_insertion_point(class_scope:Router.PAMGenericUidsRequest)
  })
_sym_db.RegisterMessage(PAMGenericUidsRequest)

PAMConfiguration = _reflection.GeneratedProtocolMessageType('PAMConfiguration', (_message.Message,), {
  'DESCRIPTOR' : _PAMCONFIGURATION,
  '__module__' : 'pam_pb2'
  # @@protoc_insertion_point(class_scope:Router.PAMConfiguration)
  })
_sym_db.RegisterMessage(PAMConfiguration)

PAMConfigurations = _reflection.GeneratedProtocolMessageType('PAMConfigurations', (_message.Message,), {
  'DESCRIPTOR' : _PAMCONFIGURATIONS,
  '__module__' : 'pam_pb2'
  # @@protoc_insertion_point(class_scope:Router.PAMConfigurations)
  })
_sym_db.RegisterMessage(PAMConfigurations)

PAMController = _reflection.GeneratedProtocolMessageType('PAMController', (_message.Message,), {
  'DESCRIPTOR' : _PAMCONTROLLER,
  '__module__' : 'pam_pb2'
  # @@protoc_insertion_point(class_scope:Router.PAMController)
  })
_sym_db.RegisterMessage(PAMController)

ControllerResponse = _reflection.GeneratedProtocolMessageType('ControllerResponse', (_message.Message,), {
  'DESCRIPTOR' : _CONTROLLERRESPONSE,
  '__module__' : 'pam_pb2'
  # @@protoc_insertion_point(class_scope:Router.ControllerResponse)
  })
_sym_db.RegisterMessage(ControllerResponse)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'\n\030com.keepersecurity.protoB\003PAM'
  _PAMOPERATIONTYPE._serialized_start=1883
  _PAMOPERATIONTYPE._serialized_end=1947
  _PAMOPERATIONRESULTTYPE._serialized_start=1949
  _PAMOPERATIONRESULTTYPE._serialized_end=2061
  _CONTROLLERMESSAGETYPE._serialized_start=2063
  _CONTROLLERMESSAGETYPE._serialized_end=2135
  _PAMROTATIONSCHEDULE._serialized_start=40
  _PAMROTATIONSCHEDULE._serialized_end=171
  _PAMROTATIONSCHEDULESRESPONSE._serialized_start=173
  _PAMROTATIONSCHEDULESRESPONSE._serialized_end=251
  _PAMONLINECONTROLLERS._serialized_start=253
  _PAMONLINECONTROLLERS._serialized_end=296
  _PAMROTATEREQUEST._serialized_start=298
  _PAMROTATEREQUEST._serialized_end=355
  _PAMCONTROLLERSRESPONSE._serialized_start=357
  _PAMCONTROLLERSRESPONSE._serialized_end=425
  _PAMREMOVECONTROLLER._serialized_start=427
  _PAMREMOVECONTROLLER._serialized_end=488
  _PAMREMOVECONTROLLERRESPONSE._serialized_start=490
  _PAMREMOVECONTROLLERRESPONSE._serialized_end=569
  _PAMMODIFYREQUEST._serialized_start=571
  _PAMMODIFYREQUEST._serialized_end=635
  _PAMDATAOPERATION._serialized_start=638
  _PAMDATAOPERATION._serialized_end=799
  _PAMCONFIGURATIONDATA._serialized_start=801
  _PAMCONFIGURATIONDATA._serialized_end=902
  _PAMELEMENTDATA._serialized_start=904
  _PAMELEMENTDATA._serialized_end=973
  _PAMELEMENTOPERATIONRESULT._serialized_start=975
  _PAMELEMENTOPERATIONRESULT._serialized_end=1087
  _PAMMODIFYRESULT._serialized_start=1089
  _PAMMODIFYRESULT._serialized_end=1158
  _PAMELEMENT._serialized_start=1160
  _PAMELEMENT._serialized_end=1283
  _PAMGENERICUIDREQUEST._serialized_start=1285
  _PAMGENERICUIDREQUEST._serialized_end=1320
  _PAMGENERICUIDSREQUEST._serialized_start=1322
  _PAMGENERICUIDSREQUEST._serialized_end=1359
  _PAMCONFIGURATION._serialized_start=1362
  _PAMCONFIGURATION._serialized_end=1536
  _PAMCONFIGURATIONS._serialized_start=1538
  _PAMCONFIGURATIONS._serialized_end=1607
  _PAMCONTROLLER._serialized_start=1610
  _PAMCONTROLLER._serialized_end=1842
  _CONTROLLERRESPONSE._serialized_start=1844
  _CONTROLLERRESPONSE._serialized_end=1881
# @@protoc_insertion_point(module_scope)
