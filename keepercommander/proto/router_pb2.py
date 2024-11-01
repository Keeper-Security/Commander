# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: router.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from . import pam_pb2 as pam__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0crouter.proto\x12\x06Router\x1a\tpam.proto\"r\n\x0eRouterResponse\x12\x30\n\x0cresponseCode\x18\x01 \x01(\x0e\x32\x1a.Router.RouterResponseCode\x12\x14\n\x0c\x65rrorMessage\x18\x02 \x01(\t\x12\x18\n\x10\x65ncryptedPayload\x18\x03 \x01(\x0c\"\xaf\x01\n\x17RouterControllerMessage\x12/\n\x0bmessageType\x18\x01 \x01(\x0e\x32\x1a.PAM.ControllerMessageType\x12\x12\n\nmessageUid\x18\x02 \x01(\x0c\x12\x15\n\rcontrollerUid\x18\x03 \x01(\x0c\x12\x16\n\x0estreamResponse\x18\x04 \x01(\x08\x12\x0f\n\x07payload\x18\x05 \x01(\x0c\x12\x0f\n\x07timeout\x18\x06 \x01(\x05\"\xd3\x01\n\x0eRouterUserAuth\x12\x17\n\x0ftransmissionKey\x18\x01 \x01(\x0c\x12\x14\n\x0csessionToken\x18\x02 \x01(\x0c\x12\x0e\n\x06userId\x18\x03 \x01(\x05\x12\x18\n\x10\x65nterpriseUserId\x18\x04 \x01(\x03\x12\x12\n\ndeviceName\x18\x05 \x01(\t\x12\x13\n\x0b\x64\x65viceToken\x18\x06 \x01(\x0c\x12\x17\n\x0f\x63lientVersionId\x18\x07 \x01(\x05\x12\x14\n\x0cneedUsername\x18\x08 \x01(\x08\x12\x10\n\x08username\x18\t \x01(\t\"\xf2\x01\n\x10RouterDeviceAuth\x12\x10\n\x08\x63lientId\x18\x01 \x01(\t\x12\x15\n\rclientVersion\x18\x02 \x01(\t\x12\x11\n\tsignature\x18\x03 \x01(\x0c\x12\x14\n\x0c\x65nterpriseId\x18\x04 \x01(\x05\x12\x0e\n\x06nodeId\x18\x05 \x01(\x03\x12\x12\n\ndeviceName\x18\x06 \x01(\t\x12\x13\n\x0b\x64\x65viceToken\x18\x07 \x01(\x0c\x12\x16\n\x0e\x63ontrollerName\x18\x08 \x01(\t\x12\x15\n\rcontrollerUid\x18\t \x01(\x0c\x12\x11\n\townerUser\x18\n \x01(\t\x12\x11\n\tchallenge\x18\x0b \x01(\t\"\x83\x01\n\x14RouterRecordRotation\x12\x11\n\trecordUid\x18\x01 \x01(\x0c\x12\x18\n\x10\x63onfigurationUid\x18\x02 \x01(\x0c\x12\x15\n\rcontrollerUid\x18\x03 \x01(\x0c\x12\x13\n\x0bresourceUid\x18\x04 \x01(\x0c\x12\x12\n\nnoSchedule\x18\x05 \x01(\x08\"E\n\x1cRouterRecordRotationsRequest\x12\x14\n\x0c\x65nterpriseId\x18\x01 \x01(\x05\x12\x0f\n\x07records\x18\x02 \x03(\x0c\"a\n\x1dRouterRecordRotationsResponse\x12/\n\trotations\x18\x01 \x03(\x0b\x32\x1c.Router.RouterRecordRotation\x12\x0f\n\x07hasMore\x18\x02 \x01(\x08\"\xed\x01\n\x12RouterRotationInfo\x12,\n\x06status\x18\x01 \x01(\x0e\x32\x1c.Router.RouterRotationStatus\x12\x18\n\x10\x63onfigurationUid\x18\x02 \x01(\x0c\x12\x13\n\x0bresourceUid\x18\x03 \x01(\x0c\x12\x0e\n\x06nodeId\x18\x04 \x01(\x03\x12\x15\n\rcontrollerUid\x18\x05 \x01(\x0c\x12\x16\n\x0e\x63ontrollerName\x18\x06 \x01(\t\x12\x12\n\nscriptName\x18\x07 \x01(\t\x12\x15\n\rpwdComplexity\x18\x08 \x01(\t\x12\x10\n\x08\x64isabled\x18\t \x01(\x08\"\xf6\x01\n\x1bRouterRecordRotationRequest\x12\x11\n\trecordUid\x18\x01 \x01(\x0c\x12\x10\n\x08revision\x18\x02 \x01(\x03\x12\x18\n\x10\x63onfigurationUid\x18\x03 \x01(\x0c\x12\x13\n\x0bresourceUid\x18\x04 \x01(\x0c\x12\x10\n\x08schedule\x18\x05 \x01(\t\x12\x18\n\x10\x65nterpriseUserId\x18\x06 \x01(\x03\x12\x15\n\rpwdComplexity\x18\x07 \x01(\x0c\x12\x10\n\x08\x64isabled\x18\x08 \x01(\x08\x12\x15\n\rremoteAddress\x18\t \x01(\t\x12\x17\n\x0f\x63lientVersionId\x18\n \x01(\x05\"<\n\x17UserRecordAccessRequest\x12\x0e\n\x06userId\x18\x01 \x01(\x05\x12\x11\n\trecordUid\x18\x02 \x01(\x0c\"a\n\x18UserRecordAccessResponse\x12\x11\n\trecordUid\x18\x01 \x01(\x0c\x12\x32\n\x0b\x61\x63\x63\x65ssLevel\x18\x02 \x01(\x0e\x32\x1d.Router.UserRecordAccessLevel\"8\n\x10RotationSchedule\x12\x12\n\nrecord_uid\x18\x01 \x01(\x0c\x12\x10\n\x08schedule\x18\x02 \x01(\t\"\x90\x01\n\x12\x41piCallbackRequest\x12\x13\n\x0bresourceUid\x18\x01 \x01(\x0c\x12.\n\tschedules\x18\x02 \x03(\x0b\x32\x1b.Router.ApiCallbackSchedule\x12\x0b\n\x03url\x18\x03 \x01(\t\x12(\n\x0bserviceType\x18\x04 \x01(\x0e\x32\x13.Router.ServiceType\"5\n\x13\x41piCallbackSchedule\x12\x10\n\x08schedule\x18\x01 \x01(\t\x12\x0c\n\x04\x64\x61ta\x18\x02 \x01(\x0c*\xb6\x01\n\x12RouterResponseCode\x12\n\n\x06RRC_OK\x10\x00\x12\x15\n\x11RRC_GENERAL_ERROR\x10\x01\x12\x13\n\x0fRRC_NOT_ALLOWED\x10\x02\x12\x13\n\x0fRRC_BAD_REQUEST\x10\x03\x12\x0f\n\x0bRRC_TIMEOUT\x10\x04\x12\x11\n\rRRC_BAD_STATE\x10\x05\x12\x17\n\x13RRC_CONTROLLER_DOWN\x10\x06\x12\x16\n\x12RRC_WRONG_INSTANCE\x10\x07*k\n\x14RouterRotationStatus\x12\x0e\n\nRRS_ONLINE\x10\x00\x12\x13\n\x0fRRS_NO_ROTATION\x10\x01\x12\x15\n\x11RRS_NO_CONTROLLER\x10\x02\x12\x17\n\x13RRS_CONTROLLER_DOWN\x10\x03*}\n\x15UserRecordAccessLevel\x12\r\n\tRRAL_NONE\x10\x00\x12\r\n\tRRAL_READ\x10\x01\x12\x0e\n\nRRAL_SHARE\x10\x02\x12\r\n\tRRAL_EDIT\x10\x03\x12\x17\n\x13RRAL_EDIT_AND_SHARE\x10\x04\x12\x0e\n\nRRAL_OWNER\x10\x05*.\n\x0bServiceType\x12\x0f\n\x0bUNSPECIFIED\x10\x00\x12\x06\n\x02KA\x10\x01\x12\x06\n\x02\x42I\x10\x02\x42\"\n\x18\x63om.keepersecurity.protoB\x06Routerb\x06proto3')

_ROUTERRESPONSECODE = DESCRIPTOR.enum_types_by_name['RouterResponseCode']
RouterResponseCode = enum_type_wrapper.EnumTypeWrapper(_ROUTERRESPONSECODE)
_ROUTERROTATIONSTATUS = DESCRIPTOR.enum_types_by_name['RouterRotationStatus']
RouterRotationStatus = enum_type_wrapper.EnumTypeWrapper(_ROUTERROTATIONSTATUS)
_USERRECORDACCESSLEVEL = DESCRIPTOR.enum_types_by_name['UserRecordAccessLevel']
UserRecordAccessLevel = enum_type_wrapper.EnumTypeWrapper(_USERRECORDACCESSLEVEL)
_SERVICETYPE = DESCRIPTOR.enum_types_by_name['ServiceType']
ServiceType = enum_type_wrapper.EnumTypeWrapper(_SERVICETYPE)
RRC_OK = 0
RRC_GENERAL_ERROR = 1
RRC_NOT_ALLOWED = 2
RRC_BAD_REQUEST = 3
RRC_TIMEOUT = 4
RRC_BAD_STATE = 5
RRC_CONTROLLER_DOWN = 6
RRC_WRONG_INSTANCE = 7
RRS_ONLINE = 0
RRS_NO_ROTATION = 1
RRS_NO_CONTROLLER = 2
RRS_CONTROLLER_DOWN = 3
RRAL_NONE = 0
RRAL_READ = 1
RRAL_SHARE = 2
RRAL_EDIT = 3
RRAL_EDIT_AND_SHARE = 4
RRAL_OWNER = 5
UNSPECIFIED = 0
KA = 1
BI = 2


_ROUTERRESPONSE = DESCRIPTOR.message_types_by_name['RouterResponse']
_ROUTERCONTROLLERMESSAGE = DESCRIPTOR.message_types_by_name['RouterControllerMessage']
_ROUTERUSERAUTH = DESCRIPTOR.message_types_by_name['RouterUserAuth']
_ROUTERDEVICEAUTH = DESCRIPTOR.message_types_by_name['RouterDeviceAuth']
_ROUTERRECORDROTATION = DESCRIPTOR.message_types_by_name['RouterRecordRotation']
_ROUTERRECORDROTATIONSREQUEST = DESCRIPTOR.message_types_by_name['RouterRecordRotationsRequest']
_ROUTERRECORDROTATIONSRESPONSE = DESCRIPTOR.message_types_by_name['RouterRecordRotationsResponse']
_ROUTERROTATIONINFO = DESCRIPTOR.message_types_by_name['RouterRotationInfo']
_ROUTERRECORDROTATIONREQUEST = DESCRIPTOR.message_types_by_name['RouterRecordRotationRequest']
_USERRECORDACCESSREQUEST = DESCRIPTOR.message_types_by_name['UserRecordAccessRequest']
_USERRECORDACCESSRESPONSE = DESCRIPTOR.message_types_by_name['UserRecordAccessResponse']
_ROTATIONSCHEDULE = DESCRIPTOR.message_types_by_name['RotationSchedule']
_APICALLBACKREQUEST = DESCRIPTOR.message_types_by_name['ApiCallbackRequest']
_APICALLBACKSCHEDULE = DESCRIPTOR.message_types_by_name['ApiCallbackSchedule']
RouterResponse = _reflection.GeneratedProtocolMessageType('RouterResponse', (_message.Message,), {
  'DESCRIPTOR' : _ROUTERRESPONSE,
  '__module__' : 'router_pb2'
  # @@protoc_insertion_point(class_scope:Router.RouterResponse)
  })
_sym_db.RegisterMessage(RouterResponse)

RouterControllerMessage = _reflection.GeneratedProtocolMessageType('RouterControllerMessage', (_message.Message,), {
  'DESCRIPTOR' : _ROUTERCONTROLLERMESSAGE,
  '__module__' : 'router_pb2'
  # @@protoc_insertion_point(class_scope:Router.RouterControllerMessage)
  })
_sym_db.RegisterMessage(RouterControllerMessage)

RouterUserAuth = _reflection.GeneratedProtocolMessageType('RouterUserAuth', (_message.Message,), {
  'DESCRIPTOR' : _ROUTERUSERAUTH,
  '__module__' : 'router_pb2'
  # @@protoc_insertion_point(class_scope:Router.RouterUserAuth)
  })
_sym_db.RegisterMessage(RouterUserAuth)

RouterDeviceAuth = _reflection.GeneratedProtocolMessageType('RouterDeviceAuth', (_message.Message,), {
  'DESCRIPTOR' : _ROUTERDEVICEAUTH,
  '__module__' : 'router_pb2'
  # @@protoc_insertion_point(class_scope:Router.RouterDeviceAuth)
  })
_sym_db.RegisterMessage(RouterDeviceAuth)

RouterRecordRotation = _reflection.GeneratedProtocolMessageType('RouterRecordRotation', (_message.Message,), {
  'DESCRIPTOR' : _ROUTERRECORDROTATION,
  '__module__' : 'router_pb2'
  # @@protoc_insertion_point(class_scope:Router.RouterRecordRotation)
  })
_sym_db.RegisterMessage(RouterRecordRotation)

RouterRecordRotationsRequest = _reflection.GeneratedProtocolMessageType('RouterRecordRotationsRequest', (_message.Message,), {
  'DESCRIPTOR' : _ROUTERRECORDROTATIONSREQUEST,
  '__module__' : 'router_pb2'
  # @@protoc_insertion_point(class_scope:Router.RouterRecordRotationsRequest)
  })
_sym_db.RegisterMessage(RouterRecordRotationsRequest)

RouterRecordRotationsResponse = _reflection.GeneratedProtocolMessageType('RouterRecordRotationsResponse', (_message.Message,), {
  'DESCRIPTOR' : _ROUTERRECORDROTATIONSRESPONSE,
  '__module__' : 'router_pb2'
  # @@protoc_insertion_point(class_scope:Router.RouterRecordRotationsResponse)
  })
_sym_db.RegisterMessage(RouterRecordRotationsResponse)

RouterRotationInfo = _reflection.GeneratedProtocolMessageType('RouterRotationInfo', (_message.Message,), {
  'DESCRIPTOR' : _ROUTERROTATIONINFO,
  '__module__' : 'router_pb2'
  # @@protoc_insertion_point(class_scope:Router.RouterRotationInfo)
  })
_sym_db.RegisterMessage(RouterRotationInfo)

RouterRecordRotationRequest = _reflection.GeneratedProtocolMessageType('RouterRecordRotationRequest', (_message.Message,), {
  'DESCRIPTOR' : _ROUTERRECORDROTATIONREQUEST,
  '__module__' : 'router_pb2'
  # @@protoc_insertion_point(class_scope:Router.RouterRecordRotationRequest)
  })
_sym_db.RegisterMessage(RouterRecordRotationRequest)

UserRecordAccessRequest = _reflection.GeneratedProtocolMessageType('UserRecordAccessRequest', (_message.Message,), {
  'DESCRIPTOR' : _USERRECORDACCESSREQUEST,
  '__module__' : 'router_pb2'
  # @@protoc_insertion_point(class_scope:Router.UserRecordAccessRequest)
  })
_sym_db.RegisterMessage(UserRecordAccessRequest)

UserRecordAccessResponse = _reflection.GeneratedProtocolMessageType('UserRecordAccessResponse', (_message.Message,), {
  'DESCRIPTOR' : _USERRECORDACCESSRESPONSE,
  '__module__' : 'router_pb2'
  # @@protoc_insertion_point(class_scope:Router.UserRecordAccessResponse)
  })
_sym_db.RegisterMessage(UserRecordAccessResponse)

RotationSchedule = _reflection.GeneratedProtocolMessageType('RotationSchedule', (_message.Message,), {
  'DESCRIPTOR' : _ROTATIONSCHEDULE,
  '__module__' : 'router_pb2'
  # @@protoc_insertion_point(class_scope:Router.RotationSchedule)
  })
_sym_db.RegisterMessage(RotationSchedule)

ApiCallbackRequest = _reflection.GeneratedProtocolMessageType('ApiCallbackRequest', (_message.Message,), {
  'DESCRIPTOR' : _APICALLBACKREQUEST,
  '__module__' : 'router_pb2'
  # @@protoc_insertion_point(class_scope:Router.ApiCallbackRequest)
  })
_sym_db.RegisterMessage(ApiCallbackRequest)

ApiCallbackSchedule = _reflection.GeneratedProtocolMessageType('ApiCallbackSchedule', (_message.Message,), {
  'DESCRIPTOR' : _APICALLBACKSCHEDULE,
  '__module__' : 'router_pb2'
  # @@protoc_insertion_point(class_scope:Router.ApiCallbackSchedule)
  })
_sym_db.RegisterMessage(ApiCallbackSchedule)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'\n\030com.keepersecurity.protoB\006Router'
  _ROUTERRESPONSECODE._serialized_start=2003
  _ROUTERRESPONSECODE._serialized_end=2185
  _ROUTERROTATIONSTATUS._serialized_start=2187
  _ROUTERROTATIONSTATUS._serialized_end=2294
  _USERRECORDACCESSLEVEL._serialized_start=2296
  _USERRECORDACCESSLEVEL._serialized_end=2421
  _SERVICETYPE._serialized_start=2423
  _SERVICETYPE._serialized_end=2469
  _ROUTERRESPONSE._serialized_start=35
  _ROUTERRESPONSE._serialized_end=149
  _ROUTERCONTROLLERMESSAGE._serialized_start=152
  _ROUTERCONTROLLERMESSAGE._serialized_end=327
  _ROUTERUSERAUTH._serialized_start=330
  _ROUTERUSERAUTH._serialized_end=541
  _ROUTERDEVICEAUTH._serialized_start=544
  _ROUTERDEVICEAUTH._serialized_end=786
  _ROUTERRECORDROTATION._serialized_start=789
  _ROUTERRECORDROTATION._serialized_end=920
  _ROUTERRECORDROTATIONSREQUEST._serialized_start=922
  _ROUTERRECORDROTATIONSREQUEST._serialized_end=991
  _ROUTERRECORDROTATIONSRESPONSE._serialized_start=993
  _ROUTERRECORDROTATIONSRESPONSE._serialized_end=1090
  _ROUTERROTATIONINFO._serialized_start=1093
  _ROUTERROTATIONINFO._serialized_end=1330
  _ROUTERRECORDROTATIONREQUEST._serialized_start=1333
  _ROUTERRECORDROTATIONREQUEST._serialized_end=1579
  _USERRECORDACCESSREQUEST._serialized_start=1581
  _USERRECORDACCESSREQUEST._serialized_end=1641
  _USERRECORDACCESSRESPONSE._serialized_start=1643
  _USERRECORDACCESSRESPONSE._serialized_end=1740
  _ROTATIONSCHEDULE._serialized_start=1742
  _ROTATIONSCHEDULE._serialized_end=1798
  _APICALLBACKREQUEST._serialized_start=1801
  _APICALLBACKREQUEST._serialized_end=1945
  _APICALLBACKSCHEDULE._serialized_start=1947
  _APICALLBACKSCHEDULE._serialized_end=2000
# @@protoc_insertion_point(module_scope)
