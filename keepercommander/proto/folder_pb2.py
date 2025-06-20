# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: folder.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from . import record_pb2 as record__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0c\x66older.proto\x12\x06\x46older\x1a\x0crecord.proto\"\\\n\x10\x45ncryptedDataKey\x12\x14\n\x0c\x65ncryptedKey\x18\x01 \x01(\x0c\x12\x32\n\x10\x65ncryptedKeyType\x18\x02 \x01(\x0e\x32\x18.Folder.EncryptedKeyType\"\x82\x01\n\x16SharedFolderRecordData\x12\x11\n\tfolderUid\x18\x01 \x01(\x0c\x12\x11\n\trecordUid\x18\x02 \x01(\x0c\x12\x0e\n\x06userId\x18\x03 \x01(\x05\x12\x32\n\x10\x65ncryptedDataKey\x18\x04 \x03(\x0b\x32\x18.Folder.EncryptedDataKey\"\\\n\x1aSharedFolderRecordDataList\x12>\n\x16sharedFolderRecordData\x18\x01 \x03(\x0b\x32\x1e.Folder.SharedFolderRecordData\"_\n\x15SharedFolderRecordFix\x12\x11\n\tfolderUid\x18\x01 \x01(\x0c\x12\x11\n\trecordUid\x18\x02 \x01(\x0c\x12 \n\x18\x65ncryptedRecordFolderKey\x18\x03 \x01(\x0c\"Y\n\x19SharedFolderRecordFixList\x12<\n\x15sharedFolderRecordFix\x18\x01 \x03(\x0b\x32\x1d.Folder.SharedFolderRecordFix\"\xa2\x02\n\rRecordRequest\x12\x11\n\trecordUid\x18\x01 \x01(\x0c\x12&\n\nrecordType\x18\x02 \x01(\x0e\x32\x12.Folder.RecordType\x12\x12\n\nrecordData\x18\x03 \x01(\x0c\x12\x1a\n\x12\x65ncryptedRecordKey\x18\x04 \x01(\x0c\x12&\n\nfolderType\x18\x05 \x01(\x0e\x32\x12.Folder.FolderType\x12\x12\n\nhowLongAgo\x18\x06 \x01(\x03\x12\x11\n\tfolderUid\x18\x07 \x01(\x0c\x12 \n\x18\x65ncryptedRecordFolderKey\x18\x08 \x01(\x0c\x12\r\n\x05\x65xtra\x18\t \x01(\x0c\x12\x15\n\rnonSharedData\x18\n \x01(\x0c\x12\x0f\n\x07\x66ileIds\x18\x0b \x03(\x03\"E\n\x0eRecordResponse\x12\x11\n\trecordUid\x18\x01 \x01(\x0c\x12\x10\n\x08revision\x18\x02 \x01(\x03\x12\x0e\n\x06status\x18\x03 \x01(\t\"\x80\x01\n\x12SharedFolderFields\x12\x1b\n\x13\x65ncryptedFolderName\x18\x01 \x01(\x0c\x12\x13\n\x0bmanageUsers\x18\x02 \x01(\x08\x12\x15\n\rmanageRecords\x18\x03 \x01(\x08\x12\x0f\n\x07\x63\x61nEdit\x18\x04 \x01(\x08\x12\x10\n\x08\x63\x61nShare\x18\x05 \x01(\x08\"3\n\x18SharedFolderFolderFields\x12\x17\n\x0fsharedFolderUid\x18\x01 \x01(\x0c\"\x8f\x02\n\rFolderRequest\x12\x11\n\tfolderUid\x18\x01 \x01(\x0c\x12&\n\nfolderType\x18\x02 \x01(\x0e\x32\x12.Folder.FolderType\x12\x17\n\x0fparentFolderUid\x18\x03 \x01(\x0c\x12\x12\n\nfolderData\x18\x04 \x01(\x0c\x12\x1a\n\x12\x65ncryptedFolderKey\x18\x05 \x01(\x0c\x12\x36\n\x12sharedFolderFields\x18\x06 \x01(\x0b\x32\x1a.Folder.SharedFolderFields\x12\x42\n\x18sharedFolderFolderFields\x18\x07 \x01(\x0b\x32 .Folder.SharedFolderFolderFields\"E\n\x0e\x46olderResponse\x12\x11\n\tfolderUid\x18\x01 \x01(\x0c\x12\x10\n\x08revision\x18\x02 \x01(\x03\x12\x0e\n\x06status\x18\x03 \x01(\t\"w\n\x19ImportFolderRecordRequest\x12,\n\rfolderRequest\x18\x01 \x03(\x0b\x32\x15.Folder.FolderRequest\x12,\n\rrecordRequest\x18\x02 \x03(\x0b\x32\x15.Folder.RecordRequest\"|\n\x1aImportFolderRecordResponse\x12.\n\x0e\x66olderResponse\x18\x01 \x03(\x0b\x32\x16.Folder.FolderResponse\x12.\n\x0erecordResponse\x18\x02 \x03(\x0b\x32\x16.Folder.RecordResponse\"\xc9\x02\n\x18SharedFolderUpdateRecord\x12\x11\n\trecordUid\x18\x01 \x01(\x0c\x12\x17\n\x0fsharedFolderUid\x18\x02 \x01(\x0c\x12\x0f\n\x07teamUid\x18\x03 \x01(\x0c\x12(\n\x07\x63\x61nEdit\x18\x04 \x01(\x0e\x32\x17.Folder.SetBooleanValue\x12)\n\x08\x63\x61nShare\x18\x05 \x01(\x0e\x32\x17.Folder.SetBooleanValue\x12\x1a\n\x12\x65ncryptedRecordKey\x18\x06 \x01(\x0c\x12\x10\n\x08revision\x18\x07 \x01(\x05\x12\x12\n\nexpiration\x18\x08 \x01(\x12\x12=\n\x15timerNotificationType\x18\t \x01(\x0e\x32\x1e.Records.TimerNotificationType\x12\x1a\n\x12rotateOnExpiration\x18\n \x01(\x08\"\xcc\x02\n\x16SharedFolderUpdateUser\x12\x10\n\x08username\x18\x01 \x01(\t\x12,\n\x0bmanageUsers\x18\x02 \x01(\x0e\x32\x17.Folder.SetBooleanValue\x12.\n\rmanageRecords\x18\x03 \x01(\x0e\x32\x17.Folder.SetBooleanValue\x12\x1b\n\x0fsharedFolderKey\x18\x04 \x01(\x0c\x42\x02\x18\x01\x12\x12\n\nexpiration\x18\x05 \x01(\x12\x12=\n\x15timerNotificationType\x18\x06 \x01(\x0e\x32\x1e.Records.TimerNotificationType\x12\x36\n\x14typedSharedFolderKey\x18\x07 \x01(\x0b\x32\x18.Folder.EncryptedDataKey\x12\x1a\n\x12rotateOnExpiration\x18\x08 \x01(\x08\"\x99\x02\n\x16SharedFolderUpdateTeam\x12\x0f\n\x07teamUid\x18\x01 \x01(\x0c\x12\x13\n\x0bmanageUsers\x18\x02 \x01(\x08\x12\x15\n\rmanageRecords\x18\x03 \x01(\x08\x12\x1b\n\x0fsharedFolderKey\x18\x04 \x01(\x0c\x42\x02\x18\x01\x12\x12\n\nexpiration\x18\x05 \x01(\x12\x12=\n\x15timerNotificationType\x18\x06 \x01(\x0e\x32\x1e.Records.TimerNotificationType\x12\x36\n\x14typedSharedFolderKey\x18\x07 \x01(\x0b\x32\x18.Folder.EncryptedDataKey\x12\x1a\n\x12rotateOnExpiration\x18\x08 \x01(\x08\"\x8e\x07\n\x1bSharedFolderUpdateV3Request\x12,\n$sharedFolderUpdateOperation_dont_use\x18\x01 \x01(\x05\x12\x17\n\x0fsharedFolderUid\x18\x02 \x01(\x0c\x12!\n\x19\x65ncryptedSharedFolderName\x18\x03 \x01(\x0c\x12\x10\n\x08revision\x18\x04 \x01(\x03\x12\x13\n\x0b\x66orceUpdate\x18\x05 \x01(\x08\x12\x13\n\x0b\x66romTeamUid\x18\x06 \x01(\x0c\x12\x33\n\x12\x64\x65\x66\x61ultManageUsers\x18\x07 \x01(\x0e\x32\x17.Folder.SetBooleanValue\x12\x35\n\x14\x64\x65\x66\x61ultManageRecords\x18\x08 \x01(\x0e\x32\x17.Folder.SetBooleanValue\x12/\n\x0e\x64\x65\x66\x61ultCanEdit\x18\t \x01(\x0e\x32\x17.Folder.SetBooleanValue\x12\x30\n\x0f\x64\x65\x66\x61ultCanShare\x18\n \x01(\x0e\x32\x17.Folder.SetBooleanValue\x12?\n\x15sharedFolderAddRecord\x18\x0b \x03(\x0b\x32 .Folder.SharedFolderUpdateRecord\x12;\n\x13sharedFolderAddUser\x18\x0c \x03(\x0b\x32\x1e.Folder.SharedFolderUpdateUser\x12;\n\x13sharedFolderAddTeam\x18\r \x03(\x0b\x32\x1e.Folder.SharedFolderUpdateTeam\x12\x42\n\x18sharedFolderUpdateRecord\x18\x0e \x03(\x0b\x32 .Folder.SharedFolderUpdateRecord\x12>\n\x16sharedFolderUpdateUser\x18\x0f \x03(\x0b\x32\x1e.Folder.SharedFolderUpdateUser\x12>\n\x16sharedFolderUpdateTeam\x18\x10 \x03(\x0b\x32\x1e.Folder.SharedFolderUpdateTeam\x12 \n\x18sharedFolderRemoveRecord\x18\x11 \x03(\x0c\x12\x1e\n\x16sharedFolderRemoveUser\x18\x12 \x03(\t\x12\x1e\n\x16sharedFolderRemoveTeam\x18\x13 \x03(\x0c\x12\x19\n\x11sharedFolderOwner\x18\x14 \x01(\t\"c\n\x1dSharedFolderUpdateV3RequestV2\x12\x42\n\x15sharedFoldersUpdateV3\x18\x01 \x03(\x0b\x32#.Folder.SharedFolderUpdateV3Request\"C\n\x1eSharedFolderUpdateRecordStatus\x12\x11\n\trecordUid\x18\x01 \x01(\x0c\x12\x0e\n\x06status\x18\x02 \x01(\t\"@\n\x1cSharedFolderUpdateUserStatus\x12\x10\n\x08username\x18\x01 \x01(\t\x12\x0e\n\x06status\x18\x02 \x01(\t\"?\n\x1cSharedFolderUpdateTeamStatus\x12\x0f\n\x07teamUid\x18\x01 \x01(\x0c\x12\x0e\n\x06status\x18\x02 \x01(\t\"\x88\x06\n\x1cSharedFolderUpdateV3Response\x12\x10\n\x08revision\x18\x01 \x01(\x03\x12K\n\x1bsharedFolderAddRecordStatus\x18\x02 \x03(\x0b\x32&.Folder.SharedFolderUpdateRecordStatus\x12G\n\x19sharedFolderAddUserStatus\x18\x03 \x03(\x0b\x32$.Folder.SharedFolderUpdateUserStatus\x12G\n\x19sharedFolderAddTeamStatus\x18\x04 \x03(\x0b\x32$.Folder.SharedFolderUpdateTeamStatus\x12N\n\x1esharedFolderUpdateRecordStatus\x18\x05 \x03(\x0b\x32&.Folder.SharedFolderUpdateRecordStatus\x12J\n\x1csharedFolderUpdateUserStatus\x18\x06 \x03(\x0b\x32$.Folder.SharedFolderUpdateUserStatus\x12J\n\x1csharedFolderUpdateTeamStatus\x18\x07 \x03(\x0b\x32$.Folder.SharedFolderUpdateTeamStatus\x12N\n\x1esharedFolderRemoveRecordStatus\x18\x08 \x03(\x0b\x32&.Folder.SharedFolderUpdateRecordStatus\x12J\n\x1csharedFolderRemoveUserStatus\x18\t \x03(\x0b\x32$.Folder.SharedFolderUpdateUserStatus\x12J\n\x1csharedFolderRemoveTeamStatus\x18\n \x03(\x0b\x32$.Folder.SharedFolderUpdateTeamStatus\x12\x17\n\x0fsharedFolderUid\x18\x0c \x01(\x0c\x12\x0e\n\x06status\x18\r \x01(\t\"m\n\x1eSharedFolderUpdateV3ResponseV2\x12K\n\x1dsharedFoldersUpdateV3Response\x18\x01 \x03(\x0b\x32$.Folder.SharedFolderUpdateV3Response\"\xfa\x01\n)GetDeletedSharedFoldersAndRecordsResponse\x12\x32\n\rsharedFolders\x18\x01 \x03(\x0b\x32\x1b.Folder.DeletedSharedFolder\x12>\n\x13sharedFolderRecords\x18\x02 \x03(\x0b\x32!.Folder.DeletedSharedFolderRecord\x12\x34\n\x11\x64\x65letedRecordData\x18\x03 \x03(\x0b\x32\x19.Folder.DeletedRecordData\x12#\n\tusernames\x18\x04 \x03(\x0b\x32\x10.Folder.Username\"\xd1\x01\n\x13\x44\x65letedSharedFolder\x12\x17\n\x0fsharedFolderUid\x18\x01 \x01(\x0c\x12\x11\n\tfolderUid\x18\x02 \x01(\x0c\x12\x11\n\tparentUid\x18\x03 \x01(\x0c\x12\x17\n\x0fsharedFolderKey\x18\x04 \x01(\x0c\x12-\n\rfolderKeyType\x18\x05 \x01(\x0e\x32\x16.Records.RecordKeyType\x12\x0c\n\x04\x64\x61ta\x18\x06 \x01(\x0c\x12\x13\n\x0b\x64\x61teDeleted\x18\x07 \x01(\x03\x12\x10\n\x08revision\x18\x08 \x01(\x03\"\x81\x01\n\x19\x44\x65letedSharedFolderRecord\x12\x11\n\tfolderUid\x18\x01 \x01(\x0c\x12\x11\n\trecordUid\x18\x02 \x01(\x0c\x12\x17\n\x0fsharedRecordKey\x18\x03 \x01(\x0c\x12\x13\n\x0b\x64\x61teDeleted\x18\x04 \x01(\x03\x12\x10\n\x08revision\x18\x05 \x01(\x03\"\x85\x01\n\x11\x44\x65letedRecordData\x12\x11\n\trecordUid\x18\x01 \x01(\x0c\x12\x10\n\x08ownerUid\x18\x02 \x01(\x0c\x12\x10\n\x08revision\x18\x03 \x01(\x03\x12\x1a\n\x12\x63lientModifiedTime\x18\x04 \x01(\x03\x12\x0c\n\x04\x64\x61ta\x18\x05 \x01(\x0c\x12\x0f\n\x07version\x18\x06 \x01(\x05\"0\n\x08Username\x12\x12\n\naccountUid\x18\x01 \x01(\x0c\x12\x10\n\x08username\x18\x02 \x01(\t\"\x8a\x01\n,RestoreDeletedSharedFoldersAndRecordsRequest\x12,\n\x07\x66olders\x18\x01 \x03(\x0b\x32\x1b.Folder.RestoreSharedObject\x12,\n\x07records\x18\x02 \x03(\x0b\x32\x1b.Folder.RestoreSharedObject\"<\n\x13RestoreSharedObject\x12\x11\n\tfolderUid\x18\x01 \x01(\x0c\x12\x12\n\nrecordUids\x18\x02 \x03(\x0c*\x1a\n\nRecordType\x12\x0c\n\x08password\x10\x00*^\n\nFolderType\x12\x12\n\x0e\x64\x65\x66\x61ult_folder\x10\x00\x12\x0f\n\x0buser_folder\x10\x01\x12\x11\n\rshared_folder\x10\x02\x12\x18\n\x14shared_folder_folder\x10\x03*\x96\x01\n\x10\x45ncryptedKeyType\x12\n\n\x06no_key\x10\x00\x12\x19\n\x15\x65ncrypted_by_data_key\x10\x01\x12\x1b\n\x17\x65ncrypted_by_public_key\x10\x02\x12\x1d\n\x19\x65ncrypted_by_data_key_gcm\x10\x03\x12\x1f\n\x1b\x65ncrypted_by_public_key_ecc\x10\x04*M\n\x0fSetBooleanValue\x12\x15\n\x11\x42OOLEAN_NO_CHANGE\x10\x00\x12\x10\n\x0c\x42OOLEAN_TRUE\x10\x01\x12\x11\n\rBOOLEAN_FALSE\x10\x02\x42\"\n\x18\x63om.keepersecurity.protoB\x06\x46olderb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'folder_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  _globals['DESCRIPTOR']._options = None
  _globals['DESCRIPTOR']._serialized_options = b'\n\030com.keepersecurity.protoB\006Folder'
  _globals['_SHAREDFOLDERUPDATEUSER'].fields_by_name['sharedFolderKey']._options = None
  _globals['_SHAREDFOLDERUPDATEUSER'].fields_by_name['sharedFolderKey']._serialized_options = b'\030\001'
  _globals['_SHAREDFOLDERUPDATETEAM'].fields_by_name['sharedFolderKey']._options = None
  _globals['_SHAREDFOLDERUPDATETEAM'].fields_by_name['sharedFolderKey']._serialized_options = b'\030\001'
  _globals['_RECORDTYPE']._serialized_start=5728
  _globals['_RECORDTYPE']._serialized_end=5754
  _globals['_FOLDERTYPE']._serialized_start=5756
  _globals['_FOLDERTYPE']._serialized_end=5850
  _globals['_ENCRYPTEDKEYTYPE']._serialized_start=5853
  _globals['_ENCRYPTEDKEYTYPE']._serialized_end=6003
  _globals['_SETBOOLEANVALUE']._serialized_start=6005
  _globals['_SETBOOLEANVALUE']._serialized_end=6082
  _globals['_ENCRYPTEDDATAKEY']._serialized_start=38
  _globals['_ENCRYPTEDDATAKEY']._serialized_end=130
  _globals['_SHAREDFOLDERRECORDDATA']._serialized_start=133
  _globals['_SHAREDFOLDERRECORDDATA']._serialized_end=263
  _globals['_SHAREDFOLDERRECORDDATALIST']._serialized_start=265
  _globals['_SHAREDFOLDERRECORDDATALIST']._serialized_end=357
  _globals['_SHAREDFOLDERRECORDFIX']._serialized_start=359
  _globals['_SHAREDFOLDERRECORDFIX']._serialized_end=454
  _globals['_SHAREDFOLDERRECORDFIXLIST']._serialized_start=456
  _globals['_SHAREDFOLDERRECORDFIXLIST']._serialized_end=545
  _globals['_RECORDREQUEST']._serialized_start=548
  _globals['_RECORDREQUEST']._serialized_end=838
  _globals['_RECORDRESPONSE']._serialized_start=840
  _globals['_RECORDRESPONSE']._serialized_end=909
  _globals['_SHAREDFOLDERFIELDS']._serialized_start=912
  _globals['_SHAREDFOLDERFIELDS']._serialized_end=1040
  _globals['_SHAREDFOLDERFOLDERFIELDS']._serialized_start=1042
  _globals['_SHAREDFOLDERFOLDERFIELDS']._serialized_end=1093
  _globals['_FOLDERREQUEST']._serialized_start=1096
  _globals['_FOLDERREQUEST']._serialized_end=1367
  _globals['_FOLDERRESPONSE']._serialized_start=1369
  _globals['_FOLDERRESPONSE']._serialized_end=1438
  _globals['_IMPORTFOLDERRECORDREQUEST']._serialized_start=1440
  _globals['_IMPORTFOLDERRECORDREQUEST']._serialized_end=1559
  _globals['_IMPORTFOLDERRECORDRESPONSE']._serialized_start=1561
  _globals['_IMPORTFOLDERRECORDRESPONSE']._serialized_end=1685
  _globals['_SHAREDFOLDERUPDATERECORD']._serialized_start=1688
  _globals['_SHAREDFOLDERUPDATERECORD']._serialized_end=2017
  _globals['_SHAREDFOLDERUPDATEUSER']._serialized_start=2020
  _globals['_SHAREDFOLDERUPDATEUSER']._serialized_end=2352
  _globals['_SHAREDFOLDERUPDATETEAM']._serialized_start=2355
  _globals['_SHAREDFOLDERUPDATETEAM']._serialized_end=2636
  _globals['_SHAREDFOLDERUPDATEV3REQUEST']._serialized_start=2639
  _globals['_SHAREDFOLDERUPDATEV3REQUEST']._serialized_end=3549
  _globals['_SHAREDFOLDERUPDATEV3REQUESTV2']._serialized_start=3551
  _globals['_SHAREDFOLDERUPDATEV3REQUESTV2']._serialized_end=3650
  _globals['_SHAREDFOLDERUPDATERECORDSTATUS']._serialized_start=3652
  _globals['_SHAREDFOLDERUPDATERECORDSTATUS']._serialized_end=3719
  _globals['_SHAREDFOLDERUPDATEUSERSTATUS']._serialized_start=3721
  _globals['_SHAREDFOLDERUPDATEUSERSTATUS']._serialized_end=3785
  _globals['_SHAREDFOLDERUPDATETEAMSTATUS']._serialized_start=3787
  _globals['_SHAREDFOLDERUPDATETEAMSTATUS']._serialized_end=3850
  _globals['_SHAREDFOLDERUPDATEV3RESPONSE']._serialized_start=3853
  _globals['_SHAREDFOLDERUPDATEV3RESPONSE']._serialized_end=4629
  _globals['_SHAREDFOLDERUPDATEV3RESPONSEV2']._serialized_start=4631
  _globals['_SHAREDFOLDERUPDATEV3RESPONSEV2']._serialized_end=4740
  _globals['_GETDELETEDSHAREDFOLDERSANDRECORDSRESPONSE']._serialized_start=4743
  _globals['_GETDELETEDSHAREDFOLDERSANDRECORDSRESPONSE']._serialized_end=4993
  _globals['_DELETEDSHAREDFOLDER']._serialized_start=4996
  _globals['_DELETEDSHAREDFOLDER']._serialized_end=5205
  _globals['_DELETEDSHAREDFOLDERRECORD']._serialized_start=5208
  _globals['_DELETEDSHAREDFOLDERRECORD']._serialized_end=5337
  _globals['_DELETEDRECORDDATA']._serialized_start=5340
  _globals['_DELETEDRECORDDATA']._serialized_end=5473
  _globals['_USERNAME']._serialized_start=5475
  _globals['_USERNAME']._serialized_end=5523
  _globals['_RESTOREDELETEDSHAREDFOLDERSANDRECORDSREQUEST']._serialized_start=5526
  _globals['_RESTOREDELETEDSHAREDFOLDERSANDRECORDSREQUEST']._serialized_end=5664
  _globals['_RESTORESHAREDOBJECT']._serialized_start=5666
  _globals['_RESTORESHAREDOBJECT']._serialized_end=5726
# @@protoc_insertion_point(module_scope)
