# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: record.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0crecord.proto\x12\x07Records\"\\\n\nRecordType\x12\x14\n\x0crecordTypeId\x18\x01 \x01(\x05\x12\x0f\n\x07\x63ontent\x18\x02 \x01(\t\x12\'\n\x05scope\x18\x03 \x01(\x0e\x32\x18.Records.RecordTypeScope\"H\n\x12RecordTypesRequest\x12\x10\n\x08standard\x18\x01 \x01(\x08\x12\x0c\n\x04user\x18\x02 \x01(\x08\x12\x12\n\nenterprise\x18\x03 \x01(\x08\"\x88\x01\n\x13RecordTypesResponse\x12(\n\x0brecordTypes\x18\x01 \x03(\x0b\x32\x13.Records.RecordType\x12\x17\n\x0fstandardCounter\x18\x02 \x01(\x05\x12\x13\n\x0buserCounter\x18\x03 \x01(\x05\x12\x19\n\x11\x65nterpriseCounter\x18\x04 \x01(\x05\"A\n\x18RecordTypeModifyResponse\x12\x14\n\x0crecordTypeId\x18\x01 \x01(\x05\x12\x0f\n\x07\x63ounter\x18\x02 \x01(\x05\"=\n\x11RecordsGetRequest\x12\x13\n\x0brecord_uids\x18\x01 \x03(\x0c\x12\x13\n\x0b\x63lient_time\x18\x02 \x01(\x03\"\xd1\x01\n\x06Record\x12\x12\n\nrecord_uid\x18\x01 \x01(\x0c\x12\x12\n\nrecord_key\x18\x02 \x01(\x0c\x12/\n\x0frecord_key_type\x18\x03 \x01(\x0e\x32\x16.Records.RecordKeyType\x12\x0c\n\x04\x64\x61ta\x18\x04 \x01(\x0c\x12\r\n\x05\x65xtra\x18\x05 \x01(\x0c\x12\x0f\n\x07version\x18\x06 \x01(\x05\x12\x1c\n\x14\x63lient_modified_time\x18\x07 \x01(\x03\x12\x10\n\x08revision\x18\x08 \x01(\x03\x12\x10\n\x08\x66ile_ids\x18\t \x03(\x0c\"M\n\x0f\x46olderRecordKey\x12\x12\n\nfolder_uid\x18\x01 \x01(\x0c\x12\x12\n\nrecord_uid\x18\x02 \x01(\x0c\x12\x12\n\nrecord_key\x18\x03 \x01(\x0c\"a\n\x06\x46older\x12\x12\n\nfolder_uid\x18\x01 \x01(\x0c\x12\x12\n\nfolder_key\x18\x02 \x01(\x0c\x12/\n\x0f\x66older_key_type\x18\x03 \x01(\x0e\x32\x16.Records.RecordKeyType\"\x95\x01\n\x04Team\x12\x10\n\x08team_uid\x18\x01 \x01(\x0c\x12\x10\n\x08team_key\x18\x02 \x01(\x0c\x12\x18\n\x10team_private_key\x18\x03 \x01(\x0c\x12-\n\rteam_key_type\x18\x04 \x01(\x0e\x32\x16.Records.RecordKeyType\x12 \n\x07\x66olders\x18\x05 \x03(\x0b\x32\x0f.Records.Folder\"\xac\x01\n\x12RecordsGetResponse\x12 \n\x07records\x18\x01 \x03(\x0b\x32\x0f.Records.Record\x12\x34\n\x12\x66older_record_keys\x18\x02 \x03(\x0b\x32\x18.Records.FolderRecordKey\x12 \n\x07\x66olders\x18\x03 \x03(\x0b\x32\x0f.Records.Folder\x12\x1c\n\x05teams\x18\x04 \x03(\x0b\x32\r.Records.Team\"4\n\nRecordLink\x12\x12\n\nrecord_uid\x18\x01 \x01(\x0c\x12\x12\n\nrecord_key\x18\x02 \x01(\x0c\",\n\x0bRecordAudit\x12\x0f\n\x07version\x18\x01 \x01(\x05\x12\x0c\n\x04\x64\x61ta\x18\x02 \x01(\x0c\"\xa0\x02\n\tRecordAdd\x12\x12\n\nrecord_uid\x18\x01 \x01(\x0c\x12\x12\n\nrecord_key\x18\x02 \x01(\x0c\x12\x1c\n\x14\x63lient_modified_time\x18\x03 \x01(\x03\x12\x0c\n\x04\x64\x61ta\x18\x04 \x01(\x0c\x12\x17\n\x0fnon_shared_data\x18\x05 \x01(\x0c\x12.\n\x0b\x66older_type\x18\x06 \x01(\x0e\x32\x19.Records.RecordFolderType\x12\x12\n\nfolder_uid\x18\x07 \x01(\x0c\x12\x12\n\nfolder_key\x18\x08 \x01(\x0c\x12)\n\x0crecord_links\x18\t \x03(\x0b\x32\x13.Records.RecordLink\x12#\n\x05\x61udit\x18\n \x01(\x0b\x32\x14.Records.RecordAudit\"M\n\x11RecordsAddRequest\x12#\n\x07records\x18\x01 \x03(\x0b\x32\x12.Records.RecordAdd\x12\x13\n\x0b\x63lient_time\x18\x02 \x01(\x03\"\xea\x01\n\x0cRecordUpdate\x12\x12\n\nrecord_uid\x18\x01 \x01(\x0c\x12\x1c\n\x14\x63lient_modified_time\x18\x02 \x01(\x03\x12\x10\n\x08revision\x18\x03 \x01(\x03\x12\x0c\n\x04\x64\x61ta\x18\x04 \x01(\x0c\x12\x17\n\x0fnon_shared_data\x18\x05 \x01(\x0c\x12-\n\x10record_links_add\x18\x06 \x03(\x0b\x32\x13.Records.RecordLink\x12\x1b\n\x13record_links_remove\x18\x07 \x03(\x0c\x12#\n\x05\x61udit\x18\x08 \x01(\x0b\x32\x14.Records.RecordAudit\"S\n\x14RecordsUpdateRequest\x12&\n\x07records\x18\x01 \x03(\x0b\x32\x15.Records.RecordUpdate\x12\x13\n\x0b\x63lient_time\x18\x02 \x01(\x03\"\x8e\x01\n\x17RecordFileForConversion\x12\x12\n\nrecord_uid\x18\x01 \x01(\x0c\x12\x14\n\x0c\x66ile_file_id\x18\x02 \x01(\t\x12\x15\n\rthumb_file_id\x18\x03 \x01(\t\x12\x0c\n\x04\x64\x61ta\x18\x04 \x01(\x0c\x12\x12\n\nrecord_key\x18\x05 \x01(\x0c\x12\x10\n\x08link_key\x18\x06 \x01(\x0c\"\x89\x02\n\x11RecordConvertToV3\x12\x12\n\nrecord_uid\x18\x01 \x01(\x0c\x12\x1c\n\x14\x63lient_modified_time\x18\x02 \x01(\x03\x12\x10\n\x08revision\x18\x03 \x01(\x03\x12\x0c\n\x04\x64\x61ta\x18\x04 \x01(\x0c\x12\x17\n\x0fnon_shared_data\x18\x05 \x01(\x0c\x12#\n\x05\x61udit\x18\x06 \x01(\x0b\x32\x14.Records.RecordAudit\x12\x35\n\x0brecord_file\x18\x07 \x03(\x0b\x32 .Records.RecordFileForConversion\x12\x12\n\nfolder_uid\x18\x08 \x01(\x0c\x12\x19\n\x11record_folder_key\x18\t \x01(\x0c\"]\n\x19RecordsConvertToV3Request\x12+\n\x07records\x18\x01 \x03(\x0b\x32\x1a.Records.RecordConvertToV3\x12\x13\n\x0b\x63lient_time\x18\x02 \x01(\x03\"\'\n\x14RecordsRemoveRequest\x12\x0f\n\x07records\x18\x01 \x03(\x0c\"f\n\x12RecordModifyStatus\x12\x12\n\nrecord_uid\x18\x01 \x01(\x0c\x12+\n\x06status\x18\x02 \x01(\x0e\x32\x1b.Records.RecordModifyResult\x12\x0f\n\x07message\x18\x03 \x01(\t\"W\n\x15RecordsModifyResponse\x12,\n\x07records\x18\x01 \x03(\x0b\x32\x1b.Records.RecordModifyStatus\x12\x10\n\x08revision\x18\x02 \x01(\x03\"Y\n\x12RecordAddAuditData\x12\x12\n\nrecord_uid\x18\x01 \x01(\x0c\x12\x10\n\x08revision\x18\x02 \x01(\x03\x12\x0c\n\x04\x64\x61ta\x18\x03 \x01(\x0c\x12\x0f\n\x07version\x18\x04 \x01(\x05\"C\n\x13\x41\x64\x64\x41uditDataRequest\x12,\n\x07records\x18\x01 \x03(\x0b\x32\x1b.Records.RecordAddAuditData\"a\n\x04\x46ile\x12\x12\n\nrecord_uid\x18\x01 \x01(\x0c\x12\x12\n\nrecord_key\x18\x02 \x01(\x0c\x12\x0c\n\x04\x64\x61ta\x18\x03 \x01(\x0c\x12\x10\n\x08\x66ileSize\x18\x04 \x01(\x03\x12\x11\n\tthumbSize\x18\x05 \x01(\x05\"D\n\x0f\x46ilesAddRequest\x12\x1c\n\x05\x66iles\x18\x01 \x03(\x0b\x32\r.Records.File\x12\x13\n\x0b\x63lient_time\x18\x02 \x01(\x03\"\xa7\x01\n\rFileAddStatus\x12\x12\n\nrecord_uid\x18\x01 \x01(\x0c\x12&\n\x06status\x18\x02 \x01(\x0e\x32\x16.Records.FileAddResult\x12\x0b\n\x03url\x18\x03 \x01(\t\x12\x12\n\nparameters\x18\x04 \x01(\t\x12\x1c\n\x14thumbnail_parameters\x18\x05 \x01(\t\x12\x1b\n\x13success_status_code\x18\x06 \x01(\x05\"9\n\x10\x46ilesAddResponse\x12%\n\x05\x66iles\x18\x01 \x03(\x0b\x32\x16.Records.FileAddStatus\"f\n\x0f\x46ilesGetRequest\x12\x13\n\x0brecord_uids\x18\x01 \x03(\x0c\x12\x16\n\x0e\x66or_thumbnails\x18\x02 \x01(\x08\x12&\n\x1e\x65mergency_access_account_owner\x18\x03 \x01(\t\"\xa2\x01\n\rFileGetStatus\x12\x12\n\nrecord_uid\x18\x01 \x01(\x0c\x12&\n\x06status\x18\x02 \x01(\x0e\x32\x16.Records.FileGetResult\x12\x0b\n\x03url\x18\x03 \x01(\t\x12\x1b\n\x13success_status_code\x18\x04 \x01(\x05\x12+\n\x0b\x66ileKeyType\x18\x05 \x01(\x0e\x32\x16.Records.RecordKeyType\"9\n\x10\x46ilesGetResponse\x12%\n\x05\x66iles\x18\x01 \x03(\x0b\x32\x16.Records.FileGetStatus\"h\n\x15\x41pplicationAddRequest\x12\x0f\n\x07\x61pp_uid\x18\x01 \x01(\x0c\x12\x12\n\nrecord_key\x18\x02 \x01(\x0c\x12\x1c\n\x14\x63lient_modified_time\x18\x03 \x01(\x03\x12\x0c\n\x04\x64\x61ta\x18\x04 \x01(\x0c\"\x88\x01\n\"GetRecordDataWithAccessInfoRequest\x12\x12\n\nclientTime\x18\x01 \x01(\x03\x12\x11\n\trecordUid\x18\x02 \x03(\x0c\x12;\n\x14recordDetailsInclude\x18\x03 \x01(\x0e\x32\x1d.Records.RecordDetailsInclude\"\xab\x01\n\x0eUserPermission\x12\x10\n\x08username\x18\x01 \x01(\t\x12\r\n\x05owner\x18\x02 \x01(\x08\x12\x12\n\nshareAdmin\x18\x03 \x01(\x08\x12\x10\n\x08sharable\x18\x04 \x01(\x08\x12\x10\n\x08\x65\x64itable\x18\x05 \x01(\x08\x12\x18\n\x10\x61waitingApproval\x18\x06 \x01(\x08\x12\x12\n\nexpiration\x18\x07 \x01(\x03\x12\x12\n\naccountUid\x18\x08 \x01(\x0c\"}\n\x16SharedFolderPermission\x12\x17\n\x0fsharedFolderUid\x18\x01 \x01(\x0c\x12\x12\n\nresharable\x18\x02 \x01(\x08\x12\x10\n\x08\x65\x64itable\x18\x03 \x01(\x08\x12\x10\n\x08revision\x18\x04 \x01(\x03\x12\x12\n\nexpiration\x18\x05 \x01(\x03\"\x87\x02\n\nRecordData\x12\x10\n\x08revision\x18\x01 \x01(\x03\x12\x0f\n\x07version\x18\x02 \x01(\x05\x12\x0e\n\x06shared\x18\x03 \x01(\x08\x12\x1b\n\x13\x65ncryptedRecordData\x18\x04 \x01(\t\x12\x1a\n\x12\x65ncryptedExtraData\x18\x05 \x01(\t\x12\x1a\n\x12\x63lientModifiedTime\x18\x06 \x01(\x03\x12\x16\n\x0eownerRecordUid\x18\x07 \x01(\x0c\x12 \n\x18\x65ncryptedLinkedRecordKey\x18\x08 \x01(\x0c\x12\x0e\n\x06\x66ileId\x18\t \x03(\x03\x12\x10\n\x08\x66ileSize\x18\n \x01(\x03\x12\x15\n\rthumbnailSize\x18\x0b \x01(\x03\"\xc8\x01\n\x18RecordDataWithAccessInfo\x12\x11\n\trecordUid\x18\x01 \x01(\x0c\x12\'\n\nrecordData\x18\x02 \x01(\x0b\x32\x13.Records.RecordData\x12/\n\x0euserPermission\x18\x03 \x03(\x0b\x32\x17.Records.UserPermission\x12?\n\x16sharedFolderPermission\x18\x04 \x03(\x0b\x32\x1f.Records.SharedFolderPermission\"\x89\x01\n#GetRecordDataWithAccessInfoResponse\x12\x43\n\x18recordDataWithAccessInfo\x18\x01 \x03(\x0b\x32!.Records.RecordDataWithAccessInfo\x12\x1d\n\x15noPermissionRecordUid\x18\x02 \x03(\x0c\"\xbc\x01\n\x18RecordShareUpdateRequest\x12.\n\x0f\x61\x64\x64SharedRecord\x18\x01 \x03(\x0b\x32\x15.Records.SharedRecord\x12\x31\n\x12updateSharedRecord\x18\x02 \x03(\x0b\x32\x15.Records.SharedRecord\x12\x31\n\x12removeSharedRecord\x18\x03 \x03(\x0b\x32\x15.Records.SharedRecord\x12\n\n\x02pt\x18\x04 \x01(\t\"\xd5\x01\n\x0cSharedRecord\x12\x12\n\ntoUsername\x18\x01 \x01(\t\x12\x11\n\trecordUid\x18\x02 \x01(\x0c\x12\x11\n\trecordKey\x18\x03 \x01(\x0c\x12\x17\n\x0fsharedFolderUid\x18\x04 \x01(\x0c\x12\x0f\n\x07teamUid\x18\x05 \x01(\x0c\x12\x10\n\x08\x65\x64itable\x18\x06 \x01(\x08\x12\x11\n\tshareable\x18\x07 \x01(\x08\x12\x10\n\x08transfer\x18\x08 \x01(\x08\x12\x11\n\tuseEccKey\x18\t \x01(\x08\x12\x17\n\x0fremoveVaultData\x18\n \x01(\x08\"\xd5\x01\n\x19RecordShareUpdateResponse\x12:\n\x15\x61\x64\x64SharedRecordStatus\x18\x01 \x03(\x0b\x32\x1b.Records.SharedRecordStatus\x12=\n\x18updateSharedRecordStatus\x18\x02 \x03(\x0b\x32\x1b.Records.SharedRecordStatus\x12=\n\x18removeSharedRecordStatus\x18\x03 \x03(\x0b\x32\x1b.Records.SharedRecordStatus\"Z\n\x12SharedRecordStatus\x12\x11\n\trecordUid\x18\x01 \x01(\x0c\x12\x0e\n\x06status\x18\x02 \x01(\t\x12\x0f\n\x07message\x18\x03 \x01(\t\x12\x10\n\x08username\x18\x04 \x01(\t\"G\n\x1bGetRecordPermissionsRequest\x12\x12\n\nrecordUids\x18\x01 \x03(\x0c\x12\x14\n\x0cisShareAdmin\x18\x02 \x01(\x08\"T\n\x1cGetRecordPermissionsResponse\x12\x34\n\x11recordPermissions\x18\x01 \x03(\x0b\x32\x19.Records.RecordPermission\"l\n\x10RecordPermission\x12\x11\n\trecordUid\x18\x01 \x01(\x0c\x12\r\n\x05owner\x18\x02 \x01(\x08\x12\x0f\n\x07\x63\x61nEdit\x18\x03 \x01(\x08\x12\x10\n\x08\x63\x61nShare\x18\x04 \x01(\x08\x12\x13\n\x0b\x63\x61nTransfer\x18\x05 \x01(\x08\"=\n\x16GetShareObjectsRequest\x12\x11\n\tstartWith\x18\x01 \x01(\t\x12\x10\n\x08\x63ontains\x18\x02 \x01(\t\"\x8e\x02\n\x17GetShareObjectsResponse\x12\x30\n\x12shareRelationships\x18\x01 \x03(\x0b\x32\x14.Records.ShareObject\x12.\n\x10shareFamilyUsers\x18\x02 \x03(\x0b\x32\x14.Records.ShareObject\x12\x32\n\x14shareEnterpriseUsers\x18\x03 \x03(\x0b\x32\x14.Records.ShareObject\x12(\n\nshareTeams\x18\x04 \x03(\x0b\x32\x14.Records.ShareObject\x12\x33\n\x15shareManagedCompanies\x18\x05 \x03(\x0b\x32\x14.Records.ShareObject\"\x8e\x01\n\x0bShareObject\x12\x0c\n\x04name\x18\x01 \x01(\t\x12 \n\x04type\x18\x02 \x01(\x0e\x32\x12.Records.ShareType\x12\x14\n\x0cisShareAdmin\x18\x03 \x01(\x08\x12\x13\n\x0b\x64isplayName\x18\x04 \x01(\t\x12$\n\x06status\x18\x05 \x01(\x0e\x32\x14.Records.ShareStatus*B\n\x0fRecordTypeScope\x12\x0f\n\x0bRT_STANDARD\x10\x00\x12\x0b\n\x07RT_USER\x10\x01\x12\x11\n\rRT_ENTERPRISE\x10\x02*\x93\x01\n\rRecordKeyType\x12\n\n\x06NO_KEY\x10\x00\x12\x19\n\x15\x45NCRYPTED_BY_DATA_KEY\x10\x01\x12\x1b\n\x17\x45NCRYPTED_BY_PUBLIC_KEY\x10\x02\x12\x1d\n\x19\x45NCRYPTED_BY_DATA_KEY_GCM\x10\x03\x12\x1f\n\x1b\x45NCRYPTED_BY_PUBLIC_KEY_ECC\x10\x04*P\n\x10RecordFolderType\x12\x0f\n\x0buser_folder\x10\x00\x12\x11\n\rshared_folder\x10\x01\x12\x18\n\x14shared_folder_folder\x10\x02*\xee\x01\n\x12RecordModifyResult\x12\x0e\n\nRS_SUCCESS\x10\x00\x12\x12\n\x0eRS_OUT_OF_SYNC\x10\x01\x12\x14\n\x10RS_ACCESS_DENIED\x10\x02\x12\x13\n\x0fRS_SHARE_DENIED\x10\x03\x12\x14\n\x10RS_RECORD_EXISTS\x10\x04\x12\x1e\n\x1aRS_OLD_RECORD_VERSION_TYPE\x10\x05\x12\x1e\n\x1aRS_NEW_RECORD_VERSION_TYPE\x10\x06\x12\x16\n\x12RS_FILES_NOT_MATCH\x10\x07\x12\x1b\n\x17RS_RECORD_NOT_SHAREABLE\x10\x08*-\n\rFileAddResult\x12\x0e\n\nFA_SUCCESS\x10\x00\x12\x0c\n\x08\x46\x41_ERROR\x10\x01*C\n\rFileGetResult\x12\x0e\n\nFG_SUCCESS\x10\x00\x12\x0c\n\x08\x46G_ERROR\x10\x01\x12\x14\n\x10\x46G_ACCESS_DENIED\x10\x02*J\n\x14RecordDetailsInclude\x12\x13\n\x0f\x44\x41TA_PLUS_SHARE\x10\x00\x12\r\n\tDATA_ONLY\x10\x01\x12\x0e\n\nSHARE_ONLY\x10\x02*k\n\tShareType\x12\x18\n\x14SHARING_RELATIONSHIP\x10\x00\x12\x13\n\x0f\x45NTERPRISE_USER\x10\x01\x12\x11\n\rFAMILY_MEMBER\x10\x02\x12\x08\n\x04TEAM\x10\x03\x12\x12\n\x0eMANAGE_COMPANY\x10\x04*1\n\x0bShareStatus\x12\n\n\x06\x41\x43TIVE\x10\x00\x12\t\n\x05\x42LOCK\x10\x01\x12\x0b\n\x07INVITED\x10\x02\x42#\n\x18\x63om.keepersecurity.protoB\x07Recordsb\x06proto3')

_RECORDTYPESCOPE = DESCRIPTOR.enum_types_by_name['RecordTypeScope']
RecordTypeScope = enum_type_wrapper.EnumTypeWrapper(_RECORDTYPESCOPE)
_RECORDKEYTYPE = DESCRIPTOR.enum_types_by_name['RecordKeyType']
RecordKeyType = enum_type_wrapper.EnumTypeWrapper(_RECORDKEYTYPE)
_RECORDFOLDERTYPE = DESCRIPTOR.enum_types_by_name['RecordFolderType']
RecordFolderType = enum_type_wrapper.EnumTypeWrapper(_RECORDFOLDERTYPE)
_RECORDMODIFYRESULT = DESCRIPTOR.enum_types_by_name['RecordModifyResult']
RecordModifyResult = enum_type_wrapper.EnumTypeWrapper(_RECORDMODIFYRESULT)
_FILEADDRESULT = DESCRIPTOR.enum_types_by_name['FileAddResult']
FileAddResult = enum_type_wrapper.EnumTypeWrapper(_FILEADDRESULT)
_FILEGETRESULT = DESCRIPTOR.enum_types_by_name['FileGetResult']
FileGetResult = enum_type_wrapper.EnumTypeWrapper(_FILEGETRESULT)
_RECORDDETAILSINCLUDE = DESCRIPTOR.enum_types_by_name['RecordDetailsInclude']
RecordDetailsInclude = enum_type_wrapper.EnumTypeWrapper(_RECORDDETAILSINCLUDE)
_SHARETYPE = DESCRIPTOR.enum_types_by_name['ShareType']
ShareType = enum_type_wrapper.EnumTypeWrapper(_SHARETYPE)
_SHARESTATUS = DESCRIPTOR.enum_types_by_name['ShareStatus']
ShareStatus = enum_type_wrapper.EnumTypeWrapper(_SHARESTATUS)
RT_STANDARD = 0
RT_USER = 1
RT_ENTERPRISE = 2
NO_KEY = 0
ENCRYPTED_BY_DATA_KEY = 1
ENCRYPTED_BY_PUBLIC_KEY = 2
ENCRYPTED_BY_DATA_KEY_GCM = 3
ENCRYPTED_BY_PUBLIC_KEY_ECC = 4
user_folder = 0
shared_folder = 1
shared_folder_folder = 2
RS_SUCCESS = 0
RS_OUT_OF_SYNC = 1
RS_ACCESS_DENIED = 2
RS_SHARE_DENIED = 3
RS_RECORD_EXISTS = 4
RS_OLD_RECORD_VERSION_TYPE = 5
RS_NEW_RECORD_VERSION_TYPE = 6
RS_FILES_NOT_MATCH = 7
RS_RECORD_NOT_SHAREABLE = 8
FA_SUCCESS = 0
FA_ERROR = 1
FG_SUCCESS = 0
FG_ERROR = 1
FG_ACCESS_DENIED = 2
DATA_PLUS_SHARE = 0
DATA_ONLY = 1
SHARE_ONLY = 2
SHARING_RELATIONSHIP = 0
ENTERPRISE_USER = 1
FAMILY_MEMBER = 2
TEAM = 3
MANAGE_COMPANY = 4
ACTIVE = 0
BLOCK = 1
INVITED = 2


_RECORDTYPE = DESCRIPTOR.message_types_by_name['RecordType']
_RECORDTYPESREQUEST = DESCRIPTOR.message_types_by_name['RecordTypesRequest']
_RECORDTYPESRESPONSE = DESCRIPTOR.message_types_by_name['RecordTypesResponse']
_RECORDTYPEMODIFYRESPONSE = DESCRIPTOR.message_types_by_name['RecordTypeModifyResponse']
_RECORDSGETREQUEST = DESCRIPTOR.message_types_by_name['RecordsGetRequest']
_RECORD = DESCRIPTOR.message_types_by_name['Record']
_FOLDERRECORDKEY = DESCRIPTOR.message_types_by_name['FolderRecordKey']
_FOLDER = DESCRIPTOR.message_types_by_name['Folder']
_TEAM = DESCRIPTOR.message_types_by_name['Team']
_RECORDSGETRESPONSE = DESCRIPTOR.message_types_by_name['RecordsGetResponse']
_RECORDLINK = DESCRIPTOR.message_types_by_name['RecordLink']
_RECORDAUDIT = DESCRIPTOR.message_types_by_name['RecordAudit']
_RECORDADD = DESCRIPTOR.message_types_by_name['RecordAdd']
_RECORDSADDREQUEST = DESCRIPTOR.message_types_by_name['RecordsAddRequest']
_RECORDUPDATE = DESCRIPTOR.message_types_by_name['RecordUpdate']
_RECORDSUPDATEREQUEST = DESCRIPTOR.message_types_by_name['RecordsUpdateRequest']
_RECORDFILEFORCONVERSION = DESCRIPTOR.message_types_by_name['RecordFileForConversion']
_RECORDCONVERTTOV3 = DESCRIPTOR.message_types_by_name['RecordConvertToV3']
_RECORDSCONVERTTOV3REQUEST = DESCRIPTOR.message_types_by_name['RecordsConvertToV3Request']
_RECORDSREMOVEREQUEST = DESCRIPTOR.message_types_by_name['RecordsRemoveRequest']
_RECORDMODIFYSTATUS = DESCRIPTOR.message_types_by_name['RecordModifyStatus']
_RECORDSMODIFYRESPONSE = DESCRIPTOR.message_types_by_name['RecordsModifyResponse']
_RECORDADDAUDITDATA = DESCRIPTOR.message_types_by_name['RecordAddAuditData']
_ADDAUDITDATAREQUEST = DESCRIPTOR.message_types_by_name['AddAuditDataRequest']
_FILE = DESCRIPTOR.message_types_by_name['File']
_FILESADDREQUEST = DESCRIPTOR.message_types_by_name['FilesAddRequest']
_FILEADDSTATUS = DESCRIPTOR.message_types_by_name['FileAddStatus']
_FILESADDRESPONSE = DESCRIPTOR.message_types_by_name['FilesAddResponse']
_FILESGETREQUEST = DESCRIPTOR.message_types_by_name['FilesGetRequest']
_FILEGETSTATUS = DESCRIPTOR.message_types_by_name['FileGetStatus']
_FILESGETRESPONSE = DESCRIPTOR.message_types_by_name['FilesGetResponse']
_APPLICATIONADDREQUEST = DESCRIPTOR.message_types_by_name['ApplicationAddRequest']
_GETRECORDDATAWITHACCESSINFOREQUEST = DESCRIPTOR.message_types_by_name['GetRecordDataWithAccessInfoRequest']
_USERPERMISSION = DESCRIPTOR.message_types_by_name['UserPermission']
_SHAREDFOLDERPERMISSION = DESCRIPTOR.message_types_by_name['SharedFolderPermission']
_RECORDDATA = DESCRIPTOR.message_types_by_name['RecordData']
_RECORDDATAWITHACCESSINFO = DESCRIPTOR.message_types_by_name['RecordDataWithAccessInfo']
_GETRECORDDATAWITHACCESSINFORESPONSE = DESCRIPTOR.message_types_by_name['GetRecordDataWithAccessInfoResponse']
_RECORDSHAREUPDATEREQUEST = DESCRIPTOR.message_types_by_name['RecordShareUpdateRequest']
_SHAREDRECORD = DESCRIPTOR.message_types_by_name['SharedRecord']
_RECORDSHAREUPDATERESPONSE = DESCRIPTOR.message_types_by_name['RecordShareUpdateResponse']
_SHAREDRECORDSTATUS = DESCRIPTOR.message_types_by_name['SharedRecordStatus']
_GETRECORDPERMISSIONSREQUEST = DESCRIPTOR.message_types_by_name['GetRecordPermissionsRequest']
_GETRECORDPERMISSIONSRESPONSE = DESCRIPTOR.message_types_by_name['GetRecordPermissionsResponse']
_RECORDPERMISSION = DESCRIPTOR.message_types_by_name['RecordPermission']
_GETSHAREOBJECTSREQUEST = DESCRIPTOR.message_types_by_name['GetShareObjectsRequest']
_GETSHAREOBJECTSRESPONSE = DESCRIPTOR.message_types_by_name['GetShareObjectsResponse']
_SHAREOBJECT = DESCRIPTOR.message_types_by_name['ShareObject']
RecordType = _reflection.GeneratedProtocolMessageType('RecordType', (_message.Message,), {
  'DESCRIPTOR' : _RECORDTYPE,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordType)
  })
_sym_db.RegisterMessage(RecordType)

RecordTypesRequest = _reflection.GeneratedProtocolMessageType('RecordTypesRequest', (_message.Message,), {
  'DESCRIPTOR' : _RECORDTYPESREQUEST,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordTypesRequest)
  })
_sym_db.RegisterMessage(RecordTypesRequest)

RecordTypesResponse = _reflection.GeneratedProtocolMessageType('RecordTypesResponse', (_message.Message,), {
  'DESCRIPTOR' : _RECORDTYPESRESPONSE,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordTypesResponse)
  })
_sym_db.RegisterMessage(RecordTypesResponse)

RecordTypeModifyResponse = _reflection.GeneratedProtocolMessageType('RecordTypeModifyResponse', (_message.Message,), {
  'DESCRIPTOR' : _RECORDTYPEMODIFYRESPONSE,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordTypeModifyResponse)
  })
_sym_db.RegisterMessage(RecordTypeModifyResponse)

RecordsGetRequest = _reflection.GeneratedProtocolMessageType('RecordsGetRequest', (_message.Message,), {
  'DESCRIPTOR' : _RECORDSGETREQUEST,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordsGetRequest)
  })
_sym_db.RegisterMessage(RecordsGetRequest)

Record = _reflection.GeneratedProtocolMessageType('Record', (_message.Message,), {
  'DESCRIPTOR' : _RECORD,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.Record)
  })
_sym_db.RegisterMessage(Record)

FolderRecordKey = _reflection.GeneratedProtocolMessageType('FolderRecordKey', (_message.Message,), {
  'DESCRIPTOR' : _FOLDERRECORDKEY,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.FolderRecordKey)
  })
_sym_db.RegisterMessage(FolderRecordKey)

Folder = _reflection.GeneratedProtocolMessageType('Folder', (_message.Message,), {
  'DESCRIPTOR' : _FOLDER,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.Folder)
  })
_sym_db.RegisterMessage(Folder)

Team = _reflection.GeneratedProtocolMessageType('Team', (_message.Message,), {
  'DESCRIPTOR' : _TEAM,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.Team)
  })
_sym_db.RegisterMessage(Team)

RecordsGetResponse = _reflection.GeneratedProtocolMessageType('RecordsGetResponse', (_message.Message,), {
  'DESCRIPTOR' : _RECORDSGETRESPONSE,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordsGetResponse)
  })
_sym_db.RegisterMessage(RecordsGetResponse)

RecordLink = _reflection.GeneratedProtocolMessageType('RecordLink', (_message.Message,), {
  'DESCRIPTOR' : _RECORDLINK,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordLink)
  })
_sym_db.RegisterMessage(RecordLink)

RecordAudit = _reflection.GeneratedProtocolMessageType('RecordAudit', (_message.Message,), {
  'DESCRIPTOR' : _RECORDAUDIT,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordAudit)
  })
_sym_db.RegisterMessage(RecordAudit)

RecordAdd = _reflection.GeneratedProtocolMessageType('RecordAdd', (_message.Message,), {
  'DESCRIPTOR' : _RECORDADD,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordAdd)
  })
_sym_db.RegisterMessage(RecordAdd)

RecordsAddRequest = _reflection.GeneratedProtocolMessageType('RecordsAddRequest', (_message.Message,), {
  'DESCRIPTOR' : _RECORDSADDREQUEST,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordsAddRequest)
  })
_sym_db.RegisterMessage(RecordsAddRequest)

RecordUpdate = _reflection.GeneratedProtocolMessageType('RecordUpdate', (_message.Message,), {
  'DESCRIPTOR' : _RECORDUPDATE,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordUpdate)
  })
_sym_db.RegisterMessage(RecordUpdate)

RecordsUpdateRequest = _reflection.GeneratedProtocolMessageType('RecordsUpdateRequest', (_message.Message,), {
  'DESCRIPTOR' : _RECORDSUPDATEREQUEST,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordsUpdateRequest)
  })
_sym_db.RegisterMessage(RecordsUpdateRequest)

RecordFileForConversion = _reflection.GeneratedProtocolMessageType('RecordFileForConversion', (_message.Message,), {
  'DESCRIPTOR' : _RECORDFILEFORCONVERSION,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordFileForConversion)
  })
_sym_db.RegisterMessage(RecordFileForConversion)

RecordConvertToV3 = _reflection.GeneratedProtocolMessageType('RecordConvertToV3', (_message.Message,), {
  'DESCRIPTOR' : _RECORDCONVERTTOV3,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordConvertToV3)
  })
_sym_db.RegisterMessage(RecordConvertToV3)

RecordsConvertToV3Request = _reflection.GeneratedProtocolMessageType('RecordsConvertToV3Request', (_message.Message,), {
  'DESCRIPTOR' : _RECORDSCONVERTTOV3REQUEST,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordsConvertToV3Request)
  })
_sym_db.RegisterMessage(RecordsConvertToV3Request)

RecordsRemoveRequest = _reflection.GeneratedProtocolMessageType('RecordsRemoveRequest', (_message.Message,), {
  'DESCRIPTOR' : _RECORDSREMOVEREQUEST,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordsRemoveRequest)
  })
_sym_db.RegisterMessage(RecordsRemoveRequest)

RecordModifyStatus = _reflection.GeneratedProtocolMessageType('RecordModifyStatus', (_message.Message,), {
  'DESCRIPTOR' : _RECORDMODIFYSTATUS,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordModifyStatus)
  })
_sym_db.RegisterMessage(RecordModifyStatus)

RecordsModifyResponse = _reflection.GeneratedProtocolMessageType('RecordsModifyResponse', (_message.Message,), {
  'DESCRIPTOR' : _RECORDSMODIFYRESPONSE,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordsModifyResponse)
  })
_sym_db.RegisterMessage(RecordsModifyResponse)

RecordAddAuditData = _reflection.GeneratedProtocolMessageType('RecordAddAuditData', (_message.Message,), {
  'DESCRIPTOR' : _RECORDADDAUDITDATA,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordAddAuditData)
  })
_sym_db.RegisterMessage(RecordAddAuditData)

AddAuditDataRequest = _reflection.GeneratedProtocolMessageType('AddAuditDataRequest', (_message.Message,), {
  'DESCRIPTOR' : _ADDAUDITDATAREQUEST,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.AddAuditDataRequest)
  })
_sym_db.RegisterMessage(AddAuditDataRequest)

File = _reflection.GeneratedProtocolMessageType('File', (_message.Message,), {
  'DESCRIPTOR' : _FILE,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.File)
  })
_sym_db.RegisterMessage(File)

FilesAddRequest = _reflection.GeneratedProtocolMessageType('FilesAddRequest', (_message.Message,), {
  'DESCRIPTOR' : _FILESADDREQUEST,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.FilesAddRequest)
  })
_sym_db.RegisterMessage(FilesAddRequest)

FileAddStatus = _reflection.GeneratedProtocolMessageType('FileAddStatus', (_message.Message,), {
  'DESCRIPTOR' : _FILEADDSTATUS,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.FileAddStatus)
  })
_sym_db.RegisterMessage(FileAddStatus)

FilesAddResponse = _reflection.GeneratedProtocolMessageType('FilesAddResponse', (_message.Message,), {
  'DESCRIPTOR' : _FILESADDRESPONSE,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.FilesAddResponse)
  })
_sym_db.RegisterMessage(FilesAddResponse)

FilesGetRequest = _reflection.GeneratedProtocolMessageType('FilesGetRequest', (_message.Message,), {
  'DESCRIPTOR' : _FILESGETREQUEST,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.FilesGetRequest)
  })
_sym_db.RegisterMessage(FilesGetRequest)

FileGetStatus = _reflection.GeneratedProtocolMessageType('FileGetStatus', (_message.Message,), {
  'DESCRIPTOR' : _FILEGETSTATUS,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.FileGetStatus)
  })
_sym_db.RegisterMessage(FileGetStatus)

FilesGetResponse = _reflection.GeneratedProtocolMessageType('FilesGetResponse', (_message.Message,), {
  'DESCRIPTOR' : _FILESGETRESPONSE,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.FilesGetResponse)
  })
_sym_db.RegisterMessage(FilesGetResponse)

ApplicationAddRequest = _reflection.GeneratedProtocolMessageType('ApplicationAddRequest', (_message.Message,), {
  'DESCRIPTOR' : _APPLICATIONADDREQUEST,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.ApplicationAddRequest)
  })
_sym_db.RegisterMessage(ApplicationAddRequest)

GetRecordDataWithAccessInfoRequest = _reflection.GeneratedProtocolMessageType('GetRecordDataWithAccessInfoRequest', (_message.Message,), {
  'DESCRIPTOR' : _GETRECORDDATAWITHACCESSINFOREQUEST,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.GetRecordDataWithAccessInfoRequest)
  })
_sym_db.RegisterMessage(GetRecordDataWithAccessInfoRequest)

UserPermission = _reflection.GeneratedProtocolMessageType('UserPermission', (_message.Message,), {
  'DESCRIPTOR' : _USERPERMISSION,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.UserPermission)
  })
_sym_db.RegisterMessage(UserPermission)

SharedFolderPermission = _reflection.GeneratedProtocolMessageType('SharedFolderPermission', (_message.Message,), {
  'DESCRIPTOR' : _SHAREDFOLDERPERMISSION,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.SharedFolderPermission)
  })
_sym_db.RegisterMessage(SharedFolderPermission)

RecordData = _reflection.GeneratedProtocolMessageType('RecordData', (_message.Message,), {
  'DESCRIPTOR' : _RECORDDATA,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordData)
  })
_sym_db.RegisterMessage(RecordData)

RecordDataWithAccessInfo = _reflection.GeneratedProtocolMessageType('RecordDataWithAccessInfo', (_message.Message,), {
  'DESCRIPTOR' : _RECORDDATAWITHACCESSINFO,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordDataWithAccessInfo)
  })
_sym_db.RegisterMessage(RecordDataWithAccessInfo)

GetRecordDataWithAccessInfoResponse = _reflection.GeneratedProtocolMessageType('GetRecordDataWithAccessInfoResponse', (_message.Message,), {
  'DESCRIPTOR' : _GETRECORDDATAWITHACCESSINFORESPONSE,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.GetRecordDataWithAccessInfoResponse)
  })
_sym_db.RegisterMessage(GetRecordDataWithAccessInfoResponse)

RecordShareUpdateRequest = _reflection.GeneratedProtocolMessageType('RecordShareUpdateRequest', (_message.Message,), {
  'DESCRIPTOR' : _RECORDSHAREUPDATEREQUEST,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordShareUpdateRequest)
  })
_sym_db.RegisterMessage(RecordShareUpdateRequest)

SharedRecord = _reflection.GeneratedProtocolMessageType('SharedRecord', (_message.Message,), {
  'DESCRIPTOR' : _SHAREDRECORD,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.SharedRecord)
  })
_sym_db.RegisterMessage(SharedRecord)

RecordShareUpdateResponse = _reflection.GeneratedProtocolMessageType('RecordShareUpdateResponse', (_message.Message,), {
  'DESCRIPTOR' : _RECORDSHAREUPDATERESPONSE,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordShareUpdateResponse)
  })
_sym_db.RegisterMessage(RecordShareUpdateResponse)

SharedRecordStatus = _reflection.GeneratedProtocolMessageType('SharedRecordStatus', (_message.Message,), {
  'DESCRIPTOR' : _SHAREDRECORDSTATUS,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.SharedRecordStatus)
  })
_sym_db.RegisterMessage(SharedRecordStatus)

GetRecordPermissionsRequest = _reflection.GeneratedProtocolMessageType('GetRecordPermissionsRequest', (_message.Message,), {
  'DESCRIPTOR' : _GETRECORDPERMISSIONSREQUEST,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.GetRecordPermissionsRequest)
  })
_sym_db.RegisterMessage(GetRecordPermissionsRequest)

GetRecordPermissionsResponse = _reflection.GeneratedProtocolMessageType('GetRecordPermissionsResponse', (_message.Message,), {
  'DESCRIPTOR' : _GETRECORDPERMISSIONSRESPONSE,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.GetRecordPermissionsResponse)
  })
_sym_db.RegisterMessage(GetRecordPermissionsResponse)

RecordPermission = _reflection.GeneratedProtocolMessageType('RecordPermission', (_message.Message,), {
  'DESCRIPTOR' : _RECORDPERMISSION,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.RecordPermission)
  })
_sym_db.RegisterMessage(RecordPermission)

GetShareObjectsRequest = _reflection.GeneratedProtocolMessageType('GetShareObjectsRequest', (_message.Message,), {
  'DESCRIPTOR' : _GETSHAREOBJECTSREQUEST,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.GetShareObjectsRequest)
  })
_sym_db.RegisterMessage(GetShareObjectsRequest)

GetShareObjectsResponse = _reflection.GeneratedProtocolMessageType('GetShareObjectsResponse', (_message.Message,), {
  'DESCRIPTOR' : _GETSHAREOBJECTSRESPONSE,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.GetShareObjectsResponse)
  })
_sym_db.RegisterMessage(GetShareObjectsResponse)

ShareObject = _reflection.GeneratedProtocolMessageType('ShareObject', (_message.Message,), {
  'DESCRIPTOR' : _SHAREOBJECT,
  '__module__' : 'record_pb2'
  # @@protoc_insertion_point(class_scope:Records.ShareObject)
  })
_sym_db.RegisterMessage(ShareObject)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'\n\030com.keepersecurity.protoB\007Records'
  _RECORDTYPESCOPE._serialized_start=6219
  _RECORDTYPESCOPE._serialized_end=6285
  _RECORDKEYTYPE._serialized_start=6288
  _RECORDKEYTYPE._serialized_end=6435
  _RECORDFOLDERTYPE._serialized_start=6437
  _RECORDFOLDERTYPE._serialized_end=6517
  _RECORDMODIFYRESULT._serialized_start=6520
  _RECORDMODIFYRESULT._serialized_end=6758
  _FILEADDRESULT._serialized_start=6760
  _FILEADDRESULT._serialized_end=6805
  _FILEGETRESULT._serialized_start=6807
  _FILEGETRESULT._serialized_end=6874
  _RECORDDETAILSINCLUDE._serialized_start=6876
  _RECORDDETAILSINCLUDE._serialized_end=6950
  _SHARETYPE._serialized_start=6952
  _SHARETYPE._serialized_end=7059
  _SHARESTATUS._serialized_start=7061
  _SHARESTATUS._serialized_end=7110
  _RECORDTYPE._serialized_start=25
  _RECORDTYPE._serialized_end=117
  _RECORDTYPESREQUEST._serialized_start=119
  _RECORDTYPESREQUEST._serialized_end=191
  _RECORDTYPESRESPONSE._serialized_start=194
  _RECORDTYPESRESPONSE._serialized_end=330
  _RECORDTYPEMODIFYRESPONSE._serialized_start=332
  _RECORDTYPEMODIFYRESPONSE._serialized_end=397
  _RECORDSGETREQUEST._serialized_start=399
  _RECORDSGETREQUEST._serialized_end=460
  _RECORD._serialized_start=463
  _RECORD._serialized_end=672
  _FOLDERRECORDKEY._serialized_start=674
  _FOLDERRECORDKEY._serialized_end=751
  _FOLDER._serialized_start=753
  _FOLDER._serialized_end=850
  _TEAM._serialized_start=853
  _TEAM._serialized_end=1002
  _RECORDSGETRESPONSE._serialized_start=1005
  _RECORDSGETRESPONSE._serialized_end=1177
  _RECORDLINK._serialized_start=1179
  _RECORDLINK._serialized_end=1231
  _RECORDAUDIT._serialized_start=1233
  _RECORDAUDIT._serialized_end=1277
  _RECORDADD._serialized_start=1280
  _RECORDADD._serialized_end=1568
  _RECORDSADDREQUEST._serialized_start=1570
  _RECORDSADDREQUEST._serialized_end=1647
  _RECORDUPDATE._serialized_start=1650
  _RECORDUPDATE._serialized_end=1884
  _RECORDSUPDATEREQUEST._serialized_start=1886
  _RECORDSUPDATEREQUEST._serialized_end=1969
  _RECORDFILEFORCONVERSION._serialized_start=1972
  _RECORDFILEFORCONVERSION._serialized_end=2114
  _RECORDCONVERTTOV3._serialized_start=2117
  _RECORDCONVERTTOV3._serialized_end=2382
  _RECORDSCONVERTTOV3REQUEST._serialized_start=2384
  _RECORDSCONVERTTOV3REQUEST._serialized_end=2477
  _RECORDSREMOVEREQUEST._serialized_start=2479
  _RECORDSREMOVEREQUEST._serialized_end=2518
  _RECORDMODIFYSTATUS._serialized_start=2520
  _RECORDMODIFYSTATUS._serialized_end=2622
  _RECORDSMODIFYRESPONSE._serialized_start=2624
  _RECORDSMODIFYRESPONSE._serialized_end=2711
  _RECORDADDAUDITDATA._serialized_start=2713
  _RECORDADDAUDITDATA._serialized_end=2802
  _ADDAUDITDATAREQUEST._serialized_start=2804
  _ADDAUDITDATAREQUEST._serialized_end=2871
  _FILE._serialized_start=2873
  _FILE._serialized_end=2970
  _FILESADDREQUEST._serialized_start=2972
  _FILESADDREQUEST._serialized_end=3040
  _FILEADDSTATUS._serialized_start=3043
  _FILEADDSTATUS._serialized_end=3210
  _FILESADDRESPONSE._serialized_start=3212
  _FILESADDRESPONSE._serialized_end=3269
  _FILESGETREQUEST._serialized_start=3271
  _FILESGETREQUEST._serialized_end=3373
  _FILEGETSTATUS._serialized_start=3376
  _FILEGETSTATUS._serialized_end=3538
  _FILESGETRESPONSE._serialized_start=3540
  _FILESGETRESPONSE._serialized_end=3597
  _APPLICATIONADDREQUEST._serialized_start=3599
  _APPLICATIONADDREQUEST._serialized_end=3703
  _GETRECORDDATAWITHACCESSINFOREQUEST._serialized_start=3706
  _GETRECORDDATAWITHACCESSINFOREQUEST._serialized_end=3842
  _USERPERMISSION._serialized_start=3845
  _USERPERMISSION._serialized_end=4016
  _SHAREDFOLDERPERMISSION._serialized_start=4018
  _SHAREDFOLDERPERMISSION._serialized_end=4143
  _RECORDDATA._serialized_start=4146
  _RECORDDATA._serialized_end=4409
  _RECORDDATAWITHACCESSINFO._serialized_start=4412
  _RECORDDATAWITHACCESSINFO._serialized_end=4612
  _GETRECORDDATAWITHACCESSINFORESPONSE._serialized_start=4615
  _GETRECORDDATAWITHACCESSINFORESPONSE._serialized_end=4752
  _RECORDSHAREUPDATEREQUEST._serialized_start=4755
  _RECORDSHAREUPDATEREQUEST._serialized_end=4943
  _SHAREDRECORD._serialized_start=4946
  _SHAREDRECORD._serialized_end=5159
  _RECORDSHAREUPDATERESPONSE._serialized_start=5162
  _RECORDSHAREUPDATERESPONSE._serialized_end=5375
  _SHAREDRECORDSTATUS._serialized_start=5377
  _SHAREDRECORDSTATUS._serialized_end=5467
  _GETRECORDPERMISSIONSREQUEST._serialized_start=5469
  _GETRECORDPERMISSIONSREQUEST._serialized_end=5540
  _GETRECORDPERMISSIONSRESPONSE._serialized_start=5542
  _GETRECORDPERMISSIONSRESPONSE._serialized_end=5626
  _RECORDPERMISSION._serialized_start=5628
  _RECORDPERMISSION._serialized_end=5736
  _GETSHAREOBJECTSREQUEST._serialized_start=5738
  _GETSHAREOBJECTSREQUEST._serialized_end=5799
  _GETSHAREOBJECTSRESPONSE._serialized_start=5802
  _GETSHAREOBJECTSRESPONSE._serialized_end=6072
  _SHAREOBJECT._serialized_start=6075
  _SHAREOBJECT._serialized_end=6217
# @@protoc_insertion_point(module_scope)
