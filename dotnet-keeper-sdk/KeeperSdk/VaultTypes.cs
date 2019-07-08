//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2019 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Text;
using KeeperSecurity.Sdk;

namespace KeeperSecurity.Sdk
{
    public interface IRecordAccessPath
    {
        string RecordUid { get; }
        string SharedFolderUid { get; set; }
        string TeamUid { get; set; }
    }

    [DataContract]
    internal class RecordUpdateUData : IExtensibleDataObject
    {
        [DataMember(Name = "file_ids", EmitDefaultValue = false)]
        public string[] fileIds;
        public ExtensionDataObject ExtensionData { get; set; }
    }

    [DataContract]
    internal class RecordUpdateRecord : IRecordAccessPath
    {
        [DataMember(Name = "record_uid")]
        public string recordUid;

        [DataMember(Name = "record_key", EmitDefaultValue = false)]
        public string recordKey;

        [DataMember(Name = "data", EmitDefaultValue = false)]
        public string data;

        [DataMember(Name = "extra", EmitDefaultValue = false)]
        public string extra;

        [DataMember(Name = "udata", EmitDefaultValue = false)]
        public RecordUpdateUData udata;

        [DataMember(Name = "revision")]
        public long revision;

        [DataMember(Name = "version")]
        public long version = 2;

        [DataMember(Name = "client_modified_time")]
        public long clientModifiedTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        public string RecordUid { get => recordUid; }
        [DataMember(Name = "shared_folder_uid", EmitDefaultValue = false)]
        public string SharedFolderUid { get; set; }
        [DataMember(Name = "team_uid", EmitDefaultValue = false)]
        public string TeamUid { get; set; }
    }

#pragma warning disable 0649
    [DataContract]
    internal class RecordUpdateCommand : AuthorizedCommand
    {
        public RecordUpdateCommand() : base("record_update") { }

        [DataMember(Name = "pt")]
        public string pt = DateTime.Now.Ticks.ToString("x");

        [DataMember(Name = "client_time")]
        public long clientTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        [DataMember(Name = "add_records", EmitDefaultValue = false)]
        public RecordUpdateRecord[] addRecords;

        [DataMember(Name = "update_records", EmitDefaultValue = false)]
        public RecordUpdateRecord[] updateRecords;

        [DataMember(Name = "remove_records", EmitDefaultValue = false)]
        public string[] removeRecords;

        [DataMember(Name = "delete_records", EmitDefaultValue = false)]
        public string[] deleteRecords;
    }

    [DataContract]
    internal class RecordUpdateStatus
    {
        [DataMember(Name = "record_uid")]
        public string recordUid;

        [DataMember(Name = "status_code")]
        public string statusCode;
    }

    [DataContract]
    internal class RecordUpdateResponse : KeeperApiResponse
    {
        [DataMember(Name = "add_records")]
        public RecordUpdateStatus[] addRecords;

        [DataMember(Name = "update_records")]
        public RecordUpdateRecord[] updateRecords;

        [DataMember(Name = "remove_records")]
        public RecordUpdateStatus[] removeRecords;

        [DataMember(Name = "delete_records")]
        public RecordUpdateStatus[] deleteRecords;

        [DataMember(Name = "revision")]
        public long revision;
    }

    [DataContract]
    internal class RecordAddCommand : AuthorizedCommand
    {
        public RecordAddCommand() : base("record_add") { }

        [DataMember(Name = "record_uid")]
        public string recordUid;

        [DataMember(Name = "record_key")]
        public string recordKey;

        [DataMember(Name = "record_type")]
        public string recordType;  // password
        
        [DataMember(Name = "folder_type")] // one of: user_folder, shared_folder, shared_folder_folder
        public string folderType;

        [DataMember(Name = "how_long_ago")]
        public int howLongAgo = 0;

        [DataMember(Name = "folder_uid", EmitDefaultValue = false)]
        public string folderUid;

        [DataMember(Name = "folder_key", EmitDefaultValue = false)]
        public string folderKey;

        [DataMember(Name = "data")]
        public string data;

        [DataMember(Name = "extra", EmitDefaultValue = false)]
        public string extra;

        [DataMember(Name = "non_shared_data", EmitDefaultValue = false)]
        public string nonSharedData;

        [DataMember(Name = "file_ids", EmitDefaultValue = false)]
        public string[] fileIds;
    }

#pragma warning restore 0649
}
