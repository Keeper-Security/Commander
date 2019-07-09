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
using System.Runtime.Serialization;
using Org.BouncyCastle.Crypto.Parameters;

namespace KeeperSecurity.Sdk
{
    [DataContract]
    internal class SyncDownCommand : AuthorizedCommand
    {
        public SyncDownCommand() : base("sync_down")
        {
            clientTime = DateTimeOffset.Now.ToUnixTimeMilliseconds();
        }

        [DataMember(Name = "revision")]
        public long revision;

        [DataMember(Name = "include")]
        public string[] include;

        [DataMember(Name = "device_name")]
        public string deviceName;

        [DataMember(Name = "client_time")]
        public long clientTime;
    }

#pragma warning disable 0649
    [DataContract]
    internal class SyncDownResponse : KeeperApiResponse
    {
        [DataMember(Name = "full_sync")]
        internal bool fullSync;

        [DataMember(Name = "revision")]
        public long revision;

        [DataMember(Name = "records")]
        public SyncDownRecord[] records;

        [DataMember(Name = "shared_folders")]
        public SyncDownSharedFolder[] sharedFolders;

        [DataMember(Name = "teams")]
        public SyncDownTeam[] teams;

        [DataMember(Name = "record_meta_data")]
        public SyncDownRecordMetaData[] recordMetaData;

        [DataMember(Name = "pending_shares_from")]
        public string[] pendingSharesFrom;

        [DataMember(Name = "sharing_changes")]
        public SyncDownSharingChanges[] sharingChanges;

        [DataMember(Name = "removed_shared_folders")]
        public string[] removedSharedFolders;

        [DataMember(Name = "removed_records")]
        public string[] removedRecords;

        [DataMember(Name = "removed_teams")]
        public string[] removedTeams;

        [DataMember(Name = "user_folders")]
        public SyncDownUserFolder[] userFolders;

        [DataMember(Name = "user_folder_records")]
        public SyncDownFolderRecord[] userFolderRecords;

        [DataMember(Name = "user_folders_removed")]
        public SyncDownFolderNode[] userFoldersRemoved;

        [DataMember(Name = "user_folders_removed_records")]
        public SyncDownFolderRecordNode[] userFoldersRemovedRecords;

        [DataMember(Name = "user_folder_shared_folders")]
        public SyncDownUserFolderSharedFolder[] userFolderSharedFolders;

        [DataMember(Name = "user_folder_shared_folders_removed")]
        public SyncDownUserFolderSharedFolder[] userFolderSharedFoldersRemoved;

        [DataMember(Name = "shared_folder_folders")]
        public SyncDownSharedFolderFolder[] sharedFolderFolders;

        [DataMember(Name = "shared_folder_folder_removed")]
        public SyncDownSharedFolderFolderNode[] sharedFolderFolderRemoved;

        [DataMember(Name = "shared_folder_folder_records")]
        public SyncDownSharedFolderFolderRecordNode[] sharedFolderFolderRecords;

        [DataMember(Name = "shared_folder_folder_records_removed")]
        public SyncDownSharedFolderFolderRecordNode[] sharedFolderFolderRecordsRemoved;
    }

    [DataContract]
    internal class SyncDownRecordUData : IExtensibleDataObject
    {
        [DataMember(Name = "file_ids")]
        public string[] fileIds;
        public ExtensionDataObject ExtensionData { get; set; }
    }

    [DataContract]
    internal class SyncDownRecord
    {
        [DataMember(Name = "record_uid")]
        public string recordUid;

        [DataMember(Name = "revision")]
        public long revision;

        [DataMember(Name = "version")]
        public long version;

        [DataMember(Name = "shared")]
        public bool shared;

        [DataMember(Name = "client_modified_time")]
        public long clientModifiedTime;

        [DataMember(Name = "data")]
        public string data;

        [DataMember(Name = "extra")]
        public string extra;

        [DataMember(Name = "udata")]
        public SyncDownRecordUData udata;

        internal byte[] unencryptedRecordKey;
    }

    [DataContract]
    internal class SyncDownSharedFolder
    {
        [DataMember(Name = "shared_folder_uid")]
        public string sharedFolderUid;

        [DataMember(Name = "revision")]
        public long revision;

        [DataMember(Name = "shared_folder_key")]
        public string sharedFolderKey;

        [DataMember(Name = "key_type")]
        public int? keyType;

        [DataMember(Name = "name")]
        public string name;

        [DataMember(Name = "full_sync")]
        public bool? fullSync;

        [DataMember(Name = "manage_records")]
        public bool? manageRecords;

        [DataMember(Name = "manage_users")]
        public bool? manageUsers;

        [DataMember(Name = "default_manage_records")]
        public bool defaultManageRecords;

        [DataMember(Name = "default_manage_users")]
        public bool defaultManageUsers;

        [DataMember(Name = "default_can_edit")]
        public bool defaultCanEdit;

        [DataMember(Name = "default_can_share")]
        public bool defaultCanShare;

        [DataMember(Name = "records")]
        public SyncDownSharedFolderRecord[] records;

        [DataMember(Name = "users")]
        public SyncDownSharedFolderUser[] users;

        [DataMember(Name = "teams")]
        public SyncDownSharedFolderTeam[] teams;

        [DataMember(Name = "records_removed")]
        public string[] recordsRemoved;

        [DataMember(Name = "users_removed")]
        public string[] usersRemoved;

        [DataMember(Name = "teams_removed")]
        public string[] teamsRemoved;

        internal byte[] unencryptedSharedFolderKey;
    }

    [DataContract]
    internal class SyncDownTeam
    {
        [DataMember(Name = "team_uid")]
        public string teamUid;

        [DataMember(Name = "name")]
        public string name;

        [DataMember(Name = "team_key")]
        public string teamKey;

        [DataMember(Name = "team_key_type")]
        public int teamKeyType;

        [DataMember(Name = "team_private_key")]
        public string teamPrivateKey;

        [DataMember(Name = "restrict_edit")]
        public bool restrictEdit;

        [DataMember(Name = "restrict_share")]
        public bool restrictShare;

        [DataMember(Name = "restrict_view")]
        public bool restrictView;

        [DataMember(Name = "removed_shared_folders")]
        public string[] removedSharedFolders;

        [DataMember(Name = "shared_folder_keys")]
        public SharedFolderKey[] sharedFolderKeys;

        internal byte[] unencryptedTeamKey;
        internal RsaPrivateCrtKeyParameters privateKey;
        internal RsaPrivateCrtKeyParameters PrivateKey
        {
            get
            {
                if (privateKey == null && unencryptedTeamKey != null)
                {
                    var unencryptedPrivateKey = CryptoUtils.DecryptAesV1(teamPrivateKey.Base64UrlDecode(), unencryptedTeamKey);
                    privateKey = unencryptedPrivateKey.LoadPrivateKey();
                }
                return privateKey;
            }
        }
    }

    [DataContract]
    internal class SyncDownSharedFolderRecord
    {
        [DataMember(Name = "record_uid")]
        public string recordUid;

        [DataMember(Name = "record_key")]
        public string recordKey;

        [DataMember(Name = "can_share")]
        public bool canShare;

        [DataMember(Name = "can_edit")]
        public bool canEdit;
    }

    [DataContract]
    internal class SyncDownSharedFolderTeam
    {
        [DataMember(Name = "team_uid")]
        public string teamUid;

        [DataMember(Name = "name")]
        public string name;

        [DataMember(Name = "manage_records")]
        public bool manageRecords;

        [DataMember(Name = "manage_users")]
        public bool manageUsers;
    }

    [DataContract]
    internal class SharedFolderKey
    {
        [DataMember(Name = "shared_folder_uid")]
        public string sharedFolderUid;

        [DataMember(Name = "shared_folder_key")]
        public string sharedFolderKey;

        [DataMember(Name = "key_type")]
        public int keyType;
    }


    [DataContract]
    internal class SyncDownSharedFolderUser
    {
        [DataMember(Name = "username")]
        public string username;

        [DataMember(Name = "manage_records")]
        public bool manageRecords;

        [DataMember(Name = "manage_users")]
        public bool manageUsers;
    }

    [DataContract]
    internal class SyncDownRecordMetaData
    {
        [DataMember(Name = "record_uid")]
        public string recordUid;

        [DataMember(Name = "owner")]
        public bool owner;

        [DataMember(Name = "record_key")]
        public string recordKey;

        [DataMember(Name = "record_key_type")]
        public int recordKeyType;

        [DataMember(Name = "can_share")]
        public bool canShare;

        [DataMember(Name = "can_edit")]
        public bool canEdit;
    }

    public enum FolderType { UserFolder, SharedFolder, SharedFolderForder }

    public interface IFolderNode
    {
        string ParentUid { get; }
        string FolderUid { get; }
        FolderType Type { get; }
    }

    public interface ISharedFolderNode
    {
        string SharedFolderUid { get; }
    }

    public interface IRecordNode
    {
        string FolderUid { get; }
        string RecordUid { get; }
    }

    [DataContract]
    internal class SyncDownFolderNode
    {
        [DataMember(Name = "folder_uid")]
        public string folderUid;
    }

    [DataContract]
    internal class SyncDownSharedFolderFolderNode
    {
        [DataMember(Name = "folder_uid")]
        public string folderUid;

        [DataMember(Name = "parent_uid")]
        public string parentUid;

        [DataMember(Name = "shared_folder_uid")]
        public string sharedFolderUid;
    }

    [DataContract]
    internal class SyncDownFolderRecordNode : IRecordNode
    {
        [DataMember(Name = "folder_uid")]
        public string folderUid;

        [DataMember(Name = "record_uid")]
        public string recordUid;

        public string FolderUid => folderUid;
        public string RecordUid => recordUid;
    }

    [DataContract]
    internal class SyncDownSharedFolderFolderRecordNode : IRecordNode
    {
        [DataMember(Name = "folder_uid")]
        public string folderUid;

        [DataMember(Name = "record_uid")]
        public string recordUid;

        [DataMember(Name = "shared_folder_uid")]
        public string sharedFolderUid;

        public string FolderUid => folderUid ?? sharedFolderUid;
        public string RecordUid => recordUid;
    }

    [DataContract]
    internal class SyncDownFolderRecord : IRecordNode
    {
        [DataMember(Name = "folder_uid")]
        public string folderUid;
        [DataMember(Name = "record_uid")]
        public string recordUid;
        [DataMember(Name = "revision")]
        public long revision;

        public string FolderUid => folderUid;
        public string RecordUid => recordUid;
    }

    [DataContract]
    internal class SyncDownUserFolder : IFolderNode
    {
        [DataMember(Name = "folder_uid")]
        public string folderUid;

        [DataMember(Name = "parent_uid")]
        public string parentUid;

        [DataMember(Name = "user_folder_key")]
        public string userFolderKey;

        [DataMember(Name = "key_type")]
        public int keyType;

        [DataMember(Name = "revision")]
        public long revision;

        [DataMember(Name = "type")]
        public string type;

        [DataMember(Name = "data")]
        public string data;

        internal byte[] unencryptedFolderKey;

        public string ParentUid => parentUid;
        public string FolderUid => folderUid;
        public FolderType Type => FolderType.UserFolder;
    }

    [DataContract]
    internal class SyncDownSharedFolderFolder : SyncDownSharedFolderFolderNode, IFolderNode, ISharedFolderNode
    {
        [DataMember(Name = "shared_folder_folder_key")]
        public string sharedFolderFolderKey;

        [DataMember(Name = "revision")]
        public long revision;

        [DataMember(Name = "type")]
        public string type;

        [DataMember(Name = "data")]
        public string data;

        internal byte[] unencryptedFolderKey;
        public string ParentUid => parentUid;
        public string FolderUid => folderUid;
        public FolderType Type => FolderType.SharedFolderForder;
        public string SharedFolderUid => sharedFolderUid;
    }

    [DataContract]
    internal class SyncDownUserFolderSharedFolder : IFolderNode, ISharedFolderNode
    {
        [DataMember(Name = "folder_uid")]
        public string folderUid;

        [DataMember(Name = "shared_folder_uid")]
        public string sharedFolderUid;

        public string ParentUid => folderUid;
        public string FolderUid => sharedFolderUid;
        public FolderType Type => FolderType.SharedFolder;
        public string SharedFolderUid => sharedFolderUid;
    }

    [DataContract]
    internal class SyncDownSharingChanges
    {
        [DataMember(Name = "record_uid")]
        public string recordUid;

        [DataMember(Name = "shared")]
        public bool shared;
    }

    [DataContract]
    internal class FolderData
    {
        [DataMember(Name = "name")]
        public string name;
    }

#pragma warning restore 0649

#pragma warning disable 0649
    [DataContract]
    internal class RecordDataCustom
    {
        [DataMember(Name = "name")]
        public string name = "";

        [DataMember(Name = "value")]
        public string value = "";

        [DataMember(Name = "type", EmitDefaultValue = false)]
        public string type;
    }

    [DataContract]
    internal class RecordData
    {
        [DataMember(Name = "title")]
        public string title = "";

        [DataMember(Name = "folder")]
        public string folder = "";

        [DataMember(Name = "secret1")]
        public string secret1 = "";

        [DataMember(Name = "secret2")]
        public string secret2 = "";

        [DataMember(Name = "link")]
        public string link = "";

        [DataMember(Name = "notes")]
        public string notes = "";

        [DataMember(Name = "custom", EmitDefaultValue = false)]
        public RecordDataCustom[] custom;
    }

    [DataContract]
    internal class RecordExtraFileThumb
    {
        [DataMember(Name = "id")]
        public string id = "";

        [DataMember(Name = "type")]
        public string type = "";

        [DataMember(Name = "size")]
        public int? size;
    }

    [DataContract]
    internal class RecordExtraFile
    {
        [DataMember(Name = "id")]
        public string id = "";

        [DataMember(Name = "name")]
        public string name = "";

        [DataMember(Name = "key")]
        public string key;

        [DataMember(Name = "size", EmitDefaultValue = false)]
        public long? size;

        [DataMember(Name = "title", EmitDefaultValue = false)]
        public string title;

        [DataMember(Name = "type", EmitDefaultValue = false)]
        public string type;

        [DataMember(Name = "lastModified", EmitDefaultValue = false)]
        public long? lastModified;

        [DataMember(Name = "thumbs")]
        public RecordExtraFileThumb[] thumbs;
    }

    [DataContract]
    internal class RecordExtra : IExtensibleDataObject
    {
        [DataMember(Name = "files", EmitDefaultValue = false)]
        public RecordExtraFile[] files;

        public ExtensionDataObject ExtensionData { get; set; }
    }
#pragma warning restore 0649


}
