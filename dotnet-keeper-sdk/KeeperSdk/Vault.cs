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
using System.Collections.Concurrent;
using System.Linq;
using System.Threading.Tasks;
using System.Runtime.Serialization.Json;
using System.IO;
using System.Diagnostics;
using System.Text;

namespace KeeperSecurity.Sdk
{
    public class PasswordRecord
    {
        public PasswordRecord() { }
        public PasswordRecord(string uid)
        {
            Uid = uid;
        }
        public string Uid { get; }
        public string Title { get; set; }
        public string Login { get; set; }
        public string Password { get; set; }
        public string Link { get; set; }
        public string Notes { get; set; }
        public IList<CustomField> Custom { get; } = new List<CustomField>();
        public IList<AttachmentFile> Attachments { get; } = new List<AttachmentFile>();
    }

    public class CustomField
    {
        public string Name { get; set; }
        public string Value { get; set; }
        public string Type { get; set; }
    }

    public class AttachmentFileThumb
    {

        public string Id { get; internal set; }
        public string Type { get; internal set; }
        public int Size { get; internal set; }
    }

    public class AttachmentFile
    {
        public string Id { get; internal set; }
        public string Key { get; internal set; }
        public string Name { get; internal set; }
        public string Title { get; internal set; }
        public string Type { get; internal set; }
        public long Size { get; internal set; }
        public DateTimeOffset LastModified { get; internal set; }

        public AttachmentFileThumb[] Thumbnails { get; internal set; }
    }

    public class SharedFolderRecord
    {
        public string RecordUid { get; internal set; }
        public bool CanEdit { get; internal set; }
        public bool CanShare { get; internal set; }
    }

    public class SharedFolderUser
    {
        public string Username { get; internal set; }
        public bool ManageRecords { get; internal set; }
        public bool ManageUsers { get; internal set; }
    }

    public class SharedFolderTeam
    {
        public string TeamUid { get; internal set; }
        public string Name { get; internal set; }
        public bool ManageRecords { get; internal set; }
        public bool ManageUsers { get; internal set; }
    }

    public class SharedFolder
    {
        public SharedFolder() : this(null)
        {
        }

        internal SharedFolder(SyncDownSharedFolder sf)
        {
            Uid = sf.sharedFolderUid;
            Name = Encoding.UTF8.GetString(CryptoUtils.DecryptAesV1(sf.name.Base64UrlDecode(), sf.unencryptedSharedFolderKey));
            ManageRecords = sf.manageRecords ?? DefaultManageRecords;
            ManageUsers = sf.manageUsers ?? DefaultManageUsers;
            DefaultManageRecords = sf.defaultManageRecords;
            DefaultManageUsers = sf.defaultManageUsers;
            DefaultCanEdit = sf.defaultCanEdit;
            DefaultCanShare = sf.defaultCanShare;
            if (sf.records != null)
            {
                foreach (var r in sf.records)
                {
                    Records.Add(new SharedFolderRecord
                    {
                        RecordUid = r.recordUid,
                        CanEdit = r.canEdit,
                        CanShare = r.canShare
                    });
                }
            }

            if (sf.users != null)
            {
                foreach (var u in sf.users)
                {
                    Users.Add(new SharedFolderUser
                    {
                        Username = u.username,
                        ManageRecords = u.manageRecords,
                        ManageUsers = u.manageUsers
                    });
                }
            }

            if (sf.teams != null)
            {
                foreach (var t in sf.teams)
                {
                    Teams.Add(new SharedFolderTeam
                    {
                        TeamUid = t.teamUid,
                        Name = t.name,
                        ManageRecords = t.manageRecords,
                        ManageUsers = t.manageUsers
                    });
                }
            }
        }

        public string Uid { get; }
        public string Name { get; set; }
        public bool ManageRecords { get; set; }
        public bool ManageUsers { get; set; }

        public bool DefaultManageRecords { get; set; }
        public bool DefaultManageUsers { get; set; }
        public bool DefaultCanEdit { get; set; }
        public bool DefaultCanShare { get; set; }

        public List<SharedFolderRecord> Records { get; } = new List<SharedFolderRecord>();
        public List<SharedFolderUser> Users { get; } = new List<SharedFolderUser>();
        public List<SharedFolderTeam> Teams { get; } = new List<SharedFolderTeam>();
    }

    public class FolderNode
    {
        public FolderType FolderType { get; internal set; } = FolderType.UserFolder;
        public string FolderUid { get; internal set; }
        public string Name { get; internal set; }
        public string ParentUid { get; internal set; }
        public IList<string> Children { get; } = new List<string>();
        public IList<string> Records { get; } = new List<string>();
    }

    public class Vault
    {
        public Vault(AuthContext auth)
        {
            Auth = auth;
        }

        internal readonly IDictionary<string, SyncDownRecordMetaData> metaData = new ConcurrentDictionary<string, SyncDownRecordMetaData>();
        internal readonly IDictionary<string, SyncDownRecord> records = new ConcurrentDictionary<string, SyncDownRecord>();
        internal readonly IDictionary<string, SyncDownSharedFolder> sharedFolders = new ConcurrentDictionary<string, SyncDownSharedFolder>();
        internal readonly IDictionary<string, SyncDownTeam> teams = new ConcurrentDictionary<string, SyncDownTeam>();
        internal readonly IDictionary<string, IFolderNode> userFolders = new ConcurrentDictionary<string, IFolderNode>();
        internal List<IRecordNode> userFolderRecords;

        internal readonly IDictionary<string, PasswordRecord> keeperRecords = new ConcurrentDictionary<string, PasswordRecord>();
        public IDictionary<string, FolderNode> keeperFolders = new ConcurrentDictionary<string, FolderNode>();
        public FolderNode Root { get; } = new FolderNode {
            Name = "My Vault"
        };
        internal readonly IDictionary<string, SharedFolder> keeperSharedFolders = new ConcurrentDictionary<string, SharedFolder>();

        public IEnumerable<PasswordRecord> Records => keeperRecords.Values;
        public IEnumerable<SharedFolder> SharedFolders => keeperSharedFolders.Values;

        public AuthContext Auth { get; }
        public long Revision { get; internal set; }

        public bool TryGetFolder(string folderUid, out FolderNode node) {
            return keeperFolders.TryGetValue(folderUid, out node);
        }

        public bool TryGetSharedFolder(string sharedFolderUid, out SharedFolder sharedFolder)
        {
            return keeperSharedFolders.TryGetValue(sharedFolderUid, out sharedFolder);
        }

        public bool TryGetRecord(string recordUid, out PasswordRecord node)
        {
            return keeperRecords.TryGetValue(recordUid, out node);
        }

        public bool ResolveRecordAccessPath(IRecordAccessPath path, bool forEdit = false)
        {
            if (string.IsNullOrEmpty(path.RecordUid))
            {
                return false;
            }
            if (metaData.TryGetValue(path.RecordUid, out SyncDownRecordMetaData sdrm))
            {
                if (sdrm.canEdit || !forEdit)
                {
                    return true;
                }
            }
            else
            {
                return false;
            }

            foreach (var sharedFolder in sharedFolders.Values)
            {
                if (sharedFolder.records != null)
                {
                    var sfr = sharedFolder.records
                        .FirstOrDefault(x => (x.recordUid == path.RecordUid) && (x.canEdit || !forEdit));
                    if (sfr != null)
                    {
                        if (string.IsNullOrEmpty(sharedFolder.sharedFolderKey))
                        {
                            if (sharedFolder.teams != null)
                            {
                                foreach (var team in sharedFolder.teams)
                                {
                                    if (teams.TryGetValue(team.teamUid, out SyncDownTeam sdt))
                                    {
                                        if (forEdit && sdt.restrictEdit)
                                        {
                                            continue;
                                        }
                                        path.SharedFolderUid = sharedFolder.sharedFolderUid;
                                        path.TeamUid = sdt.teamUid;
                                        return true;
                                    }
                                }
                            }
                        }
                        else
                        {
                            path.SharedFolderUid = sharedFolder.sharedFolderUid;
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        public async Task AddRecord(PasswordRecord record, string folderUid)
        {
            IFolderNode node = null;
            if (!string.IsNullOrEmpty(folderUid)) {
                userFolders.TryGetValue(folderUid, out node);
            }
            var recordKey = CryptoUtils.GenerateEncryptionKey();
            var recordAdd = new RecordAddCommand
            {
                recordUid = CryptoUtils.GenerateUid(),
                recordKey = CryptoUtils.EncryptAesV1(recordKey, Auth.DataKey).Base64UrlEncode(),
                recordType = "password"
            };
            if (node == null)
            {
                recordAdd.folderType = "user_folder";
            }
            else
            {
                switch (node.Type)
                {
                    case FolderType.UserFolder:
                        recordAdd.folderType = "user_folder";
                        recordAdd.folderUid = node.FolderUid;
                        break;
                    case FolderType.SharedFolder:
                    case FolderType.SharedFolderForder:
                        recordAdd.folderUid = node.FolderUid;
                        recordAdd.folderType = node.Type == FolderType.SharedFolder ? "shared_folder" : "shared_folder_folder";
                        if (node is ISharedFolderNode sfn)
                        {
                            if (sharedFolders.TryGetValue(sfn.SharedFolderUid, out SyncDownSharedFolder sf))
                            {
                                recordAdd.folderKey = CryptoUtils.EncryptAesV1(recordKey, sf.unencryptedSharedFolderKey).Base64UrlEncode();
                            }
                        }
                        if (string.IsNullOrEmpty(recordAdd.folderKey))
                        {
                            throw new Exception(string.Format("Cannot resolve shared folder for folder UID", folderUid));
                        }
                        break;
                }
            }
            var settings = new DataContractJsonSerializerSettings
            {
                UseSimpleDictionaryFormat = true
            };
            var dataSerializer = new DataContractJsonSerializer(typeof(RecordData), settings);
            var data = record.ExtractRecordData();
            using (var ms = new MemoryStream())
            {
                dataSerializer.WriteObject(ms, data);
                recordAdd.data = CryptoUtils.EncryptAesV1(ms.ToArray(), recordKey).Base64UrlEncode();
            }

            await Auth.ExecuteAuthCommand<RecordAddCommand>(recordAdd);
            await this.SyncDown();
        }

        public async Task SaveRecord(PasswordRecord record, bool skipData = false, bool skipExtra = true)
        {
            SyncDownRecord existingRecord = null;
            if (!string.IsNullOrEmpty(record.Uid))
            {
                records.TryGetValue(record.Uid, out existingRecord);
            }
            var updateRecord = new RecordUpdateRecord();

            byte[] recordKey = null;
            if (existingRecord != null)
            {
                updateRecord.recordUid = existingRecord.recordUid;
                recordKey = existingRecord.unencryptedRecordKey;
                if (metaData.TryGetValue(existingRecord.recordUid, out SyncDownRecordMetaData sdrmd))
                {
                    if (sdrmd.recordKeyType == 2)
                    {
                        updateRecord.recordKey = CryptoUtils.EncryptAesV1(recordKey, Auth.DataKey).Base64UrlEncode();
                    }
                }
                updateRecord.revision = existingRecord.revision;
                ResolveRecordAccessPath(updateRecord);
            }
            else
            {
                updateRecord.recordUid = CryptoUtils.GenerateUid();
                recordKey = CryptoUtils.GenerateEncryptionKey();
                updateRecord.recordKey = CryptoUtils.EncryptAesV1(recordKey, Auth.DataKey).Base64UrlEncode();
                updateRecord.revision = 0;
            }
            var settings = new DataContractJsonSerializerSettings
            {
                UseSimpleDictionaryFormat = true
            };
            if (!skipData)
            {
                var dataSerializer = new DataContractJsonSerializer(typeof(RecordData), settings);
                RecordData existingData = null;
                if (existingRecord != null)
                {
                    try
                    {
                        var unencrypted_data = CryptoUtils.DecryptAesV1(existingRecord.data.Base64UrlDecode(), existingRecord.unencryptedRecordKey);
                        using (var ms = new MemoryStream(unencrypted_data))
                        {
                            existingData = (RecordData)dataSerializer.ReadObject(ms);
                        }
                    }
                    catch (Exception e)
                    {
                        Trace.TraceError("Decrypt Record: UID: {0}, {1}: \"{2}\"", existingRecord.recordUid, e.GetType().Name, e.Message);
                    }
                }
                var data = record.ExtractRecordData(existingData);
                using (var ms = new MemoryStream())
                {
                    dataSerializer.WriteObject(ms, data);
                    updateRecord.data = CryptoUtils.EncryptAesV1(ms.ToArray(), recordKey).Base64UrlEncode();
                }
            }
            if (!skipExtra)
            {
                var extraSerializer = new DataContractJsonSerializer(typeof(RecordExtra), settings);
                RecordExtra existingExtra = null;
                if (existingRecord != null)
                {
                    try
                    {
                        var unencrypted_extra = CryptoUtils.DecryptAesV1(existingRecord.extra.Base64UrlDecode(), existingRecord.unencryptedRecordKey);
                        using (var ms = new MemoryStream(unencrypted_extra))
                        {
                            existingExtra = (RecordExtra)extraSerializer.ReadObject(ms);
                        }
                    }
                    catch (Exception e)
                    {
                        Trace.TraceError("Decrypt Record: UID: {0}, {1}: \"{2}\"", existingRecord.recordUid, e.GetType().Name, e.Message);
                    }
                }
                var extra = record.ExtractRecordExtra(existingExtra);
                using (var ms = new MemoryStream())
                {
                    extraSerializer.WriteObject(ms, extra);
                    updateRecord.extra = CryptoUtils.EncryptAesV1(ms.ToArray(), recordKey).Base64UrlEncode();
                }
                var udata = new RecordUpdateUData();
                var ids = new HashSet<string>();
                if (record.Attachments != null)
                {
                    foreach (var atta in record.Attachments)
                    {
                        ids.Add(atta.Id);
                        if (atta.Thumbnails != null)
                        {
                            foreach (var thumb in atta.Thumbnails)
                            {
                                ids.Add(thumb.Id);
                            }
                        }
                    }
                }
                udata.fileIds = ids.ToArray();
                updateRecord.udata = udata;
            }

            var command = new RecordUpdateCommand();
            if (existingRecord != null) {
                command.updateRecords = new RecordUpdateRecord[] { updateRecord };
            } else {
                command.addRecords = new RecordUpdateRecord[] { updateRecord };
            }

            var rs = await Auth.ExecuteAuthCommand<RecordUpdateCommand, RecordUpdateResponse>(command);
            await this.SyncDown();
        }
    }

    internal static class KeeperRecordExtension
    {
        public static RecordData ExtractRecordData(this PasswordRecord record, RecordData existingData = null)
        {
            return new RecordData
            {
                title = record.Title,
                folder = existingData?.folder,
                secret1 = record.Login,
                secret2 = record.Password,
                link = record.Link,
                notes = record.Notes,
                custom = record.Custom?.Select(x => new RecordDataCustom
                {
                    name = x.Name,
                    value = x.Value,
                    type = x.Type
                }).ToArray()
            };
        }

        public static RecordExtra ExtractRecordExtra(this PasswordRecord record, RecordExtra existingExtra = null)
        {
            IDictionary<string, RecordExtraFile> extraFiles = null;
            if (existingExtra != null && existingExtra.files != null && existingExtra.files.Length > 0)
            {
                extraFiles = new Dictionary<string, RecordExtraFile>();
                foreach (var f in existingExtra.files)
                {
                    extraFiles.Add(f.id, f);
                }
            }
            return new RecordExtra
            {
                files = record.Attachments?.Select(x =>
                {
                    RecordExtraFile extraFile;
                    if (extraFiles != null)
                    {
                        if (extraFiles.TryGetValue(x.Id, out extraFile))
                        {
                            return extraFile;
                        }
                    }
                    extraFile = new RecordExtraFile
                    {
                        id = x.Id,
                        key = x.Key,
                        name = x.Name,
                        title = x.Title ?? x.Name,
                        size = x.Size,
                        type = x.Type
                    };
                    if (x.Thumbnails != null && x.Thumbnails.Length > 0)
                    {
                        extraFile.thumbs = x.Thumbnails.Select(y =>
                            new RecordExtraFileThumb
                            {
                                id = y.Id,
                                size = y.Size,
                                type = y.Type
                            })
                            .ToArray();
                    }
                    return extraFile;
                }).ToArray(),
                ExtensionData = existingExtra?.ExtensionData
            };
        }

    }

 
}
