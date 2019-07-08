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
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.Serialization.Json;
using System.IO;
using System.Text;

namespace KeeperSecurity.Sdk
{

    public static class SyncDownExtension
    {
        static void DeleteRecordKey(this Vault vault, string recordUid)
        {
            if (vault.records.TryGetValue(recordUid, out SyncDownRecord sdr))
            {
                sdr.unencryptedRecordKey = null;
            }
            vault.keeperRecords.Remove(recordUid);
        }

        static void DeleteSharedFolderKey(this Vault vault, string sharedFolderUid)
        {
            if (vault.sharedFolders.TryGetValue(sharedFolderUid, out SyncDownSharedFolder sharedFolder))
            {
                if (sharedFolder.records != null)
                {
                    foreach (var record in sharedFolder.records)
                    {
                        vault.DeleteRecordKey(record.recordUid);
                    }
                }
                sharedFolder.unencryptedSharedFolderKey = null;
            }
        }

        static void DeleteTeamKey(this Vault vault, string teamUid)
        {
            if (vault.teams.TryGetValue(teamUid, out SyncDownTeam team))
            {
                team.unencryptedTeamKey = null;
                team.privateKey = null;

                if (team.sharedFolderKeys != null)
                {
                    foreach (var sfk in team.sharedFolderKeys)
                    {
                        vault.DeleteSharedFolderKey(sfk.sharedFolderUid);
                    }
                }
            }
        }

        private class Comparers : IComparer<IFolderNode>, IComparer<IRecordNode>
        {
            public int Compare(IFolderNode x, IFolderNode y)
            {
                return string.Compare(x.FolderUid, y.FolderUid);
            }

            public int Compare(IRecordNode x, IRecordNode y)
            {
                int res = string.Compare(x.FolderUid, y.FolderUid);
                if (res == 0)
                {
                    res = string.Compare(x.RecordUid, y.RecordUid);
                }
                return res;
            }
        }

        private static void ProcessSubFolders(this Vault vault, SyncDownResponse rs)
        {
            var comparers = new Comparers();
            var folderList = new SortedSet<IFolderNode>(vault.userFolders.Values, comparers);
            var recordList = new SortedSet<IRecordNode>(vault.userFolderRecords ?? Enumerable.Empty<IRecordNode>(), comparers);

            if (rs.userFoldersRemoved != null)
            {
                foreach (var ufr in rs.userFoldersRemoved)
                {
                    folderList.RemoveWhere(x => x.FolderUid == ufr.folderUid);
                    recordList.RemoveWhere(x => x.FolderUid == ufr.folderUid);
                }
            }

            if (rs.sharedFolderFolderRemoved != null)
            {
                foreach (var sffr in rs.sharedFolderFolderRemoved)
                {
                    folderList.RemoveWhere(x => x.FolderUid == sffr.folderUid);
                    recordList.RemoveWhere(x => x.FolderUid == sffr.folderUid);
                }
            }

            if (rs.userFolderSharedFoldersRemoved != null)
            {
                foreach (var ufsfr in rs.userFolderSharedFoldersRemoved)
                {
                    folderList.RemoveWhere(x => x.FolderUid == ufsfr.folderUid);
                    recordList.RemoveWhere(x => x.FolderUid == ufsfr.folderUid);
                }
            }

            if (rs.userFoldersRemovedRecords != null)
            {
                foreach (var uffr in rs.userFoldersRemovedRecords)
                {
                    recordList.Remove(uffr);
                }
            }

            if (rs.sharedFolderFolderRecordsRemoved != null)
            {
                foreach (var sffrr in rs.sharedFolderFolderRecordsRemoved)
                {
                    recordList.Remove(sffrr);
                }
            }

            if (rs.userFolders != null)
            {
                foreach (var uf in rs.userFolders)
                {
                    var encryptedKey = uf.userFolderKey.Base64UrlDecode();
                    uf.unencryptedFolderKey = uf.keyType == 2
                        ? CryptoUtils.DecryptRsa(encryptedKey, vault.Auth.PrivateKey)
                        : CryptoUtils.DecryptAesV1(encryptedKey, vault.Auth.DataKey);
                    folderList.Remove(uf);
                    folderList.Add(uf);
                }
            }

            if (rs.sharedFolderFolders != null)
            {
                foreach (var sff in rs.sharedFolderFolders)
                {
                    if (vault.sharedFolders.TryGetValue(sff.sharedFolderUid, out SyncDownSharedFolder sf))
                    {
                        var encryptedKey = sff.sharedFolderFolderKey.Base64UrlDecode();
                        sff.unencryptedFolderKey = CryptoUtils.DecryptAesV1(encryptedKey, sf.unencryptedSharedFolderKey);
                        folderList.Remove(sff);
                        folderList.Add(sff);
                    }
                    else
                    {
                        Trace.TraceError("Sync_Down: shared_folder_folders: Shared Folder UID {0} not found", sff.sharedFolderUid);
                    }
                }
            }

            if (rs.userFolderSharedFolders != null)
            {
                foreach (var ufsf in rs.userFolderSharedFolders)
                {
                    folderList.Remove(ufsf);
                    folderList.Add(ufsf);
                }
            }

            if (rs.userFolderRecords != null)
            {
                foreach (var ufr in rs.userFolderRecords)
                {
                    recordList.Add(ufr);
                }
            }

            if (rs.sharedFolderFolderRecords != null)
            {
                foreach (var sffr in rs.sharedFolderFolderRecords)
                {
                    recordList.Add(sffr);
                }
            }

            var toDelete = new HashSet<string>();
            foreach (var folder in vault.keeperFolders.Values)
            {
                toDelete.Add(folder.FolderUid);
                folder.Children.Clear();
                folder.Records.Clear();
            }
            foreach (var folder in folderList)
            {
                if (vault.keeperFolders.TryGetValue(folder.FolderUid, out FolderNode node))
                {
                    toDelete.Remove(folder.FolderUid);
                    node.Children.Clear();
                    node.Records.Clear();
                    node.Name = null;
                }
                else
                {
                    node = new FolderNode
                    {
                        FolderType = folder.Type,
                        FolderUid = folder.FolderUid
                    };
                    vault.keeperFolders.Add(folder.FolderUid, node);
                }
                node.ParentUid = folder.ParentUid;

                byte[] unencrypted_data = null;
                switch (folder.Type)
                {
                    case FolderType.UserFolder:
                        if (folder is SyncDownUserFolder uf)
                        {
                            unencrypted_data = CryptoUtils.DecryptAesV1(uf.data.Base64UrlDecode(), uf.unencryptedFolderKey);
                        }
                        else
                        {
                            Trace.TraceError("Folder UID {0} expected to be User-Folder", folder.FolderUid);
                        }
                        break;

                    case FolderType.SharedFolderForder:
                        if (folder is SyncDownSharedFolderFolder sff)
                        {
                            unencrypted_data = CryptoUtils.DecryptAesV1(sff.data.Base64UrlDecode(), sff.unencryptedFolderKey);
                        }
                        else
                        {
                            Trace.TraceError("Folder UID {0} expected to be Shared-Folder-Folder", folder.FolderUid);
                        }
                        break;
                    case FolderType.SharedFolder:
                        if (vault.sharedFolders.TryGetValue(folder.FolderUid, out SyncDownSharedFolder sf))
                        {
                            node.Name = Encoding.UTF8.GetString(CryptoUtils.DecryptAesV1(sf.name.Base64UrlDecode(), sf.unencryptedSharedFolderKey));
                        }
                        else
                        {
                            Trace.TraceError("Folder UID {0} expected to be Shared-Folder", folder.FolderUid);
                        }
                        break;
                }
                if (unencrypted_data != null)
                {
                    var serializer = new DataContractJsonSerializer(typeof(FolderData));
                    using (var stream = new MemoryStream(unencrypted_data))
                    {
                        var folderData = serializer.ReadObject(stream) as FolderData;
                        node.Name = folderData.name;
                    }
                }
                if (string.IsNullOrEmpty(node.Name))
                {
                    node.Name = node.FolderUid;
                }
            }
            foreach (var uid in toDelete)
            {
                vault.keeperFolders.Remove(uid);
            }
            vault.Root.Children.Clear();
            vault.Root.Records.Clear();

            foreach (var node in vault.keeperFolders.Values)
            {
                if (string.IsNullOrEmpty(node.ParentUid))
                {
                    vault.Root.Children.Add(node.FolderUid);
                }
                else
                {
                    if (vault.keeperFolders.TryGetValue(node.ParentUid, out FolderNode parent))
                    {
                        parent.Children.Add(node.FolderUid);
                    }
                    else
                    {
                        Trace.TraceError("Folder UID {0} was lost", node.FolderUid);
                    }
                }
            }

            foreach (var record in recordList)
            {
                if (string.IsNullOrEmpty(record.FolderUid))
                {
                    vault.Root.Records.Add(record.RecordUid);
                }
                else
                {
                    if (vault.keeperFolders.TryGetValue(record.FolderUid, out FolderNode node))
                    {
                        node.Records.Add(record.RecordUid);
                    }
                    else
                    {
                        Trace.TraceError("Folder UID {0} was lost", node.FolderUid);
                        vault.Root.Records.Add(record.RecordUid);
                    }
                }
            }

            vault.userFolders.Clear();
            foreach (var folder in folderList)
            {
                vault.userFolders.Add(folder.FolderUid, folder);
            }
            vault.userFolderRecords = recordList.ToList();
        }

        public static async Task SyncDown(this Vault vault)
        {
            var command = new SyncDownCommand
            {
                revision = vault.Revision,
                include = new string[] { "sfheaders", "sfrecords", "sfusers", "teams", "folders" },
                deviceName = KeeperEndpoint.DefaultDeviceName
            };

            var rs = await vault.Auth.ExecuteAuthCommand<SyncDownCommand, SyncDownResponse>(command);

            ISet<string> uids = new HashSet<string>();

            if (rs.fullSync)
            {
                vault.metaData.Clear();
                vault.records.Clear();
                vault.sharedFolders.Clear();
                vault.teams.Clear();

                vault.keeperFolders.Clear();
                vault.userFolderRecords = null;

                vault.keeperRecords.Clear();
            }

            vault.Revision = rs.revision;

            if (rs.removedRecords != null)
            {
                foreach (var uid in rs.removedRecords)
                {
                    vault.DeleteRecordKey(uid);
                    vault.metaData.Remove(uid);
                }
            }

            if (rs.removedTeams != null)
            {
                foreach (var teamUid in rs.removedTeams)
                {
                    vault.DeleteTeamKey(teamUid);
                    if (vault.teams.TryGetValue(teamUid, out SyncDownTeam sdt))
                    {
                        if (sdt.sharedFolderKeys != null)
                        {
                            foreach (var sfk in sdt.sharedFolderKeys)
                            {
                                if (vault.sharedFolders.TryGetValue(sfk.sharedFolderUid, out SyncDownSharedFolder sdsf))
                                {
                                    if (sdsf.teams != null)
                                    {
                                        sdsf.teams = sdsf.teams.Where(x => x.teamUid != teamUid).ToArray();
                                    }
                                }
                            }
                        }
                        vault.teams.Remove(teamUid);
                    }
                }
            }

            if (rs.removedSharedFolders != null)
            {
                foreach (var sharedFolderUid in rs.removedSharedFolders)
                {
                    vault.DeleteSharedFolderKey(sharedFolderUid);
                    if (vault.sharedFolders.TryGetValue(sharedFolderUid, out SyncDownSharedFolder sdsf))
                    {
                        sdsf.sharedFolderKey = null;
                        sdsf.keyType = null;
                        if (sdsf.users != null)
                        {
                            sdsf.users = sdsf.users.Where(x => string.Compare(x.username, vault.Auth.Username, true) != 0).ToArray();
                        }
                    }
                }
            }

            if (rs.teams != null)
            {
                foreach (var t in rs.teams)
                {
                    if (vault.teams.TryGetValue(t.teamUid, out SyncDownTeam team))
                    {
                        if (t.removedSharedFolders != null)
                        {
                            uids.Clear();
                            uids.UnionWith(t.removedSharedFolders);
                            team.sharedFolderKeys = t.sharedFolderKeys.Where(x => uids.Contains(x.sharedFolderUid)).ToArray();
                        }
                        if (t.sharedFolderKeys != null)
                        {
                            if (team.sharedFolderKeys == null)
                            {
                                team.sharedFolderKeys = t.sharedFolderKeys;
                            }
                            else
                            {
                                team.sharedFolderKeys = team.sharedFolderKeys.Concat(t.sharedFolderKeys).ToArray();
                            }
                        }
                        team.name = t.name ?? team.name;
                        team.restrictEdit = t.restrictEdit;
                        team.restrictView = t.restrictView;
                        team.restrictShare = t.restrictShare;
                    }
                    else
                    {
                        vault.teams.Add(t.teamUid, t);
                    }
                }
            }

            if (rs.sharedFolders != null)
            {
                foreach (var sf in rs.sharedFolders)
                {
                    if (sf.fullSync == true)
                    {
                        vault.sharedFolders.Remove(sf.sharedFolderUid);
                    }
                    if (vault.sharedFolders.TryGetValue(sf.sharedFolderUid, out SyncDownSharedFolder sharedFolder))
                    {
                        sharedFolder.revision = sf.revision;
                        sharedFolder.manageRecords = sf.manageRecords ?? sharedFolder.manageRecords;
                        sharedFolder.manageUsers = sf.manageUsers ?? sharedFolder.manageUsers;
                        sharedFolder.name = sf.name ?? sharedFolder.name;

                        if (sf.recordsRemoved != null && sharedFolder.records != null)
                        {
                            uids.Clear();
                            uids.UnionWith(sf.recordsRemoved);
                            sharedFolder.records = sharedFolder.records.Where(x => !uids.Contains(x.recordUid)).ToArray();
                        }
                        if (sf.usersRemoved != null && sharedFolder.users != null)
                        {
                            uids.Clear();
                            uids.UnionWith(sf.usersRemoved);
                            sharedFolder.users = sharedFolder.users.Where(x => !uids.Contains(x.username)).ToArray();
                        }
                        if (sf.teamsRemoved != null && sharedFolder.teams != null)
                        {
                            uids.Clear();
                            uids.UnionWith(sf.teamsRemoved);
                            sharedFolder.teams = sharedFolder.teams.Where(x => !uids.Contains(x.teamUid)).ToArray();
                        }
                        if (sf.records != null)
                        {
                            if (sharedFolder.records != null)
                            {
                                sharedFolder.records = sharedFolder.records.Concat(sf.records).ToArray();
                            }
                            else
                            {
                                sharedFolder.records = sf.records;
                            }
                        }
                        if (sf.users != null)
                        {
                            if (sharedFolder.users != null)
                            {
                                sharedFolder.users = sharedFolder.users.Concat(sf.users).ToArray();
                            }
                            else
                            {
                                sharedFolder.users = sf.users;
                            }
                        }
                        if (sf.teams != null)
                        {
                            if (sharedFolder.teams != null)
                            {
                                sharedFolder.teams = sharedFolder.teams.Concat(sf.teams).ToArray();
                            }
                            else
                            {
                                sharedFolder.teams = sf.teams;
                            }
                        }
                    }
                    else
                    {
                        vault.sharedFolders.Add(sf.sharedFolderUid, sf);
                    }
                    vault.keeperSharedFolders.Remove(sf.sharedFolderUid);
                }
            }

            if (rs.recordMetaData != null)
            {
                foreach (var rmd in rs.recordMetaData)
                {
                    if (vault.metaData.TryGetValue(rmd.recordUid, out SyncDownRecordMetaData metaData))
                    {
                        metaData.recordKey = rmd.recordKey;
                        metaData.recordKeyType = rmd.recordKeyType;
                        metaData.owner = rmd.owner;
                        metaData.canEdit = rmd.canEdit;
                        metaData.canShare = rmd.canShare;
                    }
                    else
                    {
                        vault.metaData.Add(rmd.recordUid, rmd);
                    }
                }
            }

            if (rs.records != null)
            {
                foreach (var r in rs.records)
                {
                    if (vault.records.TryGetValue(r.recordUid, out SyncDownRecord record))
                    {
                        record.data = r.data;
                        record.extra = r.extra;
                        record.udata = r.udata;
                        record.clientModifiedTime = r.clientModifiedTime;
                        record.revision = r.revision;
                        record.version = r.version;
                        record.shared = r.shared;
                    }
                    else
                    {
                        vault.records.Add(r.recordUid, r);
                    }
                    vault.keeperRecords.Remove(r.recordUid);
                }
            }

            //Process keys
            foreach (var team in vault.teams.Values)
            {
                if (team.unencryptedTeamKey == null)
                {
                    byte[] teamKey = null;
                    try
                    {
                        if (team.teamKeyType == 1)
                        {
                            teamKey = CryptoUtils.DecryptAesV1(team.teamKey.Base64UrlDecode(), vault.Auth.DataKey);
                        }
                        else if (team.teamKeyType == 2)
                        {
                            teamKey = CryptoUtils.DecryptRsa(team.teamKey.Base64UrlDecode(), vault.Auth.PrivateKey);
                        }
                    }
                    catch (Exception e)
                    {
                        Trace.TraceError("Decrypt Team Key: UID: {0}, {1}: \"{2}\"", team.teamUid, e.GetType().Name, e.Message);
                    }
                    if (teamKey != null)
                    {
                        team.unencryptedTeamKey = teamKey;
                    }
                }
            }

            foreach (var sharedFolder in vault.sharedFolders.Values)
            {
                if (sharedFolder.unencryptedSharedFolderKey == null)
                {
                    byte[] key = null;
                    if (string.IsNullOrEmpty(sharedFolder.sharedFolderKey))
                    {
                        if (sharedFolder.teams != null)
                        {
                            foreach (var team in sharedFolder.teams)
                            {
                                if (vault.teams.TryGetValue(team.teamUid, out SyncDownTeam sdt))
                                {
                                    if (sdt.sharedFolderKeys != null)
                                    {
                                        var sfk = sdt.sharedFolderKeys.FirstOrDefault(x => x.sharedFolderUid == sharedFolder.sharedFolderUid);
                                        if (sfk != null)
                                        {
                                            try
                                            {
                                                if (sfk.keyType == 1)
                                                {
                                                    key = CryptoUtils.DecryptAesV1(sfk.sharedFolderKey.Base64UrlDecode(), sdt.unencryptedTeamKey);
                                                }
                                                else if (sfk.keyType == 2)
                                                {
                                                    key = CryptoUtils.DecryptRsa(sfk.sharedFolderKey.Base64UrlDecode(), sdt.PrivateKey);
                                                }
                                            }
                                            catch (Exception e)
                                            {
                                                Trace.TraceError("Decrypt Shared Folder Key: UID: {0}, Team UID: {1}, {2}: \"{3}\"", sharedFolder.sharedFolderUid, sdt.teamUid, e.GetType().Name, e.Message);
                                            }
                                        }
                                    }
                                }
                            }
                            if (key != null)
                            {
                                break;
                            }
                        }
                    }
                    else
                    {
                        try
                        {
                            if (sharedFolder.keyType == 1)
                            {
                                key = CryptoUtils.DecryptAesV1(sharedFolder.sharedFolderKey.Base64UrlDecode(), vault.Auth.DataKey);
                            }
                            else if (sharedFolder.keyType == 2)
                            {
                                key = CryptoUtils.DecryptRsa(sharedFolder.sharedFolderKey.Base64UrlDecode(), vault.Auth.PrivateKey);
                            }
                        }
                        catch (Exception e)
                        {
                            Trace.TraceError("Decrypt Shared Folder Key: UID: {0}, {1}: \"{2}\"", sharedFolder.sharedFolderUid, e.GetType().Name, e.Message);
                        }
                    }
                    if (key != null)
                    {
                        sharedFolder.unencryptedSharedFolderKey = key;
                    }
                }
            }

            uids.Clear();
            uids.UnionWith(vault.sharedFolders.Values.Where(x => x.unencryptedSharedFolderKey == null).Select(x => x.sharedFolderUid));
            foreach (var uid in uids)
            {
                vault.sharedFolders.Remove(uid);
            }

            foreach (var record in vault.records.Values)
            {
                if (record.unencryptedRecordKey == null)
                {
                    byte[] key = null;
                    if (vault.metaData.TryGetValue(record.recordUid, out SyncDownRecordMetaData sdrmd))
                    {
                        if (string.IsNullOrEmpty(sdrmd.recordKey))
                        {
                            key = vault.Auth.DataKey;
                        }
                        else
                        {
                            try
                            {
                                if (sdrmd.recordKeyType == 1)
                                {
                                    key = CryptoUtils.DecryptAesV1(sdrmd.recordKey.Base64UrlDecode(), vault.Auth.DataKey);
                                }
                                else if (sdrmd.recordKeyType == 2)
                                {
                                    key = CryptoUtils.DecryptRsa(sdrmd.recordKey.Base64UrlDecode(), vault.Auth.PrivateKey);
                                }
                            }
                            catch (Exception e)
                            {
                                Trace.TraceError("Decrypt Record Key: UID: {0}, {1}: \"{2}\"", record.recordUid, e.GetType().Name, e.Message);
                            }
                        }
                    }
                    else
                    {
                        foreach (var sharedFolder in vault.sharedFolders.Values)
                        {
                            if (sharedFolder.records != null)
                            {
                                var sfr = sharedFolder.records.FirstOrDefault(x => x.recordUid == record.recordUid);
                                if (sfr != null)
                                {
                                    try
                                    {
                                        key = CryptoUtils.DecryptAesV1(sfr.recordKey.Base64UrlDecode(), sharedFolder.unencryptedSharedFolderKey);
                                    }
                                    catch (Exception e)
                                    {
                                        Trace.TraceError("Decrypt Record Key: UID: {0}, Shared Folder UID: {1}, {2}: \"{3}\"", record.recordUid, sharedFolder.sharedFolderUid, e.GetType().Name, e.Message);
                                    }
                                }
                                if (key != null)
                                {
                                    break;
                                }
                            }
                        }
                    }
                    if (key != null)
                    {
                        record.unencryptedRecordKey = key;
                    }
                }
            }

            uids.Clear();
            uids.UnionWith(vault.records.Values.Where(x => x.unencryptedRecordKey == null).Select(x => x.recordUid));
            foreach (var uid in uids)
            {
                vault.records.Remove(uid);
            }

            uids.Clear();
            uids.UnionWith(vault.keeperRecords.Keys);
            uids.ExceptWith(vault.records.Keys);
            foreach (var uid in uids)
            {
                vault.keeperRecords.Remove(uid);
            }

            vault.DecryptRecords();

            uids.Clear();
            uids.UnionWith(vault.sharedFolders.Values.Where(x => x.unencryptedSharedFolderKey == null).Select(x => x.sharedFolderUid));
            foreach (var uid in uids)
            {
                vault.sharedFolders.Remove(uid);
            }

            uids.Clear();
            uids.UnionWith(vault.keeperSharedFolders.Keys);
            uids.ExceptWith(vault.sharedFolders.Keys);
            foreach (var uid in uids)
            {
                vault.keeperSharedFolders.Remove(uid);
            }
            vault.DecryptSharedFolders();

            vault.ProcessSubFolders(rs);
        }

        internal static void DecryptSharedFolders(this Vault vault)
        {
            var uids = new HashSet<string>();

            uids.UnionWith(vault.sharedFolders.Keys);
            uids.ExceptWith(vault.keeperSharedFolders.Keys);
            if (uids.Count > 0)
            {
                foreach (var uid in uids) {
                    if (vault.sharedFolders.TryGetValue(uid, out SyncDownSharedFolder sdsf)) {
                        vault.keeperSharedFolders.Add(uid, new SharedFolder(sdsf));
                    }
                }
            }
        }

        internal static void DecryptRecords(this Vault vault)
        {
            var uids = new HashSet<string>();

            uids.UnionWith(vault.records.Keys);
            uids.ExceptWith(vault.keeperRecords.Keys);
            if (uids.Count > 0)
            {
                var dataSerializer = new DataContractJsonSerializer(typeof(RecordData));
                var extraSerializer = new DataContractJsonSerializer(typeof(RecordExtra));

                foreach (var uid in uids)
                {
                    if (vault.records.TryGetValue(uid, out SyncDownRecord sdr))
                    {
                        try
                        {
                            var record = new PasswordRecord(uid);

                            var unencrypted_data = CryptoUtils.DecryptAesV1(sdr.data.Base64UrlDecode(), sdr.unencryptedRecordKey);
                            using (var ms = new MemoryStream(unencrypted_data))
                            {
                                var data = (RecordData)dataSerializer.ReadObject(ms);
                                record.Title = data.title;
                                record.Login = data.secret1;
                                record.Password = data.secret2;
                                record.Link = data.link;
                                record.Notes = data.notes;
                                if (data.custom != null)
                                {
                                    foreach (var cr in data.custom)
                                    {
                                        record.Custom.Add(new CustomField
                                        {
                                            Name = cr.name,
                                            Value = cr.value,
                                            Type = cr.type
                                        });
                                    }
                                }
                            }

                            if (!string.IsNullOrEmpty(sdr.extra))
                            {
                                var unencrypted_extra = CryptoUtils.DecryptAesV1(sdr.extra.Base64UrlDecode(), sdr.unencryptedRecordKey);
                                using (var ms = new MemoryStream(unencrypted_extra))
                                {
                                    var extra = (RecordExtra)extraSerializer.ReadObject(ms);
                                    if (extra.files != null && extra.files.Length > 0)
                                    {
                                        foreach (var file in extra.files)
                                        {
                                            var atta = new AttachmentFile
                                            {
                                                Id = file.id,
                                                Key = file.key,
                                                Name = file.name,
                                                Title = file.title ?? "",
                                                Type = file.type ?? "",
                                                Size = file.size ?? 0,
                                                LastModified = file.lastModified != null ? file.lastModified.Value.FromUnixTimeMilliseconds() : DateTimeOffset.Now
                                            };
                                            if (file.thumbs != null)
                                            {
                                                atta.Thumbnails = file.thumbs
                                                .Select(t => new AttachmentFileThumb
                                                {
                                                    Id = t.id,
                                                    Type = t.type,
                                                    Size = t.size ?? 0
                                                })
                                                .ToArray();
                                            }
                                            record.Attachments.Add(atta);
                                        }
                                    }
                                }
                            }

                            vault.keeperRecords.Add(uid, record);
                        }
                        catch (Exception e)
                        {
                            Trace.TraceError("Decrypt Record: UID: {0}, {1}: \"{2}\"", uid, e.GetType().Name, e.Message);
                        }
                    }
                }
            }
        }
    }
}
