using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommandLine;
using KeeperSecurity.Sdk;

namespace Commander
{
    public class ConnectedCommands : CliCommands
    {
        private readonly Vault _vault;
        public ConnectedCommands(Vault vault) : base()
        {
            _vault = vault;

            Commands.Add("list", new ParsableCommand<ListCommandOptions>
            {
                Order = 10,
                Description = "List folder content",
                Action = ListCommand
            });

            Commands.Add("cd", new SimpleCommand
            {
                Order = 11,
                Description = "Change current folder",
                Action = ChangeDirectoryCommand
            });

            Commands.Add("tree", new ParsableCommand<TreeCommandOptions>
            {
                Order = 12,
                Description = "Display folder structure",
                Action = TreeCommand
            });

            Commands.Add("get", new SimpleCommand
            {
                Order = 13,
                Description = "Display specified Keeper record/folder/team",
                Action = GetCommand
            });

            Commands.Add("add-record", new ParsableCommand<AddRecordOptions>
            {
                Order = 20,
                Description = "Add record",
                Action = AddRecordCommand
            });

            Commands.Add("update-record", new ParsableCommand<UpdateRecordOptions>
            {
                Order = 21,
                Description = "Update record",
                Action = UpdateRecordCommand
            });

            Commands.Add("list-sf", new SimpleCommand
            {
                Order = 22,
                Description = "List shared folders",
                Action = ListSharedFoldersCommand
            });

            Commands.Add("sync-down", new SimpleCommand
            {
                Order = 100,
                Description = "Download & decrypt data",
                Action = async (_) =>
                {
                    Console.WriteLine("Syncing...");
                    await _vault.SyncDown();
                }
            });

            Commands.Add("logout", new SimpleCommand
            {
                Order = 200,
                Description = "Logout",
                Action = (_) =>
                {
                    _vault.Auth.Logout();
                    Finished = true;
                    NewCommands = new NotConnectedCliCommands(_vault.Auth);
                    return Task.FromResult(false);
                }
            });

            CommandAliases.Add("ls", "list");
            CommandAliases.Add("d", "sync-down");
            CommandAliases.Add("add", "add-record");
            CommandAliases.Add("upd", "update-record");
        }

        private string _currentFolder;

        private Task ListCommand(ListCommandOptions options)
        {
            FolderNode node = null;
            if (!string.IsNullOrEmpty(_currentFolder))
            {
                _vault.TryGetFolder(_currentFolder, out node);
            }
            if (node == null)
            {
                node = _vault.Root;
            }

            if (options.Details)
            {
                if (node.Children.Count > 0)
                {
                    var tab = new Tabulate(2)
                    {
                        DumpRowNo = true
                    };
                    tab.AddHeader(new string[] { "Folder UID", "Name" });
                    foreach (var uid in node.Children)
                    {
                        if (_vault.TryGetFolder(uid, out FolderNode f))
                        {
                            tab.AddRow(new string[] { f.FolderUid, f.Name });
                        }
                    }

                    tab.Sort(1);
                    tab.Dump();
                }

                if (node.Records.Count > 0)
                {
                    var tab = new Tabulate(4)
                    {
                        DumpRowNo = true
                    };
                    tab.AddHeader(new string[] { "Record UID", "Title", "Login", "URL" });
                    foreach (var uid in node.Records)
                    {
                        if (_vault.TryGetRecord(uid, out PasswordRecord r))
                        {
                            tab.AddRow(new string[] { r.Uid, r.Title, r.Login, r.Link });
                        }
                    }

                    tab.Sort(1);
                    tab.Dump();
                }
            }
            else
            {
                List<string> names = new List<string>();
                foreach (var uid in node.Children)
                {
                    if (_vault.TryGetFolder(uid, out FolderNode subnode))
                    {
                        names.Add(subnode.Name + "/");
                    }
                }
                names.Sort(StringComparer.InvariantCultureIgnoreCase);
                int len = names.Count;
                foreach (var uid in node.Records)
                {
                    if (_vault.TryGetRecord(uid, out PasswordRecord record))
                    {
                        names.Add(record.Title);
                    }
                }
                names.Sort(len, names.Count - len, StringComparer.InvariantCultureIgnoreCase);
                if (names.Count > 0)
                {
                    len = names.Select(x => x.Length).Max();
                    if (len < 16)
                    {
                        len = 16;
                    }
                    len += 2;
                    int columns = Console.BufferWidth / len;
                    if (columns < 1)
                    {
                        columns = 1;
                    }
                    int columnWidth = Console.BufferWidth / columns;
                    int colNo = 0;
                    for (int i = 0; i < names.Count; i++)
                    {
                        Console.Write(names[i].PadRight(columnWidth - 1));
                        colNo++;
                        if (colNo >= columns)
                        {
                            Console.WriteLine();
                            colNo = 0;
                        }
                    }
                }
            }

            return Task.FromResult(true);
        }

        public void PrintTree(FolderNode folder, string indent, bool last)
        {
            var isRoot = string.IsNullOrEmpty(indent);
            Console.WriteLine(indent + (isRoot ? "" : "+-- ") + folder.Name);
            indent += isRoot ? " " : (last ? "    " : "|   ");
            for (int i = 0; i < folder.Children.Count; i++)
            {
                if (_vault.TryGetFolder(folder.Children[i], out FolderNode node))
                {
                    PrintTree(node, indent, i == folder.Children.Count - 1);
                }
            }
        }

        private Task GetCommand(string uid)
        {
            var tab = new Tabulate(3);
            if (_vault.TryGetRecord(uid, out PasswordRecord record))
            {
                tab.AddRow(new[] { "Record UID:", record.Uid });
                tab.AddRow(new[] { "Title:", record.Title });
                tab.AddRow(new[] { "Login:", record.Login });
                tab.AddRow(new[] { "Password:", record.Password });
                tab.AddRow(new[] { "Login URL:", record.Link });
                tab.AddRow(new[] { "Notes:", record.Notes });
                if (record.Custom != null && record.Custom.Count > 0)
                {
                    tab.AddRow(new[] { "" });
                    tab.AddRow(new[] { "Custom Fields:", "" });
                    foreach (var c in record.Custom)
                    {
                        tab.AddRow(new[] { c.Name + ":", c.Value });
                    }
                }

            }
            else if (_vault.TryGetSharedFolder(uid, out SharedFolder sf))
            {
                tab.AddRow(new[] { "Shared Folder UID:", sf.Uid });
                tab.AddRow(new[] { "Name:", sf.Name });
                tab.AddRow(new[] { "Default Manage Records:", sf.DefaultManageRecords.ToString() });
                tab.AddRow(new[] { "Default Manage Users:", sf.DefaultManageUsers.ToString() });
                tab.AddRow(new[] { "Default Can Edit:", sf.DefaultCanEdit.ToString() });
                tab.AddRow(new[] { "Default Can Share:", sf.DefaultCanShare.ToString() });
                if (sf.Records.Count > 0)
                {
                    tab.AddRow(new[] { "" });
                    tab.AddRow(new[] { "Record Permissions:" });
                    foreach (var r in sf.Records)
                    {
                        tab.AddRow(new[] { r.RecordUid + ":", "Can Edit: " + r.CanEdit.ToString(), "Can Share: " + r.CanShare.ToString() });
                    }
                }
                if (sf.Users.Count > 0)
                {
                    tab.AddRow(new[] { "" });
                    tab.AddRow(new[] { "User Permissions:" });
                    foreach (var u in sf.Users)
                    {
                        tab.AddRow(new[] { u.Username + ":", "Can Manage Records: " + u.ManageRecords.ToString(), "Can Manage Records: " + u.ManageUsers.ToString() });
                    }
                }
                if (sf.Teams.Count > 0)
                {
                    tab.AddRow(new[] { "" });
                    tab.AddRow(new[] { "Team Permissions:" });
                    foreach (var t in sf.Teams)
                    {
                        tab.AddRow(new[] { t.Name + ":", "Can Manage Records: " + t.ManageRecords.ToString(), "Can Manage Records: " + t.ManageUsers.ToString() });
                    }
                }
            }
            else if (_vault.TryGetFolder(uid, out FolderNode f))
            {
                tab.AddRow(new[] { "Folder UID:", f.FolderUid });
                if (!string.IsNullOrEmpty(f.ParentUid))
                {
                    tab.AddRow(new[] { "Parent Folder UID:", f.ParentUid });
                }
                tab.AddRow(new[] { "Folder Type:", f.FolderType.ToString() });
                tab.AddRow(new[] { "Name:", f.Name });
            }
            else {
                Console.WriteLine(string.Format("UID {0} is not a valid Keeper object", uid));
                return Task.FromResult(false);
            }
            Console.WriteLine();
            tab.SetColumnRightAlign(0, true);
            tab.LeftPadding = 4;
            tab.Dump();
            return Task.FromResult(true);
        }

        private Task TreeCommand(TreeCommandOptions options)
        {
            PrintTree(_vault.Root, "", true);
            return Task.FromResult(true);
        }

        private Task ChangeDirectoryCommand(string name)
        {
            if (TryResolvePath(name, out FolderNode node))
            {
                _currentFolder = node.FolderUid;
            }
            else
            {
                Console.WriteLine(string.Format("Invalid folder name: {0}", name));
            }
            return Task.FromResult(true);
        }

        private async Task AddRecordCommand(AddRecordOptions options)
        {
            if (!TryResolvePath(options.Folder, out FolderNode node))
            {
                Console.WriteLine(string.Format("Cannot resolve folder {0}", options.Folder));
                return;
            }

            var record = new PasswordRecord
            {
                Title = options.Title,
                Login = options.Login,
                Password = options.Password,
                Link = options.Url,
                Notes = options.Notes
            };
            if (string.IsNullOrEmpty(record.Password) && options.Generate)
            {
                record.Password = CryptoUtils.GenerateUid();
            }
            if (!options.Force)
            {
                if (string.IsNullOrEmpty(record.Login))
                {
                    Console.Write("..." + "Login: ".PadRight(16));
                    record.Login = Console.ReadLine();
                }
                if (string.IsNullOrEmpty(record.Password))
                {
                    Console.Write("..." + "Password: ".PadRight(16));
                    record.Login = HelperUtils.ReadLineMasked();
                }
                if (string.IsNullOrEmpty(record.Link))
                {
                    Console.Write("..." + "Login URL: ".PadRight(16));
                    record.Link = Console.ReadLine();
                }
            }

            await _vault.AddRecord(record, node.FolderUid);
        }

        private async Task UpdateRecordCommand(UpdateRecordOptions options)
        {
            PasswordRecord record = null;
            if (_vault.TryGetRecord(options.RecordId, out record))
            {
            }
            else if (TryResolvePath(options.RecordId, out FolderNode node, out string title))
            {
                foreach (var uid in node.Records)
                {
                    if (_vault.TryGetRecord(uid, out PasswordRecord r))
                    {
                        if (string.Compare(title, r.Title) == 0)
                        {
                            record = r;
                            break;
                        }
                    }
                }
            }
            else
            {
            }
            if (record == null)
            {
                Console.WriteLine(string.Format("Cannot resolve record {0}", options.RecordId));
                return;
            }
            if (!string.IsNullOrEmpty(options.Title))
            {
                record.Title = options.Title;
            }
            if (!string.IsNullOrEmpty(options.Login))
            {
                record.Login = options.Login;
            }
            if (string.IsNullOrEmpty(options.Password))
            {
                if (options.Generate)
                {
                    record.Password = CryptoUtils.GenerateUid();
                }
            }
            else
            {
                record.Password = options.Password;
            }
            if (!string.IsNullOrEmpty(options.Url))
            {
                record.Link = options.Url;
            }
            if (!string.IsNullOrEmpty(options.Notes))
            {
                record.Notes = options.Notes;
            }

            await _vault.SaveRecord(record);
        }

        private Task ListSharedFoldersCommand(string arguments)
        {
            var tab = new Tabulate(4)
            {
                DumpRowNo = true
            };
            tab.AddHeader(new string[] { "Shared Folder UID", "Name", "# Records", "# Users" });
            foreach (var sf in _vault.SharedFolders)
            {
                tab.AddRow(new object[] { sf.Uid, sf.Name, sf.Records.Count, sf.Users.Count + sf.Teams.Count });
            }

            tab.Sort(1);
            tab.Dump();

            return Task.FromResult(true);
        }

        private bool TryResolvePath(string path, out FolderNode node)
        {
            string text;
            var res = TryResolvePath(path, out node, out text);
            if (res)
            {
                res = string.IsNullOrEmpty(text);
            }
            return res;
        }
        private bool TryResolvePath(string path, out FolderNode node, out string text)
        {
            node = null;
            text = null;
            if (string.IsNullOrEmpty(_currentFolder))
            {
                node = _vault.Root;
            }
            else
            {
                _vault.TryGetFolder(_currentFolder, out node);
            }

            if (!string.IsNullOrEmpty(path))
            {
                path = path.Trim();
                if (string.IsNullOrEmpty(path))
                {
                    return node != null;
                }

                if (path[0] == '/')
                {
                    path = path.Substring(1);
                    node = _vault.Root;
                }
                foreach (var folder in path.TokenizeArguments(CommandExtensions.IsPathDelimiter))
                {
                    if (folder == "..")
                    {
                        if (!string.IsNullOrEmpty(node.ParentUid))
                        {
                            if (!_vault.TryGetFolder(node.ParentUid, out node))
                            {
                                return false;
                            }
                        }
                        else if (!string.IsNullOrEmpty(node.FolderUid))
                        {
                            node = _vault.Root;
                        }
                        else
                        {
                            return false;
                        }
                    }
                    else
                    {
                        var found = false;
                        foreach (var subFolder in node.Children)
                        {
                            if (_vault.TryGetFolder(subFolder, out FolderNode subnode))
                            {
                                if (string.Compare(folder, subnode.Name) == 0)
                                {
                                    found = true;
                                    node = subnode;
                                    break;
                                }
                            }
                            else
                            {
                                return false;
                            }
                        }
                        if (!found)
                        {
                            if (string.IsNullOrEmpty(text))
                            {
                                text = folder;
                            }
                            else
                            {
                                return false;
                            }
                        }
                    }
                }
            }
            return true;
        }

        public void ScheduleSyncDown()
        {
            CommandQueue.Enqueue("sync-down");
        }

        public override string GetPrompt()
        {
            if (!string.IsNullOrEmpty(_currentFolder))
            {
                var folder = _currentFolder;
                var sb = new StringBuilder();
                while (_vault.TryGetFolder(folder, out FolderNode node))
                {
                    if (sb.Length > 0)
                    {
                        sb.Insert(0, '/');
                    }
                    sb.Insert(0, node.Name);
                    folder = node.ParentUid;
                    if (string.IsNullOrEmpty(folder))
                    {
                        sb.Insert(0, _vault.Root.Name + "/");
                        if (sb.Length > 40)
                        {
                            sb.Remove(0, sb.Length - 37);
                            sb.Insert(0, "...");
                        }
                        return sb.ToString();
                    }

                }
            }
            return _vault.Root.Name;
        }
    }

    class ListCommandOptions
    {
        [Option('l', "list", Required = false, Default = false, HelpText = "detailed output")]
        public bool Details { get; set; }

        [Value(0, Required = false, MetaName = "pattern", HelpText = "search pattern")]
        public string Pattern { get; set; }
    }

    class TreeCommandOptions
    {
        [Value(0, Required = false, MetaName = "folder", HelpText = "folder path or UID")]
        public string Folder { get; set; }
    }

    class EditRecord
    {
        [Option("login", Required = false, HelpText = "login name")]
        public string Login { get; set; }

        [Option("pass", Required = false, HelpText = "password")]
        public string Password { get; set; }

        [Option("url", Required = false, HelpText = "url")]
        public string Url { get; set; }

        [Option("notes", Required = false, HelpText = "notes")]
        public string Notes { get; set; }

        [Option('g', "generate", Required = false, Default = false, HelpText = "generate random password")]
        public bool Generate { get; set; }

    }

    class AddRecordOptions : EditRecord
    {
        [Option("folder", Required = false, HelpText = "folder")]
        public string Folder { get; set; }

        [Option('f', "force", Required = false, Default = false, HelpText = "do not prompt for omitted fields")]
        public bool Force { get; set; }

        [Value(0, Required = true, MetaName = "title", HelpText = "title")]
        public string Title { get; set; }
    }

    class UpdateRecordOptions : EditRecord
    {
        [Option("title", Required = false, HelpText = "title")]
        public string Title { get; set; }

        [Value(0, Required = true, MetaName = "title", HelpText = "record path or UID")]
        public string RecordId { get; set; }
    }
}
