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
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace KeeperSecurity.Sdk
{
    public class JsonConfigurationStorage : IConfigurationStorage
    {
        public JsonConfigurationStorage() : this("config.json")
        {
        }

        private string fileName_;
        public JsonConfigurationStorage(string fileName)
        {
            if (File.Exists(fileName))
            {
                fileName_ = Path.GetFileName(fileName);
            }
            else
            {
                var personalFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Personal), ".keeper");
                if (!Directory.Exists(personalFolder))
                {
                    Directory.CreateDirectory(personalFolder);
                }
                fileName_ = Path.Combine(personalFolder, fileName);
            }

            Debug.WriteLine(string.Format("JSON config path: \"{0}\"", fileName_));
        }

        public JsonConfiguration Get()
        {
            if (File.Exists(fileName_))
            {
                try
                {
                    var serializer = new DataContractJsonSerializer(typeof(JsonConfiguration));
                    using (var stream = File.OpenRead(fileName_))
                    {
                        var obj = serializer.ReadObject(stream);
                        return (JsonConfiguration)obj;
                    }
                }
                catch (SerializationException se)
                {
                    Trace.TraceError("JSON configuration: File name: \"{0}\", Error: {1}", fileName_, se.Message);
                }
                catch (Exception e)
                {
                    Trace.TraceError("JSON configuration: File name: \"{0}\", Error: {1}", fileName_, e.Message);
                }
            }
            return new JsonConfiguration();
        }

        IConfiguration IConfigurationStorage.Get()
        {
            return Get();
        }

        public void Put(IConfiguration configuration)
        {
            var config = Get();
            if (!string.IsNullOrEmpty(configuration.LastServer))
            {
                config.LastServer = configuration.LastServer;
            }
            if (!string.IsNullOrEmpty(configuration.LastLogin))
            {
                config.LastLogin = configuration.LastLogin;
            }

            var users = configuration.Users;
            if (users?.Any() == true)
            {
                if (config._users == null)
                {
                    config._users = new List<JsonUserConfiguration>();
                }
                var lookup = new Dictionary<string, JsonUserConfiguration>();
                foreach (var user in config._users)
                {
                    lookup.Add(user.Username.AdjustUserName(), user);
                }
                foreach (var user in users)
                {
                    if (!lookup.TryGetValue(user.Username.AdjustUserName(), out JsonUserConfiguration userConf))
                    {
                        userConf = new JsonUserConfiguration
                        {
                            Username = user.Username
                        };
                        config._users.Add(userConf);
                    }
                    userConf.TwoFactorToken = user.TwoFactorToken;
                }
            }

            var servers = configuration.Servers;
            if (servers?.Any() == true)
            {
                if (config._servers == null)
                {
                    config._servers = new List<JsonServerConfiguration>();
                }
                var lookup = new Dictionary<string, JsonServerConfiguration>();
                foreach (var server in config._servers)
                {
                    lookup.Add(server.Server.AdjustServerUrl(), server);
                }
                foreach (var server in servers)
                {
                    if (!lookup.TryGetValue(server.Server.AdjustServerUrl(), out JsonServerConfiguration serverConf))
                    {
                        serverConf = new JsonServerConfiguration
                        {
                            Server = server.Server.AdjustServerUrl()
                        };
                        config._servers.Add(serverConf);
                    }
                    serverConf.DeviceId = server.DeviceId.ToArray();
                    serverConf.ServerKeyId = server.ServerKeyId;
                }
            }

            var settings = new DataContractJsonSerializerSettings
            {
                UseSimpleDictionaryFormat = true
            };

            using (var stream = new MemoryStream())
            {
                using (var writer = JsonReaderWriterFactory.CreateJsonWriter(stream, Encoding.UTF8, true, true, "    "))
                {
                    var serializer = new DataContractJsonSerializer(typeof(JsonConfiguration), settings);
                    serializer.WriteObject(writer, config);
                }
                var jsonText = Encoding.UTF8.GetString(stream.ToArray());
                var pos = 0;
                while (pos < jsonText.Length - 1)
                {
                    var p = jsonText.IndexOf("\\/", pos, StringComparison.Ordinal);
                    if (p < 0)
                    {
                        break;
                    }
                    if (p > 1)
                    {
                        if (jsonText[p - 1] != '\\')
                        {
                        }
                        jsonText = jsonText.Remove(p, 1);
                    }
                    pos = p += 1;
                }

                File.WriteAllBytes(fileName_, Encoding.UTF8.GetBytes(jsonText));
            }
        }
    }

    [DataContract]
    public class JsonUserConfiguration : IUserConfiguration
    {
        [DataMember(Name = "user", EmitDefaultValue = false)]
        public string Username { get; set; }
        [DataMember(Name = "password", EmitDefaultValue = false)]
        public string Password { get; internal set; }

        [DataMember(Name = "mfa_token", EmitDefaultValue = false)]
        public string TwoFactorToken { get; set; }
    }

    [DataContract]
    public class JsonServerConfiguration : IServerConfiguration
    {
        [DataMember(Name = "server", EmitDefaultValue = false)]
        public string Server { get; set; }

        [DataMember(Name = "device_id", EmitDefaultValue = false)]
        string device_id_;
        public byte[] DeviceId { get => device_id_.Base64UrlDecode(); set => device_id_ = value.Base64UrlEncode(); }

        [DataMember(Name = "server_key_id", EmitDefaultValue = false)]
        public int ServerKeyId { get; set; }

    }

    [DataContract]
    public class JsonConfiguration : IConfiguration
    {
        [DataMember(Name = "last_server", EmitDefaultValue = false)]
        public string LastServer { get; set; }

        [DataMember(Name = "last_login", EmitDefaultValue = false)]
        public string LastLogin { get; set; }

        [DataMember(Name = "users", EmitDefaultValue = false)]
        internal List<JsonUserConfiguration> _users;

        [DataMember(Name = "servers", EmitDefaultValue = false)]
        internal List<JsonServerConfiguration> _servers;

        public IEnumerable<IUserConfiguration> Users => _users?.Cast<IUserConfiguration>();
        public IEnumerable<IServerConfiguration> Servers => _servers?.Cast<IServerConfiguration>();
    }
}
