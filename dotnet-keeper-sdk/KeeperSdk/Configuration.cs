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
using System.Linq;
using System.Threading.Tasks;

namespace KeeperSecurity.Sdk
{
    public interface IUserCredentials
    {
        string Username { get; }
        string Password { get; }
    }

    public interface IUserConfiguration : IUserCredentials
    {
        string TwoFactorToken { get;  }
    }

    public interface IServerConfiguration
    {
        string Server { get; }
        byte[] DeviceId { get; }
        int ServerKeyId { get; }
    }

    public interface IConfiguration

    {
        string LastServer { get; }
        string LastLogin { get; }

        IEnumerable<IUserConfiguration> Users { get; }
        IEnumerable<IServerConfiguration> Servers { get; }
    }

    public interface IConfigurationStorage
    {
        IConfiguration Get();
        void Put(IConfiguration configuration);
    }

    public static class ConfigurationExtension
    {
        public static IUserConfiguration GetUserConfiguration(this IConfiguration configuration, string username)
        {
            var name = username.AdjustUserName();
            return configuration?.Users?.Where(x => string.Compare(name, x.Username.AdjustUserName()) == 0).FirstOrDefault();
        }
        public static IServerConfiguration GetServerConfiguration(this IConfiguration configuration, string server)
        {
            var url = server.AdjustServerUrl();
            return configuration?.Servers?.Where(x => string.Compare(url, x.Server.AdjustServerUrl()) == 0).FirstOrDefault();
        }

        public static string AdjustServerUrl(this string server)
        {
            if (string.IsNullOrEmpty(server)) {
                return "keepersecurity.com";
            }
            var builder = new UriBuilder(server);
            return builder.Uri.Host.ToLowerInvariant();
        }

        public static string AdjustUserName(this string username)
        {
            return username.ToLowerInvariant();
        }
    }

    public class UserCredencials : IUserCredentials
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class UserConfiguration : UserCredencials, IUserConfiguration
    {
        public UserConfiguration() { }
        public UserConfiguration(IUserCredentials credentials)
        {
            Username = credentials.Username;
            Password = credentials.Password;
        }
        public UserConfiguration(IUserConfiguration user) : this((IUserCredentials)user)
        {
            TwoFactorToken = user.TwoFactorToken;
        }
        public string TwoFactorToken { get; set; }
    }

    public class ServerConfiguration : IServerConfiguration
    {
        public string Server { get; set; }
        public byte[] DeviceId { get; set; }
        public int ServerKeyId { get; set; } = 1;
    }

    public class Configuration : IConfiguration
    {
        public Configuration() {
            _users = new Dictionary<string, UserConfiguration>();
            _servers = new Dictionary<string, ServerConfiguration>();
        }

        public Configuration(IConfiguration other) : this()
        {
            MergeConfiguration(other);
        }

        public void MergeUserConfiguration(IUserConfiguration user) {
            var u = new UserConfiguration
            {
                Username = user.Username,
                Password = user.Password,
                TwoFactorToken = user.TwoFactorToken
            };
            var key = u.Username.AdjustUserName();
            _users[key] = u;
        }

        public void MergeServerConfiguration(IServerConfiguration server) {
            var s = new ServerConfiguration
            {
                Server = server.Server,
                DeviceId = server.DeviceId.ToArray(),
                ServerKeyId = server.ServerKeyId
            };
            var key = s.Server.AdjustServerUrl();
            _servers[key] = s;
        }

        public void MergeConfiguration(IConfiguration other)
        {
            if (!string.IsNullOrEmpty(other.LastLogin))
            {
                LastLogin = other.LastLogin;
            }
            if (!string.IsNullOrEmpty(other.LastServer))
            {
                LastServer = other.LastServer;
            }

            var users = other.Users;
            if (users != null)
            {
                foreach (var user in users)
                {
                    MergeUserConfiguration(user);
                }
            }

            var servers = other.Servers;
            if (servers != null)
            {
                foreach (var server in servers)
                {
                    MergeServerConfiguration(server);
                }
            }
        }

        internal readonly Dictionary<string, UserConfiguration> _users;
        internal readonly Dictionary<string, ServerConfiguration> _servers;

        public string LastServer { get; set; }
        public string LastLogin { get; set; }

        public IEnumerable<IUserConfiguration> Users => _users.Values.Cast<IUserConfiguration>();
        public IEnumerable<IServerConfiguration> Servers => _servers.Values.Cast<IServerConfiguration>();
    }

    public class InMemoryConfigurationStorage : IConfigurationStorage
    {
        private readonly Configuration _configuration;

        public InMemoryConfigurationStorage() {
            _configuration = new Configuration();
        }

        public InMemoryConfigurationStorage(string server, string user) : this()
        {
            _configuration.LastServer = server;
            _configuration.LastLogin = user;
        }

        public InMemoryConfigurationStorage(Configuration configuration)
        {
            _configuration = configuration;
        }

        public IConfiguration Get()
        {
            return new Configuration(_configuration);
        }

        public void Put(IConfiguration configuration) {
            _configuration.MergeConfiguration(configuration);
        }
    }
}
