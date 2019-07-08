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
using System.Threading.Tasks;
using KeeperSecurity.Sdk.UI;
using System.Linq;
using System.Diagnostics;
using System.Text;
using Authentication;
using Org.BouncyCastle.Crypto.Parameters;

namespace KeeperSecurity.Sdk
{
    public class AuthContext
    {
        public AuthContext(KeeperEndpoint api, IAuthUI ui)
        {
            Api = api;
            Ui = ui;
        }

        public async Task<IUserConfiguration> ResolveUserConfiguration(IUserCredentials credentials, IConfiguration configuration)
        {
            var result = new UserConfiguration
            {
                Username = credentials?.Username,
                Password = credentials?.Password
            };

            if (string.IsNullOrEmpty(result.Username))
            {
                result.Username = configuration?.LastLogin;
            }
            if (!string.IsNullOrEmpty(result.Username) && string.IsNullOrEmpty(result.Password))
            {
                result.Password = configuration?.Users?
                    .Where(x => string.Compare(x.Username, result.Username, true) == 0)
                    .Select(x => x.Password)
                    .FirstOrDefault();
            }

            while (string.IsNullOrEmpty(result.Username) || string.IsNullOrEmpty(result.Password))
            {
                if (Ui == null) throw new KeeperRequiresUI();
                var creds = await Ui.GetUserCredentials(result);
                if (creds == null)
                {
                    return null;
                }
                result.Username = creds.Username;
                result.Password = creds.Password;
            }

            if (!string.IsNullOrEmpty(result.Username) && string.IsNullOrEmpty(result.TwoFactorToken))
            {
                result.TwoFactorToken = configuration?.Users?
                            .Where(x => string.Compare(x.Username, result.Username, true) == 0)
                            .Select(x => x.TwoFactorToken)
                            .FirstOrDefault();
            }

            return result;
        }

        public async Task<KeeperApiResponse> ExecuteAuthCommand<C>(C command, bool throwOnError = true) where C : AuthorizedCommand
        {
            return await ExecuteAuthCommand<C, KeeperApiResponse>(command);
        }

        public async Task<R> ExecuteAuthCommand<C, R>(C command, bool throwOnError = true) where C : AuthorizedCommand where R : KeeperApiResponse
        {
            command.sessionToken = SessionToken;
            command.username = Username;
            command.deviceId = KeeperEndpoint.DefaultDeviceName;

            R response = null;
            int attempt = 0;
            while (attempt < 3)
            {
                attempt++;
                response = await Api.ExecuteV2Command<C, R>(command);
                if (!response.IsSuccess && response.resultCode == "auth_failed")
                {
                    Debug.WriteLine("Refresh Session Token");
                    SessionToken = null;
                    await RefreshSessionToken();
                }
                else
                {
                    break;
                }
            }
            if (response != null && !response.IsSuccess && throwOnError)
            {
                throw new KeeperApiException(response.resultCode, response.message);
            }
            return response;
        }

        public async Task Login(IUserConfiguration user = null)
        {
            var configuration = Api.Storage.Get();
            user = await ResolveUserConfiguration(user, configuration);

            var username = user?.Username;
            var password = user?.Password;
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                return;
            }
            var token = user.TwoFactorToken;
            var tokenType = "device_token";

            string authHash = null;
            PreLoginResponse preLogin = null;

            while (true)
            {
                if (preLogin == null)
                {
                    preLogin = await Api.GetPreLogin(username);
                    authHash = null;
                }

                var authParams = preLogin.Salt[0];
                int iterations = authParams.Iterations;
                byte[] salt = authParams.Salt_.ToByteArray();
                if (authHash == null)
                {
                    authHash = CryptoUtils.DeriveV1KeyHash(password, salt, iterations).Base64UrlEncode();
                }

                var command = new LoginCommand();
                command.username = username;
                command.authResponse = authHash;
                command.include = new[] { "keys", "settings", "enforcements", "is_enterprise_admin" };
                command.twoFactorToken = token;
                command.twoFactorType = !string.IsNullOrEmpty(token) ? tokenType : null;
                command.deviceTokenExpiresInDays = !string.IsNullOrEmpty(token) && tokenType != "device_token" ? 9999 : (int?)null;

                var loginRs = await Api.ExecuteV2Command<LoginCommand, LoginResponse>(command);

                if (!loginRs.IsSuccess && loginRs.resultCode == "auth_failed") // invalid password
                {
                    throw new Exception("Invalid user name or password");
                }
                else
                {
                    if (!string.IsNullOrEmpty(loginRs.deviceToken))
                    {
                        token = loginRs.deviceToken;
                        tokenType = "device_token";
                    }

                    SessionToken = loginRs.sessionToken;
                    Username = username;
                    accountSettings = loginRs.accountSettings;

                    if (loginRs.keys != null)
                    {
                        if (loginRs.keys.encryptedDataKey != null)
                        {
                            var key = CryptoUtils.DeriveKeyV2("data_key", password, salt, iterations);
                            DataKey = CryptoUtils.DecryptAesV2(loginRs.keys.encryptedDataKey.Base64UrlDecode(), key);
                        }
                        else
                        if (loginRs.keys.encryptionParams != null)
                        {
                            DataKey = CryptoUtils.DecryptEncryptionParams(password, loginRs.keys.encryptionParams.Base64UrlDecode());
                        }
                        else
                        {
                            throw new Exception("Missing data key");
                        }
                        if (loginRs.keys.encryptedPrivateKey != null)
                        {
                            privateKeyData = CryptoUtils.DecryptAesV1(loginRs.keys.encryptedPrivateKey.Base64UrlDecode(), DataKey);
                            privateKey = null;
                        }
                    }
                    if (loginRs.IsSuccess)
                    {
                        EncryptedPassword = CryptoUtils.EncryptAesV2(Encoding.UTF8.GetBytes(password), DataKey);
                        TwoFactorToken = token;
                        authResponse = authHash;
                        IsEnterpriseAdmin = loginRs.isEnterpriseAdmin ?? false;
                        enforcements = loginRs.enforcements;
                        StoreConfigurationIfChanged(configuration);
                        break;
                    }
                    switch (loginRs.resultCode)
                    {
                        case "need_totp":
                        case "invalid_device_token":
                        case "invalid_totp":
                            token = await Ui.GetTwoFactorCode();
                            if (!string.IsNullOrEmpty(token))
                            {
                                tokenType = "one_time";
                                continue;
                            }
                            break;

                        case "auth_expired":
                            await Ui.DisplayDialog(DialogType.Information, loginRs.message);
                            password = await this.ChangeMasterPassword(iterations);
                            if (!string.IsNullOrEmpty(password))
                            {
                                preLogin = null;
                                continue;
                            }
                            break;

                        case "auth_expired_transfer":
                            var shareAccountTo = loginRs.accountSettings.shareAccountTo;
                            if (await Ui.DisplayDialog(DialogType.Confirmation, "Do you accept Account Transfer policy?"))
                            {
                                await this.ShareAccount();
                                continue;
                            }
                            break;
                    }
                    throw new KeeperApiException(loginRs.resultCode, loginRs.message);
                }
            }
        }

        public void Logout()
        {
            TwoFactorToken = null;
            EncryptedPassword = null;
            SessionToken = null;
            authResponse = null;
            accountSettings = null;
            enforcements = null;
            privateKeyData = null;
            privateKey = null;
            DataKey = null;
            IsEnterpriseAdmin = false;
        }

        public async Task RefreshSessionToken()
        {
            var command = new LoginCommand
            {
                username = Username,
                authResponse = authResponse,
                twoFactorToken = TwoFactorToken,
                twoFactorType = !string.IsNullOrEmpty(TwoFactorToken) ? "device_token" : null
            };

            var loginRs = await Api.ExecuteV2Command<LoginCommand, LoginResponse>(command);
            if (loginRs.IsSuccess)
            {
                SessionToken = loginRs.sessionToken;
            }
            else
            {
                throw new KeeperApiException(loginRs.resultCode, loginRs.message);
            }
        }

        private void StoreConfigurationIfChanged(IConfiguration configuration)
        {
            var shouldSaveConfig = !(configuration.LastLogin?.AdjustServerUrl() == Api.Server?.AdjustServerUrl() && configuration.LastLogin?.AdjustUserName() == Username.AdjustUserName());
            var serverConf = configuration.GetServerConfiguration(Api.Server);
            var shouldSaveServer = serverConf == null || !(serverConf.DeviceId.SequenceEqual(Api.EncryptedDeviceToken) && serverConf.ServerKeyId == Api.ServerKeyId);

            var userConf = configuration.GetUserConfiguration(Username);
            var shouldSaveUser = userConf == null || string.Compare(userConf.TwoFactorToken, TwoFactorToken) != 0;

            if (shouldSaveConfig || shouldSaveServer || shouldSaveUser)
            {
                var conf = new Configuration
                {
                    LastLogin = Username,
                    LastServer = Api.Server.AdjustServerUrl()
                };
                if (shouldSaveServer)
                {
                    conf._servers.Add(Api.Server.AdjustServerUrl(), new ServerConfiguration
                    {
                        Server = Api.Server,
                        DeviceId = Api.EncryptedDeviceToken,
                        ServerKeyId = Api.ServerKeyId

                    });
                }
                if (shouldSaveUser)
                {
                    conf._users.Add(Username.AdjustUserName(), new UserConfiguration
                    {
                        Username = Username,
                        TwoFactorToken = TwoFactorToken
                    });
                }
                Api.Storage.Put(conf);
            }
        }

        private string authResponse;
        internal AccountSettings accountSettings;
        internal AccountEnforcements enforcements;
        private byte[] privateKeyData;
        private RsaPrivateCrtKeyParameters privateKey;

        public byte[] DataKey { get; private set; }
        public RsaPrivateCrtKeyParameters PrivateKey
        {
            get
            {
                if (privateKey == null)
                {
                    privateKey = privateKeyData.LoadPrivateKey();
                }
                return privateKey;
            }
        }

        public bool IsEnterpriseAdmin { get; private set; }

        public string SessionToken { get; private set; }
        public string TwoFactorToken { get; set; }
        public string Username { get; private set; }
        public byte[] EncryptedPassword { get; private set; }

        public KeeperEndpoint Api { get; }
        public IAuthUI Ui { get; }
    }
}
