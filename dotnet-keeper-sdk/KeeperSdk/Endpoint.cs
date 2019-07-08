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
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using System.Collections.Concurrent;
using System.Net;
using System.IO;
using Authentication;
using Google.Protobuf;
using System.Runtime.Serialization.Json;
using System.Linq;
using System.Diagnostics;
using System.Text;

namespace KeeperSecurity.Sdk
{

    public class KeeperEndpoint
    {
        public static string DefaultDeviceName = ".NET Keeper API";

        static KeeperEndpoint()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        }

        public IConfigurationStorage Storage { get; }
        private byte[] transmissionKey = CryptoUtils.GetRandomBytes(32);

        public KeeperEndpoint(IConfigurationStorage storage)
        {
            Storage = storage;
            ClientVersion = KeeperApiCommand.ClientVersion;
            Locale = KeeperSettings.DefaultLocale();
            ServerKeyId = 1;

            var conf = storage.Get();
            Server = conf.LastServer;
            var servConf = conf.GetServerConfiguration(Server);
            if (servConf != null)
            {
                EncryptedDeviceToken = servConf.DeviceId;
                ServerKeyId = servConf.ServerKeyId;
            }
        }

        public async Task<byte[]> ExecuteRest(string endpoint, byte[] payload)
        {
            var builder = new UriBuilder(Server ?? "keepersecurity.com")
            {
                Path = "/api/rest/",
                Scheme = "https",
                Port = 443
            };
            var uri = new Uri(builder.Uri, endpoint);

            var apiPayload = new ApiRequestPayload()
            {
                Payload = ByteString.CopyFrom(payload)
            };

            var attempt = 0;
            while (attempt < 3)
            {
                attempt++;

                var request = WebRequest.Create(uri);

                request.ContentType = "application/octet-stream";
                request.Method = "POST";

                var encPayload = CryptoUtils.EncryptAesV2(apiPayload.ToByteArray(), transmissionKey);
                var encKey = CryptoUtils.EncryptRsa(transmissionKey, KeeperSettings.KeeperPublicKeys[ServerKeyId]);
                var apiRequest = new ApiRequest()
                {
                    EncryptedTransmissionKey = ByteString.CopyFrom(encKey),
                    PublicKeyId = ServerKeyId,
                    Locale = Locale,
                    EncryptedPayload = ByteString.CopyFrom(encPayload)
                };

                using (var requestStream = request.GetRequestStream())
                {
                    var p = apiRequest.ToByteArray();
                    await requestStream.WriteAsync(p, 0, p.Length);
                }

                HttpWebResponse response;
                try
                {
                    response = (HttpWebResponse) request.GetResponse();
                }
                catch (WebException e)
                {
                    response = (HttpWebResponse)e.Response;
                }

                if (response.StatusCode == HttpStatusCode.OK && response.ContentType == "application/octet-stream")
                {
                    using (var ms = new MemoryStream())
                    using (var rss = response.GetResponseStream())
                    {
                        await rss.CopyToAsync(ms);
                        var bytes = ms.ToArray();
                        return CryptoUtils.DecryptAesV2(bytes, transmissionKey);
                    }
                }

                if (response.ContentType == "application/json")
                {
                    var serializer = new DataContractJsonSerializer(typeof(KeeperApiErrorResponse));
                    using (var rss = response.GetResponseStream())
                    {
                        var keeperRs = serializer.ReadObject(rss) as KeeperApiErrorResponse;
                        switch (keeperRs.Error)
                        {
                            case "key":
                                if (KeeperSettings.KeeperPublicKeys.ContainsKey(keeperRs.KeyId))
                                {
                                    ServerKeyId = keeperRs.KeyId;
                                    continue;
                                }
                                break;
                            case "region_redirect":
                                throw new KeeperRegionRedirect(keeperRs.RegionHost);

                            case "bad_request":
                                throw new KeeperInvalidDeviceToken();
                        }
                        throw new KeeperApiException(keeperRs.resultCode, keeperRs.message);
                    }
                }
                throw new Exception("Keeper Api Http error: " + response.StatusCode);
            }
            throw new Exception("Keeper Api error");
        }

        public async Task<byte[]> GetDeviceToken()
        {
            var deviceRequest = new DeviceRequest
            {
                ClientVersion = ClientVersion,
                DeviceName = DefaultDeviceName
            };

            var rs = await ExecuteRest("authentication/get_device_token", deviceRequest.ToByteArray());
            var deviceRs = DeviceResponse.Parser.ParseFrom(rs);
            if (deviceRs.Status == DeviceStatus.Ok)
            {
                return deviceRs.EncryptedDeviceToken.ToByteArray();
            }
            throw new KeeperInvalidDeviceToken();
        }

        public async Task<NewUserMinimumParams> GetNewUserParams(string userName)
        {
            var authRequest = new AuthRequest()
            {
                ClientVersion = ClientVersion,
                Username = userName,
                EncryptedDeviceToken = ByteString.CopyFrom(EncryptedDeviceToken)
            };

            var rs = await ExecuteRest("authentication/get_new_user_params", authRequest.ToByteArray());
            return NewUserMinimumParams.Parser.ParseFrom(rs);
        }

        public async Task<PreLoginResponse> GetPreLogin(string username, byte[] twoFactorToken = null)
        {
            var oldDeviceToken = EncryptedDeviceToken;
            if (EncryptedDeviceToken == null)
            {
                EncryptedDeviceToken = await GetDeviceToken();
            }

            var attempt = 0;
            while (attempt < 3)
            {
                attempt++;

                var preLogin = new PreLoginRequest()
                {
                    AuthRequest = new AuthRequest
                    {
                        ClientVersion = ClientVersion,
                        Username = username,
                        EncryptedDeviceToken = ByteString.CopyFrom(EncryptedDeviceToken)
                    },
                    LoginType = LoginType.Normal
                };

                if (twoFactorToken != null)
                {
                    preLogin.TwoFactorToken = ByteString.CopyFrom(twoFactorToken);
                }

                byte[] response = null;
                try
                {
                    response = await ExecuteRest("authentication/pre_login", preLogin.ToByteArray());
                }
                catch (KeeperInvalidDeviceToken)
                {
                    EncryptedDeviceToken = await GetDeviceToken();
                    continue;
                }
                catch (KeeperRegionRedirect redirect)
                {
                    var conf = Storage.Get();
                    var serverConf = conf.GetServerConfiguration(Server);
                    if (serverConf != null) {
                        if (!(EncryptedDeviceToken.SequenceEqual(serverConf.DeviceId) && ServerKeyId == serverConf.ServerKeyId))
                        {
                            var c = new Configuration();
                            c._servers.Add(Server.AdjustServerUrl(), new ServerConfiguration {
                                Server = Server,
                                DeviceId = EncryptedDeviceToken,
                                ServerKeyId = ServerKeyId
                            });
                            Storage.Put(c);
                        }
                    }
                    Server = redirect.RegionHost;
                    serverConf = conf.GetServerConfiguration(Server);
                    EncryptedDeviceToken = serverConf?.DeviceId;
                    if (EncryptedDeviceToken == null)
                    {
                        EncryptedDeviceToken = await GetDeviceToken();
                    }

                    continue;
                }

                return PreLoginResponse.Parser.ParseFrom(response);
            }

            throw new KeeperTooManyAttempts();
        }

        public async Task<R> ExecuteV2Command<C, R>(C command) where C : KeeperApiCommand where R : KeeperApiResponse
        {
            command.locale = Locale;
            command.clientVersion = ClientVersion;

            var settings = new DataContractJsonSerializerSettings
            {
                UseSimpleDictionaryFormat = true
            };

            byte[] rq;
            using (var ms = new MemoryStream())
            {
                var cmdSerializer = new DataContractJsonSerializer(typeof(C), settings);
                cmdSerializer.WriteObject(ms, command);
                rq = ms.ToArray();
            }

            Debug.WriteLine("Request: " + Encoding.UTF8.GetString(rq));
            var rs = await ExecuteRest("vault/execute_v2_command", rq);
            Debug.WriteLine("Response: " + Encoding.UTF8.GetString(rs));

            using (var ms = new MemoryStream(rs))
            {
                var rsSerializer = new DataContractJsonSerializer(typeof(R), settings);
                return (R)rsSerializer.ReadObject(ms);
            }
        }

        public string Server { get; set; }
        public byte[] EncryptedDeviceToken { get; private set; }
        public string ClientVersion { get; set; }
        public string Locale { get; set; }
        public int ServerKeyId { get; private set; }

    }

    static class KeeperSettings
    {
        internal static string DefaultLocale()
        {
            var culture = System.Globalization.CultureInfo.CurrentCulture;
            string locale = null;

            if (KeeperLanguages.TryGetValue(culture.Name, out locale))
            {
                return locale;
            }

            if (KeeperLanguages.TryGetValue(culture.TwoLetterISOLanguageName, out locale))
            {
                return locale;
            }

            return "en_US";
        }


        internal static readonly IDictionary<int, RsaKeyParameters> KeeperPublicKeys;

        static KeeperSettings()
        {
            var list = new[]
            {
                new KeyValuePair<int, RsaKeyParameters>(1, KeeperKey1.Base64UrlDecode().LoadPublicKey()),
                new KeyValuePair<int, RsaKeyParameters>(2, KeeperKey2.Base64UrlDecode().LoadPublicKey()),
                new KeyValuePair<int, RsaKeyParameters>(3, KeeperKey3.Base64UrlDecode().LoadPublicKey()),
                new KeyValuePair<int, RsaKeyParameters>(4, KeeperKey4.Base64UrlDecode().LoadPublicKey()),
                new KeyValuePair<int, RsaKeyParameters>(5, KeeperKey5.Base64UrlDecode().LoadPublicKey()),
                new KeyValuePair<int, RsaKeyParameters>(6, KeeperKey6.Base64UrlDecode().LoadPublicKey())
            };
            KeeperPublicKeys = new ConcurrentDictionary<int, RsaKeyParameters>(list);
        }

        static readonly IDictionary<string, string> KeeperLanguages = new Dictionary<string, string>()
        {
            {"ar", "ar_AE"},
            {"de", "de_DE"},
            {"el", "el_GR"},
            {"en-GB", "en_GB"},
            {"en", "en_US"},
            {"es", "es_ES"},
            {"fr", "fr_FR"},
            {"he", "iw_IL"},
            {"it", "it_IT"},
            {"ja", "ja_JP"},
            {"ko", "ko_KR"},
            {"nl", "nl_NL"},
            {"pl", "pl_PL"},
            {"pt", "pt_PT"},
            {"pt-BR", "pt_BR"},
            {"ro", "ro_RO"},
            {"ru", "ru_RU"},
            {"sk", "sk_SK"},
            {"zh", "zh_CN"},
            {"zh-HK", "zh_HK"},
            {"zh-TW", "zh_TW"}
        };

        const string KeeperKey1 = "MIIBCgKCAQEA9Z_CZzxiNUz8-npqI4V10-zW3AL7-M4UQDdd_17759Xzm0MOEfH" +
            "OOsOgZxxNK1DEsbyCTCE05fd3Hz1mn1uGjXvm5HnN2mL_3TOVxyLU6VwH9EDInn" +
            "j4DNMFifs69il3KlviT3llRgPCcjF4xrF8d4SR0_N3eqS1f9CBJPNEKEH-am5Xb" +
            "_FqAlOUoXkILF0UYxA_jNLoWBSq-1W58e4xDI0p0GuP0lN8f97HBtfB7ijbtF-V" +
            "xIXtxRy-4jA49zK-CQrGmWqIm5DzZcBvUtVGZ3UXd6LeMXMJOifvuCneGC2T2uB" +
            "6G2g5yD54-onmKIETyNX0LtpR1MsZmKLgru5ugwIDAQAB";

        const string KeeperKey2 = "MIIBCgKCAQEAkOpym7xC3sSysw5DAidLoVF7JUgnvXejbieDWmEiD-DQOKxzfQq" +
            "YHoFfeeix__bx3wMW3I8cAc8zwZ1JO8hyB2ON732JE2Zp301GAUMnAK_rBhQWmY" +
            "KP_-uXSKeTJPiuaW9PVG0oRJ4MEdS-t1vIA4eDPhI1EexHaY3P2wHKoV8twcGvd" +
            "WUZB5gxEpMbx5CuvEXptnXEJlxKou3TZu9uwJIo0pgqVLUgRpW1RSRipgutpUsl" +
            "BnQ72Bdbsry0KKVTlcPsudAnnWUtsMJNgmyQbESPm-aVv-GzdVUFvWKpKkAxDpN" +
            "ArPMf0xt8VL2frw2LDe5_n9IMFogUiSYt156_mQIDAQAB";

        const string KeeperKey3 = "MIIBCgKCAQEAyvxCWbLvtMRmq57oFg3mY4DWfkb1dir7b29E8UcwcKDcCsGTqoI" +
            "hubU2pO46TVUXmFgC4E-Zlxt-9F-YA-MY7i_5GrDvySwAy4nbDhRL6Z0kz-rqUi" +
            "rgm9WWsP9v-X_BwzARqq83HNBuzAjf3UHgYDsKmCCarVAzRplZdT3Q5rnNiYPYS" +
            "HzwfUhKEAyXk71UdtleD-bsMAmwnuYHLhDHiT279An_Ta93c9MTqa_Tq2Eirl_N" +
            "Xn1RdtbNohmMXldAH-C8uIh3Sz8erS4hZFSdUG1WlDsKpyRouNPQ3diorbO88wE" +
            "AgpHjXkOLj63d1fYJBFG0yfu73U80aEZehQkSawIDAQAB";

        const string KeeperKey4 = "MIIBCgKCAQEA0TVoXLpgluaqw3P011zFPSIzWhUMBqXT-Ocjy8NKjJbdrbs53eR" +
            "FKk1waeB3hNn5JEKNVSNbUIe-MjacB9P34iCfKtdnrdDB8JXx0nIbIPzLtcJC4H" +
            "CYASpjX_TVXrU9BgeCE3NUtnIxjHDy8PCbJyAS_Pv299Q_wpLWnkkjq70ZJ2_fX" +
            "-ObbQaZHwsWKbRZ_5sD6rLfxNACTGI_jo9-vVug6AdNq96J7nUdYV1cG-INQwJJ" +
            "KMcAbKQcLrml8CMPc2mmf0KQ5MbS_KSbLXHUF-81AsZVHfQRSuigOStQKxgSGL5" +
            "osY4NrEcODbEXtkuDrKNMsZYhijKiUHBj9vvgKwIDAQAB";

        const string KeeperKey5 = "MIIBCgKCAQEAueOWC26w-HlOLW7s88WeWkXpjxK4mkjqngIzwbjnsU9145R51Hv" +
            "sILvjXJNdAuueVDHj3OOtQjfUM6eMMLr-3kaPv68y4FNusvB49uKc5ETI0HtHmH" +
            "FSn9qAZvC7dQHSpYqC2TeCus-xKeUciQ5AmSfwpNtwzM6Oh2TO45zAqSA-QBSk_" +
            "uv9TJu0e1W1AlNmizQtHX6je-mvqZCVHkzGFSQWQ8DBL9dHjviI2mmWfL_egAVV" +
            "hBgTFXRHg5OmJbbPoHj217Yh-kHYA8IWEAHylboH6CVBdrNL4Na0fracQVTm-nO" +
            "WdM95dKk3fH-KJYk_SmwB47ndWACLLi5epLl9vwIDAQAB";

        const string KeeperKey6 = "MIIBCgKCAQEA2PJRM7-4R97rHwY_zCkFA8B3llawb6gF7oAZCpxprl6KB5z2cqL" +
            "AvUfEOBtnr7RIturX04p3ThnwaFnAR7ADVZWBGOYuAyaLzGHDI5mvs8D-NewG9v" +
            "w8qRkTT7Mb8fuOHC6-_lTp9AF2OA2H4QYiT1vt43KbuD0Y2CCVrOTKzDMXG8msl" +
            "_JvAKt4axY9RGUtBbv0NmpkBCjLZri5AaTMgjLdu8XBXCqoLx7qZL-Bwiv4njw-" +
            "ZAI4jIszJTdGzMtoQ0zL7LBj_TDUBI4Qhf2bZTZlUSL3xeDWOKmd8Frksw3oKyJ" +
            "17oCQK-EGau6EaJRGyasBXl8uOEWmYYgqOWirNwIDAQAB";
    }
}
