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

namespace KeeperSecurity.Sdk
{
    /// <summary>
    /// Base Keeper command
    /// </summary>
    [DataContract]
    public class KeeperApiCommand
    {
        public KeeperApiCommand(string command)
        {
            this.command = command;
        }
        public static readonly string ClientVersion = "c14.0.0";

        [DataMember(Name = "command", EmitDefaultValue = false)]
        public string command;
        [DataMember(Name = "locale", EmitDefaultValue = false)]
        public string locale = "en_US";
        [DataMember(Name = "client_version", EmitDefaultValue = false)]
        public string clientVersion = ClientVersion;
    }

    /// <summary>
    /// Base Keeper Response
    /// </summary>
    [DataContract]
    public class KeeperApiResponse
    {
        [DataMember(Name = "result", EmitDefaultValue = false)]
        public string result;
        [DataMember(Name = "result_code", EmitDefaultValue = false)]
        public string resultCode;
        [DataMember(Name = "message", EmitDefaultValue = false)]
        public string message;
        [DataMember(Name = "command", EmitDefaultValue = false)]
        public string command;

        public bool IsSuccess => result == "success";
    }

    /// <summary>
    /// REST Keeper Response
    /// </summary>
    [DataContract]
    public class KeeperApiErrorResponse : KeeperApiResponse
    {
        [DataMember(Name = "error", EmitDefaultValue = false)]
        public string Error { get; set; }
        [DataMember(Name = "key_id")]
        public int KeyId { get; set; }
        [DataMember(Name = "region_host")]
        public string RegionHost { get; set; }
    }

    /// <summary>
    /// Login command
    /// </summary>
    [DataContract]
    public class LoginCommand : KeeperApiCommand
    {
        public LoginCommand() : base("login")
        {
        }
        [DataMember(Name = "version")]
        public int version = 2;
        [DataMember(Name = "include")]
        public string[] include;
        [DataMember(Name = "auth_response")]
        public string authResponse;
        [DataMember(Name = "username")]
        public string username;
        [DataMember(Name = "2fa_type", EmitDefaultValue = false)]
        public string twoFactorType;
        [DataMember(Name = "2fa_token", EmitDefaultValue = false)]
        public string twoFactorToken;
        [DataMember(Name = "device_token_expire_days", EmitDefaultValue = false)]
        public int? deviceTokenExpiresInDays;
    }

    /// <summary>
    /// Login response
    /// </summary>
    [DataContract]
    public class AccountKeys
    {
        [DataMember(Name = "encryption_params")]
        public string encryptionParams;
        [DataMember(Name = "encrypted_data_key")]
        public string encryptedDataKey;
        [DataMember(Name = "encrypted_private_key")]
        public string encryptedPrivateKey;
        [DataMember(Name = "data_key_backup_date")]
        public long? dataKeyBackupDate;
    }
    [DataContract]
    public class AccountEnforcements
    {
        [DataMember(Name = "password_rules_intro")]
        public string passwordRulesIntro;

        [DataMember(Name = "password_rules")]
        public PasswordRule[] passwordRules;
    }
    [DataContract]
    public class AccountShareTo
    {
        [DataMember(Name = "role_id")]
        public long roleId;
        [DataMember(Name = "public_key")]
        public string publicKey;
    }

    [DataContract]
    public class PasswordRule
    {
        [DataMember(Name = "match")]
        public bool match;

        [DataMember(Name = "pattern")]
        public string pattern;

        [DataMember(Name = "description")]
        public string description;
    }

    [DataContract]
    public class AccountSettings
    {
        [DataMember(Name = "password_rules_intro")]
        public string passwordRulesIntro;

        [DataMember(Name = "password_rules")]
        public PasswordRule[] passwordRules;

        [DataMember(Name = "channel")]
        public string channel;

        [DataMember(Name = "sso_user")]
        public bool? ssoUser;

        [DataMember(Name = "must_perform_account_share_by")]
        public long? mustPerformAccountShareBy;

        [DataMember(Name = "share_account_to")]
        public AccountShareTo[] shareAccountTo;

        [DataMember(Name = "master_password_last_modified")]
        public long? masterPasswordLastModified;

        [DataMember(Name = "email_verified")]
        public string email_verified;
    }

    [DataContract]
    public class LoginResponse : KeeperApiResponse
    {
        [DataMember(Name = "session_token")]
        public string sessionToken;
        [DataMember(Name = "device_token")]
        public string deviceToken;
        [DataMember(Name = "dt_scope")]
        public string deviceTokenScope;
        /*
        "two_factor_channel_sms" - Users receive a TOTP code via text message.
        "two_factor_channel_voice" - Users receive a TOTP code via phone call.
        "two_factor_channel_google" - Users look up TOTP codes on their Google Authenticator app.
        "two_factor_channel_rsa" - Users authenticate against an RSA server, using either a generated passcode or a pin.
        "two_factor_channel_duo" - Users authenticate through Duo Security.
        "two_factor_channel_u2f" - Users authenticate with a U2F Security Key, using challenge-response.
        */
        [DataMember(Name = "channel")]
        public string channel;
        [DataMember(Name = "client_key")]
        public string clientKey;
        [DataMember(Name = "is_enterprise_admin")]
        public bool? isEnterpriseAdmin;

        [DataMember(Name = "settings")]
        public AccountSettings accountSettings;
        [DataMember(Name = "keys")]
        public AccountKeys keys;
        [DataMember(Name = "enforcements")]
        public AccountEnforcements enforcements;

        [DataMember(Name = "iterations")]
        public int? iterations;
        [DataMember(Name = "salt")]
        public string salt;
    }

    [DataContract]
    public class AuthorizedCommand : KeeperApiCommand
    {
        public AuthorizedCommand(string command) : base(command)
        {
            deviceId = "C# Keeper API";
        }

        [DataMember(Name = "device_id")]
        public string deviceId;

        [DataMember(Name = "session_token")]
        public string sessionToken;

        [DataMember(Name = "username")]
        public string username;
    }

}
