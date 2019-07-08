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
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace KeeperSecurity.Sdk
{
    [DataContract]
    public class ChangeMasterPasswordCommand : AuthorizedCommand
    {
        public ChangeMasterPasswordCommand() : base("change_master_password") { }
        [DataMember(Name = "auth_verifier")]
        public string authVerifier;

        [DataMember(Name = "encryption_params")]
        public string encryptionParams;
    }


    [DataContract]
    public class ShareAccountCommand : AuthorizedCommand
    {
        public ShareAccountCommand() : base("share_account") { }
        [DataMember(Name = "to_role_id")]
        public long toRoleId;

        [DataMember(Name = "transfer_key")]
        public string transferTey;
    }

    public class PasswordRuleMatcher { 
        public string RuleIntro { get; }
        public PasswordRule[] Rules { get; }

        public PasswordRuleMatcher(string ruleIntro, PasswordRule[] rules) {
            RuleIntro = ruleIntro;
            Rules = rules;
        }

        public string[] MatchFailedRules(string password) {
            return Rules?
                .Where(x => {
                    var match = Regex.IsMatch(password, x.pattern);
                    if (!x.match) {
                        match = !match;
                    }
                    return !match;
                })
                .Select(x => x.description).ToArray();
        }
    }

    public static class ManageAccountExtension
    {
        public static async Task ShareAccount(this AuthContext auth) {
            if (auth.accountSettings?.shareAccountTo != null) {
                foreach (var shareTo in auth.accountSettings.shareAccountTo)
                {
                    var key = CryptoUtils.LoadPublicKey(shareTo.publicKey.Base64UrlDecode());
                    var command = new ShareAccountCommand();
                    command.toRoleId = shareTo.roleId;
                    command.transferTey = CryptoUtils.EncryptRsa(auth.DataKey, key).Base64UrlEncode();
                    await auth.ExecuteAuthCommand(command);
                }
                auth.accountSettings.shareAccountTo = null;
            }
        }

        public static async Task<string> ChangeMasterPassword(this AuthContext auth, int iterations)
        {
            string passwordRulesIntro = auth.accountSettings?.passwordRulesIntro;
            PasswordRule[] passwordRules = auth.accountSettings?.passwordRules;
            if (passwordRules == null)
            {
                var userParams = await auth.Api.GetNewUserParams(auth.Username);
                passwordRules = userParams.PasswordMatchRegex
                    .Zip(userParams.PasswordMatchDescription, (rx, d) => new PasswordRule
                    {
                        match = true,
                        pattern = rx,
                        description = d
                    })
                    .ToArray();
            }
            var ruleMatcher = new PasswordRuleMatcher(passwordRulesIntro, passwordRules);
            var password = await auth.Ui.GetNewPassword(ruleMatcher);
            var failedRules = ruleMatcher.MatchFailedRules(password);
            if (failedRules.Length == 0)
            {
                var authSalt = CryptoUtils.GetRandomBytes(16);
                var authVerifier = CryptoUtils.CreateAuthVerifier(password, authSalt, iterations);
                var keySalt = CryptoUtils.GetRandomBytes(16);
                var encryptionParameters = CryptoUtils.CreateEncryptionParams(password, authSalt, iterations, auth.DataKey);

                var command = new ChangeMasterPasswordCommand();
                command.authVerifier = authVerifier.Base64UrlEncode();
                command.encryptionParams = encryptionParameters.Base64UrlEncode();

                await auth.ExecuteAuthCommand(command);
                return password;
            }
            throw new KeeperApiException("password_rule_failed", failedRules[0]);
        }
    }


}
