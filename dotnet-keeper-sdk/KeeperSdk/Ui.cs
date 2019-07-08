using System;
using System.Threading.Tasks;

namespace KeeperSecurity.Sdk.UI
{
    public enum DialogType
    {
        Information,
        Confirmation,
    }
    public interface IAuthUI
    {
        Task<bool> DisplayDialog(DialogType dialog, string information);
        Task<IUserCredentials> GetUserCredentials(IUserCredentials credentials);
        Task<string> GetTwoFactorCode();
        Task<string> GetNewPassword(PasswordRuleMatcher matcher);
    }
}
