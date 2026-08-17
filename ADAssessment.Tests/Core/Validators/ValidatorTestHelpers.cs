using System.Collections.Generic;
using ADAssessment.Core;

namespace ADAssessment.Tests.Core.Validators
{
    /// <summary>
    /// 10 sabit IComplianceRule implementasyonunun ortak "enabled + flag +
    /// bilgisayar hesabı değil" deseni için tekrarlanan AdUserAccount kurulumunu
    /// tek yerden sağlayan test yardımcı sınıfı.
    /// </summary>
    internal static class ValidatorTestHelpers
    {
        public const int Enabled = 0x0200;
        public const int Disabled = 0x0202; // enabled bit'i de içerir, ACCOUNTDISABLE üstün gelir

        public static AdUserAccount User(string samAccountName, int uac, bool isAdminCountSet = false, IReadOnlyList<string>? spns = null, System.DateTime? passwordLastSet = null, System.DateTime? lastLogonTimestamp = null, bool isCannotChangePassword = false)
        {
            return new AdUserAccount
            {
                SamAccountName = samAccountName,
                UserAccountControl = uac,
                IsAdminCountSet = isAdminCountSet,
                ServicePrincipalNames = spns ?? System.Array.Empty<string>(),
                PasswordLastSet = passwordLastSet,
                LastLogonTimestamp = lastLogonTimestamp,
                IsCannotChangePassword = isCannotChangePassword
            };
        }

        public static List<AdUserAccount> SingleUserList(AdUserAccount user) => new() { user };
    }
}
