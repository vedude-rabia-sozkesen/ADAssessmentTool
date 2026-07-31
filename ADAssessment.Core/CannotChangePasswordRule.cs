using System;
using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Active Directory ortamında kullanıcının kendi parolasını değiştirmesi engellenmiş (PASSWD_CANT_CHG) hesapları tespit eden kural sınıfı.
    /// </summary>
    public sealed class CannotChangePasswordRule : IComplianceRule
    {
        public string RuleId => "AD-008";

        public string Name => "Parolası Değiştirilemeyen Hesaplar";

        public string Description => "Kullanıcının şifresini değiştirmesini engelleyen (PASSWD_CANT_CHG) bayrağı aktif olan hesaplar, şifrenin sızması durumunda kullanıcının şifreyi kendi imkanlarıyla yenilemesini imkansız kılar.";

        public string FrameworkMapping => "CIS Controls v8 - 5.2 / MITRE ATT&CK T1078 (Valid Accounts)";

        public string Remediation => "1. Etkilenen hesapların özelliklerinden 'User cannot change password' seçeneğindeki işareti kaldırın.\n" +
                                     "2. Kullanıcıların periyodik parola hijyenine uymasını sağlayın.";

        public RuleResult Execute(object directoryData)
        {
            if (directoryData is not IEnumerable<AdUserAccount> userList)
            {
                return new RuleResult
                {
                    RuleId = this.RuleId,
                    IsVulnerable = false,
                    RiskLevel = "Informational",
                    Remediation = "Analiz edilecek geçerli veri sağlanamadı."
                };
            }

            var vulnerableAccounts = new List<string>();

            foreach (var user in userList)
            {
                bool isComputerAccount = !string.IsNullOrEmpty(user.SamAccountName) && user.SamAccountName.EndsWith("$");

                if (user.IsEnabled && user.IsCannotChangePassword && !isComputerAccount)
                {
                    string riskDetail = user.IsAdminCountSet ? "[KRİTİK YETKİLİ]" : "[STANDART HESAP]";
                    vulnerableAccounts.Add($"{riskDetail} {user.SamAccountName}");
                }
            }

            return new RuleResult
            {
                RuleId = this.RuleId,
                IsVulnerable = vulnerableAccounts.Count > 0,
                RiskLevel = vulnerableAccounts.Count > 0 ? "Low" : "Low",
                AffectedObjects = vulnerableAccounts,
                Remediation = this.Remediation
            };
        }
    }
}
