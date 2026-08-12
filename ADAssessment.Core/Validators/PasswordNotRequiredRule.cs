using System;
using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Active Directory ortamında parola gerektirmeyen (PASSWD_NOTREQD) hesapları tespit eden kural sınıfı.
    /// </summary>
    public sealed class PasswordNotRequiredRule : IComplianceRule
    {
        public string RuleId => "AD-004";

        public string Name => "Parola Gerektirmeyen Hesaplar";

        public string Description => "Parola gerektirmeyen (PASSWD_NOTREQD) olarak işaretlenmiş hesaplar, boş şifre ile veya şifresiz oturum açılmasına izin vererek kritik güvenlik zafiyeti oluşturur.";

        public string FrameworkMapping => "CIS Controls v8 - 5.2 / MITRE ATT&CK T1078 (Valid Accounts)";

        public string Remediation => "1. Etkilenen hesapların özelliklerinden 'Password Not Required' seçeneğini kaldırın.\n" +
                                     "2. Tüm kullanıcılara güçlü ve karmaşık parolalar atayın ve boş parola kullanımını engelleyin.";

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

                if (user.IsEnabled && user.IsPasswordNotRequired && !isComputerAccount)
                {
                    string riskDetail = user.IsAdminCountSet ? "[KRİTİK YETKİLİ]" : "[STANDART HESAP]";
                    vulnerableAccounts.Add($"{riskDetail} {user.SamAccountName}");
                }
            }

            return new RuleResult
            {
                RuleId = this.RuleId,
                IsVulnerable = vulnerableAccounts.Count > 0,
                RiskLevel = vulnerableAccounts.Count > 0 ? "High" : "Low",
                AffectedObjects = vulnerableAccounts,
                Remediation = this.Remediation
            };
        }
    }
}
