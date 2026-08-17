using System;
using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Active Directory ortamında parola kullanım süresi sınırsız olarak yapılandırılmış
    /// (DONT_EXPIRE_PASSWORD) aktif hesapları tespit eden kural sınıfı.
    /// </summary>
    public sealed class PasswordNeverExpiresRule : IComplianceRule
    {
        public string RuleId => "AD-003";

        public string Name => "Parolası Hiç Süresi Dolmayan Hesaplar";

        public string Description => "Parola kullanım süresi sınırsız olarak ayarlanan hesaplar, ele geçirilmeleri durumunda saldırganlara uzun süreli ve tespiti zor kalıcılık (Persistence) imkanı sağlar.";

        public string FrameworkMapping => "CIS Controls v8 - 5.2 / MITRE ATT&CK T1078 (Valid Accounts)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.5.17 (Authentication Information)";

        public string Remediation => "1. Zorunlu olmayan hesaplarda 'Password never expires' seçeneğini kaldırın.\n" +
                                     "2. Servis hesaplarında bu seçenek zorunluysa, parolayı en az 25 karakterli karmaşık hale getirin ve gMSA mimarisine geçin.\n" +
                                     "3. Etkilenen hesapları periyodik parola değiştirme politikasına dahil edin.";

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

                if (user.IsEnabled && user.IsPasswordNeverExpires && !isComputerAccount)
                {
                    string riskDetail = user.IsAdminCountSet ? "[KRİTİK YETKİLİ]" : "[STANDART HESAP]";
                    vulnerableAccounts.Add($"{riskDetail} {user.SamAccountName}");
                }
            }

            return new RuleResult
            {
                RuleId = this.RuleId,
                IsVulnerable = vulnerableAccounts.Count > 0,
                RiskLevel = vulnerableAccounts.Count > 0 ? "Medium" : "Low",
                AffectedObjects = vulnerableAccounts,
                Remediation = this.Remediation
            };
        }
    }
}
