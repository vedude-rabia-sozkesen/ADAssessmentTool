using System;
using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Active Directory ortamında uzun süredir (90 gün+) oturum açmamış atıl kalmış kullanıcı hesaplarını tespit eden kural sınıfı.
    /// </summary>
    public sealed class StaleUserAccountsRule : IComplianceRule
    {
        public string RuleId => "AD-005";

        public string Name => "Pasif / Atıl Kalmış Hesaplar (90+ Gün)";

        public string Description => "Uzun süredir (90 günden fazla) Active Directory üzerinde oturum açmamış aktif kullanıcı hesapları, saldırganlar tarafından fark edilmeden ilk erişim (Initial Access) veya kalıcılık sağlama amacıyla suiistimal edilebilir.";

        public string FrameworkMapping => "CIS Controls v8 - 5.3 / MITRE ATT&CK T1078.002 (Domain Accounts)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.5.18 (Access Rights)";

        public string Remediation => "1. Etkilenen atıl hesapların aktif olarak kullanılıp kullanılmadığını doğrulayın.\n" +
                                     "2. Kullanılmayan veya ayrılan personellere ait hesapları devre dışı bırakın (Disable) veya silin.";

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
            var thresholdDate = DateTime.UtcNow.AddDays(-90);

            foreach (var user in userList)
            {
                bool isComputerAccount = !string.IsNullOrEmpty(user.SamAccountName) && user.SamAccountName.EndsWith("$");

                // Son logon tarihi 90 günden eski veya hiç oturum açmamış aktif hesaplar
                bool isStale = !user.LastLogonTimestamp.HasValue || user.LastLogonTimestamp.Value < thresholdDate;

                if (user.IsEnabled && isStale && !isComputerAccount)
                {
                    string lastLogonInfo = user.LastLogonTimestamp.HasValue
                        ? user.LastLogonTimestamp.Value.ToString("yyyy-MM-dd")
                        : "Hiç Oturum Açmadı";

                    string riskDetail = user.IsAdminCountSet ? "[KRİTİK YETKİLİ]" : "[STANDART HESAP]";
                    vulnerableAccounts.Add($"{riskDetail} {user.SamAccountName} (Son Oturum: {lastLogonInfo})");
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
