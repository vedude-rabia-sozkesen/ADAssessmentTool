using System;
using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Active Directory ortamında Sınırsız Kerberos Delegasyonu (Unconstrained Delegation) yetkisi verilmiş hesapları tespit eden kural sınıfı.
    /// </summary>
    public sealed class UnconstrainedDelegationRule : IComplianceRule
    {
        public string RuleId => "AD-006";

        public string Name => "Sınırsız Delegasyon Yetkili Hesaplar (Unconstrained Delegation)";

        public string Description => "Sınırsız Kerberos Delegasyonu (TRUSTED_FOR_DELEGATION) yetkisi olan hesaplar, bu servise bağlanan tüm kullanıcıların (Domain Admin'ler dahil) Kerberos TGT biletlerini belleğe kaydeder. Saldırganlar bu biletleri çalarak Domain Controller'ı ele geçirebilir.";

        public string FrameworkMapping => "MITRE ATT&CK T1558 (Steal or Forge Kerberos Tickets)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.8.2 (Privileged Access Rights)";

        public string Remediation => "1. Zorunlu olmadıkça kullanıcı/servis hesaplarında Sınırsız Delegasyonu kaldırın.\n" +
                                     "2. Delegasyon gerekiyorsa Resource-Based Constrained Delegation (RBCD) veya Constrained Delegation mimarisine geçin.\n" +
                                     "3. Hassas kullanıcı ve admin hesaplarını 'Account is sensitive and cannot be delegated' olarak işaretleyin veya Protected Users grubuna ekleyin.";

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
                // Sınırsız delegasyona sahip kullanıcı hesapları (Domain Controller hesabı hariç tutulabilir veya dahil edilebilir)
                bool isComputerAccount = !string.IsNullOrEmpty(user.SamAccountName) && user.SamAccountName.EndsWith("$");

                if (user.IsEnabled && user.IsUnconstrainedDelegation && !isComputerAccount)
                {
                    string riskDetail = user.IsAdminCountSet ? "[KRİTİK YETKİLİ]" : "[STANDART SERVİS]";
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
