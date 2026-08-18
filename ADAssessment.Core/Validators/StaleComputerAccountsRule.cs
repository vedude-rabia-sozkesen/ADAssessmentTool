using System;
using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Uzun süredir (90 gün+) domain'e hiç oturum açmamış, ama hâlâ etkin (enabled) kalan
    /// bilgisayar hesaplarını tespit eder. AdUserAccount için StaleUserAccountsRule'ün (AD-005)
    /// bilgisayar nesneleri üzerindeki karşılığıdır - kullanılmayan bir makine hesabı, saldırgan
    /// tarafından ele geçirilip fark edilmeden domain'e sızmak için kullanılabilir.
    /// </summary>
    public sealed class StaleComputerAccountsRule : IComputerComplianceRule
    {
        public string RuleId => "AD-016";

        public string Name => "Pasif / Atıl Kalmış Bilgisayar Hesapları (90+ Gün)";

        public string Description => "Uzun süredir (90 günden fazla) domain'e oturum açmamış ama hâlâ etkin (enabled) bilgisayar hesapları, ele geçirilip fark edilmeden domain'e erişim sağlamak için kullanılabilir.";

        public string FrameworkMapping => "CIS Controls v8 - 5.3 / MITRE ATT&CK T1078.002 (Domain Accounts)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.5.18 (Access Rights)";

        public string Remediation => "1. Etkilenen bilgisayar hesaplarının fiziksel/sanal olarak hâlâ var olup olmadığını doğrulayın.\n" +
                                     "2. Artık kullanılmayan makine hesaplarını devre dışı bırakın (Disable) veya silin.";

        public RuleResult Execute(object directoryData)
        {
            if (directoryData is not IEnumerable<AdComputerAccount> computerList)
            {
                return new RuleResult
                {
                    RuleId = this.RuleId,
                    IsVulnerable = false,
                    RiskLevel = "Informational",
                    Remediation = "Analiz edilecek geçerli veri sağlanamadı."
                };
            }

            var vulnerableComputers = new List<string>();
            var thresholdDate = DateTime.UtcNow.AddDays(-90);

            foreach (var computer in computerList)
            {
                bool isStale = !computer.LastLogonTimestamp.HasValue || computer.LastLogonTimestamp.Value < thresholdDate;

                if (computer.IsEnabled && isStale)
                {
                    string lastLogonInfo = computer.LastLogonTimestamp.HasValue
                        ? computer.LastLogonTimestamp.Value.ToString("yyyy-MM-dd")
                        : "Hiç Oturum Açmadı";

                    vulnerableComputers.Add($"{computer.SamAccountName} (Son Oturum: {lastLogonInfo})");
                }
            }

            return new RuleResult
            {
                RuleId = this.RuleId,
                IsVulnerable = vulnerableComputers.Count > 0,
                RiskLevel = vulnerableComputers.Count > 0 ? "Medium" : "Low",
                AffectedObjects = vulnerableComputers,
                Remediation = this.Remediation
            };
        }
    }
}
