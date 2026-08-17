using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// SYSVOL üzerindeki GptTmpl.inf'ten okunan hesap kilitleme (account lockout)
    /// politikasının domain genelinde tanımlı olup olmadığını tespit eden kural
    /// sınıfı. Eşik değeri 0 ise, kilitleme hiç devreye girmez ve sınırsız sayıda
    /// parola denemesine (brute-force) izin verilmiş olur.
    /// </summary>
    public sealed class WeakLockoutPolicyRule : IGroupPolicyComplianceRule
    {
        public string RuleId => "AD-015";

        public string Name => "Zayıf Hesap Kilitleme Politikası (Brute-Force Koruması Yok)";

        public string Description => "Group Policy üzerinde hesap kilitleme eşiği (LockoutBadCount) 0 olarak ayarlanmış - yani hesaplar hiç kilitlenmiyor. Bu, politikaya bağlı tüm hesapların sınırsız sayıda yanlış parola denemesine (brute-force / kaba kuvvet saldırısı) açık olduğu anlamına gelir.";

        public string FrameworkMapping => "CIS Controls v8 - 5.2 / MITRE ATT&CK T1110 (Brute Force)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.8.5 (Secure Authentication)";

        public string Remediation => "1. Grup İlkesi Yönetim Konsolu'ndan (GPMC) ilgili GPO'yu düzenleyin.\n" +
                                     "2. 'Account lockout threshold' değerini makul bir sayıya (örn. 5-10) ayarlayın.\n" +
                                     "3. 'Account lockout duration' ve 'Reset account lockout counter after' değerlerini de gözden geçirin.";

        public RuleResult Execute(object directoryData)
        {
            if (directoryData is not IEnumerable<GroupPolicySecuritySettings> policies)
            {
                return new RuleResult
                {
                    RuleId = this.RuleId,
                    IsVulnerable = false,
                    RiskLevel = "Informational",
                    Remediation = "Analiz edilecek geçerli veri sağlanamadı."
                };
            }

            var vulnerablePolicies = new List<string>();

            foreach (var policy in policies)
            {
                if (policy.LockoutThreshold == 0)
                {
                    vulnerablePolicies.Add(policy.GpoName);
                }
            }

            return new RuleResult
            {
                RuleId = this.RuleId,
                IsVulnerable = vulnerablePolicies.Count > 0,
                RiskLevel = vulnerablePolicies.Count > 0 ? "High" : "Low",
                AffectedObjects = vulnerablePolicies,
                Remediation = this.Remediation
            };
        }
    }
}
