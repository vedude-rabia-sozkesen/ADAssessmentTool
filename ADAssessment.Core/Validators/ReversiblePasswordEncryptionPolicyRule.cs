using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// SYSVOL üzerindeki GptTmpl.inf'te "Store passwords using reversible encryption"
    /// politikasının domain genelinde açık olup olmadığını tespit eden kural sınıfı.
    /// AD-009'un (kullanıcı bazlı) domain-politikası seviyesindeki karşılığıdır -
    /// burada açık olması, politikaya bağlı TÜM hesapların parolasının düz metne
    /// dönüştürülebilir şekilde saklanması anlamına gelir.
    /// </summary>
    public sealed class ReversiblePasswordEncryptionPolicyRule : IGroupPolicyComplianceRule
    {
        public string RuleId => "AD-014";

        public string Name => "Domain Genelinde Geri Dönüştürülebilir Şifreleme Politikası";

        public string Description => "Group Policy üzerinde 'Store passwords using reversible encryption' ayarı etkinleştirilmiş. Bu, o politikaya bağlı tüm hesapların parolalarının NTDS.dit içinde düz metne dönüştürülebilir şekilde saklanmasına yol açar - AD-009'dan farklı olarak tek bir hesabı değil, politikaya bağlı tüm hesapları etkiler.";

        public string FrameworkMapping => "CIS Controls v8 - 5.2 / MITRE ATT&CK T1552.001 (Credentials in Files)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.8.24 (Use of Cryptography)";

        public string Remediation => "1. Grup İlkesi Yönetim Konsolu'ndan (GPMC) ilgili GPO'yu düzenleyin.\n" +
                                     "2. 'Store passwords using reversible encryption' ayarını 'Disabled' yapın.\n" +
                                     "3. Bu politikaya bağlı tüm hesapların parolalarını hemen değiştirmesini sağlayın.";

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
                if (policy.ReversibleEncryptionEnabled)
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
