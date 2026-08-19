using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Domain'in kök nesnesi üzerinde, "DCSync" saldırısını mümkün kılan replikasyon
    /// haklarına (DS-Replication-Get-Changes / DS-Replication-Get-Changes-All) sahip,
    /// varsayılan/beklenen olmayan (Domain Admins, Enterprise Admins, BUILTIN\Administrators,
    /// Enterprise Domain Controllers, SYSTEM dışında) bir asıl güvenlik prensibi olup
    /// olmadığını tespit eder. Bu haklara sahip olan biri, hiçbir DC'ye giriş yapmadan,
    /// tüm domain'in parola hash'lerini (krbtgt dahil) çekebilir - AD'nin en kritik
    /// zafiyet kategorilerinden biridir.
    /// </summary>
    public sealed class UnexpectedDcSyncRightsRule : IDcSyncComplianceRule
    {
        public string RuleId => "AD-023";

        public string Name => "Beklenmeyen DCSync Hakları (Unexpected Replication Rights)";

        public string Description => "Domain'in kök nesnesi üzerinde, DCSync saldırısını mümkün kılan replikasyon haklarına (Replicating Directory Changes / Replicating Directory Changes All) sahip, varsayılan olmayan bir hesap veya grup tespit edildi. Bu haklara sahip biri, hiçbir Domain Controller'a giriş yapmadan tüm domain'in parola hash'lerini (krbtgt dahil) çekebilir.";

        public string FrameworkMapping => "CIS Controls v8 - 6.8 / MITRE ATT&CK T1003.006 (OS Credential Dumping: DCSync)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.8.2 (Privileged Access Rights)";

        public string Remediation => "1. Tespit edilen hesap/grubun bu haklara neden sahip olduğunu acilen araştırın (örn. bir senkronizasyon aracının aşırı geniş yetkilendirilmiş olması).\n" +
                                     "2. Gerçekten gerekli değilse bu hakları derhal kaldırın.\n" +
                                     "3. Meşru bir ihtiyaçsa (örn. Azure AD Connect), hesabı en az yetki ilkesiyle yeniden yapılandırmayı değerlendirin.\n" +
                                     "4. Bu hesabın parolasını hemen değiştirin ve ele geçirilip geçirilmediğini araştırın.";

        public RuleResult Execute(object directoryData)
        {
            if (directoryData is not DcSyncRightsSettings settings)
            {
                return new RuleResult
                {
                    RuleId = this.RuleId,
                    IsVulnerable = false,
                    RiskLevel = "Informational",
                    Remediation = "Analiz edilecek geçerli veri sağlanamadı."
                };
            }

            bool isVulnerable = settings.UnexpectedPrincipals.Count > 0;

            return new RuleResult
            {
                RuleId = this.RuleId,
                IsVulnerable = isVulnerable,
                RiskLevel = isVulnerable ? "High" : "Low",
                AffectedObjects = settings.UnexpectedPrincipals,
                Remediation = this.Remediation
            };
        }
    }
}
