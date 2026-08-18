using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Domain Controller'ın, LDAPS (TLS şifreli) bağlantılarda Channel Binding Token
    /// (CBT) olmadan gelen bind isteklerini reddedip reddetmediğini tespit eder.
    /// LDAP signing'den (AD-019) farklı bir zafiyet yüzeyi - TLS zaten kurulmuş olsa
    /// bile, yakalanmış bir kimlik doğrulama işleminin başka bir TLS oturumuna
    /// aktarılıp tekrar oynatılmasına (relay) karşı korumasızlığı hedefler
    /// (Microsoft ADV190023 - LDAP signing ile aynı danışma belgesinde ele alınır).
    /// </summary>
    public sealed class LdapChannelBindingNotEnforcedRule : ILdapProtocolComplianceRule
    {
        public string RuleId => "AD-020";

        public string Name => "LDAP Channel Binding Zorunlu Değil";

        public string Description => "Domain Controller, LDAPS (TLS şifreli) bağlantılarda Channel Binding Token olmadan gelen bind isteklerini reddetmiyor. TLS şifreleme kendi başına yeterli değildir - bu koruma olmadan, yakalanmış bir kimlik doğrulama işlemi başka bir TLS oturumuna aktarılıp tekrar oynatılabilir (relay saldırısı).";

        public string FrameworkMapping => "CIS Controls v8 - 3.10 / MITRE ATT&CK T1557 (Adversary-in-the-Middle)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.8.20 (Networks Security)";

        public string Remediation => "1. Domain Controller'larda 'LdapEnforceChannelBinding' registry değerini 2 (Always) olarak ayarlayın (Microsoft ADV190023).\n" +
                                     "2. Değişiklik öncesi, channel binding'i desteklemeyen eski istemci/uygulamalar olup olmadığını test edin.\n" +
                                     "3. LDAP signing zorunluluğuyla (AD-019) birlikte, eş zamanlı olarak uygulayın.";

        public RuleResult Execute(object directoryData)
        {
            if (directoryData is not LdapProtocolSecuritySettings settings)
            {
                return new RuleResult
                {
                    RuleId = this.RuleId,
                    IsVulnerable = false,
                    RiskLevel = "Informational",
                    Remediation = "Analiz edilecek geçerli veri sağlanamadı."
                };
            }

            bool isVulnerable = !settings.IsChannelBindingEnforced;

            return new RuleResult
            {
                RuleId = this.RuleId,
                IsVulnerable = isVulnerable,
                RiskLevel = isVulnerable ? "High" : "Low",
                AffectedObjects = isVulnerable
                    ? new List<string> { settings.DomainController }
                    : System.Array.Empty<string>(),
                Remediation = this.Remediation
            };
        }
    }
}
