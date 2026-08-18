using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Domain Controller'ın, kimlik bilgilerinin bütünlük korumasız (imzasız) bir kanal
    /// üzerinden gönderilmesine izin verip vermediğini tespit eder. Microsoft'un
    /// ADV190023 güvenlik danışma belgesinde (2020) ele aldığı bir sertleştirme
    /// (hardening) ayarıdır - varsayılan olarak birçok ortamda hâlâ etkin değildir.
    /// </summary>
    public sealed class LdapSigningNotEnforcedRule : ILdapProtocolComplianceRule
    {
        public string RuleId => "AD-019";

        public string Name => "LDAP İmzalama Zorunlu Değil (LDAP Signing Not Enforced)";

        public string Description => "Domain Controller, imzasız (bütünlük korumasız) bir kanal üzerinden gelen basit (simple) bind isteklerini reddetmiyor. Bu, bir saldırganın ağ üzerindeki bir kimlik doğrulama denemesini yakalayıp başka bir hedefe iletebildiği (LDAP relay) saldırılara karşı DC'yi savunmasız bırakır.";

        public string FrameworkMapping => "CIS Controls v8 - 3.10 / MITRE ATT&CK T1557 (Adversary-in-the-Middle)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.8.20 (Networks Security)";

        public string Remediation => "1. Domain Controller'larda 'Domain controller: LDAP server signing requirements' Group Policy ayarını 'Require signing' olarak ayarlayın.\n" +
                                     "2. Değişiklik öncesi, imzalamayı desteklemeyen eski istemci/uygulamalar olup olmadığını test edin.\n" +
                                     "3. Mümkünse eş zamanlı olarak LDAP channel binding'i de zorunlu kılın (ADV190023).";

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

            bool isVulnerable = !settings.IsSigningEnforced;

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
