using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Kimlik doğrulaması yapılmamış (anonim) bir istemcinin, domain'in kendi veri
    /// bölümünde gerçek dizin nesnelerini (kullanıcılar vb.) arayıp okuyabildiğini
    /// tespit eder. Bu, hiçbir kimlik bilgisi olmayan bir saldırganın bile tüm
    /// kullanıcı listesini çıkarabilmesi (Orange Cyberdefense AD Mindmap'te
    /// "Enumerate LDAP" aşaması) anlamına gelir - bir saldırının en erken keşif
    /// aşamalarından birini tamamen ortadan kaldırır.
    /// </summary>
    public sealed class AnonymousLdapBindAllowedRule : ILdapProtocolComplianceRule
    {
        public string RuleId => "AD-021";

        public string Name => "Anonim LDAP Bağlantısına İzin Veriliyor (Anonymous LDAP Bind Allowed)";

        public string Description => "Domain Controller, kimlik doğrulaması yapılmamış (anonim) bir bağlantının domain'in kendi veri bölümünde gerçek kullanıcı nesnelerini aramasına izin veriyor. Hiçbir kimlik bilgisi olmayan bir saldırgan bile tüm kullanıcı listesini çıkarabilir.";

        public string FrameworkMapping => "CIS Controls v8 - 3.3 / MITRE ATT&CK T1087.002 (Account Discovery: Domain Account)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.8.5 (Secure Authentication)";

        public string Remediation => "1. 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' politikasının etkin olduğunu doğrulayın.\n" +
                                     "2. dsHeuristics özniteliğinin (Configuration partition) anonim LDAP erişimini kısıtladığından emin olun.\n" +
                                     "3. 'Anonymous Logon' asıl güvenlik prensibinin domain nesneleri üzerinde okuma izni olmadığını doğrulayın.";

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

            bool isVulnerable = settings.IsAnonymousBindAllowed;

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
