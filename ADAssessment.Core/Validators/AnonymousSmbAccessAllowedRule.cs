using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Domain Controller'ın, kimlik doğrulaması yapılmamış (null session) bir bağlantının
    /// IPC$ paylaşımına erişmesine izin verip vermediğini tespit eder. Orange Cyberdefense
    /// AD Mindmap'te "Anonymous &amp; Guest access on SMB shares" aşamasına karşılık gelir -
    /// bu erişim mümkünse, hiçbir kimlik bilgisi olmayan bir saldırgan bile SAM/LSA
    /// politika sorgularıyla kullanıcı ve grup listesini çıkarabilir.
    /// </summary>
    public sealed class AnonymousSmbAccessAllowedRule : ISmbProtocolComplianceRule
    {
        public string RuleId => "AD-022";

        public string Name => "Anonim SMB Erişimine İzin Veriliyor (Null Session)";

        public string Description => "Domain Controller, kimlik doğrulaması yapılmamış (boş kullanıcı adı + boş şifre) bir bağlantının IPC$ paylaşımına erişmesine izin veriyor. Hiçbir kimlik bilgisi olmayan bir saldırgan bile SAM/LSA politika sorgularıyla kullanıcı ve grup listesini çıkarabilir.";

        public string FrameworkMapping => "CIS Controls v8 - 3.3 / MITRE ATT&CK T1135 (Network Share Discovery)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.8.5 (Secure Authentication)";

        public string Remediation => "1. 'Network access: Restrict anonymous access to Named Pipes and Shares' politikasının etkin olduğunu doğrulayın.\n" +
                                     "2. 'Network access: Let Everyone permissions apply to anonymous users' politikasının devre dışı olduğunu doğrulayın.\n" +
                                     "3. 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' politikasının etkin olduğunu doğrulayın.";

        public RuleResult Execute(object directoryData)
        {
            if (directoryData is not SmbProtocolSecuritySettings settings)
            {
                return new RuleResult
                {
                    RuleId = this.RuleId,
                    IsVulnerable = false,
                    RiskLevel = "Informational",
                    Remediation = "Analiz edilecek geçerli veri sağlanamadı."
                };
            }

            bool isVulnerable = settings.IsAnonymousAccessAllowed;

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
