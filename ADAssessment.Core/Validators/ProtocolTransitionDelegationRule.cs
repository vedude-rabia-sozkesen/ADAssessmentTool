using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Kısıtlı Delegasyon + Protokol Geçişi (Constrained Delegation with Protocol Transition).
    /// TRUSTED_TO_AUTH_FOR_DELEGATION (UAC 0x1000000) bayrağı, bir hesabın S4U2Self Kerberos
    /// uzantısıyla HEDEF KULLANICININ PAROLASINI HİÇ BİLMEDEN o kullanıcı adına bir bilet
    /// talep edebilmesini sağlar. msDS-AllowedToDelegateTo listesiyle birlikte kullanıldığında,
    /// bu hesabı ele geçiren bir saldırgan listelenen hedeflere karşı HERHANGİ BİR domain
    /// kullanıcısı (Domain Admin dahil) gibi davranabilir - sınırsız delegasyona (AD-006/
    /// AD-024) yakın bir risk taşır, ama daha az fark edilir çünkü "kısıtlı" göründüğü için
    /// gözden kaçabilir.
    /// </summary>
    public sealed class ProtocolTransitionDelegationRule : IComputerComplianceRule
    {
        public string RuleId => "AD-029";

        public string Name => "Protokol Geçişli Kısıtlı Delegasyon (Constrained Delegation + Protocol Transition)";

        public string Description => "TRUSTED_TO_AUTH_FOR_DELEGATION bayrağı ve msDS-AllowedToDelegateTo hedef listesi birlikte set edilmiş bilgisayar hesapları, hedef kullanıcının parolasını hiç bilmeden o kullanıcı adına kimlik doğrulayabilir (S4U2Self). Bu hesabı ele geçiren bir saldırgan, listelenen hedeflere karşı herhangi bir kullanıcı gibi davranabilir.";

        public string FrameworkMapping => "MITRE ATT&CK T1558 (Steal or Forge Kerberos Tickets)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.8.2 (Privileged Access Rights)";

        public string Remediation => "1. Bu delegasyonun gerçekten protokol geçişine (ör. Kerberos'u desteklemeyen bir ön yüzden gelen isteklerin arkadaki servise iletilmesi) ihtiyaç duyup duymadığını doğrulayın.\n" +
                                     "2. Mümkünse 'Use Kerberos only' (protokol geçişi olmayan) kısıtlı delegasyona geçin.\n" +
                                     "3. Hassas/yüksek yetkili hesapları Protected Users grubuna ekleyerek veya 'Account is sensitive and cannot be delegated' işaretleyerek bu tekniğin hedefi olmalarını engelleyin.";

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

            foreach (var computer in computerList)
            {
                if (!computer.IsEnabled) continue;
                if (!computer.IsProtocolTransitionDelegation) continue;
                if (computer.AllowedToDelegateTo.Count == 0) continue;

                string targets = string.Join(", ", computer.AllowedToDelegateTo);
                vulnerableComputers.Add($"{computer.SamAccountName} -> [{targets}]");
            }

            return new RuleResult
            {
                RuleId = this.RuleId,
                IsVulnerable = vulnerableComputers.Count > 0,
                RiskLevel = vulnerableComputers.Count > 0 ? "High" : "Low",
                AffectedObjects = vulnerableComputers,
                Remediation = this.Remediation
            };
        }
    }
}
