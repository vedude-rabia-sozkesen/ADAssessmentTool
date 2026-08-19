using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Domain Controller OLMAYAN bilgisayar hesaplarında (üye sunucu/istemci) Sınırsız
    /// Kerberos Delegasyonu (Unconstrained Delegation) yetkisi tespit eder. UnconstrainedDelegationRule
    /// (AD-006) kullanıcı/servis hesaplarına bakar; bu kural aynı riski bilgisayar nesneleri
    /// üzerinde arar - bir saldırgan bu tür bir sunucuyu ele geçirirse, o sunucuya Kerberos ile
    /// bağlanan HERKESİN (potansiyel olarak Domain Admin dahil) TGT biletini çalıp Domain
    /// Controller'ı ele geçirebilir.
    /// </summary>
    public sealed class ComputerUnconstrainedDelegationRule : IComputerComplianceRule
    {
        public string RuleId => "AD-024";

        public string Name => "Sınırsız Delegasyon Yetkili Bilgisayar Hesapları (Unconstrained Delegation)";

        public string Description => "Domain Controller olmayan bir bilgisayar hesabında Sınırsız Kerberos Delegasyonu (TRUSTED_FOR_DELEGATION) etkinse, bu makineye Kerberos ile bağlanan her kullanıcının TGT bileti bellekte saklanır. Bu makineyi ele geçiren bir saldırgan, bağlanan Domain Admin dahil herkesin kimliğine bürünebilir.";

        public string FrameworkMapping => "MITRE ATT&CK T1558 (Steal or Forge Kerberos Tickets)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.8.2 (Privileged Access Rights)";

        public string Remediation => "1. Zorunlu olmadıkça sunucu/istemci bilgisayar hesaplarında Sınırsız Delegasyonu kaldırın.\n" +
                                     "2. Delegasyon gerekiyorsa Resource-Based Constrained Delegation (RBCD) veya Constrained Delegation mimarisine geçin.\n" +
                                     "3. Bu makinelere hiçbir zaman yüksek yetkili (Domain Admin vb.) hesaplarla oturum açılmadığından emin olun.";

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
                // Domain Controller'lar tasarım gereği sınırsız delegasyona sahiptir - bu
                // beklenen/normal bir durumdur, elenmezse her taramada garanti "zafiyet"
                // olarak görünür (gerçek bir bulgu değil, yanlış pozitif).
                if (computer.IsDomainController) continue;

                if (computer.IsEnabled && computer.IsUnconstrainedDelegation)
                {
                    vulnerableComputers.Add(computer.SamAccountName);
                }
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
