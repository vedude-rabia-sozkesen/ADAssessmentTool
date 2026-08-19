using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Resource-Based Constrained Delegation (RBCD) - bir bilgisayarın "kendi adına kimin
    /// kimlik doğrulayabileceğini" (msDS-AllowedToActOnBehalfOfOtherIdentity) belirttiği
    /// modern bir Kerberos delegasyon mekanizması. Bu öznitelik VARSAYILAN olarak boştur;
    /// herhangi bir değer taşıması, listelenen prensibi ele geçiren bir saldırganın o
    /// bilgisayarda SYSTEM yetkisiyle kimlik doğrulayabileceği anlamına gelir - günümüzün
    /// en sık kullanılan Active Directory ayrıcalık yükseltme tekniklerinden biridir,
    /// çünkü bir bilgisayar nesnesi üzerinde sadece "WriteProperty" hakkı olan bir
    /// saldırgan bile bu özniteliği kendi kontrolündeki bir hesap lehine ayarlayabilir.
    /// </summary>
    public sealed class UnexpectedResourceBasedConstrainedDelegationRule : IComputerComplianceRule
    {
        public string RuleId => "AD-028";

        public string Name => "Beklenmeyen Resource-Based Constrained Delegation (RBCD)";

        public string Description => "Bir bilgisayar nesnesinde msDS-AllowedToActOnBehalfOfOtherIdentity özniteliği set edilmiş - listelenen asıl güvenlik prensibi (kullanıcı/bilgisayar/grup), bu bilgisayarda SYSTEM yetkisiyle kimlik doğrulayabilir. Bu öznitelik varsayılan olarak boştur; herhangi bir değer taşıması gözden geçirilmesi gereken bir yetkilendirmedir.";

        public string FrameworkMapping => "MITRE ATT&CK T1558 (Steal or Forge Kerberos Tickets)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.8.2 (Privileged Access Rights)";

        public string Remediation => "1. Listelenen her prensip için bu delegasyonun kasıtlı/belgelenmiş bir mimari karar olup olmadığını doğrulayın.\n" +
                                     "2. Beklenmeyen/açıklanamayan bir yetkilendirme bulunursa, msDS-AllowedToActOnBehalfOfOtherIdentity özniteliğini temizleyin (Set-ADComputer -PrincipalsAllowedToDelegateToAccount $null) ve bu bilgisayar nesnesi üzerindeki yazma haklarını kimin taşıdığını (bir saldırganın bu izni nasıl elde ettiğini) inceleyin.\n" +
                                     "3. Bilgisayar nesneleri üzerinde gereksiz 'WriteProperty'/'GenericWrite' haklarını (özellikle bu özniteliğe erişimi) sınırlayın.";

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
                if (computer.ResourceBasedConstrainedDelegationPrincipals.Count == 0) continue;

                string principals = string.Join(", ", computer.ResourceBasedConstrainedDelegationPrincipals);
                vulnerableComputers.Add($"{computer.SamAccountName} -> [{principals}]");
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
