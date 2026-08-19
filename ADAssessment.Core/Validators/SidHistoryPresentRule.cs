using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// sIDHistory özniteliğinde değer taşıyan kullanıcı hesaplarını tespit eder. Bu öznitelik
    /// normalde sadece domain göçü (migration) sırasında dolar ve göç tamamlandıktan sonra
    /// temizlenmesi beklenir. Temizlenmeden kalması ya unutulmuş bir göç artığıdır ya da bir
    /// saldırganın ayrıcalık yükseltmek için kötüye kullandığı bir tekniktir (SID-History
    /// Injection, MITRE ATT&CK T1134.005) - bu teknikte saldırgan, kendi kontrolündeki bir
    /// hesabın sIDHistory'sine örneğin Domain Admins grubunun SID'ini ekleyerek, hesap
    /// normalde o gruba üye olmadığı halde o grubun yetkileriyle erişim sağlar.
    /// </summary>
    public sealed class SidHistoryPresentRule : IComplianceRule
    {
        public string RuleId => "AD-025";

        public string Name => "SID History Değeri Bulunan Hesaplar";

        public string Description => "sIDHistory özniteliğinde değer taşıyan hesaplar, o değerlerin temsil ettiği eski SID'lerin (örn. başka bir domain'deki bir grup) sahip olduğu tüm erişim haklarını da miras alır. Bu, ya temizlenmemiş bir domain göçü artığıdır ya da SID-History Injection ile yapılan bir ayrıcalık yükseltme saldırısının izidir.";

        public string FrameworkMapping => "MITRE ATT&CK T1134.005 (Access Token Manipulation: SID-History Injection)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.8.2 (Privileged Access Rights)";

        public string Remediation => "1. Her etkilenen hesap için sIDHistory değerinin meşru/planlı bir domain göçünden mi kaldığını doğrulayın.\n" +
                                     "2. Göç tamamlanmışsa, PowerShell (Set-ADUser -Remove) veya ADSI ile sIDHistory değerlerini temizleyin.\n" +
                                     "3. Beklenmeyen/açıklanamayan bir sIDHistory değeri bulunursa, bunu bir güvenlik olayı olarak ele alıp inceleyin - SID-History Injection'ın bir göstergesi olabilir.";

        public RuleResult Execute(object directoryData)
        {
            if (directoryData is not IEnumerable<AdUserAccount> userList)
            {
                return new RuleResult
                {
                    RuleId = this.RuleId,
                    IsVulnerable = false,
                    RiskLevel = "Informational",
                    Remediation = "Analiz edilecek geçerli veri sağlanamadı."
                };
            }

            var vulnerableAccounts = new List<string>();

            foreach (var user in userList)
            {
                if (user.HasSidHistory)
                {
                    vulnerableAccounts.Add(user.SamAccountName);
                }
            }

            return new RuleResult
            {
                RuleId = this.RuleId,
                IsVulnerable = vulnerableAccounts.Count > 0,
                RiskLevel = vulnerableAccounts.Count > 0 ? "High" : "Low",
                AffectedObjects = vulnerableAccounts,
                Remediation = this.Remediation
            };
        }
    }
}
