using System; //temel şeyler (string vs)
using System.Collections.Generic; //listeler diziler için

namespace ADAssessment.Core
{
    /// <summary>
    /// Active Directory ortamlarında Kerberos ön kimlik doğrulaması devre dışı bırakılmış
    /// (DONT_REQUIRE_PREAUTH) hesapları (MITRE ATT&CK T1558.004) tespit eden kural sınıfı.
    /// </summary>
    public sealed class AsRepRoastingRule : IComplianceRule //IComplianceRule interface'inden kalıtım alıyoruz
    {
        public string RuleId => "AD-002";

        public string Name => "AS-REP Roasting Riski Barındıran Hesaplar";

        public string Description => "Kerberos Ön Kimlik Doğrulaması (Pre-Authentication) devre dışı bırakılmış hesaplar, parola bilinmeden şifreli bilet talep edilmesine ve çevrimdışı parola kırma (offline brute-force) saldırılarına açık hale gelir.";

        public string FrameworkMapping => "MITRE ATT&CK T1558.004 (Steal or Forge Kerberos Tickets: AS-REP Roasting)";

        public string Remediation => "1. Etkilenen kullanıcı hesaplarının özelliklerinden 'Do not require Kerberos preauthentication' seçeneğindeki işareti kaldırın.\n" +
                                     "2. Bu durumun zorunlu olduğu servis hesapları varsa parolalarını en az 25 karakterli ve karmaşık hale getirin.\n" +
                                     "3. Mümkünse bu hesapları 'Protected Users' grubuna dahil edin.";

        public RuleResult Execute(object directoryData) //execute metodunu override ediyoruz
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
                // FİLTRELEME MANTIĞI:
                // 1. Hesap aktif olacak (IsEnabled)
                // 2. Pre-Auth kapalı olacak (IsPreauthNotRequired)
                // 3. Bilgisayar hesabı olmayacak (!isComputerAccount)

                bool isComputerAccount = !string.IsNullOrEmpty(user.SamAccountName) && user.SamAccountName.EndsWith("$");

                if (user.IsEnabled && user.IsPreauthNotRequired && !isComputerAccount)
                {
                    string riskDetail = user.IsAdminCountSet ? "[KRİTİK YETKİLİ]": "[STANDART KULLANICI]";
                    vulnerableAccounts.Add($"{riskDetail} {user.SamAccountName}");
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
