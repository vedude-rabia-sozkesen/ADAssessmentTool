using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// LAPS (Local Administrator Password Solution) tarafından yönetilmeyen, etkin,
    /// Domain Controller olmayan bilgisayar hesaplarını tespit eder. LAPS olmadan yerel
    /// yönetici (Administrator) parolaları genellikle tüm makinelerde AYNI (imaj/kurulum
    /// script'i üzerinden dağıtılan, hiç değiştirilmeyen bir parola) olur - bir saldırgan
    /// TEK bir makinede bu parolayı ele geçirdiğinde (ör. Mimikatz ile), aynı parolayla
    /// domain'deki HER makineye yerel yönetici olarak yayılabilir ("Pass-the-Hash" tarzı
    /// yanal hareket, ama parola paylaşımı yüzünden hash'e bile gerek kalmadan).
    /// </summary>
    public sealed class MissingLapsProtectionRule : IComputerComplianceRule
    {
        public string RuleId => "AD-033";

        public string Name => "LAPS Koruması Olmayan Bilgisayar Hesapları";

        public string Description => "Bilgisayar hesabında LAPS (Local Administrator Password Solution) tarafından yönetilen bir yerel yönetici parolası tespit edilemedi. LAPS olmadan yerel yönetici parolaları genellikle tüm makinelerde aynıdır - tek bir makinenin ele geçirilmesi, bu parolayla domain genelinde yanal harekete (lateral movement) yol açabilir.";

        public string FrameworkMapping => "MITRE ATT&CK T1078.003 (Valid Accounts: Local Accounts)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.8.5 (Güvenli Kimlik Doğrulama)";

        public string Remediation => "1. LAPS'ı (Windows Server 2019+'ta yerleşik 'Windows LAPS', daha eskisi için Microsoft'un ayrı LAPS eklentisi) domain genelinde bir GPO ile dağıtın.\n" +
                                     "2. Her makine için yerel yönetici parolasını benzersiz, otomatik döndürülen bir değere geçirin.\n" +
                                     "3. LAPS parola değerini okuma hakkını (CONTROL_ACCESS) sadece gerçekten ihtiyacı olan yönetici gruplarına verin - bu izin de kendi başına hassas bir yetkilendirmedir.";

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
                // Domain Controller'larda yerel Administrator hesabı kavramı LAPS'ın hedeflediği
                // senaryodan farklıdır (DC'lerde zaten ayrı bir sertleştirme modeli uygulanır) -
                // dışlanmazsa her taramada garanti "zafiyet" görünür.
                if (computer.IsDomainController) continue;
                if (computer.HasLapsManagedPassword) continue;

                vulnerableComputers.Add(computer.SamAccountName);
            }

            return new RuleResult
            {
                RuleId = this.RuleId,
                IsVulnerable = vulnerableComputers.Count > 0,
                RiskLevel = vulnerableComputers.Count > 0 ? "Medium" : "Low",
                AffectedObjects = vulnerableComputers,
                Remediation = this.Remediation
            };
        }
    }
}
