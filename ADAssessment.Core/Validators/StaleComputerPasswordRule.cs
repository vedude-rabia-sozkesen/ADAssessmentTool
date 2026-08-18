using System;
using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Bilgisayar hesabı parolasının (makine hesabı, kendi kendini periyodik olarak
    /// yeniler - varsayılan 30 günde bir) uzun süredir (90 gün+) yenilenmediği durumları
    /// tespit eder. Bu, StalePasswordRule'ün (AD-007) bilgisayar nesneleri üzerindeki
    /// karşılığıdır - normalde otomatik yenilenmesi gereken bir parolanın durması, o
    /// makinenin domain'den kopmuş/yönetim dışı kaldığının veya replikasyon sorunları
    /// yaşandığının bir işareti olabilir.
    /// </summary>
    public sealed class StaleComputerPasswordRule : IComputerComplianceRule
    {
        public string RuleId => "AD-018";

        public string Name => "Yenilenmemiş Bilgisayar Hesabı Parolası (90+ Gün)";

        public string Description => "Bilgisayar hesabı parolası (makine hesabı parolası, normalde ~30 günde bir otomatik yenilenir) 90 günden uzun süredir değişmemiş. Bu, ilgili makinenin domain'den kopmuş, kapalı kalmış veya replikasyon sorunu yaşıyor olabileceğinin göstergesidir.";

        public string FrameworkMapping => "CIS Controls v8 - 5.2 / MITRE ATT&CK T1110 (Brute Force)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.5.17 (Authentication Information)";

        public string Remediation => "1. Etkilenen makinelerin hâlâ ağda aktif ve domain'e üye olup olmadığını doğrulayın.\n" +
                                     "2. Kapalı/kaybolmuş makinelerin hesaplarını devre dışı bırakın veya silin.\n" +
                                     "3. Aktif ama parolası yenilenmeyen makinelerde replikasyon/GPO uygulama sorunlarını araştırın.";

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
            var thresholdDate = DateTime.UtcNow.AddDays(-90);

            foreach (var computer in computerList)
            {
                bool isStale = !computer.PasswordLastSet.HasValue || computer.PasswordLastSet.Value < thresholdDate;

                if (computer.IsEnabled && isStale)
                {
                    string lastSetInfo = computer.PasswordLastSet.HasValue
                        ? computer.PasswordLastSet.Value.ToString("yyyy-MM-dd")
                        : "Hiç Ayarlanmadı";

                    vulnerableComputers.Add($"{computer.SamAccountName} (Son Parola Değişimi: {lastSetInfo})");
                }
            }

            return new RuleResult
            {
                RuleId = this.RuleId,
                IsVulnerable = vulnerableComputers.Count > 0,
                RiskLevel = "Low",
                AffectedObjects = vulnerableComputers,
                Remediation = this.Remediation
            };
        }
    }
}
