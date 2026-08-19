using System;
using System.Collections.Generic;
using System.Linq;

namespace ADAssessment.Core
{
    /// <summary>
    /// KRBTGT hesabının (her domain'de otomatik oluşturulan, tüm Kerberos TGT biletlerini
    /// imzalamak için kullanılan özel sistem hesabı) parola yaşını kontrol eder. Bu parola
    /// hiç/uzun süredir değiştirilmemişse, KRBTGT hash'ini bir şekilde ele geçirmiş bir
    /// saldırganın ürettiği sahte TGT biletleri ("Golden Ticket") çok daha uzun süre
    /// geçerliliğini korur - Microsoft'un kendi tavsiyesi bu parolanın düzenli
    /// döndürülmesidir (rotation), pratikte en sık unutulan sertleştirme adımlarından biridir.
    /// </summary>
    public sealed class KrbtgtPasswordAgeRule : IComplianceRule
    {
        public string RuleId => "AD-027";

        private const int MaxPasswordAgeDays = 180;
        private const string KrbtgtSamAccountName = "krbtgt";

        public string Name => "Eski KRBTGT Parolası (Golden Ticket Riski)";

        public string Description => "KRBTGT hesabının parolası uzun süredir (180+ gün) değiştirilmemiş. Bu hesabın hash'ini ele geçiren bir saldırgan, bu parola değişene kadar geçerli sahte Kerberos biletleri (Golden Ticket) üretebilir - bu, domain'e sınırsız/kalıcı erişim anlamına gelir.";

        public string FrameworkMapping => "MITRE ATT&CK T1558.001 (Golden Ticket)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.8.24 (Kriptografinin Kullanımı)";

        public string Remediation => "1. KRBTGT parolasını PowerShell (Reset-KrbtgtKeyInteractive script'i veya Set-ADAccountPassword) ile döndürün.\n" +
                                     "2. Kerberos TGT bilet ömrü (varsayılan 10 saat) nedeniyle parolayı İKİ KEZ, aralarında en az bir bilet ömrü kadar süre bırakarak değiştirin - tek seferlik değişim yetersizdir.\n" +
                                     "3. Bu rotasyonu düzenli bir bakım takvimine (örn. yılda bir, şüpheli bir sızıntı sonrası hemen) bağlayın.";

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

            var krbtgt = userList.FirstOrDefault(u => string.Equals(u.SamAccountName, KrbtgtSamAccountName, StringComparison.OrdinalIgnoreCase));

            if (krbtgt == null)
            {
                // krbtgt hesabı çekilen kullanıcı listesinde bulunamadı (beklenmez, ama
                // örn. üst seviye bir sorgu hatası tüm listeyi boşaltmışsa oluşabilir) -
                // "güvenli" değil "veri yok" demek daha doğru.
                return new RuleResult
                {
                    RuleId = this.RuleId,
                    IsVulnerable = false,
                    RiskLevel = "Informational",
                    Remediation = "KRBTGT hesabı çekilen veri içinde bulunamadı."
                };
            }

            var thresholdDate = DateTime.UtcNow.AddDays(-MaxPasswordAgeDays);
            bool isStale = !krbtgt.PasswordLastSet.HasValue || krbtgt.PasswordLastSet.Value < thresholdDate;

            var affected = new List<string>();
            if (isStale)
            {
                string lastSetInfo = krbtgt.PasswordLastSet.HasValue
                    ? krbtgt.PasswordLastSet.Value.ToString("yyyy-MM-dd")
                    : "Hiç Değiştirilmedi";
                affected.Add($"krbtgt (Son Parola Değişimi: {lastSetInfo})");
            }

            return new RuleResult
            {
                RuleId = this.RuleId,
                IsVulnerable = isStale,
                RiskLevel = isStale ? "High" : "Low",
                AffectedObjects = affected,
                Remediation = this.Remediation
            };
        }
    }
}
