using System;
using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Active Directory ortamında uzun süredir (180 gün+) parolası değiştirilmemiş hesapları tespit eden kural sınıfı.
    /// </summary>
    public sealed class StalePasswordRule : IComplianceRule
    {
        public string RuleId => "AD-007";

        public string Name => "Uzun Süredir Parolası Değiştirilmemiş Hesaplar (180+ Gün)";

        public string Description => "Parolası 180 günden (6 aydan) daha uzun süredir değiştirilmeyen hesaplar, sızdırılmış veri tabanlarındaki (data breach) parolalarla eşleşme ve kaba kuvvet saldırılarına maruz kalma riski taşır.";

        public string FrameworkMapping => "CIS Controls v8 - 5.2 / MITRE ATT&CK T1110 (Brute Force)";

        public string Remediation => "1. Etkilenen kullanıcı hesaplarının parolalarını sıfırlayın ve yeni karmaşık bir parola belirlemelerini sağlayın.\n" +
                                     "2. Fine-Grained Password Policy (FGPP) uygulayarak parola yenileme sürelerini otomatikleştirin.";

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
            var thresholdDate = DateTime.UtcNow.AddDays(-180);

            foreach (var user in userList)
            {
                bool isComputerAccount = !string.IsNullOrEmpty(user.SamAccountName) && user.SamAccountName.EndsWith("$");

                bool isPasswordStale = user.PasswordLastSet.HasValue && user.PasswordLastSet.Value < thresholdDate;

                if (user.IsEnabled && isPasswordStale && !isComputerAccount)
                {
                    string lastSetDate = user.PasswordLastSet!.Value.ToString("yyyy-MM-dd");
                    string riskDetail = user.IsAdminCountSet ? "[KRİTİK YETKİLİ]" : "[STANDART HESAP]";
                    vulnerableAccounts.Add($"{riskDetail} {user.SamAccountName} (Son Değişim: {lastSetDate})");
                }
            }

            return new RuleResult
            {
                RuleId = this.RuleId,
                IsVulnerable = vulnerableAccounts.Count > 0,
                RiskLevel = vulnerableAccounts.Count > 0 ? "Medium" : "Low",
                AffectedObjects = vulnerableAccounts,
                Remediation = this.Remediation
            };
        }
    }
}
