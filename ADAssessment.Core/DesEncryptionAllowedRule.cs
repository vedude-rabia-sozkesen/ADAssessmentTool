using System;
using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Active Directory ortamında zayıf ve güvensiz DES şifreleme algoritması (USE_DES_KEY_ONLY) kullanılmasına izin verilen hesapları tespit eden kural sınıfı.
    /// </summary>
    public sealed class DesEncryptionAllowedRule : IComplianceRule
    {
        public string RuleId => "AD-010";

        public string Name => "Zayıf DES Şifreleme Etkin Hesaplar (DES Encryption Allowed)";

        public string Description => "DES (Data Encryption Standard) şifreleme algoritması günümüzde tamamen kırılmış ve güvensiz kabul edilir. Kullanıcı hesabında Kerberos için DES kullanımına izin verilmesi, biletlerin dakikalar içinde kırılmasına yol açar.";

        public string FrameworkMapping => "CIS Controls v8 - 5.2 / MITRE ATT&CK T1558 (Kerberos Abuse)";

        public string Remediation => "1. Etkilenen hesapların özelliklerinden 'Use Kerberos DES encryption types for this account' seçeneğindeki işareti kaldırın.\n" +
                                     "2. Kerberos şifreleme türü olarak AES-128 veya AES-256 kullanımını zorunlu kılın.";

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
                bool isComputerAccount = !string.IsNullOrEmpty(user.SamAccountName) && user.SamAccountName.EndsWith("$");

                if (user.IsEnabled && user.IsDesEncryptionAllowed && !isComputerAccount)
                {
                    string riskDetail = user.IsAdminCountSet ? "[KRİTİK YETKİLİ]" : "[STANDART HESAP]";
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
