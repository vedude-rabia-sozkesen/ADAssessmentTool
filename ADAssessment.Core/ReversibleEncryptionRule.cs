using System;
using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Active Directory ortamında parolası geri dönüştürülebilir (düz metin benzeri) şifreleme ile saklanan (ENCRYPTED_TEXT_PASSWORD_ALLOWED) hesapları tespit eden kural sınıfı.
    /// </summary>
    public sealed class ReversibleEncryptionRule : IComplianceRule
    {
        public string RuleId => "AD-009";

        public string Name => "Geri Dönüştürülebilir Şifreleme (Reversible Encryption) Açık Hesaplar";

        public string Description => "Store password using reversible encryption ayarı açık olan hesaplar, parolayı düz metne (cleartext) dönüştürülebilecek şekilde saklar. NTDS.dit veritabanı ele geçirilirse şifre anında açık metin olarak elde edilebilir.";

        public string FrameworkMapping => "CIS Controls v8 - 5.2 / MITRE ATT&CK T1552.001 (Credentials in Files)";

        public string Remediation => "1. Kullanıcı hesap özelliklerinden veya GPO üzerindeki 'Store passwords using reversible encryption' politikasını devre dışı (Disabled) bırakın.\n" +
                                     "2. Etkilenen kullanıcıların parolalarını hemen değiştirmesini sağlayın.";

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

                if (user.IsEnabled && user.IsReversibleEncryptionAllowed && !isComputerAccount)
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
