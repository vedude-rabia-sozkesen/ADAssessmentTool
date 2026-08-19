using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// msDS-SupportedEncryptionTypes özniteliği açıkça set edilmiş ama AES (128/256 bit)
    /// şifrelemesini içermeyen kullanıcı hesaplarını tespit eder. Bu hesaplar RC4/DES gibi
    /// eski, çok daha zayıf Kerberos şifrelemesine mahkum kalır - AD-001'in (Kerberoasting)
    /// doğrudan bir sonucu olarak, bu hesaplardan alınan servis bileti hash'i, AES ile
    /// korunan bir hesaba göre çok daha hızlı (GPU ile saatler yerine dakikalar/saniyeler
    /// mertebesinde) kırılabilir. Öznitelik hiç set edilmemiş (0) hesaplar bilerek
    /// DIŞLANIR - bu, çoğu domain'de son derece yaygın/varsayılan bir durumdur ve DC'nin
    /// kendi varsayılanına tabidir; burada odaklanılan, AES'i AÇIKÇA dışlayan bir
    /// yapılandırmadır.
    /// </summary>
    public sealed class AesEncryptionNotSupportedRule : IComplianceRule
    {
        public string RuleId => "AD-030";

        public string Name => "AES Desteklemeyen Kerberos Şifreleme Yapılandırması";

        public string Description => "Hesap için msDS-SupportedEncryptionTypes özniteliği açıkça set edilmiş ama AES128/AES256 bitlerini içermiyor - hesap yalnızca RC4/DES gibi zayıf Kerberos şifrelemesini kullanabilir, bu da Kerberoasting ile elde edilen hash'in çok daha hızlı kırılmasını sağlar.";

        public string FrameworkMapping => "MITRE ATT&CK T1558.003 (Kerberoasting)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.8.24 (Kriptografinin Kullanımı)";

        public string Remediation => "1. Etkilenen hesaplar için msDS-SupportedEncryptionTypes değerini AES128+AES256 bitlerini (24, yani 0x18) içerecek şekilde güncelleyin.\n" +
                                     "2. Bu yapılandırmayı gerektiren eski bir uygulama/cihaz varsa, mümkünse AES destekleyen bir sürüme yükseltin.\n" +
                                     "3. Domain fonksiyonel seviyesi Windows Server 2008 veya üzeriyse (bkz. AD-026) AES zaten desteklenir - bu ayarın neden özellikle kısıtlandığını araştırın.";

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
                if (user.IsEnabled && user.IsAesUnsupported)
                {
                    vulnerableAccounts.Add(user.SamAccountName);
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
