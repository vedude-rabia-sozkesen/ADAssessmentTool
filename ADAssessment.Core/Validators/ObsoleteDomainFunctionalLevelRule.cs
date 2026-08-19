using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Domain Fonksiyonel Seviyesi'nin (Domain Functional Level - DFL) eskimiş olup olmadığını
    /// tespit eder. DFL, domain'deki TÜM Domain Controller'ların desteklediği garanti edilen
    /// asgari Windows Server sürümünü belirler - eski bir DFL, modern kimlik doğrulama güvenlik
    /// özelliklerinin (örn. AES Kerberos şifreleme desteği, Authentication Policy Silos,
    /// Protected Users grubunun bazı korumaları) domain genelinde KULLANILAMAMASI anlamına
    /// gelir; bu da domain'i, artık desteklenmeyen ve zafiyetleri yamalanmayan eski
    /// protokollere (örn. RC4/DES Kerberos şifrelemesi) mahkum eder.
    /// </summary>
    public sealed class ObsoleteDomainFunctionalLevelRule : IDomainFunctionalLevelComplianceRule
    {
        public string RuleId => "AD-026";

        // msDS-Behavior-Version değeri 5'ten (Windows Server 2012) küçükse eskimiş kabul
        // edilir - 2000/2003/2008/2008 R2 seviyeleri hepsi çoktan destek ömrünü doldurmuş
        // sürümlere karşılık gelir.
        private const int MinimumAcceptableLevel = 5;

        public string Name => "Eskimiş Domain Fonksiyonel Seviyesi (Domain Functional Level)";

        public string Description => "Domain Fonksiyonel Seviyesi (DFL), domain'deki tüm Domain Controller'ların garanti edilen asgari yeteneğini belirler. Windows Server 2012'nin altındaki bir DFL, AES Kerberos şifrelemesi gibi modern güvenlik özelliklerinin domain genelinde zorunlu kılınmasını engeller ve domain'i eski/zayıf protokollere bağımlı bırakır.";

        public string FrameworkMapping => "CIS Controls v8 - 4.1 (Secure Configuration) / MITRE ATT&CK T1558.003 (Kerberoasting - zayıf şifrelemeye bağımlılığı artırır)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.8.9 (Configuration Management)";

        public string Remediation => "1. Domain'deki tüm Domain Controller'ların işletim sistemi sürümünü kontrol edin (bkz. AD-017 Eskimiş İşletim Sistemi kuralı).\n" +
                                     "2. Tüm DC'ler modern bir Windows Server sürümüne yükseltildikten sonra, Active Directory Yöneticisi Merkezi veya PowerShell (Set-ADDomainMode) ile Domain Fonksiyonel Seviyesini yükseltin.\n" +
                                     "3. Fonksiyonel seviye yükseltmesi GERİ ALINAMAZ bir işlemdir - önce test ortamında doğrulayın.";

        public RuleResult Execute(object directoryData)
        {
            if (directoryData is not DomainFunctionalLevelSettings settings || settings.FunctionalLevel < 0)
            {
                return new RuleResult
                {
                    RuleId = this.RuleId,
                    IsVulnerable = false,
                    RiskLevel = "Informational",
                    Remediation = "Analiz edilecek geçerli veri sağlanamadı."
                };
            }

            bool isObsolete = settings.FunctionalLevel < MinimumAcceptableLevel;
            var affected = new List<string>();

            if (isObsolete)
            {
                affected.Add($"{settings.DomainDistinguishedName} (Fonksiyonel Seviye Kodu: {settings.FunctionalLevel})");
            }

            return new RuleResult
            {
                RuleId = this.RuleId,
                IsVulnerable = isObsolete,
                RiskLevel = isObsolete ? "Medium" : "Low",
                AffectedObjects = affected,
                Remediation = this.Remediation
            };
        }
    }
}
