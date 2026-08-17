using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// SYSVOL üzerindeki GptTmpl.inf'ten okunan, domain genelinde geçerli parola
    /// politikasının (minimum uzunluk, karmaşıklık, süre) zayıf olup olmadığını
    /// tespit eden kural sınıfı. Kullanıcı bazlı değil, politika bazlıdır - tek bir
    /// bulgu, o politikaya bağlı TÜM hesapları etkiler.
    /// </summary>
    public sealed class WeakPasswordPolicyRule : IGroupPolicyComplianceRule
    {
        private const int MinimumAcceptableLength = 14;

        public string RuleId => "AD-013";

        public string Name => "Zayıf Domain Parola Politikası";

        public string Description => "SYSVOL'daki Group Policy'de tanımlı minimum parola uzunluğu, karmaşıklık zorunluluğu veya parola geçerlilik süresi endüstri standartlarının altında. Bu, politikaya bağlı tüm hesapları etkileyen domain-geneli bir risktir.";

        public string FrameworkMapping => "CIS Controls v8 - 5.2 / NIST SP 800-63B (Password Policy)";

        public string Remediation => "1. Grup İlkesi Yönetim Konsolu'ndan (GPMC) ilgili GPO'yu düzenleyin.\n" +
                                     "2. 'Minimum password length' değerini en az 14 karaktere çıkarın.\n" +
                                     "3. 'Password must meet complexity requirements' seçeneğini etkinleştirin.\n" +
                                     "4. Parolanın hiç süresi dolmayacak şekilde (0) ayarlanmadığından emin olun.";

        public RuleResult Execute(object directoryData)
        {
            if (directoryData is not IEnumerable<GroupPolicySecuritySettings> policies)
            {
                return new RuleResult
                {
                    RuleId = this.RuleId,
                    IsVulnerable = false,
                    RiskLevel = "Informational",
                    Remediation = "Analiz edilecek geçerli veri sağlanamadı."
                };
            }

            var vulnerablePolicies = new List<string>();

            foreach (var policy in policies)
            {
                bool tooShort = policy.MinimumPasswordLength < MinimumAcceptableLength;
                bool noComplexity = !policy.PasswordComplexityEnabled;
                bool neverExpires = policy.MaximumPasswordAgeDays == 0;

                if (tooShort || noComplexity || neverExpires)
                {
                    var reasons = new List<string>();
                    if (tooShort) reasons.Add($"MinLength={policy.MinimumPasswordLength}");
                    if (noComplexity) reasons.Add("Complexity=Kapalı");
                    if (neverExpires) reasons.Add("MaxAge=Süresiz");

                    vulnerablePolicies.Add($"{policy.GpoName} ({string.Join(", ", reasons)})");
                }
            }

            return new RuleResult
            {
                RuleId = this.RuleId,
                IsVulnerable = vulnerablePolicies.Count > 0,
                RiskLevel = vulnerablePolicies.Count > 0 ? "High" : "Low",
                AffectedObjects = vulnerablePolicies,
                Remediation = this.Remediation
            };
        }
    }
}
