using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// JSON/YAML dosyalarından okunan kural tanımlarını IComplianceRule arayüzüne 
    /// dönüştüren dinamik kural sarmalayıcısı (Adapter Pattern).
    /// </summary>
    public sealed class DynamicComplianceRule : IComplianceRule
    {
        private readonly JsonRuleDefinition _definition;

        public DynamicComplianceRule(JsonRuleDefinition definition)
        {
            _definition = definition;
        }

        public string RuleId => _definition.RuleId;
        public string Name => _definition.Name;
        public string Description => _definition.Description;
        public string FrameworkMapping => _definition.FrameworkMapping;

        /// <summary>
        /// Bu kuralı üreten ham JSON tanımı. WebAPI katmanının kuralı listelerken/
        /// düzenlerken (edit formu doldururken) orijinal alanlara erişebilmesi için.
        /// </summary>
        public JsonRuleDefinition Definition => _definition;

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
                // 2. Aşamada yazdığımız RuleEvaluator dinamik motorunu tetikliyoruz
                if (RuleEvaluator.IsVulnerable(user, _definition))
                {
                    string riskDetail = user.IsAdminCountSet ? "[KRİTİK YETKİLİ]" : "[STANDART HESAP]";
                    vulnerableAccounts.Add($"{riskDetail} {user.SamAccountName}");
                }
            }

            return new RuleResult
            {
                RuleId = this.RuleId,
                IsVulnerable = vulnerableAccounts.Count > 0,
                RiskLevel = vulnerableAccounts.Count > 0 ? _definition.RiskLevel : "Low",
                AffectedObjects = vulnerableAccounts,
                Remediation = _definition.Remediation
            };
        }
    }
}
