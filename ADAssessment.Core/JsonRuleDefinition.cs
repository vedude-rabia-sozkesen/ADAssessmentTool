using System.Text.Json.Serialization;

namespace ADAssessment.Core
{
    /// <summary>
    /// Kod derlemeden (No-Code) dışarıdan JSON/YAML dosyası ile tanımlanan
    /// bir güvenlik kuralının veri sözleşmesidir (Schema Model).
    /// </summary>
    public sealed class JsonRuleDefinition
    {
        [JsonPropertyName("ruleId")]
        public string RuleId { get; set; } = string.Empty;

        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("description")]
        public string Description { get; set; } = string.Empty;

        [JsonPropertyName("frameworkMapping")]
        public string FrameworkMapping { get; set; } = string.Empty;

        [JsonPropertyName("remediation")]
        public string Remediation { get; set; } = string.Empty;

        /// <summary>
        /// Analiz edilecek kullanıcı özniteliği. Örn: "UserAccountControl", "LastLogonTimestamp", "ServicePrincipalNames"
        /// </summary>
        [JsonPropertyName("targetProperty")]
        public string TargetProperty { get; set; } = string.Empty;

        /// <summary>
        /// Karşılaştırma operatörü. Örn: "BitwiseAND", "Equals", "GreaterThanDays", "NotEmpty"
        /// </summary>
        [JsonPropertyName("operator")]
        public string Operator { get; set; } = string.Empty;

        /// <summary>
        /// Karşılaştırılacak değer. Örn: 32, 65536, 90, "MSSQLSvc"
        /// </summary>
        [JsonPropertyName("value")]
        public object? Value { get; set; }

        /// <summary>
        /// Koşul sonucu kontrolü. Örn: "NotEqualZero", "EqualsZero", "IsTrue", "IsFalse"
        /// </summary>
        [JsonPropertyName("condition")]
        public string Condition { get; set; } = string.Empty;

        /// <summary>
        /// Riskin büyüklüğü. Örn: "High", "Medium", "Low"
        /// </summary>
        [JsonPropertyName("riskLevel")]
        public string RiskLevel { get; set; } = "Medium";
    }
}
