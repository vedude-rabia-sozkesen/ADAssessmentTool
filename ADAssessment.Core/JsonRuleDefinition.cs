using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace ADAssessment.Core
{
    /// <summary>
    /// Kod derlemeden (No-Code) dışarıdan JSON/YAML dosyası ile tanımlanan
    /// tekli veya çoklu (AND/OR) mantıksal güvenlik kuralı veri sözleşmesidir.
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

        [JsonPropertyName("riskLevel")]
        public string RiskLevel { get; set; } = "Medium"; // "High", "Medium", "Low"

        /// <summary>
        /// Çoklu koşul birleştirme operatörü: "AND", "OR"
        /// </summary>
        [JsonPropertyName("logicalOperator")]
        public string LogicalOperator { get; set; } = "AND";

        /// <summary>
        /// Tekli koşul için hedef öznitelik. (Çoklu koşul kullanılmıyorsa)
        /// </summary>
        [JsonPropertyName("targetProperty")]
        public string TargetProperty { get; set; } = string.Empty;

        /// <summary>
        /// Tekli koşul için operatör. (Çoklu koşul kullanılmıyorsa)
        /// </summary>
        [JsonPropertyName("operator")]
        public string Operator { get; set; } = string.Empty;

        /// <summary>
        /// Tekli koşul için değer.
        /// </summary>
        [JsonPropertyName("value")]
        public object? Value { get; set; }

        /// <summary>
        /// Tekli koşul için sonuç denetimi ("NotEqualZero", "EqualsZero", "IsTrue", "IsFalse")
        /// </summary>
        [JsonPropertyName("condition")]
        public string Condition { get; set; } = string.Empty;

        /// <summary>
        /// Karmaşık kurallar için iç içe (nested) koşul listesi
        /// </summary>
        [JsonPropertyName("conditions")]
        public List<RuleConditionNode>? Conditions { get; set; }
    }

    /// <summary>
    /// Çoklu/Karmaşık (Nested) kural düğümü
    /// </summary>
    public sealed class RuleConditionNode
    {
        [JsonPropertyName("targetProperty")]
        public string TargetProperty { get; set; } = string.Empty;

        [JsonPropertyName("operator")]
        public string Operator { get; set; } = string.Empty;

        [JsonPropertyName("value")]
        public object? Value { get; set; }

        [JsonPropertyName("condition")]
        public string Condition { get; set; } = string.Empty;

        [JsonPropertyName("logicalOperator")]
        public string LogicalOperator { get; set; } = "AND";

        [JsonPropertyName("conditions")]
        public List<RuleConditionNode>? Conditions { get; set; }
    }
}
